#!/usr/bin/env python3
"""Callable same-guest conformance APK update/restore attachment; never boots.

Seed once BEFORE the first held worker. Attach to an already genuinely admitted,
consented, populated policy-free producer. Two ordinary APK replacements retain
old instrumentation streams and start two fresh owned self-target workers.
The continuous sampler is never stopped/reset here; replacement-interval health
admission is explicitly unresolved and this action cannot qualify a campaign.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time

import phase1_conformance_clean_boot as lane
import phase1_conformance_soak_apk_update_acceptance as audit
import conformance_update_canary_epoch as epoch_canary
from phase1_conformance_common import canonical, file_ref, load
import phase1_conformance_observations as observations
import phase1_conformance_installed_path as installed_paths

require = audit.require


def write_new(path, payload):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lane.mechanics.write_new(path, payload)


def host_sources():
    return {role: {"path": str(path), **file_ref(path)} for role, path in {
        "actor": Path(__file__).resolve(), "auditor": Path(audit.__file__).resolve(),
        "runtime": Path(audit.runtime.__file__).resolve(), "scenes": Path(audit.scene_audit.__file__).resolve(),
        "transport": Path(lane.mechanics.__file__).resolve(), "owner": Path(audit.sampler.__file__).resolve(),
        "packet": Path(audit.packet_tool.__file__).resolve(), "canary_parser": Path(sys.modules[audit.marker_result.__module__].__file__).resolve(),
        "apk_parser": Path(sys.modules[audit.apk_pair.__module__].__file__).resolve(),
        "signer_parser": Path(sys.modules["native_wrong_signer_acceptance"].__file__).resolve(),
        "window_pixel_parser": Path(audit.scene_audit.raw_audit.__file__).resolve(),
        "clean_boot": Path(lane.__file__).resolve(), "owner_raw_auditor": Path(audit.sampler.owned_audit.__file__).resolve(),
        "common_schema": Path(audit.common.__file__).resolve(),
        "epoch_canary_parser": Path(epoch_canary.__file__).resolve(),
        "raw_observations": Path(observations.__file__).resolve(),
        "installed_path_parser": Path(installed_paths.__file__).resolve()}.items()}


class Attachment:
    def __init__(self, producer, identity, manifest, packet, receipt_sha256, *, prefix):
        require(isinstance(producer, lane.Producer), "Only the owned policy-free conformance producer may attach")
        require(producer.container == identity["container_id"] and producer.image == identity["image_id"] and
                producer.boot_id == identity["boot_id"] and producer.fingerprint == identity["fingerprint"],
                "Attachment guest identity differs")
        self.p, self.identity = producer, identity
        self.contract = audit.source_contract(packet, receipt_sha256)
        audit.attachment_manifest(manifest, self.contract)
        self.manifest = manifest
        self.prefix = prefix
        require(not (producer.output / prefix).exists() and not (producer.output / prefix).is_symlink(), "Never reuse an action attempt")
        (producer.output / prefix).mkdir(mode=0o700, parents=True)
        self.began = time.monotonic_ns()
        self.deadline = min(producer.deadline_ns, self.began + audit.MAX_ACTION_NS)
        self.trace_begin = len(producer.trace)
        self.sources = host_sources()
        self.sampler = getattr(producer, "sampler", None)
        self.manifest_path = prefix + "/image-manifest.json"
        write_new(producer.output / self.manifest_path, canonical(manifest))

    def bounded(self):
        require(time.monotonic_ns() < self.deadline, "Original bounded APK action deadline exceeded")
        require(getattr(self.p, "sampler", None) is self.sampler, "APK action may not replace/pause continuous sampler")

    def read(self, relative, *args):
        self.bounded()
        return self.p.read(relative, *args, timeout=min(60, max(1, (self.deadline - time.monotonic_ns()) // 1_000_000_000)))

    def owner(self, directory):
        names = ("inspect", "manifest", "root_diff", "boot", "fingerprint", "user", "consent", "selinux", "build_type", "boot_completed", "abi")
        files = {name: directory + "/owner-" + name + ".txt" for name in names}
        self.p.docker("container", "inspect", self.p.container, evidence=files["inspect"])
        self.p.docker("exec", self.p.container, "cat", "/opt/wonad/manifest.json", evidence=files["manifest"])
        self.p.docker("container", "diff", self.p.container, evidence=files["root_diff"])
        for name, args in {"boot": ("cat", "/proc/sys/kernel/random/boot_id"),
            "fingerprint": ("getprop", "ro.build.fingerprint"), "user": ("am", "get-current-user"),
            "consent": ("settings", "--user", "0", "get", "secure", "wonad_external_desktop_enabled"),
            "selinux": ("getenforce",), "build_type": ("getprop", "ro.build.type"),
            "boot_completed": ("getprop", "sys.boot_completed"), "abi": ("getprop", "ro.product.cpu.abi")}.items():
            self.read(files[name], *args)
        row = {"owner": files, "trace_start": self.trace_begin, "trace_end": len(self.p.trace)}
        info = json.loads((self.p.output / files["inspect"]).read_text())
        require(isinstance(info, list) and len(info) == 1, "Owned container is ambiguous")
        audit.sampler.verify_owner(info[0], self.identity)
        expected = {"boot": self.identity["boot_id"], "fingerprint": self.identity["fingerprint"], "user": "0",
                    "consent": "1", "selinux": "Enforcing", "build_type": "userdebug", "boot_completed": "1", "abi": "x86_64"}
        require(all((self.p.output / files[key]).read_text().strip() == value for key, value in expected.items()),
                "Original owner/OS/consent changed")
        require(load(self.p.output / files["manifest"]) == self.manifest and
                not any(re.fullmatch(r"[ACD] /opt/wonad(?:/.*)?", line) for line in (self.p.output / files["root_diff"]).read_text().splitlines()),
                "Original immutable image root/manifest changed")
        return files

    def canary_identity(self, directory):
        package = self.manifest["update_data_canary"]["instrumentation_apk"]["package"]
        files = {"path": directory + "/canary-path.txt", "apk": directory + "/canary-installed.apk"}
        raw = self.read(files["path"], "pm", "path", "--user", "0", package)
        path = installed_paths.installed_apk_path(raw, package, package_row=True)
        self.p.adb("exec-out", "cat", path, evidence=files["apk"], binary=True)
        target = self.manifest["update_data_canary"]["instrumentation_apk"]
        require(file_ref(self.p.output / files["apk"]) == {key: target[key] for key in ("sha256", "bytes")}, "Actual compiled canary differs")
        return files

    def package(self, directory):
        files = {"uids": {}, "reverse": {}, **{key: directory + "/package-" + key + (".apk" if key == "apk" else ".txt")
                 for key in ("dump", "path", "apk")}}
        uids = {}
        for index, package in enumerate((audit.APP, audit.scene_audit.FIXTURE, audit.scene_audit.raw_audit.SYSTEMUI)):
            relative = directory + f"/uid-{index}.txt"; files["uids"][package] = relative
            raw = self.read(relative, "cmd", "package", "list", "packages", "-U", "--user", "0", package)
            uids[package] = int(audit.scene_audit.raw_audit.package_manager_uid_row(raw, package).rsplit(":", 1)[1])
        for index, package in enumerate((audit.APP, audit.scene_audit.FIXTURE)):
            relative = directory + f"/reverse-{index}.txt"; files["reverse"][package] = relative
            self.read(relative, "cmd", "package", "list", "packages", "-U", "--user", "0", "--uid", uids[package])
        self.read(files["dump"], "dumpsys", "package", audit.APP)
        path = self.read(files["path"], "pm", "path", "--user", "0", audit.APP)
        path = installed_paths.installed_apk_path(path, audit.APP, package_row=True)
        self.p.adb("exec-out", "cat", path, evidence=files["apk"], binary=True)
        return files

    def epochs(self, directory):
        rows = {}
        for index, name in enumerate(audit.scene_audit.PROCESS_NAMES):
            files = {field: directory + f"/process-{index}-{field}.txt" for field in ("pidof", "before", "after")}
            raw = self.read(files["pidof"], "pidof", name)
            require(re.fullmatch(r"[1-9][0-9]*", raw), "Protected PID omitted/ambiguous: " + name)
            pid = int(raw)
            before = self.read(files["before"], "su", "0", "cat", f"/proc/{pid}/stat")
            after = self.read(files["after"], "su", "0", "cat", f"/proc/{pid}/stat")
            epoch = audit.scene_audit.proc_epoch(before, pid)
            require(epoch == audit.scene_audit.proc_epoch(after, pid), "PID/start reused within raw epoch fence")
            rows[name] = {**epoch, **files}
        require({name: {field: rows[name][field] for field in ("pid", "start_ticks")} for name in audit.scene_audit.OS_NAMES} ==
                self.p.core_epochs, "Protected four OS/phone epochs changed")
        return rows

    def frame(self, relative, slot):
        self.bounded()
        if slot == 0:
            self.p.adb("exec-out", "screencap", "-p", evidence=relative, binary=True); return
        remote = "/state/phase1-conformance-update-" + self.prefix.rsplit("-", 1)[-1] + "-" + secrets.token_hex(8) + "-" + str(slot)
        self.p.docker("exec", self.p.container, "mkdir", "-m", "700", "--", remote)
        try:
            result = self.p.adb("emu", "screenrecord", "screenshot", "--display", slot, remote)
            require("OK" in result and "KO:" not in result, "Actual framebuffer capture failed")
            names = self.p.docker("exec", self.p.container, "find", remote, "-maxdepth", "1", "-type", "f", "-name", "*.png", "-printf", "%f\\n").splitlines()
            require(len(names) == 1 and re.fullmatch(r"[A-Za-z0-9_.-]+\.png", names[0]), "Ambiguous actual framebuffer")
            target = self.p.output / relative; target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            require(not target.exists(), "Never overwrite a framebuffer")
            argv = ["docker", "cp", self.p.container + ":" + remote + "/" + names[0], str(target)]
            started = time.monotonic_ns()
            result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
            self.p._record({"kind": "command", "argv": argv, "returncode": result.returncode,
                "started_monotonic_ns": started, "ended_monotonic_ns": time.monotonic_ns(),
                "evidence": relative, "output_sha256": file_ref(target)["sha256"]} if result.returncode == 0 else
                {"kind": "command", "argv": argv, "returncode": result.returncode, "output": result.stdout.decode(errors="replace"),
                 "started_monotonic_ns": started, "ended_monotonic_ns": time.monotonic_ns()})
            require(result.returncode == 0, "Original owned framebuffer copy failed")
        finally:
            # Only this just-created nonce-bound temporary capture directory.
            self.p.docker("exec", self.p.container, "rm", "-rf", "--", remote)

    def capture(self, name):
        self.bounded()
        require(self.p.instrument is not None and self.p.instrument.poll() is None, "Actual held runtime ended before capture")
        directory = self.prefix + "/" + name
        low, began = len(self.p.trace), time.monotonic_ns()
        owner, package = self.owner(directory), self.package(directory)
        files = {key: directory + "/" + key + ".txt" for key in audit.STAGE_COMMANDS}
        for key, args in audit.STAGE_COMMANDS.items(): self.read(files[key], *args)
        epochs = self.epochs(directory)
        displays = audit.scene_audit.raw_audit.logical_displays((self.p.output / files["display"]).read_text())
        require({value["slot"] for value in displays.values()} == {1, 2, 3}, "All three mixed monitors required")
        frames = {str(slot): directory + f"/frame-{slot}.png" for slot in (0, 1, 2, 3)}
        for slot, relative in frames.items(): self.frame(relative, int(slot))
        return {"name": name, "files": files, "processes": epochs, "frames": frames, "owner": owner, "package": package,
            "trace_start": low, "trace_end": len(self.p.trace), "started_monotonic_ns": began, "ended_monotonic_ns": time.monotonic_ns()}

    def evidence(self):
        excluded = (self.p.instrument_path,) if self.p.instrument is not None else ()
        return observations.inventory(self.p.output / self.prefix, self.p.output,
            [(self.p.output, self.p.trace, False)], self.identity["container_id"], exclude=excluded)

    def marker(self, seed, mode, version, relative):
        require(self.p.instrument is None, "Canary may not run concurrently with conformance instrumentation")
        self.read(relative, *audit.canary_argv([], seed, mode)[1:])
        uid_raw = next(value for value in self.p.trace if value.get("evidence") == seed["observation"]["package"]["uids"][audit.APP])
        uid = int(audit.scene_audit.raw_audit.package_manager_uid_row((self.p.output / uid_raw["evidence"]).read_text(), audit.APP).rsplit(":", 1)[1])
        return audit.marker_result((self.p.output / relative).read_text(), mode, seed["run"], seed["nonce"], uid, version, self.p.fingerprint)

    def journal(self, relative, start):
        trace = [{**row, "sequence": index} for index, row in enumerate(self.p.trace[start:])]
        write_new(self.p.output / relative, canonical(trace))
        return trace

    def seal_failure(self, error):
        relative = self.prefix + "/failure-trace.json"
        if not (self.p.output / relative).exists(): self.journal(relative, self.trace_begin)
        failure = {"status": "failed_not_qualified", "error": str(error), "identity": self.identity,
            "runtime_qualified": False, "whole_campaign_complete": False, "sampler_stopped_by_action": False,
            "started_monotonic_ns": self.began, "ended_monotonic_ns": time.monotonic_ns(), "trace": relative,
            "owned_instrumentation_run": self.p.conformance_run,
            "owned_instrumentation_host_pid": self.p.instrument.pid if self.p.instrument is not None else None,
            "owned_instrumentation_output": str(self.p.instrument_path), "cleanup_owner": "enclosing_original_guest_owner"}
        write_new(self.p.output / self.prefix / "failure.json", canonical(failure))


def prepare_canary(producer, identity, manifest, packet, receipt_sha256):
    """Seed one private file, once, before starting any held runtime worker.

    No existing files are removed and no data/preferences are reset. This must
    be inserted after genuine prepare_guest admission, BEFORE initial runtime.
    """
    require(producer.instrument is None and not any(row.get("kind") == "background_start" for row in producer.trace),
            "Canary seed must precede every held conformance instrumentation")
    prefix = "apk-update-seed-" + secrets.token_hex(16)
    attachment = Attachment(producer, identity, manifest, packet, receipt_sha256, prefix=prefix)
    seed = {"run": secrets.token_hex(16), "nonce": secrets.token_hex(16), "identity": identity,
        "contract": attachment.contract, "started_monotonic_ns": attachment.began}
    try:
        low = len(producer.trace)
        seed["observation"] = {"owner": attachment.owner(prefix), "package": attachment.package(prefix),
                               "trace_start": low, "trace_end": len(producer.trace)}
        seed["install"], seed["marker"] = prefix + "/install.txt", prefix + "/marker.txt"
        producer.adb("install", "-r", "-t", "--user", "0", manifest["update_data_canary"]["instrumentation_apk"]["bundle_path"], evidence=seed["install"])
        require((producer.output / seed["install"]).read_text().strip().splitlines()[-1:] == ["Success"], "Ordinary canary APK install failed")
        seed["canary_identity"] = attachment.canary_identity(prefix)
        attachment.marker(seed, "create", 1, seed["marker"])
        seed["trace"] = prefix + "/commands.json"
        attachment.journal(seed["trace"], attachment.trace_begin)
        seed["observation"]["trace_start"] -= attachment.trace_begin
        seed["observation"]["trace_end"] -= attachment.trace_begin
        seed["ended_monotonic_ns"] = time.monotonic_ns()
        seed["evidence"] = attachment.evidence()
        write_new(producer.output / prefix / "seed.json", canonical(seed))
        return seed
    except BaseException as error:
        attachment.seal_failure(error); raise


class ApkUpdateAction(Attachment):
    def __init__(self, producer, identity, manifest, packet, receipt_sha256, seed, ordinal, *, permit_hooks=None):
        require(type(ordinal) is int and ordinal >= 1, "Original round ordinal required")
        require(producer.instrument is not None and producer.instrument.poll() is None, "An actual live owned conformance worker is required")
        require(getattr(producer, "sampler", None) is not None, "Original continuous sampler required; never silently pause it")
        self.nonce = secrets.token_hex(16)
        super().__init__(producer, identity, manifest, packet, receipt_sha256,
                         prefix=f"actions/apk-update-{ordinal:04d}-" + self.nonce)
        require(seed["contract"] == self.contract and seed["identity"] == identity, "Wrong seed/source guest")
        self.seed, self.ordinal, self.workers, self.replacements, self.stages = seed, ordinal, [], [], []
        require(permit_hooks is None or permit_hooks is producer.sampler and
                callable(getattr(permit_hooks, "begin_client_replacement", None)) and
                callable(getattr(permit_hooks, "end_client_replacement", None)), "Permit hooks must be the original owned continuous sampler")
        self.permit_hooks, self.pending_permits, self.seen_permits = permit_hooks, {}, set()
        if permit_hooks is not None:
            epoch_canary.require_compiled_epoch_canary(self.contract)

    def begin_permit(self, leg, transition, worker):
        if self.permit_hooks is None: return
        require(leg in (0, 1) and leg not in self.pending_permits, "Repeated/unreviewed replacement permit leg")
        # Re-derive the already admitted user-0 role UID from original raw PM
        # observations; never accept a caller-supplied new package identity.
        package = self.stages[-1]["package"]
        raw = (self.p.output / package["uids"][audit.APP]).read_text()
        uid = int(audit.scene_audit.raw_audit.package_manager_uid_row(raw, audit.APP).rsplit(":", 1)[1])
        reverse = (self.p.output / package["reverse"][audit.APP]).read_text()
        require(10000 <= uid <= 19999 and reverse.splitlines() == [f"package:{audit.APP} uid:{uid}"], "Permit role UID is not original ordinary singleton")
        permit = self.permit_hooks.begin_client_replacement(self.nonce, leg, role_uid=uid,
            before=dict(worker["epoch"]), started_monotonic_ns=transition["started_monotonic_ns"],
            action_relative=self.prefix + "/report.json")
        require(isinstance(permit, str) and 0 < len(permit) <= 256 and permit not in self.seen_permits,
                "Sampler returned missing/replayed replacement permit")
        self.pending_permits[leg] = permit; self.seen_permits.add(permit)
        transition["permit_id"] = permit

    def end_permit(self, leg, transition, worker, stage):
        if self.permit_hooks is None: return
        require(leg in self.pending_permits and transition["permit_id"] == self.pending_permits[leg], "Mismatched/replayed permit close")
        relative = self.prefix + "/" + stage["name"] + "/stage.json"
        local = {**stage, "trace_start": stage["trace_start"] - self.trace_begin, "trace_end": stage["trace_end"] - self.trace_begin}
        write_new(self.p.output / relative, canonical(local))
        self.permit_hooks.end_client_replacement(self.pending_permits[leg], after=dict(worker["epoch"]),
            ended_monotonic_ns=transition["ended_monotonic_ns"], action_relative=self.prefix + "/report.json",
            recovered_stage_relative=relative)
        transition["recovered_stage_relative"] = relative
        transition["permit_close"] = "provisional_pending_independent_complete_action_audit"
        del self.pending_permits[leg]

    def owned_worker(self):
        starts = [row for row in self.p.trace if row.get("kind") == "background_start" and
                  row.get("id") == "instrumentation-" + self.p.conformance_run]
        require(len(starts) == 1 and starts[0]["argv"] == audit.runtime_argv(
            ["docker", "exec", self.p.container, "adb", "-s", audit.SERIAL], {"run": self.p.conformance_run, "nonce": self.p.initial_nonce}),
            "Original actual held runtime start is missing")
        return {"run": self.p.conformance_run, "nonce": self.p.initial_nonce,
            "started_monotonic_ns": starts[0]["started_monotonic_ns"], "host_pid": self.p.instrument.pid}

    def complete_replaced_worker(self, worker, directory):
        # APK replacement, not host kill/force-stop/stop command, must terminate
        # this precise owned handle. Timeout leaves it to the enclosing owner.
        code = self.p.instrument.wait(timeout=30)
        self.p.instrument_file.flush(); os.fsync(self.p.instrument_file.fileno()); self.p.instrument_file.close()
        payload = lane.mechanics.acceptance.stable_bytes(self.p.instrument_path)
        worker["output"] = directory + "/replaced-instrumentation.txt"
        write_new(self.p.output / worker["output"], payload)
        worker["ended_monotonic_ns"] = time.monotonic_ns()
        self.p._record({"kind": "background_finish", "id": "instrumentation-" + worker["run"],
            "host_pid": worker["host_pid"], "cause": "ordinary_exact_apk_replacement", "returncode": code,
            "started_monotonic_ns": worker["ended_monotonic_ns"], "ended_monotonic_ns": worker["ended_monotonic_ns"],
            "evidence": worker["output"], "output_sha256": hashlib.sha256(payload).hexdigest()})
        self.p.instrument = self.p.instrument_file = None

    def new_runtime(self, directory):
        require(self.p.instrument is None, "Never replace a live held instrumentation")
        self.p.conformance_run, self.p.initial_nonce = secrets.token_hex(16), secrets.token_hex(16)
        self.p.instrument_path = self.p.output / directory / "held-instrumentation.txt"
        self.p.instrument_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.p.instrument_file = self.p.instrument_path.open("xb")
        worker = {"run": self.p.conformance_run, "nonce": self.p.initial_nonce,
                  "started_monotonic_ns": time.monotonic_ns()}
        prefix = ["docker", "exec", self.p.container, "adb", "-s", audit.SERIAL]
        argv = audit.runtime_argv(prefix, worker)
        self.p.instrument = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=self.p.instrument_file,
            stderr=subprocess.STDOUT, start_new_session=True)
        worker["host_pid"] = self.p.instrument.pid
        self.p._record({"kind": "background_start", "id": "instrumentation-" + worker["run"], "argv": argv,
            "host_pid": worker["host_pid"], "started_monotonic_ns": worker["started_monotonic_ns"],
            "ended_monotonic_ns": worker["started_monotonic_ns"]})
        limit = min(self.deadline, time.monotonic_ns() + audit.MAX_REPLACEMENT_NS)
        while time.monotonic_ns() < limit:
            self.bounded()
            require(self.p.instrument.poll() is None, "Fresh actual conformance runtime ended unexpectedly")
            raw = self.p.shell("dumpsys", "activity", "service", audit.runtime.SERVICE)
            try:
                status = audit.runtime.parse_status(raw)
            except (ValueError, json.JSONDecodeError):
                time.sleep(.2); continue
            require(status["run"] == worker["run"] and status["failure"] is None, "Fresh runtime failed or another owner took over")
            if (status["state"] == "ready" and status["runtime_readiness"] == {"ready": True, "session_open": True, "reopen_required": False} and
                    status["handshake"] == {"nonce": worker["nonce"], "phase": "start", "result": "accepted"}):
                worker["ready_sequence"] = self.p.trace[-1]["sequence"] - self.trace_begin
                return worker
            time.sleep(.2)
        raise TimeoutError("Fresh conformance self-target runtime did not genuinely reopen")

    def run(self):
        try:
            original_trace = self.prefix + "/original-runtime-trace.json"
            write_new(self.p.output / original_trace, canonical(self.p.trace[:self.trace_begin]))
            old = self.owned_worker()
            self.workers.append(old)
            before = self.capture("apk-before"); self.stages.append(before)
            old["epoch"] = {key: before["processes"][audit.APP][key] for key in ("pid", "start_ticks")}
            for index, (role, name, version) in enumerate((("v2", "apk-updated", 2), ("v1", "apk-restored", 1))):
                directory = self.prefix + f"/replacement-{index + 1}"
                transition = {"started_monotonic_ns": time.monotonic_ns(), "install": directory + "/install.txt", "marker": directory + "/marker.txt"}
                self.replacements.append(transition)
                self.begin_permit(index, transition, self.workers[-1])
                self.p.adb("install", "-r", *(("-d",) if index else ()), "--user", "0",
                    self.manifest["conformance_version_update"][role]["bundle_path"], evidence=transition["install"], timeout=120)
                require((self.p.output / transition["install"]).read_text().strip().splitlines()[-1:] == ["Success"], "Actual ordinary APK replacement failed")
                self.complete_replaced_worker(self.workers[-1], directory)
                transition["canary_identity"] = self.canary_identity(directory)
                self.marker(self.seed, "read", version, transition["marker"])
                if self.permit_hooks is not None:
                    relative = self.stages[-1]["package"]["uids"][audit.APP]
                    uid = int(audit.scene_audit.raw_audit.package_manager_uid_row((self.p.output / relative).read_text(), audit.APP).rsplit(":", 1)[1])
                    transition["canary_epoch"] = epoch_canary.marker_epoch((self.p.output / transition["marker"]).read_text(), uid)
                    command = self.p.trace[-1]
                    require(command.get("evidence") == transition["marker"] and command["kind"] == "command" and command["returncode"] == 0,
                            "Intermediate canary command journal changed")
                    transition["canary"] = epoch_canary.command_receipt((self.p.output / transition["marker"]).read_text(), uid,
                        transition["marker"], self.prefix + "/commands.json", {**command, "sequence": command["sequence"] - self.trace_begin})
                worker = self.new_runtime(directory)
                self.workers.append(worker)
                # Copy ONLY the replacement's current observation. Its ordinary
                # Runner acknowledges this instruction only after RESULT_APPLIED.
                copied = self.p.runtime_command("copy-observed")
                transition["copied_frame"] = {"status": copied,
                    "ack_sequence": self.p.trace[-1]["sequence"] - self.trace_begin}
                recovered = self.capture(name); self.stages.append(recovered)
                worker["epoch"] = {key: recovered["processes"][audit.APP][key] for key in ("pid", "start_ticks")}
                transition["ended_monotonic_ns"] = time.monotonic_ns()
                require(transition["ended_monotonic_ns"] - transition["started_monotonic_ns"] <= audit.MAX_REPLACEMENT_NS, "APK replacement/recovery interval exceeded fixed bound")
                self.end_permit(index, transition, worker, recovered)
            # Only commit the intentional client boundary AFTER independent raw
            # acceptance. Do not reset clocks, sampler, resource baselines,
            # native task identities or any cumulative growth accounting.
            trace_path = self.prefix + "/commands.json"
            self.journal(trace_path, self.trace_begin)
            report = {"schema": 1, "kind": audit.KIND, "scope": audit.SCOPE, "status": audit.STATUS,
                "ordinal": self.ordinal, "action_nonce": self.nonce, "identity": self.identity,
                "contract": self.contract, "manifest": self.manifest_path, "host_sources": self.sources,
                "seed": self.seed, "original_runtime_trace": original_trace, "trace": trace_path,
                "core_epochs": self.p.core_epochs, "workers": self.workers, "replacements": self.replacements,
                "stages": [{**row, "trace_start": row["trace_start"] - self.trace_begin,
                            "trace_end": row["trace_end"] - self.trace_begin} for row in self.stages],
                "started_monotonic_ns": self.began, "ended_monotonic_ns": time.monotonic_ns(),
                "runtime_qualified": False, "qualification_claimed": False, "whole_campaign_complete": False,
                "sampler_stopped_by_action": False,
                "health_permit_hooked": self.permit_hooks is not None,
                "health_acceptance": "unresolved_full_campaign_replacement_intervals_not_waived"}
            report["evidence"] = {**self.seed["evidence"], **self.evidence()}
            require(audit.source_contract(self.contract["packet"], self.contract["packet_receipt_sha256"]) == self.contract and
                    host_sources() == self.sources, "APK action source/input contract drifted")
            result = audit.audit_action(self.p.output.resolve(), report)
            self.p.expected_processes = {name: {key: self.stages[-1]["processes"][name][key] for key in ("pid", "start_ticks")}
                                         for name in audit.scene_audit.PROCESS_NAMES}
            report["audit"] = result
            write_new(self.p.output / self.prefix / "report.json", canonical(report))
            return report
        except BaseException as error:
            self.seal_failure(error); raise


def perform(producer, identity, manifest, packet, receipt_sha256, seed, ordinal, *, permit_hooks=None):
    """Repeatable ordinary action; new nonce/output/worker epochs each round."""
    return ApkUpdateAction(producer, identity, manifest, packet, receipt_sha256, seed, ordinal, permit_hooks=permit_hooks).run()


def finish_owned_runtime(producer):
    """Normal enclosing-owner teardown using the CURRENT owned stream path.

    The inherited Recents helper has a historical identity/instrumentation.txt
    trace literal. Never use that literal after an intentional replacement.
    Existing stop_background remains the enclosing owner's failure fallback.
    This does not stop the sampler or remove the guest/userdata/canary.
    """
    require(producer.instrument is not None and producer.instrument.poll() is None and
            producer.instrument_file is not None and not producer.instrument_file.closed,
            "No live actual owned runtime for normal teardown")
    path = producer.instrument_path
    require(path.resolve(strict=True).is_relative_to(producer.output.resolve()) and
            str(producer.instrument_file.name) == str(path), "Current instrumentation handle/output owner differs")
    starts = [row for row in producer.trace if row.get("kind") == "background_start" and
              row.get("id") == "instrumentation-" + producer.conformance_run]
    require(len(starts) == 1 and starts[0]["argv"] == audit.runtime_argv(
        ["docker", "exec", producer.container, "adb", "-s", audit.SERIAL],
        {"run": producer.conformance_run, "nonce": producer.initial_nonce}), "Current worker was not owned/self-target")
    producer.runtime_command("stop")
    code = producer.instrument.wait(timeout=30)
    producer.instrument_file.flush(); os.fsync(producer.instrument_file.fileno()); producer.instrument_file.close()
    ended = time.monotonic_ns()
    producer._record({"kind": "background_finish", "id": "instrumentation-" + producer.conformance_run,
        "host_pid": producer.instrument.pid, "returncode": code, "cause": "ordinary_owned_runtime_stop",
        "started_monotonic_ns": ended, "ended_monotonic_ns": ended,
        "evidence": path.relative_to(producer.output).as_posix(), "output_sha256": file_ref(path)["sha256"]})
    producer.instrument = producer.instrument_file = None
    require(code == 0, "Actual owned runtime normal stop failed")
    return lane.mechanics.acceptance.stable_bytes(path)
