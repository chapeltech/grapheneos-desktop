#!/usr/bin/env python3
"""One bounded client-only death on an admitted, held policy-free guest.

No boot/install/force-stop, no remembered-token replay, no health reset. The
common role-death sampler is REQUIRED before a signal. A successful attachment
is not a nine-disturbance/86400s qualification.
"""
from pathlib import Path
from phase1_conformance_installed_path import installed_apk_path
import hashlib
import os
import re
import secrets
import subprocess
import sys
import time

import phase1_conformance_soak_lock_user_actions as attached
import phase1_conformance_soak_frozen_client_action as frozen
import phase1_conformance_soak_apk_update as workers
import phase1_conformance_soak_client_death_acceptance as acceptance
from phase1_conformance_common import canonical, file_ref

runtime, health = attached.runtime, attached.health
require = runtime.require
MAX_TRANSITION_NS = 180_000_000_000
FIELDS = ("pid_before", "ps_before", "stat_before", "status", "fd", "stat_after", "pid_after", "ps_after")
ABSENT_COMMANDS = {
    "activities": ("dumpsys", "activity", "activities"),
    "fixture": ("dumpsys", "activity", "--user", "0", attached.admission.lane.acceptance.FIXTURE),
    "windows": ("dumpsys", "window", "windows"), "window_displays": ("dumpsys", "window", "displays"),
    "input": ("dumpsys", "input"), "display": ("dumpsys", "display"),
    "keyguard": ("dumpsys", "activity", "--user", "0", "service", "com.android.systemui/.SystemUIService"),
    "policy": ("dumpsys", "window", "policy"), "current_user": ("am", "get-current-user"), "users": ("dumpsys", "user"),
    "events": attached.acceptance.observations.EVENTS,
    "modem": ("getprop", health.phone.MODEM_PROPERTY), "radio": ("su", "0", "service", "list"),
    "boot": ("cat", "/proc/sys/kernel/random/boot_id"),
    "home_uid": ("pm", "list", "packages", "-U", "--user", "0", attached.admission.lane.raw_audit.LAUNCHER)}


def source_contract():
    result = attached.source_contract()
    result.update({name: {"path": str(Path(module.__file__).resolve()), **file_ref(Path(module.__file__).resolve())}
        for name, module in {"client_death_action": sys.modules[__name__], "client_death_auditor": acceptance,
            "exact_signal_fence": frozen, "owned_worker_start": workers, "black_shield": frozen.acceptance}.items()})
    root = Path(__file__).resolve().parents[2]
    for name, relative in {
        "native_death_controller": "android/os-integration/src/org/wonad/desktop/broker/NativeDesktopController.kt",
        "native_task_state": "android/input-integration/src/com/android/server/wm/WonadNativeBridge.kt",
        "native_containment": "android/input-integration/src/com/android/server/wm/WonadUiBridge.kt",
        "api_death_contract": "android/desktop-sdk/API-v3.md"}.items():
        path = root / relative; result[name] = {"path": str(path), **file_ref(path)}
    return result


class ClientDeathAction(attached.Actions):
    SCENARIO = "client_death"
    ACTION_AUDIT = acceptance

    def current_sources(self): return source_contract()
    def before_death(self, before): pass
    # Reuse the unchanged actual producer's UID/PID/start signal fence, and its
    # actual new self-target subprocess/nonce/initial-readiness method bodies.
    fence = frozen.FrozenAction.fence
    new_runtime = workers.ApkUpdateAction.new_runtime

    def __init__(self, test, admitted_contract, *, timeout=120, current_client_admission=None):
        super().__init__(test, admitted_contract, timeout=timeout, current_client_admission=current_client_admission)
        require(isinstance(test, attached.admission.lane.Producer), "Actual policy-free producer required")
        require(test.instrument is not None and test.instrument.poll() is None, "Actual owned held client required")
        self.sampler = test.sampler
        require(callable(getattr(self.sampler, "begin_role_death", None)) and
            callable(getattr(self.sampler, "end_role_death", None)), "Explicit reviewed role-death health hooks required BEFORE kill")
        self.p = test; self.sources = self.current_sources()

    def bounded(self):
        require(time.monotonic_ns() < self.deadline and self.p.sampler is self.sampler, "Bounded death deadline/sampler changed")
        self.sampler.check()

    def owned_worker(self):
        require(self.p.instrument is not None and self.p.instrument.poll() is None and
            self.p.instrument_file is not None and not self.p.instrument_file.closed and
            Path(self.p.instrument_path).resolve(strict=True).is_relative_to(self.p.output) and
            str(self.p.instrument_file.name) == str(self.p.instrument_path), "Original held worker/output is not owned")
        worker = {"run": self.p.conformance_run, "nonce": self.p.initial_nonce, "host_pid": self.p.instrument.pid,
            "output_original": self.p.instrument_path.relative_to(self.p.output).as_posix()}
        argv = workers.audit.runtime_argv(["docker", "exec", self.p.container, "adb", "-s", workers.audit.SERIAL], worker)
        starts = [row for row in self.p.trace[:self.trace_begin] if row.get("kind") == "background_start" and
            row.get("id") == "instrumentation-" + worker["run"]]
        require(len(starts) == 1 and starts[0]["argv"] == argv and list(self.p.instrument.args) == argv,
            "Original instrumentation is not the exact admitted self-target worker")
        worker["start_sequence"] = starts[0]["sequence"]
        worker["started_monotonic_ns"] = starts[0]["started_monotonic_ns"]
        now = time.monotonic_ns()
        self.p._record({"kind": "background_adopt", "id": "instrumentation-" + worker["run"], "argv": argv,
            "host_pid": worker["host_pid"], "output_original": worker["output_original"],
            "started_monotonic_ns": now, "ended_monotonic_ns": now})
        return worker

    def installed(self, label):
        prefix = self.prefix + "/installed/" + label
        files = {key: prefix + (".apk" if key == "apk" else "-" + key + ".txt") for key in ("path", "dump", "apk")}
        raw = self.raw_read(files["path"], "pm", "path", "--user", "0", runtime.PACKAGE)
        path = installed_apk_path(raw, runtime.PACKAGE, package_row=True)
        self.raw_read(files["dump"], "dumpsys", "package", runtime.PACKAGE)
        self.p.adb("exec-out", "cat", path, evidence=files["apk"], binary=True)
        require(file_ref(self.p.output / files["apk"]) == self.current_client.selection()["member"]["artifact"],
            "Actual installed client is not the exact admitted current APK")
        self.action["installed"].append(files)
        return files

    def finish_dead_worker(self, worker):
        # Android death must finish this exact handle. No host kill/stop command
        # is substituted for genuine target death; timeout remains a failure.
        code = self.p.instrument.wait(timeout=30)
        self.p.instrument_file.flush(); os.fsync(self.p.instrument_file.fileno()); self.p.instrument_file.close()
        payload = attached.admission.lane.mechanics.acceptance.stable_bytes(self.p.instrument_path)
        worker["output"] = self.prefix + "/dead-instrumentation.txt"
        workers.write_new(self.p.output / worker["output"], payload)
        acceptance.dead_instrumentation(payload.decode())
        now = time.monotonic_ns(); worker["ended_monotonic_ns"] = now
        self.p._record({"kind": "background_finish", "id": "instrumentation-" + worker["run"],
            "host_pid": worker["host_pid"], "cause": "exact_owned_client_KILL", "returncode": code,
            "started_monotonic_ns": now, "ended_monotonic_ns": now,
            "evidence": worker["output"], "output_sha256": hashlib.sha256(payload).hexdigest()})
        require(code == 0, "Actual old instrumentation transport failed")
        self.p.instrument = self.p.instrument_file = None

    def absence(self, label):
        self.bounded(); self.owner_guard(0)
        start = len(self.p.trace); files = {}
        commands = {"uid": ("pm", "list", "packages", "-U", "--user", "0", runtime.PACKAGE),
            "pid_before": ("pidof", runtime.PACKAGE), "ps_before": health.PROCESS_TABLE_COMMAND,
            "pid_after": ("pidof", runtime.PACKAGE), "ps_after": health.PROCESS_TABLE_COMMAND}
        for key, command in commands.items():
            relative = self.prefix + "/absence/" + label + "-" + key + ".txt"; files[key] = relative
            if key.startswith("pid"):
                self.p.shell(*command, allowed=(1,), evidence=relative)
            else: self.raw_read(relative, *command)
        row = {"label": label, "files": files, "trace_start": start, "trace_end": len(self.p.trace)}
        self.ACTION_AUDIT.absence(self.p.output, row, self.action, self.p.trace)
        self.action["absences"].append(row)
        return row

    def capture_absent(self, name):
        directory = self.prefix + "/captures/" + name
        require(not (self.p.output / directory).exists(), "Never replace absent capture")
        began, start = time.monotonic_ns(), len(self.p.trace)
        opening = self.absence(name + "-before")
        files = {key: directory + "/" + key + ".txt" for key in ABSENT_COMMANDS}
        for key, args in ABSENT_COMMANDS.items(): self.raw_read(files[key], *args)
        processes = {}
        for role, package in health.contract.PROCESS_NAMES.items():
            if role == "client": continue
            uid_path = directory + "/" + role + "-uid.txt"
            uid = 1000 if role == "system_server" else attached.acceptance.package_uid(
                self.raw_read(uid_path, "pm", "list", "packages", "-U", "--user", "0", package), package, 0)
            raw, refs = {}, {}
            for key in FIELDS:
                command = ("pidof", package) if key.startswith("pid") else health.PROCESS_TABLE_COMMAND if key.startswith("ps") else (
                    "su", "0", *(("ls", "-1") if key == "fd" else ("cat",)), f"/proc/{pid}/" + ("stat" if key in ("stat_before", "stat_after") else key))
                relative = directory + "/" + role + "-" + key + ".txt"
                raw[key] = self.raw_read(relative, *command); refs[key] = relative
                if key == "ps_before": pid = health.qualified_pid(raw["pid_before"], raw[key], package, uid)
            processes[role] = {"package_uid": None if role == "system_server" else uid_path, "files": refs,
                **attached.acceptance.process_metric(raw, uid, package)}
        frames = {str(slot): directory + f"/frame-{slot}.png" for slot in (0, 1, 2, 3)}
        for slot, relative in frames.items(): self.p._frame(relative, int(slot))
        closing = self.absence(name + "-after")
        row = {"name": name, "user": 0, "runtime_status_observed": False, "files": files, "processes": processes,
            "frames": frames, "absence_before": opening, "absence_after": closing,
            "trace_start": start, "trace_end": len(self.p.trace), "began_monotonic_ns": began,
            "ended_monotonic_ns": time.monotonic_ns()}
        self.action["captures"].append(row); return row

    def copy_current(self):
        raw, before = self.status_raw()
        require(before["state"] == "ready" and before["runtime_readiness"]["ready"], "Fresh actual lease is not ready")
        nonce = secrets.token_hex(16); phase = "copy-observed"
        sequence = len(self.p.trace)
        result = self.command("dumpsys", "activity", "--user", "0", "service", runtime.SERVICE,
            "runtime-command", self.p.conformance_run, nonce, phase)
        attached.acceptance.require_control_marker(result, runtime.CONTROL_MARKER + f"accepted {self.p.conformance_run} {nonce} {phase}")
        def acknowledged():
            _raw, value = self.status_raw()
            require(value["handshake"] != {"nonce": nonce, "phase": phase, "result": "rejected"}, "Fresh copy rejected")
            return value if value["handshake"] == {"nonce": nonce, "phase": phase, "result": "accepted"} and value["state"] == "ready" else False
        value = self.wait("fresh current-token frame RESULT_APPLIED", acknowledged)
        return {"nonce": nonce, "command_sequence": sequence, "ack_sequence": self.p.trace[-1]["sequence"], "status": value}

    def status_raw(self):
        # Before and after are DISTINCT owned runs. Never require dead process
        # ownership in a new worker, or query a dead/stopped service.
        raw = self.read("conformance", "dumpsys", "activity", "--user", "0", "service", runtime.SERVICE)
        attached.acceptance.require_poll_expectation_marker(raw)
        value = runtime.parse_status(raw)
        require(value["run"] == self.p.conformance_run and value["failure"] is None and value["control_error"] is None,
            "Actual current conformance worker failed/changed")
        return raw, value

    def perform(self):
        require(self.action is None and self.current_sources() == self.sources and self.p.sampler is self.sampler and
            self.SCENARIO in {"client_death", "malformed_calls"}, "Concurrent/drifted/unreviewed death action")
        require(attached.admission.input_contract(self.p.image, Path(self.contract["product"]), Path(self.contract["packet"]),
            self.contract["packet_receipt"]["sha256"]) == self.contract, "Actual immutable packet/image contract changed")
        self.ordinal += 1; nonce = secrets.token_hex(16); self.read_count = 0
        self.prefix = f"soak-actions/{self.ordinal:06d}-{self.SCENARIO}-{nonce}"
        directory = self.p.output / self.prefix
        require(directory.parent.resolve() == directory.parent and not directory.parent.is_symlink(), "Aliased original action parent")
        directory.mkdir(parents=True, mode=0o700)
        start, began = len(self.p.trace), time.monotonic_ns(); self.trace_begin = start
        self.deadline = min(self.p.deadline_ns, began + MAX_TRANSITION_NS)
        self.action = {"schema": 1, "kind": self.ACTION_AUDIT.KIND, "scenario": self.SCENARIO, "ordinal": self.ordinal,
            "nonce": nonce, "run": self.p.conformance_run, "identity": self.identity, "contract": self.contract,
            "sources": self.sources, "uids": self.p.uids, "status": self.ACTION_AUDIT.FAILED,
            "runtime_qualified": False, "whole_campaign_complete": False, "sampler_stopped_by_action": False,
            "began_monotonic_ns": began, "captures": [], "client_fences": [], "absences": [], "workers": [], "installed": []}
        attached.current_client.begin_action(self)
        attached.admission.lane.fresh.write_new_durable(directory / "attempt-started.json", self.action)
        error = None
        try:
            self.current_client.observe(self, "before")
            self.guard(0)
            workers.write_new(directory / "original-runtime-trace.json", canonical(self.p.trace[:start]))
            old = self.owned_worker(); self.action["workers"].append(old)
            before_row = self.capture("before"); before = attached.acceptance.parse_capture(self.p.output, before_row, self.action, self.p.trace)
            attached.acceptance.ready(before, self.action); original = before["processes"]["client"]
            self.installed("before")
            self.before_death(before)
            old["epoch"] = {key: original[key] for key in ("pid", "start_ticks")}
            transition_start = time.monotonic_ns(); self.action["transition_started_monotonic_ns"] = transition_start
            permit = self.sampler.begin_role_death(nonce, self.SCENARIO, role="client", role_uid=original["uid"],
                before=dict(old["epoch"]), started_monotonic_ns=transition_start, action_relative=self.prefix + "/attempt-ended.json")
            require(runtime.HEX32.fullmatch(permit), "Opaque role-death permit ID required")
            self.action["permit_id"] = permit
            self.fence("before-kill", original)
            self.action["kill_sequence"] = len(self.p.trace)
            self.command("su", "0", "kill", "-KILL", original["pid"])
            self.finish_dead_worker(old)
            self.absence("dead-first")
            for index in range(3):
                self.challenge(before); self.capture_absent(f"inactive-{index}")
            new = self.new_runtime(self.prefix + "/new-worker"); self.action["workers"].append(new)
            # Independent epoch observation completes absence permission BEFORE
            # copied placement. Read every protected OS role as well.
            probe = self.capture("new-ready")
            current_action = {**self.action, "run": new["run"]}
            probe_scene = attached.acceptance.parse_capture(self.p.output, probe, current_action, self.p.trace)
            require(probe_scene["status"]["snapshot"]["identity_epoch"] == before["status"]["snapshot"]["identity_epoch"] and
                probe_scene["status"]["snapshot"]["generation"] > 0 and
                probe_scene["status"]["snapshot"]["generation"] != before["status"]["snapshot"]["generation"],
                "Client restart changed system_server identityEpoch or reused generation")
            new["epoch"] = {key: probe_scene["processes"]["client"][key] for key in ("pid", "start_ticks")}
            require(new["epoch"] != old["epoch"] and probe_scene["processes"]["client"]["uid"] == original["uid"], "Client did not genuinely change epoch at same admitted UID")
            first_epoch_row = next(row for row in self.p.trace if row.get("evidence") == probe["processes"]["client"]["files"]["ps_after"])
            self.action["absent_end_monotonic_ns"] = first_epoch_row["ended_monotonic_ns"]
            self.action["copied_frame"] = self.copy_current()
            recovered = self.capture("recovered")
            self.installed("recovered")
            for component, record in before["records"].items(): self.p.delivered(component, record["native_display"])
            self.command("input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME")
            self.capture("delivered")
            recovery_relative = self.prefix + "/recovered-stage.json"
            attached.admission.lane.fresh.write_new_durable(self.p.output / recovery_relative, recovered)
            ended = time.monotonic_ns()
            require(ended <= transition_start + MAX_TRANSITION_NS, "Fixed role-death interval exceeded")
            self.sampler.end_role_death(permit, after=dict(new["epoch"]), ended_monotonic_ns=ended,
                action_relative=self.prefix + "/attempt-ended.json", recovered_stage_relative=recovery_relative)
            self.current_client.observe(self, "after")
            self.action.update(transition_ended_monotonic_ns=ended, recovered_stage_relative=recovery_relative, status=self.ACTION_AUDIT.STATUS)
        except BaseException as caught:
            error = caught; self.action["error"] = str(caught)
        finally:
            # Exact new handle remains owned by the enclosing guest, also on
            # failure. No fresh PID guesses, second kill, sampler pause or reset.
            self.action["cleanup"] = {"owner": "enclosing_original_guest_owner", "signal_retry": False,
                "sampler_stopped": False, "owned_run": self.p.conformance_run,
                "owned_output": str(self.p.instrument_path), "host_pid": self.p.instrument.pid if self.p.instrument else None}
            def seal(step):
                nonlocal error
                try: step()
                except BaseException as caught:
                    if error is None: error = caught
                    elif error is not caught: error.add_note("Secondary evidence-sealing failure: " + repr(caught))
                    self.action["status"] = self.ACTION_AUDIT.FAILED
                    self.action.setdefault("error", str(error))
                    self.action.setdefault("sealing_errors", []).append(repr(caught))
            try:
                self.action.update(trace_start=start, trace_end=len(self.p.trace), ended_monotonic_ns=time.monotonic_ns())
                if error is not None: self.action["status"] = self.ACTION_AUDIT.FAILED
                seal(lambda: attached.current_client.finish_journal(self))
                seal(lambda: attached.admission.lane.fresh.write_new_durable(directory / "commands.json", self.p.trace[start:]))
                excluded = self.p.instrument_path if self.p.instrument is not None else None
                def inventory():
                    self.action["evidence"] = {str(path.relative_to(self.p.output)): (
                        acceptance.observed_ref(path, self.p.trace, self.p.output, self.p.container) if error is None else
                        attached.admission.lane.mechanics.failed_file_ref(path))
                        for path in directory.rglob("*") if path.is_file() and path != excluded}
                seal(inventory)
                seal(lambda: attached.admission.lane.fresh.write_new_durable(directory / "attempt-ended.json", self.action))
            finally: self.action = None
        if error is not None: raise error
        try: result = self.ACTION_AUDIT.audit_action(directory / "attempt-ended.json", self.contract, self.identity,
            client_chain=self.current_client.chain, client_uid=self.current_client.uid)
        except BaseException as caught:
            attached.admission.lane.fresh.write_new_durable(directory / "independent-audit-failure.json", {
                "error": str(caught), "runtime_qualified": False, "original_attempt": file_ref(directory / "attempt-ended.json")})
            raise
        self.p.expected_processes = {package: {key: result["processes"][role][key] for key in ("pid", "start_ticks")}
            for role, package in health.contract.PROCESS_NAMES.items()}
        return {"path": str(directory / "attempt-ended.json"), **file_ref(directory / "attempt-ended.json"),
            "runtime_qualified": False, "whole_campaign_complete": False}
