#!/usr/bin/env python3
"""Independent bounded conformance APK update/restore raw auditor, not a soak.

Only APK binary parsers and the ordinary canary-result parser are reused from
older update helpers. No product-policy producer or product auditor is run.
Signature trust comes from exact bytes of the authenticated selected packet;
the structural signer parser is not a cryptographic signature verifier.
"""
from pathlib import Path
import hashlib
import json
import re
import sys

import conformance_runtime as runtime
import phase1_conformance_clean_boot as lane
import phase1_conformance_clean_boot_acceptance as scene_audit
import phase1_conformance_soak_sampler as sampler
import phase1_emulator_client_packet as packet_tool
import phase1_conformance_common as common
import conformance_update_canary_epoch as epoch_canary
from apk_update_smoke import marker_result
from native_apk_update_acceptance import apk_pair
from phase1_conformance_common import canonical, file_ref, load, sha256, validate_manifest
import phase1_conformance_observations as observations
from phase1_conformance_installed_path import installed_apk_path

require = scene_audit.require
APP = runtime.PACKAGE
SERIAL = "emulator-5580"
KIND = "phase1_policy_free_same_guest_apk_update_restore_action_v1"
SCOPE = "bounded_same_guest_conformance_version_only_update_restore_data_and_runtime_recovery"
STATUS = "passed_bounded_apk_update_restore_not_whole_campaign"
MAX_ACTION_NS = 1800_000_000_000
MAX_REPLACEMENT_NS = 180_000_000_000
NONCE = re.compile(r"[0-9a-f]{32}")
STAGE_COMMANDS = {
    "activities": ("dumpsys", "activity", "activities"),
    "fixture": ("dumpsys", "activity", scene_audit.FIXTURE),
    "windows": ("dumpsys", "window", "windows"),
    "window_displays": ("dumpsys", "window", "displays"),
    "input": ("dumpsys", "input"), "display": ("dumpsys", "display"),
    "conformance": ("dumpsys", "activity", "service", runtime.SERVICE),
    "events": ("logcat", "-b", "events", "-d", "-v", "threadtime", "am_anr:I", "am_crash:I", "*:S"),
}


def source_contract(packet, receipt_sha256):
    """Small immutable selected-packet closure; no SDK/OS whole-image rehash."""
    packet = Path(packet).resolve(strict=True)
    require(sha256(packet / "receipt.json") == receipt_sha256, "Selected authenticated packet receipt changed")
    receipt = load(packet / "receipt.json")
    pair_claim = packet_tool.audit_conformance_version_update(packet, receipt["conformance_version_update"])
    require(receipt["security_compile"]["canary_source_sha256"] == packet_tool.UPDATE_CANARY_SHA256,
            "Compiled ordinary update canary source changed")
    for name, record in (("security.apk", receipt["artifacts"]["security"]),
                         ("security-build-receipt.json", receipt["security_compile"]["receipt"]),
                         ("security-source-freeze.json", receipt["security_compile"]["source_freeze"])):
        require(file_ref(packet / name) == {key: record[key] for key in ("sha256", "bytes")},
                "Selected compiled canary input changed: " + name)
    canary_source = lane.ROOT / "android/session-security/src/main/kotlin/org/wonad/desktop/security/UpdateDataInstrumentation.kt"
    require(sha256(canary_source) == packet_tool.UPDATE_CANARY_SHA256, "Current canary differs from compiled source")
    require(receipt["artifacts"]["security"]["certificate_der_sha256"] == pair_claim["v1"]["certificate_der_sha256"],
            "Canary and conformance signer differ")
    require(receipt["artifacts"]["conformance"]["shared_uid"] is False and
            receipt["artifacts"]["conformance"]["privileged_manifest"] is False and
            receipt["artifacts"]["conformance"]["signers"] == 1, "Conformance packet is not an ordinary singleton signer")
    client = lane.bind_client_sources(packet)
    files = ("receipt.json", "conformance.apk", "security.apk", "security-build-receipt.json", "security-source-freeze.json",
        "conformance-version-update/preparation-receipt.json", "conformance-version-update/original.apk",
        "conformance-version-update/candidate.apk", "conformance-version-update/unsigned-version-only.apk")
    return {"packet": str(packet), "packet_receipt_sha256": receipt_sha256,
        "files": {name: file_ref(packet / name) for name in files}, "client_sources": client,
        "canary_source": {"path": str(canary_source), **file_ref(canary_source)}}


def attachment_manifest(manifest, contract):
    validate_manifest(manifest)
    receipt = load(Path(contract["packet"]) / "receipt.json")
    require(manifest["product_apk_present"] is False and
            manifest["packet"]["receipt_sha256"] == contract["packet_receipt_sha256"],
            "Not the selected source-matched policy-free candidate")
    for role in ("conformance", "security"):
        require(all(manifest["artifacts"][role][key] == receipt["artifacts"][role][key]
                    for key in ("sha256", "bytes", "package", "version_code", "certificate_der_sha256")),
                "Candidate APK differs from selected packet: " + role)
    update = manifest["conformance_version_update"]
    for role in ("v1", "v2"):
        require(all(update[role][key] == receipt["conformance_version_update"][role][key]
                    for key in receipt["conformance_version_update"][role]), "Candidate version-only APK differs")
    canary = manifest["update_data_canary"]
    require(canary["runner"] == packet_tool.UPDATE_CANARY_RUNNER and
            canary["source_sha256"] == packet_tool.UPDATE_CANARY_SHA256 and
            {key: canary["compile_receipt"][key] for key in ("sha256", "bytes")} == receipt["security_compile"]["receipt"] and
            {key: canary["source_freeze"][key] for key in ("sha256", "bytes")} == receipt["security_compile"]["source_freeze"],
            "Candidate compiled canary proof differs")


def installed_package(raw, uid, version):
    require(re.findall(r"^\s*Package \[([^]]+)\] \([^\n]*\):", raw, re.M) == [APP],
            "Installed package dump is not the singleton target")
    # Pinned Settings.dumpPackageLPr prints appId, not the historical userId
    # spelling. Original user-0 forward/reverse PackageManager rows bind UID.
    require(re.findall(r"^\s*appId=(\d+)\s*$", raw, re.M) == [str(uid)] and 10000 <= uid <= 19999 and
            re.findall(r"^\s*versionCode=(\d+)\b", raw, re.M) == [str(version)],
            "Installed version/ordinary UID differs")
    flags = re.findall(r"^\s*flags=\[([^]]*)\]\s*$", raw, re.M)
    require(len(flags) == 1 and not {"DEBUGGABLE", "SYSTEM", "UPDATED_SYSTEM_APP"}.intersection(flags[0].split()),
            "Target flags are not ordinary non-debuggable")
    require(not re.search(r"\b(?:PRIVILEGED|PRIVATE_FLAG_PRIVILEGED)\b", raw) and
            not re.search(r"^\s*sharedUser(?:Id)?=(?!null\b|None\b)[^\s]+", raw, re.M),
            "Installed privileged/shared identity changed")
    # This conformance binary manifest has no uses-permission entries. Neither
    # mutation repairs nor inherited grant state may supply special privileges.
    # Settings.java emits this heading ONLY for a nonempty request set. The
    # ordinary conformance manifest requests/declares none, so its absence is
    # required; an invented empty heading is not an actual Android observation.
    require(not re.search(r"^\s*(?:requested|declared) permissions:\s*$", raw, re.M) and
            not re.search(r"^\s*[^\s:]+: granted=true\b|^\s*android\.permission\.", raw, re.M),
            "Conformance permissions/grants changed")
    require(re.findall(r"^\s*User 0:.*?\binstalled=(true|false)\b", raw, re.M) == ["true"],
            "Target is not installed for original owner")
    extra = {}
    for key, optional in (("privateFlags", True), ("pkgFlags", False), ("privatePkgFlags", False)):
        values = re.findall(r"^\s*" + key + r"=\[([^]]*)\]\s*$", raw, re.M)
        require(len(values) == 1 or optional and not values, "Missing/ambiguous actual PackageManager flags: " + key)
        extra[key] = sorted(values[0].split()) if values else []
    return {"uid": uid, "version_code": version, "flags": sorted(flags[0].split()), **extra}


def literal(root, relative):
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute() and
            all(part not in ("", ".", "..") for part in relative.split("/")), "Unsafe raw evidence path")
    path = root / relative
    require(not path.is_symlink() and path.resolve(strict=True).is_relative_to(root), "Escaped/symlinked evidence")
    return path


class Raw:
    def __init__(self, root, trace, evidence, identity):
        self.root, self.trace, self.evidence, self.identity = root, trace, evidence, identity
        self.used = set()
        self.prefix = ["docker", "exec", identity["container_id"], "adb", "-s", SERIAL]
        prior = -1
        for index, row in enumerate(trace):
            require(row["sequence"] == index and type(row["started_monotonic_ns"]) is int and
                    type(row["ended_monotonic_ns"]) is int and
                    row["started_monotonic_ns"] >= prior and row["ended_monotonic_ns"] >= row["started_monotonic_ns"],
                    "Trace order/clock changed")
            prior = row["started_monotonic_ns"]
            if "evidence" in row:
                require(row["evidence"] in evidence and row["output_sha256"] == evidence[row["evidence"]]["sha256"],
                        "Raw trace file is not independently sealed")

    def command(self, relative, suffix, *, start=0, end=None, binary=False):
        matches = [row for row in self.trace[start:end] if row.get("evidence") == relative]
        require(len(matches) == 1, "Missing/duplicated original raw command: " + relative)
        row = matches[0]
        require(row["kind"] == "command" and row["returncode"] == 0 and row["argv"] == self.prefix + list(map(str, suffix)),
                "Raw command/return code differs: " + relative)
        self.used.add(row["sequence"])
        payload = literal(self.root, relative).read_bytes()
        return payload if binary else payload.decode()

    def other(self, row):
        self.used.add(row["sequence"])

    def owner(self, row):
        files = row["owner"]
        matches = [value for value in self.trace[row["trace_start"]:row["trace_end"]]
                   if value.get("evidence") == files["inspect"]]
        require(len(matches) == 1 and matches[0]["argv"] == ["docker", "container", "inspect", self.identity["container_id"]]
                and matches[0]["kind"] == "command" and matches[0]["returncode"] == 0, "Original owned container inspect absent")
        self.other(matches[0])
        info = json.loads(literal(self.root, files["inspect"]).read_text())
        require(isinstance(info, list) and len(info) == 1, "Owned container is ambiguous")
        sampler.verify_owner(info[0], self.identity)
        for key, argv in {"manifest": ["docker", "exec", self.identity["container_id"], "cat", "/opt/wonad/manifest.json"],
                          "root_diff": ["docker", "container", "diff", self.identity["container_id"]]}.items():
            rows = [value for value in self.trace[row["trace_start"]:row["trace_end"]] if value.get("evidence") == files[key]]
            require(len(rows) == 1 and rows[0]["kind"] == "command" and rows[0]["returncode"] == 0 and rows[0]["argv"] == argv,
                    "Original immutable candidate root read missing")
            self.other(rows[0])
        require(not any(re.fullmatch(r"[ACD] /opt/wonad(?:/.*)?", line) for line in literal(self.root, files["root_diff"]).read_text().splitlines()),
                "Candidate read-only APK/source root changed")
        commands = {"boot": ("shell", "cat", "/proc/sys/kernel/random/boot_id"),
                    "fingerprint": ("shell", "getprop", "ro.build.fingerprint"),
                    "user": ("shell", "am", "get-current-user"),
                    "consent": ("shell", "settings", "--user", "0", "get", "secure", "wonad_external_desktop_enabled"),
                    "selinux": ("shell", "getenforce"), "build_type": ("shell", "getprop", "ro.build.type"),
                    "boot_completed": ("shell", "getprop", "sys.boot_completed"), "abi": ("shell", "getprop", "ro.product.cpu.abi")}
        values = {key: self.command(files[key], command, start=row["trace_start"], end=row["trace_end"]).strip()
                  for key, command in commands.items()}
        require(values == {"boot": self.identity["boot_id"], "fingerprint": self.identity["fingerprint"], "user": "0",
                "consent": "1", "selinux": "Enforcing", "build_type": "userdebug", "boot_completed": "1", "abi": "x86_64"}, "Original owner/consent/OS fence changed")

    def canary_identity(self, paths, manifest):
        package = manifest["update_data_canary"]["instrumentation_apk"]["package"]
        path = self.command(paths["path"], ("shell", "pm", "path", "--user", "0", package))
        path = installed_apk_path(path, package, package_row=True)
        payload = self.command(paths["apk"], ("exec-out", "cat", path), binary=True)
        target = manifest["update_data_canary"]["instrumentation_apk"]
        require(len(payload) == target["bytes"] and hashlib.sha256(payload).hexdigest() == target["sha256"],
                "Installed canary is not the genuine compiled single-signer APK")

    def package(self, row, version, archive):
        low, high = row["trace_start"], row["trace_end"]
        files = row["package"]
        uids = {}
        for package, relative in files["uids"].items():
            raw = self.command(relative, ("shell", "cmd", "package", "list", "packages", "-U", "--user", "0", package), start=low, end=high)
            exact = scene_audit.raw_audit.package_manager_uid_row(raw, package)
            uids[package] = int(exact.rsplit(":", 1)[1])
        require(set(uids) == {APP, scene_audit.FIXTURE, scene_audit.raw_audit.SYSTEMUI}, "Authoritative UID roles omitted")
        for package, relative in files["reverse"].items():
            raw = self.command(relative, ("shell", "cmd", "package", "list", "packages", "-U", "--user", "0", "--uid", uids[package]), start=low, end=high)
            require(raw.splitlines() == [f"package:{package} uid:{uids[package]}"], "Shared/cross-user UID is not singleton")
        require(set(files["reverse"]) == {APP, scene_audit.FIXTURE}, "Reverse UID proof missing")
        package_raw = self.command(files["dump"], ("shell", "dumpsys", "package", APP), start=low, end=high)
        privileges = installed_package(package_raw, uids[APP], version)
        path_raw = self.command(files["path"], ("shell", "pm", "path", "--user", "0", APP), start=low, end=high)
        installed_path = installed_apk_path(path_raw, APP, package_row=True)
        installed = self.command(files["apk"], ("exec-out", "cat", installed_path), start=low, end=high, binary=True)
        require(len(installed) == archive["bytes"] and hashlib.sha256(installed).hexdigest() == archive["sha256"],
                "Installed APK is not the exact authenticated version-only binary")
        return uids, privileges

    def stage(self, row, run, version, archive):
        self.owner(row)
        uids, privileges = self.package(row, version, archive)
        low, high = row["trace_start"], row["trace_end"]
        for key, command in STAGE_COMMANDS.items():
            self.command(row["files"][key], ("shell", *command), start=low, end=high)
        for name, process in row["processes"].items():
            self.command(process["pidof"], ("shell", "pidof", name), start=low, end=high)
            for field in ("before", "after"):
                self.command(process[field], ("shell", "su", "0", "cat", f"/proc/{process['pid']}/stat"), start=low, end=high)
        for slot, relative in row["frames"].items():
            if slot == "0":
                self.command(relative, ("exec-out", "screencap", "-p"), start=low, end=high, binary=True)
            else:
                copies = [value for value in self.trace[low:high] if value.get("evidence") == relative]
                require(len(copies) == 1 and copies[0]["kind"] == "command" and copies[0]["returncode"] == 0 and
                        copies[0]["argv"][:2] == ["docker", "cp"] and len(copies[0]["argv"]) == 4 and
                        copies[0]["argv"][3] == str(self.root / relative), "Frame copy is not exact original owned output")
                remote = copies[0]["argv"][2]
                remote_path = remote.split(":", 1)[1]
                request, filename = remote_path.rsplit("/", 1)
                require(remote.startswith(self.identity["container_id"] + ":") and
                        re.fullmatch(r"/state/phase1-conformance-update-[0-9a-f]{32}-[0-9a-f]{16}-" + slot, request) and
                        re.fullmatch(r"[A-Za-z0-9_.-]+\.png", filename), "Frame temporary path/owner changed")
                shots = [value for value in self.trace[low:copies[0]["sequence"]] if value.get("argv") ==
                         self.prefix + ["emu", "screenrecord", "screenshot", "--display", slot, request]]
                require(len(shots) == 1 and shots[0]["returncode"] == 0 and "OK" in shots[0].get("output", "") and
                        "KO:" not in shots[0].get("output", ""), "Frame lacks original exact screenshot request")
                self.other(shots[0]); self.other(copies[0])
                for args in (("mkdir", "-m", "700", "--", request),
                             ("find", request, "-maxdepth", "1", "-type", "f", "-name", "*.png", "-printf", "%f\\n"),
                             ("rm", "-rf", "--", request)):
                    candidates = [value for value in self.trace[low:high] if value.get("argv") ==
                                  ["docker", "exec", self.identity["container_id"], *args]]
                    require(len(candidates) == 1 and candidates[0]["kind"] == "command" and candidates[0]["returncode"] == 0,
                            "Original bounded capture lifecycle missing")
                    if args[0] == "find":
                        require(candidates[0].get("output", "").splitlines() == [filename], "Framebuffer discovery differs")
                    self.other(candidates[0])
        parsed = scene_audit.parse_stage(self.root, row, self.evidence, uids)
        require(parsed["status"]["run"] == run and parsed["status"]["failure"] is None, "Wrong/failed actual worker run")
        require({value["slot"] for value in parsed["displays"].values()} == {1, 2, 3}, "APK action requires all three mixed monitors")
        for slot, component in scene_audit.COMPONENTS.items():
            record = parsed["records"][component]
            require(parsed["displays"][record["native_display"]]["slot"] == slot, "Recovered task reached wrong connector")
            task = scene_audit.raw_audit.runtime_task(parsed, component)
            require(task["visible"] and task["input_enabled"], "Recovered task hidden/input disabled")
            window = scene_audit.raw_audit.task_window(parsed, component, record["task"], record["native_display"], record["uid"], parsed["identities"][component])
            scene_audit.raw_audit.task_input(parsed, component, record["uid"], record["native_display"], window)
            scene_audit.raw_audit.require_fixture_colors(parsed["frames"][slot], component, record)
        return parsed, uids, privileges


def runtime_argv(prefix, worker):
    return prefix + ["shell", "am", "instrument", "-w", "-r", "-e", "run", worker["run"],
        "-e", "mode", "runtime", "-e", "nonce", worker["nonce"], "-e", "phase", "start", runtime.RUNNER]


def canary_argv(prefix, seed, mode):
    return prefix + ["shell", "am", "instrument", "-w", "-r", "-e", "mode", mode,
        "-e", "run", seed["run"], "-e", "nonce", seed["nonce"], packet_tool.UPDATE_CANARY_RUNNER]


def audit_action(root, report):
    """Replay original same-guest evidence; no summary-only transition passes."""
    root = Path(root).resolve(strict=True)
    require(type(report.get("schema")) is int and report["schema"] == 1 and report.get("kind") == KIND and report.get("scope") == SCOPE and
            report.get("status") == STATUS and all(report.get(key) is False for key in
            ("runtime_qualified", "qualification_claimed", "whole_campaign_complete")), "Not a bounded conformance APK action")
    require(report.get("health_acceptance") == "unresolved_full_campaign_replacement_intervals_not_waived" and
            report.get("sampler_stopped_by_action") is False, "Action may not waive/pause continuous health")
    require(type(report["ordinal"]) is int and report["ordinal"] >= 1 and NONCE.fullmatch(report["action_nonce"]), "Action identity absent")
    require(0 < report["ended_monotonic_ns"] - report["started_monotonic_ns"] <= MAX_ACTION_NS, "Action exceeded original bounded scenario")
    contract = source_contract(report["contract"]["packet"], report["contract"]["packet_receipt_sha256"])
    require(contract == report["contract"], "Selected source/packet closure changed")
    hooked = report.get("health_permit_hooked", False)
    require(type(hooked) is bool, "Malformed optional health permit claim")
    if hooked: epoch_canary.require_compiled_epoch_canary(contract)
    manifest = load(literal(root, report["manifest"]))
    attachment_manifest(manifest, contract)
    trace = load(literal(root, report["trace"]))
    seed_trace = load(literal(root, report["seed"]["trace"]))
    contexts = [(root, trace, False), (root, seed_trace, False)]
    for relative, ref in report["evidence"].items():
        require(observations.reference_equal(observations.inventory_ref(literal(root, relative), root, contexts, report["identity"]["container_id"]), ref), "Original raw bytes changed")
    sources = report["host_sources"]
    import phase1_conformance_soak_apk_update as action
    expected = {"actor": Path(action.__file__).resolve(), "auditor": Path(__file__).resolve(),
                "runtime": Path(runtime.__file__).resolve(), "scenes": Path(scene_audit.__file__).resolve(),
                "transport": Path(lane.mechanics.__file__).resolve(), "owner": Path(sampler.__file__).resolve(),
                "packet": Path(packet_tool.__file__).resolve(), "canary_parser": Path(sys.modules[marker_result.__module__].__file__).resolve(),
                "apk_parser": Path(sys.modules[apk_pair.__module__].__file__).resolve(),
                "signer_parser": Path(sys.modules["native_wrong_signer_acceptance"].__file__).resolve()}
    expected["window_pixel_parser"] = Path(scene_audit.raw_audit.__file__).resolve()
    expected.update(clean_boot=Path(lane.__file__).resolve(), owner_raw_auditor=Path(sampler.owned_audit.__file__).resolve(),
                    common_schema=Path(common.__file__).resolve(), epoch_canary_parser=Path(epoch_canary.__file__).resolve(),
                    raw_observations=Path(observations.__file__).resolve(),
                    installed_path_parser=Path(sys.modules[installed_apk_path.__module__].__file__).resolve())
    require(set(sources) == set(expected), "Host closure omitted")
    for role, path in expected.items():
        require(sources[role] == {"path": str(path), **file_ref(path)}, "Host source changed: " + role)
    trace = load(literal(root, report["trace"]))
    raw = Raw(root, trace, report["evidence"], report["identity"])
    require(trace and trace[0]["started_monotonic_ns"] >= report["started_monotonic_ns"] and
            trace[-1]["ended_monotonic_ns"] <= report["ended_monotonic_ns"], "Trace escaped real outer action fences")
    packet = Path(contract["packet"])
    pair = apk_pair((packet / "conformance-version-update/original.apk").read_bytes(),
                    (packet / "conformance-version-update/candidate.apk").read_bytes())
    workers = report["workers"]
    require(len(workers) == 3 and len({value["run"] for value in workers}) == 3 and
            len({value["nonce"] for value in workers}) == 3 and all(NONCE.fullmatch(value[field]) for value in workers for field in ("run", "nonce")),
            "Three genuine fresh runtime run/nonces required")
    original_trace = load(literal(root, report["original_runtime_trace"]))
    original_starts = [row for row in original_trace if row.get("kind") == "background_start" and
                       row.get("id") == "instrumentation-" + workers[0]["run"]]
    require(len(original_starts) == 1 and original_starts[0]["argv"] == runtime_argv(raw.prefix, workers[0]) and
            original_starts[0]["started_monotonic_ns"] == workers[0]["started_monotonic_ns"] and
            type(workers[0]["host_pid"]) is int and workers[0]["host_pid"] > 0,
            "Original held self-target instrumentation is not journal bound")
    require([row["name"] for row in report["stages"]] == ["apk-before", "apk-updated", "apk-restored"], "APK stage omitted/duplicated")
    require(len(report["replacements"]) == 2, "Both genuine replacements required")
    if hooked:
        permits = [row.get("permit_id") for row in report["replacements"]]
        require(all(isinstance(value, str) and 0 < len(value) <= 256 for value in permits) and len(set(permits)) == 2,
                "Both provisional permit handles must be genuine distinct legs")
    else:
        require(not any(set(row).intersection({"permit_id", "permit_close", "recovered_stage_relative", "canary_epoch", "canary"})
                        for row in report["replacements"]), "Unhooked action may not invent permit/canary epoch evidence")
    seed = report["seed"]
    require(NONCE.fullmatch(seed["run"]) and NONCE.fullmatch(seed["nonce"]) and seed["contract"] == contract and seed["identity"] == report["identity"],
            "Original private-data seed is unbound")
    seed_trace = load(literal(root, seed["trace"]))
    seed_raw = Raw(root, seed_trace, report["evidence"], report["identity"])
    require(seed_trace and seed_trace[0]["started_monotonic_ns"] >= seed["started_monotonic_ns"] and
            seed_trace[-1]["ended_monotonic_ns"] <= seed["ended_monotonic_ns"] and
            seed["ended_monotonic_ns"] < workers[0]["started_monotonic_ns"] <= report["started_monotonic_ns"],
            "Seed must precede first actual held runtime")
    seed_raw.owner(seed["observation"])
    require(load(literal(root, seed["observation"]["owner"]["manifest"])) == manifest, "Seed actual image manifest differs")
    seed_uids, _ = seed_raw.package(seed["observation"], 1, pair["original"])
    canary_bundle = manifest["update_data_canary"]["instrumentation_apk"]["bundle_path"]
    seed_install = seed_raw.command(seed["install"], ("install", "-r", "-t", "--user", "0", canary_bundle))
    require(seed_install.strip().splitlines()[-1:] == ["Success"], "Ordinary canary install did not succeed")
    seed_raw.canary_identity(seed["canary_identity"], manifest)
    seed_payload = seed_raw.command(seed["marker"], canary_argv(seed_raw.prefix, seed, "create")[len(seed_raw.prefix):])
    marker_result(seed_payload, "create", seed["run"], seed["nonce"], seed_uids[APP], 1, report["identity"]["fingerprint"])
    require(seed_raw.used == set(range(len(seed_trace))), "Unreviewed/extra seed command")
    for prior, later in zip(report["stages"], report["stages"][1:]):
        require(prior["trace_end"] <= later["trace_start"] and prior["ended_monotonic_ns"] <= later["started_monotonic_ns"],
                "Overlapping/duplicated APK observations")
    parsed = []
    for index, (stage, worker) in enumerate(zip(report["stages"], workers)):
        require(type(stage["trace_start"]) is int and type(stage["trace_end"]) is int and
                0 <= stage["trace_start"] < stage["trace_end"] <= len(trace) and
                stage["started_monotonic_ns"] <= trace[stage["trace_start"]]["started_monotonic_ns"] and
                trace[stage["trace_end"] - 1]["ended_monotonic_ns"] <= stage["ended_monotonic_ns"], "Raw stage escaped original fences")
        result, uids, privileges = raw.stage(stage, worker["run"], 2 if index == 1 else 1, pair["candidate" if index == 1 else "original"])
        require(load(literal(root, stage["owner"]["manifest"])) == manifest, "Stage actual image manifest differs")
        baseline_privileges = installed_package(literal(root, report["stages"][0]["package"]["dump"]).read_text(), seed_uids[APP], 1)
        require(uids == seed_uids and {key: value for key, value in privileges.items() if key != "version_code"} ==
            {key: value for key, value in baseline_privileges.items() if key != "version_code"}, "Ordinary UID/exact privilege flags changed")
        require(worker["epoch"] == result["processes"][APP], "Held worker PID/start does not rederive from original raw")
        parsed.append(result)
    original = parsed[0]
    require(all(scene_audit.task_tokens(stage) == scene_audit.task_tokens(original) for stage in parsed[1:]),
            "System-server-owned opaque task identity changed during APK replacement")
    require(len({stage["status"]["snapshot"]["generation"] for stage in parsed}) == 3,
            "Each actual replacement must acquire a fresh broker lease generation")
    for stage, worker, replacement, capture in zip(parsed[1:], workers[1:], report["replacements"], report["stages"][1:]):
        ready_index = worker.get("ready_sequence")
        require(type(ready_index) is int and 0 <= ready_index < len(trace), "Fresh worker initial nonce/reopen proof missing")
        ready_row = trace[ready_index]
        poll_argv = raw.prefix + ["shell", "dumpsys", "activity", "service", runtime.SERVICE]
        require(ready_row.get("argv") == poll_argv and ready_row.get("returncode") == 0,
                "Fresh worker initial nonce/reopen command differs")
        ready = runtime.parse_status(ready_row["output"])
        require(ready["run"] == worker["run"] and ready["failure"] is None and ready["state"] == "ready" and
                ready["handshake"] == {"nonce": worker["nonce"], "phase": "start", "result": "accepted"},
                "Fresh worker initial nonce/reopen acknowledgement differs")
        proof = replacement.get("copied_frame", {})
        ack_index = proof.get("ack_sequence")
        require(type(ack_index) is int and ready_index < ack_index < capture["trace_start"], "Copied-frame acknowledgement missing/outside recovery")
        ack_row = trace[ack_index]
        require(ack_row.get("argv") == poll_argv and ack_row.get("returncode") == 0, "Copied-frame acknowledgement command differs")
        ack = runtime.parse_status(ack_row["output"])
        handshake = ack["handshake"]
        require(ack == proof.get("status") and ack["run"] == worker["run"] and ack["failure"] is None and
                ack["control_error"] is None and ack["state"] == "ready" and
                handshake["phase"] == "copy-observed" and handshake["result"] == "accepted" and
                NONCE.fullmatch(handshake["nonce"]) and handshake["nonce"] != worker["nonce"] and
                stage["status"]["handshake"] == handshake, "Copied-frame APPLIED acknowledgement differs/rejected")
        require(all(ack["snapshot"][key] == ready["snapshot"][key] == stage["status"]["snapshot"][key]
                    for key in ("generation", "identity_epoch")) and
                ack["snapshot"]["revision"] >= ready["snapshot"]["revision"], "Copied-frame fresh generation/epoch differs")
        commands = [row for row in trace[ready_index + 1:ack_index] if row.get("argv") ==
                    poll_argv + ["runtime-command", worker["run"], handshake["nonce"], "copy-observed"]]
        require(len(commands) == 1, "Exact copied-frame command missing/duplicated")
        command = commands[0]
        import phase1_conformance_recents_acceptance as recents_audit
        topology_rows = [row for row in trace[ready_index + 1:command["sequence"]]
                         if row.get("argv") == raw.prefix + ["shell", "dumpsys", "display"]]
        require(topology_rows and all(row.get("returncode") == 0 and
                sorted(recents_audit.logical_displays(row["output"])) ==
                sorted(display["display_id"] for display in ready["snapshot"]["display_incarnations"])
                for row in topology_rows), "Copied-frame topology poll differs from current lease")
        for row in topology_rows:
            raw.other(row)
        marker = runtime.CONTROL_MARKER + f"accepted {worker['run']} {handshake['nonce']} copy-observed"
        require(command.get("returncode") == 0 and sum(line.strip() == marker for line in command.get("output", "").splitlines()) == 1 and
                worker["started_monotonic_ns"] <= ready_row["started_monotonic_ns"] <= ready_row["ended_monotonic_ns"] <=
                command["started_monotonic_ns"] <= command["ended_monotonic_ns"] <= ack_row["started_monotonic_ns"] <=
                ack_row["ended_monotonic_ns"] <= capture["started_monotonic_ns"], "Copied-frame command/acknowledgement fences differ")
        raw.other(command)
    require({name: original["processes"][name] for name in scene_audit.OS_NAMES} == report["core_epochs"], "Original OS epochs unbound")
    for stage in parsed[1:]:
        require(stage["identities"] == original["identities"], "Native Task/Activity/Binder/instance/UID lifetime changed")
        require(stage["displays"] == original["displays"], "Native mixed-monitor display incarnation changed")
        for component in scene_audit.COMPONENTS.values():
            require(all(stage["records"][component][field] == original["records"][component][field]
                for field in ("native_display", "left", "top", "right", "bottom")), "Observed task placement changed")
        require({name: stage["processes"][name] for name in scene_audit.OS_NAMES} == report["core_epochs"], "Protected four OS/phone epochs changed")
    for index, replacement in enumerate(report["replacements"]):
        old, new = workers[index:index + 2]
        require(old["epoch"] != new["epoch"], "Required actual client epoch replacement missing")
        require(0 < replacement["ended_monotonic_ns"] - replacement["started_monotonic_ns"] <= MAX_REPLACEMENT_NS and
                report["stages"][index]["ended_monotonic_ns"] <= replacement["started_monotonic_ns"] <=
                old["ended_monotonic_ns"] <= new["started_monotonic_ns"] <= report["stages"][index + 1]["started_monotonic_ns"] <=
                report["stages"][index + 1]["ended_monotonic_ns"] <= replacement["ended_monotonic_ns"],
                "Replacement interval/owned worker fences changed")
        role = "v2" if index == 0 else "v1"
        suffix = ("install", "-r", *( ("-d",) if index == 1 else ()), "--user", "0", manifest["conformance_version_update"][role]["bundle_path"])
        installed = raw.command(replacement["install"], suffix)
        require(installed.strip().splitlines()[-1:] == ["Success"], "Actual version-only installation failed")
        install_row = next(row for row in trace if row.get("evidence") == replacement["install"])
        require(replacement["started_monotonic_ns"] <= install_row["started_monotonic_ns"] <=
                install_row["ended_monotonic_ns"] <= old["ended_monotonic_ns"], "Install escaped real replacement fences")
        completion = [row for row in trace if row.get("kind") == "background_finish" and row.get("id") == "instrumentation-" + old["run"]]
        require(len(completion) == 1 and completion[0]["ended_monotonic_ns"] == old["ended_monotonic_ns"] and
                completion[0]["evidence"] == old["output"] and completion[0]["host_pid"] == old["host_pid"] and
                completion[0]["cause"] == "ordinary_exact_apk_replacement" and type(completion[0]["returncode"]) is int,
                "Old actual owned instrumentation completion is missing")
        raw.other(completion[0])
        starts = [row for row in trace if row.get("kind") == "background_start" and row.get("id") == "instrumentation-" + new["run"]]
        require(len(starts) == 1 and starts[0]["argv"] == runtime_argv(raw.prefix, new) and
                starts[0]["started_monotonic_ns"] == new["started_monotonic_ns"] and starts[0]["host_pid"] == new["host_pid"] and
                type(new["host_pid"]) is int and new["host_pid"] > 0, "Fresh actual self-target worker start is unbound")
        raw.other(starts[0])
        marker_row = next((row for row in trace if row.get("evidence") == replacement["marker"]), None)
        require(marker_row is not None and old["ended_monotonic_ns"] <= marker_row["started_monotonic_ns"] <=
                marker_row["ended_monotonic_ns"] <= new["started_monotonic_ns"], "Canary overlaps an owned runtime instrumentation")
        marker = raw.command(replacement["marker"], canary_argv(raw.prefix, seed, "read")[len(raw.prefix):])
        raw.canary_identity(replacement["canary_identity"], manifest)
        marker_result(marker, "read", seed["run"], seed["nonce"], seed_uids[APP], 2 if index == 0 else 1, report["identity"]["fingerprint"])
        if hooked:
            observed = epoch_canary.marker_epoch(marker, seed_uids[APP])
            descriptor = epoch_canary.command_receipt(marker, seed_uids[APP], replacement["marker"], report["trace"], marker_row)
            require(descriptor == replacement.get("canary"), "Canary epoch permit exceeds/differs from original exact instrumentation command")
            require(observed == replacement.get("canary_epoch") and
                    {key: observed[key] for key in ("pid", "start_ticks")} not in (old["epoch"], new["epoch"]),
                    "Intermediate real canary epoch absent/stale or differs from original raw")
            require(isinstance(replacement.get("permit_id"), str) and replacement["permit_id"] and
                    replacement.get("permit_close") == "provisional_pending_independent_complete_action_audit" and
                    load(literal(root, replacement["recovered_stage_relative"])) == report["stages"][index + 1],
                    "Provisional permit close is not bound to the exact recovered raw stage")
    for index, row in enumerate(trace):
        if index not in raw.used:
            require(row.get("kind") == "command" and row.get("returncode") == 0 and
                    row.get("argv") == raw.prefix + ["shell", "dumpsys", "activity", "service", runtime.SERVICE] and
                    isinstance(row.get("output"), str), "Unreviewed mutation/unbound command in action")
            status = runtime.parse_status(row["output"])
            require(any(status["run"] == worker["run"] and worker["started_monotonic_ns"] <= row["started_monotonic_ns"] <=
                        row["ended_monotonic_ns"] <= stage["started_monotonic_ns"] for worker, stage in zip(workers[1:], report["stages"][1:])),
                    "Runtime readiness poll escaped its real fresh-worker fence")
            raw.other(row)
    require(raw.used == set(range(len(trace))), "Original action trace incomplete")
    require(old["output"] in report["evidence"] and workers[0]["output"] in report["evidence"], "Completed old streams not preserved")
    return {"status": STATUS, "replacements": 2, "private_data_retained": True,
            "runtime_qualified": False, "whole_campaign_complete": False,
            "health_acceptance": report["health_acceptance"]}


def audit_report(path):
    path = Path(path).resolve(strict=True)
    require(path.name == "report.json" and path.parent.parent.name == "actions", "Wrong owned action report location")
    return audit_action(path.parent.parent.parent, load(path))
