#!/usr/bin/env python3
"""Actual current-owner RPC rejections then one exact client death/recovery.

Requires newly compiled TEST phase and foreign caller; current packet16 is NOT
such a packet. No SDK/OS permission, stale-token replay, sampler reset or PASS
substitute for the nine-action campaign.
"""
from pathlib import Path
from phase1_conformance_installed_path import installed_apk_path
import re
import secrets
import sys

import phase1_conformance_soak_client_death_action as death
import phase1_conformance_soak_malformed_calls_acceptance as acceptance
import conformance_malformed_calls as proof
from phase1_conformance_common import file_ref, load

attached, workers, FIELDS, MAX_TRANSITION_NS = death.attached, death.workers, death.FIELDS, death.MAX_TRANSITION_NS
runtime, health, require = death.runtime, death.health, death.require
FOREIGN = "org.wonad.desktop.test"
PHASE_SOURCES = (
    "android/conformance/src/main/kotlin/org/wonad/desktop/ConformanceMalformedCalls.kt",
    "android/conformance/src/main/kotlin/org/wonad/desktop/ConformanceRuntimeRunner.kt",
    "android/conformance/src/main/kotlin/org/wonad/desktop/ConformanceContract.kt",
    "android/conformance/src/main/kotlin/org/wonad/desktop/ConformanceService.kt",
    "android/conformance/src/main/AndroidManifest.xml")
FOREIGN_SOURCES = ("android/session-security/src/main/kotlin/org/wonad/desktop/security/NeutralMalformedCallerService.kt",
    "android/session-security/src/main/AndroidManifest.xml")


def source_contract():
    result = death.source_contract()
    result.update({key: {"path": str(Path(module.__file__).resolve()), **file_ref(Path(module.__file__).resolve())}
        for key, module in {"malformed_action": sys.modules[__name__], "malformed_auditor": acceptance, "malformed_marker": proof}.items()})
    root = Path(__file__).resolve().parents[2]
    result.update({relative: {"path": str(root / relative), **file_ref(root / relative)} for relative in PHASE_SOURCES + FOREIGN_SOURCES})
    return result


def require_compiled_phase(contract):
    # Existing actual immutable admission verifies signatures/payload/compiler
    # receipts. Add exact NEW TEST source bindings; never update old receipts.
    packet = Path(contract["packet"]); root = Path(__file__).resolve().parents[2]
    client = load(packet / "evidence/compile-input/source-freeze.json")["files"]
    security = load(packet / "security-source-freeze.json")["files"]
    require(all(client.get(relative) == file_ref(root / relative) for relative in PHASE_SOURCES),
        "Selected packet lacks genuinely compiled exact neutral malformed phase")
    require(all(security.get(relative) == file_ref(root / relative)["sha256"] for relative in FOREIGN_SOURCES),
        "Selected packet lacks genuinely compiled exact foreign caller service")
    require(file_ref(packet / "security.apk") == {key: load(packet / "receipt.json")["artifacts"]["security"][key]
        for key in ("sha256", "bytes")}, "Actual foreign APK differs from authenticated packet")


class MalformedCallsAction(death.ClientDeathAction):
    SCENARIO = "malformed_calls"
    ACTION_AUDIT = acceptance
    def current_sources(self): return source_contract()

    def foreign_apk_before(self):
        directory = self.prefix + '/foreign/before'
        files = {'path': directory + '/path.txt', 'apk': directory + '/installed.apk'}
        path = installed_apk_path(self.raw_read(files['path'], 'pm', 'path', '--user', '0', FOREIGN), FOREIGN, package_row=True)
        self.p.adb('exec-out', 'cat', path, evidence=files['apk'], binary=True)
        require(file_ref(self.p.output / files['apk']) == file_ref(Path(self.contract['packet']) / 'security.apk'),
            'Foreign APK differs from genuinely compiled packet BEFORE RPC phase')
        return files

    def foreign(self, label):
        directory = self.prefix + "/foreign/" + label
        files = {"uid": directory + "/uid.txt", "pid_before": directory + "/pid-before.txt", "ps_before": directory + "/ps-before.txt",
            "stat_before": directory + "/stat-before.txt", "status": directory + "/status.txt", "fd": directory + "/fd.txt",
            "stat_after": directory + "/stat-after.txt", "pid_after": directory + "/pid-after.txt", "ps_after": directory + "/ps-after.txt",
            "path": directory + "/path.txt", "apk": directory + "/installed.apk"}
        uid = attached.acceptance.package_uid(self.raw_read(files["uid"], "pm", "list", "packages", "-U", "--user", "0", FOREIGN), FOREIGN, 0)
        raw = {"pid_before": self.raw_read(files["pid_before"], "pidof", FOREIGN),
            "ps_before": self.raw_read(files["ps_before"], *health.PROCESS_TABLE_COMMAND)}
        pid = proof.foreign_pid(raw["pid_before"], raw["ps_before"], uid)
        for key in FIELDS[2:]:
            args = ("pidof", FOREIGN) if key.startswith("pid") else health.PROCESS_TABLE_COMMAND if key.startswith("ps") else (
                "su", "0", *(("ls", "-1") if key == "fd" else ("cat",)), f"/proc/{pid}/" + ("stat" if key in ("stat_before", "stat_after") else key))
            raw[key] = self.raw_read(files[key], *args)
        metric = proof.foreign_metric(raw, uid)
        path = installed_apk_path(self.raw_read(files["path"], "pm", "path", "--user", "0", FOREIGN), FOREIGN, package_row=True)
        self.p.adb("exec-out", "cat", path, evidence=files["apk"], binary=True)
        require(file_ref(self.p.output / files["apk"]) == file_ref(Path(self.contract["packet"]) / "security.apk"), "Foreign caller is not exact compiled packet APK")
        return {"files": files, "metric": metric}

    def before_death(self, before):
        require_compiled_phase(self.contract)
        foreign_before = self.foreign_apk_before()
        nonce = secrets.token_hex(16); command_sequence = len(self.p.trace)
        raw = self.command("dumpsys", "activity", "--user", "0", "service", runtime.SERVICE, "runtime-command",
            self.p.conformance_run, nonce, proof.PHASE)
        attached.acceptance.require_control_marker(raw, runtime.CONTROL_MARKER + f"accepted {self.p.conformance_run} {nonce} {proof.PHASE}")
        def finished():
            raw, status = self.status_raw()
            require(status["handshake"] != {"nonce": nonce, "phase": proof.PHASE, "result": "rejected"}, "Neutral malformed phase rejected")
            if status["handshake"] != {"nonce": nonce, "phase": proof.PHASE, "result": "accepted"} or status["state"] != "ready": return False
            value = proof.parse(raw)
            require(value is not None and value["run"] == self.p.conformance_run and value["nonce"] == nonce, "Actual neutral phase omitted exact proof")
            return value
        value = self.wait("actual foreign/stale/malformed rejection callbacks", finished)
        ack_sequence = self.p.trace[-1]["sequence"]
        after = self.capture("probe-after"); require(self.action["captures"].pop() is after, "Probe capture ordering changed")
        self.action["probe_after"] = after
        self.action["malformed"] = {"nonce": nonce, "command_sequence": command_sequence, "ack_sequence": ack_sequence,
            "proof": value, "foreign": self.foreign("observed"), 'foreign_before': foreign_before}
        acceptance.audit_probe(self.p.output, self.action, self.p.trace, before, self.contract, self.identity)
