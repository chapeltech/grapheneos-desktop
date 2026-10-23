#!/usr/bin/env python3
"""Verify dead Binder rejection and native input before a controlled client reconnects.

The test APK runs as Wonad's ordinary UID, without its policy service. It hides
two real windows, holds the dead session through a scoped SystemUI crash, and
does not open a new lease until the host independently verifies native input.
Only fresh isolated emulator userdata is changed; the demo remains a reference.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

from apk_update_smoke import APP, demo, require_no_policy_service
from desktop_smoke import phone_activity, task_visibility
from platform_gate import PACKAGE, bounds
from session_security_smoke import SessionSecuritySmoke, TEST
from systemui_death_smoke import DeathEmulator, SystemUiDeathSmoke, crash_evidence, same_lifetimes
from user_switch_smoke import native_identities

SCOPE = "systemui_death_dead_binders_and_native_input_before_reconnect"
RUNNER = TEST + "/org.wonad.desktop.security.SystemUiDeathInstrumentation"
ACTION = "org.wonad.desktop.test.NATIVE_RECOVERY_VERIFIED"
PHASES = ("ready_for_crash", "dead_calls_complete")


def status_records(output, run, uid):
    records = []
    for block in output.replace("\r\n", "\n").split("INSTRUMENTATION_STATUS_CODE: 1\n")[:-1]:
        pairs = re.findall(r"^INSTRUMENTATION_STATUS: ([a-z_]+)=([^\r\n]*)$", block, re.M)
        fields = dict(pairs)
        if len(pairs) != len(fields) or set(fields) != {"run", "phase", "generation", "owner_uid", "owner_pid"} or \
                fields["run"] != run or fields["owner_uid"] != str(uid) or not 10000 <= uid < 20000 or \
                len(records) >= len(PHASES) or fields["phase"] != PHASES[len(records)] or any(
                    not re.fullmatch(r"[1-9][0-9]*", fields[k]) or int(fields[k]) >= 2 ** 63
                    for k in ("generation", "owner_pid")):
            raise ValueError("Invalid SystemUI-death instrumentation phase or identity")
        entry = {**fields, "generation": int(fields["generation"]), "owner_pid": int(fields["owner_pid"])}
        if records and any(entry[k] != records[0][k] for k in ("generation", "owner_pid")):
            raise ValueError("SystemUI-death probe changed client identity")
        records.append(entry)
    return records


def check_result(output, fingerprint, run, uid, display, phase):
    def field(key):
        values = re.findall(r"^INSTRUMENTATION_RESULT: " + key + r"=([^\r\n]*)$", output, re.M)
        if len(values) != 1:
            raise ValueError("Missing or ambiguous SystemUI-death evidence: " + key)
        return values[0]
    expected = dict(systemui_binder_death="passed", scope=SCOPE, run=run, owner_uid=str(uid),
                    owner_pid=str(phase["owner_pid"]), old_generation=str(phase["generation"]),
                    display=str(display), fingerprint=fingerprint, native_abi="x86_64",
                    dead_session_calls="12", dead_broker_calls="3", owner_layout="applied")
    if any(field(k) != v for k, v in expected.items()) or \
            re.findall(r"^INSTRUMENTATION_CODE: ([^\r\n]*)$", output, re.M) != ["-1"] or any(
                x in output for x in ("failure_details=", "cleanup_error=", "shortMsg=", "INSTRUMENTATION_FAILED")):
        raise ValueError("Native SystemUI-death probe did not pass; see instrumentation.log")
    generation = field("new_generation")
    if not re.fullmatch(r"[1-9][0-9]*", generation) or int(generation) >= 2 ** 63 or int(generation) == phase["generation"]:
        raise ValueError("No new lease after SystemUI death")
    return {**expected, "new_generation": int(generation)}


class BinderDeathEmulator(DeathEmulator, SessionSecuritySmoke):
    label = "org.wonad.isolated-systemui-binder-death-test"
    name_prefix = "wonad-systemui-binder-death-"
    allowed_packages = (APP, TEST, PACKAGE)

    def exercise(self, base):
        before, identities = self.service(), base["task_ids"]
        original, _ = self.observe()
        tall = {c: bounds(r) for c, r in base["restored_tall"].items()}
        external = before["display"]
        native_before = native_identities(self.shell("dumpsys", "activity", "activities"), identities, 0)
        old_ui, server = self.systemui_pid(), self.pid("system_server")
        uid = self.owner.evidence["apks"][APP]["uid"]
        log = self.output / "instrumentation.log"
        self.guard()
        args = ["docker", "exec", self.identity, "adb", "-s", demo.SERIAL, "shell", "am", "instrument",
                "--user", "0", "-w", "-r", "-e", "run", self.run, RUNNER]
        with log.open("x") as stream:
            process = subprocess.Popen(args, stdout=stream, stderr=subprocess.STDOUT, text=True)
        self.owner.trace.append(dict(instrumentation_args=args, log=str(log), pid=process.pid))

        def phases():
            return status_records(log.read_text(), self.run, uid)

        def await_phase(name, timeout=40):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                entries = phases()
                for entry in entries:
                    if entry["phase"] == name:
                        return entry
                if process.poll() is not None:
                    raise ValueError("SystemUI-death probe ended before " + name + "; see instrumentation.log")
                time.sleep(.25)
            raise ValueError("SystemUI-death probe did not reach " + name)

        try:
            phase = await_phase("ready_for_crash")
            client = str(phase["owner_pid"])
            if phase["generation"] == before["generation"]:
                raise ValueError("Controlled client reused the normal policy lease")
            records, _ = self.observe()
            same_lifetimes(records, original, identities, external)
            activities = self.shell("dumpsys", "activity", "activities")
            if any(task_visibility(activities, identities.values()).values()) or \
                    native_identities(activities, identities, 0) != native_before:
                raise ValueError("Controlled client did not hide the same native windows")
            phone_before = phone_activity(activities)
            if phone_before is None or phone_before[0] != 0:
                raise ValueError("Missing foreground phone Activity")
            require_no_policy_service(self.shell("dumpsys", "activity", "service", APP + "/.DesktopService"))
            if self.pid(APP) != client or self.pid("system_server") != server:
                raise ValueError("Process identity changed before SystemUI crash")
            self.owner.evidence["before_crash"] = dict(probe=phase, tasks=records, native=native_before,
                systemui_pid=old_ui, system_server_pid=server, phone=phone_before)
            self.crash_systemui(old_ui)
            await_phase("dead_calls_complete", 20)

            def assert_paused():
                if process.poll() is not None or self.pid(APP) != client or len(phases()) != 2:
                    raise ValueError("Controlled client ended or changed before native input recovery")
                require_no_policy_service(self.shell("dumpsys", "activity", "service", APP + "/.DesktopService"))

            new_ui = self.native_recovery(client, server, old_ui, original, identities, native_before,
                                          external, tall, assert_paused)
            if phone_activity(self.shell("dumpsys", "activity", "activities")) != phone_before:
                raise ValueError("Native SystemUI recovery replaced the foreground phone Activity")
            assert_paused()
            self.owner.evidence["native_input_before_reconnect"] = True
            crash = self.shell("logcat", "-d", "-b", "crash", "--pid", old_ui)
            (self.output / "systemui-crash.txt").write_text(crash + "\n")
            self.owner.evidence["crash"] = crash_evidence(crash, old_ui)
            self.owner.evidence["new_systemui_pid"] = new_ui
            self.guard()
            reply = self.shell("am", "broadcast", "--user", 0, "-a", ACTION, "-p", APP, "--es", "run", self.run)
            if re.findall(r"^Broadcast completed: result=([0-9]+)$", reply, re.M) != ["0"]:
                raise ValueError("Test-only reconnect acknowledgement was not delivered")
            if process.wait(timeout=45) != 0:
                raise ValueError("SystemUI-death instrumentation command failed")
            self.owner.evidence["instrumentation"] = check_result(log.read_text(), self.fingerprint, self.run,
                                                                  uid, external, phase)
            if self.systemui_pid() != new_ui or self.pid("system_server") != server:
                raise ValueError("Platform process restarted again during controlled reconnect")
        finally:
            if process.poll() is None:
                self.guard()
                self.shell("am", "force-stop", "--user", 0, APP)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait(timeout=5)
        self.guard()
        self.shell("am", "force-stop", "--user", 0, APP)
        self.restore(before, identities, tall, original)
        if self.service()["generation"] in (phase["generation"], self.owner.evidence["instrumentation"]["new_generation"]):
            raise ValueError("Normal Wonad reused a controlled test lease")
        self.owner.evidence["normal_client_recovery"] = self.evidence


class BinderDeathSmoke(SystemUiDeathSmoke):
    emulator_type = BinderDeathEmulator
    scope = SCOPE


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-fingerprint", required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--original-apk", type=Path, required=True)
    parser.add_argument("--fixture-apk", type=Path, required=True)
    parser.add_argument("--test-apk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(demo.ROOT / "android/out") or output == demo.ROOT / "android/out":
        parser.error("Use a fresh private output directory under android/out")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    smoke = BinderDeathSmoke(args.expected_fingerprint, output)
    result = dict(systemui_death_smoke="not_passed", checks=smoke.evidence, full_backend_acceptance="not_passed")
    try:
        result = smoke.run_death(json.loads(args.baseline.read_text()), args.original_apk, args.fixture_apk,
                                test_path=args.test_apk)
        return 0
    except (ValueError, KeyError, OSError, subprocess.SubprocessError, ET.ParseError) as error:
        result["error"] = str(error)
        return 1
    finally:
        (output / "commands.json").write_text(json.dumps(smoke.trace, indent=2, default=str) + "\n")
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    sys.exit(main())
