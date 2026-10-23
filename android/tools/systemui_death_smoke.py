#!/usr/bin/env python3
"""Crash only the primary SystemUI in a fresh isolated emulator and require recovery.

The normal Wonad APK must reconnect without being restarted or given UI commands.
Native tasks, ActivityRecords and Java Activity instances must survive, including
windows hidden on another workspace and a previously floating window. The working
browser demo is a read-only reference. No shell window repair is permitted.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

from apk_update_smoke import APP, demo, digest
from credential_lock_smoke import CredentialLockSmoke
from desktop_smoke import phone_activity, task_visibility
from keyboard_smoke import KeyboardSmoke
from platform_gate import COMPONENTS, PACKAGE, bounds, same_tasks
from user_switch_smoke import native_identities, primary_systemui_process
from wrong_signer_smoke import FreshEmulator

SCOPE = "systemui_process_death_and_automatic_wonad_reconnect"
SYSTEMUI = "com.android.systemui"


def same_lifetimes(records, original, identities, display):
    if not same_tasks(records, identities, display) or any(
            records[c]["instance"] != original[c]["instance"] for c in identities):
        raise ValueError("SystemUI death replaced a native fixture task or Activity instance")


def crash_evidence(output, pid):
    # Crash-buffer records include both the injected exception and the exact
    # process PID. Do not accept an unrelated/historical SystemUI crash.
    if not re.search(r"Process: com\.android\.systemui, PID: " + re.escape(pid) + r"\b", output) or \
            "android.app.RemoteServiceException$CrashedByAdbException: shell-induced crash" not in output:
        raise ValueError("No exact shell-induced crash evidence for the original SystemUI process")
    return dict(process=SYSTEMUI, pid=int(pid), reason="shell-induced crash")


class DeathEmulator(FreshEmulator, KeyboardSmoke):
    label = "org.wonad.isolated-systemui-death-test"
    name_prefix = "wonad-systemui-death-"
    allowed_packages = (APP, PACKAGE)

    def pid(self, package):
        if package not in (APP, "system_server"):
            raise ValueError("Unexpected process identity query")
        output = self.shell("pidof", package)
        if not re.fullmatch(r"[1-9][0-9]*", output):
            raise ValueError("Expected exactly one process: " + package)
        return output

    def systemui_pid(self):
        return primary_systemui_process(
            self.shell("pm", "list", "packages", "-U", "--user", 0, SYSTEMUI),
            self.shell("ps", "-A", "-o", "UID,PID,NAME"))

    def crash_systemui(self, expected_pid):
        self.guard()
        if self.systemui_pid() != expected_pid:
            raise ValueError("SystemUI identity changed before the scoped crash")
        # Target a resolved package and explicit user, never a stale PID, shared
        # UID, process-name signal, system_server, or the working demo container.
        output = self.shell("am", "crash", "--user", 0, SYSTEMUI)
        if output:
            raise ValueError("Unexpected SystemUI crash command response: " + output)

    def native_recovery(self, client, server, old_ui, original, identities, native_before, external, rectangles,
                        assert_paused):
        """Require an independently checked absence of client-driven repair."""
        deadline = time.monotonic() + 60
        observations = []
        self.owner.evidence["native_observations"] = observations
        new_ui = None
        while time.monotonic() < deadline:
            assert_paused()
            if self.pid("system_server") != server:
                raise ValueError("Native SystemUI recovery replaced system_server")
            records, _ = self.observe()
            same_lifetimes(records, original, identities, external)
            activities = self.shell("dumpsys", "activity", "activities")
            if native_identities(activities, identities, 0) != native_before:
                raise ValueError("Native SystemUI recovery replaced a Task or ActivityRecord")
            processes = self.shell("ps", "-A", "-o", "UID,PID,NAME")
            if re.search(r"\bcom\.android\.systemui\s*$", processes, re.M):
                current_ui = primary_systemui_process(
                    self.shell("pm", "list", "packages", "-U", "--user", 0, SYSTEMUI), processes)
                if current_ui != old_ui:
                    if new_ui is not None and new_ui != current_ui:
                        raise ValueError("SystemUI entered a repeated native-recovery crash loop")
                    new_ui = current_ui
            visible = task_visibility(activities, identities.values())
            observations.append(dict(systemui_pid=new_ui, tasks=records, visibility=visible))
            if new_ui is not None and all(visible.values()) and all(
                    bounds(records[c]) == box for c, box in rectangles.items()):
                break
            time.sleep(.5)
        else:
            raise ValueError("Android did not restore the desktop before client reconnection")
        self.wait_for_transitions()
        input_checks = {}
        for component in COMPONENTS:
            assert_paused()
            records, attempts = self.mouse_focus(component, rectangles[component], external, "native SystemUI recovery")
            counts = {c: r["key_downs"] for c, r in records.items()}
            self.shell("input", "keyboard", "-d", external, "keyevent", "KEYCODE_B")
            records, _ = self.until(lambda r, d: same_tasks(r, identities, external) and all(
                r[c]["key_downs"] == count + (c == component) for c, count in counts.items()), "native SystemUI recovery input")
            same_lifetimes(records, original, identities, external)
            assert_paused()
            if self.systemui_pid() != new_ui:
                raise ValueError("SystemUI crashed again during native input recovery")
            input_checks[component] = dict(tasks=records, mouse_attempts=attempts)
        self.owner.evidence["native_input"] = input_checks
        return new_ui

    def exercise(self, base):
        state, identities = self.service(), base["task_ids"]
        original, _ = self.observe()
        tall = {c: bounds(r) for c, r in base["restored_tall"].items()}
        external = state["display"]
        native_before = native_identities(self.shell("dumpsys", "activity", "activities"), identities, 0)
        phone_before = phone_activity(self.shell("dumpsys", "activity", "activities"))
        if phone_before is None or phone_before[0] != 0:
            raise ValueError("No foreground owner phone Activity before the crash")
        self.mouse_focus(COMPONENTS[0], tall[COMPONENTS[0]], external, "SystemUI death setup")
        self.chord(external, "F")
        prepared, _, _ = self.await_keyboard(state, identities, "float before SystemUI death",
            lambda s, r, v: all(v.values()) and bounds(r[COMPONENTS[1]]) == state["area"] and
                bounds(r[COMPONENTS[0]]) != state["area"])
        self.chord(external, "2")
        hidden, records, visible = self.await_keyboard(prepared, identities, "hide before SystemUI death",
            lambda s, r, v: s["workspace"] == 2 and not any(v.values()))
        same_lifetimes(records, original, identities, external)
        old_ui, client, server = self.systemui_pid(), self.pid(APP), self.pid("system_server")
        self.owner.evidence["before_crash"] = dict(systemui_pid=old_ui, client_pid=client, system_server_pid=server,
            service=hidden, tasks=records, visibility=visible, native=native_before, phone=phone_before)
        new_ui = None
        self.crash_systemui(old_ui)
        print("Requested primary-user SystemUI crash in the isolated emulator", flush=True)
        deadline = time.monotonic() + 60
        observations = []
        self.owner.evidence["reconnect_observations"] = observations
        while time.monotonic() < deadline:
            if self.pid(APP) != client or self.pid("system_server") != server:
                raise ValueError("SystemUI failure restarted Wonad or system_server")
            processes = self.shell("ps", "-A", "-o", "UID,PID,NAME")
            if re.search(r"\bcom\.android\.systemui\s*$", processes, re.M):
                current_ui = primary_systemui_process(
                    self.shell("pm", "list", "packages", "-U", "--user", 0, SYSTEMUI), processes)
                if current_ui != old_ui:
                    if new_ui is not None and new_ui != current_ui:
                        raise ValueError("SystemUI entered a repeated crash loop")
                    new_ui = current_ui
            records, _ = self.observe()
            same_lifetimes(records, original, identities, external)
            activities = self.shell("dumpsys", "activity", "activities")
            if native_identities(activities, identities, 0) != native_before:
                raise ValueError("SystemUI failure replaced a native Task or ActivityRecord")
            try:
                current = self.service()
            except ValueError:
                current = None  # The normal client may have no snapshot while reconnecting.
            observations.append(dict(systemui_pid=new_ui, service=current,
                                     visibility=task_visibility(activities, identities.values())))
            if new_ui is not None and current is not None and current["generation"] != state["generation"] and \
                    current["display"] == external and current["workspace"] == 1 and current["tasks"] == 2 and \
                    not current["pending"] and all(observations[-1]["visibility"].values()) and \
                    all(bounds(records[c]) == box for c, box in tall.items()):
                break
            time.sleep(.5)
        else:
            raise ValueError("The same Wonad process did not automatically recover the original desktop")
        crash = self.shell("logcat", "-d", "-b", "crash", "--pid", old_ui)
        (self.output / "systemui-crash.txt").write_text(crash + "\n")
        self.owner.evidence["crash"] = crash_evidence(crash, old_ui)
        self.owner.evidence["new_systemui_pid"] = new_ui
        self.owner.evidence["automatic_reconnect"] = current
        self.guard()
        self.wait_for_transitions()
        if phone_activity(self.shell("dumpsys", "activity", "activities")) != phone_before:
            raise ValueError("SystemUI death replaced the foreground phone Activity")
        input_checks = {}
        for component in COMPONENTS:
            records, attempts = self.mouse_focus(component, tall[component], external, "SystemUI recovery")
            counts = {c: r["key_downs"] for c, r in records.items()}
            self.shell("input", "keyboard", "-d", external, "keyevent", "KEYCODE_B")
            records, _ = self.until(lambda r, d: same_tasks(r, identities, external) and all(
                r[c]["key_downs"] == count + (c == component) for c, count in counts.items()), "SystemUI recovery input")
            same_lifetimes(records, original, identities, external)
            input_checks[component] = dict(tasks=records, mouse_attempts=attempts)
        self.owner.evidence["recovered_input"] = input_checks
        # Confirm the newly registered shortcut lease drives real Haskell policy,
        # not merely a stale service status or ordinary Android pointer focus.
        before = self.service()
        self.chord(external, "2")
        changed, _, _ = self.await_keyboard(before, identities, "workspace after SystemUI restart",
            lambda s, r, v: s["workspace"] == 2 and not any(v.values()))
        self.chord(external, "1")
        final, records, _ = self.await_keyboard(changed, identities, "return after SystemUI restart",
            lambda s, r, v: s["workspace"] == 1 and all(v.values()) and all(bounds(r[c]) == box for c, box in tall.items()))
        same_lifetimes(records, original, identities, external)
        if self.pid(APP) != client or self.pid("system_server") != server or self.systemui_pid() != new_ui:
            raise ValueError("Recovery replaced an expected surviving process")
        self.owner.evidence["shortcut_recovery"] = final


class SystemUiDeathSmoke(CredentialLockSmoke):
    emulator_type = DeathEmulator
    scope = SCOPE

    def extra_packages(self, product, artifacts, trusted):
        return []

    def prepare_baseline(self, fresh):
        return fresh.run_checks()

    def run_death(self, baseline, original_path, fixture_path, test_path=None):
        before = self.resume_baseline(baseline)
        original = self.inspect(original_path, "original")
        if original["sha256"] != before[4][APP]["sha256"]:
            raise ValueError("Original APK differs from the live baseline")
        fixture = self.input_copy(fixture_path, "fixture.apk")
        if digest(fixture) != before[4][PACKAGE]["sha256"]:
            raise ValueError("Fixture differs from the live baseline")
        self.evidence["input_apks"] = dict(original=original["sha256"], fixture=digest(fixture))
        packages = [(APP, Path(original["path"])), (PACKAGE, fixture)]
        if test_path is not None:
            from session_security_smoke import TEST
            tests = self.input_copy(test_path, "test.apk")
            self.verify_test_apk(tests, original["signer"])
            self.evidence["input_apks"]["tests"] = digest(tests)
            packages.append((TEST, tests))
        info = demo.container(); self.assert_owned()
        product = next(Path(m["Source"]).resolve(strict=True) for m in info["Mounts"] if m["Destination"] == "/product")
        packages.extend(self.extra_packages(product, before[4], original["signer"]))
        fresh = self.emulator_type(self, product, uuid.uuid4().hex)
        try:
            fresh.start()
            self.evidence["os_artifacts"] = fresh.os_artifacts(before[4])
            self.evidence["environment"] = fresh.enable_external_desktop(original["signer"])
            self.evidence["apks"] = {p: fresh.install_new(p, path) for p, path in packages}
            base = self.prepare_baseline(fresh)
            (self.output / "isolated-layout-baseline.json").write_text(json.dumps(base, indent=2) + "\n")
            fresh.exercise(base)
            fresh.os_artifacts(before[4])
        except Exception as error:
            self.evidence["operation_error"] = str(error)
            try:
                fresh.guard()
                for name, args in (
                    ("failure-activities", ("dumpsys", "activity", "activities")),
                    ("failure-windows", ("dumpsys", "window", "windows")),
                    ("failure-fixtures", ("dumpsys", "activity", PACKAGE)),
                    ("failure-shell", ("dumpsys", "activity", "service", SYSTEMUI + "/.SystemUIService", "WMShell")),
                    ("failure-crash", ("logcat", "-d", "-b", "crash")),
                    ("failure-system-log", ("logcat", "-d", "-b", "main", "-b", "system", "-s",
                        "WonadBroker:V", "WonadDesktop:V", "WonadFocus:I", "ActivityTaskManager:I", "ActivityManager:I", "ShellDesktopMode:V"))):
                    (self.output / (name + ".txt")).write_text(fresh.shell(*args) + "\n")
            except Exception as diagnostic_error:
                self.evidence["diagnostic_error"] = str(diagnostic_error)
            raise
        finally:
            fresh.stop()
            self.assert_owned()
            if self.resume_baseline(baseline) != before:
                raise ValueError("Working demo changed during isolated SystemUI crash test")
            self.evidence["reference_unchanged"] = True
        return dict(systemui_death_smoke="passed", scope=self.scope,
                    fingerprint=self.fingerprint, run=fresh.run,
                    checks=self.evidence, full_backend_acceptance="not_passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-fingerprint", required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--original-apk", type=Path, required=True)
    parser.add_argument("--fixture-apk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(demo.ROOT / "android/out") or output == demo.ROOT / "android/out":
        parser.error("Use a fresh private output directory under android/out")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    smoke = SystemUiDeathSmoke(args.expected_fingerprint, output)
    result = dict(systemui_death_smoke="not_passed", checks=smoke.evidence, full_backend_acceptance="not_passed")
    try:
        result = smoke.run_death(json.loads(args.baseline.read_text()), args.original_apk, args.fixture_apk)
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
