#!/usr/bin/env python3
"""Repeatable ordinary lock/user actions on ONE admitted populated TEST guest.

No boot, APK, grant, policy-service or app privilege path. These three actions
are attachment components, never a complete 86400-second campaign producer.
"""
from pathlib import Path
import json
import re
import secrets
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

import conformance_runtime as runtime
import phase1_conformance_soak_expectation as expectation
import phase1_conformance_soak_hotplug_slice as admission
import phase1_conformance_soak_sampler as sampler
import phase1_conformance_soak_health as health
import phase1_conformance_soak_lock_user_acceptance as acceptance
import lock_smoke as lock
import user_switch_smoke as user_helpers
import phase1_conformance_current_client as current_client
from phase1_conformance_common import canonical, file_ref, load

require = runtime.require
SCENARIOS = ("credential_sleep", "credential_key", "user_switch")


def admit_role_uids(test, label):
    """Return actual user0 UID bindings for explicit continuous observer use.

    No UID is inferred from a status summary, selected dynamically by active
    user, or replaced on a missing read. Caller must independently raw-bind
    this original proof to its admitted held-runtime/whole-guest context.
    """
    require(re.fullmatch(r"[a-z][a-z0-9-]{1,63}", label), "Literal fresh UID observation label required")
    require(Path(test.output).resolve(strict=True) == Path(test.output) and not (test.output / label).exists() and
        not (test.output / label).is_symlink(), "Never reuse/alias UID admission")
    files, bindings, epochs = {}, {}, {}
    for role, package in health.contract.PROCESS_NAMES.items():
        def read(kind, *command):
            relative = label + "/" + role + "-" + kind + ".txt"
            raw, record = health.read_new(test, relative, *command)
            files[role + "-" + kind] = record
            return raw
        uid = 1000 if role == "system_server" else acceptance.package_uid(read("package-uid", "pm", "list", "packages", "-U", "--user", "0", package), package, 0)
        raw = {"pid_before": read("pid-before", "pidof", package), "ps_before": read("ps-before", *health.PROCESS_TABLE_COMMAND)}
        pid = health.qualified_pid(raw["pid_before"], raw["ps_before"], package, uid)
        for kind, command in (("stat_before", ("su", "0", "cat", f"/proc/{pid}/stat")),
            ("status", ("su", "0", "cat", f"/proc/{pid}/status")), ("fd", ("su", "0", "ls", "-1", f"/proc/{pid}/fd")),
            ("stat_after", ("su", "0", "cat", f"/proc/{pid}/stat")), ("pid_after", ("pidof", package)), ("ps_after", health.PROCESS_TABLE_COMMAND)):
            raw[kind] = read(kind.replace("_", "-"), *command)
        value = acceptance.process_metric(raw, uid, package)
        bindings[role] = uid; epochs[role] = {key: value[key] for key in ("pid", "start_ticks")}
    return {"kind": "original_owned_user0_role_uid_admission_v1", "identity": test.sampler_identity,
        "role_uids": bindings, "epochs": epochs, "files": files, "sources": source_contract(),
        "observer_authority": "explicit_TEST_read_only_userdebug_root_proc_stat_status_fd"}


def source_contract():
    return {name: {"path": str(Path(module.__file__).resolve()), **file_ref(Path(module.__file__).resolve())}
        for name, module in {"actions": sys.modules[__name__], "auditor": acceptance,
            "expected_revocation": expectation, "runtime": runtime, "ordinary_keyguard": lock,
            "ordinary_users": user_helpers, "admitted_slice": admission, "owned_sampler": sampler,
            "raw_health": health, "inactive_input": acceptance.input_consumers,
            "current_client_admission": current_client}.items()}


class Actions:
    def __init__(self, test, admitted_contract, *, timeout=120, current_client_admission=None):
        require(type(timeout) is int and 30 <= timeout <= 120, "Bounded ordinary transition timeout required")
        self.test, self.contract, self.timeout = test, admitted_contract, timeout
        require(Path(test.output).is_absolute() and Path(test.output).resolve(strict=True) == Path(test.output) and
            Path(test.output).is_dir() and not Path(test.output).is_symlink(), "Literal original runtime output required")
        self.identity = test.sampler_identity
        require(test.container == self.identity["container_id"] and test.image == self.identity["image_id"] and
            test.boot_id == self.identity["boot_id"] and test.fingerprint == self.identity["fingerprint"], "Foreign action owner")
        require(admitted_contract["image_id"] == test.image and
            re.fullmatch(r"[0-9a-f]{64}", admitted_contract["packet_receipt"]["sha256"]), "Actual admitted contract/image/receipt required")
        require(set(test.uids) >= {runtime.PACKAGE, admission.lane.acceptance.FIXTURE}, "Actual installed UID inventory required")
        self.sources = source_contract(); self.ordinal = 0
        self.action = None; self.prefix = None; self.read_count = 0
        require(getattr(test, "sampler", None) is not None, "Existing unchanged continuous observer required for attached actions")
        self.current_client = current_client.current_client_for(test, admitted_contract, current_client_admission)

    def read(self, label, *args):
        self.read_count += 1
        relative = self.prefix + f"/reads/{self.read_count:05d}-{label}.txt"
        self.raw_read(relative, *args)
        return (self.test.output / relative).read_text()

    def raw_read(self, relative, *args):
        before, began = len(self.test.trace), time.monotonic_ns()
        try: return self.test.read(relative, *map(str, args))
        except BaseException as error:
            if len(self.test.trace) == before:
                self.test._record({"kind": "action_read_failure", "argv": ["docker", "exec", self.test.container,
                    "adb", "-s", "emulator-5580", "shell", *map(str, args)], "requested_evidence": relative,
                    "error": str(error), "started_monotonic_ns": began, "ended_monotonic_ns": time.monotonic_ns()})
            raise

    def command(self, *args):
        before, began = len(self.test.trace), time.monotonic_ns()
        try: return self.test.shell(*map(str, args))
        except BaseException as error:
            if len(self.test.trace) == before:
                self.test._record({"kind": "action_command_failure", "argv": ["docker", "exec", self.test.container,
                    "adb", "-s", "emulator-5580", "shell", *map(str, args)], "error": str(error),
                    "started_monotonic_ns": began, "ended_monotonic_ns": time.monotonic_ns()})
            raise

    def wait(self, label, predicate, *, cleanup=False):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if cleanup: self.owner_guard(0)
            else: self.test.alive()
            result = predicate()
            if result: return result
            time.sleep(.2)
        raise TimeoutError("Ordinary transition did not settle: " + label)

    def guard(self, user=0, *, users_expected=None):
        self.test.alive()
        self.test.sampler.check()
        return self.owner_guard(user, users_expected=users_expected)

    def owner_guard(self, user=0, *, users_expected=None):
        """Cleanup authority is exact owner/boot/user, never runtime readiness."""
        raw = self.test.docker("container", "inspect", self.test.container)
        values = json.loads(raw); require(isinstance(values, list) and len(values) == 1, "Ambiguous action-owned guest")
        sampler.verify_owner(values[0], self.identity)
        require(self.read("boot", "cat", "/proc/sys/kernel/random/boot_id").strip() == self.test.boot_id and
            self.read("current-user", "am", "get-current-user").strip() == str(user), "Unexpected original boot/current user")
        if users_expected is not None:
            require(user in users_expected and user_helpers.users(self.read("users", "dumpsys", "user")) == users_expected, "Exact owned user inventory changed")

    def keyguard(self):
        return lock.keyguard_state(self.read("keyguard", "dumpsys", "activity", "--user", "0", "service", "com.android.systemui/.SystemUIService"))

    def credential_state(self, showing, secure=True, *, cleanup=False):
        def settled():
            value = self.keyguard()
            return value if (value["mShowing"] is showing and value["mSecure"] is secure and
                (not showing or value["mCanDismissLockScreen"] is False)) else False
        return self.wait("exact credential state", settled, cleanup=cleanup)

    def awake(self):
        return lock.phone_awake(self.read("phone-policy", "dumpsys", "window", "policy"))

    def wake(self):
        self.command("input", "keyboard", "-d", "0", "keyevent", "KEYCODE_WAKEUP")
        self.wait("ordinary phone wake", self.awake)

    def status_raw(self):
        raw = self.read("conformance", "dumpsys", "activity", "--user", "0", "service", runtime.SERVICE)
        acceptance.require_poll_expectation_marker(raw)
        value = runtime.parse_status(raw)
        require(value["run"] == self.test.conformance_run and value["failure"] is None and value["control_error"] is None,
            "Held conformance runtime changed or failed")
        if self.action is not None and self.action["captures"]:
            acceptance.service_owner(raw, self.action["captures"][0]["processes"]["client"]["pid"])
        return raw, value

    def control(self, phase):
        require(phase in {"remember-observed", "reopen", "restore-observed"}, "Unreviewed ordinary action phase")
        _raw, before = self.status_raw()
        require(before["state"] == ("waiting-reopen" if phase == "reopen" else "ready"), "Wrong observed state for exact action phase")
        nonce = secrets.token_hex(16)
        raw = self.command("dumpsys", "activity", "--user", "0", "service", runtime.SERVICE,
            "runtime-command", self.test.conformance_run, nonce, phase)
        marker = runtime.CONTROL_MARKER + f"accepted {self.test.conformance_run} {nonce} {phase}"
        acceptance.require_control_marker(raw, marker)
        def acknowledged():
            _raw, value = self.status_raw()
            require(value["handshake"] != {"nonce": nonce, "phase": phase, "result": "rejected"}, "Action control rejected")
            return value if (value["handshake"] == {"nonce": nonce, "phase": phase, "result": "accepted"} and
                value["state"] == "ready" and value["runtime_readiness"]["ready"]) else False
        return self.wait("exact " + phase, acknowledged)

    def arm(self, reason):
        require(type(reason) is int and reason in (3, 4), "Only exact LOCKED/USER_CHANGED action expectations allowed")
        _raw, value = self.status_raw(); snapshot = value["snapshot"]
        require(value["state"] == "ready" and value["runtime_readiness"]["ready"], "Expected revocation needs an actual ready lease")
        nonce = secrets.token_hex(16)
        raw = self.command("dumpsys", "activity", "--user", "0", "service", runtime.SERVICE, "runtime-command",
            self.test.conformance_run, nonce, "expect-revocation", snapshot["generation"], snapshot["identity_epoch"], reason)
        marker = runtime.CONTROL_MARKER + f"accepted {self.test.conformance_run} {nonce} expect-revocation"
        acceptance.require_control_marker(raw, marker)
        def armed():
            raw, status = self.status_raw()
            if status["handshake"] != {"nonce": nonce, "phase": "expect-revocation", "result": "accepted"}: return False
            return expectation.require_armed(raw, self.test.conformance_run, nonce, snapshot["generation"], snapshot["identity_epoch"], reason)
        return self.wait("exact one-shot expected revocation", armed)

    def consumed(self, armed):
        def observed():
            raw, value = self.status_raw()
            if value["state"] != "waiting-reopen": return False
            return expectation.require_consumed(raw, self.test.conformance_run, armed)
        return self.wait("exact actual planned callback", observed)

    def capture(self, name, *, user=0):
        directory = self.prefix + "/captures/" + name
        require(not (self.test.output / directory).exists(), "Never replace action capture")
        began, start = time.monotonic_ns(), len(self.test.trace)
        commands = {"activities": ("dumpsys", "activity", "activities"),
            "fixture": ("dumpsys", "activity", "--user", "0", admission.lane.acceptance.FIXTURE),
            "windows": ("dumpsys", "window", "windows"), "window_displays": ("dumpsys", "window", "displays"),
            "input": ("dumpsys", "input"), "display": ("dumpsys", "display"),
            "conformance": ("dumpsys", "activity", "--user", "0", "service", runtime.SERVICE),
            "keyguard": ("dumpsys", "activity", "--user", "0", "service", "com.android.systemui/.SystemUIService"),
            "policy": ("dumpsys", "window", "policy"), "current_user": ("am", "get-current-user"),
            "users": ("dumpsys", "user"), "events": ("logcat", "-b", "events", "-d", "-v", "threadtime", "am_anr:I", "am_crash:I", "*:S"),
            "modem": ("getprop", health.phone.MODEM_PROPERTY), "radio": ("su", "0", "service", "list"),
            "boot": ("cat", "/proc/sys/kernel/random/boot_id")}
        commands["home_uid"] = ("pm", "list", "packages", "-U", "--user", str(user), admission.lane.raw_audit.LAUNCHER)
        files = {key: directory + "/" + key + ".txt" for key in commands}
        for key, command in commands.items(): self.raw_read(files[key], *command)
        processes = {}
        for role, package in health.contract.PROCESS_NAMES.items():
            uid_path = directory + "/" + role + "-uid.txt"
            if role == "system_server": uid = 1000
            else:
                raw = self.raw_read(uid_path, "pm", "list", "packages", "-U", "--user", "0", package)
                uid = acceptance.package_uid(raw, package, 0)
            raw = {}; refs = {}
            for kind in ("pid_before", "ps_before", "stat_before", "status", "fd", "stat_after", "pid_after", "ps_after"):
                relative = directory + "/" + role + "-" + kind + ".txt"
                if kind in {"pid_before", "pid_after"}: command = ("pidof", package)
                elif kind.startswith("ps"):
                    command = health.PROCESS_TABLE_COMMAND
                else:
                    command = ("su", "0", *( ("ls", "-1") if kind == "fd" else ("cat",)), f"/proc/{pid}/" + ("stat" if kind in {"stat_before", "stat_after"} else kind))
                raw[kind] = self.raw_read(relative, *command); refs[kind] = relative
                if kind == "ps_before": pid = health.qualified_pid(raw["pid_before"], raw[kind], package, uid)
            processes[role] = {"uid": uid, "package_uid": uid_path if role != "system_server" else None,
                "files": refs, **acceptance.process_metric(raw, uid, package)}
        frames = {str(slot): directory + f"/frame-{slot}.png" for slot in (0, 1, 2, 3)}
        for slot, relative in frames.items(): self.test._frame(relative, int(slot))
        row = {"name": name, "user": user, "files": files, "processes": processes, "frames": frames,
            "trace_start": start, "trace_end": len(self.test.trace), "began_monotonic_ns": began, "ended_monotonic_ns": time.monotonic_ns()}
        self.action["captures"].append(row)
        return row

    def challenge(self, original):
        for component, record in original["records"].items():
            display = record["native_display"]
            self.command("input", "keyboard", "-d", display, "keyevent", "KEYCODE_B")
            self.command("input", "mouse", "-d", display, "tap", (record["left"] + record["right"]) // 2,
                (record["top"] + record["bottom"]) // 2)

    def credential_command(self, pin, *args, cleanup=False):
        # Only this generated TEST PIN is ever touched; never print it or a
        # locksettings response in ordinary raw journals or exception strings.
        require(re.fullmatch(r"[0-9]{8}", pin) and tuple(map(str, args)) in {
            ("locksettings", "set-pin", "--user", "0", pin), ("locksettings", "clear", "--old", pin, "--user", "0"),
            ("input", "keyboard", "-d", "0", "text", pin)}, "Credential transport is exact generated TEST-only scope")
        if cleanup:
            require(tuple(map(str, args)) == ("locksettings", "clear", "--old", pin, "--user", "0"), "Cleanup is only authenticated owned PIN removal")
            self.owner_guard(0)
        else: self.guard()
        argv = ["docker", "exec", self.test.container, "adb", "-s", "emulator-5580", "shell", *map(str, args)]
        safe = [value.replace(pin, "<owned-test-pin>") for value in argv]
        began = time.monotonic_ns(); result = None
        try:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
            raw = result.stdout
            self.test._record({"kind": "owned_test_credential", "argv": safe, "returncode": result.returncode,
                "started_monotonic_ns": began, "ended_monotonic_ns": time.monotonic_ns(), "output": raw.replace(pin, "<owned-test-pin>")})
            require(result.returncode == 0, "Owned TEST credential command failed; no credential/output exposed")
            return raw
        except (OSError, subprocess.SubprocessError):
            self.test._record({"kind": "owned_test_credential_failure", "argv": safe,
                "started_monotonic_ns": began, "ended_monotonic_ns": time.monotonic_ns(), "output": "credential and output deliberately omitted"})
            raise ValueError("Owned TEST credential command failed; no credential/output exposed") from None

    def unlock_pin(self, pin):
        self.guard(0)
        require(self.keyguard() == {"mShowing": True, "mSecure": True, "mCanDismissLockScreen": False},
            "Generated credential disappeared before ordinary input unlock")
        # A long inactive capture can reach the stock ten-second keyguard
        # timeout. WAKEUP is a no-op while already awake (PowerGroup), so a
        # momentary ON/AWAKE poll alone does not create a fresh input window.
        # Confirm a real ordinary sleep-to-wake transition, never repair a
        # lock setting or invoke privileged keyguard dismissal.
        self.command("input", "keyboard", "-d", "0", "keyevent", "KEYCODE_SLEEP")
        self.wait("settled ordinary phone sleep", lambda: acceptance.phone_asleep(
            self.read("unlock-sleep-policy", "dumpsys", "window", "policy")))
        wake_started = time.monotonic_ns()
        self.wake()
        require(time.monotonic_ns() - wake_started < acceptance.MAX_UNLOCK_INPUT_NS,
            "Fresh ordinary wake consumed safe PIN input window")
        self.command("input", "touchscreen", "-d", "0", "swipe", "540", "1800", "540", "400", "600")
        require(lock.phone_awake(self.read("unlock-post-swipe-policy", "dumpsys", "window", "policy")) and
            time.monotonic_ns() - wake_started < acceptance.MAX_UNLOCK_INPUT_NS,
            "Ordinary PIN swipe did not finish inside actual awake input window")
        def entry():
            relative = self.prefix + f"/credential-entry-{self.read_count:05d}.xml"
            raw = self.test.hierarchy(evidence=relative)
            nodes = [node for node in ET.fromstring(raw).iter("node") if node.get("package") == "com.android.systemui" and
                node.get("enabled") == "true" and (node.get("password") == "true" or node.get("resource-id", "").endswith(":id/pinEntry"))]
            require(len(nodes) <= 1, "Ambiguous system-owned PIN entry")
            self.read_count += 1
            return bool(nodes)
        self.wait("ordinary system PIN field", entry)
        self.credential_command(pin, "input", "keyboard", "-d", "0", "text", pin)
        self.command("input", "keyboard", "-d", "0", "keyevent", "KEYCODE_ENTER")
        self.credential_state(False)

    def recover(self, original):
        self.guard(0)
        self.command("input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME")
        self.control("reopen"); self.control("restore-observed")
        self.command("input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME")
        recovered = self.capture("recovered")
        for component, record in original["records"].items(): self.test.delivered(component, record["native_display"])
        self.command("input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME")
        self.capture("delivered")
        return recovered

    def perform(self, name):
        require(name in SCENARIOS and self.action is None, "Unknown or concurrent action")
        require(admission.input_contract(self.test.image, Path(self.contract["product"]), Path(self.contract["packet"]),
            self.contract["packet_receipt"]["sha256"]) == self.contract and source_contract() == self.sources, "Current admitted contract/source drift")
        self.ordinal += 1; nonce = secrets.token_hex(16)
        self.prefix = f"soak-actions/{self.ordinal:06d}-{name}-{nonce}"; self.read_count = 0
        parent = self.test.output / "soak-actions"
        require(not parent.is_symlink() and (not parent.exists() or parent.is_dir() and parent.resolve(strict=True) == parent),
            "Preserve unexpected existing action parent/alias")
        directory = self.test.output / self.prefix; directory.mkdir(parents=True, mode=0o700)
        started = time.monotonic_ns(); trace_start = len(self.test.trace)
        self.action = {"schema": 1, "kind": acceptance.KIND, "scenario": name, "ordinal": self.ordinal, "nonce": nonce,
            "identity": self.identity, "run": self.test.conformance_run, "uids": self.test.uids,
            "contract": self.contract, "sources": self.sources, "began_monotonic_ns": started, "captures": [],
            "status": "failed_bounded_action_not_qualified", "runtime_qualified": False, "whole_campaign_complete": False}
        current_client.begin_action(self)
        admission.lane.fresh.write_new_durable(directory / "attempt-started.json", self.action)
        error = None
        try:
            self.guard(0)
            self.current_client.observe(self, "before")
            initial = self.capture("before")
            original = acceptance.parse_capture(self.test.output, initial, self.action, self.test.trace)
            acceptance.ready(original, self.action)
            if name == "user_switch":
                require(self.test.sampler.process_uids == {role: row["uid"] for role, row in original["processes"].items()},
                    "User switch requires the unchanged explicitly UID-qualified continuous observer")
            self.control("remember-observed")
            if name == "user_switch": self.user_switch(original)
            else: self.credential(original, "sleep" if name == "credential_sleep" else "lock-key")
            self.current_client.observe(self, "after")
            require(source_contract() == self.sources and admission.input_contract(self.test.image, Path(self.contract["product"]),
                Path(self.contract["packet"]), self.contract["packet_receipt"]["sha256"]) == self.contract, "Action contract changed")
            self.action["status"] = acceptance.STATUS
        except BaseException as caught:
            error = caught; self.action["error"] = str(caught)
        finally:
            def seal(step):
                nonlocal error
                try: step()
                except BaseException as caught:
                    if error is None: error = caught
                    elif error is not caught: error.add_note("Secondary evidence-sealing failure: " + repr(caught))
                    self.action["status"] = "failed_bounded_action_not_qualified"
                    self.action.setdefault("error", str(error))
                    self.action.setdefault("sealing_errors", []).append(repr(caught))
            try:
                self.action.update(ended_monotonic_ns=time.monotonic_ns(), trace_start=trace_start, trace_end=len(self.test.trace))
                seal(lambda: current_client.finish_journal(self))
                seal(lambda: admission.lane.fresh.write_new_durable(directory / "commands.json", self.test.trace[trace_start:]))
                def inventory():
                    self.action["evidence"] = {str(path.relative_to(self.test.output)):
                        (acceptance.observed_ref(path, self.test.trace, self.test.output) if error is None else admission.lane.mechanics.failed_file_ref(path))
                        for path in directory.rglob("*") if path.is_file()}
                seal(inventory)
                seal(lambda: admission.lane.fresh.write_new_durable(directory / "attempt-ended.json", self.action))
            finally: self.action = None
        if error is not None: raise error
        try: acceptance.audit_action(directory / "attempt-ended.json", self.contract, self.identity,
            client_chain=self.current_client.chain, client_uid=self.current_client.uid)
        except Exception as caught:
            admission.lane.fresh.write_new_durable(directory / "independent-audit-failure.json", {
                "status": "failed_original_raw_action_audit_not_qualified", "error": str(caught),
                "original_attempt": file_ref(directory / "attempt-ended.json"), "runtime_qualified": False})
            raise
        return {"path": str(directory / "attempt-ended.json"), **file_ref(directory / "attempt-ended.json"),
            "runtime_qualified": False, "whole_campaign_complete": False}

    def credential(self, original, trigger):
        require(self.keyguard() == {"mShowing": False, "mSecure": False, "mCanDismissLockScreen": True}, "Never alter an existing credential/locked user")
        disabled = self.read("lock-disabled-before", "locksettings", "get-disabled", "--user", "0").strip()
        require(disabled in {"true", "false"}, "Unknown original lock configuration")
        pin = str(secrets.randbelow(90_000_000) + 10_000_000); created = False; cleanup_error = None
        try:
            result = self.credential_command(pin, "locksettings", "set-pin", "--user", "0", pin)
            require("Pin set to '" + pin + "'" in result.splitlines(), "Owned credential creation was not confirmed")
            created = True; self.credential_state(False)
            self.action["expectation"] = armed = self.arm(3)
            self.command("input", "keyboard", "-d", "0", "keyevent", "KEYCODE_SLEEP" if trigger == "sleep" else "KEYCODE_LOCK")
            if trigger == "sleep":
                self.wait("actual phone sleep", lambda: not self.awake()); self.wake()
            self.credential_state(True); require(self.awake(), "Credential lock must remain awake")
            self.consumed(armed)
            for index in range(3):
                self.command("input", "touchscreen", "-d", "0", "tap", "12", "500")
                self.challenge(original); self.capture(f"inactive-{index}")
            self.unlock_pin(pin); self.recover(original)
        except BaseException as caught:
            self.action["disturbance_error"] = str(caught).replace(pin, "<owned-test-pin>")
            raise
        finally:
            # Even failed creation may have changed this newly owned state;
            # authenticate with only this generated PIN, never force reset.
            try:
                raw = self.credential_command(pin, "locksettings", "clear", "--old", pin, "--user", "0", cleanup=True)
                require("Lock credential cleared" in raw.splitlines(), "Owned credential removal was not confirmed")
                if self.read("lock-disabled-after-clear", "locksettings", "get-disabled", "--user", "0").strip() != disabled:
                    self.command("locksettings", "set-disabled", "--user", "0", disabled)
                self.credential_state(False, secure=False, cleanup=True)
                require(self.read("lock-disabled-restored", "locksettings", "get-disabled", "--user", "0").strip() == disabled, "Original lock configuration not restored")
                self.action["credential_cleanup"] = {"created": created, "removed": True, "original_disabled": disabled}
            except Exception as caught:
                cleanup_error = str(caught).replace(pin, "<owned-test-pin>")
                self.action["credential_cleanup"] = {"created": created, "removed": False, "error": cleanup_error}
            if cleanup_error is not None: raise ValueError("Owned TEST credential cleanup failed: " + cleanup_error)

    def user_switch(self, original):
        initial = user_helpers.users(self.read("users-before", "dumpsys", "user")); require(set(initial) == {0}, "Never reuse a secondary user")
        require(not self.keyguard()["mSecure"], "User transition requires credential-free original user")
        name = "Wonad-soak-" + self.action["nonce"]; secondary = None; expected = None; cleanup_error = None
        try:
            raw = self.command("pm", "create-user", "--for-testing", name)
            found = re.findall(r"^Success: created user id ([1-9][0-9]*)$", raw, re.M)
            require(len(found) == 1 and 10 <= int(found[0]) <= 1000, "Fresh test user creation not confirmed")
            secondary = int(found[0]); expected = user_helpers.users(self.read("users-created", "dumpsys", "user"))
            require(set(expected) == {0, secondary} and expected[0] == initial[0] and expected[secondary]["name"] == name and
                expected[secondary]["serial"] > initial[0]["serial"], "Foreign newly created user")
            self.action["secondary"] = {"id": secondary, **expected[secondary]}
            self.command("am", "start-user", "-w", secondary)
            self.wait("exact new user unlocked storage", lambda: self.read("secondary-state", "am", "get-started-user-state", secondary).strip() == "RUNNING_UNLOCKED")
            self.action["expectation"] = armed = self.arm(4)
            self.command("am", "switch-user", "-w", secondary); self.guard(secondary, users_expected=expected)
            self.wake(); require(not self.keyguard()["mSecure"], "Fresh secondary user unexpectedly has a credential")
            if self.keyguard()["mShowing"]: self.command("input", "touchscreen", "-d", "0", "swipe", "540", "1800", "540", "400", "600")
            self.consumed(armed); self.complete_setup(secondary)
            consent = self.read("secondary-consent", "settings", "--user", secondary, "get", "secure", "wonad_external_desktop_enabled").strip()
            require(consent in {"null", "0"}, "Secondary user inherited desktop consent")
            for package in (runtime.PACKAGE, admission.lane.acceptance.FIXTURE):
                require(self.read("secondary-package-absence", "pm", "list", "packages", "--user", secondary, package).strip() == "", "Secondary user inherited installed conformance/fixture package")
            for index in range(3): self.challenge(original); self.capture(f"inactive-{index}", user=secondary)
            self.command("am", "switch-user", "-w", "0"); self.guard(0, users_expected=expected)
            self.wake()
            if self.keyguard()["mShowing"]: self.command("input", "touchscreen", "-d", "0", "swipe", "540", "1800", "540", "400", "600")
            require(not self.keyguard()["mSecure"], "Original user unexpectedly gained a credential")
            self.recover(original)
        except BaseException as caught:
            self.action["disturbance_error"] = str(caught)
            raise
        finally:
            try:
                if secondary is not None:
                    require(expected is not None and set(expected) == {0, secondary} and expected[0] == initial[0] and
                        expected[secondary]["name"] == name and expected[secondary]["serial"] > initial[0]["serial"],
                        "Preserve created user whose exact owned name/serial was not authenticated")
                    self.owner_guard(int(self.read("cleanup-current-user", "am", "get-current-user").strip()), users_expected=expected)
                    self.command("am", "switch-user", "-w", "0"); self.owner_guard(0, users_expected=expected)
                    self.command("am", "stop-user", "-w", "-f", secondary)
                    raw = self.command("pm", "remove-user", secondary)
                    require(raw.strip() == f"Success: removed user", "Only owned TEST user removal must be confirmed")
                    require(user_helpers.users(self.read("users-restored", "dumpsys", "user")) == initial, "Original exact user set not restored")
                require(user_helpers.users(self.read("users-cleanup-final", "dumpsys", "user")) == initial, "Unresolved created user must be preserved as failed cleanup")
                self.action["user_cleanup"] = {"removed": secondary is not None, "restored": {str(user): row for user, row in initial.items()}}
            except Exception as caught:
                cleanup_error = str(caught); self.action["user_cleanup"] = {"removed": False, "error": cleanup_error}
            if cleanup_error: raise ValueError("Owned TEST user cleanup failed: " + cleanup_error)

    def complete_setup(self, secondary):
        original = self.read("owner-provisioning", "settings", "--user", "0", "get", "secure", "user_setup_complete").strip()
        self.command("input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME")
        for index in range(10):
            if self.read("secondary-provisioning", "settings", "--user", secondary, "get", "secure", "user_setup_complete").strip() == "1":
                home = self.read("secondary-home", "cmd", "package", "resolve-activity", "--brief", "--user", secondary,
                    "-a", "android.intent.action.MAIN", "-c", "android.intent.category.HOME")
                require(home.splitlines()[-1:] == [admission.lane.raw_audit.PHONE_HOME_COMPONENT], "New user did not expose actual stock Home")
                require(self.read("owner-provisioning-after", "settings", "--user", "0", "get", "secure", "user_setup_complete").strip() == original,
                    "Ordinary secondary setup changed original provisioning")
                return
            raw = self.read("secondary-phone-focus", "dumpsys", "window", "displays")
            found = re.findall(r"mFocusedApp=ActivityRecord\{[^\n]*? u" + str(secondary) + r" (\S+) t[1-9][0-9]*\}", raw)
            require(len(found) == 1, "Setup has ambiguous secondary phone focus")
            relative = self.prefix + f"/secondary-setup-{index}.xml"
            hierarchy = self.test.hierarchy(evidence=relative)
            _label, point = user_helpers.setup_button(hierarchy, found[0])
            self.command("input", "touchscreen", "-d", "0", "tap", *point)
        raise ValueError("Ordinary secondary setup did not complete")
