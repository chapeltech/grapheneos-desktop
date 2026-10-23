#!/usr/bin/env python3
"""Exact TEST-client STOP/expiry/CONT on one admitted, held runtime.

No boot, APK change or product service. Frozen observations are OS-only: never
query a stopped app or pretend its callback/status was observed before CONT.
"""
from pathlib import Path
import secrets
import sys
import time
import re

import phase1_conformance_soak_lock_user_actions as attached
import phase1_conformance_soak_frozen_client_acceptance as acceptance
from phase1_conformance_common import file_ref

runtime, health = attached.runtime, attached.health
require = runtime.require


def source_contract():
    sources = attached.source_contract()
    sources.update({key: {"path": str(Path(module.__file__).resolve()), **file_ref(Path(module.__file__).resolve())}
        for key, module in {"frozen_action": sys.modules[__name__], "frozen_auditor": acceptance,
            "frozen_observations": attached.acceptance.observations}.items()})
    protocol = Path(__file__).resolve().parents[1] / "desktop-sdk/src/main/kotlin/org/wonad/desktop/api/DesktopProtocol.kt"
    sources["frozen_protocol"] = {"path": str(protocol), **file_ref(protocol)}
    return sources


def client_timeout_ns():
    protocol = Path(source_contract()["frozen_protocol"]["path"]).read_text()
    values = re.findall(r"^\s*const val CLIENT_TIMEOUT_MILLIS = ([1-9][0-9]*)L\s*$", protocol, re.M)
    require(values == ["5000"], "Frozen client requires the exact authenticated v3 timeout")
    return int(values[0]) * 1_000_000


class FrozenAction(attached.Actions):
    def __init__(self, test, admitted_contract, *, timeout=120, current_client_admission=None):
        super().__init__(test, admitted_contract, timeout=timeout, current_client_admission=current_client_admission)
        self.sources = source_contract()

    def fence(self, label, original, *, state=None):
        """Fresh exact UID/PID/start re-admission before EVERY signal."""
        self.owner_guard(0)
        package = runtime.PACKAGE
        uid = attached.acceptance.package_uid(self.read(label + "-uid", "pm", "list", "packages", "-U", "--user", "0", package), package, 0)
        raw, files = {}, {}
        for key in ("pid_before", "ps_before", "stat_before", "status", "fd", "stat_after", "pid_after", "ps_after"):
            command = ("pidof", package) if key.startswith("pid") else health.PROCESS_TABLE_COMMAND if key.startswith("ps") else (
                "su", "0", *(("ls", "-1") if key == "fd" else ("cat",)), f"/proc/{pid}/" + ("stat" if key in ("stat_before", "stat_after") else key))
            before = len(self.test.trace); raw[key] = self.read(label + "-" + key, *command)
            files[key] = self.test.trace[before]["evidence"]
            if key == "ps_before": pid = health.qualified_pid(raw["pid_before"], raw[key], package, uid)
        observed = attached.acceptance.process_metric(raw, uid, package)
        require(all(observed[key] == original[key] for key in ("pid", "start_ticks", "uid")), "Refuse signal to changed/recycled/foreign client")
        states = [acceptance.process_state(raw[key], pid) for key in ("stat_before", "stat_after")]
        require(state is None or states == [state, state], "Client was not actually in the required kernel process state")
        proof = {"label": label, "uid": uid, "pid": pid, "start_ticks": observed["start_ticks"], "states": states,
            "files": files, "trace_start": self.test.trace[before - 7]["sequence"], "trace_end": len(self.test.trace)}
        self.action["client_fences"].append(proof)
        return proof

    def arm_failure(self):
        raw, value = self.status_raw(); snapshot = value["snapshot"]
        require(value["state"] == "ready" and value["runtime_readiness"]["ready"], "Frozen expectation needs the actual ready original lease")
        nonce = secrets.token_hex(16)
        result = self.command("dumpsys", "activity", "--user", "0", "service", runtime.SERVICE, "runtime-command",
            self.test.conformance_run, nonce, "expect-revocation", snapshot["generation"], snapshot["identity_epoch"], 5)
        markers = [line.strip() for line in result.splitlines() if runtime.CONTROL_MARKER.rstrip() in line]
        require(markers == [runtime.CONTROL_MARKER + f"accepted {self.test.conformance_run} {nonce} expect-revocation"],
            "Actual reason-5 seven-field expectation was not accepted")
        def armed():
            raw, status = self.status_raw()
            if status["handshake"] != {"nonce": nonce, "phase": "expect-revocation", "result": "accepted"}: return False
            return attached.expectation.require_armed(raw, self.test.conformance_run, nonce, snapshot["generation"], snapshot["identity_epoch"], 5)
        return self.wait("exact source-26 reason-5 expectation", armed)

    def capture_stopped(self, name):
        # This explicit observation set omits ONLY stopped-app dumpsys. Every
        # retained OS/fixture/process/frame value is fresh and actually read.
        directory = self.prefix + "/captures/" + name
        require(not (self.test.output / directory).exists(), "Never replace frozen capture")
        began, start = time.monotonic_ns(), len(self.test.trace)
        commands = {"activities": ("dumpsys", "activity", "activities"), "fixture": ("dumpsys", "activity", "--user", "0", attached.admission.lane.acceptance.FIXTURE),
            "windows": ("dumpsys", "window", "windows"), "window_displays": ("dumpsys", "window", "displays"),
            "input": ("dumpsys", "input"), "display": ("dumpsys", "display"),
            "keyguard": ("dumpsys", "activity", "--user", "0", "service", "com.android.systemui/.SystemUIService"),
            "policy": ("dumpsys", "window", "policy"), "current_user": ("am", "get-current-user"), "users": ("dumpsys", "user"),
            "events": ("logcat", "-b", "events", "-d", "-v", "threadtime", "am_anr:I", "am_crash:I", "*:S"),
            "modem": ("getprop", health.phone.MODEM_PROPERTY), "radio": ("su", "0", "service", "list"),
            "boot": ("cat", "/proc/sys/kernel/random/boot_id"), "home_uid": ("pm", "list", "packages", "-U", "--user", "0", attached.admission.lane.raw_audit.LAUNCHER)}
        files = {key: directory + "/" + key + ".txt" for key in commands}
        for key, args in commands.items(): self.raw_read(files[key], *args)
        processes = {}
        for role, package in health.contract.PROCESS_NAMES.items():
            uid_path = directory + "/" + role + "-uid.txt"
            uid = 1000 if role == "system_server" else attached.acceptance.package_uid(
                self.raw_read(uid_path, "pm", "list", "packages", "-U", "--user", "0", package), package, 0)
            raw, refs = {}, {}
            for key in ("pid_before", "ps_before", "stat_before", "status", "fd", "stat_after", "pid_after", "ps_after"):
                args = ("pidof", package) if key.startswith("pid") else health.PROCESS_TABLE_COMMAND if key.startswith("ps") else (
                    "su", "0", *(("ls", "-1") if key == "fd" else ("cat",)), f"/proc/{pid}/" + ("stat" if key in ("stat_before", "stat_after") else key))
                relative = directory + "/" + role + "-" + key + ".txt"
                raw[key] = self.raw_read(relative, *args); refs[key] = relative
                if key == "ps_before": pid = health.qualified_pid(raw["pid_before"], raw[key], package, uid)
            processes[role] = {"package_uid": None if role == "system_server" else uid_path, "files": refs,
                **attached.acceptance.process_metric(raw, uid, package)}
        frames = {str(slot): directory + f"/frame-{slot}.png" for slot in (0, 1, 2, 3)}
        for slot, relative in frames.items(): self.test._frame(relative, int(slot))
        row = {"name": name, "user": 0, "runtime_status_observed": False, "files": files, "processes": processes, "frames": frames,
            "trace_start": start, "trace_end": len(self.test.trace), "began_monotonic_ns": began, "ended_monotonic_ns": time.monotonic_ns()}
        self.action["captures"].append(row)
        return row

    def perform(self):
        require(self.action is None and source_contract() == self.sources, "Concurrent/drifted frozen action")
        require(attached.admission.input_contract(self.test.image, Path(self.contract["product"]), Path(self.contract["packet"]),
            self.contract["packet_receipt"]["sha256"]) == self.contract, "Current admitted frozen contract changed")
        self.ordinal += 1; nonce = secrets.token_hex(16); self.read_count = 0
        self.prefix = f"soak-actions/{self.ordinal:06d}-frozen_client-{nonce}"
        directory = self.test.output / self.prefix
        require(directory.parent.resolve() == directory.parent and not directory.parent.is_symlink(), "Unexpected frozen action parent alias")
        directory.mkdir(parents=True, mode=0o700)
        start, began = len(self.test.trace), time.monotonic_ns()
        self.action = {"schema": 1, "kind": acceptance.KIND, "scenario": "frozen_client", "ordinal": self.ordinal, "nonce": nonce,
            "run": self.test.conformance_run, "identity": self.identity, "contract": self.contract, "sources": self.sources, "uids": self.test.uids,
            "status": "failed_bounded_frozen_action_not_qualified", "runtime_qualified": False, "whole_campaign_complete": False,
            "began_monotonic_ns": began, "captures": [], "client_fences": [], "timeout_ns": client_timeout_ns()}
        attached.current_client.begin_action(self)
        attached.admission.lane.fresh.write_new_durable(directory / "attempt-started.json", self.action)
        error = None; stop_attempted = False; original = None
        try:
            self.guard(0); self.current_client.observe(self, "before"); before = self.capture("before")
            scene = attached.acceptance.parse_capture(self.test.output, before, self.action, self.test.trace)
            attached.acceptance.ready(scene, self.action); original = scene["processes"]["client"]
            self.control("remember-observed"); self.action["expectation"] = self.arm_failure()
            self.fence("before-stop", original)
            stop_attempted = True; stop_index = len(self.test.trace)
            self.command("su", "0", "kill", "-STOP", original["pid"])
            self.action["stop_trace_index"] = stop_index
            def stopped():
                observed = self.fence("stopped", original)
                require(not any(state in {"Z", "X", "x"} for state in observed["states"]), "Client died instead of stopping")
                return observed if observed["states"] == ["T", "T"] else False
            self.wait("actual exact client stopped", stopped)
            stop_end = self.test.trace[stop_index]["ended_monotonic_ns"]
            # Time is only a lower-bound prerequisite. Exact original native
            # black/input observations + deferred actual reason5 are required.
            while time.monotonic_ns() - stop_end < self.action["timeout_ns"] + 2_000_000_000:
                self.guard(0); time.sleep(.2)
            for index in range(3):
                self.challenge(scene); self.capture_stopped(f"inactive-{index}")
            self.fence("before-cont", original, state="T")
            self.action["cont_trace_index"] = len(self.test.trace)
            self.command("su", "0", "kill", "-CONT", original["pid"])
            self.fence("after-cont", original)
            self.consumed(self.action["expectation"])
            self.recover(scene)
            self.current_client.observe(self, "after")
            require(source_contract() == self.sources, "Frozen source drift")
            self.action["status"] = acceptance.STATUS
        except BaseException as caught:
            error = caught; self.action["error"] = str(caught)
        finally:
            # Failed STOP/read/observer must not strand an authenticated exact
            # client. Never signal a recycled PID or an unproven target.
            cleanup = {"attempted": stop_attempted, "continued": False}
            if stop_attempted and original is not None:
                try:
                    fence = self.fence("cleanup-cont-owner", original)
                    if fence["states"] == ["T", "T"]:
                        self.command("su", "0", "kill", "-CONT", original["pid"]); cleanup["continued"] = True
                        self.fence("cleanup-cont-after", original)
                    elif "T" in fence["states"]: raise ValueError("Ambiguous stopped state during cleanup")
                except BaseException as caught:
                    cleanup["error"] = str(caught)
                    if error is None: error = caught; self.action["error"] = str(caught)
            self.action["signal_cleanup"] = cleanup
            def seal(step):
                nonlocal error
                try: step()
                except BaseException as caught:
                    if error is None: error = caught
                    elif error is not caught: error.add_note("Secondary evidence-sealing failure: " + repr(caught))
                    self.action["status"] = "failed_bounded_frozen_action_not_qualified"
                    self.action.setdefault("error", str(error))
                    self.action.setdefault("sealing_errors", []).append(repr(caught))
            try:
                self.action.update(trace_start=start, trace_end=len(self.test.trace), ended_monotonic_ns=time.monotonic_ns())
                if error is not None: self.action["status"] = "failed_bounded_frozen_action_not_qualified"
                seal(lambda: attached.current_client.finish_journal(self))
                seal(lambda: attached.admission.lane.fresh.write_new_durable(directory / "commands.json", self.test.trace[start:]))
                def inventory():
                    self.action["evidence"] = {str(path.relative_to(self.test.output)): (
                        attached.acceptance.observed_ref(path, self.test.trace, self.test.output) if error is None else attached.admission.lane.mechanics.failed_file_ref(path))
                        for path in directory.rglob("*") if path.is_file()}
                seal(inventory)
                seal(lambda: attached.admission.lane.fresh.write_new_durable(directory / "attempt-ended.json", self.action))
            finally: self.action = None
        if error is not None: raise error
        try: acceptance.audit_action(directory / "attempt-ended.json", self.contract, self.identity,
            client_chain=self.current_client.chain, client_uid=self.current_client.uid)
        except Exception as caught:
            attached.admission.lane.fresh.write_new_durable(directory / "independent-audit-failure.json", {
                "status": "failed_original_frozen_action_audit_not_qualified", "error": str(caught),
                "original_attempt": file_ref(directory / "attempt-ended.json"), "runtime_qualified": False})
            raise
        return {"path": str(directory / "attempt-ended.json"), **file_ref(directory / "attempt-ended.json"),
            "runtime_qualified": False, "whole_campaign_complete": False}
