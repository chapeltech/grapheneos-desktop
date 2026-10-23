"""Bounded TEST-only SystemUI death on one already admitted held runtime.

No boot, signer, APK install or OS repair. Real source-matched containment and
Binder callbacks remain runtime prerequisites, never supplied by host models.
"""
from pathlib import Path
import secrets
import time

import conformance_broker_death as death
import phase1_conformance_soak_lock_user_actions as inherited
import phase1_conformance_soak_systemui_death_acceptance as audit
from phase1_conformance_common import canonical, file_ref

require = audit.require


def source_contract():
    values = inherited.source_contract()
    for role, module in {"systemui_actor": __import__(__name__), "systemui_auditor": audit,
                         "broker_death_parser": death}.items():
        path = Path(module.__file__).resolve(strict=True)
        values[role] = {"path": str(path), **file_ref(path)}
    root = Path(__file__).resolve().parents[2]
    for role, relative in {
        "native_controller": "android/os-integration/src/org/wonad/desktop/broker/NativeDesktopController.kt",
        "native_task_state": "android/input-integration/src/com/android/server/wm/WonadNativeBridge.kt",
        "native_containment": "android/input-integration/src/com/android/server/wm/WonadUiBridge.kt",
        "generation_seed": "android/os-integration/src/org/wonad/desktop/broker/WonadController.kt",
        "rust_native_authority": "android/broker-rust/src/native_authority.rs",
        "api_restart_contract": "android/desktop-sdk/API-v3.md"}.items():
        path = root / relative
        values[role] = {"path": str(path), **file_ref(path)}
    return values


class Actions(inherited.Actions):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sources = source_contract()
        self.sampler = self.test.sampler
        self.worker = self.test.instrument
        require(self.worker is not None and type(self.worker.pid) is int and self.worker.pid > 0 and
                self.worker.poll() is None, "Exact original held instrumentation owner required")

    def arm_broker_death(self):
        raw, current = self.status_raw()
        require(current["state"] == "ready" and current["runtime_readiness"]["ready"], "Exact ready lease required")
        nonce = secrets.token_hex(16)
        snap = current["snapshot"]
        self.read("broker-death-arm-command", "dumpsys", "activity", "--user", "0", "service", inherited.runtime.SERVICE,
            "runtime-command", self.test.conformance_run, nonce, "expect-broker-death", snap["generation"], snap["identity_epoch"])
        command_relative = self.test.trace[-1]["evidence"]
        inherited.acceptance.require_control_marker((self.test.output / command_relative).read_text(),
            inherited.runtime.CONTROL_MARKER + f"accepted {self.test.conformance_run} {nonce} expect-broker-death")
        def armed():
            raw, value = self.status_raw()
            if value["handshake"] != {"nonce": nonce, "phase": "expect-broker-death", "result": "accepted"}:
                require(value["handshake"] != {"nonce": nonce, "phase": "expect-broker-death", "result": "rejected"}, "Death arm rejected")
                return False
            proof = death.require_armed(raw, self.test.conformance_run, nonce, snap["generation"], snap["identity_epoch"])
            return {"raw_relative": self.test.trace[-1]["evidence"], "command_relative": command_relative, **proof}
        return self.wait("actual registered exact-owner broker death arm", armed)

    def observed_broker_death(self, armed):
        def observed():
            raw, value = self.status_raw()
            if value["state"] != "waiting-reopen": return False
            actual = death.require_observed(raw, armed)
            return {"raw_relative": self.test.trace[-1]["evidence"], **actual}
        return self.wait("actual registered Binder DeathRecipient callback", observed)

    def fence_old_systemui(self, expected):
        role = "systemui"; name = inherited.health.contract.PROCESS_NAMES[role]
        uid = inherited.acceptance.package_uid(self.read("kill-package-uid", "pm", "list", "packages", "-U", "--user", "0", name), name, 0)
        values = {"pid_before": self.read("kill-pid-before", "pidof", name),
                  "ps_before": self.read("kill-ps-before", *inherited.health.PROCESS_TABLE_COMMAND)}
        pid = inherited.health.qualified_pid(values["pid_before"], values["ps_before"], name, uid)
        for key, argv in (("stat_before", ("su", "0", "cat", f"/proc/{pid}/stat")),
            ("status", ("su", "0", "cat", f"/proc/{pid}/status")),
            ("fd", ("su", "0", "ls", "-1", f"/proc/{pid}/fd")),
            ("stat_after", ("su", "0", "cat", f"/proc/{pid}/stat")),
            ("pid_after", ("pidof", name)), ("ps_after", inherited.health.PROCESS_TABLE_COMMAND)):
            values[key] = self.read("kill-" + key.replace("_", "-"), *argv)
        actual = inherited.acceptance.process_metric(values, uid, name)
        require(all(actual[k] == expected[k] for k in ("uid", "pid", "start_ticks")), "SystemUI kill fence no longer owns exact old epoch")
        return actual

    def reopen_prerequisites(self):
        """Observe authorization prerequisites; never repair consent/credentials."""
        def observed():
            self.owner_guard(0)
            paths = {}
            def read(label, *argv):
                value = self.read("reopen-" + label, *argv)
                paths[label] = self.test.trace[-1]["evidence"]
                return value
            consent = read("consent", "settings", "--user", "0", "get", "secure", "wonad_external_desktop_enabled")
            guard = inherited.lock.keyguard_state(read("keyguard", "dumpsys", "activity", "--user", "0", "service", "com.android.systemui/.SystemUIService"))
            awake = inherited.lock.phone_awake(read("policy", "dumpsys", "window", "policy"))
            return paths if consent.strip() == "1" and awake and guard == {
                "mShowing": False, "mSecure": False, "mCanDismissLockScreen": True} else False
        return self.wait("separately restored ordinary broker prerequisites", observed)

    def perform(self):
        require(self.action is None, "Concurrent action forbidden")
        hooks = self.test.sampler
        require(callable(getattr(hooks, "begin_role_death", None)) and callable(getattr(hooks, "end_role_death", None)),
                "Exact role-death continuous observer required BEFORE disturbance")
        # Genuine whole packet/source/APK admission is required, not the unsigned
        # private compilation result and not historical packet15.
        require(inherited.admission.input_contract(self.test.image, Path(self.contract["product"]), Path(self.contract["packet"]),
                self.contract["packet_receipt"]["sha256"]) == self.contract, "Original packet/image contract changed")
        inherited.admission.lane.bind_client_sources(Path(self.contract["packet"]))
        self.ordinal += 1; nonce = secrets.token_hex(16); self.read_count = 0
        self.prefix = f"soak-actions/{self.ordinal:06d}-systemui_death-{nonce}"
        directory = self.test.output / self.prefix
        require(not directory.exists() and directory.resolve() == directory, "Never replace/alias death attempt")
        directory.mkdir(mode=0o700, parents=True)
        start = len(self.test.trace)
        self.action = dict(schema=1, kind=audit.KIND, scenario="systemui_death", ordinal=self.ordinal,
            nonce=nonce, identity=self.identity, run=self.test.conformance_run, uids=self.test.uids,
            contract=self.contract, sources=self.sources, began_monotonic_ns=time.monotonic_ns(), captures=[],
            status="failed_bounded_action_not_qualified", runtime_qualified=False, whole_campaign_complete=False)
        write = inherited.admission.lane.fresh.write_new_durable
        worker_starts = [row for row in self.test.trace[:start] if row.get("kind") == "background_start" and
                         row.get("id") == "instrumentation-" + self.test.conformance_run]
        require(len(worker_starts) == 1 and self.test.instrument is self.worker and self.worker.poll() is None,
                "Original owned worker startup missing/replaced")
        worker_relative = self.prefix + "/held-worker-start.json"
        write(self.test.output / worker_relative, worker_starts[0])
        self.action["worker"] = dict(host_pid=self.worker.pid, run=self.test.conformance_run,
            initial_nonce=self.test.initial_nonce, original_start_relative=worker_relative)
        inherited.current_client.begin_action(self)
        write(directory / "attempt-started.json", self.action)
        primary = None
        try:
            self.guard(0)
            self.current_client.observe(self, "before")
            original_row = self.capture("before")
            original = inherited.acceptance.parse_capture(self.test.output, original_row, self.action, self.test.trace)
            inherited.acceptance.ready(original, self.action)
            armed = self.arm_broker_death(); self.action["armed"] = armed
            self.owner_guard(0)
            old = self.fence_old_systemui(original["processes"]["systemui"])
            began = time.monotonic_ns()
            relative = self.prefix + "/attempt-ended.json"
            handle = hooks.begin_role_death(nonce, "systemui_death", role="systemui", role_uid=old["uid"],
                before={k: old[k] for k in ("pid", "start_ticks")}, started_monotonic_ns=began, action_relative=relative)
            self.action["transition"] = dict(permit_id=handle, started_monotonic_ns=began, old=old, action_relative=relative)
            self.command("su", "0", "kill", "-KILL", old["pid"])
            self.action["transition"]["kill_sequence"] = self.test.trace[-1]["sequence"]
            self.action["observed"] = self.observed_broker_death(armed)
            for index in range(3):
                self.challenge(original)
                row = self.capture(f"inactive-{index}")
                current = inherited.acceptance.parse_capture(self.test.output, row, self.action, self.test.trace)
                audit.shield(original, current, self.action)
            self.action["reopen_prerequisites"] = self.reopen_prerequisites()
            self.control("reopen")
            self.control("restore-observed")
            self.command("input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME")
            recovered = self.capture("recovered")
            current = inherited.acceptance.parse_capture(self.test.output, recovered, self.action, self.test.trace)
            audit.recovered(original, current, self.action)
            recovered_relative = self.prefix + "/recovered-stage.json"
            write(self.test.output / recovered_relative, recovered)
            endpoint = {k: current["processes"]["systemui"][k] for k in ("pid", "start_ticks")}
            ended = recovered["ended_monotonic_ns"]
            hooks.end_role_death(handle, after=endpoint, ended_monotonic_ns=ended,
                action_relative=relative, recovered_stage_relative=recovered_relative)
            self.action["transition"].update(after=endpoint, ended_monotonic_ns=ended, recovered_stage_relative=recovered_relative)
            for component, record in original["records"].items(): self.test.delivered(component, record["native_display"])
            self.command("input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME")
            self.capture("delivered")
            self.test.alive()
            require(self.test.instrument is self.worker and self.worker.poll() is None and self.worker.pid == self.action["worker"]["host_pid"],
                    "SystemUI death replaced/retired the original held client worker")
            require(source_contract() == self.sources and self.test.sampler is hooks, "Action source/observer changed")
            self.current_client.observe(self, "after")
            self.action["status"] = audit.STATUS
        except BaseException as error:
            primary = error; self.action["error"] = str(error)
        finally:
            try:
                self.action.update(ended_monotonic_ns=time.monotonic_ns(), trace_start=start, trace_end=len(self.test.trace),
                    cleanup_owner="enclosing_original_guest_owner", sampler_stopped_by_action=False)
                inherited.current_client.finish_journal(self)
                write(directory / "commands.json", self.test.trace[start:])
                self.action["evidence"] = (inherited.acceptance.observations.inventory(directory, self.test.output,
                    [(self.test.output, self.test.trace, False)], self.test.container) if primary is None else
                    {str(p.relative_to(self.test.output)): inherited.admission.lane.mechanics.failed_file_ref(p)
                     for p in directory.rglob("*") if p.is_file()})
                write(directory / "attempt-ended.json", self.action)
            except BaseException as sealing_error:
                if primary is None: primary = sealing_error
                elif sealing_error is not primary: primary.add_note("Secondary evidence-sealing failure: " + repr(sealing_error))
            finally:
                self.action = None
        if primary is not None: raise primary
        try: verdict = audit.audit_action(directory / "attempt-ended.json", self.contract, self.identity,
            client_chain=self.current_client.chain, client_uid=self.current_client.uid)
        except BaseException as error:
            try:
                write(directory / "independent-audit-failure.json", dict(status="failed_original_raw_action_audit_not_qualified",
                    error=str(error), original_attempt=file_ref(directory / "attempt-ended.json"), runtime_qualified=False))
            except BaseException as sealing_error:
                if sealing_error is not error: error.add_note("Secondary independent failure-sealing error: " + repr(sealing_error))
            raise
        # Advance ONLY the independently proved role endpoint for subsequent
        # ordinary rounds. Original boot/stages and cumulative health floor are
        # untouched; no sampler replacement or baseline reset occurs.
        epochs = {package: {key: verdict["processes"][role][key] for key in ("pid", "start_ticks")}
                  for role, package in inherited.health.contract.PROCESS_NAMES.items()}
        old_core = dict(self.test.core_epochs)
        require(all(epochs[name] == old_core[name] for name in old_core if name != "com.android.systemui") and
                self.test.sampler is self.sampler, "Protected endpoint/observer changed before commit")
        self.test.core_epochs = {**old_core, "com.android.systemui": epochs["com.android.systemui"]}
        self.test.expected_processes = epochs
        return {"path": str(directory / "attempt-ended.json"), **file_ref(directory / "attempt-ended.json"),
                "runtime_qualified": False, "whole_campaign_complete": False}
