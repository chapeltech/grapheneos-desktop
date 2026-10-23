"""Private host-only producer/auditor regressions; never a guest runtime PASS."""
import copy
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import sys

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import phase1_conformance_clean_boot as producer
audit = producer.acceptance


class CleanBootTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.core = {name: {"pid": index + 1, "start_ticks": index + 101}
                     for index, name in enumerate(audit.OS_NAMES)}

    def guest(self):
        return producer.Producer("c" * 64, "sha256:" + "a" * 64,
            "11111111-1111-1111-1111-111111111111", "test/fingerprint", self.root, 120,
            core_epochs=self.core)

    def test_twenty_cycle_plan_preserves_all_three_connectors_and_mixed_modes(self):
        self.assertEqual(len(audit.slot_plan()), 20)
        self.assertEqual({slot for _, slot in audit.slot_plan()}, {1, 2, 3})
        self.assertEqual(len({spec[:2] for spec in audit.SPECS.values()}), 3)
        self.assertEqual(len({spec[2] for spec in audit.SPECS.values()}), 3)
        self.assertEqual(len(audit.PHASE_NAMES), 64)
        self.assertEqual(audit.PROCESS_NAMES, (*audit.OS_NAMES, "org.wonad.desktop"))

    def test_old_selected_packet_is_refused_before_output_or_guest_exists(self):
        packet = self.root / "old-packet"; (packet / "evidence/compile-input").mkdir(parents=True)
        (packet / "evidence/compile-input/source-freeze.json").write_text(json.dumps({"files": {}}))
        output = self.root / "no-guest-created"
        with patch.object(producer.fresh, "Producer") as launch, self.assertRaisesRegex(ValueError, "predates exact observed-replay"):
            producer.run_guest("sha256:" + "a" * 64, self.root, packet, "f" * 64, output)
        self.assertFalse(output.exists()); launch.assert_not_called()

    def test_source_binding_requires_exact_new_helper_and_current_client_bytes(self):
        packet = self.root / "new-packet"; (packet / "evidence/compile-input").mkdir(parents=True)
        sources = {relative: producer.file_ref(producer.ROOT / relative) for relative in producer.CLIENT_FILES}
        target = packet / "evidence/compile-input/source-freeze.json"
        target.write_text(json.dumps({"files": sources}))
        self.assertEqual(producer.bind_client_sources(packet)["files"], sources)
        changed = copy.deepcopy(sources); changed[producer.CLIENT_FILES[-1]]["sha256"] = "0" * 64
        target.write_text(json.dumps({"files": changed}))
        with self.assertRaisesRegex(ValueError, "predates exact observed-replay"):
            producer.bind_client_sources(packet)

    def test_held_instrumentation_retains_handle_output_and_exact_runtime_argv(self):
        guest = self.guest(); handle = Mock()
        handle.poll.return_value = None; handle.wait.return_value = 0
        with patch.object(producer.subprocess, "Popen", return_value=handle) as spawn, \
             patch.object(guest, "wait", return_value={"ready": True}):
            self.assertEqual(guest.start_runtime(), {"ready": True})
        self.assertIs(guest.instrument, handle)
        self.assertIs(spawn.call_args.kwargs["stdout"], guest.instrument_file)
        self.assertNotEqual(spawn.call_args.kwargs["stdout"], producer.subprocess.DEVNULL)
        self.assertIn("runtime", spawn.call_args.args[0]); self.assertNotIn("full", spawn.call_args.args[0])
        guest.instrument_file.write(b"retained raw instrument output\n")
        guest.stop_background()
        handle.terminate.assert_called_once()
        self.assertEqual(guest.instrument_path.read_bytes(), b"retained raw instrument output\n")
        self.assertIsNone(guest.instrument_file)

    def test_unexpected_instrumentation_exit_is_fatal_and_never_readiness(self):
        guest = self.guest(); guest.instrument = Mock(); guest.instrument.poll.return_value = 0
        with self.assertRaisesRegex(ValueError, "ended unexpectedly"):
            guest.alive()

    def test_deadline_cannot_be_extended_by_a_ready_predicate(self):
        guest = self.guest(); guest.deadline_ns = 1
        with self.assertRaisesRegex(TimeoutError, "waiting"):
            guest.wait("pretend ready", lambda: True)

    def test_five_role_proc_inventory_rejects_omission_reuse_and_pid_alias(self):
        rows, raw = {}, {}
        for index, name in enumerate(audit.PROCESS_NAMES):
            pid, ticks = index + 10, index + 100
            before, after, pidof = name + "-before", name + "-after", name + "-pidof"
            stat = f"{pid} ({name}) S " + " ".join(["1"] * 18 + [str(ticks)]) + "\n"
            raw.update({pidof: str(pid), before: stat, after: stat})
            rows[name] = {"pid": pid, "start_ticks": ticks, "pidof": pidof, "before": before, "after": after}
        self.assertEqual(len(audit.process_inventory(rows, raw)), 5)
        for role in ("com.android.phone", "org.wonad.desktop"):
            omitted = copy.deepcopy(rows); del omitted[role]
            with self.assertRaisesRegex(ValueError, "Missing protected"):
                audit.process_inventory(omitted, raw)
        reused = dict(raw)
        old = str(rows["com.android.phone"]["start_ticks"])
        reused[rows["com.android.phone"]["after"]] = reused[rows["com.android.phone"]["after"]].replace(old, str(int(old) + 1))
        with self.assertRaisesRegex(ValueError, "reused"):
            audit.process_inventory(rows, reused)

    def test_runtime_handshake_enforces_exact_nonce_and_explicit_phase(self):
        guest = self.guest(); nonce = "f" * 32
        acknowledged = {"run": guest.conformance_run, "state": "ready",
                        "handshake": {"nonce": nonce, "phase": "remember-observed", "result": "accepted"}}
        def wait(label, predicate, **unused):
            return True if label == "current ready topology" else predicate()
        marker = producer.runtime.CONTROL_MARKER + f"accepted {guest.conformance_run} {nonce} remember-observed"
        with patch.object(guest, "wait", side_effect=wait), patch.object(guest, "shell", return_value=marker), \
             patch.object(guest, "status", return_value=acknowledged), patch.object(producer.secrets, "token_hex", return_value=nonce):
            self.assertEqual(guest.runtime_command("remember-observed"), acknowledged)
        for invalid in ("layout", "expect-revocation"):
            with self.subTest(phase=invalid), patch.object(guest, "shell") as action:
                with self.assertRaisesRegex(ValueError, "Unreviewed"):
                    guest.runtime_command(invalid)
                action.assert_not_called()

    def test_auditor_never_accepts_a_product_report_or_a_short_cycle_list(self):
        target = self.root / "report.json"
        target.write_text(json.dumps({"kind": "native_v3_normal_startup_three_monitor_matrix", "cycles": 20}))
        with self.assertRaisesRegex(ValueError, "policy-free"):
            audit.audit_report(target)
        with self.assertRaisesRegex(ValueError, "Exactly 20"):
            audit.audit_phases([])

    def test_final_deferred_configuration_requires_authoritative_phone_membership(self):
        raw = "TASK leaf id=7 userId=0 displayId=3(type=VIRTUAL)\nWONAD_PALETTE " + json.dumps({
            "component": audit.COMPONENTS[1], "task": 7, "display": 3,
            "instance": "11111111-1111-1111-1111-111111111111", "pid": 20, "uid": 10180,
            "left": 0, "top": 0, "right": 100, "bottom": 100, "key_downs": 0,
            "pointer_downs": 0, "mouse_downs": 0, "lifecycle": "stopped"})
        with self.assertRaisesRegex(ValueError, "exact native phone survivor"):
            audit.final_fixture_lifetimes(raw, "", 10180)

    def test_stock_chrome_and_decoration_handles_are_not_silently_ignored(self):
        for title in ("Taskbar", "DesktopWallpaperActivity", "DragResizeInputListener", "DecorCaption"):
            with self.subTest(title=title), self.assertRaisesRegex(ValueError, "Stock"):
                audit.stock_chrome(f"Window #0 Window{{a u0 {title}}}:\n mDisplayId=3\n", "", {3})
        with self.assertRaisesRegex(ValueError, "Stock"):
            audit.stock_chrome("Window #0 Window{a u0 StatusBar}:\n mDisplayId=3\n ty=STATUS_BAR\n", "", {3})

    def test_actual_exercise_keeps_twenty_populated_cycles_and_final_phone_recovery(self):
        guest = self.guest(); live, records, phases, controls, actions = {}, {}, [], [], []
        tokens = {component: index + 101 for index, component in audit.COMPONENTS.items()}
        serial = [10]
        def attach(slot):
            serial[0] += 1
            display = serial[0]
            live[slot] = {"slot": slot, "display": display, "width": audit.SPECS[slot][0],
                          "height": audit.SPECS[slot][1], "density": audit.SPECS[slot][2]}
            actions.append(("attach", slot)); return live[slot]
        def detach(slot):
            removed = live.pop(slot)["display"]; actions.append(("detach", slot))
            destination = next(iter(live.values()))["display"] if live else 0
            for record in records.values():
                if record["display"] == removed:
                    record["display"] = record["native_display"] = destination; record["focused"] = False
            return True
        def populate():
            for slot, component in audit.COMPONENTS.items():
                records[component] = {"display": live[slot]["display"], "native_display": live[slot]["display"], "focused": False,
                    "left": 0, "top": 0, "right": 100, "bottom": 100, "key_downs": 0, "mouse_downs": 0}
        def status():
            return {"state": "ready" if live else "waiting-reopen", "snapshot": {
                "tasks": [{"token": token, "visible": False, "input_enabled": False}
                          for token in tokens.values()]}}
        def shell(*args, **kwargs):
            if args == ("dumpsys", "window", "windows"): return "mTopFocusedDisplayId=0\n"
            if args[:4] == ("input", "touchscreen", "-d", 0) and args[4] == "tap":
                records[audit.COMPONENTS[1]]["focused"] = True
            return ""
        def capture(name):
            phases.append(name)
            guest.phases.append({"name": name})
            return {"records": copy.deepcopy(records)}
        def restore(phase):
            controls.append(phase)
            if phase == "restore-observed":
                for slot, component in audit.COMPONENTS.items():
                    records[component]["display"] = records[component]["native_display"] = live[slot]["display"]
            return {}
        def delivered(component, display, final=False):
            self.assertEqual(records[component]["display"], display)
            records[component]["key_downs"] += 1; records[component]["mouse_downs"] += 1
            actions.append(("delivered", component, display))
        def finish():
            controls.append("stop"); guest.instrument_path.parent.mkdir(parents=True, exist_ok=True)
            guest.instrument_path.write_text("controlled terminal fixture\n"); return {"state": "stopped"}
        contexts = [patch.object(guest, "inspect_container"), patch.object(guest, "package_identities", return_value={}),
            patch.object(guest, "attach", side_effect=attach), patch.object(guest, "detach", side_effect=detach),
            patch.object(guest, "populate", side_effect=populate), patch.object(guest, "start_runtime"),
            patch.object(guest, "displays", side_effect=lambda: {row["display"]: row for row in live.values()}),
            patch.object(guest, "capture_phase", side_effect=capture), patch.object(guest, "runtime_command", side_effect=restore),
            patch.object(guest, "records", side_effect=lambda final=False: records), patch.object(guest, "status", side_effect=status),
            patch.object(guest, "runtime_topology_ready", return_value=True),
            patch.object(guest, "runtime_task_ready", return_value=True),
            patch.object(guest, "wait", side_effect=lambda label, predicate, **unused: predicate()),
            patch.object(guest, "shell", side_effect=shell), patch.object(guest, "delivered", side_effect=delivered),
            patch.object(guest, "enter_phone_overview"), patch.object(guest, "hierarchy", return_value="<hierarchy/>"),
            patch.object(guest, "finish_instrumentation", side_effect=finish), patch.object(producer.time, "sleep"),
            patch.object(audit, "task_tokens", return_value=tokens),
            patch.object(producer.raw_audit, "recents_card", return_value=([540, 1200], (0, 0, 1080, 2400))),
            patch.object(producer.raw_audit, "instrumentation_success", return_value=True), patch("builtins.print")]
        with ExitStack() as stack:
            for context in contexts: stack.enter_context(context)
            self.assertEqual(guest.exercise(), {"state": "stopped"})
        self.assertEqual(phases, list(audit.PHASE_NAMES))
        self.assertEqual(controls, [phase for _ in range(20) for phase in ("remember-observed", "restore-observed")] + ["stop"])
        self.assertEqual([action[1] for action in actions if action[0] == "detach"],
                         [slot for _, slot in audit.slot_plan()] + [3, 2, 1])
        self.assertEqual(sum(action[0] == "delivered" for action in actions), 21)

    def test_actual_populated_body_repeats_without_restarting_guest_or_runtime(self):
        guest = self.guest()
        guest.instrument = Mock(); guest.instrument.poll.return_value = None
        original_instrument = guest.instrument
        tokens = {component: index + 101 for index, component in audit.COMPONENTS.items()}
        records = {component: {"native_display": 11, "left": 0, "top": 0, "right": 100, "bottom": 100}
            for component in tokens}
        status = {"snapshot": {"tasks": [{"token": token, "visible": False, "input_enabled": False} for token in tokens.values()]}}
        def capture(name):
            value = {"name": name}; guest.phases.append(value); return value
        with ExitStack() as stack:
            calls = {}
            for name in ("inspect_container", "populate", "start_runtime", "finish_instrumentation", "stop_background",
                         "attach", "detach", "runtime_command", "shell", "delivered", "home"):
                calls[name] = stack.enter_context(patch.object(guest, name))
            stack.enter_context(patch.object(guest, "capture_phase", side_effect=capture))
            stack.enter_context(patch.object(audit, "task_tokens", return_value=tokens))
            stack.enter_context(patch.object(guest, "status", return_value=status))
            stack.enter_context(patch.object(guest, "records", return_value=records))
            stack.enter_context(patch.object(guest, "displays", return_value={slot * 11: {"slot": slot, "display": slot * 11} for slot in (1, 2, 3)}))
            stack.enter_context(patch.object(guest, "runtime_task_ready", return_value=True))
            stack.enter_context(patch.object(guest, "runtime_topology_ready", return_value=True))
            stack.enter_context(patch.object(guest, "wait", side_effect=lambda label, predicate, **kwargs: predicate()))
            stack.enter_context(patch.object(producer.time, "sleep")); stack.enter_context(patch("builtins.print"))
            rounds = [guest.populated_hotplug_round(tokens, phase_prefix=f"round-{ordinal}-") for ordinal in (1, 2)]
        self.assertIs(guest.instrument, original_instrument)
        self.assertEqual([len(rows) for rows in rounds], [61, 61])
        self.assertEqual([row["name"] for row in guest.phases],
            [f"round-{ordinal}-" + name for ordinal in (1, 2) for name in audit.PHASE_NAMES[:61]])
        for name in ("inspect_container", "populate", "start_runtime", "finish_instrumentation", "stop_background"):
            calls[name].assert_not_called()
        self.assertEqual(calls["detach"].call_count, 40)
        self.assertEqual(calls["attach"].call_count, 40)
        self.assertEqual(calls["delivered"].call_count, 40)
        self.assertEqual([call.args[0] for call in calls["runtime_command"].call_args_list],
            [phase for _ in range(40) for phase in ("remember-observed", "restore-observed")])

    def test_repeatable_body_rejects_wrong_identity_and_round_before_any_action(self):
        guest = self.guest()
        tokens = {component: index + 101 for index, component in audit.COMPONENTS.items()}
        invalid = ({}, {**tokens, "foreign/Task": 99}, dict.fromkeys(tokens, 101),
                   {**tokens, next(iter(tokens)): True}, {**tokens, next(iter(tokens)): 0})
        with patch.object(guest, "runtime_command") as action:
            for value in invalid:
                with self.assertRaisesRegex(ValueError, "token map"):
                    guest.populated_hotplug_round(value, phase_prefix="round-1-")
            for prefix in ("round-0-", "round-01-", "cycle-1-", "../", None):
                with self.assertRaisesRegex(ValueError, "phase prefix"):
                    guest.populated_hotplug_round(tokens, phase_prefix=prefix)
        action.assert_not_called()

    def test_failed_final_capture_never_admits_replacement_round(self):
        guest = self.guest()
        tokens = {component: index + 101 for index, component in audit.COMPONENTS.items()}
        guest.populated_rounds = 1
        guest.populated_round_active = True
        guest.capture_names = tuple(f"round-{ordinal}-" + name for ordinal in (1, 2) for name in audit.PHASE_NAMES[:61])
        guest.phases = [{"name": name} for name in guest.capture_names]
        with patch.object(guest, "capture_phase") as capture, patch.object(guest, "runtime_command") as action:
            with self.assertRaisesRegex(ValueError, "incomplete"):
                guest.populated_hotplug_round(tokens, phase_prefix="round-2-")
        capture.assert_not_called(); action.assert_not_called()
        self.assertEqual(len(guest.phases), 122)
        self.assertEqual(guest.populated_rounds, 1)


if __name__ == "__main__":
    unittest.main()
