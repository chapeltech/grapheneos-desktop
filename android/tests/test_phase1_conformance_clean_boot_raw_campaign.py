"""Whole-auditor raw fixture tests. Synthetic bytes are never live evidence."""
import copy
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import conformance_clean_boot_raw_fixture as fixture
audit = fixture.audit
producer = fixture.producer

_real_png = audit.raw_audit.png_info
_pixel_cache = {}
pixel_decode_calls = 0

def exact_pixel_decoder(payload, regions=None):
    """Reuse only actual decoder output for identical bytes + exact arguments."""
    global pixel_decode_calls
    key = (hashlib.sha256(payload).hexdigest(), json.dumps(regions, sort_keys=True))
    if key not in _pixel_cache:
        pixel_decode_calls += 1
        print(f"Decoding actual full-size PNG variant {pixel_decode_calls}", flush=True)
        _pixel_cache[key] = _real_png(payload, regions)
    return copy.deepcopy(_pixel_cache[key])

class FullRawCampaignTests(unittest.TestCase):
    def setUp(self):
        self.campaign = fixture.Campaign(self)

    def check_rejection(self, regex):
        self.campaign.seal()
        with self.assertRaisesRegex(ValueError, regex):
            self.campaign.audit(exact_pixel_decoder)

    def test_complete_actual_auditor_accepts_all_64_synthetic_raw_stages(self):
        self.assertEqual(len(self.campaign.report["stages"]), 64)
        self.assertEqual(self.campaign.audit(exact_pixel_decoder),
            {"cycles": 20, "connectors": 3, "runtime_qualified": False, "qualification_claimed": False})

    def round_stages(self, prefix="round-1-"):
        self.campaign.seal()
        rows = [dict(row, name=prefix + row["name"]) for row in self.campaign.report["stages"][:61]]
        with patch.object(audit.raw_audit, "png_info", side_effect=exact_pixel_decoder):
            return [audit.parse_stage(self.campaign.runtime, row,
                self.campaign.report["runtime_evidence"], self.campaign.report["uids"]) for row in rows]

    def test_reusable_round_auditor_reopens_all_61_original_raw_populated_stages(self):
        stages = self.round_stages()
        self.assertEqual(audit.audit_populated_cycles(stages, phase_prefix="round-1-"),
            {"cycles": 20, "connectors": 3, "runtime_qualified": False, "qualification_claimed": False})
        # A reusable populated round does not contain the required final phone
        # recovery and therefore cannot substitute for a full clean-boot lane.
        with self.assertRaisesRegex(ValueError, "final recovery"):
            audit.audit_phases(stages)

    def test_reusable_round_requires_exact_ordinal_and_all_twenty_cycles(self):
        stages = self.round_stages()
        for changed in (stages[:-3], [*stages[:10], stages[9], *stages[11:]]):
            with self.assertRaisesRegex(ValueError, "20 populated"):
                audit.audit_populated_cycles(changed, phase_prefix="round-1-")
        with self.assertRaisesRegex(ValueError, "20 populated"):
            audit.audit_populated_cycles(stages, phase_prefix="round-2-")
        for prefix in ("round-0-", "round-01-", None):
            with self.assertRaisesRegex(ValueError, "round prefix"):
                audit.audit_populated_cycles(stages, phase_prefix=prefix)

    def test_reusable_round_preserves_original_hidden_input_rejection(self):
        def mutate(raw):
            rows = raw.splitlines()
            for index, row in enumerate(rows):
                if row.startswith("WONAD_PALETTE ") and fixture.COMPONENTS[0] in row:
                    value = json.loads(row.split("WONAD_PALETTE ", 1)[1]); value["key_downs"] += 1
                    rows[index] = "WONAD_PALETTE " + json.dumps(value)
            return "\n".join(rows) + "\n"
        self.campaign.rewrite(2, "fixture", mutate)
        stages = self.round_stages()
        with self.assertRaisesRegex(ValueError, "Hidden task received ordinary input"):
            audit.audit_populated_cycles(stages, phase_prefix="round-1-")

    def repeated_capture_guest(self):
        """Real producer/capture/parser; only Android transport is a fixture."""
        output = self.campaign.directory / "repeat-capture"; output.mkdir()
        guest = producer.Producer(self.campaign.report["container_id"], self.campaign.report["image_id"],
            self.campaign.report["boot_id"], self.campaign.report["fingerprint"], output, 120,
            core_epochs={name: fixture.EPOCHS[name] for name in audit.OS_NAMES})
        guest.instrument = Mock(); guest.instrument.poll.return_value = None
        guest.uids = self.campaign.report["uids"]
        originals = {row["name"]: row for row in self.campaign.report["stages"][:61]}
        def source_row(relative):
            label = Path(relative).parts[1].split("-", 1)[1]
            canonical = label.split("-", 2)[2] if label.startswith("round-") else label
            return originals[canonical]
        def read(relative, *args):
            row = source_row(relative)
            if args[0] == "pidof": source = row["processes"][args[1]]["pidof"]
            elif args[:3] == ("su", "0", "cat"):
                pid = int(args[-1].split("/")[2])
                name = next(name for name, data in fixture.EPOCHS.items() if data["pid"] == pid)
                source = row["processes"][name]["after" if relative.endswith("-after.txt") else "before"]
            else: source = row["files"][Path(relative).stem]
            raw = (self.campaign.runtime / source).read_bytes()
            target = output / relative; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
            guest._record({"kind": "command", "argv": ["explicit-fixture-transport", *map(str, args)],
                "evidence": relative, "returncode": 0, "output_sha256": hashlib.sha256(raw).hexdigest()})
            return raw.decode().strip()
        def frame(relative, slot):
            row = source_row(relative)
            raw = (self.campaign.runtime / row["frames"][str(slot)]).read_bytes()
            target = output / relative; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
        return guest, read, frame

    def test_two_rounds_use_actual_capture_order_raw_parsers_and_current_token_proof(self):
        initial = self.round_stages()[0]
        expected = audit.task_tokens(initial)
        guest, read, frame = self.repeated_capture_guest()
        original_instrument = guest.instrument
        hidden = {component: {"native_display": 11, "left": 0, "top": 0, "right": 100, "bottom": 100}
            for component in expected}
        status = {"snapshot": {"tasks": [{"token": token, "visible": False, "input_enabled": False} for token in expected.values()]}}
        with ExitStack() as stack:
            stack.enter_context(patch.object(guest, "read", side_effect=read))
            stack.enter_context(patch.object(guest, "_frame", side_effect=frame))
            stack.enter_context(patch.object(audit.raw_audit, "png_info", side_effect=exact_pixel_decoder))
            for name in ("attach", "detach", "runtime_command", "shell", "delivered", "home"):
                stack.enter_context(patch.object(guest, name))
            stack.enter_context(patch.object(guest, "records", return_value=hidden))
            stack.enter_context(patch.object(guest, "status", return_value=status))
            stack.enter_context(patch.object(guest, "displays", return_value={slot * 11: {"slot": slot, "display": slot * 11} for slot in (1, 2, 3)}))
            stack.enter_context(patch.object(guest, "runtime_task_ready", return_value=True))
            stack.enter_context(patch.object(guest, "runtime_topology_ready", return_value=True))
            stack.enter_context(patch.object(guest, "wait", side_effect=lambda label, predicate, **kwargs: predicate()))
            stack.enter_context(patch.object(producer.time, "sleep")); stack.enter_context(patch("builtins.print"))
            # capture_phase itself is deliberately NOT patched: real ordering,
            # protected epochs, original text fields and all PNGs are parsed.
            for ordinal in (1, 2):
                rows = guest.populated_hotplug_round(expected, phase_prefix=f"round-{ordinal}-")
                evidence = {str(path.relative_to(guest.output)): audit.file_ref(path) for path in guest.output.rglob("*") if path.is_file()}
                parsed = [audit.parse_stage(guest.output, row, evidence, guest.uids) for row in rows]
                self.assertEqual(audit.audit_populated_cycles(parsed, phase_prefix=f"round-{ordinal}-")["cycles"], 20)
        self.assertIs(guest.instrument, original_instrument)
        self.assertEqual(len(guest.phases), 122)
        self.assertEqual(guest.populated_rounds, 2)
        self.assertEqual([row["name"] for row in guest.phases],
            [f"round-{ordinal}-" + name for ordinal in (1, 2) for name in audit.PHASE_NAMES[:61]])

    def test_real_initial_capture_rejects_foreign_token_before_any_hotplug_action(self):
        expected = audit.task_tokens(self.round_stages()[0])
        expected[next(iter(expected))] += 100000
        guest, read, frame = self.repeated_capture_guest()
        with patch.object(guest, "read", side_effect=read), patch.object(guest, "_frame", side_effect=frame), \
             patch.object(audit.raw_audit, "png_info", side_effect=exact_pixel_decoder), \
             patch.object(guest, "runtime_command") as control, patch.object(guest, "detach") as detach, \
             patch("builtins.print"):
            with self.assertRaisesRegex(ValueError, "actual current lease observation"):
                guest.populated_hotplug_round(expected, phase_prefix="round-1-")
        control.assert_not_called(); detach.assert_not_called()
        self.assertEqual([row["name"] for row in guest.phases], ["round-1-initial"])

    def test_actual_final_capture_parser_failure_keeps_raw_row_and_forbids_retry(self):
        guest, read, frame = self.repeated_capture_guest()
        guest.populated_rounds = 1
        guest.populated_round_active = True
        guest.capture_names = tuple(f"round-{ordinal}-" + name for ordinal in (1, 2) for name in audit.PHASE_NAMES[:61])
        guest.phases = [{"name": name} for name in guest.capture_names[:-1]]
        with patch.object(guest, "read", side_effect=read), patch.object(guest, "_frame", side_effect=frame), \
             patch.object(audit, "parse_stage", side_effect=ValueError("controlled last raw parser failure")):
            with self.assertRaisesRegex(ValueError, "last raw parser failure"):
                guest.capture_phase("round-2-cycle-20-restored")
        self.assertEqual(len(guest.phases), 122)
        self.assertEqual(guest.phases[-1]["name"], "round-2-cycle-20-restored")
        self.assertTrue((guest.output / guest.phases[-1]["files"]["activities"]).is_file())
        tokens = {component: index + 101 for index, component in audit.COMPONENTS.items()}
        with patch.object(guest, "capture_phase") as capture, patch.object(guest, "runtime_command") as action:
            with self.assertRaisesRegex(ValueError, "incomplete"):
                guest.populated_hotplug_round(tokens, phase_prefix="round-2-")
        capture.assert_not_called(); action.assert_not_called()

    def test_missing_stage_cannot_discharge_twenty_cycles(self):
        del self.campaign.report["stages"][20]
        self.check_rejection("Exactly 20|bracket exact cycle phase")

    def test_duplicate_stage_is_rejected_even_with_valid_raw_hashes(self):
        self.campaign.report["stages"][20] = copy.deepcopy(self.campaign.report["stages"][19])
        self.check_rejection("overlap|Exactly 20")

    def test_stale_android_task_object_cannot_hide_behind_same_scalar_id(self):
        self.campaign.rewrite(3, "activities", lambda raw: raw.replace("Task{a000001 #10", "Task{a999999 #10"))
        self.check_rejection("Task/ActivityRecord/Binder/UID/process lifetime")

    def test_reused_sdk_task_token_is_not_continuity(self):
        def mutate(raw):
            value = json.loads(raw.split(producer.runtime.STATUS_MARKER, 1)[1])
            value["snapshot"]["tasks"][0]["token"] = 200
            return producer.runtime.STATUS_MARKER + json.dumps(value) + "\n"
        self.campaign.rewrite(3, "conformance", mutate)
        self.check_rejection("opaque task token")

    def test_stale_connector_token_cannot_be_rebound_to_new_android_display(self):
        def mutate(raw):
            value = json.loads(raw.split(producer.runtime.STATUS_MARKER, 1)[1])
            old = value["snapshot"]["display_incarnations"][-1]["token"]
            value["snapshot"]["display_incarnations"][-1]["token"] = 1003
            value["snapshot"]["display_incarnations"].sort(key=lambda row: row["token"])
            for task in value["snapshot"]["tasks"]:
                if task["display_token"] == old: task["display_token"] = 1003
            return producer.runtime.STATUS_MARKER + json.dumps(value) + "\n"
        self.campaign.rewrite(3, "conformance", mutate)
        self.campaign.rewrite(3, "activities", lambda raw: raw.replace("wonad-shell://77/1006", "wonad-shell://77/1003"))
        self.check_rejection("Stale display authority")

    def test_hidden_departed_task_receiving_input_fails_independent_raw_audit(self):
        def mutate(raw):
            rows = raw.splitlines()
            for index, row in enumerate(rows):
                if row.startswith("WONAD_PALETTE ") and fixture.COMPONENTS[0] in row:
                    value = json.loads(row.split("WONAD_PALETTE ", 1)[1]); value["key_downs"] += 1
                    rows[index] = "WONAD_PALETTE " + json.dumps(value)
            return "\n".join(rows) + "\n"
        self.campaign.rewrite(2, "fixture", mutate)
        self.check_rejection("Hidden task received ordinary input")

    def test_phone_focused_external_not_focusable_handles_remain_valid(self):
        # Existing task_input intentionally accepts NOT_FOCUSABLE when native
        # display 0 is globally focused. It still requires exact live handles.
        for phase in self.campaign.report["stages"][:61]:
            raw = (self.campaign.runtime / phase["files"]["input"]).read_text()
            self.assertIn("NOT_FOCUSABLE", raw)
        self.assertEqual(self.campaign.audit(exact_pixel_decoder)["cycles"], 20)

    def test_restored_inactive_monitor_cannot_have_not_touchable_app_handle(self):
        self.campaign.rewrite(3, "input", lambda raw: raw.replace(
            "name=a00000b org.wonad.fixture", "name=a00000b org.wonad.fixture").replace(
            "ownerUid=10181, inputConfig=NOT_FOCUSABLE", "ownerUid=10181, inputConfig=NOT_FOCUSABLE | NOT_TOUCHABLE"))
        self.check_rejection("live exact app input handle")

    def test_omitted_phone_epoch_fails_even_when_raw_files_are_retained(self):
        del self.campaign.report["stages"][7]["processes"]["com.android.phone"]
        self.check_rejection("Missing protected")

    def test_restarted_phone_epoch_fails_after_hashes_and_summary_are_resealed(self):
        phase = self.campaign.report["stages"][7]
        metric = phase["processes"]["com.android.phone"]
        for field in ("before", "after"):
            relative = metric[field]; path = self.campaign.runtime / relative
            path.write_text(path.read_text().replace("1004", "2004"))
            next(row for row in self.campaign.trace if row.get("evidence") == relative)["output_sha256"] = audit.sha256(path)
        metric["start_ticks"] = 2004
        self.check_rejection("Protected OS/phone/client epoch changed")

    def test_final_phone_recovery_requires_delivered_input_to_existing_task(self):
        self.campaign.rewrite(62, "fixture", lambda raw: raw.replace('"focused": true', '"focused": false'))
        self.check_rejection("ordinary phone input recovery")

    def test_final_phone_home_requires_native_global_display_zero_focus(self):
        self.campaign.rewrite(63, "windows", lambda raw: raw.replace("mTopFocusedDisplayId=0", "mTopFocusedDisplayId=3"))
        self.check_rejection("Native global focus")

    def test_structured_crash_record_is_not_confused_with_logged_command(self):
        self.campaign.rewrite(10, "events", lambda raw: raw +
            "10-13 21:00:00.100  100  100 I am_crash: [0,404,com.android.phone,1,java.lang.Exception,failed]\n")
        self.check_rejection("Unexpected crash/ANR")

    def test_runtime_cannot_precede_actual_setup_epoch_fences(self):
        self.campaign.trace[0]["started_monotonic_ns"] = 1
        self.campaign.trace[0]["ended_monotonic_ns"] = 2
        self.check_rejection("outside actual outer protected epoch window")

    def test_runtime_cannot_extend_after_actual_terminal_epoch_fences(self):
        for row in self.campaign.trace:
            for field in ("started_monotonic_ns", "ended_monotonic_ns"):
                if field in row: row[field] += 600000
        self.check_rejection("outside actual outer protected epoch window")

    def test_reported_uid_must_equal_raw_forward_and_reverse_observations(self):
        self.campaign.report["uids"][audit.APP] += 1
        self.check_rejection("UID summary differs")

    def test_foreign_reverse_uid_cannot_be_resealed_into_same_report(self):
        row = next(row for row in self.campaign.trace if "--uid" in row.get("argv", []))
        row["output"] = "package:other.package uid:10180\n"
        self.check_rejection("not reverse-bound")

    def test_missing_derived_uid_read_is_rejected_before_stage_parsing(self):
        index = next(index for index, row in enumerate(self.campaign.trace) if row.get("kind") == "derived")
        del self.campaign.trace[index]
        for number, row in enumerate(self.campaign.trace): row["sequence"] = number
        for phase in self.campaign.report["stages"]:
            phase["trace_start"] -= 1; phase["trace_end"] -= 1
        self.check_rejection("Missing or duplicated authoritative package identity")

class EpochAndEventRegressions(unittest.TestCase):
    def inventory(self):
        rows, raw = {}, {}
        for name in audit.PROCESS_NAMES:
            row = {**fixture.EPOCHS[name], **{field: name + '-' + field for field in ("pidof", "before", "after")}}
            raw[row["pidof"]] = str(row["pid"]); raw[row["before"]] = fixture.stat(name)
            raw[row["after"]] = fixture.stat(name, after=True); rows[name] = row
        return rows, raw

    def test_independent_epoch_allows_cpu_ticks_and_state_to_advance(self):
        rows, raw = self.inventory()
        self.assertEqual(audit.process_inventory(rows, raw), fixture.EPOCHS)

    def test_epoch_rejects_actual_start_time_change_between_reads(self):
        rows, raw = self.inventory(); row = rows["com.android.phone"]
        raw[row["after"]] = fixture.stat("com.android.phone", after=True, start=row["start_ticks"] + 1)
        with self.assertRaisesRegex(ValueError, "reused"):
            audit.process_inventory(rows, raw)

    def test_epoch_rejects_pid_change_between_reads(self):
        rows, raw = self.inventory(); row = rows["com.android.phone"]
        raw[row["after"]] = raw[row["after"]].replace("404 (", "405 (", 1)
        with self.assertRaisesRegex(ValueError, "Malformed protected"):
            audit.process_inventory(rows, raw)

    def test_actual_producer_retains_both_changed_stat_reads_and_checks_epoch(self):
        output = fixture.PRIVATE / "test-tmp" / "producer-epoch-fixture"
        output.mkdir(parents=True, exist_ok=True)
        guest = producer.Producer("c" * 64, "sha256:" + "a" * 64,
            "11111111-1111-1111-1111-111111111111", "fingerprint", output, 120, core_epochs=fixture.CORE)
        calls = []
        def read(relative, *argv):
            calls.append((relative, argv))
            if argv[0] == "pidof": return str(fixture.EPOCHS[argv[1]]["pid"])
            name = next(name for name in fixture.EPOCHS if argv[-1] == f"/proc/{fixture.EPOCHS[name]['pid']}/stat")
            return fixture.stat(name, after=relative.endswith("after.txt"))
        with patch.object(guest, "read", side_effect=read):
            result = guest.observe_epochs("epoch")
        self.assertEqual({name: {key: row[key] for key in ("pid", "start_ticks")} for name, row in result.items()}, fixture.EPOCHS)
        self.assertEqual(len(calls), 15)

    def test_structured_events_ignore_command_echo_but_reject_anr_and_crash(self):
        self.assertEqual(audit.crash_events("adbd : shell,v2:logcat -b events -d -v threadtime am_anr:I am_crash:I *:S\n"), [])
        for event in ("am_anr", "am_crash"):
            self.assertEqual(audit.crash_events(f"I {event}: [0,404,com.android.phone,1,reason]\n"),
                             [{"kind": event, "process": "com.android.phone"}])

if __name__ == "__main__":
    unittest.main(verbosity=2)
