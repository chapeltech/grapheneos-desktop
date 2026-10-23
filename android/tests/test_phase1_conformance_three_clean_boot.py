"""Private aggregate controls. Skeleton children here are NOT guest evidence.

The companion raw test runs all three complete real child auditors against
synthetic raw fixtures; these faster tests isolate aggregate/producer controls.
"""
from pathlib import Path
import copy
import json
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import phase1_conformance_three_clean_boot as producer
audit = producer.acceptance
from phase1_conformance_common import canonical, file_ref, load


def write(path, value):
    path.write_bytes(canonical(value))


class ThreeBootTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.product = self.root / "product"; self.product.mkdir()
        self.packet = self.root / "packet"; (self.packet / "evidence/compile-input").mkdir(parents=True)
        write(self.packet / "receipt.json", {"synthetic_test_packet": True})
        paths = [audit.ROOT / (name + "/build.gradle.kts") for name in ("android/conformance", "android/desktop-sdk")]
        for name in ("android/conformance/src/main", "android/desktop-sdk/src/main"):
            paths.extend(path for path in (audit.ROOT / name).rglob("*") if path.is_file())
        write(self.packet / "evidence/compile-input/source-freeze.json", {
            "files": {str(path.relative_to(audit.ROOT)): file_ref(path) for path in paths}})
        self.image = "sha256:" + "a" * 64
        self.receipt = file_ref(self.packet / "receipt.json")["sha256"]
        self.contract = audit.input_contract(self.image, self.product, self.packet, self.receipt)
        self.output = self.root / "aggregate"

    def child(self, directory, index, *, clock=False):
        directory.mkdir(); state = directory / "emulator-state"; state.mkdir(); (state / "tmp").mkdir()
        actual = state.stat()
        userdata = {"path": str(state), "dev": actual.st_dev, "ino": actual.st_ino,
            "mode": 0o700, "uid": os.getuid(), "gid": os.getgid()}
        write(directory / "prelaunch-userdata.json", {"state": userdata})
        write(directory / "image-manifest.json", {"synthetic_conformance_image": True})
        write(directory / "product-candidate-manifest.json", {"emulator_runtime": {
            "sha256": "f" * 64, "files": {"emulator": {"sha256": "e" * 64}}}})
        roles = {"producer": "child_producer", "auditor": "child_auditor", "runtime_status": "runtime_status",
            "fresh_guest": "fresh_guest", "stream_mechanics": "stream_mechanics",
            "raw_window_pixel_audit": "raw_window_pixel_audit"}
        started = time.monotonic_ns() if clock else index * 1000 + 100
        ended = time.monotonic_ns() if clock else index * 1000 + 900
        report = {"image_id": self.image, "packet": str(self.packet), "product": str(self.product),
            "packet_receipt_sha256": self.receipt, "client_sources": {
                "source_freeze": self.contract["compiled_sources"]["source_freeze"],
                "files": {name: self.contract["compiled_sources"]["files"][name] for name in audit.child.CLIENT_FILES}},
            "source_files": {role: self.contract["host_sources"][name] for role, name in roles.items()},
            "boot_id": f"0000000{index + 1}-1234-1234-1234-000000000001", "container_id": str(index + 1) * 64,
            "container_run": str(index + 4) * 32, "conformance_run": str(index + 7) * 32,
            "prelaunch_state": {"state": userdata}, "started_monotonic_ns": started, "ended_monotonic_ns": ended,
            "stages": [{"name": name} for name in audit.child.acceptance.PHASE_NAMES]}
        write(directory / "report.json", report)
        return report

    def synthetic_child_audit(self, path):
        # Explicit boundary: no raw window/PNG/Android proof in skeletons.
        report = load(path)
        if [row["name"] for row in report["stages"]] != list(audit.child.acceptance.PHASE_NAMES):
            raise ValueError("Exactly 20 populated cycles required by synthetic child boundary")
        return copy.deepcopy(audit.CHILD_RESULT)

    def fixture(self):
        self.output.mkdir()
        write(self.output / "contract-before.json", self.contract)
        attempts = []
        for index, name in enumerate(audit.BOOT_DIRS):
            report = self.child(self.output / name, index)
            attempt = {"directory": name, "status": "passed_original_child", "error": None,
                "started_monotonic_ns": index * 1000 + 1, "ended_monotonic_ns": index * 1000 + 999,
                "report": file_ref(self.output / name / "report.json")}
            write(self.output / (name + "-started.json"), {key: value for key, value in
                {**attempt, "status": "started", "report": None}.items() if key != "ended_monotonic_ns"})
            write(self.output / (name + "-ended.json"), attempt); attempts.append(attempt)
        write(self.output / "attempts.json", attempts)
        with patch.object(audit.child.acceptance, "audit_report", side_effect=self.synthetic_child_audit):
            children = audit.audit_children(self.output, self.contract)
        report = {"schema": 1, "kind": audit.KIND, "scope": audit.SCOPE, "status": audit.STATUS,
            "boot_count": 3, "cycles_per_boot": 20, "connectors": 3, "runtime_qualified": False,
            "qualification_claimed": False, "separate_24h_campaign_required": True, "contract": self.contract,
            "children": children, "attempts": attempts, "attempt_journal": file_ref(self.output / "attempts.json"),
            "started_monotonic_ns": 1, "ended_monotonic_ns": 4000}
        write(self.output / "report.json", report)
        return report

    def check(self, *, seal=None):
        seal = seal or file_ref(self.output / "report.json")["sha256"]
        with patch.object(audit.child.acceptance, "audit_report", side_effect=self.synthetic_child_audit) as independently:
            result = audit.audit_report(self.output / "report.json", seal)
        return result, independently.call_count

    def mutate_child(self, index, mutate):
        path = self.output / audit.BOOT_DIRS[index] / "report.json"
        report = load(path); mutate(report); write(path, report)

    def test_three_original_children_independently_audited_and_never_24h_substitution(self):
        self.fixture(); result, calls = self.check()
        self.assertEqual(calls, 3); self.assertEqual(result["boot_count"], 3)
        self.assertFalse(result["runtime_qualified"]); self.assertTrue(result["separate_24h_campaign_required"])

    def test_duplicate_actual_boot_rejected_even_with_three_output_directories(self):
        self.fixture(); first = load(self.output / "boot-01/report.json")
        self.mutate_child(1, lambda row: row.update(boot_id=first["boot_id"]))
        with self.assertRaisesRegex(ValueError, "Duplicate actual boot_id"): self.check()

    def test_duplicate_container_and_both_run_identities_rejected(self):
        self.fixture(); first = load(self.output / "boot-01/report.json")
        second = load(self.output / "boot-02/report.json")
        for key in ("container_id", "container_run", "conformance_run"):
            with self.subTest(key=key):
                altered = copy.deepcopy(second); altered[key] = first[key]
                write(self.output / "boot-02/report.json", altered)
                with self.assertRaisesRegex(ValueError, "Duplicate actual " + key): self.check()
        write(self.output / "boot-02/report.json", second)

    def test_foreign_image_rejected_by_actual_child_record_not_summary(self):
        self.fixture(); self.mutate_child(1, lambda row: row.update(image_id="sha256:" + "b" * 64))
        with self.assertRaisesRegex(ValueError, "foreign image"): self.check()

    def test_reused_actual_userdata_inode_rejected_with_distinct_paths(self):
        self.fixture(); first = load(self.output / "boot-01/prelaunch-userdata.json")
        second_path = self.output / "boot-02/prelaunch-userdata.json"
        second = load(second_path)
        second["state"].update(dev=first["state"]["dev"], ino=first["state"]["ino"])
        write(second_path, second)
        self.mutate_child(1, lambda row: row.update(prelaunch_state=second))
        with self.assertRaisesRegex(ValueError, "Duplicate actual userdata"): self.check()

    def test_changed_sdk_manifest_is_not_same_immutable_runtime(self):
        self.fixture(); manifest = self.output / "boot-02/product-candidate-manifest.json"
        value = load(manifest); value["emulator_runtime"]["sha256"] = "1" * 64
        write(manifest, value)
        with self.assertRaisesRegex(ValueError, "image/SDK manifest changed"): self.check()

    def test_failed_marker_symlink_is_not_hidden_as_an_absent_attempt(self):
        self.fixture(); (self.output / "boot-02/failure.json").symlink_to(self.root / "absent")
        with self.assertRaisesRegex(ValueError, "Failed/unfinalized child"): self.check()

    def test_skipped_cycle_rejected_by_independent_child_audit(self):
        self.fixture(); self.mutate_child(1, lambda row: row["stages"].pop(20))
        with self.assertRaisesRegex(ValueError, "Exactly 20"): self.check()

    def test_changed_source_cannot_be_substituted_in_preboot_and_summary(self):
        report = self.fixture(); altered = copy.deepcopy(self.contract)
        altered["host_sources"]["child_producer"]["sha256"] = "0" * 64
        write(self.output / "contract-before.json", altered); report["contract"] = altered
        write(self.output / "report.json", report)
        with self.assertRaisesRegex(ValueError, "contract changed since before"): self.check()

    def test_failed_child_is_fatal_while_other_original_children_still_audited(self):
        self.fixture(); write(self.output / "boot-02/failure.json", {"status": "failed"})
        with patch.object(audit.child.acceptance, "audit_report", side_effect=self.synthetic_child_audit) as reopened:
            with self.assertRaisesRegex(ValueError, "Failed/unfinalized child"):
                audit.audit_children(self.output, self.contract)
        self.assertEqual(reopened.call_count, 2)

    def test_failed_attempt_summary_cannot_be_resealed_to_passing(self):
        report = self.fixture(); attempts = load(self.output / "attempts.json")
        attempts[1]["status"] = "failed_original_child"
        write(self.output / "attempts.json", attempts)
        report.update(attempts=attempts, attempt_journal=file_ref(self.output / "attempts.json"))
        write(self.output / "report.json", report)
        with self.assertRaisesRegex(ValueError, "Failed/skipped"): self.check()

    def test_resealed_aggregate_summary_fails_original_pin_and_raw_comparison(self):
        report = self.fixture(); original = file_ref(self.output / "report.json")["sha256"]
        report["children"][1]["identity"]["boot_id"] = "99999999-1234-1234-1234-000000000001"
        write(self.output / "report.json", report)
        with self.assertRaisesRegex(ValueError, "seal changed"): self.check(seal=original)
        with self.assertRaisesRegex(ValueError, "summary differs"): self.check()

    def test_fourth_or_unreported_attempt_is_not_discardable(self):
        self.fixture(); (self.output / "boot-04").mkdir()
        with self.assertRaisesRegex(ValueError, "extra child attempt"): self.check()

    def test_policy_or_runtime_qualification_cannot_be_claimed(self):
        report = self.fixture(); report["runtime_qualified"] = True
        write(self.output / "report.json", report)
        with self.assertRaisesRegex(ValueError, "bounded conformance aggregate"): self.check()

    def test_producer_invokes_exact_existing_child_three_times_and_owns_no_guest_hooks(self):
        calls = []
        def controlled(image, product, packet, receipt, output, timeout):
            calls.append((image, product, packet, receipt, output, timeout))
            return self.child(output, len(calls) - 1, clock=True)
        with patch.object(producer.child, "run_guest", side_effect=controlled), \
             patch.object(audit.child.acceptance, "audit_report", side_effect=self.synthetic_child_audit):
            result = producer.run_campaign(self.image, self.product, self.packet, self.receipt, self.output, 90)
        self.assertEqual([row[4].name for row in calls], list(audit.BOOT_DIRS))
        self.assertTrue(all(row[:4] == (self.image, self.product, self.packet, self.receipt) and row[-1] == 90 for row in calls))
        self.assertEqual(result["sha256"], file_ref(self.output / "report.json")["sha256"])

    def test_producer_preserves_failed_original_attempt_and_never_retries(self):
        def failed(*args):
            output = args[4]; output.mkdir(); write(output / "failure.json", {"original_failure": "retained"})
            raise ValueError("controlled original child failure")
        with patch.object(producer.child, "run_guest", side_effect=failed) as launched:
            with self.assertRaisesRegex(ValueError, "original child failure"):
                producer.run_campaign(self.image, self.product, self.packet, self.receipt, self.output)
        self.assertEqual(launched.call_count, 1); self.assertFalse((self.output / "boot-02").exists())
        self.assertEqual(load(self.output / "boot-01/failure.json"), {"original_failure": "retained"})
        self.assertEqual(load(self.output / "attempts.json")[0]["status"], "failed_original_child")
        self.assertTrue((self.output / "boot-01-started.json").exists()); self.assertTrue((self.output / "boot-01-ended.json").exists())
        self.assertFalse((self.output / "report.json").exists()); self.assertTrue((self.output / "failure.json").exists())

    def test_input_drift_after_child_stops_before_second_launch_and_preserves_first(self):
        count = [0]
        def contract(*unused):
            count[0] += 1
            return self.contract if count[0] < 3 else {**self.contract, "image_id": "sha256:" + "b" * 64}
        with patch.object(audit, "input_contract", side_effect=contract), \
             patch.object(producer.child, "run_guest", side_effect=lambda *args: self.child(args[4], 0, clock=True)) as launched, \
             patch.object(audit.child.acceptance, "audit_report", side_effect=self.synthetic_child_audit):
            with self.assertRaisesRegex(ValueError, "changed during child"):
                producer.run_campaign(self.image, self.product, self.packet, self.receipt, self.output)
        self.assertEqual(launched.call_count, 1); self.assertTrue((self.output / "boot-01/report.json").exists())

    def test_observed_tool_byte_change_after_child_stops_campaign(self):
        tool = self.root / "controlled-observer.py"; tool.write_text("original test-only observer\n")
        original_sources = audit.source_contract()
        def current_sources():
            return {**original_sources, "controlled_test_observer": {"path": str(tool), **file_ref(tool)}}
        def changed_child(*args):
            args[4].mkdir(); write(args[4] / "report.json", {"synthetic_child": True})
            tool.write_text("changed test-only observer\n")
        with patch.object(audit, "source_contract", side_effect=current_sources), \
             patch.object(producer.child, "run_guest", side_effect=changed_child) as launched, \
             patch.object(audit, "child_record"):
            with self.assertRaisesRegex(ValueError, "changed during child"):
                producer.run_campaign(self.image, self.product, self.packet, self.receipt, self.output)
        self.assertEqual(launched.call_count, 1); self.assertTrue((self.output / "boot-01/report.json").exists())

    def test_output_reuse_or_old_packet_fails_before_any_child(self):
        self.output.mkdir()
        with patch.object(producer.child, "run_guest") as launched:
            with self.assertRaisesRegex(ValueError, "Never reuse"):
                producer.run_campaign(self.image, self.product, self.packet, self.receipt, self.output)
        launched.assert_not_called()
        write(self.packet / "evidence/compile-input/source-freeze.json", {"files": {}})
        with patch.object(producer.child, "run_guest") as launched:
            with self.assertRaisesRegex(ValueError, "exact current client/SDK"):
                producer.run_campaign(self.image, self.product, self.packet, self.receipt, self.root / "fresh")
        launched.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
