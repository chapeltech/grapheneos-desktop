"""Host-only comparator tests; FakeBackend does not run Docker or Android."""

import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock


TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
sys.path.insert(0, str(TESTS.parent / "tools"))
import phase1_upstream_test_comparison as comparison
import run_phase1_upstream_tests as runner
import test_run_phase1_upstream_tests as runner_tests


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ComparisonBackend(runner_tests.FakeBackend):
    def __init__(self, fixture, role):
        super().__init__(fixture.image, fixture.fingerprint, fixture.artifacts)
        self.role = role
        self.case_overrides = {}
        self.omit = set()
        self.extra = []

    def adb(self, adb, broker, serial, arguments, *, timeout=60):
        result = super().adb(adb, broker, serial, arguments, timeout=timeout)
        if self.role == "custom" and arguments == [
                "shell", "cat", "/proc/sys/kernel/random/boot_id"]:
            return subprocess.CompletedProcess(
                arguments, 0, "87654321-4321-4321-4321-cba987654321\n")
        return result

    def atest_value(self, suite):
        group = "WmTests" if suite == "wmtests" else suite
        names = ["Class#method"]
        if suite == "grapheneos_secure_paste":
            group = "InputTests"
            names = [case.split("/InputTests/", 1)[1]
                     for case in sorted(comparison.REQUIRED_GRAPHENEOS_CASES)]
        if self.role == "custom" and suite == "wmtests":
            names += [case.split("/WmTests/", 1)[1]
                      for case in sorted(comparison.CUSTOM_ONLY_CASES[suite])]
            names += self.extra
        rows = {"PASSED": [], "FAILED": [], "IGNORED": []}
        for name in names:
            if name not in self.omit:
                rows[self.case_overrides.get(name, "PASSED")].append({"test_name": name})
        summary = {status: len(values) for status, values in rows.items()}
        return {"test_runner": {"AtestTradefedTestRunner": {group: {
                    **rows, "summary": summary}}}, "total_summary": summary}


class IsolatedComparison(unittest.TestCase):
    def setUp(self):
        self.fixtures = {}
        for role in ("baseline", "custom"):
            fixture = runner_tests.IsolatedUpstreamRunner()
            fixture.setUp()
            self.addCleanup(fixture.tearDown)
            fixture.receipt["role"] = role
            fixture.receipt["source"]["stage"] = (
                {"state": "absent"} if role == "baseline" else {
                    "state": "schema-4-owned-stage", "marker": {"patches": {
                        "frameworks_base": [{"name": name, "sha256": sha}
                            for name, sha in comparison.CUSTOM_CASE_PATCHES.items()]}}})
            self.fixtures[role] = fixture
            fixture.backend = ComparisonBackend(fixture, role)
            self.refresh_build(role)
        self.pair = self.fixtures["baseline"].root / "pair.json"
        self.pair.write_text("{}\n")
        self.pair_patch = mock.patch.object(comparison, "verify_build_comparison")
        self.pair_verify = self.pair_patch.start()
        self.addCleanup(self.pair_patch.stop)
        self.runner_patch = mock.patch.object(comparison, "isolated_runner", return_value=runner)
        self.runner_patch.start()
        self.addCleanup(self.runner_patch.stop)
        self.full_patch = mock.patch.object(runner, "full_build_verify", side_effect=self.full_build)
        self.full_verify = self.full_patch.start()
        self.addCleanup(self.full_patch.stop)

    def refresh_build(self, role):
        fixture = self.fixtures[role]
        fixture.build_receipt.write_text(json.dumps(fixture.receipt))
        fixture.build_sha = digest(fixture.build_receipt)
        fixture.build = runner.summarize_build(fixture.build_receipt, fixture.receipt, role)

    def full_build(self, path, expected, role):
        fixture = self.fixtures[role]
        self.assertEqual(digest(path), expected)
        self.assertEqual(expected, fixture.build_sha)
        return fixture.receipt, fixture.build

    def run_role(self, role):
        fixture = self.fixtures[role]
        return runner.run(role, fixture.build_receipt, fixture.build_sha, fixture.plan_path,
                          fixture.test_out, fixture.output, "wonad-comparator-test", 60,
                          backend=fixture.backend)

    def run_pair(self):
        return self.run_role("baseline"), self.run_role("custom")

    def compare(self, runs):
        output = self.fixtures["baseline"].root / "comparison.json"
        value, sha = comparison.compare(*runs[0], *runs[1], self.pair, digest(self.pair), output)
        return output, sha, value

    def projections(self, runs):
        return [comparison.authenticated_run(*run) for run in runs]

    def test_schema2_compare_and_replay_includes_all_reviewed_additions(self):
        runs = self.run_pair()
        output, sha, value = self.compare(runs)
        self.assertEqual(value["schema"], 2)
        self.assertEqual(value["status"], "passed")
        self.assertEqual(value["suites"]["wmtests"]["custom_only_passed"],
                         sorted(comparison.CUSTOM_ONLY_CASES["wmtests"]))
        self.assertEqual(len(value["suites"]["wmtests"]["custom_only_passed"]), 13)
        self.assertEqual(comparison.verify_comparison(
            output, sha, *runs[0], *runs[1], self.pair, digest(self.pair)), value)
        self.assertEqual(self.pair_verify.call_count, 2)
        self.assertGreaterEqual(self.full_verify.call_count, 8)

    def test_schema1_manual_receipt_is_never_accepted(self):
        path = self.fixtures["baseline"].root / "legacy.json"
        path.write_text(json.dumps({"schema": 1, "kind": comparison.KIND_RUN}))
        with self.assertRaisesRegex(comparison.EvidenceError, "schema-1 captures do not"):
            comparison.authenticated_run(path, digest(path))

    def test_run_digest_is_checked_before_any_build_or_result_claim(self):
        run = self.run_role("baseline")
        with self.assertRaisesRegex(comparison.EvidenceError, "authenticated SHA"):
            comparison.authenticated_run(run[0], "0" * 64)

    def test_live_build_rehash_cannot_be_skipped(self):
        run = self.run_role("baseline")
        with mock.patch.object(runner, "full_build_verify", side_effect=ValueError("live mutation")):
            with self.assertRaisesRegex(comparison.EvidenceError, "live mutation"):
                comparison.authenticated_run(*run)

    def test_raw_native_atest_tampering_is_detected(self):
        run = self.run_role("baseline")
        value = comparison.load_json(run[0])
        reference = next(iter(value["suites"]["wmtests"]["results"].values()))
        (run[0].parent / reference["path"]).write_text("{}\n")
        with self.assertRaisesRegex(comparison.EvidenceError, "verification failed"):
            comparison.authenticated_run(*run)

    def test_source_declared_grapheneos_cases_cannot_be_omitted(self):
        name = next(iter(comparison.REQUIRED_GRAPHENEOS_CASES)).split("/InputTests/", 1)[1]
        self.fixtures["baseline"].backend.omit.add(name)
        self.fixtures["custom"].backend.omit.add(name)
        runs = self.run_pair()
        with self.assertRaisesRegex(comparison.EvidenceError, "Secure Paste coverage omits"):
            self.compare(runs)

    def test_grapheneos_shortcut_regression_is_rejected(self):
        name = next(iter(comparison.REQUIRED_GRAPHENEOS_CASES)).split("/InputTests/", 1)[1]
        self.fixtures["custom"].backend.case_overrides[name] = "FAILED"
        runs = self.run_pair()
        with self.assertRaisesRegex(comparison.EvidenceError, "must all pass on the custom side"):
            self.compare(runs)

    def test_required_grapheneos_common_nonpasses_cannot_qualify(self):
        baseline, custom = self.projections(self.run_pair())
        case = sorted(comparison.REQUIRED_GRAPHENEOS_CASES)[0]
        for status in ("skipped", "failure", "error"):
            before, after = copy.deepcopy(baseline), copy.deepcopy(custom)
            before["suites"]["grapheneos_secure_paste"]["cases"][case] = status
            after["suites"]["grapheneos_secure_paste"]["cases"][case] = status
            with self.subTest(status=status), self.assertRaisesRegex(
                    comparison.EvidenceError, "must all pass on the custom side"):
                comparison.result_delta(before, after)

    def test_required_grapheneos_baseline_failure_may_be_resolved(self):
        baseline, custom = self.projections(self.run_pair())
        case = sorted(comparison.REQUIRED_GRAPHENEOS_CASES)[0]
        baseline["suites"]["grapheneos_secure_paste"]["cases"][case] = "failure"
        suites, _common, resolved = comparison.result_delta(baseline, custom)
        self.assertEqual(suites["grapheneos_secure_paste"]["required_custom_passed"],
                         sorted(comparison.REQUIRED_GRAPHENEOS_CASES))
        self.assertTrue(any(row["case"] == case for row in resolved))

    def test_copied_bundle_can_be_relocated_before_comparison(self):
        runs = self.run_pair()
        relocated = []
        for role, run in zip(("baseline", "custom"), runs):
            target = self.fixtures[role].root / "relocated"
            shutil.copytree(run[0].parent, target)
            relocated.append((target / run[0].name, run[1]))
        _, _, value = self.compare(relocated)
        self.assertEqual(value["status"], "passed")

    def test_comparison_can_be_replayed_with_relocated_inputs(self):
        runs = self.run_pair()
        output, sha, value = self.compare(runs)
        relocated = []
        for role, run in zip(("baseline", "custom"), runs):
            target = self.fixtures[role].root / "relocated"
            shutil.copytree(run[0].parent, target)
            relocated.append((target / run[0].name, run[1]))
        pair_copy = self.fixtures["custom"].root / "copied-pair.json"
        shutil.copyfile(self.pair, pair_copy)
        comparison_copy = self.fixtures["custom"].root / "copied-comparison.json"
        shutil.copyfile(output, comparison_copy)
        self.assertEqual(comparison.verify_comparison(
            comparison_copy, sha, *relocated[0], *relocated[1], pair_copy, digest(pair_copy)), value)

    def test_custom_addition_missing_is_rejected(self):
        name = sorted(comparison.CUSTOM_ONLY_CASES["wmtests"])[0].split("/WmTests/")[1]
        self.fixtures["custom"].backend.omit.add(name)
        with self.assertRaisesRegex(comparison.EvidenceError, "exact reviewed additions"):
            self.compare(self.run_pair())

    def test_unreviewed_custom_addition_is_rejected(self):
        self.fixtures["custom"].backend.extra.append("Unreviewed#extra")
        with self.assertRaisesRegex(comparison.EvidenceError, "exact reviewed additions"):
            self.compare(self.run_pair())

    def test_missing_shared_case_is_rejected(self):
        baseline, custom = self.projections(self.run_pair())
        custom["suites"]["wmtests"]["cases"].pop("AtestTradefedTestRunner/WmTests/Class#method")
        with self.assertRaisesRegex(comparison.EvidenceError, "Case set differs"):
            comparison.result_delta(baseline, custom)

    def test_reviewed_custom_only_case_cannot_appear_in_baseline(self):
        baseline, custom = self.projections(self.run_pair())
        case = sorted(comparison.CUSTOM_ONLY_CASES["wmtests"])[0]
        baseline["suites"]["wmtests"]["cases"][case] = "passed"
        with self.assertRaisesRegex(comparison.EvidenceError, "appear in baseline"):
            comparison.result_delta(baseline, custom)

    def test_skipped_custom_addition_is_not_a_pass(self):
        name = sorted(comparison.CUSTOM_ONLY_CASES["wmtests"])[0].split("/WmTests/")[1]
        self.fixtures["custom"].backend.case_overrides[name] = "IGNORED"
        with self.assertRaisesRegex(comparison.EvidenceError, "must all pass"):
            self.compare(self.run_pair())

    def test_custom_shared_failure_is_a_regression(self):
        self.fixtures["custom"].backend.case_overrides["Class#method"] = "FAILED"
        with self.assertRaisesRegex(comparison.EvidenceError, "introduces/worsens"):
            self.compare(self.run_pair())

    def test_missing_reviewed_build_patch_is_rejected(self):
        self.fixtures["custom"].receipt["source"]["stage"]["marker"]["patches"][
            "frameworks_base"].pop()
        self.refresh_build("custom")
        with self.assertRaisesRegex(comparison.EvidenceError, "reviewed build patches"):
            comparison.authenticated_run(*self.run_role("custom"))

    def test_same_guest_boot_is_rejected(self):
        baseline, custom = self.projections(self.run_pair())
        custom["authority"]["boot_id"] = baseline["authority"]["boot_id"]
        with self.assertRaisesRegex(comparison.EvidenceError, "distinct guest boots"):
            comparison.result_delta(baseline, custom)

    def test_builder_toolchain_device_or_runner_drift_is_rejected(self):
        baseline, original = self.projections(self.run_pair())
        for key in ("builder", "toolchain", "device_class", "runner"):
            with self.subTest(key=key):
                custom = copy.deepcopy(original)
                custom["authority"][key] = {"unmatched": key}
                with self.assertRaisesRegex(comparison.EvidenceError, "identities differ"):
                    comparison.result_delta(baseline, custom)

    def test_source_pin_or_plan_drift_is_rejected(self):
        baseline, original = self.projections(self.run_pair())
        custom = copy.deepcopy(original)
        custom["build"]["source_pin_sha256"] = "f" * 64
        with self.assertRaisesRegex(comparison.EvidenceError, "same source pin"):
            comparison.result_delta(baseline, custom)
        custom = copy.deepcopy(original)
        custom["plan"]["release"] = "2026100601"
        custom["plan_sha256"] = comparison.canonical_digest(custom["plan"])
        with self.assertRaisesRegex(comparison.EvidenceError, "plans differ"):
            comparison.result_delta(baseline, custom)

    def test_comparison_contract_cannot_be_replaced_even_with_new_receipt_digest(self):
        runs = self.run_pair()
        output, _, value = self.compare(runs)
        value["custom_case_contract"]["cases"]["wmtests"] = []
        output.write_text(json.dumps(value))
        with self.assertRaisesRegex(comparison.EvidenceError, "semantics or generator"):
            comparison.verify_comparison(output, digest(output), *runs[0], *runs[1],
                                         self.pair, digest(self.pair))


if __name__ == "__main__":
    unittest.main()
