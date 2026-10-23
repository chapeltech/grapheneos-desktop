import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import phase1_upstream_test_comparison as upstream


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class LegacyCaptureParsersAndDelta(unittest.TestCase):
    """Archive/parser tests; schema-2 qualification is tested separately.

    Delta tests inject checked projections explicitly. A legacy receipt is
    never accepted by the production authenticated_run boundary.
    """
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.verifier = self.root / "verifier.py"
        self.verifier.write_text("# frozen verifier\n")
        self.adb = self.root / "adb"
        self.adb.write_text("frozen adb\n")
        self.builds = {}
        for role in ("baseline", "custom"):
            path = self.root / (role + "-build.json")
            path.write_text(json.dumps({"kind": "wonad-x86-build-comparison-input",
                                        "role": role}) + "\n")
            self.builds[role] = path
        self.build_comparison = self.root / "build-comparison.json"
        self.build_comparison.write_text("{}\n")
        self.plan = self.root / "plan.json"
        self.plan_value = {
            "schema": 1,
            "kind": upstream.KIND_PLAN,
            "scope": upstream.SCOPE,
            "release": "2026100600",
            "suites": [{
                "id": name,
                "component": "test/component/" + name,
                "format": "junit-xml",
                "minimum_cases": 1,
                "command_record": name + "/command.json",
                "result_files": [name + "/results.xml"],
                "argv": ["atest", "--no-bazel-mode", name],
                "cwd": "{source}",
                "environment": {
                    "ANDROID_BUILD_TOP": "{source}",
                    "LANG": "C.UTF-8",
                    "OUT_DIR": "{out_dir}",
                },
            } for name in sorted(upstream.REQUIRED_SUITES)],
        }
        self.plan.write_text(json.dumps(self.plan_value) + "\n")
        self.results = {}
        for role in ("baseline", "custom"):
            result = self.root / (role + "-results")
            result.mkdir()
            self.results[role] = result
            for suite in self.plan_value["suites"]:
                directory = result / suite["id"]
                directory.mkdir()
                (directory / "stdout.txt").write_text("completed\n")
                self.write_xml(role, suite["id"], "passed")
                self.write_command(role, suite)
            self.write_device(role)
        self.patch_build = mock.patch.object(
            upstream, "verify_build_receipt", side_effect=self.verify_build)
        self.patch_pair = mock.patch.object(upstream, "verify_build_comparison")
        self.patch_run = mock.patch.object(
            upstream, "authenticated_run", side_effect=self.legacy_test_projection)
        self.patch_build.start()
        self.pair_mock = self.patch_pair.start()
        self.patch_run.start()

    def tearDown(self):
        self.patch_run.stop()
        self.patch_pair.stop()
        self.patch_build.stop()
        self.temporary.cleanup()

    def legacy_test_projection(self, path, digest):
        value = copy.deepcopy(upstream.authenticated_legacy_run(path, digest))
        value["schema"] = 2
        value["authority"] = {
            "builder": "unit-test-builder", "toolchain": "unit-test-toolchain",
            "device_class": "unit-test-emulator", "runner": "unit-test-runner",
            "boot_id": value["role"],
        }
        value["suites"]["grapheneos_secure_paste"]["cases"].update(
            {case: "passed" for case in upstream.REQUIRED_GRAPHENEOS_CASES})
        if value["role"] == "custom":
            for suite, additions in upstream.CUSTOM_ONLY_CASES.items():
                value["suites"][suite]["cases"].update(
                    {case: "passed" for case in additions})
        return value

    def verify_build(self, path, expected, role):
        self.assertEqual(expected, sha(path))
        self.assertEqual(path, self.builds[role])
        source = "/sources/" + role
        out_dir = "/out/" + role
        artifacts = {"os_artifacts": {
            "services": {"path": "system/framework/services.jar", "state": "present",
                         "sha256": "1" * 64, "size": 123},
            "native": {"path": "system/lib64/libwonad.so", "state": "absent"},
        }}
        receipt = {"role": role, "source": {"pin": {"release": "2026100600"}},
                   "artifacts": artifacts, "fingerprint": "fingerprint/" + role,
                   "locations": {"source": source, "out_dir": out_dir}}
        return receipt, {
            "architecture": "x86_64",
            "kind": "wonad-x86-build-comparison-input",
            "receipt": upstream.file_ref(path),
            "source_pin_sha256": upstream.canonical_digest(receipt["source"]["pin"]),
            "artifacts_sha256": upstream.canonical_digest(receipt["artifacts"]),
            "fingerprint": receipt["fingerprint"],
            "os_artifacts": artifacts["os_artifacts"],
            "source_root": source,
            "out_dir": out_dir,
            "verifier": upstream.file_ref(self.verifier),
        }

    def build_summary(self, role):
        return self.verify_build(self.builds[role], sha(self.builds[role]), role)[1]

    def write_device(self, role, **changes):
        build = self.build_summary(role)
        value = {
            "schema": 1,
            "kind": "wonad-phase1-upstream-test-device",
            "serial": "emulator-5580",
            "build_receipt_sha256": sha(self.builds[role]),
            "fingerprint": build["fingerprint"],
            "boot_completed": "1",
            "selinux": "Enforcing",
            "adb": upstream.file_ref(self.adb),
            "artifacts": {
                "services": {"path": "/system/framework/services.jar", "state": "present",
                             "sha256": "1" * 64},
                "native": {"path": "/system/lib64/libwonad.so", "state": "absent"},
            },
        }
        value.update(changes)
        (self.results[role] / "device.json").write_text(json.dumps(value) + "\n")

    def write_xml(self, role, suite, status, *, extra=""):
        outcome = {
            "passed": "",
            "skipped": '<skipped message="not applicable"/>',
            "failure": '<failure message="failed"/>',
            "error": '<error message="crashed"/>',
        }[status]
        count = 2 if extra else 1
        (self.results[role] / suite / "results.xml").write_text(
            '<testsuite tests="%d"><testcase classname="org.example.%s" name="case">%s</testcase>%s</testsuite>\n'
            % (count, suite, outcome, extra))

    def write_command(self, role, suite, **changes):
        value = {
            "schema": 1,
            "kind": "wonad-phase1-upstream-test-command",
            "suite": suite["id"],
            "argv": [upstream.expand_command(item, {
                "source_root": "/sources/" + role, "out_dir": "/out/" + role,
            }) for item in suite["argv"]],
            "cwd": "/sources/" + role,
            "environment": {key: upstream.expand_command(item, {
                "source_root": "/sources/" + role, "out_dir": "/out/" + role,
            }) for key, item in suite["environment"].items()},
            "exit_code": 0,
            "timed_out": False,
            "completed": True,
            "result_files": suite["result_files"],
            "build_receipt_sha256": sha(self.builds[role]),
        }
        value.update(changes)
        (self.results[role] / suite["id"] / "command.json").write_text(
            json.dumps(value) + "\n")

    def capture(self, role):
        output = self.root / (role + "-run.json")
        value, digest = upstream.capture(
            role, self.builds[role], sha(self.builds[role]), self.plan,
            self.results[role], output)
        self.assertEqual(digest, sha(output))
        return output, digest, value

    def capture_pair(self):
        baseline = self.capture("baseline")
        custom = self.capture("custom")
        return baseline, custom

    def compare(self, baseline, custom):
        output = self.root / "upstream-comparison.json"
        value, digest = upstream.compare(
            baseline[0], baseline[1], custom[0], custom[1],
            self.build_comparison, sha(self.build_comparison), output)
        return output, digest, value

    def test_capture_compare_and_verify_allow_resolution(self):
        suite = sorted(upstream.REQUIRED_SUITES)[0]
        self.write_xml("baseline", suite, "failure")
        baseline, custom = self.capture_pair()
        output, digest, value = self.compare(baseline, custom)
        self.assertEqual(value["status"], "passed")
        self.assertEqual(len(value["resolved_baseline_failures"]), 1)
        self.assertEqual(value["common_baseline_failures"], [])
        self.assertEqual(
            upstream.verify_comparison(
                output, digest, baseline[0], baseline[1], custom[0], custom[1],
                self.build_comparison, sha(self.build_comparison)), value)
        self.assertGreaterEqual(self.pair_mock.call_count, 2)

    def test_common_baseline_failure_is_documented(self):
        suite = sorted(upstream.REQUIRED_SUITES)[0]
        for role in ("baseline", "custom"):
            self.write_xml(role, suite, "failure")
        baseline, custom = self.capture_pair()
        _, _, value = self.compare(baseline, custom)
        self.assertEqual(len(value["common_baseline_failures"]), 1)

    def test_new_or_worsened_custom_result_is_rejected(self):
        suite = sorted(upstream.REQUIRED_SUITES)[0]
        self.write_xml("custom", suite, "failure")
        baseline, custom = self.capture_pair()
        with self.assertRaisesRegex(upstream.EvidenceError, "introduces/worsens"):
            self.compare(baseline, custom)

        # A failure becoming an error is also a regression.
        (self.root / "baseline-run.json").unlink()
        (self.root / "custom-run.json").unlink()
        self.write_xml("baseline", suite, "failure")
        self.write_xml("custom", suite, "error")
        baseline, custom = self.capture_pair()
        with self.assertRaisesRegex(upstream.EvidenceError, "introduces/worsens"):
            self.compare(baseline, custom)

    def test_case_set_drift_is_rejected(self):
        suite = sorted(upstream.REQUIRED_SUITES)[0]
        self.write_xml("custom", suite, "passed",
                       extra='<testcase classname="org.example.extra" name="case"/>')
        baseline, custom = self.capture_pair()
        with self.assertRaisesRegex(upstream.EvidenceError, "Case set differs"):
            self.compare(baseline, custom)

    def test_plan_requires_every_privileged_component(self):
        value = copy.deepcopy(self.plan_value)
        value["suites"] = value["suites"][1:]
        with self.assertRaisesRegex(upstream.EvidenceError, "omits required suites"):
            upstream.validate_plan(value)

    def test_timeout_incomplete_and_wrong_build_binding_are_rejected(self):
        suite = self.plan_value["suites"][0]
        for changes in (
            {"timed_out": True}, {"completed": False},
            {"build_receipt_sha256": "0" * 64}, {"result_files": []},
            {"argv": ["atest", "one-narrow-test"]},
            {"cwd": "/unrelated/source"},
            {"environment": {"LANG": "C.UTF-8"}},
        ):
            with self.subTest(changes=changes):
                self.write_command("baseline", suite, **changes)
                with self.assertRaisesRegex(upstream.EvidenceError, "command record"):
                    upstream.capture("baseline", self.builds["baseline"],
                                     sha(self.builds["baseline"]), self.plan,
                                     self.results["baseline"], self.root / "bad-run.json")
                self.write_command("baseline", suite)

    def test_device_must_be_exact_booted_enforcing_build(self):
        for changes in (
            {"fingerprint": "other/build"},
            {"boot_completed": "0"},
            {"selinux": "Permissive"},
            {"build_receipt_sha256": "0" * 64},
            {"artifacts": {
                "services": {"path": "/system/framework/services.jar", "state": "present",
                             "sha256": "2" * 64},
                "native": {"path": "/system/lib64/libwonad.so", "state": "absent"},
            }},
        ):
            with self.subTest(changes=changes):
                self.write_device("baseline", **changes)
                with self.assertRaisesRegex(upstream.EvidenceError,
                                            "device|Device|Booted"):
                    upstream.capture("baseline", self.builds["baseline"],
                                     sha(self.builds["baseline"]), self.plan,
                                     self.results["baseline"], self.root / "bad-run.json")
                self.write_device("baseline")

    def test_raw_result_tampering_is_detected(self):
        output, digest, _ = self.capture("baseline")
        suite = self.plan_value["suites"][0]["id"]
        self.write_xml("baseline", suite, "failure")
        with self.assertRaisesRegex(upstream.EvidenceError, "Referenced file changed"):
            upstream.authenticated_run(output, digest)

    def test_out_of_band_receipt_digest_is_required(self):
        output, digest, _ = self.capture("baseline")
        with self.assertRaisesRegex(upstream.EvidenceError, "authenticated SHA"):
            upstream.authenticated_run(output, "0" * 64)
        self.assertNotEqual(digest, "0" * 64)

    def test_duplicate_json_and_junit_cases_are_rejected(self):
        bad_plan = self.root / "duplicate-plan.json"
        bad_plan.write_text('{"schema":1,"schema":1}\n')
        with self.assertRaisesRegex(upstream.EvidenceError, "Duplicate JSON"):
            upstream.load_json(bad_plan)
        suite = self.plan_value["suites"][0]["id"]
        self.write_xml("baseline", suite, "passed",
                       extra='<testcase classname="org.example.%s" name="case"/>' % suite)
        with self.assertRaisesRegex(upstream.EvidenceError, "Duplicate JUnit case"):
            upstream.capture("baseline", self.builds["baseline"],
                             sha(self.builds["baseline"]), self.plan,
                             self.results["baseline"], self.root / "bad-run.json")

    def test_junit_count_and_tradefed_skip_outcomes_are_strict(self):
        suite = self.plan_value["suites"][0]["id"]
        result = self.results["baseline"] / suite / "results.xml"
        result.write_text('<testsuite tests="2"><testcase classname="c" name="n"/></testsuite>')
        with self.assertRaisesRegex(upstream.EvidenceError, "count is missing or inconsistent"):
            upstream.parse_junit(result)
        for element in ("ignored", "assumption_failure", "skipped"):
            result.write_text('<testsuite tests="1"><testcase classname="c" name="n"><%s/></testcase></testsuite>' % element)
            self.assertEqual(upstream.parse_junit(result), {"c#n": "skipped"})
        result.write_text('<testsuite tests="1"><testcase classname="c" name="n"><flakyFailure/></testcase></testsuite>')
        with self.assertRaisesRegex(upstream.EvidenceError, "unknown result element"):
            upstream.parse_junit(result)

    def test_atest_json_cases_and_summaries_are_strict(self):
        path = self.root / "atest-result.json"
        value = {
            "args": "WmTests",
            "test_runner": {
                "AtestTradefedTestRunner": {
                    "WmTests": {
                        "PASSED": [{"test_name": "Class#pass"}],
                        "FAILED": [{"test_name": "Class#fail"}],
                        "IGNORED": [{"test_name": "Class#skip"}],
                        "summary": {"PASSED": 1, "FAILED": 1, "IGNORED": 1},
                    }
                }
            },
            "total_summary": {"PASSED": 1, "FAILED": 1, "IGNORED": 1},
        }
        path.write_text(json.dumps(value))
        self.assertEqual(set(upstream.parse_atest(path).values()),
                         {"passed", "failure", "skipped"})
        value["total_summary"]["PASSED"] = 2
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(upstream.EvidenceError, "total summary"):
            upstream.parse_atest(path)

    def test_symlinks_and_xml_entities_are_rejected(self):
        suite = self.plan_value["suites"][0]
        result = self.results["baseline"] / suite["id"] / "results.xml"
        target = self.root / "target.xml"
        target.write_bytes(result.read_bytes())
        result.unlink()
        result.symlink_to(target)
        with self.assertRaisesRegex(upstream.EvidenceError, "symlink"):
            upstream.capture("baseline", self.builds["baseline"],
                             sha(self.builds["baseline"]), self.plan,
                             self.results["baseline"], self.root / "bad-run.json")
        result.unlink()
        result.write_text('<!DOCTYPE x [<!ENTITY y "z">]><testsuite><testcase classname="c" name="n">&y;</testcase></testsuite>')
        with self.assertRaisesRegex(upstream.EvidenceError, "DTD/entity"):
            upstream.capture("baseline", self.builds["baseline"],
                             sha(self.builds["baseline"]), self.plan,
                             self.results["baseline"], self.root / "bad-run.json")

    def test_plan_and_source_pin_mismatch_are_rejected(self):
        baseline, custom = self.capture_pair()
        custom_value = json.loads(custom[0].read_text())
        custom_value["plan"]["release"] = "2026100601"
        custom_value["plan_sha256"] = upstream.canonical_digest(custom_value["plan"])
        custom[0].write_text(json.dumps(custom_value, sort_keys=True) + "\n")
        custom = (custom[0], sha(custom[0]), custom[2])
        with self.assertRaisesRegex(upstream.EvidenceError, "plans differ"):
            self.compare(baseline, custom)

    def test_comparison_tampering_is_detected(self):
        baseline, custom = self.capture_pair()
        output, digest, _ = self.compare(baseline, custom)
        value = json.loads(output.read_text())
        value["status"] = "failed"
        output.write_text(json.dumps(value) + "\n")
        with self.assertRaisesRegex(upstream.EvidenceError, "authenticated SHA"):
            upstream.verify_comparison(
                output, digest, baseline[0], baseline[1], custom[0], custom[1],
                self.build_comparison, sha(self.build_comparison))


if __name__ == "__main__":
    unittest.main()
