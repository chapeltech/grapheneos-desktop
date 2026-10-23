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
import phase1_generic_upstream_evidence as generic
import run_phase1_upstream_tests as isolated


def event(action, package="example/pkg", test=None, **extra):
    value = {"Time": "2026-10-11T00:00:00Z", "Action": action, "Package": package}
    if test is not None:
        value["Test"] = test
    value.update(extra)
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def passing_stream(package="example/pkg", test="TestThing"):
    return b"".join((event("start", package), event("run", package, test),
                     event("output", package, test, Output="ok\n"),
                     event("pass", package, test, Elapsed=0.01),
                     event("pass", package, Elapsed=0.02)))


class FakeHostBackend:
    def __init__(self, image, build_out):
        self.image = copy.deepcopy(image)
        self.build_out = build_out
        self.specs = {}
        self.removed = set()
        self.mutate_out = False

    def docker_identity(self):
        return {"endpoint": "unix:///run/docker.sock",
                "cli": {"path": "/usr/bin/docker", "sha256": "d" * 64},
                "socket": {"path": "/run/docker.sock", "device": 1, "inode": 2},
                "context": {"name": "default"},
                "daemon": {"id": "test-daemon", "architecture": "x86_64"}}

    def inspect_image(self, image_id):
        value = copy.deepcopy(self.image)
        value["id"] = image_id
        return value

    def run_host_container(self, spec, stdout_path, timeout):
        del timeout
        self.specs[spec["name"]] = copy.deepcopy(spec)
        stdout_path.write_bytes(passing_stream(package="pkg/" + spec["invocation"]))
        if self.mutate_out:
            (self.build_out / "host-test-mutation").write_text("forbidden\n")
            self.mutate_out = False
        return {"exit_code": 0, "timed_out": False,
                "docker_argv": generic.host_docker_argv(spec)}

    def inspect_container(self, name):
        spec = self.specs[name]
        identifier = hashlib.sha256(name.encode()).hexdigest()
        environment = sorted(key + "=" + value for key, value in spec["environment"].items())
        return {
            "Id": identifier, "Name": "/" + name, "Image": spec["image"],
            "Config": {"Image": spec["image"], "Entrypoint": ["/usr/bin/env"],
                       "Cmd": ["-i", *environment, *spec["argv"]], "User": spec["user"],
                       "WorkingDir": spec["cwd"], "Env": environment,
                       "Labels": {"org.wonad.phase1.nonce": spec["nonce"],
                                  "org.wonad.phase1.class": "aosp_host",
                                  "org.wonad.phase1.invocation": spec["invocation"]}},
            "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True,
                           "Privileged": False, "CapDrop": ["ALL"],
                           "SecurityOpt": ["no-new-privileges:true", "label=disable"],
                           "Devices": [], "DeviceRequests": [],
                           "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                           "AutoRemove": False,
                           "Memory": generic.HOST_RESOURCES["memory"],
                           "MemorySwap": generic.HOST_RESOURCES["memory_swap"],
                           "NanoCpus": generic.HOST_RESOURCES["nano_cpus"],
                           "PidsLimit": generic.HOST_RESOURCES["pids_limit"],
                           "Tmpfs": {"/tmp":
                                     "rw,nosuid,nodev,noexec,mode=1777,size=268435456"}},
            "Mounts": [
                {"Type": "bind", "Source": spec["source"], "Destination": "/sources",
                 "RW": False, "Propagation": "rprivate"},
                {"Type": "bind", "Source": spec["workspace"], "Destination": "/test-out",
                 "RW": True, "Propagation": "rprivate"}],
            "State": {"Running": False, "Restarting": False, "Dead": False,
                      "OOMKilled": False, "ExitCode": 0},
        }

    def remove_container(self, identity):
        self.removed.add(identity)
        for name in self.specs:
            if hashlib.sha256(name.encode()).hexdigest() == identity:
                self.removed.add(name)

    def container_absent(self, identity):
        return identity in self.removed or (identity not in self.specs and
            all(hashlib.sha256(name.encode()).hexdigest() != identity for name in self.specs))


class GenericUpstreamEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.plan = generic.reviewed_plan()
        self.host = generic.class_row(self.plan, "aosp_host")

    def test_memory_budget_retains_full_normal_and_upstream_race_test_scope(self):
        self.assertEqual(self.host["environment"]["GOMEMLIMIT"], "40GiB")
        self.assertEqual(self.host["environment"]["GOMAXPROCS"], "4")
        self.assertEqual(len(self.host["invocations"]), 10)
        self.assertEqual(sum("-race" in row["argv"] for row in self.host["invocations"]), 5)
        for row in self.host["invocations"]:
            with self.subTest(invocation=row["id"]):
                self.assertEqual(row["argv"].count("-p=1"), 1)
                self.assertIn("-count=1", row["argv"])
                self.assertIn("-json", row["argv"])
                self.assertEqual("-short" in row["argv"], "-race" in row["argv"])
                self.assertNotIn("-run", row["argv"])
        self.assertEqual(generic.HOST_RESOURCES["memory"], 48 * 1024**3)
        self.assertEqual(generic.HOST_RESOURCES["memory_swap"], generic.HOST_RESOURCES["memory"])

    def test_production_memory_guard_reports_exact_below_threshold_observation(self):
        threshold = generic.HOST_MIN_AVAILABLE_MEMORY // 1024
        observation_time = 1_760_184_123_456_789_012
        read = mock.Mock(return_value=f"MemAvailable: {threshold - 1} kB\n")
        with mock.patch.object(generic.Path, "read_text", read), \
                mock.patch.object(generic.time, "time_ns", return_value=observation_time):
            with self.assertRaises(generic.EvidenceError) as raised:
                generic.require_host_memory()
        read.assert_called_once_with(encoding="ascii")
        message = str(raised.exception)
        self.assertIn("44 GiB available RAM", message)
        self.assertIn(f"observed_at_unix_ns={observation_time}", message)
        self.assertIn(f"threshold_bytes={generic.HOST_MIN_AVAILABLE_MEMORY}", message)
        self.assertIn(f"threshold_kib={threshold}", message)
        self.assertIn("status=below_threshold", message)
        self.assertIn(f"observed_bytes={(threshold - 1) * 1024}", message)
        self.assertIn(f"observed_kib={threshold - 1}", message)

    def test_production_memory_guard_accepts_equal_and_above_threshold(self):
        threshold = generic.HOST_MIN_AVAILABLE_MEMORY // 1024
        for observed in (threshold, threshold + 1):
            with self.subTest(observed_kib=observed):
                read = mock.Mock(return_value=f"MemAvailable: {observed} kB\n")
                clock = mock.Mock(return_value=1_760_184_123_456_789_012)
                with mock.patch.object(generic.Path, "read_text", read), \
                        mock.patch.object(generic.time, "time_ns", clock):
                    self.assertIsNone(generic.require_host_memory())
                read.assert_called_once_with(encoding="ascii")
                clock.assert_called_once_with()

    def test_production_memory_guard_rejects_missing_malformed_and_ambiguous(self):
        threshold = generic.HOST_MIN_AVAILABLE_MEMORY // 1024
        cases = (
            ("MemTotal: 999999999 kB\n", "missing", 0, 0),
            ("MemAvailable: unavailable kB\n", "malformed", 1, 0),
            ("MemAvailable:   \t\n", "malformed", 1, 0),
            (f"MemAvailable:\n{threshold} kB\n", "malformed", 1, 0),
            (f"MemAvailable: {threshold}\n kB\n", "malformed", 1, 0),
            (f"MemAvailable: {threshold} kB\nMemAvailable: {threshold} kB\n",
             "ambiguous", 2, 2),
            (f"MemAvailable: {threshold} kB\nMemAvailable: unavailable kB\n",
             "ambiguous", 2, 1),
        )
        for contents, status, candidates, values in cases:
            with self.subTest(status=status, contents=contents):
                with mock.patch.object(generic.Path, "read_text", return_value=contents), \
                        mock.patch.object(generic.time, "time_ns", return_value=123):
                    with self.assertRaises(generic.EvidenceError) as raised:
                        generic.require_host_memory()
                message = str(raised.exception)
                self.assertIn(f"observed_at_unix_ns=123", message)
                self.assertIn(f"threshold_bytes={generic.HOST_MIN_AVAILABLE_MEMORY}", message)
                self.assertIn(f"status={status}", message)
                self.assertIn("observed_bytes=unavailable", message)
                self.assertIn("observed_kib=unavailable", message)
                self.assertIn(f"candidate_lines={candidates}", message)
                self.assertIn(f"exact_values={values}", message)

    def test_production_memory_guard_reports_read_failure(self):
        read_error = OSError("meminfo read denied")
        read = mock.Mock(side_effect=read_error)
        with mock.patch.object(generic.Path, "read_text", read), \
                mock.patch.object(generic.time, "time_ns", return_value=456):
            with self.assertRaises(generic.EvidenceError) as raised:
                generic.require_host_memory()
        read.assert_called_once_with(encoding="ascii")
        self.assertIs(raised.exception.__cause__, read_error)
        message = str(raised.exception)
        self.assertIn("observed_at_unix_ns=456", message)
        self.assertIn(f"threshold_bytes={generic.HOST_MIN_AVAILABLE_MEMORY}", message)
        self.assertIn("status=read_error", message)
        self.assertIn("observed_bytes=unavailable observed_kib=unavailable", message)
        self.assertIn("error_type=OSError", message)
        self.assertIn('error="meminfo read denied"', message)

    def resolved_pairs(self):
        """Synthetic authenticated projections; this does not run native tests."""
        future = copy.deepcopy(self.plan)
        generic.class_row(future, "grapheneos_host")["state"] = "not_applicable_source_declared"
        pairs = {}
        for cls in generic.REQUIRED_CLASSES:
            pairs[cls] = {}
            for role in ("baseline", "custom"):
                side = {
                    "class": cls, "role": role, "source_pin_sha256": "a" * 64,
                    "build_receipt": {"sha256": ("b" if role == "baseline" else "c") * 64,
                                      "size": 1},
                    "receipt_sha256": ("d" if role == "baseline" else "e") * 64,
                    "plan_sha256": generic.PLAN_SHA256, "cases": {"case": "passed"},
                    "authority": {"builder": {"id": "sha256:" + "f" * 64},
                                  "toolchain": {"source_tools": "pinned"}},
                }
                if cls == "aosp_emulator":
                    side["module_plan_sha256"] = generic.canonical_digest(
                        generic.atest_comparison.load_json(
                            generic.ROOT / generic.class_row(future, cls)["module_plan"]["path"]))
                    side["authority"].update({"device_class": {"serial": "emulator-5580"},
                                              "runner": {"sha256": "f" * 64},
                                              "boot_id": role + "-boot"})
                    side["cases"].update({"grapheneos_secure_paste/" + case: "passed"
                                          for case in generic.atest_comparison.REQUIRED_GRAPHENEOS_CASES})
                    if role == "custom":
                        side["cases"].update({suite + "/" + case: "passed"
                                              for suite, cases in
                                              generic.atest_comparison.CUSTOM_ONLY_CASES.items()
                                              for case in cases})
                if cls == "grapheneos_host":
                    del side["cases"]
                    side["applicability"] = {
                        "result": "not_applicable_source_declared",
                        "evidence": {"definition": {"sha256": "f" * 64},
                                     "scope": "pinned-source-declarations-only-no-external-ci-claim"},
                    }
                pairs[cls][role] = side
        return future, pairs

    def compare_resolved(self, plan, sides):
        with mock.patch.object(generic, "validate_plan", return_value=plan), \
             mock.patch.object(generic, "reviewed_plan", return_value=plan):
            return generic.compare_native_sides(plan, sides)

    def test_reviewed_plan_covers_three_classes_without_inventing_a_host_test(self):
        self.assertEqual({row["class"] for row in self.plan["classes"]},
                         generic.REQUIRED_CLASSES)
        graphene = generic.class_row(self.plan, "grapheneos_host")
        self.assertEqual(graphene["state"], "not_applicable_source_declared")
        self.assertEqual(graphene["applicability_definition"]["sha256"],
                         generic.grapheneos_applicability.DEFINITION_SHA256)
        self.assertNotIn("command", graphene)
        self.assertNotIn("selected_module", graphene)

    def test_alternate_even_byte_identical_plan_is_not_selectable(self):
        with tempfile.TemporaryDirectory() as temporary:
            alternate = Path(temporary) / "plan.json"
            alternate.write_bytes(generic.PLAN.read_bytes())
            with self.assertRaisesRegex(generic.EvidenceError, "repository-reviewed"):
                generic.reviewed_plan(alternate)

    def test_plan_rejects_operator_command_change(self):
        changed = copy.deepcopy(self.plan)
        host = generic.class_row(changed, "aosp_host")
        host["invocations"][0]["argv"] = ["sh", "-c", "true"]
        with self.assertRaisesRegex(generic.EvidenceError, "source-pinned Go"):
            generic.validate_plan(changed)

    def test_plan_rejects_class_omission(self):
        changed = copy.deepcopy(self.plan)
        changed["classes"].pop()
        with self.assertRaisesRegex(generic.EvidenceError, "Unsupported generic"):
            generic.validate_plan(changed)

    def test_plan_rejects_pretending_graphene_candidate_is_selected(self):
        changed = copy.deepcopy(self.plan)
        gate = generic.class_row(changed, "grapheneos_host")
        gate["selected_module"] = "hardened_malloc"
        gate["selected_command"] = ["make", "test"]
        with self.assertRaisesRegex(generic.EvidenceError, "unexpected fields"):
            generic.validate_plan(changed)

    def test_go_json_reconstructs_package_and_test_cases(self):
        cases = generic.parse_go_json_payload(passing_stream(), "soong", 0)
        self.assertEqual(cases, {
            "soong/example/pkg#TestThing": "passed",
            "soong/example/pkg::<package>": "passed",
        })

    def test_go_json_accepts_native_failure_only_with_nonzero_exit(self):
        payload = b"".join((event("start"), event("run", test="TestThing"),
                            event("fail", test="TestThing"), event("fail")))
        cases = generic.parse_go_json_payload(payload, "soong", 1)
        self.assertEqual(set(cases.values()), {"failure"})
        with self.assertRaisesRegex(generic.EvidenceError, "exit status"):
            generic.parse_go_json_payload(payload, "soong", 0)

    def test_go_json_rejects_prose_junit_and_self_declared_summary(self):
        for payload in (b"PASS\n", b"<testsuite tests='1'/>\n",
                        b'{"failures":[],"result":"passed"}\n'):
            with self.subTest(payload=payload):
                with self.assertRaises(generic.EvidenceError):
                    generic.parse_go_json_payload(payload, "soong", 0)

    def test_go_json_rejects_incomplete_or_empty_stream(self):
        for payload in (b"", event("start"),
                        b"\n".join((event("start").rstrip(), b"")) + b"\n"):
            with self.subTest(payload=payload):
                with self.assertRaises(generic.EvidenceError):
                    generic.parse_go_json_payload(payload, "soong", 0)

    def test_package_only_result_does_not_prove_host_tests_executed(self):
        for status, code in (("pass", 0), ("fail", 1)):
            with self.subTest(status=status):
                payload = event("start") + event(status)
                cases = generic.parse_go_json_payload(payload, "soong", code)
                with self.assertRaisesRegex(generic.EvidenceError, "no executed test cases"):
                    generic.require_executed_go_test(cases, "soong")

    def test_host_normalizer_uses_only_reviewed_invocations_and_native_bytes(self):
        rows = {}
        for invocation in self.host["invocations"]:
            rows[invocation["id"]] = {
                "argv": invocation["argv"], "cwd": invocation["cwd"],
                "environment": self.host["environment"], "completed": True,
                "timed_out": False, "exit_code": 0,
                "raw": passing_stream(package="pkg/" + invocation["id"]),
            }
        result = generic.normalize_host_invocations(self.plan, rows)
        self.assertEqual(len(result["invocations"]), 10)
        self.assertEqual(len(result["cases"]), 20)
        self.assertFalse(any("failures" in row for row in result["invocations"].values()))

    def test_host_normalizer_rejects_operator_command_and_failure_field(self):
        rows = {}
        for invocation in self.host["invocations"]:
            rows[invocation["id"]] = {
                "argv": invocation["argv"], "cwd": invocation["cwd"],
                "environment": self.host["environment"], "completed": True,
                "timed_out": False, "exit_code": 0,
                "raw": passing_stream(package="pkg/" + invocation["id"]),
            }
        rows[self.host["invocations"][0]["id"]]["argv"] = ["sh", "-c", "true"]
        with self.assertRaisesRegex(generic.EvidenceError, "reviewed command"):
            generic.normalize_host_invocations(self.plan, rows)
        rows[self.host["invocations"][0]["id"]]["argv"] = self.host["invocations"][0]["argv"]
        rows[self.host["invocations"][0]["id"]]["failures"] = []
        with self.assertRaisesRegex(generic.EvidenceError, "unexpected fields"):
            generic.normalize_host_invocations(self.plan, rows)

    def test_complete_comparison_refuses_missing_native_coverage_before_output(self):
        with self.assertRaisesRegex(generic.EvidenceError, "omits"):
            generic.compare_native_sides(self.plan, {})

    def test_comparison_logic_rejects_class_omission_and_worsening(self):
        future, pairs = self.resolved_pairs()
        with self.assertRaisesRegex(generic.EvidenceError, "omits"):
            self.compare_resolved(future, {})
        pairs["aosp_host"]["custom"]["cases"]["case"] = "failure"
        with self.assertRaisesRegex(generic.EvidenceError, "worsened"):
            self.compare_resolved(future, pairs)

    def test_comparison_accepts_exact_passing_reviewed_emulator_additions(self):
        future, pairs = self.resolved_pairs()
        result = self.compare_resolved(future, pairs)
        self.assertEqual(len(result["classes"]["aosp_emulator"]["custom_only_passed"]), 13)
        self.assertEqual(result["result"], "passed_no_new_or_worsened_native_failures")

    def test_required_grapheneos_common_nonpasses_cannot_qualify(self):
        for status in ("skipped", "failure", "error"):
            plan, pairs = self.resolved_pairs()
            case = "grapheneos_secure_paste/" + sorted(
                generic.atest_comparison.REQUIRED_GRAPHENEOS_CASES)[0]
            for role in ("baseline", "custom"):
                pairs["aosp_emulator"][role]["cases"][case] = status
            with self.subTest(status=status), self.assertRaisesRegex(
                    generic.EvidenceError, "must all pass on the custom side"):
                self.compare_resolved(plan, pairs)

    def test_required_grapheneos_baseline_failure_may_be_resolved(self):
        plan, pairs = self.resolved_pairs()
        cases = sorted(case for case in pairs["aosp_emulator"]["baseline"]["cases"]
                       if case.startswith("grapheneos_secure_paste/"))
        pairs["aosp_emulator"]["baseline"]["cases"][cases[0]] = "failure"
        result = self.compare_resolved(plan, pairs)
        self.assertEqual(result["classes"]["aosp_emulator"]["required_custom_passed"], cases)

    def test_comparison_rejects_missing_extra_skipped_and_baseline_additions(self):
        for mutation in ("missing", "extra", "skipped", "baseline"):
            with self.subTest(mutation=mutation):
                future, pairs = self.resolved_pairs()
                custom = pairs["aosp_emulator"]["custom"]["cases"]
                addition = next(name for name in custom if name.startswith("wmtests/"))
                if mutation == "missing":
                    del custom[addition]
                elif mutation == "extra":
                    custom["unreviewed"] = "passed"
                elif mutation == "skipped":
                    custom[addition] = "skipped"
                else:
                    pairs["aosp_emulator"]["baseline"]["cases"][addition] = "passed"
                with self.assertRaisesRegex(generic.EvidenceError, "additions"):
                    self.compare_resolved(future, pairs)

    def test_comparison_rejects_cross_class_build_source_and_pair_tool_drift(self):
        for mutation in ("build", "source", "builder", "toolchain", "plan", "boot"):
            with self.subTest(mutation=mutation):
                future, pairs = self.resolved_pairs()
                side = pairs["aosp_emulator"]["custom"]
                if mutation == "build":
                    side["build_receipt"]["sha256"] = "9" * 64
                elif mutation == "source":
                    for role in ("baseline", "custom"):
                        pairs["aosp_emulator"][role]["source_pin_sha256"] = "9" * 64
                elif mutation in ("builder", "toolchain"):
                    side["authority"][mutation]["changed"] = True
                elif mutation == "plan":
                    side["module_plan_sha256"] = "9" * 64
                else:
                    side["authority"]["boot_id"] = pairs["aosp_emulator"]["baseline"][
                        "authority"]["boot_id"]
                with self.assertRaises(generic.EvidenceError):
                    self.compare_resolved(future, pairs)

    def test_applicability_is_not_a_passing_test_and_cannot_gain_invented_cases(self):
        future, pairs = self.resolved_pairs()
        result = self.compare_resolved(future, pairs)
        self.assertEqual(result["classes"]["grapheneos_host"]["case_count"], 0)
        self.assertIs(result["classes"]["grapheneos_host"]["tests_executed"], False)
        pairs["grapheneos_host"]["custom"]["cases"] = {"invented": "passed"}
        with self.assertRaisesRegex(generic.EvidenceError, "invent passing"):
            self.compare_resolved(future, pairs)

    def test_applicability_baseline_custom_inventory_must_match(self):
        future, pairs = self.resolved_pairs()
        pairs["grapheneos_host"]["custom"]["applicability"]["evidence"]["scope"] = "broader claim"
        with self.assertRaisesRegex(generic.EvidenceError, "inventories differ"):
            self.compare_resolved(future, pairs)

    def test_emulator_normalizer_requires_live_schema2_rehash_and_native_cases(self):
        run = {
            "role": "baseline",
            "build": {"source_pin_sha256": "c" * 64,
                      "receipt": {"path": "/tmp/build.json", "sha256": "b" * 64,
                                  "size": 1}},
            "authority": {"builder": {}, "toolchain": {}},
            "plan_sha256": "e" * 64,
            "suites": {
                "one": {"cases": {"runner/case" + str(index): "passed"
                                    for index in range(324)}},
            },
        }
        with mock.patch.object(generic.atest_comparison, "authenticated_run",
                               return_value=run) as verify:
            result = generic.normalize_emulator(Path("/tmp/run-receipt.json"), "d" * 64)
        verify.assert_called_once_with(Path("/tmp/run-receipt.json"), "d" * 64)
        self.assertEqual(result["source_pin_sha256"], "c" * 64)
        self.assertEqual(result["build_receipt"], {"sha256": "b" * 64, "size": 1})
        self.assertEqual(len(result["cases"]), 324)


class AuthenticatedHostProducerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.build_out = self.root / "build-out"
        self.test_out = self.root / "host-test-out"
        self.output = self.root / "host-evidence"
        self.source.mkdir()
        self.build_out.mkdir()
        self.image = {
            "id": "sha256:" + "a" * 64,
            "repo_digests": ["builder@sha256:" + "a" * 64],
            "os": "linux", "architecture": "amd64", "size": 1234,
            "rootfs": {"type": "layers", "layers": ["sha256:" + "b" * 64]},
            "config": {"User": "builder",
                       "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                               "LANG=C.UTF-8", "DEBIAN_FRONTEND=noninteractive"],
                       "Entrypoint": None, "Cmd": ["bash"], "WorkingDir": "/sources",
                       "Labels": None},
        }
        self.source_pin = {"release": generic.RELEASE, "commit": "1" * 40, "projects": []}
        self.receipt = {
            "role": "baseline", "kind": "wonad-x86-build-comparison-input",
            "source": {"pin": self.source_pin},
            "artifacts": {"images": {}, "os_artifacts": {
                "services": {"path": "system/framework/services.jar", "state": "present",
                             "sha256": "3" * 64, "size": 99}}},
            "locations": {"source": str(self.source), "out_dir": str(self.build_out)},
            "builder": {"image": self.image},
            "fingerprint": "Android/example/emu64x:17/test:userdebug/test-keys",
        }
        self.build_receipt = self.root / "build.json"
        self.build_receipt.write_text(json.dumps(self.receipt, sort_keys=True) + "\n")
        self.build_sha = hashlib.sha256(self.build_receipt.read_bytes()).hexdigest()
        self.build = isolated.summarize_build(self.build_receipt, self.receipt, "baseline")
        self.backend = FakeHostBackend(self.image, self.build_out)
        self.binding = {"source_pin_sha256": generic.canonical_digest(self.source_pin),
                        "plan_sha256": generic.PLAN_SHA256,
                        "classes": sorted(generic.REQUIRED_CLASSES)}
        self.patches = [
            mock.patch.object(isolated, "full_build_verify",
                              return_value=(self.receipt, self.build)),
            mock.patch.object(isolated, "source_freeze_verify", side_effect=self.source_freeze),
            mock.patch.object(generic, "authenticate_source_bindings",
                              return_value=self.binding),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temporary.cleanup()

    def source_freeze(self, receipt, build):
        return {"schema": isolated.SCHEMA, "kind": "wonad-phase1-current-source-freeze",
                "receipt_sha256": build["receipt_sha256"],
                "snapshot_sha256": generic.canonical_digest(receipt["source"]),
                "snapshot": receipt["source"]}

    def execute(self):
        return generic.run_aosp_host(
            "baseline", self.build_receipt, self.build_sha, self.test_out, self.output,
            "wonad-host", 60, backend=self.backend)

    def test_fixed_host_producer_isolated_portable_and_native_verifiable(self):
        receipt, digest = self.execute()
        self.assertFalse(self.test_out.exists())
        result = generic.verify_host(receipt, digest, rehash_build=False)
        self.assertEqual(result["class"], "aosp_host")
        self.assertEqual(len(result["cases"]), 20)
        self.assertEqual(len(self.backend.specs), 10)
        for spec in self.backend.specs.values():
            self.assertNotIn(str(self.build_out), json.dumps(spec))
            argv = generic.host_docker_argv(spec)
            self.assertIn("none", argv)
            self.assertIn("--read-only", argv)
            self.assertIn("no-new-privileges:true", argv)
            self.assertEqual(sum("dst=/test-out" in item for item in argv), 1)
            mount = next(item for item in argv if "dst=/test-out" in item)
            self.assertIn(",readonly=false,", mount)
            self.assertNotIn(",rw,", mount)
            self.assertEqual(spec["resources"], generic.HOST_RESOURCES)
            self.assertEqual(spec["environment"]["GOMAXPROCS"], "4")
            self.assertEqual(spec["environment"]["GOMEMLIMIT"], "40GiB")

    def test_parser_failure_keeps_original_diagnostic_and_removes_owned_container(self):
        with mock.patch.object(generic, "parse_go_json",
                               side_effect=generic.EvidenceError("original native parser failure")):
            with self.assertRaisesRegex(generic.EvidenceError, "original native parser failure"):
                self.execute()
        self.assertFalse(self.test_out.exists())
        self.assertFalse((self.output / "host-run-receipt.json").exists())
        self.assertTrue(self.backend.removed)

    def test_oom_profile_failure_retains_exact_inspect_before_owned_cleanup(self):
        inspect = self.backend.inspect_container
        def oom_inspect(name):
            value = inspect(name)
            value["State"]["OOMKilled"] = True
            value["State"]["ExitCode"] = 1
            return value
        with mock.patch.object(self.backend, "inspect_container", side_effect=oom_inspect):
            with self.assertRaisesRegex(generic.EvidenceError, "sealed isolation profile"):
                self.execute()
        record = generic.load_json(next(self.output.glob("invocations/*/failure-observation.json")))
        self.assertIs(record["qualification_claimed"], False)
        self.assertIs(record["inspect"]["State"]["OOMKilled"], True)
        self.assertEqual(record["inspect"]["State"]["ExitCode"], 1)
        self.assertEqual(record["spec"]["resources"], generic.HOST_RESOURCES)
        self.assertTrue(self.backend.container_absent(record["inspect"]["Id"]))
        self.assertFalse(self.test_out.exists())
        self.assertFalse((self.output / "host-run-receipt.json").exists())

    def test_failure_observation_write_error_does_not_mask_original_parser_failure(self):
        write = generic.isolated_atest.write_json_new
        def fail_observation(path, record):
            if path.name == "failure-observation.json":
                raise OSError("disk full while preserving diagnostic")
            return write(path, record)
        with mock.patch.object(generic, "parse_go_json", side_effect=generic.EvidenceError("native parse failure")), \
             mock.patch.object(generic.isolated_atest, "write_json_new", side_effect=fail_observation):
            with self.assertRaisesRegex(generic.EvidenceError, "native parse failure") as caught:
                self.execute()
        self.assertIn("disk full", " ".join(caught.exception.__notes__))
        self.assertTrue(self.backend.removed)
        self.assertFalse((self.output / "host-run-receipt.json").exists())

    def test_docker_creation_failure_retains_original_output_without_inspect_masking(self):
        def creation_failure(spec, stdout_path, timeout):
            del timeout
            stdout_path.write_text("Docker rejected the command\n")
            return {"exit_code": 125, "timed_out": False,
                    "docker_argv": generic.host_docker_argv(spec)}

        with mock.patch.object(self.backend, "run_host_container", side_effect=creation_failure), \
             mock.patch.object(self.backend, "inspect_container") as inspect:
            with self.assertRaisesRegex(generic.EvidenceError, "did not create a container.*exit=125"):
                self.execute()
        inspect.assert_not_called()
        self.assertFalse(self.test_out.exists())
        self.assertFalse((self.output / "host-run-receipt.json").exists())
        self.assertEqual(next(self.output.glob("invocations/*/go-test.jsonl")).read_text(),
                         "Docker rejected the command\n")

    def test_native_host_evidence_cannot_drop_or_change_resource_limits(self):
        self.execute()
        path = next(self.output.glob("invocations/*/container.json"))
        original = generic.load_json(path)
        for field in generic.HOST_RESOURCES:
            record = copy.deepcopy(original)
            record["observed"]["resources"][field] = 0
            with self.subTest(field=field), self.assertRaisesRegex(generic.EvidenceError, "resource bounds"):
                generic.validate_host_container_evidence(record, record["spec"], 0)

    def test_host_verifier_rejects_tampered_native_stream(self):
        receipt, digest = self.execute()
        raw = next(self.output.glob("invocations/*/go-test.jsonl"))
        raw.write_text('<testsuite tests="1"/>\n')
        with self.assertRaisesRegex(isolated.comparison.EvidenceError, "changed"):
            generic.verify_host(receipt, digest, rehash_build=False)

    def test_host_producer_detects_complete_out_mutation_and_never_seals(self):
        self.backend.mutate_out = True
        with self.assertRaisesRegex(generic.EvidenceError, "OUT inventory changed"):
            self.execute()
        self.assertFalse((self.output / "host-run-receipt.json").exists())
        self.assertFalse(self.test_out.exists())

    def test_host_producer_has_no_operator_command_or_raw_result_argument(self):
        parser = generic.parser()
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            parser.parse_args(["run-aosp-host", "--role", "baseline",
                               "--build-receipt", str(self.build_receipt),
                               "--build-receipt-sha256", self.build_sha,
                               "--test-out", str(self.test_out), "--output", str(self.output),
                               "--command", "sh -c true"])


if __name__ == "__main__":
    unittest.main()
