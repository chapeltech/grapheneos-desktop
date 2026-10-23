#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "sdk_two_publications", HERE / "run_two_publications.py")
assert SPEC is not None and SPEC.loader is not None
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)


class TwoPublicationDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = driver.load_manifest()
        cls.authority = driver.authority()

    def test_exact_current_source_freeze(self) -> None:
        files = self.manifest["files"]
        self.assertEqual(112, len(files))
        self.assertEqual(driver.SOURCE_RECORDS_SHA256, driver.canonical_sha(files))
        self.assertEqual(files, driver.source_records(driver.ROOT, files))

    def test_host_executable_identity(self) -> None:
        observed = driver.executable_guards()
        self.assertEqual(driver.DOCKER_SHA256, observed["docker"]["sha256"])
        self.assertEqual(driver.PYTHON_SHA256, observed["python"]["sha256"])

    def test_authority_is_exact_immutable_gate(self) -> None:
        self.assertEqual(driver.AUTHORITY_GATE_SHA256,
                         driver.canonical_sha(self.authority["gate"]))
        self.assertEqual(driver.AUTHORITY_SDK_SHA256,
                         driver.canonical_sha(self.authority["sdk_tools"]))
        self.assertEqual(driver.GATE_ID, self.authority["gate"]["Id"])
        self.assertEqual(driver.GATE_IMAGE, self.authority["gate"]["Image"])
        self.assertEqual([], self.authority["gate"]["Mounts"])

    def test_gate_lifecycle_and_profile_are_both_required(self) -> None:
        actual = copy.deepcopy(self.authority["gate"])
        actual["State"] = {"Running": True, "Paused": False, "Restarting": False,
                           "Dead": False, "OOMKilled": False, "Pid": 123,
                           "StartedAt": "2026-10-12T00:00:00Z"}
        row = driver.validate_gate(actual, self.authority["gate"])
        self.assertEqual({"Pid": 123, "StartedAt": "2026-10-12T00:00:00Z"},
                         row["lifecycle"])
        for mutation in (
            lambda value: value["Mounts"].append({"Destination": "/foreign"}),
            lambda value: value["State"].update(Running=False),
            lambda value: value["State"].update(OOMKilled=True),
            lambda value: value.update(Image="sha256:" + "0" * 64),
        ):
            hostile = copy.deepcopy(actual)
            mutation(hostile)
            with self.assertRaises(driver.Failure):
                driver.validate_gate(hostile, self.authority["gate"])

    def test_aidl_is_added_without_weakening_existing_tool_record(self) -> None:
        observed = copy.deepcopy(self.authority["sdk_tools"])
        observed["tools"][driver.AIDL] = "a" * 64
        value = driver.validate_sdk_observation(
            observed, self.authority["sdk_tools"])
        self.assertEqual({"path": driver.AIDL, "sha256": "a" * 64}, value["aidl"])
        for hostile in (
            {**observed, "tools": {key: val for key, val in observed["tools"].items()
                                    if key != driver.AIDL}},
            {**observed, "offline_dependency_artifacts": {}},
            {**observed, "tools": {**observed["tools"], driver.AIDL: "not-a-digest"}},
        ):
            with self.assertRaises(driver.Failure):
                driver.validate_sdk_observation(hostile, self.authority["sdk_tools"])

    def test_library_only_gradle_command_is_exact(self) -> None:
        remote = "/work/fresh-sdk-a"
        command = driver.gradle_command(remote)
        self.assertEqual([":desktop-sdk:clean", ":desktop-sdk:testReleaseUnitTest",
                          ":desktop-sdk:verifyPhase1Publication"], command[-3:])
        self.assertIn("--offline", command)
        self.assertIn("--no-daemon", command)
        self.assertIn("--rerun-tasks", command)
        self.assertIn("--no-parallel", command)
        self.assertIn("--max-workers=2", command)
        self.assertIn("-Dorg.gradle.jvmargs=-Xmx2048m -XX:MaxMetaspaceSize=768m",
                      command)
        joined = " ".join(command)
        for forbidden in ("assemble", "conformance", "desktop:build", "sign", "apk"):
            self.assertNotIn(forbidden, joined.lower())

    def test_lane_commands_use_distinct_source_and_repository(self) -> None:
        root = Path("/u/elric/tree/wonad-phase1-build-evidence/phase1-sdk-3.0.1-independent-publication-run-fixture")
        a = driver.lane_commands(root, "build-a", "/work/fixture-a")
        b = driver.lane_commands(root, "build-b", "/work/fixture-b")
        self.assertNotEqual(a["copy_source"], b["copy_source"])
        self.assertNotEqual(a["collect"], b["collect"])
        self.assertIn(str(root / "build-a/source"), a["copy_source"])
        self.assertIn(str(root / "build-b/source"), b["copy_source"])
        self.assertIn(str(root / "build-a/sdk-repository"), a["collect"])
        self.assertIn(str(root / "build-b/sdk-repository"), b["collect"])

    def test_verifier_protocol_requires_exact_coordinate_and_primaries(self) -> None:
        artifacts = {name: "a" * 64 for name in driver.PRIMARY_FILES}
        good = json.dumps({"coordinate": "org.wonad:desktop-sdk:3.0.1",
                           "reproducible": None, "artifact_sha256": artifacts})
        driver.parse_verifier(good, comparison=False)
        for mutation in (
            {"coordinate": "org.wonad:desktop-sdk:3.0.0", "reproducible": None,
             "artifact_sha256": artifacts},
            {"coordinate": "org.wonad:desktop-sdk:3.0.1", "reproducible": None,
             "artifact_sha256": {**artifacts, "foreign": "b" * 64}},
            {"coordinate": "org.wonad:desktop-sdk:3.0.1", "reproducible": False,
             "artifact_sha256": artifacts},
        ):
            with self.assertRaises(driver.Failure):
                driver.parse_verifier(json.dumps(mutation), comparison=False)

    def test_comparison_protocol_requires_all_five_primaries(self) -> None:
        good = {"reproducible": True, "comparison_scope": list(driver.PRIMARY_FILES)}
        driver.parse_verifier(json.dumps(good), comparison=True)
        for mutation in (
            {"reproducible": False, "comparison_scope": list(driver.PRIMARY_FILES)},
            {"reproducible": True, "comparison_scope": list(driver.PRIMARY_FILES[:-1])},
            {"reproducible": True,
             "comparison_scope": [*driver.PRIMARY_FILES, "foreign"]},
        ):
            with self.assertRaises(driver.Failure):
                driver.parse_verifier(json.dumps(mutation), comparison=True)

    def test_inventory_rejects_symlink_and_records_every_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sdk-publication-inventory-") as raw:
            root = Path(raw)
            (root / "a").write_bytes(b"one")
            (root / "nested").mkdir()
            (root / "nested/b").write_bytes(b"two")
            value = driver.inventory(root)
            self.assertEqual({"a", "nested/b"}, set(value))
            (root / "link").symlink_to("a")
            with self.assertRaises(driver.Failure):
                driver.inventory(root)

    def test_copy_source_is_independent_and_byte_exact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sdk-source-copy-") as raw:
            target = Path(raw) / "source"
            driver.copy_source(target, self.manifest["files"])
            self.assertEqual(self.manifest["files"],
                             driver.source_records(target, self.manifest["files"]))
            first = target / sorted(self.manifest["files"])[0]
            self.assertFalse(first.stat().st_mode & 0o222)

    def test_bad_output_is_rejected_before_any_side_effect(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sdk-invalid-output-parent-") as raw:
            target = Path(raw) / "phase1-sdk-3.0.1-independent-publication-run-bad"
            with self.assertRaises(driver.Failure):
                driver.prepare(target)
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
