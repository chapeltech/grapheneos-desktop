#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("sdk301_candidate", HERE / "verify_candidate.py")
assert SPEC is not None and SPEC.loader is not None
candidate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(candidate)


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.plan = candidate.load(HERE / "integration-map.json")

    def verify_mutation(self, mutate):
        changed = copy.deepcopy(self.plan)
        mutate(changed)
        with mock.patch.object(candidate, "load", return_value=changed):
            with self.assertRaises(candidate.CandidateError):
                candidate.verify(HERE, candidate.WORKSPACE)

    def test_actual_external_candidate_verifies(self):
        result = candidate.verify(HERE, candidate.WORKSPACE)
        self.assertEqual(result["status"], candidate.SCOPE)
        self.assertEqual(result["modified_source_count"], 14)
        self.assertEqual(result["unchanged_sdk_source_count"], 17)
        self.assertEqual(result["unresolved_artifact_count"], 5)

    def test_unknown_3_0_1_artifact_hash_cannot_be_prepopulated(self):
        def mutate(value):
            row = value["proposed_3_0_1"]["artifacts"]["desktop-sdk-3.0.1.aar"]
            row["sha256"] = "0" * 64
            row["bytes"] = 1
        self.verify_mutation(mutate)

    def test_unpublished_state_cannot_be_promoted_by_the_candidate(self):
        self.verify_mutation(
            lambda value: value["proposed_3_0_1"]["state"].__setitem__("built", True))

    def test_api_machine_signature_and_version_cannot_change(self):
        self.verify_mutation(
            lambda value: value["machine_contract"].__setitem__("signature_sha256", "0" * 64))
        self.verify_mutation(lambda value: value.__setitem__("api_version", 4))
        self.verify_mutation(
            lambda value: value["machine_contract"].__setitem__(
                "wire_or_jvm_or_numeric_change", True))

    def test_contract_document_identity_is_not_advisory(self):
        self.verify_mutation(
            lambda value: value["proposed_3_0_1"]["contract_members"]["API-v3.md"].__setitem__(
                "sha256", "0" * 64))
        self.verify_mutation(
            lambda value: value["proposed_3_0_1"]["contract_members"]["API-v3.md"].__setitem__(
                "bytes", True))

    def test_historical_3_0_0_cannot_be_replaced_or_relabelled(self):
        self.verify_mutation(
            lambda value: value["canonical_historical_3_0_0"].__setitem__(
                "coordinate", "org.wonad:desktop-sdk:3.0.1"))
        self.verify_mutation(
            lambda value: value["noncanonical_historical_observation"].__setitem__(
                "canonical_publication", True))

    def test_current_and_proposed_source_pins_are_enforced(self):
        name = "android/tools/verify_sdk_publication.py"
        self.verify_mutation(
            lambda value: value["source_snapshots"]["modified"][name].__setitem__(
                "after", "0" * 64))
        self.verify_mutation(
            lambda value: value["source_snapshots"]["modified"][name].__setitem__(
                "before", "1" * 64))

    def test_unknown_future_receipts_and_qualification_cannot_be_fabricated(self):
        self.verify_mutation(
            lambda value: value["required_future_results"].__setitem__(
                "fresh_successor_receipt", {"sha256": "0" * 64}))

    def test_normative_language_covers_global_cadence_and_unobservable_outcomes(self):
        text = (HERE / "proposed/android/desktop-sdk/API-v3.md").read_text()
        self.assertIn("one process-global monotonic clock", text)
        self.assertIn("`T + 1000` milliseconds", text)
        self.assertIn("`launcherPage` is synchronous and nullable", text)
        self.assertIn("one-way, fire-and-forget request", text)
        self.assertIn("API v3 has no exact", text)
        self.assertNotIn("changes API negotiation", text)

    def test_only_documentation_coordinate_and_trust_consumers_change(self):
        wanted = {
            "android/desktop-sdk/API-v3.md", "android/desktop-sdk/README.md",
            "android/desktop-sdk/build.gradle.kts", "android/EXTERNAL-SHELL.md",
            "android/tools/verify_sdk_publication.py",
            "android/tools/build_native_successor.py",
            "android/tools/native_current_compile_acceptance.py",
            "android/tools/phase1_provenance.py", "android/tools/release_receipt.py",
            "android/tools/phase1_release_index.py", "android/tests/test_sdk_publication.py",
            "android/tests/test_native_current_compile.py",
            "android/tests/test_phase1_provenance.py",
            "android/tests/test_release_receipt.py",
        }
        self.assertEqual(set(self.plan["source_snapshots"]["modified"]), wanted)

    def test_wire_kotlin_manifest_and_machine_contract_sources_are_byte_identical(self):
        current = candidate.file_tree(HERE / "current/android/desktop-sdk/src")
        proposed = candidate.file_tree(HERE / "proposed/android/desktop-sdk/src")
        live = candidate.file_tree(candidate.WORKSPACE / "android/desktop-sdk/src")
        self.assertEqual(current, proposed)
        self.assertEqual(proposed, live)
        self.assertEqual(
            candidate.digest(HERE / "current/android/tests/fixtures/desktop-sdk-contract-v3.json"),
            candidate.digest(HERE / "proposed/android/tests/fixtures/desktop-sdk-contract-v3.json"))
        self.assertEqual(
            candidate.digest(HERE / "current/android/tools/sdk_contract.py"),
            candidate.digest(HERE / "proposed/android/tools/sdk_contract.py"))

    def test_proposed_consumers_require_3_0_1_while_docs_keep_historical_3_0_0(self):
        consumers = (
            "android/tools/build_native_successor.py",
            "android/tools/native_current_compile_acceptance.py",
            "android/tools/phase1_provenance.py",
            "android/tools/release_receipt.py",
            "android/tools/phase1_release_index.py",
        )
        for name in consumers:
            text = (HERE / "proposed" / name).read_text()
            with self.subTest(name=name):
                self.assertIn("org.wonad:desktop-sdk:3.0.1", text)
                self.assertNotIn("org.wonad:desktop-sdk:3.0.0", text)
        shell = (HERE / "proposed/android/EXTERNAL-SHELL.md").read_text()
        self.assertIn("canonical historical 3.0.0", shell)
        self.assertIn("org.wonad:desktop-sdk:3.0.1", shell)


if __name__ == "__main__":
    unittest.main()
