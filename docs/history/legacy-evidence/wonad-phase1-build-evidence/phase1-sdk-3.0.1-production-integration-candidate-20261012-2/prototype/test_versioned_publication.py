#!/usr/bin/env python3

from __future__ import annotations

import copy
import difflib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
WORKSPACE = Path("/u/elric/tree/wonad")
SPEC = importlib.util.spec_from_file_location("versioned_publication", HERE / "versioned_publication.py")
assert SPEC is not None and SPEC.loader is not None
vp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vp)


class VersionedPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = vp.load_json(HERE / "known-publications.json")

    def assertRejected(self, value, *, files=False):
        with self.assertRaises(vp.VerificationError):
            vp.validate_inventory(value, HERE, WORKSPACE, check_files=files)

    def valid_verifier_output(self):
        known = self.inventory["publications"]["3.0.0"]
        return {
            "coordinate": known["coordinate"],
            "contract_signature": vp.SIGNATURE,
            "artifact_sha256": {name: row["sha256"] for name, row in known["artifacts"].items()},
        }

    def test_actual_inventory_and_frozen_files_validate(self):
        vp.validate_inventory(self.inventory, HERE, WORKSPACE, check_files=True)

    def test_actual_known_publication_delegates_to_production_verifier(self):
        result = vp.verify_known_publication(self.inventory, HERE, WORKSPACE, "3.0.0")
        self.assertEqual(result["coordinate"], "org.wonad:desktop-sdk:3.0.0")
        self.assertEqual(result["contract_signature"], vp.SIGNATURE)
        self.assertFalse(result["runtime_qualified"])

    def test_draft_cannot_be_verified_while_hashes_unknown(self):
        with self.assertRaisesRegex(vp.VerificationError, "hashes remain unknown"):
            vp.verify_known_publication(self.inventory, HERE, WORKSPACE, "3.0.1")

    def test_unknown_version_rejected(self):
        with self.assertRaisesRegex(vp.VerificationError, "unknown SDK version"):
            vp.verify_known_publication(self.inventory, HERE, WORKSPACE, "3.1.0")

    def test_draft_artifact_hash_alias_is_rejected(self):
        changed = copy.deepcopy(self.inventory)
        row = changed["publications"]["3.0.1"]["artifacts"]["desktop-sdk-3.0.1.aar"]
        row["sha256"] = "0" * 64
        row["bytes"] = 1
        self.assertRejected(changed)

    def test_bool_is_not_accepted_as_schema_or_size_integer(self):
        changed = copy.deepcopy(self.inventory)
        changed["schema"] = True
        self.assertRejected(changed)
        changed = copy.deepcopy(self.inventory)
        changed["publications"]["3.0.0"]["artifacts"]["desktop-sdk-3.0.0.aar"]["bytes"] = True
        self.assertRejected(changed)

    def test_noncanonical_later_contract_cannot_replace_known_3_0_0(self):
        changed = copy.deepcopy(self.inventory)
        changed["publications"]["3.0.0"]["repository_path"] = (
            "android/out/native-current-successor-12-phase1-v3-runtime-20261011-18/sdk-repository")
        with self.assertRaisesRegex(vp.VerificationError, "contract.zip bytes differ"):
            vp.validate_inventory(changed, HERE, WORKSPACE, check_files=True)

    def test_missing_or_extra_primary_artifact_rejected(self):
        changed = copy.deepcopy(self.inventory)
        del changed["publications"]["3.0.0"]["artifacts"]["desktop-sdk-3.0.0.pom"]
        self.assertRejected(changed)
        changed = copy.deepcopy(self.inventory)
        changed["publications"]["3.0.0"]["artifacts"]["extra.jar"] = {
            "sha256": "0" * 64, "bytes": 1}
        self.assertRejected(changed)

    def test_draft_is_complete_relative_to_frozen_reviewed_spec(self):
        base = (WORKSPACE / "android/desktop-sdk/API-v3.md").read_text(encoding="utf-8")
        draft = (HERE / "API-v3.0.1-draft.md").read_text(encoding="utf-8")
        base_headings = {line for line in base.splitlines() if line.startswith("## ")}
        draft_headings = {line for line in draft.splitlines() if line.startswith("## ")}
        self.assertTrue(base_headings <= draft_headings)
        self.assertIn("## Picker admission and observability", draft_headings)
        self.assertIn("org.wonad:desktop-sdk:3.0.1", draft)
        self.assertIn("documentation-only patch", draft)
        changed_base_ranges = [
            (op, start, end)
            for op, start, end, _draft_start, _draft_end in difflib.SequenceMatcher(
                None, base.splitlines(), draft.splitlines(), autojunk=False).get_opcodes()
            if op != "equal"
        ]
        self.assertEqual(changed_base_ranges, [
            ("replace", 0, 1),
            ("replace", 2, 4),
            ("replace", 6, 7),
            ("replace", 52, 56),
            ("insert", 205, 205),
            ("replace", 225, 231),
            ("replace", 235, 238),
            ("replace", 245, 254),
        ])

    def test_captured_picker_is_byte_identical_to_reviewed_source(self):
        self.assertEqual(
            (HERE / "native_picker.rs").read_bytes(),
            (WORKSPACE / "android/broker-rust/src/native_picker.rs").read_bytes())

    def test_process_global_picker_owner_is_authenticated(self):
        row = self.inventory["frozen_inputs"]["picker_process_owner"]
        source = (WORKSPACE / row["path"]).read_text(encoding="utf-8")
        self.assertEqual(source.count(row["required_declaration"]), 1)

    def test_duplicate_json_key_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text('{"schema":1,"schema":1}\n', encoding="utf-8")
            with self.assertRaisesRegex(vp.VerificationError, "duplicate JSON key"):
                vp.load_json(path)

    def test_production_verifier_failure_is_not_skipped(self):
        def failed(*args, **kwargs):
            return subprocess.CompletedProcess(args[0], 9, stdout="rejected\n", stderr="")
        with self.assertRaisesRegex(vp.VerificationError, "rejected publication"):
            vp.verify_known_publication(self.inventory, HERE, WORKSPACE, "3.0.0", run=failed)

    def test_authenticated_verifier_bytes_are_executed_from_private_copy(self):
        wanted = (WORKSPACE / self.inventory["publications"]["3.0.0"]["verifier_inputs"]
                  ["verify_sdk_publication.py"]["path"]).read_bytes()
        sibling = (WORKSPACE / self.inventory["publications"]["3.0.0"]["verifier_inputs"]
                   ["sdk_contract.py"]["path"]).read_bytes()
        def inspect(command, **kwargs):
            script = Path(command[2])
            self.assertNotEqual(script, WORKSPACE / "android/tools/verify_sdk_publication.py")
            self.assertEqual(script.read_bytes(), wanted)
            self.assertEqual(script.with_name("sdk_contract.py").read_bytes(), sibling)
            return subprocess.CompletedProcess(command, 0,
                stdout=json.dumps(self.valid_verifier_output()), stderr="")
        vp.verify_known_publication(self.inventory, HERE, WORKSPACE, "3.0.0", run=inspect)

    def test_input_drift_after_production_verifier_is_rejected(self):
        def valid(*args, **kwargs):
            return subprocess.CompletedProcess(args[0], 0,
                stdout=json.dumps(self.valid_verifier_output()), stderr="")
        with mock.patch.object(vp, "_snapshot_known_files", side_effect=[
                {"input": ("1" * 64, 1)}, {"input": ("2" * 64, 1)}]):
            with self.assertRaisesRegex(vp.VerificationError, "changed during verification"):
                vp.verify_known_publication(self.inventory, HERE, WORKSPACE, "3.0.0", run=valid)

    def test_production_verifier_result_must_cross_bind_coordinate(self):
        output = self.valid_verifier_output()
        output["coordinate"] = "org.wonad:desktop-sdk:3.0.1"
        def forged(*args, **kwargs):
            return subprocess.CompletedProcess(args[0], 0, stdout=json.dumps(output), stderr="")
        with self.assertRaisesRegex(vp.VerificationError, "coordinate differs"):
            vp.verify_known_publication(self.inventory, HERE, WORKSPACE, "3.0.0", run=forged)

    def test_production_verifier_result_must_cross_bind_every_artifact(self):
        output = self.valid_verifier_output()
        hashes = output["artifact_sha256"]
        hashes["desktop-sdk-3.0.0.aar"] = "0" * 64
        def forged(*args, **kwargs):
            return subprocess.CompletedProcess(args[0], 0, stdout=json.dumps(output), stderr="")
        with self.assertRaisesRegex(vp.VerificationError, "artifact result differs"):
            vp.verify_known_publication(self.inventory, HERE, WORKSPACE, "3.0.0", run=forged)

    def test_verifier_stderr_is_rejected_even_on_zero(self):
        output = self.valid_verifier_output()
        def noisy(*args, **kwargs):
            return subprocess.CompletedProcess(args[0], 0, stdout=json.dumps(output), stderr="warning")
        with self.assertRaisesRegex(vp.VerificationError, "emitted stderr"):
            vp.verify_known_publication(self.inventory, HERE, WORKSPACE, "3.0.0", run=noisy)

    def test_required_draft_document_hash_is_not_advisory(self):
        changed = copy.deepcopy(self.inventory)
        changed["publications"]["3.0.1"]["draft"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(vp.VerificationError, "3.0.1 draft bytes differ"):
            vp.validate_inventory(changed, HERE, WORKSPACE, check_files=True)


if __name__ == "__main__":
    unittest.main()
