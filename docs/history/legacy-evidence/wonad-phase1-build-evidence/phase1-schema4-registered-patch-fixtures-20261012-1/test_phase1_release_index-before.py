#!/usr/bin/env python3
"""Adversarial tests for the aggregate Phase-1 release-evidence freeze."""

from __future__ import annotations

import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "android/tools/phase1_release_index.py"
SPEC = importlib.util.spec_from_file_location("phase1_release_index_under_test", TOOL)
index = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(index)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return path


def ref(root, relative):
    payload = (root / relative).read_bytes()
    return {"path": relative, "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload)}


class PrimitiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wonad-phase1-index-unit-")
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def test_safe_relative_rejects_aliases_and_escape(self):
        for value in ("", "/absolute", "../escape", "a/../b", "a//b", "a\\b", "a/./b"):
            with self.subTest(value=value), self.assertRaises(index.IndexError):
                index.safe_relative(value)

    def test_duplicate_json_keys_are_rejected(self):
        path = self.root / "duplicate.json"
        path.write_text('{"schema":1,"schema":1}\n')
        with self.assertRaisesRegex(index.IndexError, "Duplicate JSON"):
            index.load_json_path(path, "duplicate")

    def test_stable_bytes_uses_the_standard_file_digest_once(self):
        for name, payload in (("small", b"one block\n"),
                              ("large", b"0123456789abcdef" * 100000)):
            path = self.root / name
            path.write_bytes(payload)
            raw, reference = index.stable_bytes(path, maximum=len(payload) + 1)
            self.assertEqual(payload, raw)
            self.assertEqual(hashlib.sha256(payload).hexdigest(), reference["sha256"])

    def test_symlinked_evidence_is_rejected(self):
        target = self.root / "target"; target.write_text("x")
        (self.root / "alias").symlink_to(target)
        with self.assertRaisesRegex(index.IndexError, "symlink"):
            index.file_ref(self.root, "alias")

    def test_private_material_is_rejected_even_with_public_looking_name(self):
        path = self.root / "certificate.pem"
        path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nsecret\n")
        with self.assertRaisesRegex(index.IndexError, "Private-key"):
            index.file_ref(self.root, path.name)

    def test_tree_rejects_private_key_suffix(self):
        tree = self.root / "sdk"; tree.mkdir()
        (tree / "accidental.pk8").write_bytes(b"secret")
        with self.assertRaisesRegex(index.IndexError, "private key"):
            index.tree_ref(self.root, "sdk")

    def test_disguised_private_suffix_and_ec_key_header_are_rejected(self):
        disguised = self.root / "public.pk8.txt"
        disguised.write_bytes(b"binary secret")
        with self.assertRaisesRegex(index.IndexError, "Private-key"):
            index.file_ref(self.root, disguised.name)
        disguised.unlink()
        disguised = self.root / "apparently-public.key.pem"
        disguised.write_bytes(b"opaque binary")
        with self.assertRaisesRegex(index.IndexError, "Private-key"):
            index.file_ref(self.root, disguised.name)
        disguised.unlink()
        disguised = self.root / "public.txt"
        disguised.write_bytes(b"-----BEGIN EC PRIVATE KEY-----\nsecret\n")
        with self.assertRaisesRegex(index.IndexError, "Private-key"):
            index.file_ref(self.root, disguised.name)

    def test_structured_json_cannot_smuggle_private_key_material(self):
        path = self.root / "record.json"
        write_json(path, {"summary": "-----BEGIN PRIVATE KEY-----"})
        with self.assertRaisesRegex(index.IndexError, "Private-key"):
            index.load_json_ref(self.root, path.name, "record")


class PublicCertificateAlgorithmTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wonad-phase1-public-algorithm-")
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def certificate(self, algorithm, *, curve=None):
        path = self.root / "certificate.x509.pem"
        command = [index.provenance.HOST_TOOL_PINS["openssl"]["path"],
                   "req", "-x509", "-newkey", algorithm, "-nodes", "-days", "1",
                   "-subj", "/CN=Wonad Algorithm Unit Test", "-keyout", "/dev/null",
                   "-out", str(path)]
        if curve is not None:
            command.extend(["-pkeyopt", "ec_paramgen_curve:" + curve])
        # Ephemeral test keys are discarded, never retained in public evidence.
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30,
                       env=index.provenance.hermetic_environment(openssl=True))
        observed = index.provenance.public_certificate(path)
        return {"algorithm": "RSA-3072", "certificate": ref(self.root, path.name),
                "der_sha256": observed["der_sha256"], "der_size": observed["der_size"],
                "subject": observed["subject"]}

    def test_certificate_algorithm_cannot_be_relabelled(self):
        value = self.certificate("rsa:3072")
        index.validate_public_certificate(self.root, value, "unit signer")
        for algorithm in ("RSA-4096", "ECDSA-P256", "ECDSA-P384"):
            broken = dict(value, algorithm=algorithm)
            with self.subTest(algorithm=algorithm), self.assertRaisesRegex(
                    index.IndexError, "algorithm"):
                index.validate_public_certificate(self.root, broken, "unit signer")

    def test_unsupported_rsa_size_cannot_claim_an_allowed_algorithm(self):
        value = self.certificate("rsa:2048")
        with self.assertRaisesRegex(index.IndexError, "algorithm"):
            index.validate_public_certificate(self.root, value, "unit signer")

    def test_rsa4096_is_inspected_from_the_certificate(self):
        value = self.certificate("rsa:4096")
        value["algorithm"] = "RSA-4096"
        index.validate_public_certificate(self.root, value, "unit signer")

    def test_rsa_pss_key_cannot_claim_plain_rsa(self):
        value = self.certificate("rsa-pss:3072")
        with self.assertRaisesRegex(index.IndexError, "algorithm"):
            index.validate_public_certificate(self.root, value, "unit signer")

    def test_supported_ec_curves_are_inspected_and_cannot_be_relabelled(self):
        for curve, algorithm in (("prime256v1", "ECDSA-P256"), ("secp384r1", "ECDSA-P384")):
            with self.subTest(curve=curve):
                value = self.certificate("ec", curve=curve)
                value["algorithm"] = algorithm
                index.validate_public_certificate(self.root, value, "unit signer")
                for other in {"RSA-3072", "RSA-4096", "ECDSA-P256", "ECDSA-P384"} - {algorithm}:
                    value["algorithm"] = other
                    with self.subTest(other=other), self.assertRaisesRegex(index.IndexError, "algorithm"):
                        index.validate_public_certificate(self.root, value, "unit signer")

    def test_ec_bit_count_alone_does_not_admit_an_unsupported_curve(self):
        value = self.certificate("ec", curve="secp256k1")
        value["algorithm"] = "ECDSA-P256"
        with self.assertRaisesRegex(index.IndexError, "algorithm"):
            index.validate_public_certificate(self.root, value, "unit signer")

    def test_algorithm_inspection_requires_the_authenticated_file_snapshot(self):
        value = self.certificate("ec", curve="prime256v1")
        expected = {"sha256": "0" * 64, "size": value["certificate"]["size"]}
        with mock.patch.object(index.subprocess, "run") as execute:
            with self.assertRaisesRegex(index.IndexError, "changed before algorithm"):
                index.public_certificate_algorithm(self.root / "certificate.x509.pem",
                                                   expected, "unit signer")
        execute.assert_not_called()

    def test_path_swap_back_cannot_mix_certificate_identity(self):
        value_a = self.certificate("ec", curve="prime256v1")
        path = self.root / "certificate.x509.pem"
        payload_a = path.read_bytes()
        value_b = self.certificate("ec", curve="prime256v1")
        payload_b = path.read_bytes()
        path.write_bytes(payload_a)
        mixed = dict(value_b, algorithm="ECDSA-P256", certificate=value_a["certificate"])
        original_run = subprocess.run
        inputs = []

        def swap_for_pathname_parsing(command, *args, **kwargs):
            if "x509" in command and "-in" in command:
                path.write_bytes(payload_b)
                try:
                    return original_run(command, *args, **kwargs)
                finally:
                    path.write_bytes(payload_a)
            if "x509" in command:
                inputs.append(kwargs.get("input"))
            return original_run(command, *args, **kwargs)

        with mock.patch.object(index.subprocess, "run", side_effect=swap_for_pathname_parsing):
            with self.assertRaisesRegex(index.IndexError, "identity differs"):
                index.validate_public_certificate(self.root, mixed, "unit signer")
        self.assertTrue(inputs)
        self.assertTrue(all(payload == payload_a for payload in inputs))

    def test_algorithm_inspection_rejects_parser_failure_and_tool_drift(self):
        value = self.certificate("ec", curve="prime256v1")
        expected = {key: value["certificate"][key] for key in ("sha256", "size")}
        path = self.root / "certificate.x509.pem"
        with mock.patch.object(index.subprocess, "run", side_effect=subprocess.TimeoutExpired(
                "openssl", 30)):
            with self.assertRaisesRegex(index.IndexError, "Cannot inspect.*algorithm"):
                index.public_certificate_algorithm(path, expected, "unit signer")
        with mock.patch.object(index.provenance, "_host_tool_uncached", return_value={"changed": True}):
            with self.assertRaisesRegex(index.IndexError, "Pinned OpenSSL changed"):
                index.public_certificate_algorithm(path, expected, "unit signer")

    def test_ambiguous_algorithm_rendering_is_rejected(self):
        value = self.certificate("ec", curve="prime256v1")
        expected = {key: value["certificate"][key] for key in ("sha256", "size")}
        rendered = b"  Public Key Algorithm: rsaEncryption\n  Public-Key: (4096 bit)\n"
        for suffix in (b"  Public Key Algorithm: rsaEncryption\n",
                       b"  Public-Key: (3072 bit)\n",
                       b"  ASN1 OID: prime256v1\n"):
            with self.subTest(suffix=suffix), mock.patch.object(index.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 0, stdout=rendered + suffix)):
                with self.assertRaisesRegex(index.IndexError, "algorithm"):
                    index.public_certificate_algorithm(self.root / "certificate.x509.pem",
                                                       expected, "unit signer")


class AtomicPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wonad-phase1-publication-unit-")
        self.root = Path(self.temporary.name).resolve()
        self.output = self.root / "release.json"
        self.value = {"schema": 1, "evidence": "complete" * 4096}
        self.payload = (json.dumps(self.value, indent=2, sort_keys=True) + "\n").encode()

    def tearDown(self):
        self.temporary.cleanup()

    def assert_no_pending(self):
        self.assertEqual(list(self.root.glob(".*.pending-*")), [])

    def test_final_is_invisible_until_complete_file_is_fsynced(self):
        original_fsync = os.fsync
        observations = []

        def inspect_fsync(descriptor):
            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                self.assertFalse(self.output.exists())
                pending = list(self.root.glob(".*.pending-*"))
                self.assertEqual(len(pending), 1)
                self.assertEqual(pending[0].read_bytes(), self.payload)
                observations.append("complete-file-before-publication")
            else:
                self.assertEqual(self.output.read_bytes(), self.payload)
                self.assert_no_pending()
                observations.append("directory-after-publication")
            original_fsync(descriptor)

        with mock.patch.object(index.os, "fsync", side_effect=inspect_fsync):
            digest = index.atomic_new(self.output, self.value)
        self.assertEqual(observations, ["complete-file-before-publication",
                                        "directory-after-publication"])
        self.assertEqual(digest, hashlib.sha256(self.output.read_bytes()).hexdigest())
        self.assert_no_pending()

    def test_existing_output_is_never_overwritten(self):
        self.output.write_bytes(b"existing release\n")
        with self.assertRaisesRegex(index.IndexError, "fresh absolute"):
            index.atomic_new(self.output, self.value)
        self.assertEqual(self.output.read_bytes(), b"existing release\n")
        self.assert_no_pending()

    def test_competing_publication_is_preserved(self):
        original_link = os.link

        def create_competitor(*args, **kwargs):
            self.output.write_bytes(b"concurrent release\n")
            return original_link(*args, **kwargs)

        with mock.patch.object(index.os, "link", side_effect=create_competitor):
            with self.assertRaises(FileExistsError):
                index.atomic_new(self.output, self.value)
        self.assertEqual(self.output.read_bytes(), b"concurrent release\n")
        self.assert_no_pending()

    def test_failed_file_fsync_leaves_no_final_or_owned_temporary(self):
        with mock.patch.object(index.os, "fsync", side_effect=OSError("file fsync failed")):
            with self.assertRaisesRegex(OSError, "file fsync failed"):
                index.atomic_new(self.output, self.value)
        self.assertFalse(self.output.exists())
        self.assert_no_pending()

    def test_failed_stream_write_leaves_no_final_or_owned_temporary(self):
        original_fdopen = os.fdopen

        class PartialStream:
            def __init__(self, descriptor, *args, **kwargs):
                self.stream = original_fdopen(descriptor, *args, **kwargs)

            def __enter__(self):
                self.stream.__enter__()
                return self

            def write(self, payload):
                self.stream.write(payload[:100])
                raise OSError("injected incomplete write")

            def __exit__(self, *args):
                return self.stream.__exit__(*args)

        with mock.patch.object(index.os, "fdopen", side_effect=PartialStream):
            with self.assertRaisesRegex(OSError, "incomplete write"):
                index.atomic_new(self.output, self.value)
        self.assertFalse(self.output.exists())
        self.assert_no_pending()

    def test_short_write_without_exception_cannot_publish_partial_record(self):
        original_fdopen = os.fdopen

        class ShortStream:
            def __init__(self, descriptor, *args, **kwargs):
                self.stream = original_fdopen(descriptor, *args, **kwargs)

            def __enter__(self):
                self.stream.__enter__()
                return self

            def write(self, payload):
                return self.stream.write(payload[:100])

            def __exit__(self, *args):
                return self.stream.__exit__(*args)

        with mock.patch.object(index.os, "fdopen", side_effect=ShortStream), \
             mock.patch.object(index.os, "link") as publish:
            with self.assertRaisesRegex(index.IndexError, "Incomplete index write"):
                index.atomic_new(self.output, self.value)
        publish.assert_not_called()
        self.assertFalse(self.output.exists())
        self.assert_no_pending()

    def test_corrupted_temporary_cannot_be_published(self):
        original_fsync = os.fsync

        def corrupt_temporary(descriptor):
            original_fsync(descriptor)
            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                pending = next(self.root.glob(".*.pending-*"))
                pending.write_bytes(self.payload.replace(b"complete", b"modified"))

        with mock.patch.object(index.os, "fsync", side_effect=corrupt_temporary), \
             mock.patch.object(index.os, "link") as publish:
            with self.assertRaisesRegex(index.IndexError, "temporary bytes or identity changed"):
                index.atomic_new(self.output, self.value)
        publish.assert_not_called()
        self.assertFalse(self.output.exists())
        self.assert_no_pending()

    def test_directory_observation_failure_closes_directory_descriptor(self):
        original_close = os.close
        with mock.patch.object(index.os, "fstat", side_effect=OSError("directory observation failed")), \
             mock.patch.object(index.os, "close", wraps=original_close) as close:
            with self.assertRaisesRegex(OSError, "directory observation failed"):
                index.atomic_new(self.output, self.value)
        self.assertEqual(close.call_count, 1)
        self.assertFalse(self.output.exists())
        self.assert_no_pending()

    def test_transient_temporary_observation_failure_cleans_owned_name(self):
        original_fstat = os.fstat
        failed = False

        def transient_failure(descriptor):
            nonlocal failed
            observed = original_fstat(descriptor)
            if stat.S_ISREG(observed.st_mode) and not failed:
                failed = True
                raise OSError("temporary observation failed")
            return observed

        with mock.patch.object(index.os, "fstat", side_effect=transient_failure):
            with self.assertRaisesRegex(OSError, "temporary observation failed"):
                index.atomic_new(self.output, self.value)
        self.assertTrue(failed)
        self.assertFalse(self.output.exists())
        self.assert_no_pending()

    def test_directory_fsync_failure_preserves_complete_published_record(self):
        original_fsync = os.fsync

        def fail_directory(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError("directory fsync failed")
            return original_fsync(descriptor)

        with mock.patch.object(index.os, "fsync", side_effect=fail_directory):
            with self.assertRaisesRegex(OSError, "directory fsync failed"):
                index.atomic_new(self.output, self.value)
        self.assertEqual(self.output.read_bytes(), self.payload)
        self.assert_no_pending()

    def test_replaced_final_inode_cannot_return_original_digest(self):
        original_fsync = os.fsync

        def replace_final(descriptor):
            original_fsync(descriptor)
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                self.output.unlink()
                self.output.write_bytes(self.payload)

        with mock.patch.object(index.os, "fsync", side_effect=replace_final):
            with self.assertRaisesRegex(index.IndexError, "replaced"):
                index.atomic_new(self.output, self.value)
        self.assertEqual(self.output.read_bytes(), self.payload)
        self.assert_no_pending()

    def test_changed_final_bytes_cannot_return_original_digest(self):
        original_fsync = os.fsync

        def alter_final(descriptor):
            original_fsync(descriptor)
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                self.output.write_bytes(self.payload.replace(b"complete", b"modified"))

        with mock.patch.object(index.os, "fsync", side_effect=alter_final):
            with self.assertRaisesRegex(index.IndexError, "bytes or identity changed"):
                index.atomic_new(self.output, self.value)
        self.assertNotEqual(self.output.read_bytes(), self.payload)
        self.assert_no_pending()


class StructuredEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wonad-phase1-index-record-")
        self.root = Path(self.temporary.name).resolve()
        for name in ("closure.txt", "review.md", "upstream-atest.json"):
            (self.root / name).write_text(name + "\n")
        self.source = {
            "lock_sha256": "a" * 64, "manifest_commit": "b" * 40,
            "manifest_tag_object": "c" * 40, "default_xml_sha256": "d" * 64,
            "project_count": 1057, "project_ledger_sha256": "e" * 64,
            "worktree_materializations_sha256": "f" * 64,
        }

    def tearDown(self):
        self.temporary.cleanup()

    def upstream(self):
        """Envelope-validation fixture, not evidence of native execution."""
        generic = index.generic_upstream
        self.generic_plan = copy.deepcopy(generic.reviewed_plan())
        generic.class_row(self.generic_plan, "grapheneos_host")["state"] = "not_applicable_source_declared"
        write_json(self.root / "generic-plan.json", self.generic_plan)
        self.generic_sha = ref(self.root, "generic-plan.json")["sha256"]
        self.expected_builds = {side: {"sha256": ("1" if side == "baseline" else "2") * 64,
                                       "size": 100}
                                for side in ("baseline", "custom")}
        self.expected_pin = "3" * 64
        self.native_projections = {}
        runs = []
        for category in sorted(index.REQUIRED_UPSTREAM_CLASSES):
            baseline_cases = {"common.failure": "failure" if category == "aosp_host" else "passed",
                              "potential.failure": "passed"}
            sides = {}
            for side in ("baseline", "custom"):
                name = f"{category}-{side}.json"
                write_json(self.root / name, {"kind": "fake-native-boundary-fixture",
                                             "class": category, "role": side})
                sides[side] = ref(self.root, name)
                projection = {
                    "class": category, "role": side, "source_pin_sha256": self.expected_pin,
                    "build_receipt": copy.deepcopy(self.expected_builds[side]),
                    "receipt_sha256": sides[side]["sha256"],
                    "plan_sha256": self.generic_sha, "cases": dict(baseline_cases),
                    "authority": {"builder": {"id": "immutable"},
                                  "toolchain": {"source_tools": "pinned"}},
                }
                if category == "grapheneos_host":
                    del projection["cases"]
                    projection["applicability"] = {
                        "result": "not_applicable_source_declared",
                        "evidence": {"definition": {"sha256": "4" * 64},
                                     "scope": "pinned-source-declarations-only-no-external-ci-claim"},
                    }
                if category == "aosp_emulator":
                    projection["module_plan_sha256"] = generic.canonical_digest(
                        generic.atest_comparison.load_json(index.UPSTREAM_PLAN))
                    projection["authority"].update({"device_class": {"serial": "emulator-5580"},
                                                     "runner": {"sha256": "4" * 64},
                                                     "boot_id": side + "-boot"})
                    projection["cases"].update({"grapheneos_secure_paste/" + case: "passed"
                                               for case in generic.atest_comparison.REQUIRED_GRAPHENEOS_CASES})
                    if side == "custom":
                        projection["cases"].update({suite + "/" + case: "passed"
                                                   for suite, cases in
                                                   generic.atest_comparison.CUSTOM_ONLY_CASES.items()
                                                   for case in cases})
                self.native_projections[name] = projection
            runs.append({"class": category, **sides})
        return {"schema": 2, "kind": index.UPSTREAM_KIND, "qualification": "production",
                "source": self.source, "plan": ref(self.root, "generic-plan.json"), "runs": runs,
                "result": "passed_no_new_or_worsened_native_failures"}

    def validate_native(self, value):
        generic = index.generic_upstream
        def native(test_class, path, digest):
            projection = self.native_projections[path.name]
            self.assertEqual(projection["class"], test_class)
            self.assertEqual(projection["receipt_sha256"], digest)
            return projection
        with mock.patch.object(generic, "reviewed_plan", return_value=self.generic_plan), \
             mock.patch.object(generic, "validate_plan", return_value=self.generic_plan), \
             mock.patch.object(generic, "PLAN_SHA256", self.generic_sha), \
             mock.patch.object(index, "native_upstream_run", side_effect=native):
            return index.validate_upstream(self.root, value, self.source,
                                          expected_builds=self.expected_builds,
                                          expected_source_pin_sha256=self.expected_pin)

    def test_upstream_accepts_only_common_baseline_failures(self):
        result = self.validate_native(self.upstream())
        self.assertEqual(result["classes"], sorted(index.REQUIRED_UPSTREAM_CLASSES))

    def test_upstream_rejects_new_custom_failure(self):
        value = self.upstream()
        self.native_projections["aosp_host-custom.json"]["cases"]["potential.failure"] = "failure"
        with self.assertRaisesRegex(index.IndexError, "new or worsened"):
            self.validate_native(value)

    def test_upstream_rejects_operator_failure_claim_and_arbitrary_command(self):
        value = self.upstream()
        for field, claim in (("failures", []), ("test_plan", ["sh", "-c", "true"])):
            changed = copy.deepcopy(value)
            changed["runs"][0][field] = claim
            with self.subTest(field=field), self.assertRaisesRegex(index.IndexError, "Unexpected .* fields"):
                self.validate_native(changed)

    def test_upstream_rejects_missing_coverage_class(self):
        value = self.upstream(); value["runs"].pop()
        with self.assertRaisesRegex(index.IndexError, "required coverage class"):
            self.validate_native(value)

    def test_upstream_rejects_report_tampering(self):
        value = self.upstream()
        (self.root / "aosp_host-baseline.json").write_text("tampered\n")
        with self.assertRaisesRegex(index.IndexError, "bytes differ|Invalid JSON"):
            self.validate_native(value)

    def test_upstream_rejects_native_run_bound_to_another_build_or_source(self):
        for field, replacement in (("build_receipt", {"sha256": "9" * 64, "size": 100}),
                                    ("source_pin_sha256", "9" * 64), ("role", "baseline")):
            value = self.upstream()
            self.native_projections["aosp_host-custom.json"][field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(index.IndexError, "selected class/role/build/source"):
                self.validate_native(value)

    def test_legacy_manual_junit_envelope_cannot_qualify(self):
        value = self.upstream()
        value["schema"] = 1
        with self.assertRaisesRegex(index.IndexError, "wrong identity"):
            self.validate_native(value)

    def test_operator_cannot_mark_reviewed_applicability_resolved(self):
        value = self.upstream()
        changed_plan = copy.deepcopy(index.generic_upstream.reviewed_plan())
        index.generic_upstream.class_row(changed_plan, "grapheneos_host")["state"] = "resolved"
        write_json(self.root / "generic-plan.json", changed_plan)
        value["plan"] = ref(self.root, "generic-plan.json")
        with self.assertRaisesRegex(index.IndexError, "repository-reviewed bytes"):
            index.validate_upstream(self.root, value, self.source,
                                    expected_builds=self.expected_builds,
                                    expected_source_pin_sha256=self.expected_pin)

    def test_native_dispatch_uses_full_rehash_and_never_imports_a_junit_log(self):
        path = self.root / "native.json"
        with mock.patch.object(index.generic_upstream, "verify_host", return_value={}) as host:
            index.native_upstream_run("aosp_host", path, "1" * 64)
        host.assert_called_once_with(path, "1" * 64, rehash_build=True)
        with mock.patch.object(index.generic_upstream, "normalize_emulator", return_value={}) as emulator:
            index.native_upstream_run("aosp_emulator", path, "2" * 64)
        emulator.assert_called_once_with(path, "2" * 64)
        with mock.patch.object(index.generic_upstream.grapheneos_applicability,
                               "verify", return_value={}) as graphene:
            index.native_upstream_run("grapheneos_host", path, "3" * 64)
        graphene.assert_called_once_with(path, "3" * 64, rehash_build=True)
        with self.assertRaisesRegex(index.IndexError, "No reviewed upstream"):
            index.native_upstream_run("unknown", path, "3" * 64)

    def upstream_selection(self):
        value = self.upstream()
        builds = {}
        for role in ("baseline", "custom"):
            write_json(self.root / (role + "-build.json"), {
                "role": role, "source": {"pin": {"release": index.RELEASE}}})
            builds[role] = ref(self.root, role + "-build.json")
        selection = {"schema": 1, "kind": index.UPSTREAM_INPUTS_KIND,
                     "plan": value["plan"], "builds": builds, "runs": value["runs"]}
        path = write_json(self.root / "upstream-selection.json", selection)
        return selection, path

    def test_native_record_creator_replays_producers_before_sealing(self):
        selection, path = self.upstream_selection()
        output = self.root / "upstream-record.json"
        def build_verifier(receipt, digest, role):
            self.assertEqual(ref(self.root, receipt.name)["sha256"], digest)
            return json.loads(receipt.read_text()), {}
        with mock.patch.object(index.generic_upstream.isolated_atest, "full_build_verify",
                               side_effect=build_verifier) as build, \
             mock.patch.object(index, "validate_upstream", return_value={}) as replay:
            value, digest = index.create_upstream_record(self.root, path, output)
        self.assertEqual(build.call_count, 2)
        self.assertEqual(replay.call_count, 1)
        self.assertEqual(replay.call_args.kwargs["expected_builds"], selection["builds"])
        self.assertEqual(value["schema"], 2)
        self.assertEqual(value["runs"], selection["runs"])
        self.assertEqual(digest, ref(self.root, output.name)["sha256"])

    def test_native_record_creator_cannot_publish_when_a_native_gate_fails(self):
        _selection, path = self.upstream_selection()
        output = self.root / "upstream-record.json"
        with mock.patch.object(index.generic_upstream.isolated_atest, "full_build_verify",
                               side_effect=lambda receipt, digest, role:
                               (json.loads(receipt.read_text()), {})), \
             mock.patch.object(index, "validate_upstream",
                               side_effect=index.IndexError("native coverage incomplete")):
            with self.assertRaisesRegex(index.IndexError, "native coverage incomplete"):
                index.create_upstream_record(self.root, path, output)
        self.assertFalse(output.exists())

    def test_native_record_creator_rejects_selection_mutation_before_publication(self):
        _selection, path = self.upstream_selection()
        output = self.root / "upstream-record.json"
        def mutate(*args, **kwargs):
            del args, kwargs
            path.write_text("changed selection\n")
            return {}
        with mock.patch.object(index.generic_upstream.isolated_atest, "full_build_verify",
                               side_effect=lambda receipt, digest, role:
                               (json.loads(receipt.read_text()), {})), \
             mock.patch.object(index, "validate_upstream", side_effect=mutate):
            with self.assertRaisesRegex(index.IndexError, "selection changed"):
                index.create_upstream_record(self.root, path, output)
        self.assertFalse(output.exists())

    def defect_register(self, item):
        return {"schema": 1, "kind": index.DEFECT_KIND, "qualification": "production",
                "items": [item],
                "result": "zero_known_critical_high_and_no_untriaged_defects"}

    def test_medium_accepted_defect_requires_owner_and_workaround(self):
        item = {"id": "WONAD_123", "severity": "medium", "status": "accepted",
                "summary": "Known cosmetic limitation", "owner": "desktop-team",
                "workaround": "Reconnect the display", "closure_evidence": []}
        summary = index.validate_defects(self.root, self.defect_register(item))
        self.assertEqual(summary["accepted"], ["WONAD_123"])
        for field in ("owner", "workaround"):
            broken = copy.deepcopy(item); broken[field] = None
            with self.subTest(field=field), self.assertRaisesRegex(index.IndexError, "placeholder"):
                index.validate_defects(self.root, self.defect_register(broken))
        broken = copy.deepcopy(item); broken["workaround"] = "none"
        with self.assertRaisesRegex(index.IndexError, "placeholder"):
            index.validate_defects(self.root, self.defect_register(broken))

    def test_critical_or_high_defect_cannot_be_accepted(self):
        for severity in ("critical", "high"):
            item = {"id": "WONAD_123", "severity": severity, "status": "accepted",
                    "summary": "Blocker", "owner": "owner", "workaround": "none",
                    "closure_evidence": []}
            with self.subTest(severity=severity), self.assertRaisesRegex(index.IndexError, "medium/low"):
                index.validate_defects(self.root, self.defect_register(item))

    def test_resolved_defect_requires_immutable_closure_evidence(self):
        item = {"id": "WONAD_123", "severity": "high", "status": "resolved",
                "summary": "Fixed blocker", "owner": None, "workaround": None,
                "closure_evidence": [ref(self.root, "closure.txt")]}
        self.assertEqual(index.validate_defects(self.root, self.defect_register(item))["ids"],
                         ["WONAD_123"])
        item["closure_evidence"] = []
        with self.assertRaisesRegex(index.IndexError, "closure evidence"):
            index.validate_defects(self.root, self.defect_register(item))

    def test_open_defect_status_is_rejected(self):
        item = {"id": "WONAD_123", "severity": "low", "status": "open",
                "summary": "Untriaged", "owner": "owner", "workaround": "workaround",
                "closure_evidence": []}
        with self.assertRaisesRegex(index.IndexError, "untriaged"):
            index.validate_defects(self.root, self.defect_register(item))

    def test_review_requires_every_scope_exact_bindings_and_defects(self):
        bindings = {name: "a" * 64 for name in index.REVIEW_BINDING_KEYS}
        bindings["source_difference_proof"] = None
        value = {"schema": 1, "kind": index.REVIEW_KIND, "qualification": "production",
                 "decision": "approved", "reviewers": [{"name": "Reviewer", "role": "OS glue"}],
                 "scopes": sorted(index.REQUIRED_REVIEW_SCOPES),
                 "evidence_sha256": bindings, "defect_ids": ["WONAD_123"],
                 "report": ref(self.root, "review.md")}
        self.assertEqual(index.validate_review(
            self.root, value, bindings, ["WONAD_123"])["decision"], "approved")
        for mutation in ("scope", "binding", "defect"):
            broken = copy.deepcopy(value)
            if mutation == "scope": broken["scopes"].pop()
            elif mutation == "binding": broken["evidence_sha256"]["client_record"] = "b" * 64
            else: broken["defect_ids"] = []
            with self.subTest(mutation=mutation), self.assertRaisesRegex(index.IndexError, "does not cover"):
                index.validate_review(self.root, broken, bindings, ["WONAD_123"])
        broken = copy.deepcopy(value); broken["reviewers"][0]["name"] = "TBD"
        with self.assertRaisesRegex(index.IndexError, "placeholder"):
            index.validate_review(self.root, broken, bindings, ["WONAD_123"])


class SourceDifferenceTests(unittest.TestCase):
    def receipt(self, signer, marker_extra=None, target="x86"):
        marker = {
            "schema": 4, "signer_sha256": signer,
            "signer_certificate": {"path": "WonadReleaseCertificate.der",
                                   "sha256": signer, "size": 1000},
            "files": {
                "WonadReleaseCertificate.der": signer,
                "WonadSigning.kt": signer,
                "generated-res/values/wonad_signer.xml": signer,
                "common.txt": "9" * 64,
            },
            "patches": {"frameworks_base": [{"name": "one.patch", "sha256": "8" * 64}]},
        }
        if marker_extra:
            marker.update(marker_extra)
        identity = {
            "release": index.RELEASE,
            "lock": {"sha256": "1" * 64, "size": 1},
            "manifest_commit": "2" * 40, "manifest_tag_object": "3" * 40,
            "default_xml": {"sha256": "4" * 64, "size": 1},
            "project_count": 1, "project_ledger_sha256": "5" * 64,
        }
        source = {"pin": identity, "worktree_materializations_sha256": "6" * 64}
        if target == "x86":
            source["stage"] = {"state": "schema-4-owned-stage", "qualification":
                "emulator-development-only", "marker": marker,
                "development_certificate": {"der_sha256": signer}}
        else:
            source["stage"] = {"state": "schema-4-with-project-updater", "marker": marker,
                               "signer": {"der_sha256": signer}, "updater": {"schema": 1}}
        return {"role": "custom", "source": source}

    def test_exact_signer_only_difference_produces_proof(self):
        value = index.expected_source_proof(
            self.receipt("a" * 64), {"path": "x", "sha256": "b" * 64, "size": 1},
            self.receipt("c" * 64, target="arm"),
            {"path": "a", "sha256": "d" * 64, "size": 2})
        self.assertEqual(value["result"], "passed_exhaustive_signer_only_source_difference")
        self.assertEqual(set(value["x86_custom_receipt"]), {"sha256", "size"})

    def test_non_signer_stage_difference_is_rejected(self):
        arm = self.receipt("c" * 64, {"new_privileged_patch": True}, target="arm")
        with self.assertRaisesRegex(index.IndexError, "outside signer-generated"):
            index.expected_source_proof(
                self.receipt("a" * 64), {"sha256": "b" * 64, "size": 1}, arm,
                {"sha256": "d" * 64, "size": 2})

    def test_project_or_materialization_difference_is_rejected(self):
        arm = self.receipt("c" * 64, target="arm")
        arm["source"]["worktree_materializations_sha256"] = "7" * 64
        with self.assertRaisesRegex(index.IndexError, "source/project/materialization"):
            index.expected_source_proof(
                self.receipt("a" * 64), {"sha256": "b" * 64, "size": 1}, arm,
                {"sha256": "d" * 64, "size": 2})

    def test_same_signer_forbids_difference_proof(self):
        with self.assertRaisesRegex(index.IndexError, "forbidden"):
            index.expected_source_proof(
                self.receipt("a" * 64), {"sha256": "b" * 64, "size": 1},
                self.receipt("a" * 64, target="arm"), {"sha256": "d" * 64, "size": 2})


class RuntimeBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wonad-phase1-runtime-binding-")
        self.root = Path(self.temporary.name).resolve()
        self.signer = "1" * 64
        self.xreceipt = {"fingerprint": "fingerprint", "source": {"pin": {"release": "pin"}}}
        self.refs = {}
        for name in ("baseline_receipt", "custom_receipt", "comparison"):
            path = self.root / (name + ".json")
            path.write_text(name + "\n")
            self.refs[name] = ref(self.root, path.name)
        self.plan = {"image": {"manifest": {"value": {"phase1_build_evidence": {
            **{name: {"expected_sha256": row["sha256"],
                      "file": {"sha256": row["sha256"], "size": row["size"]}}
               for name, row in self.refs.items()},
            "client_packet": {"development_only": True, "runtime_qualified": False,
                              "staged_signer_der_sha256": self.signer},
            "source_pin_sha256": index.canonical_digest(self.xreceipt["source"]["pin"]),
            "shared_fingerprint": "fingerprint", "qualification_claimed": False,
        }}}}}
        self.write_bound("inputs.json", self.plan)
        self.write_bound("qualification.json", {"qualified": True})
        admission = {"inputs": self.bound("inputs.json"),
                     "qualification": self.bound("qualification.json"),
                     "image_id": "sha256:" + "a" * 64}
        self.write_bound("admission.json", admission)
        self.write_bound("evidence-index.json", {"records": [
            {"identity": {"run": "%032x" % ordinal,
                          "boot_id": "%08x-0000-0000-0000-%012x" % (ordinal, ordinal),
                          "container": "%064x" % ordinal}}
            for ordinal in range(1, 5)]})
        self.result = {"admission": self.bound("admission.json"),
                       "evidence_index": self.bound("evidence-index.json")}
        write_json(self.root / "result.json", self.result)

    def tearDown(self):
        self.temporary.cleanup()

    def write_bound(self, name, value):
        write_json(self.root / name, value)

    def bound(self, name):
        payload = (self.root / name).read_bytes()
        return {"path": str(self.root / name), "sha256": hashlib.sha256(payload).hexdigest()}

    def verify(self):
        return index.runtime_embedded_binding(
            self.root, self.root / "result.json", self.refs, self.xreceipt, self.signer)

    def test_embedded_records_are_authenticated_and_confined(self):
        value = self.verify()
        self.assertEqual(value["admission"]["path"], "admission.json")
        self.assertEqual(value["candidate_image"], "sha256:" + "a" * 64)
        self.assertEqual(len(value["guests"]), 4)

    def test_absolute_bound_record_outside_evidence_root_is_rejected(self):
        outside = self.root.parent / (self.root.name + "-outside.json")
        try:
            write_json(outside, {"outside": True})
            payload = outside.read_bytes()
            self.result["admission"] = {"path": str(outside),
                "sha256": hashlib.sha256(payload).hexdigest()}
            write_json(self.root / "result.json", self.result)
            with self.assertRaisesRegex(index.IndexError, "outside"):
                self.verify()
        finally:
            outside.unlink(missing_ok=True)

    def test_manifest_file_identity_cannot_differ_from_expected_digest(self):
        self.plan["image"]["manifest"]["value"]["phase1_build_evidence"][
            "custom_receipt"]["file"]["sha256"] = "0" * 64
        self.write_bound("inputs.json", self.plan)
        admission = json.loads((self.root / "admission.json").read_text())
        admission["inputs"] = self.bound("inputs.json")
        self.write_bound("admission.json", admission)
        self.result["admission"] = self.bound("admission.json")
        write_json(self.root / "result.json", self.result)
        with self.assertRaisesRegex(index.IndexError, "different x86 custom_receipt"):
            self.verify()


class FreshConformanceCrossBindingTests(unittest.TestCase):
    def setUp(self):
        self.signer = "1" * 64
        self.packet_ref = {"sha256": "2" * 64, "size": 200}
        self.receipt = {
            "schema": 2,
            "kind": "phase1_source_matched_x86_development_client_packet_v1",
            "status": "compile_qualified_development_packet_not_runtime_qualified",
            "development_only": True, "runtime_qualified": False,
            "successor": {
                "build_receipt": {"sha256": "3" * 64, "bytes": 300},
                "source_freeze": {"sha256": "4" * 64, "bytes": 400},
                "input_conformance": {"sha256": "5" * 64, "bytes": 500},
            },
            "artifacts": {
                "conformance": {"payload_sha256": "6" * 64,
                                "certificate_der_sha256": self.signer},
                "wonad": {"certificate_der_sha256": self.signer},
            },
        }
        self.client = {
            "source_receipt": {"sha256": "3" * 64, "size": 300},
            "source_freeze": {"identity": {"sha256": "4" * 64, "size": 400}},
            "conformance": {
                "unsigned_apk": {"sha256": "5" * 64, "size": 500},
                # Production provenance and development packet payload hashes
                # use deliberately different normalized schemas.
                "payload_sha256": "7" * 64,
            },
        }
        self.api = {"container": "%064x" % 11, "boot_id": self.boot(11),
                    "container_run": "%032x" % 11, "run": "%032x" % 12,
                    "userdata_retained_path": "/evidence/api/state"}
        self.recents_report = {"userdata_retained_path": "/evidence/recents/state"}
        self.recents = {"container_id": "%064x" % 12, "boot_id": self.boot(12),
                        "run": "%032x" % 13, "recents_run": "%032x" % 14,
                        "conformance_run": "%032x" % 15}
        self.campaign = [{"run": "%032x" % ordinal, "boot_id": self.boot(ordinal),
                          "container": "%064x" % ordinal}
                         for ordinal in range(1, 5)]

    @staticmethod
    def boot(value):
        return "%08x-0000-0000-0000-%012x" % (value, value)

    def test_packet_binds_the_production_compile_but_keeps_development_signer(self):
        value = index.validate_development_packet_binding(
            self.receipt, self.packet_ref, self.client, self.signer)
        self.assertEqual("3" * 64, value["compile_receipt_sha256"])
        self.assertEqual(self.signer, value["development_signer_sha256"])

    def test_packet_compile_unsigned_and_signer_substitutions_fail(self):
        mutations = []
        changed = copy.deepcopy(self.receipt)
        changed["successor"]["build_receipt"]["sha256"] = "0" * 64
        mutations.append(changed)
        changed = copy.deepcopy(self.receipt)
        changed["successor"]["input_conformance"]["sha256"] = "0" * 64
        mutations.append(changed)
        changed = copy.deepcopy(self.receipt)
        changed["artifacts"]["wonad"]["certificate_der_sha256"] = "0" * 64
        mutations.append(changed)
        for ordinal, changed in enumerate(mutations):
            with self.subTest(ordinal=ordinal), self.assertRaises(index.IndexError):
                index.validate_development_packet_binding(
                    changed, self.packet_ref, self.client, self.signer)

    def test_all_api_recents_and_campaign_identities_are_distinct(self):
        value = index.validate_fresh_identity_separation(
            self.api, self.recents_report, self.recents, self.campaign)
        self.assertEqual({"runs": 9, "boots": 6, "containers": 6, "userdata": "distinct"},
                         value)

    def test_reused_run_boot_container_or_userdata_fails(self):
        mutations = []
        recents = copy.deepcopy(self.recents); recents["run"] = self.api["run"]
        mutations.append((self.api, self.recents_report, recents, self.campaign))
        recents = copy.deepcopy(self.recents); recents["boot_id"] = self.campaign[0]["boot_id"]
        mutations.append((self.api, self.recents_report, recents, self.campaign))
        recents = copy.deepcopy(self.recents); recents["container_id"] = self.api["container"]
        mutations.append((self.api, self.recents_report, recents, self.campaign))
        report = {"userdata_retained_path": self.api["userdata_retained_path"]}
        mutations.append((self.api, report, self.recents, self.campaign))
        for ordinal, arguments in enumerate(mutations):
            with self.subTest(ordinal=ordinal), self.assertRaisesRegex(
                    index.IndexError, "reused"):
                index.validate_fresh_identity_separation(*arguments)


class ConformancePublicationBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="wonad-phase1-conformance-publication-")
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def test_raw_evidence_substitution_after_audit_is_rejected(self):
        evidence = self.root / "api"; evidence.mkdir()
        raw = evidence / "commands.json"; raw.write_bytes(b"reviewed raw commands\n")
        records = {"commands.json": {
            "sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
            "bytes": raw.stat().st_size}}
        accepted = index.declared_evidence_set(
            self.root, evidence, records, "fresh API evidence set")
        self.assertEqual(1, accepted["file_count"])
        raw.write_bytes(b"substituted after semantic auditor returned\n")
        with self.assertRaisesRegex(index.IndexError, "changed after independent replay"):
            index.declared_evidence_set(
                self.root, evidence, records, "fresh API evidence set")

    def test_product_substitution_after_audit_is_rejected(self):
        product = self.root / "product"; product.mkdir()
        image = product / "system-qemu.img"; image.write_bytes(b"exact product image")
        digest = hashlib.sha256(image.read_bytes()).hexdigest()
        value = index.product_identity(
            self.root, "product", {"base": True}, {image.name: digest}, {})
        self.assertEqual(1, value["file_count"])
        image.write_bytes(b"substituted product image")
        with self.assertRaisesRegex(index.IndexError, "selected product changed"):
            index.product_identity(
                self.root, "product", {"base": True}, {image.name: digest}, {})

    def test_packet_tree_and_all_five_publication_identities_are_reviewed(self):
        packet = self.root / "packet"; packet.mkdir()
        (packet / "receipt.json").write_bytes(b"receipt\n")
        before = index.packet_tree_binding(self.root, "packet")
        (packet / "wonad.apk").write_bytes(b"substituted packet payload\n")
        after = index.packet_tree_binding(self.root, "packet")
        self.assertNotEqual(before["sha256"], after["sha256"])
        self.assertTrue({
            "conformance_packet_tree", "conformance_product_identity",
            "conformance_api_evidence_set", "conformance_recents_guest_evidence_set",
            "conformance_recents_child_evidence_set",
        } <= index.REVIEW_BINDING_KEYS)
        self.assertEqual(44, len(index.REVIEW_BINDING_KEYS))


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wonad-phase1-operations-")
        self.root = Path(self.temporary.name).resolve()
        (self.root / "runbook.md").write_bytes(index.OPERATIONS_RUNBOOK.read_bytes())
        write_json(self.root / "ceremony.json", {"public": True})
        self.source = {"lock_sha256": "1" * 64}
        self.pair = {"pair": {"predecessor": {"number": "2026100600"},
                              "successor": {"number": "2026100601"}}}
        owner = lambda role: {"name": role + " team", "contact": "mailto:" + role + "@wonad.dev"}
        self.value = {
            "schema": 1, "kind": index.OPERATIONS_KIND, "qualification": "production",
            "release": index.RELEASE, "product": index.PRODUCT, "source": self.source,
            "candidate": {"channel": "candidate", "status":
                "private_flashable_candidate_not_production_or_hardware_qualified",
                "update_url": "https://updates.wonad.dev/releases/",
                "predecessor_build": "2026100600", "successor_build": "2026100601"},
            "ownership": {role: owner(role) for role in index.OWNER_ROLES},
            "publication": {"artifact_base_url": "https://downloads.wonad.dev/candidate/",
                "metadata_base_url": "https://updates.wonad.dev/releases/",
                "release_index_digest_url": "https://wonad.dev/releases/index/",
                "failure_communication_url": "https://wonad.dev/status/",
                "signed_ota_metadata": True, "release_pair_and_endpoint_receipts": True,
                "public_trust_anchors_separately_published": True,
                "out_of_band_index_sha256_required": True,
                "offline_verification_before_publication": True},
            "rollout": {"mode": "private_allowlisted_candidate", "production_enabled": False,
                "approval_gate": "phase2_exact_hash_physical_pixel10_qualification",
                "promotion_owner": "release", "withdrawal_owner": "withdrawal",
                "withdrawal_action":
                    "remove_signed_metadata_and_artifacts_then_publish_signed_notice"},
            "maintenance": {"security_monitoring_urls": ["https://grapheneos.org/releases/"],
                "security_review_cadence_days": 7, "rebase_decision_cadence_days": 14,
                "rebase_policy":
                    "each_grapheneos_security_release_is_triaged_and_required_os_changes_reenter_phase1"},
            "change_control": {
                "os_privileged_interface_or_signer_change":
                    "requires_new_phase1_and_phase2_qualification",
                "ordinary_apk_only_change":
                    "may_ship_independently_only_when_api_os_trust_policy_and_signer_are_unchanged"},
            "runbook": ref(self.root, "runbook.md"),
            "signing_ceremony": ref(self.root, "ceremony.json"),
            "physical_rollback": {"tested": False, "qualification_phase": "Phase 2",
                                  "claim": "procedural_guidance_only_untested_until_phase2"},
            "result": "complete_private_candidate_channel_and_handoff_operations",
        }

    def tearDown(self):
        self.temporary.cleanup()

    def validate(self, value=None):
        return index.validate_operations(
            self.root, value or self.value, self.source, self.pair,
            {"update_url": "https://updates.wonad.dev/releases/"},
            ref(self.root, "ceremony.json"))

    def test_complete_private_candidate_operations_are_accepted(self):
        result = self.validate()
        self.assertFalse(result["production_enabled"])

    def test_example_or_grapheneos_update_endpoint_is_rejected(self):
        for url in ("https://updates.example.invalid/", "https://releases.grapheneos.org/",
                    "https://localhost/", "https://192.168.1.2/", "https://singlelabel/"):
            broken = copy.deepcopy(self.value)
            broken["candidate"]["update_url"] = url
            with self.subTest(url=url), self.assertRaises(index.IndexError):
                index.validate_operations(self.root, broken, self.source, self.pair,
                                          {"update_url": url}, ref(self.root, "ceremony.json"))

    def test_production_rollout_or_physical_rollback_claim_is_rejected(self):
        broken = copy.deepcopy(self.value); broken["rollout"]["production_enabled"] = True
        with self.assertRaisesRegex(index.IndexError, "rollout"):
            self.validate(broken)
        broken = copy.deepcopy(self.value); broken["physical_rollback"]["tested"] = True
        with self.assertRaisesRegex(index.IndexError, "overclaims"):
            self.validate(broken)

    def test_owner_and_security_cadence_cannot_be_implicit(self):
        broken = copy.deepcopy(self.value); broken["ownership"]["release"]["name"] = "TBD"
        with self.assertRaisesRegex(index.IndexError, "placeholder"):
            self.validate(broken)
        broken = copy.deepcopy(self.value); broken["maintenance"]["security_review_cadence_days"] = 30
        with self.assertRaisesRegex(index.IndexError, "cadence"):
            self.validate(broken)

    def test_publication_endpoint_and_reviewed_runbook_are_exact(self):
        broken = copy.deepcopy(self.value)
        broken["publication"]["metadata_base_url"] = "https://metadata.wonad.dev/releases/"
        with self.assertRaisesRegex(index.IndexError, "endpoint/authenticity"):
            self.validate(broken)
        (self.root / "runbook.md").write_text("substituted instructions\n")
        broken = copy.deepcopy(self.value); broken["runbook"] = ref(self.root, "runbook.md")
        with self.assertRaisesRegex(index.IndexError, "reviewed repository runbook"):
            self.validate(broken)


class SigningCeremonyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wonad-phase1-ceremony-")
        self.root = Path(self.temporary.name).resolve()
        (self.root / "policy.md").write_bytes(index.SIGNING_POLICY.read_bytes())
        for name in ("preflight.json", "postflight.json", "restore.json",
                     "pair.json", "avb.bin", "factory.pub"):
            (self.root / name).write_text(name + "\n")
        self.certificate_rows = {}
        for role in sorted(index.OS_SIGNER_ROLES | {"wonad"}):
            path = self.root / (role + ".x509.pem")
            path.write_text("public certificate " + role + "\n")
            payload = path.read_bytes()
            self.certificate_rows[role] = {
                "algorithm": "RSA-4096", "certificate": ref(self.root, path.name),
                "der_sha256": hashlib.sha256(b"DER:" + payload).hexdigest(),
                "der_size": 512, "subject": "subject=" + role,
            }
        self.source = {"lock_sha256": "1" * 64}
        self.pair = {"pair": {"predecessor": {"number": "2026100600"},
                              "successor": {"number": "2026100601"}}}
        self.release_refs = {
            "release_pair_receipt": ref(self.root, "pair.json"),
            "avb_public_key": ref(self.root, "avb.bin"),
            "ota_certificate": self.certificate_rows["releasekey"]["certificate"],
            "factory_public_key": ref(self.root, "factory.pub"),
        }
        operator = {"name": "release operator", "contact": "mailto:release@wonad.dev"}
        custodian = {"name": "key custodian", "contact": "mailto:custodian@wonad.dev"}
        independent = {"name": "independent verifier", "contact": "mailto:verify@wonad.dev"}
        for filename, category, observer, observed in (
                ("preflight.json", "preflight", operator, "2026-10-10T10:10:00Z"),
                ("postflight.json", "postflight", independent, "2026-10-10T11:50:00Z"),
                ("restore.json", "backup_restore", custodian, "2026-10-10T11:55:00Z")):
            write_json(self.root / filename, {
                "schema": 1, "kind": index.CUSTODY_OBSERVATION_KIND,
                "qualification": "production", "release": index.RELEASE,
                "product": index.PRODUCT, "category": category,
                "observed_utc": observed, "observer": observer,
                "predecessor_build": "2026100600", "successor_build": "2026100601",
                "release_pair_sha256": self.release_refs["release_pair_receipt"]["sha256"],
                "wonad_signer_sha256": self.certificate_rows["wonad"]["der_sha256"],
                "controls": index.CUSTODY_CONTROLS[category],
                "result": "passed_observed_signing_custody_controls",
            })
        self.value = {
            "schema": 1, "kind": index.CEREMONY_KIND, "qualification": "production",
            "release": index.RELEASE, "product": index.PRODUCT, "source": self.source,
            "predecessor_build": "2026100600", "successor_build": "2026100601",
            "started_utc": "2026-10-10T10:00:00Z", "ended_utc": "2026-10-10T12:00:00Z",
            "release_operator": operator,
            "key_custodian": custodian,
            "independent_verifier": independent,
            "policy": ref(self.root, "policy.md"),
            "custody": {"offline_host": True, "networking_disabled": True,
                "swap_disabled": True, "hibernation_disabled": True,
                "core_dumps_disabled": True,
                "private_material_outside_source_build_and_evidence": True,
                "locked_ram_temporary_material_removed": True,
                "two_geographic_encrypted_backups": True,
                "build_container_removed_before_signing": True,
                "independent_verification_host": True,
                "preflight_evidence": [ref(self.root, "preflight.json")],
                "postflight_evidence": [ref(self.root, "postflight.json")],
                "backup_restore_evidence": [ref(self.root, "restore.json")]},
            "identities": {"os_certificates": {
                    role: self.certificate_rows[role] for role in index.OS_SIGNER_ROLES},
                "wonad": self.certificate_rows["wonad"],
                "avb": {"algorithm": "RSA-4096", "public": ref(self.root, "avb.bin")},
                "factory": {"algorithm": "Ed25519", "public": ref(self.root, "factory.pub")}},
            "tools": {name: index.stable_ref(path, name, reject_private=False)["sha256"]
                      for name, path in sorted(index.CEREMONY_TOOLS.items())},
            "result": "passed_protected_key_ceremony_and_public_verification",
        }

    def tearDown(self):
        self.temporary.cleanup()

    def public_certificate(self, path, expected_file, label):
        payload = Path(path).read_bytes()
        role = Path(path).name.split(".x509.pem", 1)[0]
        return {"file": {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)},
                "der_sha256": hashlib.sha256(b"DER:" + payload).hexdigest(),
                "der_size": 512, "subject": "subject=" + role, "algorithm": "RSA-4096"}

    def validate(self, value=None, production_signer=None, signer_ref=None):
        value = value or self.value
        production_signer = production_signer or self.certificate_rows["wonad"]["der_sha256"]
        signer_ref = signer_ref or self.certificate_rows["wonad"]["certificate"]
        with mock.patch.object(index, "public_certificate_snapshot", side_effect=self.public_certificate):
            return index.validate_signing_ceremony(
                self.root, value, self.source, self.pair, production_signer,
                self.release_refs, signer_ref)

    def test_structured_ceremony_cross_binds_public_identities_and_custody(self):
        result = self.validate()
        self.assertEqual(result["os_signer_count"], 9)

    def test_wonad_identity_cannot_alias_an_os_signer(self):
        broken = copy.deepcopy(self.value)
        broken["identities"]["wonad"] = copy.deepcopy(
            broken["identities"]["os_certificates"]["platform"])
        platform = self.certificate_rows["platform"]
        for field, filename in (("preflight_evidence", "preflight.json"),
                                ("postflight_evidence", "postflight.json"),
                                ("backup_restore_evidence", "restore.json")):
            observation = json.loads((self.root / filename).read_text())
            observation["wonad_signer_sha256"] = platform["der_sha256"]
            write_json(self.root / filename, observation)
            broken["custody"][field] = [ref(self.root, filename)]
        with self.assertRaisesRegex(index.IndexError, "aliased"):
            self.validate(broken, platform["der_sha256"], platform["certificate"])

    def test_prose_policy_without_observed_custody_evidence_is_rejected(self):
        broken = copy.deepcopy(self.value); broken["custody"]["preflight_evidence"] = []
        with self.assertRaisesRegex(index.IndexError, "lacks preflight"):
            self.validate(broken)

    def test_arbitrary_prose_is_not_custody_observation(self):
        (self.root / "preflight.json").write_text("we followed the policy\n")
        broken = copy.deepcopy(self.value)
        broken["custody"]["preflight_evidence"] = [ref(self.root, "preflight.json")]
        with self.assertRaisesRegex(index.IndexError, "Invalid JSON"):
            self.validate(broken)

    def test_custody_observation_must_bind_release_and_observer(self):
        observation = json.loads((self.root / "postflight.json").read_text())
        observation["release_pair_sha256"] = "0" * 64
        write_json(self.root / "postflight.json", observation)
        broken = copy.deepcopy(self.value)
        broken["custody"]["postflight_evidence"] = [ref(self.root, "postflight.json")]
        with self.assertRaisesRegex(index.IndexError, "exact public observation"):
            self.validate(broken)

    def test_public_avb_identity_must_match_verified_release_pair(self):
        broken = copy.deepcopy(self.value)
        (self.root / "other-avb.bin").write_text("other\n")
        broken["identities"]["avb"]["public"] = ref(self.root, "other-avb.bin")
        with self.assertRaisesRegex(index.IndexError, "verified release trust anchor"):
            self.validate(broken)

    def test_reviewed_ceremony_policy_is_immutable(self):
        (self.root / "policy.md").write_text("substituted policy\n")
        broken = copy.deepcopy(self.value); broken["policy"] = ref(self.root, "policy.md")
        with self.assertRaisesRegex(index.IndexError, "reviewed repository policy"):
            self.validate(broken)


class SignedSourceBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wonad-phase1-signed-source-")
        self.root = Path(self.temporary.name).resolve()
        self.release = self.root / "releases/2/release-frankel-2"
        (self.release / "wonad-provenance").mkdir(parents=True)
        self.receipt_path = self.release / "release-receipt.json"
        self.receipt_path.write_text("{}\n")
        self.projects = [{"path": "frameworks/base", "name": "platform_frameworks_base",
                          "revision": "1" * 40, "remote": "grapheneos"}]
        self.materializations = {"frameworks/base": {
            "gitlinks": {}, "materialized_eol": {}, "materialized_lfs": {}}}
        self.pin = {"lock": {"sha256": "2" * 64, "size": 1},
                    "manifest_commit": "3" * 40, "manifest_tag_object": "4" * 40,
                    "default_xml": {"sha256": "5" * 64, "size": 1},
                    "projects": self.projects, "project_count": 1,
                    "project_ledger_sha256": index.canonical_digest(self.projects)}
        self.arm = {"source": {"pin": self.pin,
            "owned_tracked_changes": {"owned": {"sha256": "6" * 64, "size": 1, "mode": 420}},
            "generated_inputs": {"generated": {"sha256": "7" * 64, "size": 1, "mode": 420}},
            "worktree_materializations": self.materializations,
            "worktree_materializations_sha256": index.canonical_digest(self.materializations)}}
        self.source_record = {"lock": self.pin["lock"],
            "manifest": {"commit": self.pin["manifest_commit"],
                         "tag_object": self.pin["manifest_tag_object"],
                         "default_xml": self.pin["default_xml"], "projects": self.projects,
                         "project_count": 1,
                         "project_ledger_sha256": self.pin["project_ledger_sha256"]},
            "owned_tracked_changes": self.arm["source"]["owned_tracked_changes"],
            "generated_inputs": self.arm["source"]["generated_inputs"],
            "generated_inputs_sha256": index.canonical_digest(
                self.arm["source"]["generated_inputs"]),
            "source_audit": {"projects": {"frameworks/base": {
                "config": {}, "gitlinks": {}, "materialized_eol": {},
                "materialized_lfs": {}}}}}
        self.source_path = self.release / "wonad-provenance/source-provenance.json"
        write_json(self.source_path, self.source_record)
        reference = index.stable_ref(self.source_path, "unused", reject_private=False)
        self.pair = {"paths": {"successor": self.receipt_path}, "successor": {
            "phase1_provenance": {"source_record": {
                "sha256": reference["sha256"], "size": reference["size"],
                "manifest_commit": self.pin["manifest_commit"], "project_count": 1,
                "project_ledger_sha256": self.pin["project_ledger_sha256"]}}}}

    def tearDown(self):
        self.temporary.cleanup()

    def verify(self, pair=None, arm=None):
        with mock.patch.object(index.provenance, "validate_source_record_shape",
                               side_effect=lambda value: value):
            return index.validate_signed_source_binding(
                self.root, pair or self.pair, arm or self.arm)

    def test_complete_signed_source_state_is_bound(self):
        result = self.verify()
        self.assertEqual(result["worktree_materializations_sha256"],
                         self.arm["source"]["worktree_materializations_sha256"])

    def test_generated_input_substitution_is_rejected(self):
        arm = copy.deepcopy(self.arm)
        arm["source"]["generated_inputs"]["generated"]["sha256"] = "8" * 64
        with self.assertRaisesRegex(index.IndexError, "generated-input"):
            self.verify(arm=arm)

    def test_materialization_substitution_is_rejected(self):
        arm = copy.deepcopy(self.arm)
        arm["source"]["worktree_materializations"]["frameworks/base"]["gitlinks"] = {
            "submodule": {"mode": "160000"}}
        with self.assertRaisesRegex(index.IndexError, "materializations"):
            self.verify(arm=arm)

    def test_source_provenance_outside_evidence_root_is_rejected(self):
        outside = Path(self.temporary.name).parent / (self.root.name + "-outside")
        try:
            (outside / "wonad-provenance").mkdir(parents=True)
            receipt = outside / "release-receipt.json"; receipt.write_text("{}\n")
            pair = copy.deepcopy(self.pair); pair["paths"]["successor"] = receipt
            with self.assertRaisesRegex(index.IndexError, "outside"):
                self.verify(pair=pair)
        finally:
            import shutil
            shutil.rmtree(outside, ignore_errors=True)

    def test_symlinked_signed_source_provenance_is_rejected(self):
        outside = self.root.parent / (self.root.name + "-source.json")
        try:
            outside.write_bytes(self.source_path.read_bytes())
            self.source_path.unlink()
            self.source_path.symlink_to(outside)
            with self.assertRaisesRegex(index.IndexError, "symlink"):
                self.verify()
        finally:
            outside.unlink(missing_ok=True)


class AggregateFixture(unittest.TestCase):
    """Exercise create/verify and the cross-bindings with semantic producers mocked.

    The producer implementations have their own large test suites.  These tests
    deliberately mock only the expensive replay boundary and retain real file,
    schema, signer, source, review and defect binding logic here.
    """

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wonad-phase1-index-e2e-")
        self.root = Path(self.temporary.name).resolve()
        (self.root / "sdk").mkdir()
        (self.root / "product").mkdir()
        (self.root / "dev-packet").mkdir()
        (self.root / "sdk/artifact.aar").write_bytes(b"sdk")
        for name in ("api-contract.md", "xbase.json", "xcustom.json", "xcompare.json",
                     "runtime.json", "abase.json", "acustom.json", "acompare.json",
                     "pair.json", "avb.pub", "ota.x509.pem", "factory.pub", "otatools.json",
                     "client.json", "client-source.json", "conformance.apk", "signer.x509.pem",
                     "apksigner", "gh-b.log", "gh-c.log", "ah-b.log", "ah-c.log",
                     "ae-b.log", "ae-c.log", "review.md", "up-base.json", "up-custom.json",
                     "up-atest.json", "ceremony.json", "operations.json", "runtime-admission.json",
                     "runtime-inputs.json", "runtime-qualification.json", "runtime-index.json"):
            (self.root / name).write_bytes((name + "\n").encode())
        for name in ("api-conformance.json", "recents-conformance.json",
                     "recents-child.json"):
            (self.root / name).write_bytes((name + "\n").encode())
        write_json(self.root / "dev-packet/receipt.json", {"packet": "development"})
        (self.root / "api-contract.md").write_bytes(
            (ROOT / "android/EXTERNAL-SHELL.md").read_bytes())
        (self.root / "grapheneos.lock.json").write_bytes(
            (ROOT / "android/grapheneos.lock.json").read_bytes())
        (self.root / "upstream-plan.json").write_bytes(index.UPSTREAM_PLAN.read_bytes())
        (self.root / "runbook.md").write_bytes(index.OPERATIONS_RUNBOOK.read_bytes())
        (self.root / "signing-policy.md").write_bytes(index.SIGNING_POLICY.read_bytes())
        self.dev_signer, self.prod_signer = "1" * 64, "2" * 64
        self.marker_x = self.marker(self.dev_signer)
        self.marker_a = self.marker(self.prod_signer)
        self.shared = {"lock_sha256": ref(self.root, "grapheneos.lock.json")["sha256"],
            "manifest_commit": "3" * 40, "manifest_tag_object": "4" * 40,
            "default_xml_sha256": "5" * 64, "project_count": 1057,
            "project_ledger_sha256": "6" * 64,
            "worktree_materializations_sha256": "7" * 64}
        self.xbase = self.build_receipt("baseline", "x86")
        self.xcustom = self.build_receipt("custom", "x86")
        self.abase = self.build_receipt("baseline", "arm")
        self.acustom = self.build_receipt("custom", "arm")
        write_json(self.root / "xbase.json", self.xbase)
        write_json(self.root / "xcustom.json", self.xcustom)
        write_json(self.root / "abase.json", self.abase)
        write_json(self.root / "acustom.json", self.acustom)

        self.client = {
            "qualification": "production", "coordinate": index.SDK_COORDINATE,
            "public_signer": {"der_sha256": self.prod_signer},
            "conformance": {"apk": {"sha256": ref(self.root, "conformance.apk")["sha256"],
                                        "size": ref(self.root, "conformance.apk")["size"]}},
            "sdk_publication": {"files": {"artifact.aar": {
                "sha256": hashlib.sha256(b"sdk").hexdigest(), "size": 3, "mode": 0o644}}},
            "source_freeze": {"files_sha256": "8" * 64},
        }
        write_json(self.root / "client.json", self.client)
        self.client_ref = ref(self.root, "client.json")

        self.proof = index.expected_source_proof(
            self.xcustom, ref(self.root, "xcustom.json"),
            self.acustom, ref(self.root, "acustom.json"))
        write_json(self.root / "source-proof.json", self.proof)
        self.upstream = self.upstream_record()
        write_json(self.root / "upstream.json", self.upstream)
        self.defects = {"schema": 1, "kind": index.DEFECT_KIND,
                        "qualification": "production", "items": [],
                        "result": "zero_known_critical_high_and_no_untriaged_defects"}
        write_json(self.root / "defects.json", self.defects)
        write_json(self.root / "ceremony.json", {})
        write_json(self.root / "operations.json", {})
        self.review = self.review_record()
        write_json(self.root / "review.json", self.review)
        self.assembly = self.assembly_record()
        write_json(self.root / "phase1-assembly.json", self.assembly)

    def tearDown(self):
        self.temporary.cleanup()

    def marker(self, signer):
        return {"schema": 4, "signer_sha256": signer,
                "signer_certificate": {"path": "WonadReleaseCertificate.der",
                                       "sha256": signer, "size": 1000},
                "files": {"WonadReleaseCertificate.der": signer,
                          "WonadSigning.kt": signer,
                          "generated-res/values/wonad_signer.xml": signer,
                          "common": "9" * 64},
                "patches": {"frameworks_base": [{"name": "patch", "sha256": "a" * 64}]}}

    def build_receipt(self, role, target):
        pin = {"lock": {"sha256": self.shared["lock_sha256"]},
               "manifest_commit": self.shared["manifest_commit"],
               "manifest_tag_object": self.shared["manifest_tag_object"],
               "default_xml": {"sha256": self.shared["default_xml_sha256"]},
               "project_count": self.shared["project_count"],
               "project_ledger_sha256": self.shared["project_ledger_sha256"]}
        source = {"pin": pin, "worktree_materializations_sha256":
                  self.shared["worktree_materializations_sha256"]}
        if role == "baseline": source["stage"] = {"state": "absent"}
        elif target == "x86":
            source["stage"] = {"state": "schema-4-owned-stage", "marker": self.marker_x,
                "development_certificate": {"der_sha256": self.dev_signer},
                "qualification": "emulator-development-only"}
        else:
            source["stage"] = {"state": "schema-4-with-project-updater", "marker": self.marker_a,
                "signer": {"der_sha256": self.prod_signer}, "updater": {"schema": 1}}
        value = {"role": role, "source": source}
        value["build_contract" if target == "x86" else "contract"] = (
            {"target_arch": "x86_64"} if target == "x86" else {"abi": "arm64-v8a"})
        return value

    def upstream_record(self):
        runs = []
        for prefix, category in (("gh", "grapheneos_host"), ("ah", "aosp_host"),
                                 ("ae", "aosp_emulator")):
            runs.append({"name": prefix, "class": category, "test_plan": ["test", prefix],
                "baseline": {"exit_code": 0, "failures": [],
                             "report": ref(self.root, prefix + "-b.log")},
                "custom": {"exit_code": 0, "failures": [],
                           "report": ref(self.root, prefix + "-c.log")},
                "new_failures": [], "attributable_failures": []})
        return {"schema": 1, "kind": index.UPSTREAM_KIND, "qualification": "production",
                "source": self.shared, "runs": runs,
                "result": "passed_no_new_patch_attributable_failures"}

    def review_record(self):
        refs = {
            "grapheneos_lock": ref(self.root, "grapheneos.lock.json"),
            "api_contract": ref(self.root, "api-contract.md"),
            "x86_baseline_receipt": ref(self.root, "xbase.json"),
            "x86_custom_receipt": ref(self.root, "xcustom.json"),
            "x86_comparison": ref(self.root, "xcompare.json"),
            "runtime_result": ref(self.root, "runtime.json"),
            "arm_baseline_receipt": ref(self.root, "abase.json"),
            "arm_custom_receipt": ref(self.root, "acustom.json"),
            "arm_comparison": ref(self.root, "acompare.json"),
            "release_pair": ref(self.root, "pair.json"),
            "avb_public_key": ref(self.root, "avb.pub"),
            "ota_certificate": ref(self.root, "ota.x509.pem"),
            "factory_public_key": ref(self.root, "factory.pub"),
            "trusted_otatools_manifest": ref(self.root, "otatools.json"),
            "client_record": self.client_ref,
            "client_source_receipt": ref(self.root, "client-source.json"),
            "conformance_apk": ref(self.root, "conformance.apk"),
            "signer_certificate": ref(self.root, "signer.x509.pem"),
            "apksigner": ref(self.root, "apksigner"),
            "upstream_regression": ref(self.root, "upstream.json"),
            "upstream_atest_comparison": ref(self.root, "up-atest.json"),
            "upstream_test_plan": ref(self.root, "upstream-plan.json"),
            "upstream_baseline_run": ref(self.root, "up-base.json"),
            "upstream_custom_run": ref(self.root, "up-custom.json"),
            "production_operations": ref(self.root, "operations.json"),
            "operations_runbook": ref(self.root, "runbook.md"),
            "signing_ceremony": ref(self.root, "ceremony.json"),
            "signing_policy": ref(self.root, "signing-policy.md"),
            "runtime_admission": ref(self.root, "runtime-admission.json"),
            "runtime_inputs": ref(self.root, "runtime-inputs.json"),
            "runtime_qualification": ref(self.root, "runtime-qualification.json"),
            "runtime_evidence_index": ref(self.root, "runtime-index.json"),
            "conformance_packet_receipt": ref(self.root, "dev-packet/receipt.json"),
            "conformance_api_report": ref(self.root, "api-conformance.json"),
            "conformance_recents_report": ref(self.root, "recents-conformance.json"),
            "conformance_recents_child_report": ref(self.root, "recents-child.json"),
            "conformance_packet_tree": {"sha256": "1" * 64},
            "conformance_product_identity": {"sha256": "2" * 64},
            "conformance_api_evidence_set": {"sha256": "3" * 64},
            "conformance_recents_guest_evidence_set": {"sha256": "4" * 64},
            "conformance_recents_child_evidence_set": {"sha256": "5" * 64},
            "defects": ref(self.root, "defects.json"),
        }
        sdk_files = {"artifact.aar": {"sha256": hashlib.sha256(b"sdk").hexdigest(), "size": 3}}
        return {"schema": 1, "kind": index.REVIEW_KIND, "qualification": "production",
                "decision": "approved", "reviewers": [{"name": "Reviewer", "role": "OS glue"}],
                "scopes": sorted(index.REQUIRED_REVIEW_SCOPES),
                "evidence_sha256": index.review_bindings(
                    refs, index.canonical_digest(sdk_files), ref(self.root, "source-proof.json")),
                "defect_ids": [], "report": ref(self.root, "review.md")}

    def assembly_record(self):
        return {"schema": 1, "kind": index.ASSEMBLY_KIND, "qualification": "production",
            "grapheneos_lock": "grapheneos.lock.json", "api_contract": "api-contract.md",
            "x86": {"baseline_receipt": "xbase.json", "custom_receipt": "xcustom.json",
                    "comparison": "xcompare.json", "runtime_result": "runtime.json"},
            "arm": {"baseline_receipt": "abase.json", "custom_receipt": "acustom.json",
                    "comparison": "acompare.json", "release_pair_receipt": "pair.json",
                    "avb_public_key": "avb.pub", "ota_certificate": "ota.x509.pem",
                    "factory_public_key": "factory.pub", "trusted_otatools_manifest": "otatools.json",
                    "trusted_otatools_manifest_sha256": ref(self.root, "otatools.json")["sha256"]},
            "clients": {"record": "client.json", "sdk_publication": "sdk",
                        "conformance_apk": "conformance.apk", "source_receipt": "client-source.json",
                        "signer_certificate": "signer.x509.pem", "apksigner": "apksigner"},
            "conformance_acceptance": {"product": "product", "client_packet": "dev-packet",
                "api_report": "api-conformance.json", "recents_report": "recents-conformance.json"},
            "source_difference_proof": "source-proof.json",
            "upstream_regression": "upstream.json",
            "upstream_atest_comparison": "up-atest.json",
            "upstream_test_plan": "upstream-plan.json",
            "upstream_baseline_run": "up-base.json", "upstream_custom_run": "up-custom.json",
            "production_operations": "operations.json", "signing_ceremony": "ceremony.json",
            "review": "review.json",
            "defects": "defects.json"}

    def pair_bound(self):
        predecessor = {"build": {"number": "2026100600", "timestamp": 1791288000}}
        successor = {"grapheneos_lock": {"sha256": self.shared["lock_sha256"]},
            "wonad_stage": self.marker_a, "updater_stage": {"schema": 1},
            "apk_signer_sha256": self.prod_signer,
            "build": {"number": "2026100601", "timestamp": 1791288001},
            "phase1_provenance": {"client_record": {
                "sha256": self.client_ref["sha256"], "size": self.client_ref["size"],
                "signer_sha256": self.prod_signer,
                "conformance_apk_sha256": self.client["conformance"]["apk"]["sha256"],
                "sdk_publication_sha256": index.canonical_digest(
                    self.client["sdk_publication"]["files"]),
                "source_freeze_sha256": self.client["source_freeze"]["files_sha256"]}}}
        return {"pair": {
            "predecessor": {"number": predecessor["build"]["number"],
                            "build": copy.deepcopy(predecessor["build"])},
            "successor": {"number": successor["build"]["number"],
                          "build": copy.deepcopy(successor["build"])}},
            "predecessor": predecessor, "successor": successor}

    def patches(self):
        return mock.patch.multiple(
            index,
            load_lock=mock.DEFAULT,
            runtime_embedded_binding=mock.DEFAULT,
        )

    def semantic_patches(self):
        stack = ExitStack()
        stack.enter_context(mock.patch.object(index, "load_lock", return_value={
            "release": index.RELEASE, "device": index.PRODUCT,
            "production_target": {"product": index.PRODUCT}}))
        stack.enter_context(mock.patch.object(index.x86, "verify_comparison", return_value={}))
        stack.enter_context(mock.patch.object(index.frankel, "verify_comparison", return_value={}))
        stack.enter_context(mock.patch.object(index.runtime, "verify_result", return_value={
            "runtime_qualification": "passed", "production_acceptance": "passed",
            "candidate_image": "sha256:" + "b" * 64, "boots": 4, "soak_rounds": 3}))
        stack.enter_context(mock.patch.object(index, "runtime_embedded_binding", return_value={
            "candidate_image": "sha256:" + "b" * 64, "x86_evidence_embedded": True,
            "development_signer_sha256": self.dev_signer,
            "admission": ref(self.root, "runtime-admission.json"),
            "inputs": ref(self.root, "runtime-inputs.json"),
            "qualification": ref(self.root, "runtime-qualification.json"),
            "evidence_index": ref(self.root, "runtime-index.json"),
            "guests": [{"run": "%032x" % ordinal,
                        "boot_id": "%08x-0000-0000-0000-%012x" % (ordinal, ordinal),
                        "container": "%064x" % ordinal} for ordinal in range(1, 5)]}))
        stack.enter_context(mock.patch.object(index.verify_release_pair, "verify", return_value={
            "schema": 1, "status": "verified", "target": "frankel-user"}))
        stack.enter_context(mock.patch.object(index.release_pair_receipt, "verify_pair_receipt",
                                              return_value=self.pair_bound()))
        stack.enter_context(mock.patch.object(index, "validate_signed_source_binding", return_value={
            "source_provenance": {"path": "release/source.json", "sha256": "c" * 64, "size": 1},
            "project_ledger_sha256": self.shared["project_ledger_sha256"],
            "worktree_materializations_sha256": self.shared["worktree_materializations_sha256"],
            "generated_inputs_sha256": "d" * 64}))
        stack.enter_context(mock.patch.object(index.provenance, "validate_clients_shape",
                                              side_effect=lambda value: value))
        stack.enter_context(mock.patch.object(index.provenance, "collect_clients",
                                              return_value=self.client))
        stack.enter_context(mock.patch.object(index, "validate_conformance_acceptance",
            return_value=({"candidate_image": "sha256:" + "e" * 64,
                           "base_image": "sha256:" + "b" * 64,
                           "fingerprint": "test/fingerprint"}, {
                "conformance_packet_receipt": ref(self.root, "dev-packet/receipt.json"),
                "conformance_api_report": ref(self.root, "api-conformance.json"),
                "conformance_recents_report": ref(self.root, "recents-conformance.json"),
                "conformance_recents_child_report": ref(self.root, "recents-child.json"),
                "conformance_packet_tree": {"sha256": "1" * 64},
                "conformance_product_identity": {"sha256": "2" * 64},
                "conformance_api_evidence_set": {"sha256": "3" * 64},
                "conformance_recents_guest_evidence_set": {"sha256": "4" * 64},
                "conformance_recents_child_evidence_set": {"sha256": "5" * 64},
            })))
        stack.enter_context(mock.patch.object(index, "validate_upstream", return_value={
            "runs": 3, "cases": 3, "classes": sorted(index.REQUIRED_UPSTREAM_CLASSES),
            "result": "passed_no_new_patch_attributable_failures"}))
        plan = json.loads(index.UPSTREAM_PLAN.read_text())

        def upstream_run(path, _digest):
            role = "baseline" if Path(path).name == "up-base.json" else "custom"
            receipt = ref(self.root, "xbase.json" if role == "baseline" else "xcustom.json")
            return {"role": role, "build": {"receipt": receipt}, "plan": plan,
                    "plan_sha256": index.canonical_digest(plan)}

        stack.enter_context(mock.patch.object(index.upstream_tests, "authenticated_run",
                                              side_effect=upstream_run))
        stack.enter_context(mock.patch.object(index.upstream_tests, "verify_comparison", return_value={
            "architecture": "x86_64", "status": "passed", "new_or_worsened_failures": [],
            "source_pin_sha256": index.canonical_digest(self.xcustom["source"]["pin"]),
            "suites": {"wmtests": {"cases": 100}}}))
        stack.enter_context(mock.patch.object(index, "validate_signing_ceremony", return_value={
            "result": "passed_protected_key_ceremony_and_public_verification",
            "started_utc": "2026-10-10T10:00:00Z", "ended_utc": "2026-10-10T11:00:00Z",
            "policy": ref(self.root, "signing-policy.md"), "custody_reports": [],
            "wonad_signer_sha256": self.prod_signer, "os_signer_count": 9}))
        stack.enter_context(mock.patch.object(index, "validate_operations", return_value={
            "channel": "candidate", "update_url": "https://updates.wonad.test.invalid/",
            "production_enabled": False, "runbook": ref(self.root, "runbook.md"),
            "result": "complete_private_candidate_channel_and_handoff_operations"}))
        return stack

    def test_create_and_verify_full_aggregate(self):
        with self.semantic_patches():
            value, digest = index.create(self.root, self.root / "phase1-assembly.json",
                                         self.root / "phase1-release-index.json")
            self.assertEqual(value["exit_gate"]["result"],
                             "passed_phase1_flashable_candidate_evidence_freeze")
            verified = index.verify(self.root, self.root / "phase1-release-index.json", digest)
        self.assertEqual(verified, value)

    def test_index_hash_is_mandatory_and_authenticated(self):
        with self.semantic_patches():
            _value, digest = index.create(self.root, self.root / "phase1-assembly.json",
                                          self.root / "phase1-release-index.json")
            with self.assertRaisesRegex(index.IndexError, "out-of-band"):
                index.verify(self.root, self.root / "phase1-release-index.json", "bad")
            with self.assertRaisesRegex(index.IndexError, "differs"):
                index.verify(self.root, self.root / "phase1-release-index.json", "0" * 64)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_different_signers_without_source_proof_fail(self):
        self.assembly["source_difference_proof"] = None
        write_json(self.root / "phase1-assembly.json", self.assembly)
        with self.semantic_patches(), self.assertRaisesRegex(index.IndexError, "require an exhaustive"):
            index.collect(self.root, self.root / "phase1-assembly.json")

    def test_runtime_must_be_production_24_hour_acceptance(self):
        with self.semantic_patches() as _stack, \
                mock.patch.object(index.runtime, "verify_result", return_value={
                    "runtime_qualification": "passed", "production_acceptance": "not_passed",
                    "candidate_image": "sha256:" + "b" * 64, "boots": 4, "soak_rounds": 3}), \
                self.assertRaisesRegex(index.IndexError, "24-hour soak"):
            index.collect(self.root, self.root / "phase1-assembly.json")

    def test_signed_release_must_bundle_exact_client_record(self):
        broken = self.pair_bound()
        broken["successor"]["phase1_provenance"]["client_record"]["sha256"] = "0" * 64
        with self.semantic_patches(), \
                mock.patch.object(index.release_pair_receipt, "verify_pair_receipt", return_value=broken), \
                self.assertRaisesRegex(index.IndexError, "selected production client"):
            index.collect(self.root, self.root / "phase1-assembly.json")

    def validate_release_bindings(self, pair):
        client = copy.deepcopy(self.client)
        client["_reference"] = self.client_ref
        return index.validate_release_cross_bindings(
            pair, self.acustom, client, {"sha256": self.shared["lock_sha256"]})

    def test_strictly_increasing_ota_dates_preserve_direct_cross_bindings(self):
        self.assertEqual(self.validate_release_bindings(self.pair_bound()), self.prod_signer)

    def test_equal_or_regressed_ota_dates_are_rejected(self):
        for offset in (0, -1):
            broken = self.pair_bound()
            timestamp = broken["predecessor"]["build"]["timestamp"] + offset
            broken["successor"]["build"]["timestamp"] = timestamp
            broken["pair"]["successor"]["build"]["timestamp"] = timestamp
            with self.subTest(offset=offset), self.assertRaisesRegex(index.IndexError, "OTA"):
                self.validate_release_bindings(broken)

    def test_missing_or_nonpositive_or_noninteger_ota_dates_are_rejected(self):
        for location in ("full", "pair"):
            for role in ("predecessor", "successor"):
                for invalid in (None, True, False, 0, -1, 1791288001.0, "1791288001"):
                    broken = self.pair_bound()
                    build = (broken[role]["build"] if location == "full" else
                             broken["pair"][role]["build"])
                    if invalid is None:
                        del build["timestamp"]
                    else:
                        build["timestamp"] = invalid
                    with self.subTest(location=location, role=role, invalid=invalid), \
                            self.assertRaisesRegex(index.IndexError, "OTA"):
                        self.validate_release_bindings(broken)

    def test_pair_ota_dates_and_endpoint_labels_must_match_full_receipts(self):
        for role in ("predecessor", "successor"):
            for field in ("timestamp", "number", "embedded_number", "full_number"):
                broken = self.pair_bound()
                other = "successor" if role == "predecessor" else "predecessor"
                if field == "timestamp":
                    broken["pair"][role]["build"]["timestamp"] += 1
                elif field == "number":
                    broken["pair"][role]["number"] = broken[other]["build"]["number"]
                elif field == "embedded_number":
                    broken["pair"][role]["build"]["number"] = broken[other]["build"]["number"]
                else:
                    broken[role]["build"]["number"] = broken[other]["build"]["number"]
                with self.subTest(role=role, field=field), \
                        self.assertRaisesRegex(index.IndexError, "OTA"):
                    self.validate_release_bindings(broken)

    def test_equal_ota_dates_are_rejected_before_later_semantic_collection(self):
        broken = self.pair_bound()
        timestamp = broken["predecessor"]["build"]["timestamp"]
        broken["successor"]["build"]["timestamp"] = timestamp
        broken["pair"]["successor"]["build"]["timestamp"] = timestamp
        with self.semantic_patches(), \
                mock.patch.object(index.release_pair_receipt, "verify_pair_receipt",
                                  return_value=broken), \
                mock.patch.object(index, "validate_signed_source_binding") as signed_source, \
                mock.patch.object(index.provenance, "collect_clients") as clients:
            with self.assertRaisesRegex(index.IndexError, "OTA"):
                index.collect(self.root, self.root / "phase1-assembly.json")
            signed_source.assert_not_called()
            clients.assert_not_called()

    def test_review_cannot_approve_different_evidence(self):
        self.review["evidence_sha256"]["runtime_result"] = "0" * 64
        write_json(self.root / "review.json", self.review)
        with self.semantic_patches(), self.assertRaisesRegex(index.IndexError, "does not cover"):
            index.collect(self.root, self.root / "phase1-assembly.json")

    def test_production_client_record_is_recomputed_not_merely_hashed(self):
        different = copy.deepcopy(self.client)
        different["coordinate"] = "org.wonad:desktop-sdk:4.0.0"
        with self.semantic_patches(), \
                mock.patch.object(index.provenance, "collect_clients", return_value=different), \
                self.assertRaisesRegex(index.IndexError, "differs from its immutable"):
            index.collect(self.root, self.root / "phase1-assembly.json")

    def test_unreviewed_upstream_plan_is_rejected_even_if_comparator_claims_pass(self):
        plan = json.loads((self.root / "upstream-plan.json").read_text())
        plan["release"] = "2026100601"
        write_json(self.root / "upstream-plan.json", plan)
        with self.semantic_patches(), self.assertRaisesRegex(index.IndexError, "reviewed release plan"):
            index.collect(self.root, self.root / "phase1-assembly.json")

    def test_upstream_run_cannot_substitute_another_build_receipt(self):
        plan = json.loads(index.UPSTREAM_PLAN.read_text())

        def substituted(path, _digest):
            role = "baseline" if Path(path).name == "up-base.json" else "custom"
            receipt = ref(self.root, "xbase.json")
            return {"role": role, "build": {"receipt": receipt}, "plan": plan,
                    "plan_sha256": index.canonical_digest(plan)}

        with self.semantic_patches(), \
                mock.patch.object(index.upstream_tests, "authenticated_run",
                                  side_effect=substituted), \
                self.assertRaisesRegex(index.IndexError, "different x86 build receipt"):
            index.collect(self.root, self.root / "phase1-assembly.json")

    def test_atest_comparison_cannot_hide_a_new_failure(self):
        broken = {"architecture": "x86_64", "status": "passed",
                  "new_or_worsened_failures": [{"case": "bad"}],
                  "source_pin_sha256": index.canonical_digest(self.xcustom["source"]["pin"]),
                  "suites": {"wmtests": {"cases": 100}}}
        with self.semantic_patches(), \
                mock.patch.object(index.upstream_tests, "verify_comparison", return_value=broken), \
                self.assertRaisesRegex(index.IndexError, "not a same-pin passing"):
            index.collect(self.root, self.root / "phase1-assembly.json")

    def test_verifier_bytes_cannot_change_during_collection(self):
        before = index.tool_ledger()
        after = copy.deepcopy(before)
        after["phase1_release_index"]["sha256"] = "0" * 64
        with self.semantic_patches(), \
                mock.patch.object(index, "tool_ledger", side_effect=[before, after]), \
                self.assertRaisesRegex(index.IndexError, "changed during"):
            index.collect(self.root, self.root / "phase1-assembly.json")


if __name__ == "__main__":
    unittest.main()
