import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ANDROID = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_release_pair", ANDROID / "tools/verify_release_pair.py")
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)

OLD = "2026101000"
NEW = "2026101001"


def digest(path):
    data = path.read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


class PairVerification(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        releases = self.root / "releases"
        old_dir = releases / OLD / f"release-frankel-{OLD}"
        new_dir = releases / NEW / f"release-frankel-{NEW}"
        old_dir.mkdir(parents=True)
        new_dir.mkdir(parents=True)
        self.old_receipt = old_dir / "release-receipt.json"
        self.new_receipt = new_dir / "release-receipt.json"
        self.old_receipt.write_text("old receipt\n")
        self.new_receipt.write_text("new receipt\n")
        self.delta = releases / NEW / f"frankel-incremental-{OLD}-{NEW}.zip"
        with zipfile.ZipFile(self.delta, "w") as archive:
            archive.writestr("META-INF/com/android/metadata", "ota-type=AB\n")
            archive.writestr("payload.bin", b"incremental payload")
            archive.writestr("payload_properties.txt", b"FILE_HASH=fixture\n")
        self.pair_receipt = releases / NEW / f"frankel-incremental-{OLD}-{NEW}-receipt.json"
        self.pair_receipt.write_text("authenticated pair receipt\n")
        self.avb = self.root / "avb_pkmd.bin"
        self.ota = self.root / "releasekey.x509.pem"
        self.factory = self.root / "factory.pub"
        self.manifest = self.root / "trusted-otatools.json"
        for path, data in ((self.avb, b"public avb"), (self.ota, b"public ota cert"),
                           (self.factory, b"public factory key"),
                           (self.manifest, b"trusted tools")):
            path.write_bytes(data)
        self.signature_tool = new_dir / "bin/check_ota_package_signature"
        self.signature_tool.parent.mkdir()
        self.signature_tool.write_text("#!/bin/sh\nexit 0\n")
        self.signature_tool.chmod(0o755)
        anchors = {
            "avb": {"sha256": "a" * 64, "size": 1032, "path": str(self.avb)},
            "ota": {"sha256": "b" * 64, "size": 512, "path": str(self.ota)},
            "factory": {"sha256": "c" * 64, "size": 80, "path": str(self.factory)},
        }
        self.evidence = {
            OLD: {"status": "verified", "build": OLD, "public_trust_anchors": anchors},
            NEW: {"status": "verified", "build": NEW, "public_trust_anchors": anchors},
        }
        self.pair = {
            "predecessor": {"number": OLD, "receipt": {"sha256": digest(self.old_receipt)["sha256"]}},
            "successor": {"number": NEW, "receipt": {"sha256": digest(self.new_receipt)["sha256"]}},
            "incremental_ota": {
                "path": f"{NEW}/{self.delta.name}", **digest(self.delta),
                "metadata": {
                    "ota-type": "AB", "pre-device": "frankel",
                    "pre-build": f"fingerprint/{OLD}", "pre-build-incremental": OLD,
                    "post-build": f"fingerprint/{NEW}", "post-build-incremental": NEW,
                    "post-timestamp": "1791633600",
                    "post_datetime_utc": "2026-10-10T12:00:00+00:00",
                },
            },
        }
        self.bound = {
            "pair": self.pair,
            "paths": {"predecessor": self.old_receipt, "successor": self.new_receipt,
                      "incremental": self.delta, "pair": self.pair_receipt},
            "predecessor": {"build": {"number": OLD}},
            "successor": {"build": {"number": NEW}, "files": {}},
        }
        self.calls = []

    def runner(self, argv, **kwargs):
        self.calls.append(([str(value) for value in argv], kwargs))
        return SimpleNamespace(returncode=0, stdout=b"verified\n", stderr=b"")

    def run_verify(self, artifact_side_effect=None, runner=None):
        def full_artifact(_receipt, _avb, _ota, _factory, expected, *_args, **_kwargs):
            build = OLD if expected == self.pair["predecessor"]["receipt"]["sha256"] else NEW
            return self.evidence[build]

        with patch.object(verify.release_pair_receipt, "verify_pair_receipt",
                          return_value=self.bound), \
                patch.object(verify.verify_release_artifacts, "verify",
                             side_effect=artifact_side_effect or full_artifact) as artifact, \
                patch.object(verify.verify_release_artifacts, "trusted_tool_identities",
                             return_value={"check_ota_package_signature": {}}), \
                patch.object(verify.verify_release_artifacts, "resolve_tools",
                             return_value=(
                                 {"check_ota_package_signature": self.signature_tool},
                                 {"check_ota_package_signature": {
                                     "path": "bin/check_ota_package_signature",
                                     **digest(self.signature_tool)}})):
            result = verify.verify(
                self.pair_receipt, self.avb, self.ota, self.factory,
                digest(self.pair_receipt)["sha256"], self.manifest,
                digest(self.manifest)["sha256"], runner=runner or self.runner)
            return result, artifact

    def test_pair_digest_is_authenticated_before_json_parsing_or_tool_execution(self):
        with patch.object(verify.release_pair_receipt, "verify_pair_receipt",
                          side_effect=AssertionError("untrusted pair parsed")):
            with self.assertRaisesRegex(
                    verify.verify_release_artifacts.VerificationError,
                    "pair receipt SHA-256"):
                verify.verify(self.pair_receipt, self.avb, self.ota, self.factory,
                              "0" * 64, self.manifest,
                              digest(self.manifest)["sha256"], runner=self.runner)
        self.assertFalse(self.calls)

    def test_both_full_endpoints_and_incremental_signatures_are_verified(self):
        result, artifact = self.run_verify()
        self.assertEqual("verified", result["status"])
        self.assertEqual(OLD, result["predecessor"]["build"])
        self.assertEqual(NEW, result["successor"]["build"])
        self.assertEqual(2, artifact.call_count)
        expected_digests = [call.args[4] for call in artifact.call_args_list]
        self.assertEqual([
            self.pair["predecessor"]["receipt"]["sha256"],
            self.pair["successor"]["receipt"]["sha256"],
        ], expected_digests)
        signature = self.calls[-1]
        self.assertEqual("check_ota_package_signature", Path(signature[0][0]).name)
        self.assertEqual(self.ota.resolve(), Path(signature[0][1]))
        self.assertEqual(self.delta.resolve(), Path(signature[0][2]))
        self.assertIn("incremental_whole_file_and_payload_signatures", result["checks"])

    def test_failure_of_either_endpoint_is_never_downgraded(self):
        def reject(_receipt, _avb, _ota, _factory, expected, *_args, **_kwargs):
            if expected == self.pair["successor"]["receipt"]["sha256"]:
                raise verify.verify_release_artifacts.VerificationError("bad successor AVB")
            return self.evidence[OLD]

        with self.assertRaisesRegex(verify.PairVerificationError, "Successor.*bad successor AVB"):
            self.run_verify(artifact_side_effect=reject)
        self.assertFalse(self.calls)

    def test_endpoints_must_verify_under_the_same_public_key_lineage(self):
        different = json.loads(json.dumps(self.evidence[NEW]))
        different["public_trust_anchors"]["ota"]["sha256"] = "0" * 64
        self.evidence[NEW] = different
        with self.assertRaisesRegex(verify.PairVerificationError, "one public signing lineage"):
            self.run_verify()
        self.assertFalse(self.calls)

    def test_unsafe_or_incomplete_incremental_archive_fails_before_signature_tool(self):
        with zipfile.ZipFile(self.delta, "w") as archive:
            archive.writestr("META-INF/com/android/metadata", "ota-type=AB\n")
            archive.writestr("payload.bin", b"payload without properties")
        with self.assertRaisesRegex(verify.PairVerificationError, "missing.*payload_properties"):
            self.run_verify()
        self.assertFalse(self.calls)

    def test_official_signature_failure_is_fatal(self):
        def reject(_argv, **_kwargs):
            raise verify.verify_release_artifacts.VerificationError("payload signature rejected")

        with self.assertRaisesRegex(verify.PairVerificationError,
                                    "payload signature rejected"):
            self.run_verify(runner=reject)


if __name__ == "__main__":
    unittest.main()
