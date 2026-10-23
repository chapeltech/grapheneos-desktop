import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ANDROID = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("stage_os", ANDROID / "platform/stage-os.py")
stage_os = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage_os)
SIGNER = "12" * 32
REVISION = json.loads((ANDROID / "grapheneos.lock.json").read_text())["frameworks_base"]["commit"]
LAUNCHER_REVISION = json.loads((ANDROID / "grapheneos.lock.json").read_text())["launcher3"]["commit"]
EMULATOR_REVISION = json.loads((ANDROID / "grapheneos.lock.json").read_text())[
    "emulator_goldfish"]["commit"]


class StageSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)
        (self.source / ".repo").mkdir()
        (self.source / "external").mkdir()
        self.target = self.source / "external/wonad"
        self.certificate = Path(self.temp.name) / "wonad-release.x509.pem"
        self.certificate.write_text("fixture public certificate\n")
        def head(args, **_):
            value = str(args)
            if "packages/apps/Launcher3" in value:
                return LAUNCHER_REVISION + "\n"
            if "device/generic/goldfish" in value:
                return EMULATOR_REVISION + "\n"
            return REVISION + "\n"
        self.head = patch.object(stage_os.subprocess, "check_output", side_effect=head)
        self.git = patch.object(stage_os, "framework_plan", return_value=[])
        self.target_hashes = patch.object(stage_os, "target_hashes", return_value={"fixture": "34" * 32})
        self.verify_targets = patch.object(stage_os, "verify_targets")
        self.certificate_identity = patch.object(
            stage_os, "certificate_identity", return_value=(SIGNER, b"fixture DER certificate" * 8))
        self.head.start()
        self.calls = self.git.start()
        self.target_hashes.start()
        self.verify_targets.start()
        self.certificate_identity.start()
        self.addCleanup(self.head.stop)
        self.addCleanup(self.git.stop)
        self.addCleanup(self.target_hashes.stop)
        self.addCleanup(self.verify_targets.stop)
        self.addCleanup(self.certificate_identity.stop)

    def stage(self):
        stage_os.stage(self.source, self.certificate)

    def test_explicit_public_pin_and_idempotent_owned_updates(self):
        self.stage()
        before = (self.target / ".wonad-stage.json").read_bytes()
        times = {str(p): p.stat().st_mtime_ns for p in self.target.rglob("*") if p.is_file()}
        self.stage()
        self.assertEqual(times, {str(p): p.stat().st_mtime_ns for p in self.target.rglob("*") if p.is_file()})
        self.assertEqual(before, (self.target / ".wonad-stage.json").read_bytes())
        self.assertIn(SIGNER, (self.target / "WonadSigning.kt").read_text())
        signer_resource = self.target / "generated-res/values/wonad_signer.xml"
        self.assertIn(SIGNER, signer_resource.read_text())
        self.assertEqual(
            json.loads(before)["files"]["generated-res/values/wonad_signer.xml"],
            stage_os.digest(signer_resource),
        )
        self.assertEqual(LAUNCHER_REVISION, json.loads(before)["launcher3_revision"])
        self.assertEqual(EMULATOR_REVISION, json.loads(before)["emulator_goldfish_revision"])
        self.assertEqual(4, json.loads(before)["schema"])
        self.assertGreater(len(json.loads(before)["files"]), 15)

    def test_invalid_signer_certificate_does_not_touch_checkout(self):
        with patch.object(stage_os, "certificate_identity",
                          side_effect=ValueError("invalid public certificate")):
            for value in ("", "missing.pem", self.source):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    stage_os.stage(self.source, value)
        self.assertFalse(self.target.exists())
        self.calls.assert_not_called()

    def test_incompatible_sdk_is_refused_before_os_mutation(self):
        with patch.object(stage_os.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 1, stdout="wire declarations changed", stderr="")):
            with self.assertRaisesRegex(ValueError, "SDK contract review required"):
                self.stage()
        self.assertFalse(self.target.exists())
        self.calls.assert_not_called()

    def test_wrong_framework_pin_refused_before_mutation(self):
        with patch.object(stage_os.subprocess, "check_output", return_value="wrong\n"):
            with self.assertRaisesRegex(ValueError, "revision"):
                self.stage()
        self.assertFalse(self.target.exists())

    def test_wrong_launcher_pin_refused_before_mutation(self):
        with patch.object(stage_os.subprocess, "check_output", side_effect=lambda args, **_: (
                "wrong" if "packages/apps/Launcher3" in str(args) else REVISION) + "\n"):
            with self.assertRaisesRegex(ValueError, "Launcher3 revision"):
                self.stage()
        self.assertFalse(self.target.exists())

    def test_wrong_goldfish_pin_refused_before_mutation(self):
        def head(args, **_):
            value = str(args)
            if "packages/apps/Launcher3" in value:
                return LAUNCHER_REVISION + "\n"
            if "device/generic/goldfish" in value:
                return "wrong\n"
            return REVISION + "\n"
        with patch.object(stage_os.subprocess, "check_output", side_effect=head):
            with self.assertRaisesRegex(ValueError, "Goldfish revision"):
                self.stage()
        self.assertFalse(self.target.exists())

    def test_existing_unowned_directory_is_preserved(self):
        self.target.mkdir()
        note = self.target / "unrelated"
        note.write_text("keep me")
        with self.assertRaisesRegex(ValueError, "unowned"):
            self.stage()
        self.assertEqual("keep me", note.read_text())

    def test_edited_owned_file_is_preserved(self):
        self.stage()
        edited = self.target / "WonadSigning.kt"
        edited.write_text("independent change")
        with self.assertRaisesRegex(ValueError, "independently changed"):
            self.stage()
        self.assertEqual("independent change", edited.read_text())

    def test_foreign_symlink_directory_is_preserved(self):
        self.stage()
        link = self.target / "foreign"
        link.symlink_to(self.source, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlinked"):
            self.stage()
        self.assertTrue(link.is_symlink())

    def test_independently_modified_framework_patch_targets_refused(self):
        self.calls.side_effect = ValueError("Preserving independently modified framework integration files")
        with self.assertRaisesRegex(ValueError, "independently modified"):
            self.stage()
        self.assertFalse(self.target.exists())


class FrameworkPatches(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)
        self.frameworks = self.source / "frameworks"
        self.frameworks.mkdir()
        self.file = self.frameworks / "hook.java"
        self.file.write_text("before\nhook\nafter\n")
        for args in (("init", "-q"), ("add", "."),
                     ("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                      "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")):
            subprocess.run(["git", "-C", str(self.frameworks), *args], check=True, capture_output=True)
        self.patches = [self.source / (str(i) + ".patch") for i in range(2)]
        self.patches[0].write_text("--- a/hook.java\n+++ b/hook.java\n@@ -1,3 +1,4 @@\n before\n hook\n+first\n after\n")
        self.patches[1].write_text("--- a/hook.java\n+++ b/hook.java\n@@ -2,3 +2,4 @@\n hook\n first\n+second\n after\n")

    def test_new_framework_test_file_is_owned_and_idempotent(self):
        addition = self.source / "new.patch"
        addition.write_text("--- /dev/null\n+++ b/tests/new.kt\n@@ -0,0 +1 @@\n+test\n")
        target = self.frameworks / "tests/new.kt"
        self.assertEqual([(target, None, b"test\n")], stage_os.framework_plan(self.frameworks, [addition]))
        target.parent.mkdir()
        target.write_bytes(b"test\n")
        self.assertEqual([], stage_os.framework_plan(self.frameworks, [addition]))
        target.write_bytes(b"foreign edit\n")
        with self.assertRaisesRegex(ValueError, "independently modified"):
            stage_os.framework_plan(self.frameworks, [addition])
        self.assertEqual(b"foreign edit\n", target.read_bytes())

    def test_new_framework_file_preserves_foreign_symlink(self):
        addition = self.source / "new.patch"
        addition.write_text("--- /dev/null\n+++ b/tests/new.kt\n@@ -0,0 +1 @@\n+test\n")
        (self.frameworks / "tests").symlink_to(self.source, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlinked"):
            stage_os.framework_plan(self.frameworks, [addition])

    def test_pristine_prefix_and_complete_patches(self):
        for prefix in range(3):
            plan = stage_os.framework_plan(self.frameworks, self.patches)
            if prefix < 2:
                self.assertEqual([(self.file, self.file.read_bytes(), b"before\nhook\nfirst\nsecond\nafter\n")], plan)
                subprocess.run(["git", "-C", str(self.frameworks), "apply", str(self.patches[prefix])], check=True)
            else:
                self.assertEqual([], plan)

    def test_independent_edit_after_owned_patch_is_preserved(self):
        subprocess.run(["git", "-C", str(self.frameworks), "apply", str(self.patches[0])], check=True)
        self.file.write_text(self.file.read_text() + "independent\n")
        before = self.file.read_bytes()
        with self.assertRaisesRegex(ValueError, "independently modified"):
            stage_os.framework_plan(self.frameworks, self.patches)
        self.assertEqual(before, self.file.read_bytes())

    def test_post_stage_target_hashes_reject_direct_byte_tampering(self):
        plan = stage_os.framework_plan(self.frameworks, self.patches)
        targets = stage_os.target_hashes(self.frameworks, self.patches, plan)
        with self.assertRaisesRegex(ValueError, "differs from its stage marker"):
            stage_os.verify_targets(self.frameworks, targets, "fixture")
        for patch_file in self.patches:
            subprocess.run(["git", "-C", str(self.frameworks), "apply", str(patch_file)],
                           check=True, capture_output=True)
        stage_os.verify_targets(self.frameworks, targets, "fixture")
        self.file.write_bytes(self.file.read_bytes() + b"post-stage tamper\n")
        with self.assertRaisesRegex(ValueError, "differs from its stage marker"):
            stage_os.verify_targets(self.frameworks, targets, "fixture")

    def test_symlink_is_not_followed(self):
        target = self.source / "unrelated"
        self.file.rename(target)
        self.file.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlinked"):
            stage_os.framework_plan(self.frameworks, self.patches)
        self.assertTrue(self.file.is_symlink())
        self.assertEqual("before\nhook\nafter\n", target.read_text())


@unittest.skipUnless(shutil.which("openssl"), "openssl is required by release staging")
class SignerCertificate(unittest.TestCase):
    def certificate(self, directory, common_name):
        private = Path(directory) / "private"
        private.mkdir()
        key = private / "private-key.pem"
        certificate = Path(directory) / "public.x509.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-subj", f"/CN={common_name}", "-keyout", str(key), "-out", str(certificate),
                        "-days", "1"], check=True, capture_output=True, timeout=30)
        return certificate, key

    def test_der_digest_is_derived_from_a_valid_public_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.mkdir()
            certificate, _ = self.certificate(directory, "Wonad Release")
            identity, der = stage_os.certificate_identity(certificate, source)
            self.assertEqual(64, len(identity))
            self.assertEqual(stage_os.hashlib.sha256(der).hexdigest(), identity)

    def test_debug_subject_and_private_material_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.mkdir()
            certificate, _ = self.certificate(directory, "Android Debug")
            with self.assertRaisesRegex(ValueError, "debug/test"):
                stage_os.certificate_identity(certificate, source)
            certificate.write_text("-----BEGIN PRIVATE KEY-----\nsecret\n")
            with self.assertRaisesRegex(ValueError, "private key"):
                stage_os.certificate_identity(certificate, source)

    def test_certificate_directory_must_not_contain_generic_private_material(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.mkdir()
            certificate, key = self.certificate(directory, "Wonad Release")
            sibling = Path(directory) / "private.pem"
            sibling.write_bytes(key.read_bytes())
            with self.assertRaisesRegex(ValueError, "directory contains private"):
                stage_os.certificate_identity(certificate, source)
            sibling.unlink()
            container = Path(directory) / "signer.p12"
            container.write_bytes(b"opaque PKCS#12 placeholder")
            with self.assertRaisesRegex(ValueError, "directory contains private"):
                stage_os.certificate_identity(certificate, source)
