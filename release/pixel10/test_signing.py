import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("sign_release", Path(__file__).with_name("sign-release.py"))
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)
BUILD, COMMIT, MANIFEST = "2026112601", "a" * 40, "b" * 40


class Signing(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        self.config = {}
        for key in ("source_root", "graphene_root", "unsigned_root", "intake_root", "signed_root", "log_root"):
            path = self.root / key
            path.mkdir()
            self.config[key] = str(path)
        self.config.update(tool_path="/usr/bin:/bin", apk_keystore="/dummy/keys", apk_passfile="/dummy/password")
        self.source = Path(self.config["unsigned_root"]) / BUILD
        self.source.mkdir()
        self.staged = self.root / "staged"
        self.staged.mkdir()
        self.approved = Path(self.config["intake_root"]) / BUILD
        self.output = Path(self.config["signed_root"]) / BUILD
        for name in signer.UNSIGNED_FILES:
            (self.source / name).write_text(name + "\n")
        (self.source / "source-commit").write_text(COMMIT + "\n")
        (self.source / "build-number").write_text(BUILD + "\n")
        (self.source / "native-inputs-sha256").write_text("f" * 64 + "\n")
        pins = Path(self.config["source_root"]) / COMMIT / "release/pixel10/pins.json"
        pins.parent.mkdir(parents=True)
        pins.write_text('{"manifest":"' + MANIFEST + '"}')
        self.digest = self.inventory()

    def inventory(self):
        contents = "".join(self.digest_of((self.source / name).read_bytes()) + "  " + name + "\n"
                           for name in sorted(signer.UNSIGNED_FILES)).encode()
        (self.source / "SHA256SUMS").write_bytes(contents)
        return self.digest_of(contents)

    @staticmethod
    def digest_of(value):
        return hashlib.sha256(value).hexdigest()

    def test_stages_a_private_matching_snapshot(self):
        signer.stage_unsigned(self.source, self.staged, BUILD, COMMIT, self.digest)
        for p in self.staged.iterdir():
            self.assertEqual(p.read_bytes(), (self.source / p.name).read_bytes())

    def test_rejects_rewritten_inventory_and_payload(self):
        with self.assertRaisesRegex(ValueError, "approved digest"):
            signer.stage_unsigned(self.source, self.staged, BUILD, COMMIT, "0" * 64)
        (self.source / "frankel-otatools.zip").write_text("changed")
        with self.assertRaisesRegex(ValueError, "does not match inventory"):
            signer.stage_unsigned(self.source, self.staged, BUILD, COMMIT, self.digest)

    def test_rejects_extra_files_and_symlink_inputs(self):
        extra = self.source / "extra"
        extra.write_text("extra")
        with self.assertRaisesRegex(ValueError, "directory differs"):
            signer.stage_unsigned(self.source, self.staged, BUILD, COMMIT, self.digest)
        extra.unlink()
        apk = self.source / "controller.apk"
        apk.rename(self.root / "controller.apk")
        apk.symlink_to(self.root / "controller.apk")
        with self.assertRaises(OSError):
            signer.stage_unsigned(self.source, self.staged, BUILD, COMMIT, self.digest)

    def test_refuses_wrong_metadata_even_with_matching_checksums(self):
        (self.source / "build-number").write_text("2026112602\n")
        with self.assertRaisesRegex(ValueError, "metadata"):
            signer.stage_unsigned(self.source, self.staged, BUILD, COMMIT, self.inventory())

    def test_signing_requires_exact_local_intake(self):
        self.approved.write_text(f"{COMMIT} {'0' * 64}\n")
        with patch.object(signer.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "registered handoff"):
                signer.sign(self.config, BUILD, COMMIT, self.digest)
            run.assert_not_called()

    def test_publishes_only_complete_output_and_reuses_the_exact_handoff(self):
        self.approved.write_text(f"{COMMIT} {self.digest}\n")

        def package(_cmd, *, env, **_kwargs):
            self.assertFalse(self.output.exists())
            self.assertNotIn("GH_TOKEN", env)
            self.assertEqual(env["DESKTOP_KS_PASS_FILE"], "/dummy/password")
            unsigned, signed = Path(env["UNSIGNED"]), Path(env["SIGNED"])
            self.assertNotEqual(unsigned, self.source)
            signed.mkdir()
            for name in ("controller.apk", "styx.apk", "xmonad.apk", "build-number", "source-commit",
                         "native-inputs-sha256"):
                (signed / name).write_bytes((unsigned / name).read_bytes())
            (signed / "unsigned-inputs-sha256").write_text(self.digest + "\n")
            for name in ("SHA256SUMS", "SHA256SUMS.sig", f"frankel-install-{BUILD}.zip",
                         f"frankel-install-{BUILD}.zip.sig", f"frankel-ota_update-{BUILD}.zip"):
                (signed / name).write_text("fixture")

        with patch.object(signer.subprocess, "run", side_effect=package) as run:
            signer.sign(self.config, BUILD, COMMIT, self.digest)
            self.assertTrue(self.output.exists())
            signer.sign(self.config, BUILD, COMMIT, self.digest)
            run.assert_called_once()

    def test_signing_failure_leaves_no_publishable_directory(self):
        self.approved.write_text(f"{COMMIT} {self.digest}\n")
        with patch.object(signer.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "fixture")):
            with self.assertRaises(subprocess.CalledProcessError):
                signer.sign(self.config, BUILD, COMMIT, self.digest)
        self.assertFalse(self.output.exists())
