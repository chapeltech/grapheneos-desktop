import base64
import hashlib
import io
import os
from pathlib import Path
import stat
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

import hosted_intake as intake
import hosted_keys as keys
import hosted_security as security
import hosted_run as runner


class Hosted(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def test_key_parts_are_bounded_private_and_round_trip(self):
        source = self.root / "source"
        source.mkdir()
        for name in keys.FILES["os"]:
            (source / name).write_bytes(os.urandom(3000))
        chunks = keys.pack("os", source)
        self.assertEqual(len(chunks), 3)
        self.assertTrue(all(0 < len(c) <= keys.CHUNK for c in chunks))
        output = self.root / "output"
        keys.restore("os", chunks, output)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        for name in keys.FILES["os"]:
            self.assertEqual(stat.S_IMODE((output / name).stat().st_mode), 0o600)
            self.assertEqual((output / name).read_bytes(), (source / name).read_bytes())

    def test_key_transport_rejects_symlinks_and_duplicate_parts(self):
        record = io.BytesIO()
        with tarfile.open(fileobj=record, mode="w:gz") as archive:
            entry = tarfile.TarInfo("desktop.p12")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "../other"
            archive.addfile(entry)
        with self.assertRaisesRegex(ValueError, "inventory"):
            keys.decode("apps", [base64.b64encode(record.getvalue()).decode(), keys.UNUSED])
        with self.assertRaisesRegex(ValueError, "framing"):
            keys.decode("apps", [keys.UNUSED, "AAAA"])

    def test_intake_reconstruction_holds_to_original_approved_digest(self):
        source = self.root / "input"
        source.mkdir()
        build = "2026112603"
        commit = "a" * 40
        for name in intake.FILES["os"]:
            (source / name).write_bytes(b"test archive body" * 4)
        (source / "build-number").write_text(build + "\n")
        (source / "source-commit").write_text(commit + "\n")
        (source / "native-inputs-sha256").write_text("b" * 64 + "\n")
        manifest = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
                           for p in source.iterdir()).encode()
        approved = hashlib.sha256(manifest).hexdigest()
        (source / "SHA256SUMS").write_bytes(manifest)
        parts = self.root / "parts"
        intake.pack("os", source, parts, build, commit, approved, limit=20)
        output = self.root / "unsigned"
        intake.unpack("os", parts, output, build, commit, approved, limit=20)
        self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()},
                         {p.name: p.read_bytes() for p in source.iterdir()})
        first = parts / "frankel-target_files.zip.part000"
        first.write_bytes(b"x" * first.stat().st_size)
        invalid = self.root / "invalid"
        with self.assertRaisesRegex(ValueError, "failed approved checksum"):
            intake.unpack("os", parts, invalid, build, commit, approved, limit=20)
        self.assertFalse(invalid.exists())

    def test_policy_cannot_be_weakened_before_releasing_keys(self):
        env = {"name": "pixel10-sign", "can_admins_bypass": False,
               "protection_rules": [{"type": "required_reviewers", "reviewers": [{}]}],
               "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}
        policies = {"branch_policies": [{"type": "branch", "name": "release/pixel10"}]}
        security.check(security.REF, True, "github-hosted", env, policies)
        for runner, bypass, rules in (
            ("self-hosted", False, policies),
            ("github-hosted", True, policies),
            ("github-hosted", False, {"branch_policies": [{"type": "tag", "name": "*"}]}),
        ):
            with self.assertRaises(ValueError):
                security.check(security.REF, True, runner, env | {"can_admins_bypass": bypass}, rules)

    def test_hosted_download_checks_github_asset_size_and_digest(self):
        payload = b"reviewed signing asset bytes"
        checksum = "sha256:" + hashlib.sha256(payload).hexdigest()
        reply = {"assets": [{"name": "data.part000", "size": len(payload), "id": 123, "digest": checksum}]}

        def deliver(_argv, *, stdout, check):
            self.assertTrue(check)
            stdout.write(payload)

        with patch.object(runner.sp, "run", side_effect=deliver):
            runner.download(reply, self.root / "ok", lambda _: True, 1000)
            self.assertEqual((self.root / "ok/data.part000").read_bytes(), payload)
            reply["assets"][0]["digest"] = "sha256:" + "f" * 64
            with self.assertRaisesRegex(ValueError, "asset differs"):
                runner.download(reply, self.root / "bad", lambda _: True, 1000)

    def test_ota_tool_extraction_cannot_shadow_sdk_apksigner(self):
        sdk = self.root / "sdk"
        sdk.mkdir()
        apksigner = sdk / "apksigner"
        apksigner.touch(mode=0o700)
        with ZipFile(self.root / "frankel-otatools.zip", "w") as ota_tools:
            for name in ("check_ota_package_signature", "avbtool", "delta_generator", "apksigner", "aapt2"):
                ota_tools.writestr(f"bin/{name}", b"fixture")
            ota_tools.writestr("lib64/libcrypto-host.so", b"fixture library")
        with patch.dict(os.environ, {"PATH": str(sdk)}):
            runner.run_verify_tools(self.root, self.root)
            self.assertEqual(shutil.which("apksigner"), str(apksigner))
            self.assertEqual({p.name for p in (self.root / "verify-tools/bin").iterdir()},
                             {"check_ota_package_signature", "avbtool", "delta_generator"})
            self.assertTrue((self.root / "verify-tools/lib64/libcrypto-host.so").is_file())
