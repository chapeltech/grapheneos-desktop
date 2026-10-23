import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile


ANDROID = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_release_artifacts", ANDROID / "tools/verify_release_artifacts.py")
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)

BUILD = "2026101000"
AVB_PUBLIC = struct.pack("!II", 4096, 1) + b"a" * 1024
CERT_DER = b"synthetic-public-certificate-der"
CERT_PEM = (b"-----BEGIN CERTIFICATE-----\n" +
            base64.encodebytes(CERT_DER) +
            b"-----END CERTIFICATE-----\n")
SSH_BLOB = base64.b64encode(b"synthetic-ed25519-public-blob" * 3).decode()
SSH_PUBLIC = f"ssh-ed25519 {SSH_BLOB} release fixture\n".encode()


def digest(path):
    data = path.read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def zip_bytes(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return output.getvalue()


class ArtifactVerification(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.release = self.root / f"release-frankel-{BUILD}"
        self.release.mkdir()
        self.receipt_path = self.release / "release-receipt.json"
        self.receipt_path.write_text("{}\n")
        self.roles = verify.release_receipt.artifact_roles(BUILD)
        self.avb = self.root / "avb_pkmd.bin"
        self.avb.write_bytes(AVB_PUBLIC)
        self.ota_cert = self.root / "releasekey.x509.pem"
        self.ota_cert.write_bytes(CERT_PEM)
        self.factory_key = self.root / "factory.pub"
        self.factory_key.write_bytes(SSH_PUBLIC)

        self.image_entries = {
            "android-info.txt": b"require product=frankel\n",
            "vbmeta.img": b"signed vbmeta image",
            "boot.img": b"signed boot image",
            "init_boot.img": b"signed init boot image",
            "vendor_boot.img": b"signed vendor boot image",
            "system.img": b"signed system image",
        }
        self.image_zip = zip_bytes(self.image_entries)
        (self.release / self.roles["images"]).write_bytes(self.image_zip)
        factory_root = f"frankel-factory-{BUILD}"
        factory = {
            f"{factory_root}/flash-all.sh": b"#!/bin/sh\n",
            f"{factory_root}/flash-all.bat": b"@echo off\n",
            f"{factory_root}/avb_pkmd.bin": AVB_PUBLIC,
            f"{factory_root}/image-frankel-{BUILD}.zip": self.image_zip,
        }
        (self.release / self.roles["factory"]).write_bytes(zip_bytes(factory))
        install_root = f"frankel-install-{BUILD}"
        install = {
            f"{install_root}/flash-all.sh": b"#!/bin/sh\n",
            f"{install_root}/flash-all.bat": b"@echo off\n",
            f"{install_root}/script.txt": b"flash vbmeta vbmeta.img\n",
            f"{install_root}/avb_pkmd.bin": AVB_PUBLIC,
            f"{install_root}/vbmeta.img": self.image_entries["vbmeta.img"],
        }
        (self.release / self.roles["install"]).write_bytes(zip_bytes(install))
        (self.release / self.roles["install_signature"]).write_bytes(
            b"-----BEGIN SSH SIGNATURE-----\nfixture\n-----END SSH SIGNATURE-----\n")
        ota_metadata = (f"post-build=wonad/frankel/frankel:17/FIXTURE/{BUILD}:user/release-keys\n"
                        f"post-timestamp=1791633600\npre-device=frankel\n").encode()
        ota = {
            "META-INF/com/android/metadata": ota_metadata,
            "payload.bin": b"signed payload",
            "payload_properties.txt": b"FILE_HASH=fixture\n",
        }
        (self.release / self.roles["full_ota"]).write_bytes(zip_bytes(ota))

        otacerts = zip_bytes({"releasekey.x509.pem": CERT_PEM})
        self.properties = (
            f"ro.build.version.incremental={BUILD}\n"
            "ro.build.type=user\n"
            "ro.build.tags=release-keys\n"
            "ro.debuggable=0\n"
            "ro.secure=1\n"
            "ro.product.system.device=frankel\n"
            f"ro.build.fingerprint=Wonad/frankel/frankel:17/FIXTURE/{BUILD}:user/release-keys\n"
        ).encode()
        self.misc = (
            b"avb_enable=true\n"
            b"avb_building_vbmeta_image=true\n"
            b"avb_vbmeta_algorithm=SHA256_RSA4096\n"
            b"avb_vbmeta_key_path=keys/avb.pem\n"
            b"default_system_dev_certificate=keys/releasekey\n"
            b"vintf_enforce=true\n"
        )
        self.write_target(self.properties, self.misc, otacerts)

        for name in verify.REQUIRED_TOOLS:
            tool = self.release / "bin" / name
            tool.parent.mkdir(exist_ok=True)
            tool.write_text("#!/bin/sh\nexit 0\n")
            tool.chmod(0o755)
        self.tool_manifest = self.root / "trusted-otatools.json"
        self.tool_manifest.write_text(json.dumps({
            "schema": 1,
            "tools": {name: digest(self.release / "bin" / name)
                      for name in verify.REQUIRED_TOOLS},
        }, sort_keys=True))
        for channel in ("alpha", "beta", "stable", "testing"):
            (self.release / self.roles[f"channel_{channel}"]).write_text(
                f"{BUILD} 1791633600 frankel {channel}\n")

        self.refresh_receipt()
        self.calls = []

    def write_target(self, properties, misc, otacerts):
        target = {
            "META/misc_info.txt": misc,
            "META/apkcerts.txt": b'name="Wonad.apk" certificate="keys/releasekey"\n',
            "META/otakeys.txt": b"keys/releasekey.x509.pem\n",
            "SYSTEM/build.prop": properties,
            "SYSTEM/etc/security/otacerts.zip": otacerts,
            "SYSTEM/etc/selinux/plat_sepolicy.cil": b"(allow init self (process (fork)))\n",
            "VENDOR/etc/build.prop": b"ro.product.vendor.device=frankel\n",
            "VENDOR/etc/selinux/precompiled_sepolicy": b"compiled policy",
        }
        for name, data in self.image_entries.items():
            if name.endswith(".img"):
                target[f"IMAGES/{name}"] = data
        (self.release / self.roles["signed_target_files"]).write_bytes(zip_bytes(target))

    def refresh_receipt(self):
        files = {}
        for path in self.release.rglob("*"):
            if path.is_file() and path != self.receipt_path:
                files[path.relative_to(self.release).as_posix()] = digest(path)
        self.receipt = {
            "build": {"number": BUILD, "timestamp": 1791633600},
            "target": {"product": "frankel", "variant": "user"},
            "artifacts": self.roles,
            "files": files,
            "artifact_verifier": {
                "name": "android/tools/verify_release_artifacts.py",
                **digest(Path(verify.__file__)),
            },
        }

    def runner(self, argv, **kwargs):
        argv = [str(value) for value in argv]
        self.calls.append((argv, kwargs))
        if "info_image" in argv:
            output = Path(argv[argv.index("--output_pubkey") + 1])
            output.write_bytes(AVB_PUBLIC)
        if "unpack_bootimg" in Path(argv[0]).name:
            out = Path(argv[argv.index("--out") + 1])
            (out / "bootconfig").write_text("androidboot.verifiedbootstate=green\n")
            return SimpleNamespace(returncode=0, stdout=b"--cmdline 'quiet'\n", stderr=b"")
        return SimpleNamespace(returncode=0, stdout=b"verified\n", stderr=b"")

    def run_verify(self, runner=None):
        with patch.object(verify.release_receipt, "verify_receipt", return_value=self.receipt):
            return verify.verify(self.receipt_path, self.avb, self.ota_cert,
                                 self.factory_key, digest(self.receipt_path)["sha256"],
                                 self.tool_manifest, digest(self.tool_manifest)["sha256"],
                                 runner=runner or self.runner)

    def test_authentication_precedes_receipt_parsing_and_tool_execution(self):
        with patch.object(verify.release_receipt, "verify_receipt",
                          side_effect=AssertionError("untrusted receipt parsed")):
            with self.assertRaisesRegex(verify.VerificationError, "release receipt SHA-256"):
                verify.verify(self.receipt_path, self.avb, self.ota_cert, self.factory_key,
                              "0" * 64, self.tool_manifest,
                              digest(self.tool_manifest)["sha256"], runner=self.runner)
        self.assertFalse(self.calls)

    def test_self_receipted_tool_substitution_is_rejected_by_independent_identity(self):
        tool = self.release / "bin/avbtool"
        tool.write_text("#!/bin/sh\necho substituted\n")
        tool.chmod(0o755)
        self.receipt["files"]["bin/avbtool"] = digest(tool)
        with self.assertRaisesRegex(verify.VerificationError, "independently trusted identity"):
            self.run_verify()
        self.assertFalse(self.calls)

    def test_shiba_release_target_is_rejected(self):
        self.receipt["target"]["product"] = "shiba"
        with self.assertRaisesRegex(verify.VerificationError, "frankel user target"):
            self.run_verify()
        self.assertFalse(self.calls)

    def test_full_verification_constructs_every_official_proof(self):
        result = self.run_verify()
        self.assertEqual("verified", result["status"])
        self.assertEqual("frankel-user", result["target"])
        self.assertFalse(result["release_metadata"]["debuggable"])
        commands = [Path(call[0][0]).name for call in self.calls]
        for name in verify.REQUIRED_TOOLS:
            self.assertIn(name, commands)
        self.assertIn("ssh-keygen", commands)
        avb_commands = [call[0] for call in self.calls if Path(call[0][0]).name == "avbtool"]
        self.assertTrue(any("--follow_chain_partitions" in command for command in avb_commands))
        ssh = next(call for call in self.calls if Path(call[0][0]).name == "ssh-keygen")
        self.assertEqual(self.release / self.roles["install"], ssh[1]["stdin_path"])

    def test_missing_or_unreceipted_official_tool_fails_closed(self):
        tool = self.release / "bin/avbtool"
        tool.unlink()
        with self.assertRaisesRegex(verify.VerificationError, "otatool is absent"):
            self.run_verify()

    def test_official_tool_rejection_is_not_downgraded(self):
        def rejecting(argv, **kwargs):
            if Path(argv[0]).name == "check_ota_package_signature":
                raise verify.VerificationError("synthetic OTA signature rejection")
            return self.runner(argv, **kwargs)

        with self.assertRaisesRegex(verify.VerificationError, "OTA signature rejection"):
            self.run_verify(rejecting)

    def test_debuggable_or_test_key_target_is_rejected_before_crypto(self):
        bad = self.properties.replace(b"ro.debuggable=0", b"ro.debuggable=1")
        self.write_target(bad, self.misc, zip_bytes({"releasekey.x509.pem": CERT_PEM}))
        self.refresh_receipt()
        with self.assertRaisesRegex(verify.VerificationError, "ro.debuggable=0"):
            self.run_verify()
        self.assertFalse(self.calls)

        self.write_target(self.properties, self.misc + b"legacy_key=testkey\n",
                          zip_bytes({"releasekey.x509.pem": CERT_PEM}))
        self.refresh_receipt()
        with self.assertRaisesRegex(verify.VerificationError, "debug/test key"):
            self.run_verify()

    def test_permissive_boot_argument_is_rejected(self):
        def permissive(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if Path(argv[0]).name == "unpack_bootimg":
                return SimpleNamespace(returncode=0,
                                       stdout=b"--cmdline androidboot.selinux=permissive\n",
                                       stderr=b"")
            return result

        with self.assertRaisesRegex(verify.VerificationError, "requests permissive SELinux"):
            self.run_verify(permissive)

    def test_wrong_avb_or_ota_public_identity_is_rejected(self):
        def wrong_avb(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if "info_image" in [str(value) for value in argv]:
                output = Path(argv[[str(value) for value in argv].index("--output_pubkey") + 1])
                output.write_bytes(b"wrong public key")
            return result

        with self.assertRaisesRegex(verify.VerificationError, "Root vbmeta key differs"):
            self.run_verify(wrong_avb)

        self.ota_cert.write_bytes(
            b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(b"other") +
            b"-----END CERTIFICATE-----\n")
        with self.assertRaisesRegex(verify.VerificationError, "OTA certificate differs"):
            self.run_verify()

    def test_private_input_and_unsafe_or_duplicate_zip_entries_are_rejected(self):
        private_avb = self.root / "avb.pem"
        private_avb.write_bytes(b"-----BEGIN PRIVATE KEY-----\nsecret\n")
        with patch.object(verify.release_receipt, "verify_receipt", return_value=self.receipt), \
                patch.object(verify, "read_public_file",
                             side_effect=AssertionError("private path was opened")):
            with self.assertRaisesRegex(verify.VerificationError, "encoded public-key blob"):
                verify.verify(self.receipt_path, private_avb, self.ota_cert,
                              self.factory_key, digest(self.receipt_path)["sha256"],
                              self.tool_manifest, digest(self.tool_manifest)["sha256"],
                              runner=self.runner)

        self.ota_cert.write_bytes(
            b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n")
        with self.assertRaisesRegex(verify.VerificationError, "private material"):
            self.run_verify()

        malicious = self.root / "traversal.zip"
        malicious.write_bytes(zip_bytes({"../escape": b"bad"}))
        with self.assertRaisesRegex(verify.VerificationError, "Unsafe ZIP"):
            with verify.SafeZip(malicious, "malicious"):
                pass

        duplicate = self.root / "duplicate.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate, "w") as archive:
                archive.writestr("same", b"one")
                archive.writestr("same", b"two")
        with self.assertRaisesRegex(verify.VerificationError, "Duplicate"):
            with verify.SafeZip(duplicate, "duplicate"):
                pass

    def test_factory_payload_and_detached_signature_are_mandatory(self):
        factory_root = f"frankel-factory-{BUILD}"
        bad_factory = {
            f"{factory_root}/flash-all.sh": b"#!/bin/sh\n",
            f"{factory_root}/flash-all.bat": b"@echo off\n",
            f"{factory_root}/avb_pkmd.bin": AVB_PUBLIC,
            f"{factory_root}/image-frankel-{BUILD}.zip": b"different image payload",
        }
        (self.release / self.roles["factory"]).write_bytes(zip_bytes(bad_factory))
        self.refresh_receipt()
        with self.assertRaisesRegex(verify.VerificationError, "Factory image payload differs"):
            self.run_verify()

        # Restore the factory and then damage the detached SSH signature.
        bad_factory[f"{factory_root}/image-frankel-{BUILD}.zip"] = self.image_zip
        (self.release / self.roles["factory"]).write_bytes(zip_bytes(bad_factory))
        (self.release / self.roles["install_signature"]).write_bytes(b"not an SSH signature")
        self.refresh_receipt()
        with self.assertRaisesRegex(verify.VerificationError, "detached install signature"):
            self.run_verify()

    def test_factory_image_archive_cannot_add_an_unsigned_target_image(self):
        image_entries = dict(self.image_entries)
        image_entries["unreceipted-partition.img"] = b"not present in signed target-files"
        image_zip = zip_bytes(image_entries)
        (self.release / self.roles["images"]).write_bytes(image_zip)
        factory_root = f"frankel-factory-{BUILD}"
        factory = {
            f"{factory_root}/flash-all.sh": b"#!/bin/sh\n",
            f"{factory_root}/flash-all.bat": b"@echo off\n",
            f"{factory_root}/avb_pkmd.bin": AVB_PUBLIC,
            f"{factory_root}/image-frankel-{BUILD}.zip": image_zip,
        }
        (self.release / self.roles["factory"]).write_bytes(zip_bytes(factory))
        self.refresh_receipt()
        with self.assertRaisesRegex(
                verify.VerificationError,
                "images absent from signed target-files: unreceipted-partition.img"):
            self.run_verify()


if __name__ == "__main__":
    unittest.main()
