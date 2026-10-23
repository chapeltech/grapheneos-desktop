"""Host-only tests for the development APK packet builder and verifier."""

import copy
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "android/tools"))
import phase1_emulator_client_packet as packet


def make_apk(path, *, traversal=False, duplicate=False):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"payload")
        archive.writestr("META-INF/CERT.SF", b"old signature")
        archive.writestr("META-INF/CERT.RSA", b"old certificate")
        if traversal:
            archive.writestr("../escape", b"bad")
        if duplicate:
            archive.writestr("classes.dex", b"duplicate")


class Phase1EmulatorClientPacketTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_signature_stripping_preserves_exact_non_signature_payload(self):
        source, target = self.root / "source.apk", self.root / "target.apk"
        make_apk(source)
        expected = packet.apk_payload(source)
        packet.strip_signatures(source, target)
        self.assertEqual(packet.apk_payload(target), expected)
        with zipfile.ZipFile(target) as archive:
            self.assertFalse(any(packet.signature_member(name) for name in archive.namelist()))

    def fresh_conformance(self):
        unsigned = self.root / "conformance-unsigned.apk"
        make_apk(unsigned)
        compile_receipt = {"conformance_artifact": {
            **packet.ref(unsigned), "path": str(unsigned), "package": "org.wonad.desktop",
            "version_code": 1, "version_name": "3.0-phase1-conformance", "signed": False,
            "native_code": False, "privileged": False, "test_only": False, "shared_uid": False,
        }}
        metadata = {"package": "org.wonad.desktop", "certificate_der_sha256": packet.WONAD_CERT,
                    "version_code": 1, "version_name": "3.0-phase1-conformance"}
        return unsigned, compile_receipt, metadata

    def test_fresh_conformance_is_signed_from_exact_compile_output(self):
        unsigned, receipt, metadata = self.fresh_conformance()
        target = self.root / "conformance.apk"
        signer, platform, tools = self.root / "signer", self.root / "platform", object()

        def sign(_tools, source, destination, role, key, os_source):
            self.assertEqual((_tools, source, destination, role, key, os_source),
                             (tools, unsigned, target, "wonad", signer, platform))
            packet.strip_signatures(source, destination)

        with patch.object(packet, "sign_apk", side_effect=sign) as signing, \
                patch.object(packet, "inspect_apk", return_value=metadata):
            self.assertEqual(packet.conformance_input(
                self.root, tools, target, signer, platform, compile_receipt=receipt), target)
        signing.assert_called_once()
        self.assertEqual(packet.apk_payload(target), packet.apk_payload(unsigned))

    def test_conformance_compile_artifact_drift_is_rejected_before_signing(self):
        _unsigned, original, _metadata = self.fresh_conformance()
        for key, wrong in (("sha256", "0" * 64), ("bytes", 1), ("signed", True),
                           ("path", "/historical/conformance-unsigned.apk"),
                           ("package", "org.wrong"), ("version_code", 2), ("native_code", True)):
            with self.subTest(key=key):
                receipt = copy.deepcopy(original)
                receipt["conformance_artifact"][key] = wrong
                with patch.object(packet, "sign_apk") as signing:
                    with self.assertRaisesRegex(packet.PacketError, "authenticated successor"):
                        packet.conformance_input(self.root, object(), self.root / "signed.apk",
                            self.root / "signer", self.root / "platform", compile_receipt=receipt)
                    signing.assert_not_called()

    def test_conformance_signed_payload_or_signer_drift_is_rejected(self):
        unsigned, receipt, metadata = self.fresh_conformance()
        target = self.root / "signed.apk"

        def sign(_tools, source, destination, *_rest):
            packet.strip_signatures(source, destination)

        for key, wrong in (("certificate_der_sha256", packet.FIXTURE_CERT),
                           ("version_code", 2), ("version_name", "old-runtime")):
            with self.subTest(key=key):
                with patch.object(packet, "sign_apk", side_effect=sign), \
                        patch.object(packet, "inspect_apk", return_value={**metadata, key: wrong}):
                    with self.assertRaisesRegex(packet.PacketError, "Fresh signed conformance"):
                        packet.conformance_input(self.root, object(), target, self.root / "signer",
                                                 self.root / "platform", compile_receipt=receipt)
                target.unlink()
        self.assertTrue(unsigned.exists())

    def test_archive_traversal_and_duplicate_members_fail_closed(self):
        traversal = self.root / "traversal.apk"
        duplicate = self.root / "duplicate.apk"
        make_apk(traversal, traversal=True)
        make_apk(duplicate, duplicate=True)
        with self.assertRaisesRegex(packet.PacketError, "Unsafe"):
            packet.apk_payload(traversal)
        with self.assertRaisesRegex(packet.PacketError, "Duplicate"):
            packet.apk_payload(duplicate)

    def test_only_exact_jar_signature_members_are_excluded(self):
        self.assertTrue(packet.signature_member("META-INF/MANIFEST.MF"))
        self.assertTrue(packet.signature_member("META-INF/CERT.SF"))
        self.assertTrue(packet.signature_member("META-INF/CERT.RSA"))
        self.assertFalse(packet.signature_member("classes.dex"))
        self.assertFalse(packet.signature_member("META-INF/sub/CERT.RSA"))
        self.assertFalse(packet.signature_member("META-INF/CERT.RSA.backup"))

    def test_signer_parser_requires_one_verified_v3_signer(self):
        valid = """Verifies
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Number of signers: 1
Signer #1 certificate SHA-256 digest: %s
""" % ("a" * 64)
        self.assertEqual(packet.parse_signer(valid)["certificate_der_sha256"], "a" * 64)
        with self.assertRaisesRegex(packet.PacketError, "v3"):
            packet.parse_signer(valid.replace("scheme (APK Signature Scheme v3): true", "scheme (APK Signature Scheme v3): false"))
        with self.assertRaisesRegex(packet.PacketError, "exactly one"):
            packet.parse_signer(valid + "Signer #2 certificate SHA-256 digest: " + "b" * 64)

    def test_manifest_parser_recognizes_compiled_boolean_and_targets(self):
        badging = "package: name='org.example.test' versionCode='7' versionName='dev'\napplication-debuggable\n"
        manifest = """
          A: android:targetPackage(0x01010021)=\"org.wonad.desktop\" (Raw: \"org.wonad.desktop\")
          A: android:testOnly(0x01010272)=(type 0x12)0xffffffff
        """
        value = packet.apk_metadata(badging, manifest)
        self.assertTrue(value["test_only"])
        self.assertTrue(value["debuggable"])
        self.assertEqual(value["instrumentation_targets"], ["org.wonad.desktop"])
        self.assertFalse(value["shared_uid"])

    def test_manifest_parser_recognizes_text_xml_and_system_shared_uid(self):
        badging = "package: name='org.example.test' versionCode='1' versionName=''\n"
        manifest = """
          A: http://schemas.android.com/apk/res/android:testOnly(0x01010272)=true
          A: android:sharedUserId(0x0101000b)=\"android.uid.system\" (Raw: \"android.uid.system\")
        """
        value = packet.apk_metadata(badging, manifest)
        self.assertTrue(value["test_only"])
        self.assertTrue(value["shared_uid"])
        self.assertTrue(value["privileged_manifest"])

    def test_source_copy_uses_packet_relative_origin_and_rejects_symlinks(self):
        source, target = self.root / "incoming", self.root / "packet/source"
        source.mkdir(); target.mkdir(parents=True)
        (source / "one.txt").write_text("one")
        origins = {}
        packet.copy_tree(source, target / "module", origins, "working/module", target)
        self.assertEqual(list(origins), ["module/one.txt"])
        self.assertEqual(origins["module/one.txt"]["origin"], "working/module/one.txt")
        (source / "link").symlink_to(source / "one.txt")
        with self.assertRaisesRegex(packet.PacketError, "Symlinked"):
            packet.copy_tree(source, target / "again", {}, "working/module", target)

    def test_signer_classes_and_instrumentation_exception_are_explicit(self):
        self.assertNotEqual(packet.WONAD_CERT, packet.FIXTURE_CERT)
        self.assertEqual(packet.BUILT_APKS["fixture"][2:], ("fixture", False, True))
        self.assertEqual(packet.BUILT_APKS["probe"][2:], ("fixture", False, True))
        for role in ("security", "reuse", "prerequisite"):
            self.assertEqual(packet.BUILT_APKS[role][2:], ("wonad", True, False))
        self.assertEqual(packet.BUILT_APKS["fault"][2:], ("platform", True, False))

    def test_artifact_contract_keeps_conformance_and_harnesses_separate(self):
        platform, wrong = "c" * 64, "d" * 64
        expected = {
            "wonad": ("org.wonad.desktop", packet.WONAD_CERT),
            "conformance": ("org.wonad.desktop", packet.WONAD_CERT),
            "fixture": ("org.wonad.fixture", packet.FIXTURE_CERT),
            "ime": ("org.wonad.imefixture", packet.FIXTURE_CERT),
            "security": ("org.wonad.desktop.test", packet.WONAD_CERT),
            "reuse": ("org.wonad.desktop.taskreuse", packet.WONAD_CERT),
            "fault": ("org.wonad.desktop.transitionfault", platform),
            "prerequisite": ("org.wonad.desktop.prerequisites", packet.WONAD_CERT),
            "probe": ("org.wonad.probe", packet.FIXTURE_CERT),
            "wrong_wonad": ("org.wonad.desktop", wrong),
            "wrong_security": ("org.wonad.desktop.test", wrong),
        }
        test_only = {"security", "reuse", "fault", "prerequisite", "wrong_security"}
        targets = {
            "conformance": ["org.wonad.desktop"], "security": ["org.wonad.desktop"],
            "reuse": ["org.wonad.desktop", "org.wonad.desktop.taskreuse"],
            "fault": ["com.android.systemui"], "prerequisite": ["org.wonad.desktop"],
            "wrong_security": ["org.wonad.desktop"],
        }
        roles = {role: dict(package=value[0], certificate_der_sha256=value[1],
            test_only=role in test_only, instrumentation_targets=targets.get(role, []),
            shared_uid=False, privileged_manifest=False, signers=1, schemes={"3": True})
            for role, value in expected.items()}
        packet.validate_artifact_contract(roles, expected)
        invalid = copy.deepcopy(roles); invalid["conformance"]["instrumentation_targets"] = []
        with self.assertRaisesRegex(packet.PacketError, "instrumentation"):
            packet.validate_artifact_contract(invalid, expected)
        invalid = copy.deepcopy(roles); invalid["fixture"]["certificate_der_sha256"] = packet.WONAD_CERT
        with self.assertRaisesRegex(packet.PacketError, "package/signer"):
            packet.validate_artifact_contract(invalid, expected)

    def test_canonical_receipt_is_order_independent_and_new_only(self):
        self.assertEqual(packet.canonical({"b": 1, "a": 2}), b'{"a":2,"b":1}\n')
        path = self.root / "receipt.json"
        packet.write_new(path, {"b": 1, "a": 2}, canonical_json=True)
        self.assertEqual(path.read_bytes(), b'{"a":2,"b":1}\n')
        with self.assertRaises(FileExistsError):
            packet.write_new(path, {}, canonical_json=True)

    def test_verifier_requires_the_receipt_digest_out_of_band(self):
        directory = self.root / "packet"; directory.mkdir()
        (directory / "receipt.json").write_text("{}\n")
        with self.assertRaisesRegex(packet.PacketError, "out-of-band"):
            packet.validate_receipt(directory, {}, "not-a-digest", live_tools=False)
        with self.assertRaisesRegex(packet.PacketError, "differs"):
            packet.validate_receipt(directory, {}, "0" * 64, live_tools=False)

    def test_disposable_tools_record_ignores_only_container_epoch(self):
        base = {"container_id": "1" * 64, "image_id": "sha256:" + "2" * 64,
                "tools": {"/tool": "3" * 64}, "packet_specific_tools": {},
                "offline_dependencies_sha256": "4" * 64,
                "offline_dependencies_count": 1, "fixture_keystore_sha256": "5" * 64}
        recorded = {**base, "container_id": "6" * 64,
                    "image_build": {"kind": "phase1_immutable_client_tools_image_v1"}}
        self.assertTrue(packet.equivalent_tools_record(base, recorded))
        changed = copy.deepcopy(recorded); changed["image_id"] = "sha256:" + "7" * 64
        self.assertFalse(packet.equivalent_tools_record(base, changed))
        missing = copy.deepcopy(recorded); missing.pop("image_build")
        self.assertFalse(packet.equivalent_tools_record(base, missing))

    def test_version_preparer_receives_exact_disposable_tools_identity(self):
        image = "sha256:" + "2" * 64
        tools = packet.Tools(image)
        tools.container = "1" * 64
        tools.token = "3" * 32
        command = packet.version_prepare_command(
            tools, Path("/packet/wonad.apk"), "/tmp/existing.p12", Path("/packet/version"))
        self.assertEqual(command[-6:], [
            "--tools-container", "1" * 64,
            "--tools-image", image,
            "--tools-label-token", "3" * 32,
        ])
        self.assertNotIn("wonad-android-gate-tools", command)

    def test_version_preparer_rejects_an_unstarted_tools_epoch(self):
        tools = packet.Tools("sha256:" + "2" * 64)
        with self.assertRaisesRegex(packet.PacketError, "not started"):
            packet.version_prepare_command(
                tools, Path("/packet/wonad.apk"), "/tmp/existing.p12", Path("/packet/version"))

    def test_conformance_update_claim_requires_exact_pair_permissions_and_commands(self):
        def reference(value):
            return {"sha256": value * 64, "bytes": 1}
        normalized, payload = "5" * 64, "6" * 64
        def member(version, value):
            return {"file": reference(value), "package": "org.wonad.desktop",
                "version_code": version, "version_name": "3.0-phase1-conformance",
                "certificate_der_sha256": packet.WONAD_CERT,
                "normalized_manifest_sha256": normalized,
                "non_manifest_payload_sha256": payload}
        v1, v2 = member(1, "1"), member(2, "2")
        version_only = {"package": "org.wonad.desktop",
            "version_name": "3.0-phase1-conformance",
            "certificate_der_sha256": packet.WONAD_CERT,
            "original_version_code": 1, "candidate_version_code": 2,
            "normalized_manifest_sha256": normalized,
            "non_manifest_payload_sha256": payload,
            "permissions_binding": "exact_binary_manifest_equality_except_root_version_code"}
        remote = "/tmp/phase1-client-signing.Ab12Cd34"
        commands = [
            [packet.OPENSSL, "pkcs8", "-topk8", "-nocrypt", "-in", remote + "/existing.pem",
             "-outform", "DER", "-out", remote + "/existing.pk8"],
            [packet.ZIPALIGN, "-P", "16", "-f", "4", remote + "/unsigned.apk", remote + "/aligned.apk"],
            [packet.APKSIGNER, "sign", "--key", remote + "/existing.pk8", "--cert",
             remote + "/existing.x509.pem", "--v1-signing-enabled", "true",
             "--v2-signing-enabled", "true", "--v3-signing-enabled", "true",
             "--v4-signing-enabled", "false", "--out", remote + "/candidate.apk", remote + "/aligned.apk"],
            [packet.ZIPALIGN, "-c", "-P", "16", "4", remote + "/candidate.apk"],
        ]
        canary = {"runner": packet.UPDATE_CANARY_RUNNER,
                  "source_sha256": packet.UPDATE_CANARY_SHA256}
        preparation = {"schema": 1, "api": 3,
            "kind": "phase1_conformance_version_only_preparation_v1",
            "status": "prepared_not_runtime_qualified", "development_only": True,
            "runtime_qualified": False, "guests_started": False,
            "tools": {"container_id": "7" * 64, "image_id": "sha256:" + "8" * 64,
                      "label_token": "9" * 32},
            "source": reference("1"), "artifacts": {"v1": v1, "v2": v2},
            "version_only": version_only, "private_data_canary": canary,
            "commands": [{"argv": argv, "stdout": "", "stdout_sha256": packet.sha_bytes(b""),
                          "stdout_bytes": 0}
                         for argv in commands],
            "files": {"original.apk": reference("1"), "candidate.apk": reference("2"),
                      "unsigned-version-only.apk": reference("3")}}
        record = {"receipt": reference("4"), "v1": v1, "v2": v2,
            "version_only": version_only, "private_data_canary": canary,
            "temporary_private_key_removed": True}
        self.assertEqual(record, packet.validate_conformance_update_claim(preparation, record))
        for label, mutation, message in (
            ("signer", lambda p, r: p["artifacts"]["v2"].__setitem__(
                "certificate_der_sha256", "f" * 64), "identity|version-only"),
            ("permissions", lambda p, r: p["version_only"].__setitem__(
                "permissions_binding", "claimed"), "permission"),
            ("command", lambda p, r: p["commands"][2]["argv"].__setitem__(1, "verify"),
             "existing-key command"),
        ):
            changed_preparation, changed_record = copy.deepcopy(preparation), copy.deepcopy(record)
            mutation(changed_preparation, changed_record)
            with self.subTest(label=label), self.assertRaisesRegex(packet.PacketError, message):
                packet.validate_conformance_update_claim(changed_preparation, changed_record)

    def test_transfer_paths_are_confined_to_exact_owned_roots(self):
        accepted = (packet.REMOTE, packet.REMOTE + "/source/file.apk",
                    "/tmp/phase1-client-signing.Ab12Cd34",
                    "/tmp/phase1-client-signing.Ab12Cd34/input.apk")
        for value in accepted:
            packet.Tools._safe_remote(value)
        for value in ("/work/other", "/tmp/file", packet.REMOTE + "/../escape",
                      packet.REMOTE + "//escape",
                      "/tmp/phase1-client-signing.Ab12Cd34/nested/file"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    packet.PacketError, "Unsafe|outside owned"):
                packet.Tools._safe_remote(value)

    def test_transfer_inventory_rejects_a_symlinked_root(self):
        source = self.root / "source"
        source.write_bytes(b"payload")
        alias = self.root / "alias"
        alias.symlink_to(source)
        with self.assertRaisesRegex(packet.PacketError, "aliased|symlinked"):
            packet.Tools._local_transfer_inventory(alias, include_root=True)

    def test_archive_extraction_preserves_modes_and_rejects_canonical_duplicates(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            directory = tarfile.TarInfo("nested"); directory.type = tarfile.DIRTYPE
            directory.mode = 0o700; archive.addfile(directory)
            member = tarfile.TarInfo("nested/value"); member.mode = 0o600
            member.size = 7; archive.addfile(member, io.BytesIO(b"payload"))
        target = self.root / "valid"; target.mkdir()
        packet.Tools._extract_transfer(stream, target)
        self.assertEqual((target / "nested").stat().st_mode & 0o7777, 0o700)
        self.assertEqual((target / "nested/value").stat().st_mode & 0o7777, 0o600)
        self.assertEqual((target / "nested/value").read_bytes(), b"payload")

        duplicate = io.BytesIO()
        with tarfile.open(fileobj=duplicate, mode="w") as archive:
            for name in ("same", "./same"):
                member = tarfile.TarInfo(name); member.size = 1
                archive.addfile(member, io.BytesIO(b"x"))
        with self.assertRaisesRegex(packet.PacketError, "Unsafe"):
            packet.Tools._extract_transfer(duplicate, self.root / "valid")

    def test_archive_extraction_enforces_member_and_payload_bounds(self):
        members = io.BytesIO()
        with tarfile.open(fileobj=members, mode="w") as archive:
            for name in ("one", "two"):
                member = tarfile.TarInfo(name); member.size = 1
                archive.addfile(member, io.BytesIO(b"x"))
        with patch.object(packet, "TRANSFER_MAX_MEMBERS", 1), \
                self.assertRaisesRegex(packet.PacketError, "member/byte bounds"):
            packet.Tools._extract_transfer(members, self.root)

        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w") as archive:
            member = tarfile.TarInfo("large"); member.size = 2
            archive.addfile(member, io.BytesIO(b"xx"))
        with patch.object(packet, "TRANSFER_MAX_PAYLOAD_BYTES", 1), \
                self.assertRaisesRegex(packet.PacketError, "member/byte bounds"):
            packet.Tools._extract_transfer(payload, self.root)

    def test_signing_cleanup_is_empty_safe_and_preserves_primary_failure(self):
        class FakeTools:
            def __init__(self, failure=False):
                self.failure, self.closed = failure, False
            def exec(self, *_args, **_kwargs):
                if self.failure:
                    raise packet.PacketError("cleanup failure")
                return "[]\n"
            def close(self):
                self.closed = True

        empty = packet.SigningSession(FakeTools(), self.root)
        empty.remote = "/tmp/phase1-client-signing.Ab12Cd34"
        self.assertFalse(empty.__exit__(None, None, None))

        tools = FakeTools(failure=True)
        session = packet.SigningSession(tools, self.root)
        session.remote = "/tmp/phase1-client-signing.Ab12Cd34"
        primary = RuntimeError("primary")
        self.assertFalse(session.__exit__(RuntimeError, primary, None))
        self.assertTrue(tools.closed)
        self.assertIn("cleanup failed", " ".join(primary.__notes__))

        tools = FakeTools(failure=True)
        session = packet.SigningSession(tools, self.root)
        session.remote = "/tmp/phase1-client-signing.Ab12Cd34"
        with self.assertRaisesRegex(packet.PacketError, "cleanup failure"):
            session.__exit__(None, None, None)
        self.assertTrue(tools.closed)

    def test_tools_image_manifest_binds_exact_image_and_payload_inventory(self):
        directory = self.root / "tools"; directory.mkdir()
        old_packet = ROOT / "android/out/phase1-emulator-client-packet-20261010-7"
        source_receipt_value = packet.load(old_packet / "receipt.json")
        source_plan_value = packet.load(old_packet / "evidence/compile-input/plan.json")
        required = packet.source_required_tools_files(source_receipt_value, source_plan_value)
        inventory = {
            "/opt/android-sdk": {"kind": "directory", "mode": 0o755},
            "/opt/android-sdk/tool": {"kind": "file", "mode": 0o755,
                                      "bytes": 4, "sha256": hashlib.sha256(b"tool").hexdigest()},
            packet.JAVA_HOME: {"kind": "directory", "mode": 0o755},
            packet.JAVA_HOME + "/lib": {"kind": "directory", "mode": 0o755},
            packet.JAVA_HOME + "/lib/server": {"kind": "directory", "mode": 0o755},
            packet.JAVA_HOME + "/lib/security": {"kind": "directory", "mode": 0o755},
            packet.JAVA_HOME + "/lib/security/cacerts": {
                "kind": "symlink", "target": "/etc/ssl/certs/java/cacerts"},
            packet.JAVA_HOME + "/docs": {
                "kind": "symlink", "target": "../../../share/doc/openjdk-21-jre-headless"},
            "/etc/ssl/certs/java/cacerts": {"kind": "file", "mode": 0o644,
                "bytes": 7, "sha256": hashlib.sha256(b"cacerts").hexdigest()},
            "/usr/share/doc/openjdk-21-jre-headless": {"kind": "directory", "mode": 0o755},
        }
        elf_digest = hashlib.sha256(b"elf").hexdigest()
        for name in packet.JAVA_RUNTIME_ELFS:
            inventory[name] = {"kind": "file", "mode": 0o755,
                               "bytes": 3, "sha256": elf_digest}
        for name, digest in required.items():
            if name not in packet.PARENT_TOOLS_FILES:
                inventory[name] = {"kind": "file", "mode": 0o644,
                                   "bytes": 1, "sha256": digest}
        for row in inventory.values():
            row.update(uid=0, gid=0)
        inventory_path = directory / "payload-inventory.json"
        inventory_path.write_bytes(packet.canonical(inventory))
        image = "sha256:" + "1" * 64
        resolved = ["/lib/x86_64-linux-gnu/libc.so.6"]
        closure = {
            "entrypoints": {name: {"sha256": inventory[name]["sha256"],
                "closure_sha256": packet.sha_bytes(packet.canonical(resolved)), "resolved": resolved}
                for name in packet.JAVA_RUNTIME_ELFS},
            "frozen_dependencies": [],
            "parent_dependencies": {resolved[0]: "9" * 64},
            "smoke": {name: {"sha256": "a" * 64, "bytes": 1} for name in (
                "java_version", "keytool_cacerts", "keytool_debug_keystore",
                "gradle_version", "apksigner_version", "apksigner_sign_verify")},
        }
        source_receipt = directory / "source-packet-receipt.json"
        source_receipt.write_bytes((old_packet / "receipt.json").read_bytes())
        source_plan = directory / "source-packet-plan.json"
        source_plan.write_bytes((old_packet / "evidence/compile-input/plan.json").read_bytes())
        dockerfile = directory / "Dockerfile"
        dockerfile.write_bytes((ROOT / "android/container/Dockerfile.phase1-client-tools").read_bytes())
        builder = directory / "build-phase1-client-tools.py"
        builder.write_bytes((ROOT / "android/container/build-phase1-client-tools.py").read_bytes())
        manifest = {
            "schema": 1, "kind": "phase1_immutable_client_tools_image_v1",
            "scope": "development_only_android_client_compile_and_apk_verification",
            "production_identity": False, "network_used": False, "image_id": image,
            "base_image_id": source_receipt_value["tools"]["image_id"],
            "source_container_id": source_receipt_value["tools"]["container_id"],
            "source_packet_receipt": packet.ref(source_receipt),
            "source_packet_plan": packet.ref(source_plan),
            "payload_inventory": {"sha256": packet.sha(inventory_path),
                "bytes": inventory_path.stat().st_size, "entries": len(inventory),
                "regular_files": sum(row["kind"] == "file" for row in inventory.values()),
                "payload_bytes": sum(row.get("bytes", 0) for row in inventory.values())},
            "required_files": {"count": len(required),
                "sha256": packet.sha_bytes(packet.canonical(required)), "files": required},
            "nonruntime_symlink_exclusions": packet.NONRUNTIME_TOOLS_SYMLINK_EXCLUSIONS,
            "java_runtime_closure": closure,
            "dockerfile": packet.ref(dockerfile),
            "builder": packet.ref(builder),
        }
        path = directory / "manifest.json"; path.write_bytes(packet.canonical(manifest))
        expected = packet.sha(path)
        actual = packet.authenticate_tools_image_manifest(path, expected, image)
        self.assertEqual(image, actual["manifest"]["image_id"])
        self.assertNotIn(packet.JAVA_HOME + "/lib/src.zip", inventory)
        wrong_owner_inventory = copy.deepcopy(inventory)
        wrong_owner_inventory[packet.JAVA_HOME]["uid"] = 1000
        inventory_path.write_bytes(packet.canonical(wrong_owner_inventory))
        wrong_owner_manifest = copy.deepcopy(manifest)
        wrong_owner_manifest["payload_inventory"]["sha256"] = packet.sha(inventory_path)
        wrong_owner_manifest["payload_inventory"]["bytes"] = inventory_path.stat().st_size
        path.write_bytes(packet.canonical(wrong_owner_manifest))
        with self.assertRaisesRegex(packet.PacketError, "payload inventory row"):
            packet.authenticate_tools_image_manifest(path, packet.sha(path), image)
        inventory_path.write_bytes(packet.canonical(inventory))
        path.write_bytes(packet.canonical(manifest))
        expected = packet.sha(path)
        original_builder = builder.read_bytes()
        builder.write_bytes(original_builder + b"# changed\n")
        with self.assertRaisesRegex(packet.PacketError, "build inputs"):
            packet.authenticate_tools_image_manifest(path, expected, image)
        builder.write_bytes(original_builder)
        forged = copy.deepcopy(manifest)
        forged["java_runtime_closure"]["parent_dependencies"]["/forged.so"] = "b" * 64
        path.write_bytes(packet.canonical(forged))
        with self.assertRaisesRegex(packet.PacketError, "omits or forges"):
            packet.authenticate_tools_image_manifest(path, packet.sha(path), image)
        omitted = copy.deepcopy(manifest)
        omitted["java_runtime_closure"]["parent_dependencies"].pop(resolved[0])
        path.write_bytes(packet.canonical(omitted))
        with self.assertRaisesRegex(packet.PacketError, "native dependency closure"):
            packet.authenticate_tools_image_manifest(path, packet.sha(path), image)
        changed = copy.deepcopy(manifest); changed["image_id"] = "sha256:" + "8" * 64
        path.write_bytes(packet.canonical(changed))
        with self.assertRaisesRegex(packet.PacketError, "out-of-band"):
            packet.authenticate_tools_image_manifest(path, expected, image)

    def test_security_compile_evidence_binds_live_canary_tests_lint_and_signed_payload(self):
        output = self.root / "packet"
        source = output / "source"
        manifest_name = "android/session-security/src/main/AndroidManifest.xml"
        canary_name = ("android/session-security/src/main/kotlin/org/wonad/desktop/security/"
                       "UpdateDataInstrumentation.kt")
        live_manifest = ROOT / manifest_name
        live_canary = ROOT / canary_name
        records = {}
        for name, live in ((manifest_name, live_manifest), (canary_name, live_canary)):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(live.read_bytes())
            records[name] = {"origin": "working-tree/" + name,
                             "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                             "bytes": target.stat().st_size}
        built = output / "evidence/built/security.apk"
        signed = output / "security.apk"
        built.parent.mkdir(parents=True)
        make_apk(built)
        signed.write_bytes(built.read_bytes())
        lint = output / "evidence/lint/session-security-lint-results-debug.xml"
        lint.parent.mkdir(parents=True)
        lint.write_text('<issues><issue severity="Warning" /></issues>')
        log = output / "evidence/gradle.log"
        log.write_text("BUILD SUCCESSFUL\n")
        build = {"tasks": [":session-security:testDebugUnitTest", ":session-security:lintDebug",
                           ":session-security:assembleDebug"],
                 "exit_code": 0,
                 "jvm": {"count": 1, "cases": [["org.wonad.desktop.security.CanaryTest", "works"]]},
                 "lint": {"files": 1, "warnings": 1}, "log": packet.ref(log)}
        artifact = {"package": "org.wonad.desktop.test", "test_only": True,
                    "privileged_manifest": False, "shared_uid": False,
                    "certificate_der_sha256": packet.WONAD_CERT,
                    "sha256": packet.sha(signed), "bytes": signed.stat().st_size}
        evidence = packet.security_compile_evidence(output, records, build, artifact, write=True)
        self.assertEqual(packet.UPDATE_CANARY_SHA256, evidence["canary_source_sha256"])
        self.assertEqual(1, evidence["tests"])
        self.assertEqual(evidence,
                         packet.security_compile_evidence(output, records, build, artifact, write=False))
        receipt = packet.load(output / packet.SECURITY_BUILD_RECEIPT)
        self.assertTrue(receipt["signing"]["payload_preserved"])
        self.assertEqual(0, receipt["build"]["lint_errors"])


if __name__ == "__main__":
    unittest.main()
