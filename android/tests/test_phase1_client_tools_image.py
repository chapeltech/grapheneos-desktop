"""Host-only closure tests for the immutable Phase-1 client tools image."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "android/container/build-phase1-client-tools.py"
SPEC = importlib.util.spec_from_file_location("phase1_client_tools_image", PATH)
tools_image = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tools_image)


class ClientToolsImageTest(unittest.TestCase):
    def test_packet_receipt_requires_exact_out_of_band_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_text("{}\n")
            with self.assertRaisesRegex(tools_image.FreezeError, "out-of-band"):
                tools_image.packet_tool_contract(path, "bad")
            with self.assertRaisesRegex(tools_image.FreezeError, "differs"):
                tools_image.packet_tool_contract(path, tools_image.SOURCE_PACKET_RECEIPT_SHA256)

    def test_exact_bootstrap_packet_reconstructs_the_sealed_required_mapping(self):
        path = ROOT / "android/out/phase1-emulator-client-packet-20261010-7/receipt.json"
        receipt, required = tools_image.packet_tool_contract(
            path, tools_image.SOURCE_PACKET_RECEIPT_SHA256)
        self.assertEqual(tools_image.SOURCE_PACKET_RECEIPT_SHA256, tools_image.sha256(path))
        self.assertEqual(tools_image.REQUIRED_TOOLS_FILE_COUNT, len(required))
        self.assertEqual(tools_image.REQUIRED_TOOLS_FILES_SHA256,
                         tools_image.hashlib.sha256(tools_image.canonical(required)).hexdigest())
        self.assertEqual(receipt["tools"]["fixture_keystore_sha256"],
                         required["/root/.android/debug.keystore"])

    def test_source_container_rejects_replacement_name_mount_or_image(self):
        expected = {"container_id": "1" * 64, "image_id": "sha256:" + "2" * 64}
        receipt = {"tools": expected}
        valid = {"Id": expected["container_id"], "Image": expected["image_id"],
                 "Name": "/wonad-android-gate-tools", "State": {"Running": True,
                 "Paused": False, "Dead": False}, "Mounts": [],
                 "HostConfig": {"Privileged": False, "PortBindings": {}}}
        mutations = {
            "identity": {"Id": "3" * 64},
            "image": {"Image": "sha256:" + "3" * 64},
            "name": {"Name": "/replacement"},
            "mount": {"Mounts": [{"Source": "/host"}]},
        }
        for name, changes in mutations.items():
            row = {**valid, **changes}
            with self.subTest(name=name), patch.object(tools_image, "inspect_one", return_value=row), \
                    self.assertRaisesRegex(tools_image.FreezeError, "identity/isolation"):
                tools_image.source_container(expected["container_id"], receipt)

    def test_reviewed_dangling_source_link_is_the_only_exclusion(self):
        source = {
            "/usr/lib/jvm/java-21-openjdk-amd64/lib/src.zip": {
                "kind": "symlink", "target": "../../openjdk-21/src.zip", "uid": 0, "gid": 0},
            "/usr/lib/jvm/java-21-openjdk-amd64/lib/security/cacerts": {
                "kind": "symlink", "target": "/etc/ssl/certs/java/cacerts", "uid": 0, "gid": 0},
            "/usr/lib/jvm/java-21-openjdk-amd64/docs": {
                "kind": "symlink", "target": "../../../share/doc/openjdk-21-jre-headless",
                "uid": 0, "gid": 0},
            "/etc/ssl/certs/java/cacerts": {
                "kind": "file", "mode": 0o644, "bytes": 1, "sha256": "1" * 64,
                "uid": 0, "gid": 0},
            "/usr/share/doc/openjdk-21-jre-headless": {
                "kind": "directory", "mode": 0o755, "uid": 0, "gid": 0},
        }
        selected = tools_image.select_payload_inventory(source)
        self.assertNotIn("/usr/lib/jvm/java-21-openjdk-amd64/lib/src.zip", selected)
        tools_image.reject_private_material(selected)
        self.assertIn("/etc/ssl/certs/java/cacerts", tools_image.SOURCE_PATHS)
        self.assertIn("/usr/share/doc/openjdk-21-jre-headless", tools_image.SOURCE_PATHS)

    def test_changed_or_missing_reviewed_exclusion_fails_closed(self):
        name = "/usr/lib/jvm/java-21-openjdk-amd64/lib/src.zip"
        for row in (None, {"kind": "symlink", "target": "../../../escape"},
                    {"kind": "file", "mode": 0o644, "bytes": 0, "sha256": "0" * 64}):
            source = {} if row is None else {name: row}
            with self.subTest(row=row), self.assertRaisesRegex(
                    tools_image.FreezeError, "non-runtime symlink changed"):
                tools_image.select_payload_inventory(source)

    def test_any_other_escaping_symlink_is_rejected(self):
        selected = {"/opt/android-sdk/escape": {"kind": "symlink", "target": "/host/private"}}
        with self.assertRaisesRegex(tools_image.FreezeError, "escapes the frozen roots"):
            tools_image.reject_private_material(selected)

    def test_ownership_is_bound_separately_from_docker_cp_content(self):
        source = {"/opt/android-sdk/tool": {"kind": "file", "mode": 0o755,
                  "bytes": 1, "sha256": "1" * 64, "uid": 0, "gid": 0}}
        copied = {name: {**row, "uid": 1000, "gid": 1000} for name, row in source.items()}
        self.assertEqual(tools_image.content_inventory(source),
                         tools_image.content_inventory(copied))
        tools_image.require_ownership(source, 0, 0, "source")
        tools_image.require_ownership(copied, 1000, 1000, "context")
        with self.assertRaisesRegex(tools_image.FreezeError, "ownership differs"):
            tools_image.require_ownership(copied, 0, 0, "final image")

    def test_private_key_material_is_rejected_except_exact_debug_keystore(self):
        ordinary = {"kind": "file", "mode": 0o600, "bytes": 1, "sha256": "1" * 64}
        tools_image.reject_private_material({"/root/.android/debug.keystore": ordinary})
        for path in ("/opt/android-sdk/private.pem", "/root/.gradle/release.keystore",
                     "/usr/lib/jvm/java-21-openjdk-amd64/secret.pk8"):
            with self.subTest(path=path), self.assertRaisesRegex(
                    tools_image.FreezeError, "private material"):
                tools_image.reject_private_material({path: ordinary})

    def test_missing_or_changed_required_file_is_rejected(self):
        path, digest = "/opt/android-sdk/tool", "1" * 64
        for inventory in ({}, {path: {"kind": "file", "sha256": "2" * 64}},
                          {path: {"kind": "symlink", "target": "/elsewhere"}}):
            with self.subTest(inventory=inventory), self.assertRaisesRegex(
                    tools_image.FreezeError, "Required tool/dependency differs"):
                tools_image.verify_required(inventory, {path: digest})

    def test_conflicting_required_paths_are_rejected(self):
        # Reuse the authenticated 437-entry mapping: this test exercises the
        # duplicate logical path conflict, not an invented dependency set.
        source_plan = ROOT / "android/out/phase1-emulator-client-packet-20261010-7/evidence/compile-input/plan.json"
        dependencies = json.loads(source_plan.read_text())["sdk_tools"]["offline_dependency_artifacts"]
        tools = {"tools": {"/opt/android-sdk/tool": "3" * 64},
                 "packet_specific_tools": {"/opt/android-sdk/tool": "4" * 64},
                 "fixture_keystore_sha256": "5" * 64}
        with self.assertRaisesRegex(tools_image.FreezeError, "Conflicting required tool"):
            tools_image.required_file_mapping(tools, dependencies)

    def test_image_ancestry_requires_exact_parent_plus_one_layer(self):
        image = "sha256:" + "1" * 64
        base_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        base = {"RootFS": {"Layers": ["parent-a", "parent-b"]},
                "Config": {"Env": ["PATH=" + base_path]}}
        valid = {"Id": image, "Architecture": "amd64", "Os": "linux",
                 "RootFS": {"Layers": ["parent-a", "parent-b", "payload"]},
                 "Config": {"Cmd": ["sleep", "infinity"],
                            "Env": ["PATH=" + tools_image.JAVA_HOME + "/bin:" + base_path,
                                    "JAVA_HOME=" + tools_image.JAVA_HOME]}}
        tools_image.validate_image_ancestry(valid, image, base)
        for row in ({**valid, "RootFS": {"Layers": ["parent-a", "other", "payload"]}},
                    {**valid, "RootFS": {"Layers": ["parent-a", "parent-b", "payload", "extra"]}},
                    {**valid, "Config": {"Cmd": ["sh"], "Env": valid["Config"]["Env"]}},
                    {**valid, "Config": {"Cmd": ["sleep", "infinity"],
                                          "Env": ["PATH=" + base_path]}}):
            with self.assertRaisesRegex(tools_image.FreezeError, "ancestry/configuration"):
                tools_image.validate_image_ancestry(row, image, base)

    def test_java_closure_binds_external_dependencies_to_parent(self):
        digest = "1" * 64
        inventory = {name: {"kind": "file", "mode": 0o755, "bytes": 1, "sha256": digest}
                     for name in tools_image.JAVA_RUNTIME_ELFS}
        jli = tools_image.JAVA_HOME + "/lib/libjli.so"
        ldd = ("libjli.so => %s (0x1)\n"
               "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x2)\n") % jli

        def command(_image, entrypoint, *arguments):
            if entrypoint == "/usr/bin/ldd": return ldd
            if entrypoint == "/usr/bin/python3.13":
                return "Verifies\nVerified using v3 scheme (APK Signature Scheme v3): true\n" + \
                    "Signer #1 certificate SHA-256 digest: " + \
                    tools_image.FIXTURE_CERTIFICATE_SHA256 + "\n"
            return "real command output\n"

        def hashes(image, paths):
            self.assertEqual(paths, ["/lib/x86_64-linux-gnu/libc.so.6"])
            return {paths[0]: "2" * 64}

        with patch.object(tools_image, "image_command", side_effect=command), \
                patch.object(tools_image, "image_hashes", side_effect=hashes) as image_hashes:
            closure = tools_image.java_runtime_closure("final", "parent", inventory)
        self.assertEqual(2, image_hashes.call_count)
        self.assertEqual({"/lib/x86_64-linux-gnu/libc.so.6": "2" * 64},
                         closure["parent_dependencies"])
        self.assertEqual([jli], closure["frozen_dependencies"])
        self.assertEqual(6, len(closure["smoke"]))

    def test_java_closure_rejects_parent_dependency_drift(self):
        digest = "1" * 64
        inventory = {name: {"kind": "file", "mode": 0o755, "bytes": 1, "sha256": digest}
                     for name in tools_image.JAVA_RUNTIME_ELFS}
        ldd = "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x2)\n"
        with patch.object(tools_image, "image_command", return_value=ldd), \
                patch.object(tools_image, "image_hashes", side_effect=[
                    {"/lib/x86_64-linux-gnu/libc.so.6": "2" * 64},
                    {"/lib/x86_64-linux-gnu/libc.so.6": "3" * 64},
                ]), self.assertRaisesRegex(tools_image.FreezeError, "authenticated parent"):
            tools_image.java_runtime_closure("final", "parent", inventory)


if __name__ == "__main__":
    unittest.main()
