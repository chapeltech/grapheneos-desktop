"""Host-only checks for packet7 native4/derived6/wrong-bundle7 preparation."""

import contextlib
import importlib.util
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
ROOT = Path("/u/elric/tree/wonad")
NATIVE3 = HERE / "run-phase1-native-candidate-custom7-5-3.sh"
NATIVE4 = HERE / "run-phase1-native-candidate-custom7-5-4.sh"
DERIVED5 = HERE / "run-phase1-conformance-candidate-custom7-5-5.sh"
DERIVED6_PREBIND = HERE / "phase1-conformance-candidate-custom7-5-6-prebinding-20261011-1.sh"
DERIVED6 = HERE / "run-phase1-conformance-candidate-custom7-5-6.sh"
WRONG7 = HERE / "run-phase1-wrong-signer-bundle7-20261011-1.py"
WRONG7_TEST_OUTPUT = ROOT / "android/out/phase1-wrong-signer-bundle-20261011-7-host-preflight-only"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read(path):
    return path.read_text(errors="strict")


def constants(path):
    return dict(re.findall(r"^readonly ([a-z0-9_]+)=(.*)$", read(path), flags=re.MULTILINE))


class Packet7CandidatePreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native3 = read(NATIVE3)
        cls.native4 = read(NATIVE4)
        cls.derived5 = read(DERIVED5)
        cls.derived6_prebind = read(DERIVED6_PREBIND)
        cls.derived6 = read(DERIVED6)
        cls.wrong = load(WRONG7, "phase1_wrong_bundle7_preparation")

    def test_shell_launchers_are_syntactically_valid(self):
        for path in (NATIVE4, DERIVED6):
            result = subprocess.run(["/bin/bash", "-n", str(path)], text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(0, result.returncode, result.stderr)

    def test_native4_preserves_native3_trust_and_resource_profile(self):
        old, new = constants(NATIVE3), constants(NATIVE4)
        for name in ("repo", "python", "python_target", "python_sha", "builder", "builder_sha",
                     "x86", "x86_sha", "packet_tool", "packet_tool_sha", "product", "baseline",
                     "custom", "custom_sha", "comparison", "base"):
            self.assertEqual(old[name], new[name], name)
        for exact in (
            "(( mem_kib >= 12 * 1024 * 1024 ))",
            "(( u_free >= 16 * gib ))",
            "(( tmp_free >= 4 * gib ))",
            "(( docker_free >= 16 * gib ))",
            '--phase1-build-evidence',
            '--phase1-comparison "$comparison"',
            '--phase1-baseline-receipt "$baseline"',
            '--phase1-custom-receipt "$custom"',
            '--phase1-client-packet "$packet"',
        ):
            self.assertIn(exact, self.native3)
            self.assertIn(exact, self.native4)
        self.assertIn("phase1-emulator-client-packet-20261011-7", self.native4)
        self.assertIn("phase1-native-candidate-custom7-5-4", self.native4)
        self.assertIn("wonad:native-v3-candidate-phase1-custom7-5-4", self.native4)

    def test_native4_binds_actual_packet7_records_before_and_after_audit(self):
        pins = {
            "packet_sha": "5d5737ebe26048152fccfb4881cd89fb4b583ca2df0cfc84fbe8d023799cc459",
            "packet_wonad_sha": "7494132416df3b4957ca944bdf5657be3d6e1df2a6eca74833462702d4d1e2ac",
            "packet_update_sha": "1eef12a24e976bf4711c8c2e2872096436f28621c6ebe07c0151dd37aa29e177",
            "packet_conformance_update_sha": "2febd46ac4870fafe053798258a450ef328f39887d680cbeeab4d0bc033b2293",
            "packet_wonad_cert_sha": "65e326ada8f623cd6e1852d6fefba8262f445bcd5949966e10361c6d770c70a3",
            "packet_platform_cert_sha": "9837de028f460c35cc8d3fa45f14eecce30f6fbfe4b93d399aef1acb80c20d14",
        }
        current = constants(NATIVE4)
        for name, value in pins.items():
            self.assertEqual(value, current[name])
        for path, variable in (
            ("receipt.json", "packet_sha"),
            ("wonad.apk", "packet_wonad_sha"),
            ("version-update/preparation-receipt.json", "packet_update_sha"),
            ("conformance-version-update/preparation-receipt.json", "packet_conformance_update_sha"),
            ("evidence/certificates/wonad.x509.pem", "packet_wonad_cert_sha"),
            ("evidence/certificates/platform.x509.pem", "packet_platform_cert_sha"),
        ):
            self.assertEqual(2, self.native4.count(f'exact_sha "$packet/{path}" "${variable}"'))

    def test_derived6_single_delta_binds_actual_native4_and_preserves_pending_guard(self):
        actual = "sha256:1b2336859e12d70ce10a2e96e1f4d4c1dcd40ddf027bd8b647f63cba0d92d051"
        self.assertEqual("25a1cb8b9b9206f4be092ff669d7baeacf73bd8fee4c74125e4f28a7d6562c36",
                         hashlib.sha256(DERIVED6_PREBIND.read_bytes()).hexdigest())
        self.assertEqual(self.derived6_prebind.replace("readonly native_image=PENDING",
                                                       "readonly native_image=" + actual),
                         self.derived6)
        result = subprocess.run(["/bin/bash", str(DERIVED6), "sha256:" + "0" * 64], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(65, result.returncode)
        self.assertIn("only the authenticated native4 image", result.stderr)
        result = subprocess.run(["/bin/bash", "-s", "--", "sha256:" + "0" * 64],
                                input=self.derived6_prebind, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(78, result.returncode)
        self.assertIn("remains PENDING", result.stderr)

    def test_derived6_preserves_builder_profile_and_exact_four_bundled_sources(self):
        old, new = constants(DERIVED5), constants(DERIVED6)
        for name in ("repo", "python", "python_target", "python_sha", "builder", "builder_sha",
                     "native_builder", "native_builder_sha", "packet_tool", "packet_tool_sha",
                     "product", "common_source", "common_source_sha", "guest_source",
                     "guest_source_sha", "api_auditor", "api_auditor_sha"):
            self.assertEqual(old[name], new[name], name)
        self.assertEqual("d193c2641d3ceebb7bc498308181a4d0b02b0d0701544e343ad059b4917b3dd5",
                         new["smoke_source_sha"])
        builder = read(ROOT / "android/container/build-phase1-conformance-candidate.py")
        source_block = builder.split("SOURCE_FILES = {", 1)[1].split("}\n", 1)[0]
        self.assertEqual({"conformance_smoke.py", "common.py", "driver.py", "acceptance.py"},
                         set(re.findall(r'^\s*"([^"]+)":', source_block, flags=re.MULTILINE)))
        for name in ("smoke_source", "common_source", "guest_source", "api_auditor"):
            self.assertEqual(2, self.derived6.count(f'exact_sha "${name}" "${name}_sha"'))
        self.assertNotIn("recents_guest_auditor", self.derived6)
        self.assertIn("phase1-native-candidate-custom7-5-4", self.derived6)
        self.assertIn("phase1-conformance-candidate-custom7-5-6", self.derived6)

    def test_wrong_bundle7_preflight_is_read_only_and_fully_packet_bound(self):
        self.assertFalse(WRONG7_TEST_OUTPUT.exists())
        with mock.patch.object(self.wrong, "OUTPUT", WRONG7_TEST_OUTPUT):
            record = self.wrong.preflight()
        self.assertEqual("prepared_not_executed", record["status"])
        self.assertEqual("5d5737ebe26048152fccfb4881cd89fb4b583ca2df0cfc84fbe8d023799cc459",
                         record["packet_receipt_sha256"])
        self.assertFalse(record["private_keys_consumed"])
        self.assertFalse(record["runtime_qualified"])
        self.assertFalse(record["guests_started"])
        self.assertFalse(WRONG7_TEST_OUTPUT.exists())
        command = record["command"]
        self.assertEqual([str(self.wrong.PYTHON), "-B", str(self.wrong.CONVERTER)], command[:3])
        self.assertNotIn("--keystore", command)
        self.assertNotIn("--signer", command)
        self.assertNotIn("--private-key", command)
        receipt = json.loads((self.wrong.PACKET / "receipt.json").read_text())
        self.assertEqual(set(self.wrong.EXPECTED_SIGNERS), set(receipt["signers"]))

    def test_wrong_bundle7_execute_switch_only_delegates_exact_reviewed_command(self):
        self.assertFalse(WRONG7_TEST_OUTPUT.exists())
        with mock.patch.object(self.wrong, "OUTPUT", WRONG7_TEST_OUTPUT), \
                mock.patch.object(self.wrong.os, "execve") as execute:
            expected = self.wrong.command()
            self.assertIsNone(self.wrong.main(["--execute-after-root-authorization"]))
        execute.assert_called_once()
        path, argv, environment = execute.call_args.args
        self.assertEqual(str(self.wrong.PYTHON), path)
        self.assertEqual(expected, argv)
        self.assertEqual("1", environment["PYTHONDONTWRITEBYTECODE"])
        self.assertFalse(WRONG7_TEST_OUTPUT.exists())

    def test_missing_authorization_cannot_launch_any_producer(self):
        result = subprocess.run(["/bin/bash", str(NATIVE4)], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(64, result.returncode)
        self.assertIn("usage:", result.stderr)
        output = io.StringIO()
        self.assertFalse(WRONG7_TEST_OUTPUT.exists())
        with mock.patch.object(self.wrong, "OUTPUT", WRONG7_TEST_OUTPUT), \
                contextlib.redirect_stdout(output):
            self.assertEqual(0, self.wrong.main([]))
        self.assertIn('"status": "prepared_not_executed"', output.getvalue())
        self.assertFalse(WRONG7_TEST_OUTPUT.exists())


if __name__ == "__main__":
    unittest.main()
