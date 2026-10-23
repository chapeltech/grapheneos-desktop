import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
DRIVER_PATH = HERE / "run-phase1-emulator-client-packet7-20261011-1.py"
PACKET6_PATH = HERE / "run-phase1-emulator-client-packet6-20261011-1.py"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DRIVER = load(DRIVER_PATH, "phase1_packet7_driver")
PACKET6 = load(PACKET6_PATH, "phase1_packet6_driver")


class Packet7DraftTests(unittest.TestCase):
    def test_pending_or_missing_pin_fails_before_any_observation_or_execution(self):
        forbidden = AssertionError("unresolved receipt reached a side effect")
        for value in (None, "", "PENDING", "0" * 63, "G" * 64):
            with self.subTest(value=value), \
                    mock.patch.object(DRIVER, "EXPECTED_SUCCESSOR_RECEIPT_SHA256", value), \
                    mock.patch.object(DRIVER, "literal", side_effect=forbidden) as literal, \
                    mock.patch.object(DRIVER, "digest", side_effect=forbidden) as digest, \
                    mock.patch.object(DRIVER.os, "getuid", side_effect=forbidden) as getuid, \
                    mock.patch.object(DRIVER.os, "getgid", side_effect=forbidden) as getgid, \
                    mock.patch.object(DRIVER.os, "execve", side_effect=forbidden) as execve:
                with self.assertRaisesRegex(ValueError, r"^NOT READY: .* PENDING$"):
                    DRIVER.preflight()
                literal.assert_not_called()
                digest.assert_not_called()
                getuid.assert_not_called()
                getgid.assert_not_called()
                execve.assert_not_called()

    def test_execute_cannot_bypass_pending_pin_or_create_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "packet7"
            with mock.patch.object(DRIVER, "OUTPUT", output), \
                    mock.patch.object(DRIVER, "EXPECTED_SUCCESSOR_RECEIPT_SHA256", "PENDING"), \
                    mock.patch.object(sys, "argv", [str(DRIVER_PATH), "--execute"]), \
                    mock.patch.object(DRIVER.os, "execve") as execve:
                with self.assertRaisesRegex(ValueError, r"^NOT READY:"):
                    DRIVER.main()
                self.assertFalse(output.exists())
                execve.assert_not_called()

    def test_command_is_exact_fresh_successor18_packet7_build(self):
        self.assertEqual(Path("/usr/bin/python3.14"), DRIVER.PYTHON)
        self.assertEqual(
            Path("/u/elric/tree/wonad/android/out/"
                 "native-current-successor-12-phase1-v3-runtime-20261011-18"),
            DRIVER.SUCCESSOR,
        )
        self.assertEqual(
            Path("/u/elric/tree/wonad/android/out/phase1-emulator-client-packet-20261011-7"),
            DRIVER.OUTPUT,
        )
        self.assertEqual("build", DRIVER.command()[3])
        self.assertEqual(1, DRIVER.command().count("--successor"))
        self.assertEqual(1, DRIVER.command().count("--output"))
        self.assertEqual(str(DRIVER.SUCCESSOR), DRIVER.command()[DRIVER.command().index("--successor") + 1])
        self.assertEqual(str(DRIVER.OUTPUT), DRIVER.command()[DRIVER.command().index("--output") + 1])

    def test_packet6_tool_signer_and_public_identity_are_preserved(self):
        for name in ("PYTHON", "BUILDER", "BUILDER_SHA256", "SIGNER", "PUBLIC_CERT",
                     "PLATFORM_ROOT", "TOOLS_IMAGE", "TOOLS_MANIFEST",
                     "TOOLS_MANIFEST_SHA256", "SUCCESSOR_FILES"):
            self.assertEqual(getattr(PACKET6, name), getattr(DRIVER, name), name)
        self.assertEqual(
            "65e326ada8f623cd6e1852d6fefba8262f445bcd5949966e10361c6d770c70a3",
            DRIVER.PUBLIC_CERT_SHA256,
        )
        self.assertEqual(
            "09f786a9e86ada4576be8ace27997959bca7c959f45651d5376afa7aeaab4211",
            DRIVER.PREVIOUS_PACKET_RECEIPT_SHA256,
        )

    def test_receipt_is_not_operator_selectable(self):
        with mock.patch.object(
                sys, "argv",
                [str(DRIVER_PATH), "--expected-successor-receipt-sha256", "0" * 64]), \
                mock.patch.object(DRIVER, "preflight") as preflight, \
                self.assertRaises(SystemExit) as failure:
            DRIVER.main()
        self.assertEqual(2, failure.exception.code)
        preflight.assert_not_called()


if __name__ == "__main__":
    unittest.main()
