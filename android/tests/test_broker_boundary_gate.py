from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from broker_boundary_gate import BoundarySmoke, check_result

PASS = "\n".join("INSTRUMENTATION_RESULT: " + k + "=" + v for k, v in {
    "broker_boundary": "passed", "denied_calls": "3", "fingerprint": "image",
    "native_abi": "x86_64", "scope": "wrong_uid_broker_authentication",
}.items()) + "\nINSTRUMENTATION_CODE: -1\n"


class BoundaryGateChecks(unittest.TestCase):
    def test_all_three_actual_calls_and_exact_image_are_required(self):
        self.assertEqual(3, check_result(PASS, "image")["denied_calls"])
        for output in ("", PASS + PASS, PASS.replace("denied_calls=3", "denied_calls=0"),
                       PASS.replace("fingerprint=image", "fingerprint=other"),
                       PASS.replace("CODE: -1", "CODE: 0"),
                       PASS + "INSTRUMENTATION_RESULT: failure_details=timeout"):
            with self.assertRaises(ValueError):
                check_result(output, "image")

    def test_device_attestation_precedes_any_instrumentation(self):
        check = BoundarySmoke("adb", "emulator-5580", "image", Path("unused"))
        with patch.object(check, "resume_baseline", side_effect=ValueError("wrong image")), \
                patch.object(check, "shell") as shell, self.assertRaisesRegex(ValueError, "wrong image"):
            check.run_boundary({})
        shell.assert_not_called()

    def test_delayed_desktop_change_is_not_accepted(self):
        check = BoundarySmoke("adb", "emulator-5580", "image", Path("unused"))
        state, records = {"generation": 1}, {"app": {"task": 1}}
        with patch.object(check, "resume_baseline", return_value=(state, {}, {}, records, {})), \
                patch.object(check, "shell", side_effect=["package:/data/app/test.apk", "a" * 64, PASS]), \
                patch.object(check, "service", side_effect=[state, {"generation": 2}]), \
                patch.object(check, "observe", return_value=(records, set())), \
                patch("broker_boundary_gate.time.sleep"), \
                self.assertRaisesRegex(ValueError, "disturbed"):
            check.run_boundary({})

    def test_physical_device_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "emulator-only"):
            BoundarySmoke("adb", "physical-phone", "image", Path("unused"))
