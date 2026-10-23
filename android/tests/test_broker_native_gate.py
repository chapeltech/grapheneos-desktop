from contextlib import redirect_stderr
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import broker_native_gate as gate

FINGERPRINT = "Android/sdk_phone64_x86_64/emu64x:17/ID/wonad.2026092500:userdebug/test-keys"
PASS = "\n".join("INSTRUMENTATION_RESULT: " + field + "=" + value for field, value in {
    "wonad_broker_core": "passed", "tests": "40", "failures": "0",
    "fingerprint": FINGERPRINT, "native_abi": "x86_64",
    "scope": "unprivileged_rust_jni_probe", "wm_broker": "not_tested",
}.items()) + "\nINSTRUMENTATION_CODE: -1\n"


class BrokerNativeGate(unittest.TestCase):
    def test_success_is_not_privileged_broker_evidence(self):
        result = gate.check_result(PASS, FINGERPRINT)
        self.assertEqual("passed", result["wonad_broker_core"])
        self.assertEqual("not_tested", result["wm_broker"])
        self.assertEqual(40, result["tests"])

    def test_missing_ambiguous_or_failing_results_are_rejected(self):
        for output in ("", PASS + PASS, PASS.replace("tests=40", "tests=0"),
                       PASS.replace("tests=40", "tests=36"),
                       PASS.replace("tests=40", "tests=37"),
                       PASS.replace("tests=40", "tests=39"),
                       PASS.replace("failures=0", "failures=1"),
                       PASS.replace(FINGERPRINT, "a-different-build"),
                       PASS.replace("native_abi=x86_64", "native_abi=arm64-v8a"),
                       PASS.replace("CODE: -1", "CODE: 0"),
                       PASS.replace("wm_broker=not_tested", "wm_broker=passed"),
                       PASS + "INSTRUMENTATION_FAILED: crash", PASS + "shortMsg=crash",
                       PASS + "INSTRUMENTATION_RESULT: failure_details=error"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                gate.check_result(output, FINGERPRINT)

    def test_phone_is_rejected_before_adb(self):
        with patch.object(sys, "argv", ["gate", "--serial", "pixel8",
                                       "--expected-fingerprint", FINGERPRINT]), \
                patch.object(subprocess, "check_output") as command, redirect_stderr(io.StringIO()):
            self.assertEqual(1, gate.main())
            command.assert_not_called()

    def test_security_or_fingerprint_mismatch_prevents_instrumentation(self):
        from platform_gate import Experiment
        for answers in (["offline"], ["device", "0"], ["device", "1", "Permissive"],
                        ["device", "1", "Enforcing", "arm64-v8a"],
                        ["device", "1", "Enforcing", "x86_64", "wrong-build"]):
            experiment = Experiment("adb", "emulator-5580", FINGERPRINT, Path("."))
            with patch.object(experiment, "command", side_effect=answers) as command, \
                    self.assertRaises(ValueError):
                gate.run_gate(experiment)
            self.assertFalse(any("instrument" in call.args for call in command.call_args_list))


if __name__ == "__main__":
    unittest.main()
