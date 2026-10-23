#!/usr/bin/env python3
"""Run the unprivileged Kotlin/Rust JNI tests, not the privileged WM broker.

The test APK must already be installed. Requires an explicit emulator and exact
OS fingerprint; never roots, changes security settings or selects a phone.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

from platform_gate import Experiment

RUNNER = "org.wonad.desktop.broker.test/org.wonad.desktop.broker.NativeBrokerInstrumentation"
EXPECTED_TESTS = 40


def check_result(output, fingerprint):
    expected = {"wonad_broker_core": "passed", "tests": str(EXPECTED_TESTS), "failures": "0",
                "fingerprint": fingerprint, "native_abi": "x86_64",
                "scope": "unprivileged_rust_jni_probe", "wm_broker": "not_tested"}
    for field, value in expected.items():
        found = re.findall(r"^INSTRUMENTATION_RESULT: " + re.escape(field) +
                           r"=([^\r\n]*)", output, re.M)
        if found != [value]:
            raise ValueError("missing or ambiguous Rust JNI evidence: " + field)
    if re.findall(r"^INSTRUMENTATION_CODE: ([^\r\n]*)", output, re.M) != ["-1"]:
        raise ValueError("Rust JNI instrumentation did not finish successfully")
    if any(marker in output for marker in ("INSTRUMENTATION_FAILED", "shortMsg=", "failure_details=")):
        raise ValueError("Rust JNI instrumentation reported failure")
    return {**expected, "tests": EXPECTED_TESTS, "failures": 0, "selinux": "Enforcing",
            "grapheneos_hardening": "not_verified", "pixel8_hardware": "not_tested"}


def run_gate(experiment):
    experiment.validate()
    output = experiment.shell("am", "instrument", "-w", "-r", RUNNER)
    return check_result(output, experiment.fingerprint)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--expected-fingerprint", required=True)
    args = parser.parse_args()
    try:
        experiment = Experiment(args.adb, args.serial, args.expected_fingerprint, Path("."))
        print(json.dumps(run_gate(experiment), indent=2))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"wonad_broker_core": "not_passed", "wm_broker": "not_tested",
                          "error": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
