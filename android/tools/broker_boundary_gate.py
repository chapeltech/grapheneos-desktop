#!/usr/bin/env python3
"""Probe actual broker authentication from a separate unprivileged test APK.

Requires a passed keyboard baseline and already-installed test APK. Makes three
unauthorized Binder calls; requires precise security denials and an unchanged
live desktop. Does not adopt Shell permissions or claim general security proof.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time

from broker_native_gate import RUNNER
from keyboard_smoke import KeyboardSmoke

TEST_PACKAGE = "org.wonad.desktop.broker.test"


def check_result(output, fingerprint):
    expected = {"broker_boundary": "passed", "denied_calls": "3", "fingerprint": fingerprint,
                "native_abi": "x86_64", "scope": "wrong_uid_broker_authentication"}
    for field, value in expected.items():
        matches = re.findall(r"^INSTRUMENTATION_RESULT: " + re.escape(field) + r"=([^\r\n]*)", output, re.M)
        if matches != [value]:
            raise ValueError("Missing or ambiguous broker authentication evidence: " + field)
    if re.findall(r"^INSTRUMENTATION_CODE: ([^\r\n]*)", output, re.M) != ["-1"] or any(
            marker in output for marker in ("INSTRUMENTATION_FAILED", "shortMsg=", "failure_details=")):
        raise ValueError("Broker authentication instrumentation did not succeed")
    return {**expected, "denied_calls": 3}


class BoundarySmoke(KeyboardSmoke):
    def run_boundary(self, baseline):
        state, identities, tall, records, artifacts = self.resume_baseline(baseline)
        package = self.shell("pm", "path", TEST_PACKAGE)
        if not re.fullmatch(r"package:/[A-Za-z0-9_+/.=~-]+", package):
            raise ValueError("Expected one installed broker test APK")
        path = package.removeprefix("package:")
        checksum = self.shell("sha256sum", path).split()[0]
        if not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError("Invalid test APK checksum")
        output = self.shell("am", "instrument", "-w", "-r", "-e", "mode", "broker-boundary", RUNNER)
        result = check_result(output, self.fingerprint)
        # Repeated observations, not just an immediately cached snapshot.
        for _ in range(6):
            if self.service() != state or self.observe()[0] != records:
                raise ValueError("Unauthorized calls disturbed the live desktop")
            time.sleep(0.25)
        return {**result, "artifacts": artifacts, "test_apk": {"path": path, "sha256": checksum},
                "service": state, "run": self.run, "task_ids": identities,
                "desktop_unchanged": True, "full_backend_acceptance": "not_passed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--serial", required=True)
    parser.add_argument("--expected-fingerprint", required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    smoke = BoundarySmoke(args.adb, args.serial, args.expected_fingerprint, args.output)
    args.output.mkdir(parents=True, exist_ok=False)
    result = {"broker_boundary": "not_passed", "full_backend_acceptance": "not_passed"}
    try:
        result = smoke.run_boundary(json.loads(args.baseline.read_text()))
        return 0
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        result["error"] = str(error)
        return 1
    finally:
        (args.output / "commands.json").write_text(json.dumps(smoke.trace, indent=2) + "\n")
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    sys.exit(main())
