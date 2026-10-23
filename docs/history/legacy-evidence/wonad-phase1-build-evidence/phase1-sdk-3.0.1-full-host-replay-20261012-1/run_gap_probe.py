#!/usr/bin/env python3
"""Retain the expected-failing contract-member probes as structured evidence."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import sys
import time
import unittest


HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "contract-member-gap-probe"


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write_new(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            count = os.write(descriptor, payload[offset:])
            if count <= 0:
                raise RuntimeError("short write")
            offset += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    if OUTPUT.exists() or OUTPUT.is_symlink():
        raise RuntimeError("gap-probe output must be absent")
    OUTPUT.mkdir(mode=0o700)
    sys.path.insert(0, str(HERE))
    selected = unittest.defaultTestLoader.loadTestsFromName(
        "test_contract_member_binding_gaps")
    stream = io.StringIO()
    started = time.monotonic_ns()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(selected)
    ended = time.monotonic_ns()
    raw = stream.getvalue().encode()
    write_new(OUTPUT / "test-output.txt", raw)
    record = {
        "schema": 1,
        "kind": "wonad-sdk-3.0.1-contract-member-expected-red-v1",
        "expected_red": True,
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "unexpected_success": result.wasSuccessful(),
        "started_monotonic_ns": started,
        "ended_monotonic_ns": ended,
        "probe": {"path": "../test_contract_member_binding_gaps.py",
                  "sha256": sha256(HERE / "test_contract_member_binding_gaps.py")},
        "tested_production": {
            "native_current_compile_acceptance.py": sha256(
                HERE / "corrected/android/tools/native_current_compile_acceptance.py"),
            "phase1_provenance.py": sha256(
                HERE / "corrected/android/tools/phase1_provenance.py"),
        },
        "test_output": {"path": "test-output.txt",
                        "sha256": sha256(OUTPUT / "test-output.txt"),
                        "bytes": len(raw)},
        "scope": "pure host functions; no subprocess, Docker, Gradle, JVM, build, VM, key, or publication",
    }
    write_new(OUTPUT / "result.json",
              (json.dumps(record, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0 if result.testsRun == 3 and len(result.failures) == 3 and not result.errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
