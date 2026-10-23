#!/usr/bin/env python3
"""Prepared custom7/packet6 full native23 + serialized GUI4 wrapper.

This thin successor authenticates and reuses the already reviewed packet4
admission implementation, changing only the fresh immutable image, pair driver,
frozen inputs and output identities.  It remains deliberately unexecutable
until the pair4-driver and frozen-input digests are published and reviewed.
"""

import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path("/u/elric/tree/wonad")
EVIDENCE = Path("/u/elric/tree/wonad-phase1-build-evidence")
BASE_WRAPPER = EVIDENCE / "run-phase1-native-matrix-custom7-5-packet4-1.py"
BASE_WRAPPER_SHA = "1191e75b3d8bdd8ed6302297fcd0446e97c9699e43eee474c28144f8ef1d6f8a"
INPUTS = ROOT / "android/out/phase1-native-matrix-custom7-5-packet6-inputs-3/inputs.json"
INPUTS_SHA = "PENDING_FROZEN_PACKET6_INPUTS_SHA256"
OUTPUT = ROOT / "android/out/phase1-native-matrix-custom7-5-packet6-run-3"
IMAGE = "sha256:aa5e43bdc95a2a7ba3abcd581af4776d0a3ebb503314a4a1637159eb2a5febbb"
PAIR_DRIVER = EVIDENCE / "run-phase1-custom7-api-recents-packet6-20261011-4.py"
PAIR_DRIVER_SHA = "b2ecf91dfc4e046ca20180555cc88dbf35cdd428d14ef61b19412fe7344c4c47"
PAIR_IMAGE = "sha256:17b8fc30cee3a61bb692b1529d75d43c506a0cc4bd84a7b0cf4fda6502273500"


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    require(path.is_file() and not path.is_symlink() and path.resolve(strict=True) == path,
            "Missing or aliased reviewed base wrapper")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def reviewed_base():
    require(digest(BASE_WRAPPER) == BASE_WRAPPER_SHA,
            "Reviewed full native23/GUI4 admission wrapper changed")
    spec = importlib.util.spec_from_file_location("phase1_packet6_matrix_base", BASE_WRAPPER)
    require(spec is not None and spec.loader is not None, "Cannot load reviewed matrix wrapper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(module.COMMAND[-8:] == ["--output", str(module.OUTPUT), "--phase", "all",
            "--jobs", "2", "--timeout", "7200"] and
            module.RUNNER_SHA == "f29b136a2ea62c02c7c722f2746a4ce92b8ea666e87ba1c0656d028d7d68be8e",
            "Reviewed full native23/GUI4 command changed")
    return module


def main():
    require(re.fullmatch("[0-9a-f]{64}", INPUTS_SHA) is not None,
            "Frozen packet6 matrix input digest is unresolved; freeze must complete first")
    require(re.fullmatch("[0-9a-f]{64}", PAIR_DRIVER_SHA) is not None,
            "Final pair4 driver digest is unresolved")
    module = reviewed_base()
    module.INPUTS = INPUTS
    module.INPUTS_SHA = INPUTS_SHA
    module.OUTPUT = OUTPUT
    module.IMAGE = IMAGE
    module.PAIR_DRIVER = PAIR_DRIVER
    module.PAIR_DRIVER_SHA = PAIR_DRIVER_SHA
    module.PAIR_IMAGE = PAIR_IMAGE
    module.BLOCKED_RUNNERS = set(module.BLOCKED_RUNNERS) | {PAIR_DRIVER.name}
    module.COMMAND = [str(module.PYTHON), "-B", str(module.RUNNER), "run",
        "--inputs", str(INPUTS), "--output", str(OUTPUT), "--phase", "all",
        "--jobs", "2", "--timeout", "7200"]
    return module.main()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BlockingIOError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
