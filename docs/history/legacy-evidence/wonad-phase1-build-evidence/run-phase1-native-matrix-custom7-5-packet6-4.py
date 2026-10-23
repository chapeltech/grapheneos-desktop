#!/usr/bin/env python3
"""Hardened admission for the future full packet6 native23 + GUI4 run.

The reviewed packet4 admission and final pair4 driver are each captured once
through a no-follow descriptor, authenticated as bounded stable regular-file
bytes, and executed from those exact bytes.  No import loader may reopen either
pathname.  The frozen matrix-input digest intentionally remains unresolved, so
this successor cannot yet perform even a real check-only admission.
"""

import argparse
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import types


ROOT = Path("/u/elric/tree/wonad")
EVIDENCE = Path("/u/elric/tree/wonad-phase1-build-evidence")
BASE_WRAPPER = EVIDENCE / "run-phase1-native-matrix-custom7-5-packet4-1.py"
BASE_WRAPPER_SHA = "1191e75b3d8bdd8ed6302297fcd0446e97c9699e43eee474c28144f8ef1d6f8a"
PAIR_DRIVER = EVIDENCE / "run-phase1-custom7-api-recents-packet6-20261011-4.py"
PAIR_DRIVER_SHA = "b2ecf91dfc4e046ca20180555cc88dbf35cdd428d14ef61b19412fe7344c4c47"
INPUTS = ROOT / "android/out/phase1-native-matrix-custom7-5-packet6-inputs-3/inputs.json"
INPUTS_SHA = "PENDING_FROZEN_PACKET6_INPUTS_SHA256"
OUTPUT = ROOT / "android/out/phase1-native-matrix-custom7-5-packet6-run-3"
IMAGE = "sha256:aa5e43bdc95a2a7ba3abcd581af4776d0a3ebb503314a4a1637159eb2a5febbb"
PAIR_IMAGE = "sha256:17b8fc30cee3a61bb692b1529d75d43c506a0cc4bd84a7b0cf4fda6502273500"
MAX_SOURCE_BYTES = 256 * 1024
MAX_CMDLINE_BYTES = 65536


def require(value, message):
    if not value:
        raise ValueError(message)


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


@dataclass(frozen=True)
class CapturedSource:
    path: Path
    data: bytes
    sha256: str
    expected_sha256: str
    file_identity: tuple


def capture_source(path, expected_sha256, *, max_bytes=MAX_SOURCE_BYTES):
    """Capture and authenticate one stable ordinary file without following it."""
    path = Path(path)
    require(re.fullmatch("[0-9a-f]{64}", expected_sha256) is not None,
            "Exact source SHA-256 is required")
    require(type(max_bytes) is int and 1 <= max_bytes <= 1024 * 1024,
            "Bounded source limit required")
    before_path = os.lstat(path)
    require(stat.S_ISREG(before_path.st_mode) and before_path.st_uid == os.getuid() and
            before_path.st_size <= max_bytes and before_path.st_size > 0 and
            before_path.st_mode & 0o022 == 0,
            "Owned, bounded, non-writable ordinary source required: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        require(identity(opened) == identity(before_path),
                "Source identity changed while opening: " + str(path))
        chunks = []
        observed = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            require(observed <= max_bytes, "Source exceeds bounded capture: " + str(path))
        after = os.fstat(fd)
        require(identity(after) == identity(opened) and observed == opened.st_size,
                "Source changed during capture: " + str(path))
    finally:
        os.close(fd)
    after_path = os.lstat(path)
    require(identity(after_path) == identity(opened),
            "Source pathname changed during capture: " + str(path))
    data = b"".join(chunks)
    actual = hashlib.sha256(data).hexdigest()
    require(actual == expected_sha256, "Authenticated source digest changed: " + str(path))
    return CapturedSource(path, data, actual, expected_sha256, identity(opened))


def execute_source(source, module_name, *, compiler=compile):
    """Compile and execute only already captured/authenticated bytes."""
    require(isinstance(source, CapturedSource) and
            hashlib.sha256(source.data).hexdigest() == source.sha256 == source.expected_sha256,
            "Captured source bytes do not match the authenticated digest")
    require(re.fullmatch("[A-Za-z_][A-Za-z0-9_]*", module_name) is not None,
            "Bounded isolated module name required")
    code = compiler(source.data, str(source.path), "exec", dont_inherit=True)
    module = types.ModuleType(module_name)
    module.__file__ = str(source.path)
    module.__loader__ = None
    module.__package__ = None
    exec(code, module.__dict__)
    return module


def read_cmdline(path, *, opener=os.open, reader=os.read, closer=os.close):
    fd = opener(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        chunks = []
        observed = 0
        while True:
            chunk = reader(fd, min(65536, MAX_CMDLINE_BYTES + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            require(observed <= MAX_CMDLINE_BYTES,
                    "Process command line exceeds bounded observation: " + str(path.parent.name))
    finally:
        closer(fd)
    return b"".join(chunks)


def hardened_process_kind(base, argv):
    kind = base.process_kind(argv)
    if kind is None and argv and Path(argv[0]).name == "qemu-kvm":
        return "emulator_or_qemu"
    return kind


def inspect_live_processes(base, *, proc_root=Path("/proc"), own_pid=None,
                           cmdline_reader=read_cmdline):
    """Replay the old classification while refusing unobservable live PIDs."""
    own_pid = os.getpid() if own_pid is None else own_pid
    blocked = []
    for item in proc_root.iterdir():
        if not item.name.isdecimal() or int(item.name) == own_pid:
            continue
        try:
            raw = cmdline_reader(item / "cmdline")
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            if error.errno in (errno.ENOENT, errno.ESRCH):
                continue
            raise ValueError("Cannot observe live process command line: PID " + item.name) from error
        if not raw:
            continue
        argv = [value.decode(errors="replace") for value in raw.rstrip(b"\0").split(b"\0")]
        kind = hardened_process_kind(base, argv)
        if kind is not None:
            blocked.append({"pid": int(item.name), "kind": kind,
                            "executable": Path(argv[0]).name,
                            "matching_names": sorted({Path(value).name for value in argv} &
                                                       base.BLOCKED_RUNNERS)})
    base.require(not blocked, "Live runtime/build/emulator process exists: " +
                 json.dumps(blocked, sort_keys=True))
    return {"blocked_processes": 0}


def configure(base, pair):
    require(base.COMMAND[-8:] == ["--output", str(base.OUTPUT), "--phase", "all",
            "--jobs", "2", "--timeout", "7200"] and
            base.RUNNER_SHA == "f29b136a2ea62c02c7c722f2746a4ce92b8ea666e87ba1c0656d028d7d68be8e",
            "Reviewed full native23/GUI4 command changed")
    require(pair.DEBUG_ID == base.DEBUG_ID and pair.DEBUG_PROOF == base.DEBUG_PROOF,
            "Reviewed pair/debug identity changed")
    base.INPUTS = INPUTS
    base.INPUTS_SHA = INPUTS_SHA
    base.OUTPUT = OUTPUT
    base.IMAGE = IMAGE
    base.PAIR_DRIVER = PAIR_DRIVER
    base.PAIR_DRIVER_SHA = PAIR_DRIVER_SHA
    base.PAIR_IMAGE = PAIR_IMAGE
    base.BLOCKED_RUNNERS = set(base.BLOCKED_RUNNERS) | {PAIR_DRIVER.name}
    base.COMMAND = [str(base.PYTHON), "-B", str(base.RUNNER), "run",
        "--inputs", str(INPUTS), "--output", str(OUTPUT), "--phase", "all",
        "--jobs", "2", "--timeout", "7200"]
    base.reviewed_pair_module = lambda: pair
    base.inspect_live_processes = lambda: inspect_live_processes(base)
    require(base.COMMAND == [str(base.PYTHON), "-B", str(base.RUNNER), "run",
            "--inputs", str(INPUTS), "--output", str(OUTPUT), "--phase", "all",
            "--jobs", "2", "--timeout", "7200"],
            "Exact full native23/GUI4 successor command changed")
    return base


def load_dependencies():
    base_source = capture_source(BASE_WRAPPER, BASE_WRAPPER_SHA)
    pair_source = capture_source(PAIR_DRIVER, PAIR_DRIVER_SHA)
    base = execute_source(base_source, "phase1_packet6_matrix_base_sealed")
    pair = execute_source(pair_source, "phase1_packet6_pair_driver_sealed")
    return configure(base, pair)


def main(argv=None):
    require(re.fullmatch("[0-9a-f]{64}", INPUTS_SHA) is not None,
            "Frozen packet6 matrix input digest is unresolved; freeze must complete first")
    base = load_dependencies()
    return base.main(argv)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BlockingIOError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
