#!/usr/bin/env python3
"""Prepared admission for a future packet7 native23 + serialized GUI4 run.

Every unpublished identity is deliberately a literal ``PENDING_*`` value.
The pending gate executes before source loading, lock creation, Docker access,
auditor execution, or output inspection.  Once separately reviewed identities
replace those literals, this wrapper captures the reviewed predecessor and the
exact pair6 driver through no-follow descriptors and executes only those bytes.
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
PAIR_DRIVER = EVIDENCE / "run-phase1-custom7-api-recents-packet7-20261011-6.py"
PAIR_DRIVER_SHA = "4453baf396587587d1e2d7825ddb548536a4d8e88f4e3baf2b43fbf06a910f40"
PACKET = ROOT / "android/out/phase1-emulator-client-packet-20261011-7"
PACKET_SHA = "5d5737ebe26048152fccfb4881cd89fb4b583ca2df0cfc84fbe8d023799cc459"
WRONG = ROOT / "android/out/phase1-wrong-signer-bundle-20261011-7/signing-receipt.json"
WRONG_SHA = "PENDING_ACTUAL_WRONG7_SIGNING_RECEIPT_SHA256"
INPUTS = ROOT / "android/out/phase1-native-matrix-custom7-5-packet7-inputs-5/inputs.json"
INPUTS_SHA = "PENDING_FROZEN_PACKET7_INPUTS_SHA256"
OUTPUT = ROOT / "android/out/phase1-native-matrix-custom7-5-packet7-run-5"
IMAGE = "PENDING_ACTUAL_NATIVE4_IMMUTABLE_IMAGE_ID"
PAIR_IMAGE = "PENDING_ACTUAL_DERIVED6_IMMUTABLE_IMAGE_ID"
PAIR_API_REPORT = (ROOT / "android/out/phase1-evidence-custom7-5/"
                   "runtime-api-packet7-20261011-6/report.json")
PAIR_API_REPORT_SHA = "PENDING_ACTUAL_PAIR6_API_REPORT_SHA256"
PAIR_RECENTS_REPORT = (ROOT / "android/out/phase1-evidence-custom7-5/"
                       "runtime-recents-packet7-20261011-6/report.json")
PAIR_RECENTS_REPORT_SHA = "PENDING_ACTUAL_PAIR6_RECENTS_REPORT_SHA256"
MAX_SOURCE_BYTES = 256 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_CMDLINE_BYTES = 65536
HEX64 = re.compile(r"[0-9a-f]{64}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")

# Names are matched against every argv element, not only argv[0].  This closes
# wrappers such as ``python -B /path/to/build_native_successor.py`` while
# retaining all classifications inherited from the reviewed predecessor.
EXTRA_BLOCKED_RUNNERS = {
    PAIR_DRIVER.name,
    "phase1_emulator_client_packet.py",
    "build_native_successor.py",
    "native_compile_finalize.py",
    "convert_packet_wrong_signer.py",
    "build-native-candidate.py",
    "build-phase1-conformance-candidate.py",
    "phase1_conformance_guest.py",
    "run_phase1_conformance_recents_guest.py",
    "run_native_matrix.py",
    "run_phase1_runtime_qualification.py",
    "run_phase1_upstream_guest.py",
    "run_phase1_upstream_tests.py",
    "run_x86_build.py",
    "run_x86_emulator_build.py",
    "run_frankel_build.py",
}


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
    """Capture one owned stable ordinary file without following a symlink."""
    path = Path(path)
    require(HEX64.fullmatch(str(expected_sha256)) is not None,
            "Exact source SHA-256 is required")
    require(type(max_bytes) is int and 1 <= max_bytes <= 4 * 1024 * 1024,
            "Bounded source limit required")
    before_path = os.lstat(path)
    require(stat.S_ISREG(before_path.st_mode) and before_path.st_uid == os.getuid() and
            0 < before_path.st_size <= max_bytes and before_path.st_mode & 0o022 == 0,
            "Owned, bounded, non-writable ordinary source required: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        require(identity(opened) == identity(before_path),
                "Source identity changed while opening: " + str(path))
        chunks, observed = [], 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            require(observed <= max_bytes,
                    "Source exceeds bounded capture: " + str(path))
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
    require(actual == expected_sha256,
            "Authenticated source digest changed: " + str(path))
    return CapturedSource(path, data, actual, expected_sha256, identity(opened))


def execute_source(source, module_name, *, compiler=compile):
    """Compile and execute only already captured/authenticated bytes."""
    require(isinstance(source, CapturedSource) and
            hashlib.sha256(source.data).hexdigest() == source.sha256 == source.expected_sha256,
            "Captured source bytes do not match the authenticated digest")
    require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", module_name) is not None,
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
        chunks, observed = [], 0
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
    if kind is not None:
        return kind
    if not argv:
        return None
    names = {Path(value).name for value in argv}
    executable = Path(argv[0]).name
    if executable == "qemu-kvm":
        return "emulator_or_qemu"
    if names & EXTRA_BLOCKED_RUNNERS:
        return "phase1_runner_or_build"
    if any((name.startswith("run-phase1-native-matrix-") or
            name.startswith("freeze-phase1-native-matrix-") or
            (name.startswith("run-phase1-") and "api-recents" in name))
           for name in names):
        return "phase1_runner_or_build"
    wrapper_prefixes = ("run-", "freeze-", "prepare-", "build-", "continue-")
    lane_markers = ("packet", "successor", "native-candidate",
                    "conformance-candidate", "native-matrix", "api-recents",
                    "runtime-qualification", "frankel-build", "x86-build")
    if any(name.startswith(wrapper_prefixes) and "phase1" in name and
           any(marker in name for marker in lane_markers) for name in names):
        return "phase1_runner_or_build"
    if "native-x11-keyboard-smoke.py" in names:
        return "native_gate"
    return None


def inspect_live_processes(base, *, proc_root=Path("/proc"), own_pid=None,
                           cmdline_reader=read_cmdline):
    """Replay old classifications and refuse unobservable live processes."""
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
            names = {Path(value).name for value in argv}
            blocked.append({"pid": int(item.name), "kind": kind,
                            "executable": Path(argv[0]).name,
                            "matching_names": sorted(names &
                                (set(base.BLOCKED_RUNNERS) | EXTRA_BLOCKED_RUNNERS))})
    base.require(not blocked, "Live runtime/build/emulator process exists: " +
                 json.dumps(blocked, sort_keys=True))
    return {"blocked_processes": 0}


def pending_gate():
    """Fail before dependencies, lock, Docker, auditors, or output access."""
    require(HEX64.fullmatch(INPUTS_SHA) is not None,
            "Frozen packet7 matrix input digest is unresolved")
    require(IMAGE_ID.fullmatch(IMAGE) is not None,
            "Native4 immutable image ID is unresolved")
    require(IMAGE_ID.fullmatch(PAIR_IMAGE) is not None,
            "Derived6 immutable image ID is unresolved")
    require(HEX64.fullmatch(WRONG_SHA) is not None,
            "Wrong-signer7 receipt is unresolved")
    require(HEX64.fullmatch(PAIR_API_REPORT_SHA) is not None,
            "Pair6 API acceptance report is unresolved")
    require(HEX64.fullmatch(PAIR_RECENTS_REPORT_SHA) is not None,
            "Pair6 Recents acceptance report is unresolved")


def configure(base, pair):
    require(base.COMMAND[-8:] == ["--output", str(base.OUTPUT), "--phase", "all",
            "--jobs", "2", "--timeout", "7200"] and
            base.RUNNER_SHA == "f29b136a2ea62c02c7c722f2746a4ce92b8ea666e87ba1c0656d028d7d68be8e",
            "Reviewed full native23/GUI4 command changed")
    require(pair.DEBUG_ID == base.DEBUG_ID and pair.DEBUG_PROOF == base.DEBUG_PROOF,
            "Reviewed pair/debug identity changed")
    require(pair.PACKET == PACKET and pair.PACKET_SHA == PACKET_SHA and pair.WRONG == WRONG,
            "Pair6 packet7 lineage changed")
    base.INPUTS = INPUTS
    base.INPUTS_SHA = INPUTS_SHA
    base.OUTPUT = OUTPUT
    base.IMAGE = IMAGE
    base.PAIR_DRIVER = PAIR_DRIVER
    base.PAIR_DRIVER_SHA = PAIR_DRIVER_SHA
    base.PAIR_IMAGE = PAIR_IMAGE
    base.BLOCKED_RUNNERS = set(base.BLOCKED_RUNNERS) | EXTRA_BLOCKED_RUNNERS
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
    base = execute_source(base_source, "phase1_packet7_matrix_base_sealed")
    pair = execute_source(pair_source, "phase1_packet7_pair6_driver_sealed")
    return configure(base, pair), pair


def stable_report(path, expected_sha256):
    return capture_source(path, expected_sha256, max_bytes=MAX_REPORT_BYTES)


def validate_pair_reports(pair, *, run=subprocess.run):
    """Re-run both exact independent pair auditors against pinned reports."""
    require(pair.WRONG_SHA == WRONG_SHA,
            "Pair6 wrong-signer receipt differs from matrix selection")
    pair.actual_identity_ready()
    pair.local_inputs()
    selection = pair.selected()
    require(selection["native_image_id"] == IMAGE and
            selection["derived_image_id"] == PAIR_IMAGE and
            selection["packet_receipt_sha256"] == PACKET_SHA,
            "Pair6 reports do not bind exact Native4/Derived6/packet7 identities")
    reports = {"api": (PAIR_API_REPORT, PAIR_API_REPORT_SHA),
               "recents": (PAIR_RECENTS_REPORT, PAIR_RECENTS_REPORT_SHA)}
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    for lane, (path, expected) in reports.items():
        before = stable_report(path, expected)
        command = pair.commands(selection, lane, audit=True)
        require(command[:3] == [str(pair.PYTHON), "-B",
                str(ROOT / "android/tools" /
                    {"api": "phase1_conformance_acceptance.py",
                     "recents": "phase1_conformance_recents_guest_acceptance.py"}[lane])] and
                command[3:5] == ["--report", str(path)] and
                command[-6:] == ["--product", selection["product"], "--packet", str(PACKET),
                                 "--expected-receipt-sha256", PACKET_SHA],
                "Pair6 independent auditor command changed: " + lane)
        result = run(command, cwd=ROOT, env=environment, text=True,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900)
        require(result.returncode == 0,
                "Pair6 independent auditor failed: " + lane)
        require(len(result.stdout.encode()) <= 512 * 1024 and
                len(result.stderr.encode()) <= 512 * 1024,
                "Pair6 auditor output exceeded bounded evidence: " + lane)
        after = stable_report(path, expected)
        require(before.file_identity == after.file_identity and before.data == after.data,
                "Pair6 report changed during independent audit: " + lane)
    return selection


def main(argv=None):
    pending_gate()
    base, pair = load_dependencies()
    validate_pair_reports(pair)
    return base.main(argv)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BlockingIOError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
