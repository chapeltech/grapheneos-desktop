#!/usr/bin/env python3
"""Admit the frozen custom7/packet4 full native23 + serialized GUI4 run.

This external wrapper changes no matrix semantics.  It authenticates the exact
frozen inputs/tool/interpreter, refuses overlap with every other build,
runtime, emulator or KVM guest, and then execs the reviewed repository runner
with ``--phase all --jobs 2``.  Check-only never starts a container or guest.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


ROOT = Path("/u/elric/tree/wonad")
EVIDENCE = Path("/u/elric/tree/wonad-phase1-build-evidence")
PYTHON = Path("/srv/wonad-os37-pending-permission-3/wonad-styx-live.0DimSmO9/x11-test-venv/bin/python3")
PYTHON_TARGET = Path("/usr/bin/python3.14")
PYTHON_SHA = "0d64bd6d66d68dac91cdadafc46e22d4f09f22bdc997aaae870f42865b024a3e"
RUNNER = ROOT / "android/tools/run_native_matrix.py"
RUNNER_SHA = "f29b136a2ea62c02c7c722f2746a4ce92b8ea666e87ba1c0656d028d7d68be8e"
INPUTS = ROOT / "android/out/phase1-native-matrix-custom7-5-packet4-inputs-1/inputs.json"
INPUTS_SHA = "66ce0c34e7839c02bf3aebe08c96f87b307b89e393cbe82e53d18a61293ee81d"
OUTPUT = ROOT / "android/out/phase1-native-matrix-custom7-5-packet4-run-1"
IMAGE = "sha256:df954ed12d18cb150789608d3bb5d95996bbd399656de48e52a7a6cc6f6e6d27"
LOCALITY = ROOT / "android/tools/docker_locality_proof.py"
LOCALITY_SHA = "09b68ceabeb83ed997608a427f8bd5e4196a229d0e3ffd5fc59a98cff85da780"
PAIR_DRIVER = EVIDENCE / "run-phase1-custom7-api-recents-packet4-20261011-2.py"
PAIR_DRIVER_SHA = "b56b0f4e7f234cc4feb54e007bd92eee693a57f50a6907faf18067ca4f94b8f4"
DEBUG_PROOF = EVIDENCE / "phase1-custom7-preserved-debug-sleep-adb-proof-20261011-1.json"
DEBUG_PROOF_SHA = "49ee022282157cbe77b215660a8afcf98c75184872b1cb93b1e902f9c85d24f8"
DEBUG_ID = "e5e8d4c4d2b1373416027fa86d88a5d9e6d6d3e3592c0b9cabcf80a6b59ffc4d"
PAIR_LABEL = "org.wonad.phase1-fresh-conformance"
PAIR_IMAGE = "sha256:b9d00f28733fe80146f50ad96f3a809c5b382f91cb5d5de74b694ac740bf3840"
LOCK = Path("/tmp/wonad-phase1-native-full-matrix.lock")
COMMAND = [str(PYTHON), "-B", str(RUNNER), "run", "--inputs", str(INPUTS),
           "--output", str(OUTPUT), "--phase", "all", "--jobs", "2",
           "--timeout", "7200"]

BLOCKED_RUNNERS = {
    "run-phase1-custom7-api-recents-packet4-20261011-2.py",
    "phase1_conformance_guest.py",
    "run_phase1_conformance_recents_guest.py",
    "run_native_matrix.py",
    "run_phase1_runtime_qualification.py",
    "run_phase1_upstream_guest.py",
    "run_phase1_upstream_tests.py",
    "run_x86_build.py",
    "run_x86_emulator_build.py",
    "run_frankel_build.py",
    "build-native-candidate.py",
    "build-phase1-conformance-candidate.py",
}
BLOCKED_COMPILERS = {"ninja", "siso", "soong_ui", "soong_ui.bash", "buildctl"}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    require(path.is_file() and not path.is_symlink() and path.resolve(strict=True) == path,
            "Missing or aliased pinned file: " + str(path))
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique(rows):
    result = {}
    for key, value in rows:
        require(key not in result, "Duplicate JSON field: " + key)
        result[key] = value
    return result


def load(path):
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def reviewed_pair_module():
    require(digest(PAIR_DRIVER) == PAIR_DRIVER_SHA, "Reviewed API/Recents driver changed")
    require(digest(DEBUG_PROOF) == DEBUG_PROOF_SHA, "Reviewed debug observation changed")
    spec = importlib.util.spec_from_file_location("phase1_custom7_pair_driver", PAIR_DRIVER)
    require(spec is not None and spec.loader is not None, "Cannot load reviewed pair driver")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(module.DEBUG_ID == DEBUG_ID and module.DEBUG_PROOF == DEBUG_PROOF,
            "Reviewed debug helper identity changed")
    return module


def inspect_running_containers(pair):
    raw = subprocess.check_output(["docker", "ps", "-q", "--no-trunc"], text=True, timeout=30)
    blocked = []
    debug_seen = False
    for identifier in raw.splitlines():
        require(re.fullmatch("[0-9a-f]{64}", identifier), "Malformed running container ID")
        rows = json.loads(subprocess.check_output(
            ["docker", "container", "inspect", identifier], text=True, timeout=30),
            object_pairs_hook=unique)
        require(len(rows) == 1 and rows[0].get("Id") == identifier,
                "Running container inspect identity differs")
        info = rows[0]
        if identifier == DEBUG_ID:
            pair.preserved_debug_check(info)
            debug_seen = True
            continue
        devices = info.get("HostConfig", {}).get("Devices") or []
        kvm = any(device.get("PathOnHost") == "/dev/kvm" or
                  device.get("PathInContainer") == "/dev/kvm" for device in devices)
        labels = info.get("Config", {}).get("Labels") or {}
        mounts = info.get("Mounts") or []
        kvm = kvm or any(item.get("Source") == "/dev/kvm" or
                         item.get("Destination") == "/dev/kvm" for item in mounts)
        phase1_guest = (info.get("Image") in {IMAGE, PAIR_IMAGE} or
                        PAIR_LABEL in labels or
                        str(info.get("Name", "")).startswith("/wonad-phase1-conformance-") or
                        any(item.get("Destination") == "/state" and kvm for item in mounts))
        if kvm or phase1_guest:
            blocked.append({"id": identifier, "name": info.get("Name"),
                            "image": info.get("Image"), "kvm": kvm,
                            "phase1_guest": phase1_guest})
    require(not blocked, "Live API/Recents/native/GUI/KVM container exists: " +
            json.dumps(blocked, sort_keys=True))
    return {"running_container_count": len(raw.splitlines()),
            "preserved_debug_seen": debug_seen}


def process_kind(argv):
    if not argv:
        return None
    executable = Path(argv[0]).name
    names = {Path(value).name for value in argv}
    if executable == "emulator" or executable.startswith("qemu-system"):
        return "emulator_or_qemu"
    if names & BLOCKED_RUNNERS:
        return "phase1_runner_or_build"
    if any(name.startswith("native_") and name.endswith("_smoke.py") for name in names):
        return "native_gate"
    if any(name.startswith("continue-phase1-x86-") and name.endswith(".sh") for name in names):
        return "x86_build_driver"
    if executable in BLOCKED_COMPILERS:
        return "compiler"
    if executable in {"docker", "buildx"} and "build" in argv:
        return "docker_build"
    if executable in {"gradle", "gradlew"} or any(
            "org.gradle.launcher" in value or "GradleDaemon" in value for value in argv):
        return "gradle_build"
    return None


def inspect_live_processes():
    blocked = []
    for item in Path("/proc").iterdir():
        if not item.name.isdecimal() or int(item.name) == os.getpid():
            continue
        try:
            with (item / "cmdline").open("rb") as stream:
                raw = stream.read(65537)
            if not raw or len(raw) > 65536:
                continue
            argv = [value.decode(errors="replace") for value in raw.rstrip(b"\0").split(b"\0")]
            kind = process_kind(argv)
            if kind is not None:
                blocked.append({"pid": int(item.name), "kind": kind,
                                "executable": Path(argv[0]).name,
                                "matching_names": sorted({Path(value).name for value in argv} &
                                                         BLOCKED_RUNNERS)})
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    require(not blocked, "Live runtime/build/emulator process exists: " +
            json.dumps(blocked, sort_keys=True))
    return {"blocked_processes": 0}


def acquire_lock():
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        require(os.fstat(fd).st_uid == os.getuid(), "Foreign native matrix lock owner")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.set_inheritable(fd, True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def local_inputs():
    require(os.getuid() == os.getgid() == 1000, "Use the owned UID/GID1000 host lane")
    require(PYTHON.is_symlink() and PYTHON.resolve(strict=True) == PYTHON_TARGET and
            digest(PYTHON_TARGET) == PYTHON_SHA, "Pinned matrix Python changed")
    require(digest(RUNNER) == RUNNER_SHA, "Reviewed native matrix runner changed")
    require(digest(LOCALITY) == LOCALITY_SHA, "Reviewed Docker locality helper changed")
    require(digest(INPUTS) == INPUTS_SHA, "Frozen native matrix input bytes changed")
    plan = load(INPUTS)
    require(plan.get("kind") == "native_api3_required23_and_gui4_frozen_inputs_v2" and
            plan.get("guests_started") is False and
            plan.get("image", {}).get("image_id") == IMAGE,
            "Wrong frozen full native23/GUI4 input selection")
    require(not OUTPUT.exists() and not OUTPUT.is_symlink(),
            "Preserving existing native matrix output; use a fresh successor driver")
    sys.path.insert(0, str(ROOT / "android/tools"))
    import docker_locality_proof
    environment = docker_locality_proof.command_environment(dict(os.environ))
    _cli, _socket, _context, daemon = docker_locality_proof.trusted_local_docker(environment)
    inspect = json.loads(subprocess.check_output(
        ["docker", "image", "inspect", IMAGE], text=True, timeout=30),
        object_pairs_hook=unique)
    require(len(inspect) == 1 and inspect[0].get("Id") == IMAGE,
            "Frozen immutable native image is unavailable or substituted")
    import run_native_matrix
    require(len(run_native_matrix.GATES) == 23 and len(run_native_matrix.GUI) == 4,
            "Reviewed full native23/GUI4 inventory changed")
    budget = run_native_matrix.resources(2)
    return environment, daemon, budget


def admission():
    environment, daemon, budget = local_inputs()
    pair = reviewed_pair_module()
    containers = inspect_running_containers(pair)
    processes = inspect_live_processes()
    return environment, {"schema": 1,
        "status": "admitted_nonreserving_no_guest_started",
        "inputs_sha256": INPUTS_SHA,
        "image_id": IMAGE,
        "phase": "all",
        "required_backend_gates": 23,
        "required_gui_gates": 4,
        "backend_jobs": 2,
        "gui_execution": "serialized_by_repository_runner",
        "budget": budget,
        "local_docker_daemon_id": daemon["id"],
        "container_observation": containers,
        "process_observation": processes,
        "command": COMMAND}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--execute-after-root-go", action="store_true")
    args = parser.parse_args(argv)
    require(args.check_only != args.execute_after_root_go,
            "Choose check-only OR explicit root-authorized execution")
    lock_fd = acquire_lock()
    environment, record = admission()
    print(json.dumps(record, sort_keys=True), flush=True)
    if args.check_only:
        os.close(lock_fd)
        return 0
    # Close the pre-exec observation gap as far as a host wrapper can: replay
    # all live-container/process checks immediately before replacing this PID.
    pair = reviewed_pair_module()
    inspect_running_containers(pair)
    inspect_live_processes()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    os.chdir(ROOT)
    os.execve(PYTHON, COMMAND, environment)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BlockingIOError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
