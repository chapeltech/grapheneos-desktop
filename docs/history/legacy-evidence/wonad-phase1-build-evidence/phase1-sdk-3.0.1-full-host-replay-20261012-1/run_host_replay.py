#!/usr/bin/env python3
"""Run the bounded SDK 3.0.1 host replay without touching the live tree."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import time
import unittest


HERE = Path(__file__).resolve().parent
BASE = HERE / "base"
PROPOSED = HERE / "corrected"
CANDIDATE = Path(
    "/u/elric/tree/wonad-phase1-build-evidence/"
    "phase1-sdk-3.0.1-production-integration-candidate-20261012-1"
)
RESULTS = HERE / "results-attempt3"
CANDIDATE_RECEIPT_SHA256 = (
    "968c2e810e70f7785e6c12fc60e66a4fa88faa076199451cffb47a6874085fd7"
)
SUITES = (
    "test_sdk_contract",
    "test_sdk_publication",
    "test_native_current_compile",
    "test_phase1_provenance",
    "test_release_receipt",
    "test_phase1_release_index",
)
CORRECTION_PATH = "android/tests/test_release_receipt.py"
CORRECTION_SHA256 = "e7cbbf28f08e1428a469acc4bd9067008fb9ca448feef55d81b3e594bb69c97e"
FORBIDDEN_EXECUTABLES = {
    "adb", "avdmanager", "cargo", "docker", "emulator", "gradle", "java",
    "javac", "qemu-kvm", "qemu-system-aarch64", "qemu-system-x86_64",
    "rustc", "rustup", "sdkmanager",
}


class ReplayError(RuntimeError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise ReplayError(message)


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def write_new(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            require(count > 0, f"short write: {path}")
            written += count
        os.fsync(descriptor)
        observed = os.fstat(descriptor)
        require(observed.st_size == len(payload), f"written size differs: {path}")
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def safe_tree(root: Path) -> dict[str, dict[str, object]]:
    require(root.is_dir() and not root.is_symlink(), f"invalid tree root: {root}")
    result: dict[str, dict[str, object]] = {}
    for current, directories, files in os.walk(root, followlinks=False):
        parent = Path(current)
        for name in directories:
            require(not (parent / name).is_symlink(), f"symlinked directory: {parent / name}")
        for name in files:
            path = parent / name
            relative = path.relative_to(root).as_posix()
            pure = PurePosixPath(relative)
            require(pure.as_posix() == relative and
                    all(part not in ("", ".", "..") for part in pure.parts),
                    f"unsafe inventory path: {relative}")
            before = path.stat(follow_symlinks=False)
            require(stat.S_ISREG(before.st_mode) and not path.is_symlink(),
                    f"non-regular inventory path: {relative}")
            digest = sha256(path)
            after = path.stat(follow_symlinks=False)
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                    f"inventory path changed while hashing: {relative}")
            result[relative] = {
                "sha256": digest,
                "bytes": before.st_size,
                "mode": stat.S_IMODE(before.st_mode),
            }
    return dict(sorted(result.items()))


def load_json(path: Path) -> dict[str, object]:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key in {path}: {key}")
            result[key] = value
        return result
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    require(type(value) is dict, f"JSON root is not object: {path}")
    return value


def preflight() -> dict[str, object]:
    require(not RESULTS.exists() and not RESULTS.is_symlink(),
            "results must be fresh and absent")
    require(sha256(CANDIDATE / "receipt.json") == CANDIDATE_RECEIPT_SHA256,
            "frozen candidate receipt changed")
    plan = load_json(CANDIDATE / "integration-map.json")
    modified = plan["source_snapshots"]["modified"]
    require(type(modified) is dict and len(modified) == 14,
            "expected exact 14-file proposed overlay")
    base = safe_tree(BASE)
    proposed = safe_tree(PROPOSED)
    require(set(base) == set(proposed), "base/proposed inventory paths differ")
    delta = {}
    for name in base:
        if base[name] != proposed[name]:
            delta[name] = {"before": base[name], "after": proposed[name]}
    require(set(delta) == set(modified), "replay delta is not exact reviewed overlay")
    for name, row in modified.items():
        expected_after = CORRECTION_SHA256 if name == CORRECTION_PATH else row["after"]
        require(delta[name]["before"]["sha256"] == row["before"] and
                delta[name]["after"]["sha256"] == expected_after,
                f"reviewed/corrective overlay identity differs: {name}")
    require(sha256(HERE / "proposed" / CORRECTION_PATH) ==
            modified[CORRECTION_PATH]["after"],
            "preserved frozen candidate fixture changed")
    return {
        "schema": 1,
        "kind": "wonad-sdk-3.0.1-full-host-replay-inputs-v1",
        "scope": "captured_host_harness_only_not_android_jvm_or_publication_qualification",
        "candidate_receipt": {
            "path": str(CANDIDATE / "receipt.json"),
            "sha256": CANDIDATE_RECEIPT_SHA256,
            "bytes": (CANDIDATE / "receipt.json").stat().st_size,
        },
        "base": {"file_count": len(base), "files": base},
        "proposed": {"file_count": len(proposed), "files": proposed},
        "overlay": {"file_count": len(delta), "files": delta},
        "supplemental_fixture_correction": {
            "path": CORRECTION_PATH,
            "frozen_candidate_sha256": modified[CORRECTION_PATH]["after"],
            "corrected_sha256": CORRECTION_SHA256,
            "scope": "synthetic release-receipt SDK verification fixture only",
        },
    }


ORIGINAL_POPEN = subprocess.Popen
COMMANDS: list[dict[str, object]] = []


def executable(argv: object, env: object) -> tuple[str, str]:
    require(isinstance(argv, (list, tuple)) and argv and
            all(isinstance(item, (str, os.PathLike)) for item in argv),
            "host replay requires an argv sequence")
    raw = os.fspath(argv[0])
    if os.path.isabs(raw) or "/" in raw:
        resolved = Path(raw).resolve(strict=True)
    else:
        path = None
        if isinstance(env, dict):
            path = env.get("PATH")
        found = shutil.which(raw, path=path)
        require(found is not None, f"host replay executable missing: {raw}")
        resolved = Path(found).resolve(strict=True)
    return raw, str(resolved)


def guarded_popen(*args, **kwargs):
    require(not kwargs.get("shell", False), "shell subprocess forbidden in host replay")
    argv = args[0] if args else kwargs.get("args")
    raw, resolved = executable(argv, kwargs.get("env"))
    name = Path(resolved).name
    require(name not in FORBIDDEN_EXECUTABLES and Path(raw).name not in FORBIDDEN_EXECUTABLES,
            f"heavy/external executable forbidden in host replay: {raw}")
    allowed = {
        "/usr/bin/git", "/usr/bin/git-lfs", "/usr/bin/openssl",
        str(Path(sys.executable).resolve(strict=True)),
    }
    temporary_apksigner = (Path(resolved).name == "apksigner" and
                           str(Path(resolved)).startswith("/tmp/") and
                           Path(resolved).is_file() and not Path(resolved).is_symlink())
    require(resolved in allowed or temporary_apksigner,
            f"unreviewed subprocess executable: {raw} -> {resolved}")
    COMMANDS.append({
        "argv": [os.fspath(item) for item in argv],
        "resolved_executable": resolved,
        "ephemeral_test_apksigner": temporary_apksigner,
    })
    return ORIGINAL_POPEN(*args, **kwargs)


def suite() -> tuple[unittest.TestSuite, dict[str, int]]:
    tests = unittest.TestSuite()
    counts = {}
    loader = unittest.defaultTestLoader
    for name in SUITES:
        selected = loader.loadTestsFromName(name)
        count = selected.countTestCases()
        require(count > 0, f"suite did not resolve: {name}")
        counts[name] = count
        tests.addTests(selected)
    return tests, counts


def main() -> int:
    start = time.monotonic_ns()
    inputs = preflight()
    before_base = inputs["base"]["files"]
    before_proposed = inputs["proposed"]["files"]
    RESULTS.mkdir(mode=0o700)
    write_new(RESULTS / "inputs.json", canonical(inputs))

    original_cwd = Path.cwd()
    os.chdir(PROPOSED)
    sys.path[:] = [str(PROPOSED / "android/tests"), str(PROPOSED / "android/tools"),
                   str(PROPOSED / "android/container"), str(PROPOSED / "android/demo")] + [
        value for value in sys.path
        if value and str(Path(value).resolve()) not in {
            "/u/elric/tree/wonad", "/u/elric/tree/wonad/android/tests",
            "/u/elric/tree/wonad/android/tools", "/u/elric/tree/wonad/android/container",
        }
    ]
    subprocess.Popen = guarded_popen
    stream = io.StringIO()
    result = None
    counts = {}
    try:
        selected, counts = suite()
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(selected)
    finally:
        subprocess.Popen = ORIGINAL_POPEN
        os.chdir(original_cwd)

    after_base = safe_tree(BASE)
    after_proposed = safe_tree(PROPOSED)
    require(after_base == before_base and after_proposed == before_proposed,
            "captured replay inputs changed during host tests")
    end = time.monotonic_ns()
    assert result is not None
    output = stream.getvalue().encode()
    write_new(RESULTS / "test-output.txt", output)
    record = {
        "schema": 1,
        "kind": "wonad-sdk-3.0.1-full-host-replay-result-v1",
        "scope": "captured_host_harness_only_not_android_jvm_or_publication_qualification",
        "success": result.wasSuccessful(),
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "suite_counts": counts,
        "started_monotonic_ns": start,
        "ended_monotonic_ns": end,
        "reported_seconds": round((end - start) / 1_000_000_000, 6),
        "input_inventory": {
            "path": "inputs.json", "sha256": sha256(RESULTS / "inputs.json"),
            "bytes": (RESULTS / "inputs.json").stat().st_size,
            "unchanged_after_tests": True,
        },
        "test_output": {
            "path": "test-output.txt", "sha256": sha256(RESULTS / "test-output.txt"),
            "bytes": len(output),
        },
        "subprocesses": COMMANDS,
        "subprocess_policy": {
            "forbidden": sorted(FORBIDDEN_EXECUTABLES),
            "allowed_actual": ["git", "git-lfs", "openssl", "current Python",
                               "temporary synthetic-fixture apksigner"],
            "docker_gradle_java_vm_emulator_compiler_started": False,
        },
        "ephemeral_fixture_disclosure": (
            "Existing tests create temporary Git repositories, temporary self-signed RSA/EC "
            "certificates and test keys (deleted or directed to /dev/null), and temporary fake "
            "apksigner scripts. No production/private project key is read, generated, or retained."
        ),
        "limitations": [
            "No Gradle or Android/JVM compilation was run.",
            "No real Maven SDK publication was built or compared.",
            "No Docker container, emulator, VM, APK build, OS build, signing ceremony, or runtime gate ran.",
            "Passing results qualify only the captured Python host harness and synthetic fixtures.",
        ],
        "runner": {"path": str(Path(__file__).resolve()), "sha256": sha256(Path(__file__)),
                   "bytes": Path(__file__).stat().st_size},
    }
    write_new(RESULTS / "result.json", canonical(record))
    print(canonical(record).decode(), end="")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
