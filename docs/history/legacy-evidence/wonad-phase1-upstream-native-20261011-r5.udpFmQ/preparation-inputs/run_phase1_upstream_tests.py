#!/usr/bin/env python3
"""Run Phase-1 Atests without granting them access to a receipted build OUT.

This runner is intentionally stricter than the older capture helper.  It fully
re-verifies the authenticated build receipt before and after the test, starts a
private source-pinned adb server on a Unix socket, and runs every suite in a new
locked-down container.  The source checkout is read-only and the only writable
host bind is a new, disposable test OUT directory.  A successful run produces
a self-contained, relative-reference schema-2 evidence bundle; failures never
produce a run receipt.

The emulator itself is an input to this program.  This program never starts,
stops, snapshots, or otherwise manages an emulator.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time

import docker_locality_proof as locality
import phase1_provenance as provenance
import phase1_upstream_test_comparison as comparison


SCHEMA = 2
KIND = "wonad-phase1-isolated-upstream-test-run"
SCOPE = "same-pin-isolated-atest-not-runtime-or-hardware-qualification"
RESULT_PREFIX = "Atest results and logs directory: "
DEFAULT_TIMEOUT = 4 * 60 * 60
MAX_TIMEOUT = 12 * 60 * 60
CONTAINER_SOURCE = "/sources"
CONTAINER_TEST = "/test-out"
CONTAINER_OUT = CONTAINER_TEST + "/out"
CONTAINER_ADB = "/adb/adb.sock"
DOCKER = Path("/usr/bin/docker")
MAX_EVIDENCE = 256 * 1024 * 1024
# A source snapshot is already embedded in a build receipt bounded by the
# comparison parser's 64-MiB limit.  Leave bounded room for the authenticated
# IPC envelope without allowing a child to make its parent retain arbitrary
# output.
SOURCE_FREEZE_IPC_MAX = comparison.MAX_JSON + 1024 * 1024
SOURCE_FREEZE_IPC_SCHEMA = 1
SOURCE_FREEZE_ERROR_MAX = 4096
PR_SET_PDEATHSIG = 1
SHA256 = re.compile(r"[0-9a-f]{64}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,80}")
RUNNER = Path(__file__).resolve()
ROOT = RUNNER.parents[2]

PLAN_ENVIRONMENT = {
    "ANDROID_BUILD_TOP", "ANDROID_SERIAL", "BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE",
    "BUILD_DATETIME", "BUILD_HOSTNAME", "BUILD_NUMBER", "BUILD_USERNAME",
    "DEBIAN_FRONTEND", "ENABLE_ATEST_LOG_UPLOADING", "HOME", "LANG", "LC_ALL",
    "NINJA_HIGHMEM_NUM_JOBS", "OUT_DIR", "PATH", "PYTHONDONTWRITEBYTECODE",
    "TMPDIR", "TZ",
}
FORBIDDEN_ENVIRONMENT = {
    "ADB_SERVER_PORT", "ADB_VENDOR_KEYS", "ANDROID_ADB_SERVER_PORT", "ANDROID_HOST_OUT",
    "ANDROID_PRODUCT_OUT", "ANDROID_SOONG_HOST_OUT", "ANDROID_TOOLCHAIN",
    "JAVA_TOOL_OPTIONS", "CLASSPATH", "LD_LIBRARY_PATH", "LD_PRELOAD", "PYTHONPATH",
}


def require(condition, message):
    if not condition:
        raise comparison.EvidenceError(message)


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def stable_bytes(path: Path, *, maximum=MAX_EVIDENCE, allow_empty=True):
    path = Path(path)
    require(path.is_absolute(), "Evidence path must be absolute: " + str(path))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise comparison.EvidenceError("Cannot safely open file: " + str(path)) from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), "Not an ordinary file: " + str(path))
        require(before.st_size <= maximum and (allow_empty or before.st_size > 0),
                "Invalid evidence size: " + str(path))
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            require(total <= maximum, "Evidence is too large: " + str(path))
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = os.lstat(path)
    fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    require(all(getattr(before, key) == getattr(after, key) == getattr(current, key)
                for key in fields), "File changed while read: " + str(path))
    payload = b"".join(chunks)
    require(len(payload) == before.st_size, "Short file read: " + str(path))
    return payload


def sha256_file(path: Path, *, maximum=MAX_EVIDENCE, allow_empty=True):
    payload = stable_bytes(path, maximum=maximum, allow_empty=allow_empty)
    return {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}


def stream_file_identity(path: Path):
    """Hash an arbitrarily large ordinary file without following a symlink."""
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise comparison.EvidenceError("Cannot safely hash protected file: " + str(path)) from error
    digest = hashlib.sha256()
    total = 0
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), "Protected entry is not an ordinary file: " + str(path))
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        current = os.lstat(path)
    except OSError as error:
        raise comparison.EvidenceError("Protected file disappeared while hashing: " + str(path)) from error
    fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    require(all(getattr(before, key) == getattr(after, key) == getattr(current, key)
                for key in fields) and total == before.st_size,
            "Protected file changed while hashing: " + str(path))
    return {
        "device": before.st_dev, "inode": before.st_ino,
        "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid, "gid": before.st_gid,
        "size": total, "sha256": digest.hexdigest(),
        "mtime_ns": before.st_mtime_ns, "ctime_ns": before.st_ctime_ns,
    }


def fsync_directory(path: Path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_bytes_new(path: Path, payload: bytes, mode=0o600):
    require(path.parent.is_dir() and not os.path.lexists(path),
            "Refusing to replace evidence: " + str(path))
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync_directory(path.parent)


def write_json_new(path: Path, value):
    write_bytes_new(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def copy_new(source: Path, destination: Path):
    write_bytes_new(destination, stable_bytes(source), stat.S_IMODE(source.stat().st_mode) & 0o755)


def portable_ref(root: Path, path: Path, *, maximum=MAX_EVIDENCE, allow_empty=True):
    root = root.resolve(strict=True)
    path = Path(path)
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as error:
        raise comparison.EvidenceError("Evidence reference escaped bundle: " + str(path)) from error
    comparison.safe_relative(relative, "portable evidence reference")
    return {"path": relative, **sha256_file(path, maximum=maximum, allow_empty=allow_empty)}


def resolve_ref(root: Path, value, label, *, maximum=MAX_EVIDENCE, allow_empty=True):
    require(isinstance(value, dict) and set(value) == {"path", "sha256", "size"} and
            isinstance(value.get("path"), str) and
            SHA256.fullmatch(str(value.get("sha256", ""))) and
            type(value.get("size")) is int and 0 <= value["size"] <= maximum,
            "Invalid portable reference: " + label)
    relative = comparison.safe_relative(value["path"], label)
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            node = current.lstat()
        except OSError as error:
            raise comparison.EvidenceError("Missing referenced evidence: " + label) from error
        require(not stat.S_ISLNK(node.st_mode), "Evidence reference traverses a symlink: " + label)
        if index + 1 < len(relative.parts):
            require(stat.S_ISDIR(node.st_mode), "Evidence parent is not a directory: " + label)
        else:
            require(stat.S_ISREG(node.st_mode), "Evidence reference is not a file: " + label)
    observed = {"path": value["path"],
                **sha256_file(current, maximum=maximum, allow_empty=allow_empty)}
    require(observed == value, "Referenced evidence changed: " + label)
    return current


def exact_existing_directory(path: Path, label: str):
    path = Path(path)
    require(path.is_absolute(), label + " must be absolute")
    require(path.parent.resolve(strict=True) == path.parent and not path.is_symlink(),
            label + " has an aliased parent")
    node = path.lstat()
    require(stat.S_ISDIR(node.st_mode), label + " must be a directory")
    return path


def exact_new_path(path: Path, label: str):
    path = Path(path)
    require(path.is_absolute() and path.name not in ("", ".", "..") and
            path.parent.resolve(strict=True) == path.parent and not os.path.lexists(path),
            label + " must be a new literal absolute path")
    return path


def overlaps(left: Path, right: Path):
    left, right = Path(left), Path(right)
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def safe_roots(source: Path, build_out: Path, workspace: Path, output: Path):
    source = exact_existing_directory(source, "receipted source")
    build_out = exact_existing_directory(build_out, "receipted OUT")
    workspace = exact_new_path(workspace, "test OUT")
    output = exact_new_path(output, "evidence output")
    protected = (source, build_out, ROOT)
    require(all("," not in str(path) and "\n" not in str(path) and "\x00" not in str(path)
                for path in (source, build_out, workspace, output)),
            "Docker bind paths may not contain commas or control characters")
    require(not overlaps(workspace, output), "Test OUT and evidence output overlap")
    for candidate, label in ((workspace, "test OUT"), (output, "evidence output")):
        require(all(not overlaps(candidate, root) for root in protected),
                label + " overlaps a protected source/build tree")
    return source, build_out, workspace, output


def summarize_build(receipt_path: Path, receipt, role: str):
    require(receipt.get("role") == role, "Build receipt role differs from requested role")
    source = receipt.get("source")
    artifacts = receipt.get("artifacts")
    locations = receipt.get("locations")
    builder = receipt.get("builder")
    require(isinstance(source, dict) and isinstance(source.get("pin"), dict) and
            isinstance(artifacts, dict) and isinstance(artifacts.get("os_artifacts"), dict) and
            artifacts["os_artifacts"] and isinstance(locations, dict) and
            isinstance(locations.get("source"), str) and
            isinstance(locations.get("out_dir"), str) and isinstance(builder, dict) and
            isinstance(builder.get("image"), dict), "Build receipt lacks required bindings")
    kind = receipt.get("kind")
    require(kind in comparison.BUILD_VERIFIERS, "Unsupported build receipt kind")
    architecture, _ = comparison.BUILD_VERIFIERS[kind]
    image = builder["image"]
    require(architecture == "x86_64" and image.get("os") == "linux" and
            image.get("architecture") == "amd64" and
            IMAGE_ID.fullmatch(str(image.get("id", ""))),
            "Atest requires the immutable linux/amd64 x86 builder")
    return {
        "architecture": architecture,
        "kind": kind,
        "receipt_sha256": sha256_file(receipt_path, allow_empty=False)["sha256"],
        "source_pin_sha256": canonical_digest(source["pin"]),
        "artifacts_sha256": canonical_digest(artifacts),
        "fingerprint": receipt.get("fingerprint"),
        "os_artifacts": artifacts["os_artifacts"],
        "source_root": locations["source"],
        "out_dir": locations["out_dir"],
        "builder_image": image,
        "builder_identity_sha256": canonical_digest(image),
    }


def full_build_verify(receipt_path: Path, expected_sha256: str, role: str):
    receipt_path = comparison.literal_file(receipt_path, "build receipt")
    require(SHA256.fullmatch(str(expected_sha256)) is not None,
            "Exact lowercase build-receipt SHA-256 is required")
    require(sha256_file(receipt_path, allow_empty=False)["sha256"] == expected_sha256,
            "Build receipt differs from authenticated SHA-256")
    kind = comparison.peek_build_kind(receipt_path)
    architecture, verifier = comparison.BUILD_VERIFIERS[kind]
    module = comparison.load_module(verifier, "_wonad_isolated_" + architecture)
    try:
        receipt = module.verify(receipt_path, expected_sha256, rehash=True)
    except Exception as error:
        raise comparison.EvidenceError("Full build-receipt verification failed: " + str(error)) from error
    return receipt, summarize_build(receipt_path, receipt, role)


def _source_freeze_ipc_bytes(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise comparison.EvidenceError(
            "Source-freeze child produced a non-JSON value: " + str(error)) from error


def _write_source_freeze_ipc(descriptor: int, payload: bytes):
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        require(written > 0, "Source-freeze child IPC write made no progress")
        offset += written


def _source_freeze_child(descriptor: int, module, source: Path, role: str,
                         certificate: Path | None, jobs: int):
    """Run the unchanged, memory-intensive source collector in one child.

    The two complete 72-worker source passes remain inside the reviewed build
    verifier.  Only their process lifetime changes: exiting this child returns
    every Python/glibc worker arena before the parent reaches a suite guard.
    """
    exit_code = 0
    try:
        snapshot = module.collect_source_snapshot(
            source, role, certificate, module.LOCK, jobs)
        envelope = {
            "schema": SOURCE_FREEZE_IPC_SCHEMA,
            "status": "ok",
            "snapshot": snapshot,
        }
        payload = _source_freeze_ipc_bytes(envelope)
        if len(payload) > SOURCE_FREEZE_IPC_MAX:
            raise comparison.EvidenceError(
                "Source-freeze child output exceeds its bounded IPC limit")
    except Exception as error:
        exit_code = 1
        envelope = {
            "schema": SOURCE_FREEZE_IPC_SCHEMA,
            "status": "error",
            "error": {
                "type": type(error).__name__[:256],
                "message": str(error)[:SOURCE_FREEZE_ERROR_MAX],
            },
        }
        payload = _source_freeze_ipc_bytes(envelope)
    try:
        _write_source_freeze_ipc(descriptor, payload)
    except (BrokenPipeError, OSError):
        return 1
    return exit_code


def _terminate_source_freeze_child(pid: int):
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _terminate_source_freeze_child_uninterruptibly(pid: int):
    while True:
        try:
            _terminate_source_freeze_child(pid)
            return
        except (InterruptedError, KeyboardInterrupt, SystemExit):
            continue


def _wait_source_freeze_child(pid: int):
    while True:
        try:
            found, status = os.waitpid(pid, 0)
            require(found == pid, "Wait returned another source-freeze child")
            return status
        except InterruptedError:
            continue


def _reap_source_freeze_child_uninterruptibly(pid: int):
    while True:
        try:
            return _wait_source_freeze_child(pid)
        except (InterruptedError, KeyboardInterrupt, SystemExit):
            continue
        except ChildProcessError:
            # A signal may be delivered after waitpid has reaped the child but
            # before Python returns its status. This path is used only while
            # preserving an already-raised parent exception.
            return None


def _cleanup_source_freeze_child_uninterruptibly(pid: int):
    """Kill only a PID still owned by our unreaped collector child.

    A signal can be raised after waitpid has reaped the child but before Python
    returns its status. Probe with WNOHANG first: ECHILD or a returned child PID
    proves there is no longer an owned live PID to signal; zero proves that the
    unreaped child still reserves the PID, closing PID-reuse races around kill.
    """
    while True:
        try:
            found, _status = os.waitpid(pid, os.WNOHANG)
            require(found in {0, pid}, "Wait returned another source-freeze child")
            break
        except (InterruptedError, KeyboardInterrupt, SystemExit):
            continue
        except ChildProcessError:
            return
    if found == pid:
        return
    _terminate_source_freeze_child_uninterruptibly(pid)
    _reap_source_freeze_child_uninterruptibly(pid)


def _close_source_freeze_descriptor_uninterruptibly(descriptor: int):
    while True:
        try:
            os.close(descriptor)
            return
        except InterruptedError:
            continue
        except (KeyboardInterrupt, SystemExit):
            continue
        except OSError:
            return


def _arm_source_freeze_parent_death(expected_parent: int):
    """Kill the collector if its exact parent disappears unexpectedly."""
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                      ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    # PR_SET_PDEATHSIG cannot report a death which raced before prctl. Compare
    # the exact pre-fork parent afterwards to close that documented window.
    if os.getppid() != expected_parent:
        os.kill(os.getpid(), signal.SIGKILL)
        os._exit(125)


def _strict_source_freeze_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "Duplicate source-freeze IPC field: " + str(key))
        value[key] = item
    return value


def _decode_source_freeze_ipc(payload: bytes, child_status: int):
    require(payload, "Source-freeze child returned no IPC evidence")
    try:
        value = json.loads(payload.decode("utf-8"),
                           object_pairs_hook=_strict_source_freeze_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise comparison.EvidenceError(
            "Malformed source-freeze child IPC: " + str(error)) from error
    require(_source_freeze_ipc_bytes(value) == payload,
            "Source-freeze child IPC is not canonical JSON")
    require(isinstance(value, dict) and
            value.get("schema") == SOURCE_FREEZE_IPC_SCHEMA and
            value.get("status") in {"ok", "error"},
            "Invalid source-freeze child IPC envelope")
    require(os.WIFEXITED(child_status),
            "Source-freeze child terminated abnormally")
    exit_code = os.WEXITSTATUS(child_status)
    if value["status"] == "error":
        require(set(value) == {"schema", "status", "error"} and exit_code != 0 and
                isinstance(value["error"], dict) and
                set(value["error"]) == {"type", "message"} and
                isinstance(value["error"]["type"], str) and
                isinstance(value["error"]["message"], str),
                "Invalid source-freeze child failure envelope")
        raise comparison.EvidenceError(
            "Source-freeze collector child failed (" + value["error"]["type"] +
            "): " + value["error"]["message"])
    require(set(value) == {"schema", "status", "snapshot"} and exit_code == 0 and
            isinstance(value["snapshot"], dict),
            "Invalid successful source-freeze child IPC")
    return value["snapshot"]


def _isolated_source_snapshot(module, source: Path, role: str,
                              certificate: Path | None, jobs: int):
    expected_parent = os.getpid()
    try:
        read_descriptor, write_descriptor = os.pipe()
    except OSError as error:
        raise comparison.EvidenceError(
            "Cannot create source-freeze child IPC") from error
    try:
        pid = os.fork()
    except BaseException as error:
        _close_source_freeze_descriptor_uninterruptibly(read_descriptor)
        _close_source_freeze_descriptor_uninterruptibly(write_descriptor)
        if not isinstance(error, Exception):
            raise
        raise comparison.EvidenceError("Cannot start source-freeze child") from error
    if pid == 0:
        exit_code = 125
        try:
            _arm_source_freeze_parent_death(expected_parent)
            os.close(read_descriptor)
            exit_code = _source_freeze_child(
                write_descriptor, module, source, role, certificate, jobs)
        except BaseException:
            exit_code = 125
        finally:
            try:
                os.close(write_descriptor)
            except BaseException:
                pass
            finally:
                os._exit(exit_code)

    chunks = []
    total = 0
    oversized = False
    pending_error = None
    reaped = False
    write_closed = False
    read_closed = False
    status = None
    try:
        os.close(write_descriptor)
        write_closed = True
        while True:
            chunk = os.read(read_descriptor,
                            min(1024 * 1024, SOURCE_FREEZE_IPC_MAX + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > SOURCE_FREEZE_IPC_MAX:
                oversized = True
                break
        os.close(read_descriptor)
        read_closed = True
        if oversized:
            _terminate_source_freeze_child(pid)
        status = _wait_source_freeze_child(pid)
        reaped = True
    except BaseException as error:
        pending_error = error
    finally:
        if not read_closed:
            _close_source_freeze_descriptor_uninterruptibly(read_descriptor)
        if not write_closed:
            _close_source_freeze_descriptor_uninterruptibly(write_descriptor)
        if not reaped:
            _cleanup_source_freeze_child_uninterruptibly(pid)
    if pending_error is not None:
        if not isinstance(pending_error, Exception):
            raise pending_error
        raise comparison.EvidenceError(
            "Could not complete source-freeze child IPC") from pending_error
    require(not oversized, "Source-freeze child IPC exceeds its bounded limit")
    require(status is not None, "Source-freeze child status is unavailable")
    return _decode_source_freeze_ipc(b"".join(chunks), status)


def source_freeze_verify(receipt, build_summary):
    """Recollect the complete current source snapshot embedded in an x86 receipt.

    The x86 receipt verifier deliberately rehashes retained build outputs but
    does not rescan all source worktrees.  Atest consumes those worktrees, so
    this runner closes that separate gap immediately before and after testing.
    """
    require(receipt.get("kind") == "wonad-x86-build-comparison-input",
            "Isolated Atest source authentication requires an x86 receipt")
    _, verifier = comparison.BUILD_VERIFIERS[receipt["kind"]]
    module = comparison.load_module(verifier, "_wonad_isolated_source_x86")
    source = exact_existing_directory(Path(build_summary["source_root"]),
                                      "receipted source")
    certificate = None
    if receipt.get("role") == "custom":
        try:
            certificate_row = receipt["source"]["stage"]["marker"]["signer_certificate"]
            certificate_relative = comparison.safe_relative(
                certificate_row["path"], "staged signer certificate")
        except (KeyError, TypeError) as error:
            raise comparison.EvidenceError(
                "Custom receipt lacks its staged signer-certificate binding") from error
        certificate = comparison.literal_file(
            source / "external/wonad" / Path(*certificate_relative.parts),
            "staged signer certificate")
        require(sha256_file(certificate, allow_empty=False) == {
                    "sha256": certificate_row["sha256"], "size": certificate_row["size"]},
                "Staged signer certificate differs from the source receipt")
    jobs = min(72, max(1, os.cpu_count() or 1))
    try:
        observed = _isolated_source_snapshot(
            module, source, receipt["role"], certificate, jobs)
    except Exception as error:
        raise comparison.EvidenceError(
            "Current receipted source-freeze verification failed: " + str(error)) from error
    require(observed == receipt.get("source"),
            "Current source worktrees differ from the receipted source freeze")
    return {
        "schema": SCHEMA, "kind": "wonad-phase1-current-source-freeze",
        "receipt_sha256": build_summary["receipt_sha256"],
        "snapshot_sha256": canonical_digest(observed),
        "snapshot": observed,
    }


def image_path(image):
    environment = image.get("config", {}).get("Env")
    require(isinstance(environment, list), "Builder image environment is missing")
    rows = [item.split("=", 1)[1] for item in environment
            if isinstance(item, str) and item.startswith("PATH=")]
    require(len(rows) == 1 and rows[0].startswith("/"), "Builder image PATH is ambiguous")
    return rows[0]


def normalize_image(value):
    if isinstance(value, dict) and "Config" in value:
        return provenance.builder_subset(value)
    return value


def validate_plan_environment(plan, image, build_summary):
    serials = set()
    effective = {}
    for suite in plan["suites"]:
        environment = suite["environment"]
        require(set(environment) == PLAN_ENVIRONMENT,
                "Suite environment is not the reviewed closed set: " + suite["id"])
        require(not any(key in FORBIDDEN_ENVIRONMENT or key.startswith("DOCKER_")
                        for key in environment), "Suite contains a forbidden ambient control")
        expanded = {key: value.replace("{source}", CONTAINER_SOURCE)
                    .replace("{out_dir}", CONTAINER_OUT)
                    for key, value in environment.items()}
        expanded["ADB_SERVER_SOCKET"] = "localfilesystem:" + CONTAINER_ADB
        require(expanded["ANDROID_BUILD_TOP"] == CONTAINER_SOURCE and
                expanded["OUT_DIR"] == CONTAINER_OUT and
                expanded["PATH"] == image_path(image) and
                expanded["HOME"].startswith(CONTAINER_OUT + "/") and
                expanded["TMPDIR"].startswith(CONTAINER_OUT + "/"),
                "Suite does not use the sealed source/test OUT/toolchain")
        forbidden_values = (build_summary["source_root"], build_summary["out_dir"])
        require(all(not any(item and item in value for item in forbidden_values)
                    for value in expanded.values()),
                "Effective environment exposes a protected host tree")
        serial = expanded.get("ANDROID_SERIAL")
        require(re.fullmatch(r"emulator-[0-9]+", serial or "") is not None,
                "Phase-1 device Atests require one explicit emulator serial")
        serials.add(serial)
        cwd = suite["cwd"].replace("{source}", CONTAINER_SOURCE).replace(
            "{out_dir}", CONTAINER_OUT)
        require(cwd == CONTAINER_SOURCE, "Atest working directory must be read-only source")
        argv = [item.replace("{source}", CONTAINER_SOURCE).replace(
            "{out_dir}", CONTAINER_OUT) for item in suite["argv"]]
        require(all(build_summary["source_root"] not in item and
                    build_summary["out_dir"] not in item for item in argv),
                "Atest command exposes a protected host tree")
        effective[suite["id"]] = {"argv": argv, "cwd": cwd,
                                  "environment": dict(sorted(expanded.items()))}
    require(len(serials) == 1, "All device suites must select the same emulator")
    return effective, next(iter(serials))


def classify_suite(suite):
    component = suite["component"].lower()
    if re.fullmatch(r"emulator-[0-9]+", suite["environment"].get("ANDROID_SERIAL", "")):
        return {"platform": "aosp", "execution": "emulator-device"}
    if "grapheneos" in component:
        return {"platform": "grapheneos", "execution": "host"}
    return {"platform": "aosp", "execution": "host"}


def source_tool(path: Path, source: Path, label: str):
    path = Path(path)
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
            label + " has an aliased parent")
    relative = path.relative_to(source).as_posix()
    comparison.safe_relative(relative, label)
    node = path.lstat()
    if stat.S_ISLNK(node.st_mode):
        link_target = os.readlink(path)
        require(link_target and "\x00" not in link_target,
                label + " has an invalid symlink target")
        resolved = path.resolve(strict=True)
        try:
            resolved_relative = resolved.relative_to(source).as_posix()
        except ValueError as error:
            raise comparison.EvidenceError(label + " symlink escapes source") from error
        comparison.safe_relative(resolved_relative, label + " resolved target")
        require(resolved.is_file() and not resolved.is_symlink(),
                label + " symlink does not resolve to an ordinary file")
        return {"source_relative": relative, "link_target": link_target,
                "resolved_source_relative": resolved_relative,
                **sha256_file(resolved, allow_empty=False)}
    require(stat.S_ISREG(node.st_mode), label + " is not an ordinary file")
    return {"source_relative": relative, "link_target": None,
            "resolved_source_relative": relative,
            **sha256_file(path, allow_empty=False)}


def toolchain_record(source: Path, image, docker_identity):
    return {
        "schema": SCHEMA,
        "kind": "wonad-phase1-isolated-toolchain",
        "builder_image_id": image["id"],
        "builder_identity_sha256": canonical_digest(image),
        "builder_path": image_path(image),
        "source_tools": {
            "adb": source_tool(source / "prebuilts/runtime/adb", source, "source-pinned adb"),
            "atest": source_tool(source / "prebuilts/asuite/atest/linux-x86/atest",
                                 source, "source-pinned atest"),
            "envsetup": source_tool(source / "build/envsetup.sh", source,
                                    "source-pinned envsetup"),
        },
        "docker": docker_identity,
    }


class ProductionBackend:
    """Small injectable boundary; unit tests never call real Docker or adb."""

    def __init__(self):
        self.environment = None

    def docker_identity(self):
        try:
            self.environment = locality.command_environment()
            cli, socket, context, daemon = locality.trusted_local_docker(self.environment)
        except Exception as error:
            raise comparison.EvidenceError("Untrusted Docker endpoint: " + str(error)) from error
        return {"endpoint": locality.ENDPOINT, "cli": cli, "socket": socket,
                "context": context, "daemon": daemon}

    def _docker(self, arguments, *, timeout=60, stdout=None):
        require(self.environment is not None, "Docker identity was not established")
        argv = [str(DOCKER), "--host", locality.ENDPOINT, *map(str, arguments)]
        try:
            return subprocess.run(argv, env=self.environment, timeout=timeout, check=False,
                                  stdout=stdout or subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=stdout is None)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise comparison.EvidenceError("Docker command failed: " + repr(argv)) from error

    def inspect_image(self, image_id):
        result = self._docker(["image", "inspect", image_id])
        require(result.returncode == 0, "Cannot inspect immutable builder image: " + result.stdout)
        try:
            rows = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise comparison.EvidenceError("Docker image inspect returned invalid JSON") from error
        require(isinstance(rows, list) and len(rows) == 1, "Docker image inspect was ambiguous")
        return provenance.builder_subset(rows[0])

    def start_broker(self, adb: Path, workspace: Path, serial: str):
        adb_dir = workspace / "adb"
        home = workspace / "adb-home"
        temporary = workspace / "adb-tmp"
        for directory in (adb_dir, home, temporary):
            directory.mkdir(mode=0o700)
        socket = adb_dir / "adb.sock"
        log = workspace / "adb-server.log"
        argv = [str(adb), "-L", "localfilesystem:" + str(socket),
                "--one-device", serial, "nodaemon", "server"]
        environment = {"HOME": str(home), "TMPDIR": str(temporary),
                       "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
        stream = log.open("xb")
        try:
            process = subprocess.Popen(argv, env=environment, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
        except Exception:
            stream.close()
            raise
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise comparison.EvidenceError("Private adb server exited during startup")
                try:
                    node = socket.lstat()
                except FileNotFoundError:
                    time.sleep(0.1)
                    continue
                if stat.S_ISSOCK(node.st_mode):
                    return {"process": process, "stream": stream, "socket": socket,
                            "log": log, "argv": argv, "environment": environment,
                            "pid": process.pid}
                raise comparison.EvidenceError("Private adb endpoint is not a Unix socket")
            raise comparison.EvidenceError("Private adb server did not create its socket")
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
            stream.close()
            socket.unlink(missing_ok=True)
            raise

    def stop_broker(self, broker):
        process = broker["process"]
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
        broker["stream"].close()
        try:
            socket_node = Path(broker["socket"])
            if socket_node.exists() or socket_node.is_socket():
                socket_node.unlink()
        except OSError as error:
            raise comparison.EvidenceError("Cannot remove private adb socket") from error
        broker["exit_code"] = process.returncode
        broker["stopped"] = True
        return broker

    def adb(self, adb: Path, broker, serial: str, arguments, *, timeout=60):
        environment = dict(broker["environment"])
        environment["ADB_SERVER_SOCKET"] = "localfilesystem:" + str(broker["socket"])
        try:
            return subprocess.run([str(adb), "-s", serial, *map(str, arguments)],
                                  env=environment, timeout=timeout, check=False, text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise comparison.EvidenceError("Private adb command failed") from error

    def run_container(self, spec, stdout_path: Path, timeout: int):
        argv = container_docker_argv(spec)
        stream = stdout_path.open("xb")
        process = subprocess.Popen(argv, env=self.environment, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._docker(["stop", "--time", "10", spec["name"]], timeout=30)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._docker(["kill", spec["name"]], timeout=30)
                process.wait(timeout=15)
        finally:
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
        return {"exit_code": process.returncode, "timed_out": timed_out,
                "docker_argv": argv}

    def inspect_container(self, name):
        result = self._docker(["container", "inspect", name])
        require(result.returncode == 0, "Cannot inspect test container: " + result.stdout)
        try:
            rows = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise comparison.EvidenceError("Docker container inspect returned invalid JSON") from error
        require(isinstance(rows, list) and len(rows) == 1,
                "Docker container inspect was ambiguous")
        return rows[0]

    def remove_container(self, container_id):
        result = self._docker(["container", "rm", container_id])
        require(result.returncode == 0, "Cannot remove exact test container: " + result.stdout)

    def container_absent(self, identity):
        result = self._docker(["container", "inspect", identity])
        if result.returncode == 0:
            return False
        require("No such object" in result.stdout or "No such container" in result.stdout,
                "Cannot prove test-container absence: " + result.stdout)
        return True


def container_docker_argv(spec):
    environment_arguments = []
    for key, value in sorted(spec["environment"].items()):
        environment_arguments += ["--env", key + "=" + value]
    return [
        str(DOCKER), "--host", locality.ENDPOINT, "run", "--name", spec["name"],
        "--platform", "linux/amd64", "--pull", "never", "--network", "none",
        "--read-only", "--user", spec["user"], "--workdir", CONTAINER_SOURCE,
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--security-opt", "label=disable", "--restart", "no", "--pids-limit", "4096",
        "--hostname", "wonad-atest", "--label", "org.wonad.phase1.nonce=" + spec["nonce"],
        "--label", "org.wonad.phase1.suite=" + spec["suite"],
        "--mount", "type=bind,src=" + spec["source"] +
        ",dst=" + CONTAINER_SOURCE + ",readonly,bind-propagation=rprivate",
        "--mount", "type=bind,src=" + spec["workspace"] +
        ",dst=" + CONTAINER_TEST + ",readonly=false,bind-propagation=rprivate",
        "--mount", "type=bind,src=" + spec["adb_dir"] +
        ",dst=/adb,readonly,bind-propagation=rprivate",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=268435456",
        *environment_arguments, "--entrypoint", "/usr/bin/env", spec["image"], "-i",
        *[key + "=" + value for key, value in sorted(spec["environment"].items())],
        *spec["argv"],
    ]


def container_projection(raw):
    config = raw.get("Config", {})
    host = raw.get("HostConfig", {})
    state = raw.get("State", {})
    mounts = []
    for row in raw.get("Mounts", []):
        mounts.append({"type": row.get("Type"), "source": row.get("Source"),
                       "destination": row.get("Destination"), "rw": row.get("RW"),
                       "propagation": row.get("Propagation")})
    return {
        "id": raw.get("Id"), "name": str(raw.get("Name", "")).removeprefix("/"),
        "image": raw.get("Image"), "config_image": config.get("Image"),
        "entrypoint": config.get("Entrypoint"), "cmd": config.get("Cmd"),
        "user": config.get("User"), "working_dir": config.get("WorkingDir"),
        "environment": sorted(config.get("Env") or []), "labels": config.get("Labels") or {},
        "network_mode": host.get("NetworkMode"), "read_only": host.get("ReadonlyRootfs"),
        "privileged": host.get("Privileged"), "cap_drop": sorted(host.get("CapDrop") or []),
        "security_opt": sorted(host.get("SecurityOpt") or []),
        "devices": host.get("Devices") or [], "device_requests": host.get("DeviceRequests") or [],
        "restart": host.get("RestartPolicy"), "auto_remove": host.get("AutoRemove"),
        "tmpfs": host.get("Tmpfs") or {}, "mounts": sorted(mounts,
            key=lambda row: str(row["destination"])),
        "running": state.get("Running"), "restarting": state.get("Restarting"),
        "dead": state.get("Dead"), "oom_killed": state.get("OOMKilled"),
        "exit_code": state.get("ExitCode"),
    }


def validate_container(raw, spec, exit_code):
    row = container_projection(raw)
    expected_environment = sorted(key + "=" + value for key, value in spec["environment"].items())
    expected_command = ["-i", *expected_environment, *spec["argv"]]
    expected_mounts = sorted([
        {"type": "bind", "source": spec["source"], "destination": CONTAINER_SOURCE,
         "rw": False, "propagation": "rprivate"},
        {"type": "bind", "source": spec["workspace"], "destination": CONTAINER_TEST,
         "rw": True, "propagation": "rprivate"},
        {"type": "bind", "source": spec["adb_dir"], "destination": "/adb",
         "rw": False, "propagation": "rprivate"},
    ], key=lambda item: item["destination"])
    security = set(row["security_opt"])
    require(re.fullmatch(r"[0-9a-f]{64}", str(row["id"])) is not None and
            row["name"] == spec["name"] and row["image"] == spec["image"] and
            row["config_image"] == spec["image"] and row["entrypoint"] == ["/usr/bin/env"] and
            row["cmd"] == expected_command and row["user"] == spec["user"] and
            row["working_dir"] == CONTAINER_SOURCE and row["environment"] == expected_environment and
            row["labels"] == {"org.wonad.phase1.nonce": spec["nonce"],
                              "org.wonad.phase1.suite": spec["suite"]} and
            row["network_mode"] == "none" and row["read_only"] is True and
            row["privileged"] is False and row["cap_drop"] == ["ALL"] and
            ("no-new-privileges:true" in security or "no-new-privileges" in security) and
            "label=disable" in security and not row["devices"] and not row["device_requests"] and
            row["restart"] == {"Name": "no", "MaximumRetryCount": 0} and
            row["auto_remove"] is False and row["mounts"] == expected_mounts and
            row["tmpfs"] == {"/tmp": "rw,nosuid,nodev,noexec,mode=1777,size=268435456"} and
            row["running"] is False and row["restarting"] is False and row["dead"] is False and
            row["oom_killed"] is False and row["exit_code"] == exit_code,
            "Test container differs from the sealed isolation profile")
    return row


def adb_call(backend, adb, broker, serial, arguments, *, allow_failure=False):
    result = backend.adb(adb, broker, serial, arguments)
    require(allow_failure or result.returncode == 0,
            "adb command failed: " + " ".join(arguments) + "\n" + (result.stdout or ""))
    return result


def capture_device(backend, adb: Path, broker, serial: str, build):
    queries = {}

    def query(name, arguments):
        result = adb_call(backend, adb, broker, serial, arguments)
        value = result.stdout.strip()
        queries[name] = {"argv": list(arguments), "value": value}
        return value

    state = query("state", ["get-state"])
    boot = query("boot_completed", ["shell", "getprop", "sys.boot_completed"])
    fingerprint = query("fingerprint", ["shell", "getprop", "ro.build.fingerprint"])
    enforcing = query("selinux", ["shell", "getenforce"])
    boot_id = query("boot_id", ["shell", "cat", "/proc/sys/kernel/random/boot_id"])
    require(state == "device" and boot == "1" and fingerprint == build["fingerprint"] and
            enforcing == "Enforcing" and
            re.fullmatch(r"[0-9a-f]{8}-[0-9a-f-]{27}", boot_id) is not None,
            "Emulator is not the enforcing, booted, receipted build")
    artifacts = {}
    for name, expected in sorted(build["os_artifacts"].items()):
        path = "/" + expected["path"]
        if expected["state"] == "absent":
            result = adb_call(backend, adb, broker, serial,
                              ["shell", "sh", "-c", 'test ! -e "$1"', "sh", path],
                              allow_failure=True)
            require(result.returncode == 0, "Receipted-absent device artifact exists: " + name)
            artifacts[name] = {"path": path, "state": "absent"}
        else:
            result = adb_call(backend, adb, broker, serial,
                              ["shell", "sha256sum", path])
            fields = result.stdout.strip().split()
            require(len(fields) == 2 and fields[1] == path and
                    fields[0] == expected["sha256"],
                    "Device artifact differs from receipt: " + name)
            artifacts[name] = {"path": path, "state": "present", "sha256": fields[0]}
    return {"schema": SCHEMA, "kind": "wonad-phase1-isolated-device",
            "serial": serial, "fingerprint": fingerprint, "boot_id": boot_id,
            "boot_completed": boot, "selinux": enforcing, "state": state,
            "build_receipt_sha256": build["receipt_sha256"],
            "adb": source_tool(adb, Path(build["source_root"]), "source-pinned adb"),
            "queries": queries, "artifacts": artifacts}


def locate_atest_result(output: str, workspace: Path, temporary: str):
    rows = []
    for line in output.splitlines():
        plain = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", line)
        if plain.startswith(RESULT_PREFIX):
            rows.append(plain[len(RESULT_PREFIX):].strip())
    require(len(rows) == 1 and rows[0], "Atest did not report exactly one results directory")
    container = PurePosixPath(rows[0])
    tmp = PurePosixPath(temporary)
    require(container.is_absolute() and container.is_relative_to(tmp) and container != tmp,
            "Atest results escaped the sealed TMPDIR")
    relative = container.relative_to(PurePosixPath(CONTAINER_TEST))
    host = workspace.joinpath(*relative.parts)
    require(host.is_dir() and not host.is_symlink(), "Atest results directory is missing or aliased")
    current = workspace
    for part in relative.parts:
        current = current / part
        require(not current.is_symlink(), "Atest results path traverses a symlink")
    return host


def make_container_spec(suite, effective, build, source, workspace, broker, prefix, nonce):
    name = f"{prefix}-{suite['id']}-{nonce[:12]}"
    require(NAME.fullmatch(name) is not None, "Invalid test container name")
    require(os.getuid() != 0, "Refusing to run Atest containers as host root")
    return {
        "name": name, "suite": suite["id"], "nonce": nonce,
        "image": build["builder_image"]["id"], "user": f"{os.getuid()}:{os.getgid()}",
        "source": str(source), "workspace": str(workspace),
        "adb_dir": str(Path(broker["socket"]).parent),
        "argv": effective["argv"], "environment": effective["environment"],
    }


def cleanup_unsealed_container(backend, spec):
    """Remove a container created before its normal evidence path completed."""
    if backend.container_absent(spec["name"]):
        return
    raw = backend.inspect_container(spec["name"])
    identity = container_projection(raw)
    require(re.fullmatch(r"[0-9a-f]{64}", str(identity["id"])) is not None and
            identity["name"] == spec["name"] and identity["image"] == spec["image"] and
            identity["labels"].get("org.wonad.phase1.nonce") == spec["nonce"],
            "Cannot bind interrupted test container to its cleanup identity")
    backend.remove_container(identity["id"])
    require(backend.container_absent(identity["id"]) and
            backend.container_absent(spec["name"]),
            "Interrupted test container was not removed")


def run_suite(backend, suite, effective, build, source, workspace, output,
              broker, prefix, timeout_seconds, nonce):
    destination = output / "suites" / suite["id"]
    destination.mkdir(mode=0o700, parents=True)
    stdout = destination / "stdout.txt"
    spec = make_container_spec(suite, effective, build, source, workspace,
                               broker, prefix, nonce)
    try:
        execution = backend.run_container(spec, stdout, timeout_seconds)
        raw = backend.inspect_container(spec["name"])
    except BaseException:
        cleanup_unsealed_container(backend, spec)
        raise
    identity = container_projection(raw)
    require(re.fullmatch(r"[0-9a-f]{64}", str(identity["id"])) is not None and
            identity["name"] == spec["name"] and identity["image"] == spec["image"] and
            identity["labels"].get("org.wonad.phase1.nonce") == spec["nonce"],
            "Cannot bind the test container to its exact cleanup identity")
    container_id = identity["id"]
    inspect_path = destination / "container.json"
    container_record = None
    removed = None
    try:
        projected = validate_container(raw, spec, execution["exit_code"])
        container_record = {"schema": SCHEMA,
                            "kind": "wonad-phase1-isolated-container", "spec": spec,
                            "docker_argv": execution["docker_argv"], "observed": projected,
                            "timed_out": execution["timed_out"]}
        require(not execution["timed_out"], "Upstream test timed out: " + suite["id"])
        output_text = stable_bytes(stdout).decode("utf-8", errors="replace")
        result_directory = locate_atest_result(
            output_text, workspace, effective["environment"]["TMPDIR"])
        require(suite["format"] == "atest-json" and len(suite["result_files"]) == 1,
                "Isolated runner requires one native Atest JSON result")
        source_result = comparison.literal_file(result_directory / "test_result",
                                                "Atest test_result")
        result_path = destination / "test_result.json"
        copy_new(source_result, result_path)
        cases = dict(sorted(comparison.parse_atest(result_path).items()))
        require(len(cases) >= suite["minimum_cases"],
                "Suite has fewer cases than its reviewed minimum: " + suite["id"])
        command = {
            "schema": SCHEMA, "kind": "wonad-phase1-isolated-command",
            "suite": suite["id"], "target": classify_suite(suite),
            "argv": effective["argv"], "cwd": effective["cwd"],
            "environment": effective["environment"], "exit_code": execution["exit_code"],
            "timed_out": False, "completed": True,
            "build_receipt_sha256": build["receipt_sha256"],
        }
        command_path = destination / "command.json"
        write_json_new(command_path, command)
    finally:
        backend.remove_container(container_id)
        removed = {"container_id": container_id, "name": spec["name"],
                   "id_absent": backend.container_absent(container_id),
                   "name_absent": backend.container_absent(spec["name"])}
        require(removed["id_absent"] and removed["name_absent"],
                "Exact test container was not removed")
    container_record["cleanup"] = removed
    write_json_new(inspect_path, container_record)
    return {
        "target": classify_suite(suite), "case_count": len(cases), "cases": cases,
        "command": portable_ref(output, command_path),
        "container": portable_ref(output, inspect_path),
        "stdout": portable_ref(output, stdout),
        "results": {suite["result_files"][0]: portable_ref(output, result_path)},
    }


def mount_points_below(root: Path):
    found = []
    try:
        lines = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError as error:
        raise comparison.EvidenceError("Cannot audit mounts before cleanup") from error
    for line in lines:
        fields = line.split()
        if len(fields) < 5:
            continue
        value = fields[4].replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")
        path = Path(value)
        if path == root or path.is_relative_to(root):
            found.append(str(path))
    return sorted(found)


def protected_tree_inventory(root: Path):
    """Authenticate every entry currently retained in a protected tree.

    This describes the tree that exists now.  It intentionally does not demand
    build intermediates which an authenticated prune operation has removed.
    Its purpose is to prove that an isolated test did not mutate, add, replace,
    or delete any entry in the receipted OUT.
    """
    root = exact_existing_directory(Path(root), "protected inventory root")
    root_node = root.lstat()
    root_device = root_node.st_dev
    nested_mounts = [path for path in mount_points_below(root) if Path(path) != root]
    require(not nested_mounts, "Protected tree contains a nested mount point")
    rows = []
    byte_count = 0

    def metadata(node):
        return {
            "device": node.st_dev, "inode": node.st_ino,
            "mode": stat.S_IMODE(node.st_mode), "uid": node.st_uid, "gid": node.st_gid,
            "mtime_ns": node.st_mtime_ns, "ctime_ns": node.st_ctime_ns,
        }

    def scan(directory: Path, relative: PurePosixPath):
        nonlocal byte_count
        before = directory.lstat()
        require(stat.S_ISDIR(before.st_mode) and not directory.is_symlink() and
                before.st_dev == root_device,
                "Protected inventory directory changed identity: " + str(directory))
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as error:
            raise comparison.EvidenceError(
                "Cannot enumerate protected inventory: " + str(directory)) from error
        for entry in entries:
            child = directory / entry.name
            child_relative = PurePosixPath(entry.name) if relative == PurePosixPath(".") \
                else relative / entry.name
            comparison.safe_relative(child_relative.as_posix(), "protected OUT inventory path")
            try:
                node = child.lstat()
            except OSError as error:
                raise comparison.EvidenceError(
                    "Cannot stat protected OUT entry: " + child_relative.as_posix()) from error
            if stat.S_ISDIR(node.st_mode):
                scan(child, child_relative)
            elif stat.S_ISREG(node.st_mode):
                identity = stream_file_identity(child)
                byte_count += identity["size"]
                rows.append({"path": child_relative.as_posix(), "type": "file", **identity})
            elif stat.S_ISLNK(node.st_mode):
                link_before = node
                try:
                    target = os.readlink(child)
                    link_after = child.lstat()
                except OSError as error:
                    raise comparison.EvidenceError(
                        "Cannot authenticate protected symlink: " + child_relative.as_posix()) from error
                fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
                require(target and "\x00" not in target and
                        all(getattr(link_before, key) == getattr(link_after, key) for key in fields),
                        "Protected symlink changed while reading: " + child_relative.as_posix())
                rows.append({"path": child_relative.as_posix(), "type": "symlink",
                             "target": target, **metadata(link_before)})
            else:
                raise comparison.EvidenceError(
                    "Protected OUT contains a special entry: " + child_relative.as_posix())
        after = directory.lstat()
        fields = ("st_dev", "st_ino", "st_mode", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, key) == getattr(after, key) for key in fields),
                "Protected directory changed while inventorying: " + str(directory))
        rows.append({"path": "." if relative == PurePosixPath(".") else relative.as_posix(),
                     "type": "directory", **metadata(after)})

    scan(root, PurePosixPath("."))
    require(not [path for path in mount_points_below(root) if Path(path) != root],
            "Protected tree mount topology changed while inventorying")
    rows.sort(key=lambda row: row["path"])
    return {
        "schema": SCHEMA, "kind": "wonad-phase1-complete-current-out-inventory",
        "semantics": "complete-current-tree-including-pruned-state-not-required-intermediates",
        "entry_count": len(rows), "byte_count": byte_count,
        "ledger_sha256": canonical_digest(rows), "entries": rows,
    }


def validate_protected_inventory(value):
    require(isinstance(value, dict) and set(value) == {
                "schema", "kind", "semantics", "entry_count", "byte_count",
                "ledger_sha256", "entries"} and
            value.get("schema") == SCHEMA and
            value.get("kind") == "wonad-phase1-complete-current-out-inventory" and
            value.get("semantics") ==
            "complete-current-tree-including-pruned-state-not-required-intermediates" and
            isinstance(value.get("entries"), list) and value.get("entries") and
            type(value.get("entry_count")) is int and
            value["entry_count"] == len(value["entries"]) and
            type(value.get("byte_count")) is int and value["byte_count"] >= 0 and
            SHA256.fullmatch(str(value.get("ledger_sha256", ""))) is not None and
            value["ledger_sha256"] == canonical_digest(value["entries"]),
            "Invalid complete current OUT inventory evidence")
    require([row.get("path") for row in value["entries"]] ==
            sorted(row.get("path") for row in value["entries"]) and
            len({row.get("path") for row in value["entries"]}) == len(value["entries"]) and
            any(row.get("path") == "." and row.get("type") == "directory"
                for row in value["entries"]),
            "Complete current OUT inventory is unordered or lacks its root")
    return value


def inventory_tree(root: Path):
    rows, total = [], 0
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        for name in sorted(names + files):
            path = directory_path / name
            node = path.lstat()
            relative = path.relative_to(root).as_posix()
            require(not stat.S_ISLNK(node.st_mode), "Refusing to clean a symlinked test OUT")
            if stat.S_ISDIR(node.st_mode):
                rows.append({"path": relative, "type": "directory",
                             "mode": stat.S_IMODE(node.st_mode), "uid": node.st_uid})
            elif stat.S_ISREG(node.st_mode):
                file_value = sha256_file(path)
                total += file_value["size"]
                rows.append({"path": relative, "type": "file",
                             "mode": stat.S_IMODE(node.st_mode), "uid": node.st_uid,
                             **file_value})
            else:
                raise comparison.EvidenceError(
                    "Refusing to clean special entry in test OUT: " + relative)
    return {"entry_count": len(rows), "byte_count": total,
            "ledger_sha256": canonical_digest(rows)}


def cleanup_workspace(workspace: Path, ownership):
    node = workspace.lstat()
    require((node.st_dev, node.st_ino, node.st_uid, stat.S_IMODE(node.st_mode)) ==
            (ownership["device"], ownership["inode"], ownership["uid"], 0o700),
            "Test OUT identity changed before cleanup")
    marker = workspace / ".wonad-atest-owner"
    require(stable_bytes(marker, maximum=1024, allow_empty=False).decode() == ownership["nonce"] + "\n",
            "Test OUT ownership marker changed")
    require(not mount_points_below(workspace), "Test OUT still contains a mount point")
    inventory = inventory_tree(workspace)
    quarantine = workspace.parent / (".wonad-atest-delete-" + ownership["nonce"])
    require(not os.path.lexists(quarantine), "Cleanup quarantine already exists")
    os.rename(workspace, quarantine)
    fsync_directory(workspace.parent)
    quarantined = quarantine.lstat()
    require((quarantined.st_dev, quarantined.st_ino, quarantined.st_uid) ==
            (ownership["device"], ownership["inode"], ownership["uid"]),
            "Cleanup quarantine is not the owned test OUT")
    shutil.rmtree(quarantine)
    fsync_directory(workspace.parent)
    require(not os.path.lexists(workspace) and not os.path.lexists(quarantine),
            "Disposable test OUT cleanup was incomplete")
    return {"schema": SCHEMA, "kind": "wonad-phase1-isolated-cleanup",
            "ownership": ownership, "inventory": inventory,
            "method": "same-parent-rename-then-rmtree", "workspace_absent": True,
            "quarantine_absent": True}


def broker_evidence(broker, output: Path):
    log_copy = output / "adb-server.log"
    copy_new(Path(broker["log"]), log_copy)
    return {"schema": SCHEMA, "kind": "wonad-phase1-private-adb",
            "transport": "localfilesystem-unix-socket", "serial": broker["serial"],
            "argv": broker["argv"], "socket": str(broker["socket"]),
            "pid": broker["pid"], "stopped": broker.get("stopped") is True,
            "exit_code": broker.get("exit_code"), "log": portable_ref(output, log_copy)}


def validate_stable_device(before, after):
    require(before == after and before["boot_id"] == after["boot_id"],
            "Emulator identity/state changed during the test run")


def run(role: str, build_receipt: Path, build_sha256: str, plan_path: Path,
        test_out: Path, output: Path, container_prefix: str, timeout_seconds: int,
        *, backend=None):
    require(role in {"baseline", "custom"}, "Role must be baseline or custom")
    require(type(timeout_seconds) is int and 60 <= timeout_seconds <= MAX_TIMEOUT,
            "Per-suite timeout must be 60 seconds..12 hours")
    require(NAME.fullmatch(container_prefix) is not None, "Invalid container-name prefix")
    production = backend is None
    backend = ProductionBackend() if production else backend
    build_receipt = comparison.literal_file(Path(build_receipt), "build receipt")
    plan_path = comparison.literal_file(Path(plan_path), "upstream-test plan")

    # Establish and pin the local Docker endpoint before invoking the existing
    # build verifier, whose preserved-container checks call `docker` by name.
    # With endpoint overrides forbidden and PATH resolving to the audited CLI,
    # those inherited verifier probes cannot silently select a remote daemon.
    docker_identity = backend.docker_identity()
    if production:
        locality.reject_overrides()
        selected_docker = shutil.which("docker")
        require(selected_docker is not None and
                Path(selected_docker).resolve(strict=True) == DOCKER,
                "PATH does not select the audited /usr/bin/docker")
    receipt_before, build_before = full_build_verify(build_receipt, build_sha256, role)
    source, build_out, test_out, output = safe_roots(
        Path(build_before["source_root"]), Path(build_before["out_dir"]),
        Path(test_out), Path(output))
    plan = comparison.validate_plan(comparison.load_json(plan_path))
    require(plan["release"] == receipt_before["source"]["pin"]["release"],
            "Test plan release differs from build receipt")
    image_before = normalize_image(backend.inspect_image(build_before["builder_image"]["id"]))
    require(image_before == build_before["builder_image"],
            "Installed builder image differs from the receipted immutable image")
    effective, serial = validate_plan_environment(plan, image_before, build_before)
    source_freeze_before = source_freeze_verify(receipt_before, build_before)
    out_inventory_before = protected_tree_inventory(build_out)

    output.mkdir(mode=0o700)
    (output / "inputs").mkdir(mode=0o700)
    copy_new(build_receipt, output / "inputs/build-receipt.json")
    copy_new(plan_path, output / "inputs/plan.json")
    copy_new(RUNNER, output / "inputs/run_phase1_upstream_tests.py")
    write_json_new(output / "build-before.json", build_before)
    write_json_new(output / "builder-image-before.json", image_before)
    write_json_new(output / "source-freeze-before.json", source_freeze_before)
    write_json_new(output / "build-out-inventory-before.json", out_inventory_before)
    tool_before = toolchain_record(source, image_before, docker_identity)
    write_json_new(output / "toolchain-before.json", tool_before)

    test_out.mkdir(mode=0o700)
    node = test_out.lstat()
    nonce = secrets.token_hex(16)
    ownership = {"path": str(test_out), "device": node.st_dev, "inode": node.st_ino,
                 "uid": node.st_uid, "gid": node.st_gid, "nonce": nonce}
    write_bytes_new(test_out / ".wonad-atest-owner", (nonce + "\n").encode())
    (test_out / "out").mkdir(mode=0o700)
    adb = comparison.literal_file(source / "prebuilts/runtime/adb", "source-pinned adb")

    broker = None
    suites = {}
    cleanup = None
    failure = None
    try:
        broker = backend.start_broker(adb, test_out, serial)
        broker["serial"] = serial
        before_device = capture_device(backend, adb, broker, serial, build_before)
        write_json_new(output / "device-before.json", before_device)
        for suite in plan["suites"]:
            suites[suite["id"]] = run_suite(
                backend, suite, effective[suite["id"]], build_before, source, test_out,
                output, broker, container_prefix, timeout_seconds, nonce)
        after_device = capture_device(backend, adb, broker, serial, build_before)
        validate_stable_device(before_device, after_device)
        write_json_new(output / "device-after.json", after_device)
    except BaseException as error:  # cleanup must also run for interrupts
        failure = error
    finally:
        try:
            if broker is not None:
                broker = backend.stop_broker(broker)
                broker_record = broker_evidence(broker, output)
                write_json_new(output / "adb-broker.json", broker_record)
            cleanup = cleanup_workspace(test_out, ownership)
            write_json_new(output / "cleanup.json", cleanup)
        except BaseException as cleanup_error:
            if failure is None:
                failure = cleanup_error
    if failure is not None:
        raise failure

    receipt_after, build_after = full_build_verify(build_receipt, build_sha256, role)
    require(build_after == build_before and receipt_after == receipt_before and
            sha256_file(build_receipt, allow_empty=False)["sha256"] == build_sha256 and
            sha256_file(plan_path, allow_empty=False) ==
            sha256_file(output / "inputs/plan.json", allow_empty=False) and
            sha256_file(RUNNER, allow_empty=False) ==
            sha256_file(output / "inputs/run_phase1_upstream_tests.py", allow_empty=False),
            "Authenticated inputs changed during Atest execution")
    source_freeze_after = source_freeze_verify(receipt_after, build_after)
    require(source_freeze_after == source_freeze_before,
            "Receipted source freeze changed during Atest execution")
    out_inventory_after = protected_tree_inventory(build_out)
    require(out_inventory_after == out_inventory_before,
            "Complete current receipted OUT inventory changed during Atest execution")
    image_after = normalize_image(backend.inspect_image(build_after["builder_image"]["id"]))
    require(image_after == image_before, "Immutable builder image changed during testing")
    docker_identity_after = backend.docker_identity()
    require(docker_identity_after == docker_identity,
            "Docker daemon/endpoint identity changed during testing")
    tool_after = toolchain_record(source, image_after, docker_identity_after)
    require(tool_after == tool_before, "Source-pinned test toolchain changed during testing")
    write_json_new(output / "build-after.json", build_after)
    write_json_new(output / "builder-image-after.json", image_after)
    write_json_new(output / "source-freeze-after.json", source_freeze_after)
    write_json_new(output / "build-out-inventory-after.json", out_inventory_after)
    write_json_new(output / "toolchain-after.json", tool_after)

    receipt = {
        "schema": SCHEMA, "kind": KIND, "scope": SCOPE, "role": role,
        "build": {
            "receipt": portable_ref(output, output / "inputs/build-receipt.json"),
            "authenticated_sha256": build_sha256,
            "before": portable_ref(output, output / "build-before.json"),
            "after": portable_ref(output, output / "build-after.json"),
            "summary_sha256": canonical_digest(build_before),
            "verification": "receipt-verifier-rehash-true-before-and-after",
        },
        "plan": {"file": portable_ref(output, output / "inputs/plan.json"),
                 "canonical_sha256": canonical_digest(plan)},
        "builder": {"id": image_before["id"],
                    "identity_sha256": canonical_digest(image_before),
                    "before": portable_ref(output, output / "builder-image-before.json"),
                    "after": portable_ref(output, output / "builder-image-after.json")},
        "toolchain": {"before": portable_ref(output, output / "toolchain-before.json"),
                      "after": portable_ref(output, output / "toolchain-after.json")},
        "protected_inputs": {
            "source_freeze": {
                "before": portable_ref(output, output / "source-freeze-before.json"),
                "after": portable_ref(output, output / "source-freeze-after.json"),
                "snapshot_sha256": source_freeze_before["snapshot_sha256"],
                "verification": "complete-receipted-source-recollection-before-and-after",
            },
            "receipted_out": {
                "before": portable_ref(output, output / "build-out-inventory-before.json"),
                "after": portable_ref(output, output / "build-out-inventory-after.json"),
                "ledger_sha256": out_inventory_before["ledger_sha256"],
                "verification": "complete-current-tree-before-and-after",
            },
        },
        "device": {"before": portable_ref(output, output / "device-before.json"),
                   "after": portable_ref(output, output / "device-after.json")},
        "adb_broker": portable_ref(output, output / "adb-broker.json"),
        "cleanup": portable_ref(output, output / "cleanup.json"),
        "isolation": {
            "source": "read-only bind at " + CONTAINER_SOURCE,
            "receipted_out": "not mounted",
            "test_out": "sole writable host bind at " + CONTAINER_TEST,
            "network": "none", "rootfs": "read-only", "capabilities": "none",
            "no_new_privileges": True, "container_per_suite": True,
        },
        "suites": suites,
        "generator": portable_ref(output, output / "inputs/run_phase1_upstream_tests.py"),
    }
    validate_bundle_shape(receipt)
    receipt_path = output / "run-receipt.json"
    candidate = output / (".run-receipt-candidate-" + nonce + ".json")
    write_json_new(candidate, receipt)
    digest = sha256_file(candidate, allow_empty=False)["sha256"]
    try:
        verify(candidate, digest)
    except BaseException:
        candidate.unlink(missing_ok=True)
        fsync_directory(output)
        raise
    os.rename(candidate, receipt_path)
    fsync_directory(output)
    return receipt_path, digest


def load_portable_json(root: Path, reference, label):
    path = resolve_ref(root, reference, label, allow_empty=False)
    return comparison.load_json(path)


def validate_bundle_shape(value):
    require(isinstance(value, dict) and set(value) == {
        "schema", "kind", "scope", "role", "build", "plan", "builder", "toolchain",
        "protected_inputs", "device", "adb_broker", "cleanup", "isolation", "suites",
        "generator"
    } and value.get("schema") == SCHEMA and value.get("kind") == KIND and
            value.get("scope") == SCOPE and value.get("role") in {"baseline", "custom"} and
            isinstance(value.get("suites"), dict), "Invalid schema-2 Atest receipt")
    require(isinstance(value.get("build"), dict) and set(value["build"]) == {
        "receipt", "authenticated_sha256", "before", "after", "summary_sha256",
        "verification"
    } and value["build"]["verification"] ==
            "receipt-verifier-rehash-true-before-and-after" and
            SHA256.fullmatch(str(value["build"]["authenticated_sha256"])) is not None and
            SHA256.fullmatch(str(value["build"]["summary_sha256"])) is not None and
            isinstance(value.get("plan"), dict) and set(value["plan"]) == {
                "file", "canonical_sha256"} and
            SHA256.fullmatch(str(value["plan"]["canonical_sha256"])) is not None and
            isinstance(value.get("builder"), dict) and set(value["builder"]) == {
                "id", "identity_sha256", "before", "after"} and
            IMAGE_ID.fullmatch(str(value["builder"]["id"])) is not None and
            SHA256.fullmatch(str(value["builder"]["identity_sha256"])) is not None and
            isinstance(value.get("toolchain"), dict) and set(value["toolchain"]) == {
                "before", "after"} and
            isinstance(value.get("protected_inputs"), dict) and
            set(value["protected_inputs"]) == {"source_freeze", "receipted_out"} and
            isinstance(value["protected_inputs"].get("source_freeze"), dict) and
            set(value["protected_inputs"]["source_freeze"]) == {
                "before", "after", "snapshot_sha256", "verification"} and
            value["protected_inputs"]["source_freeze"]["verification"] ==
            "complete-receipted-source-recollection-before-and-after" and
            SHA256.fullmatch(str(value["protected_inputs"]["source_freeze"].get(
                "snapshot_sha256", ""))) is not None and
            isinstance(value["protected_inputs"].get("receipted_out"), dict) and
            set(value["protected_inputs"]["receipted_out"]) == {
                "before", "after", "ledger_sha256", "verification"} and
            value["protected_inputs"]["receipted_out"]["verification"] ==
            "complete-current-tree-before-and-after" and
            SHA256.fullmatch(str(value["protected_inputs"]["receipted_out"].get(
                "ledger_sha256", ""))) is not None and
            isinstance(value.get("device"), dict) and set(value["device"]) == {
                "before", "after"}, "Invalid schema-2 binding records")
    require(value.get("isolation") == {
        "source": "read-only bind at " + CONTAINER_SOURCE,
        "receipted_out": "not mounted",
        "test_out": "sole writable host bind at " + CONTAINER_TEST,
        "network": "none", "rootfs": "read-only", "capabilities": "none",
        "no_new_privileges": True, "container_per_suite": True,
    }, "Receipt does not claim the exact isolation profile")
    return value


def verify(receipt_path: Path, expected_sha256: str, *, rehash_build=False):
    receipt_path = comparison.literal_file(Path(receipt_path), "schema-2 run receipt")
    require(SHA256.fullmatch(str(expected_sha256)) is not None and
            sha256_file(receipt_path, allow_empty=False)["sha256"] == expected_sha256,
            "Run receipt differs from its out-of-band SHA-256")
    root = receipt_path.parent
    value = validate_bundle_shape(comparison.load_json(receipt_path))
    generator = resolve_ref(root, value["generator"], "generator", allow_empty=False)
    require(sha256_file(generator, allow_empty=False) == sha256_file(RUNNER, allow_empty=False),
            "Run generator differs from the reviewed runner")

    plan = comparison.validate_plan(load_portable_json(root, value["plan"]["file"], "plan"))
    require(value["plan"]["canonical_sha256"] == canonical_digest(plan),
            "Plan canonical digest differs")
    build_before = load_portable_json(root, value["build"]["before"], "build before")
    build_after = load_portable_json(root, value["build"]["after"], "build after")
    require(build_before == build_after and
            value["build"]["summary_sha256"] == canonical_digest(build_before) and
            value["build"]["authenticated_sha256"] == build_before["receipt_sha256"],
            "Build full-rehash records differ")
    copied_build = resolve_ref(root, value["build"]["receipt"], "build receipt", allow_empty=False)
    require(value["build"]["receipt"]["sha256"] == value["build"]["authenticated_sha256"],
            "Copied build receipt is not the authenticated receipt")
    copied_build_value = comparison.load_json(copied_build)

    image_before = load_portable_json(root, value["builder"]["before"], "builder before")
    image_after = load_portable_json(root, value["builder"]["after"], "builder after")
    require(image_before == image_after and value["builder"]["id"] == image_before["id"] and
            value["builder"]["identity_sha256"] == canonical_digest(image_before) and
            image_before == build_before["builder_image"], "Builder image binding differs")
    tool_before = load_portable_json(root, value["toolchain"]["before"], "toolchain before")
    tool_after = load_portable_json(root, value["toolchain"]["after"], "toolchain after")
    require(tool_before == tool_after and tool_before["builder_image_id"] == image_before["id"],
            "Toolchain changed during testing")
    protected = value["protected_inputs"]
    source_before = load_portable_json(
        root, protected["source_freeze"]["before"], "source freeze before")
    source_after = load_portable_json(
        root, protected["source_freeze"]["after"], "source freeze after")
    require(source_before == source_after and set(source_before) == {
                "schema", "kind", "receipt_sha256", "snapshot_sha256", "snapshot"} and
            source_before.get("schema") == SCHEMA and
            source_before.get("kind") == "wonad-phase1-current-source-freeze" and
            source_before.get("receipt_sha256") == build_before["receipt_sha256"] and
            source_before.get("snapshot") == copied_build_value.get("source") and
            source_before.get("snapshot_sha256") == canonical_digest(source_before["snapshot"]) ==
            protected["source_freeze"]["snapshot_sha256"],
            "Source-freeze recollection evidence differs from the build receipt")
    out_before = validate_protected_inventory(load_portable_json(
        root, protected["receipted_out"]["before"], "receipted OUT inventory before"))
    out_after = validate_protected_inventory(load_portable_json(
        root, protected["receipted_out"]["after"], "receipted OUT inventory after"))
    require(out_before == out_after and out_before["ledger_sha256"] ==
            protected["receipted_out"]["ledger_sha256"],
            "Complete current receipted OUT inventory changed during testing")
    effective, expected_serial = validate_plan_environment(plan, image_before, build_before)
    device_before = load_portable_json(root, value["device"]["before"], "device before")
    device_after = load_portable_json(root, value["device"]["after"], "device after")
    validate_stable_device(device_before, device_after)
    require(device_before["fingerprint"] == build_before["fingerprint"] and
            device_before["artifacts"] == {
                name: ({"path": "/" + row["path"], "state": "absent"}
                       if row["state"] == "absent" else
                       {"path": "/" + row["path"], "state": "present",
                        "sha256": row["sha256"]})
                for name, row in build_before["os_artifacts"].items()},
            "Device is not bound to receipted OS artifacts")
    broker = load_portable_json(root, value["adb_broker"], "adb broker")
    require(broker.get("transport") == "localfilesystem-unix-socket" and
            broker.get("stopped") is True and broker.get("serial") == expected_serial ==
            device_before["serial"],
            "Private adb broker evidence is incomplete")
    resolve_ref(root, broker["log"], "adb broker log")
    cleanup = load_portable_json(root, value["cleanup"], "cleanup")
    require(cleanup.get("workspace_absent") is True and
            cleanup.get("quarantine_absent") is True and
            cleanup.get("method") == "same-parent-rename-then-rmtree",
            "Disposable test OUT cleanup is incomplete")

    require(set(value["suites"]) == {suite["id"] for suite in plan["suites"]},
            "Receipt suite set differs from plan")
    for suite in plan["suites"]:
        row = value["suites"][suite["id"]]
        require(isinstance(row, dict) and set(row) == {
            "target", "case_count", "cases", "command", "container", "stdout", "results"
        } and row["target"] == classify_suite(suite) and
                row["case_count"] == len(row["cases"]) >= suite["minimum_cases"] and
                list(row["cases"]) == sorted(row["cases"]),
                "Invalid suite evidence: " + suite["id"])
        command = load_portable_json(root, row["command"], suite["id"] + " command")
        require(command.get("completed") is True and command.get("timed_out") is False and
                command.get("suite") == suite["id"] and
                command.get("build_receipt_sha256") == build_before["receipt_sha256"] and
                command.get("argv") == effective[suite["id"]]["argv"] and
                command.get("cwd") == effective[suite["id"]]["cwd"] and
                command.get("environment") == effective[suite["id"]]["environment"],
                "Incomplete command evidence: " + suite["id"])
        container = load_portable_json(root, row["container"], suite["id"] + " container")
        spec = container.get("spec", {})
        observed = container.get("observed", {})
        mounts = observed.get("mounts", [])
        require(spec.get("image") == image_before["id"] and
                spec.get("source") == build_before["source_root"] and
                spec.get("workspace") == cleanup["ownership"]["path"] and
                spec.get("adb_dir") == str(Path(broker["socket"]).parent) and
                spec.get("argv") == effective[suite["id"]]["argv"] and
                spec.get("environment") == effective[suite["id"]]["environment"] and
                build_before["out_dir"] not in json.dumps(spec, sort_keys=True) and
                container.get("docker_argv") == container_docker_argv(spec) and
                container.get("cleanup") == {
                    "container_id": observed.get("id"), "name": observed.get("name"),
                    "id_absent": True, "name_absent": True} and
                container.get("timed_out") is False and observed.get("network_mode") == "none" and
                observed.get("read_only") is True and observed.get("cap_drop") == ["ALL"] and
                len(mounts) == 3 and
                sorted((mount.get("destination"), mount.get("rw")) for mount in mounts) ==
                [("/adb", False), (CONTAINER_SOURCE, False), (CONTAINER_TEST, True)],
                "Container evidence lost the isolation profile: " + suite["id"])
        resolve_ref(root, row["stdout"], suite["id"] + " stdout")
        require(set(row["results"]) == set(suite["result_files"]),
                "Suite raw result set differs from plan")
        rebuilt = {}
        for relative, reference in row["results"].items():
            path = resolve_ref(root, reference, suite["id"] + " " + relative,
                               maximum=comparison.MAX_JSON, allow_empty=False)
            for identity, status in comparison.parse_atest(path).items():
                require(identity not in rebuilt, "Duplicate Atest case")
                rebuilt[identity] = status
        require(dict(sorted(rebuilt.items())) == row["cases"],
                "Normalized cases differ from native Atest JSON")
    if rehash_build:
        live_receipt, observed_build = full_build_verify(
            copied_build, value["build"]["authenticated_sha256"], value["role"])
        require(observed_build == build_before, "Live build rehash differs from run evidence")
        require(source_freeze_verify(live_receipt, observed_build) == source_before,
                "Live source-freeze recollection differs from run evidence")
        require(protected_tree_inventory(Path(observed_build["out_dir"])) == out_before,
                "Live complete receipted OUT inventory differs from run evidence")
    return value


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    actions = value.add_subparsers(dest="action", required=True)
    run_parser = actions.add_parser("run", help="execute and seal an isolated Atest run")
    run_parser.add_argument("--role", choices=("baseline", "custom"), required=True)
    run_parser.add_argument("--build-receipt", type=Path, required=True)
    run_parser.add_argument("--build-receipt-sha256", required=True)
    run_parser.add_argument("--plan", type=Path, required=True)
    run_parser.add_argument("--test-out", type=Path, required=True,
                            help="fresh disposable directory outside source/build/evidence")
    run_parser.add_argument("--output", type=Path, required=True)
    run_parser.add_argument("--container-prefix", default="wonad-atest")
    run_parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT)
    verify_parser = actions.add_parser("verify", help="verify a schema-2 evidence bundle")
    verify_parser.add_argument("--receipt", type=Path, required=True)
    verify_parser.add_argument("--expected-sha256", required=True)
    verify_parser.add_argument("--rehash-build", action="store_true")
    return value


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.action == "run":
            receipt, digest = run(
                args.role, args.build_receipt, args.build_receipt_sha256, args.plan,
                args.test_out, args.output, args.container_prefix, args.timeout_seconds)
            print(str(receipt))
            print(digest)
        else:
            verify(args.receipt, args.expected_sha256, rehash_build=args.rehash_build)
            print("PASS: " + str(args.receipt))
        return 0
    except (comparison.EvidenceError, locality.ProofError, provenance.ProvenanceError,
            OSError, subprocess.SubprocessError) as error:
        print("run_phase1_upstream_tests.py: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
