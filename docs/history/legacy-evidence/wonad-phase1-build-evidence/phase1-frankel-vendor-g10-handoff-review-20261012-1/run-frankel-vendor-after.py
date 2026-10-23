#!/usr/bin/env python3
"""Prepare the pinned Frankel vendor tree across a strict host/builder boundary.

The host authenticates the checkout, host tools and public factory cache and
owns every cleanup of regenerable adevtool state.  The immutable builder sees
three explicit binds and executes only ``generate-frankel-vendor.sh``.  It is
never given authority to run the host-pinned provenance cleanup.

The default action is a read-only admission check.  ``--run`` is the only
mutating action.  It creates a fresh, retained attempt lock/work/log/evidence
namespace, uses FICLONE with no byte-copy fallback, and retains the exact
owned Docker container whether generation succeeds or fails.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import types

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "android/platform/generate-frankel-vendor.sh"
DOCKER = ("/usr/bin/docker", "--host", "unix:///var/run/docker.sock")
BUILDER_SOURCE = Path("/grapheneos")
BUILDER_REPO = Path("/wonad")
BUILDER_CACHE = Path("/adevtool-images")
# The retained generation-8 builder was OOM-killed under the fixed 40 GiB
# cap. This proposed 48 GiB/no-extra-swap profile is not a measured peak or a
# success guarantee. Admission observes >=48 GiB physical RAM and >=42 GiB
# currently available RAM; it does not reserve either. Upstream clears the
# graph builder's environment, so GOMEMLIMIT is not a runtime heap bound here.
MEMORY = 48 * 1024**3
MIN_MEM_AVAILABLE = 42 * 1024**3
MIN_SOURCE_FREE = 64 * 1024**3
# Docker's tmpfs defaults include noexec. AOSP's Go bootstrap executes its
# freshly compiled microfactory from TMPDIR, so execution here is required.
# This remains an ephemeral, bounded, nosuid/nodev mount in the non-root,
# capability-free builder; no host mount or permission is changed.
TMPFS = "rw,nosuid,nodev,exec,size=4294967296,mode=1777"
FICLONE = 0x40049409
MAX_JSON = 1024 * 1024
MAX_INPUT = 8 * 1024 * 1024
MAX_CMDLINE = 65536
MAX_DEBUG_TOP = 65536

REQUIRED_REPO_INPUTS = (
    "android/grapheneos.lock.json",
    "android/platform/allowed_signers",
    "android/platform/generate-frankel-vendor.sh",
    "android/tools/checkout_health.py",
    "android/tools/docker_locality_proof.py",
    "android/tools/phase1_provenance.py",
    "android/tools/run_frankel_vendor.py",
    "android/tools/verify_checkout.py",
    "android/tools/verify_sources.py",
)

REQUIRED_SOURCE_INPUTS = (
    ".repo/manifests/default.xml",
    "vendor/adevtool/config/build-index/build-index-main.yml",
    "vendor/adevtool/config/device/common/gen10pixel.yml",
    "vendor/adevtool/config/device/frankel.yml",
    "vendor/adevtool/src/commands/download.ts",
    "vendor/adevtool/src/config/paths.ts",
    "vendor/adevtool/src/frontend/source.ts",
    "vendor/adevtool/src/images/device-image.ts",
    "vendor/adevtool/src/images/download.ts",
    "vendor/adevtool/vendor-specs/google_devices/frankel.yml",
    "vendor/adevtool/yarn.lock",
    "vendor/state/frankel.json",
)

EXPECTED_ADEVTOOL_TARGETS = (
    "aapt2", "apksigner", "aprotoc", "arsclib", "debugfs", "dispol",
    "fsck.erofs", "lpdump", "lpunpack", "lz4", "ota_extractor",
    "simg2img", "sqlite3", "toybox",
)


class Refusal(RuntimeError):
    """A fail-closed admission or evidence failure."""


def require(value, message):
    if not value:
        raise Refusal(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def unique_json(payload, label):
    def pairs(values):
        result = {}
        for key, value in values:
            require(isinstance(key, str) and key not in result,
                    f"Duplicate or non-string key in {label}: {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(payload, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Refusal(f"Invalid JSON in {label}: {error}") from error
    require(isinstance(value, dict), f"{label} must be one object")
    return value


def _same_stat(left, right):
    fields = ("st_dev", "st_ino", "st_size", "st_mode", "st_uid", "st_gid",
              "st_nlink", "st_mtime_ns", "st_ctime_ns")
    return all(getattr(left, name) == getattr(right, name) for name in fields)


def capture_regular(path, maximum=MAX_JSON):
    """Read one no-follow regular-file object and bind its pathname identity."""
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
            path.resolve(strict=True) == path,
            f"Not one canonical ordinary file: {path}")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        require(_same_stat(before, opened), f"File changed before capture: {path}")
        chunks = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        require(total <= maximum, f"File exceeds the bounded capture size: {path}")
        require(_same_stat(opened, os.fstat(descriptor)),
                f"File changed during capture: {path}")
    finally:
        os.close(descriptor)
    require(_same_stat(before, path.lstat()), f"File pathname changed during capture: {path}")
    payload = b"".join(chunks)
    return payload, {"path": str(path), "bytes": len(payload),
                     "sha256": hashlib.sha256(payload).hexdigest()}


def directory(path, *, uid=None, gid=None):
    path = Path(path)
    value = path.lstat()
    require(stat.S_ISDIR(value.st_mode) and not path.is_symlink() and
            path.resolve(strict=True) == path, f"Not a canonical ordinary directory: {path}")
    if uid is not None:
        require(value.st_uid == uid, f"Directory UID differs: {path}")
    if gid is not None:
        require(value.st_gid == gid, f"Directory GID differs: {path}")
    return {"path": str(path), "device": value.st_dev, "inode": value.st_ino,
            "mode": stat.S_IMODE(value.st_mode), "uid": value.st_uid, "gid": value.st_gid}


def source_directory_identities(config):
    """Capture stable directory identities, excluding mutable timestamps."""
    return {
        "source": directory(config.source, uid=os.getuid(), gid=os.getgid()),
        "repo_metadata": directory(config.source / ".repo", uid=os.getuid(), gid=os.getgid()),
        "out": directory(config.source / "out", uid=os.getuid(), gid=os.getgid()),
        "adevtool": directory(config.source / "vendor/adevtool",
                              uid=os.getuid(), gid=os.getgid()),
    }


def require_source_directory_identities(config, expected, locked_source_fd):
    require(isinstance(expected, dict) and
            set(expected) == {"source", "repo_metadata", "out", "adevtool"},
            "Source directory identity inventory differs")
    current = source_directory_identities(config)
    require(current == expected, "Source directory identity changed")
    opened = os.fstat(locked_source_fd)
    source = expected["source"]
    require(stat.S_ISDIR(opened.st_mode) and
            {"device": opened.st_dev, "inode": opened.st_ino,
             "mode": stat.S_IMODE(opened.st_mode), "uid": opened.st_uid,
             "gid": opened.st_gid} ==
            {key: source[key] for key in ("device", "inode", "mode", "uid", "gid")},
            "Locked source directory identity changed")
    return current


def capture_open_regular(path, descriptor, maximum=MAX_JSON):
    """Capture an already-open file and prove its pathname is the same object."""
    path = Path(path)
    opened = os.fstat(descriptor)
    require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1,
            f"Open evidence object is not one ordinary file: {path}")
    require(_same_stat(opened, path.lstat()), f"Open evidence pathname changed: {path}")
    result = bytearray()
    offset = 0
    while len(result) <= maximum:
        chunk = os.pread(descriptor, min(1024 * 1024, maximum + 1 - len(result)), offset)
        if not chunk:
            break
        result.extend(chunk)
        offset += len(chunk)
    require(len(result) <= maximum, f"Open evidence exceeds bounded size: {path}")
    require(_same_stat(opened, os.fstat(descriptor)) and
            _same_stat(opened, path.lstat()), f"Open evidence object changed: {path}")
    return {"path": str(path), "bytes": len(result),
            "sha256": hashlib.sha256(result).hexdigest(),
            "device": opened.st_dev, "inode": opened.st_ino,
            "mode": stat.S_IMODE(opened.st_mode), "uid": opened.st_uid,
            "gid": opened.st_gid}


def fresh(path):
    path = Path(path)
    directory(path.parent, uid=os.getuid(), gid=os.getgid())
    require(not os.path.lexists(path), f"Fresh output already exists: {path}")


def write_raw_new(path, payload):
    path = Path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        count = stream.write(payload)
        require(count == len(payload), f"Short write: {path}")
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY |
                     os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return capture_regular(path)[1]


def write_new(path, value):
    return write_raw_new(path, canonical(value))


def parse_pin_rows(rows, required, label):
    result = {}
    for row in rows:
        relative, separator, digest = row.partition("=")
        path = Path(relative)
        require(separator and relative and not path.is_absolute() and ".." not in path.parts and
                re.fullmatch(r"[0-9a-f]{64}", digest) and relative not in result,
                f"Malformed or duplicate {label} pin: {row!r}")
        result[relative] = digest
    require(set(result) == set(required),
            f"{label} pin inventory differs: missing={sorted(set(required)-set(result))} "
            f"extra={sorted(set(result)-set(required))}")
    return result


def captured_inventory(root, expected, label):
    result = {}
    payloads = {}
    for relative, digest in sorted(expected.items()):
        payload, reference = capture_regular(Path(root) / relative, MAX_INPUT)
        require(reference["sha256"] == digest, f"{label} input differs: {relative}")
        result[relative] = reference
        payloads[relative] = payload
    return result, payloads


def load_captured_module(payload, path, name):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    try:
        exec(compile(payload, str(path), "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


@contextmanager
def host_environment():
    saved = dict(os.environ)
    os.environ.clear()
    os.environ.update({
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "HOME": "/nonexistent", "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
    })
    try:
        yield dict(os.environ)
    finally:
        os.environ.clear()
        os.environ.update(saved)


def run_command(argv, *, environment, timeout=120):
    return subprocess.run(argv, env=environment, check=False, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout)


def checked_command(argv, *, environment, timeout=120):
    result = run_command(argv, environment=environment, timeout=timeout)
    require(result.returncode == 0 and not result.stderr,
            f"Command failed: {argv!r}: {result.stderr[-512:].decode(errors='replace')}")
    return result.stdout


def docker_run(arguments, environment, timeout=120):
    return run_command([*DOCKER, *arguments], environment=environment, timeout=timeout)


def docker_checked(arguments, environment, timeout=120):
    return checked_command([*DOCKER, *arguments], environment=environment, timeout=timeout)


def docker_inspect(identity, environment):
    raw = docker_checked(["container", "inspect", identity], environment)
    value = unique_json(b'{"rows":' + raw + b"}", "Docker inspect wrapper")["rows"]
    require(isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict),
            "Docker inspect is ambiguous")
    return value[0], raw


def missing_container(name, environment):
    result = docker_run(["container", "inspect", "--format", "{{.Id}}", name], environment)
    require(result.returncode == 1 and not result.stdout.strip() and
            re.search(rb"No such (?:object|container):\s*" + re.escape(name.encode()) + rb"\s*$",
                      result.stderr), f"Cannot prove fresh container name: {name}")
    return True


def cpu_set(text):
    result = set()
    for piece in text.strip().split(","):
        ends = piece.split("-")
        require(1 <= len(ends) <= 2 and all(item.isdecimal() for item in ends),
                "Malformed online CPU set")
        low, high = int(ends[0]), int(ends[-1])
        require(0 <= low <= high <= 65535, "Invalid online CPU range")
        result.update(range(low, high + 1))
    return result


def _bounded_read(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        result = bytearray()
        while len(result) <= maximum:
            chunk = os.read(descriptor, min(8192, maximum + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        require(len(result) <= maximum, f"Process evidence exceeds {maximum} bytes: {path}")
        return bytes(result)
    finally:
        os.close(descriptor)


def process_kind(arguments):
    require(isinstance(arguments, list) and arguments and
            all(isinstance(item, str) and item for item in arguments), "Malformed process argv")
    names = [Path(item).name for item in arguments]
    exact = {
        "emulator": "Android emulator", "qemu-kvm": "KVM guest",
        "soong_ui": "Soong compiler", "soong_build": "Soong compiler",
        "ninja": "native compiler", "siso": "native compiler", "gradle": "Gradle build",
        "run_x86_build.py": "x86 OS build", "run_frankel_build.py": "Frankel OS build",
        "run_release_build.py": "release OS build",
        "phase1_conformance_guest.py": "fresh conformance guest",
        "run_phase1_conformance_recents_guest.py": "fresh Recents guest",
        "run_native_matrix.py": "native/GUI matrix",
        "run_phase1_upstream_guest.py": "upstream test guest",
        "run_phase1_upstream_tests.py": "upstream Atest run",
        "build_native_successor.py": "APK successor build",
        "native_compile_finalize.py": "APK successor finalize",
        "phase1_emulator_client_packet.py": "emulator packet build",
        "build-native-candidate.py": "native candidate image build",
        "build-phase1-conformance-candidate.py": "conformance candidate image build",
        "run_frankel_vendor.py": "Frankel vendor preparation",
        "generate-frankel-vendor.sh": "adevtool vendor generation",
    }
    for name in names:
        if name in exact:
            return exact[name]
        if name.startswith("qemu-system-"):
            return "QEMU guest"
        if name.startswith("continue-phase1-x86-") and name.endswith(".sh"):
            return "x86 build continuation"
        if re.fullmatch(r"run-phase1-.*-api-recents-.*\.py", name):
            return "API/Recents guest wrapper"
        if name.startswith(("run-phase1-native-matrix-", "freeze-phase1-native-matrix-")) and \
                name.endswith((".py", ".sh")):
            return "native/GUI matrix wrapper"
        if name.startswith("run-phase1-emulator-client-packet") and name.endswith((".py", ".sh")):
            return "emulator packet wrapper"
        if (name.startswith("prepare-phase1-frankel-vendor") and name.endswith(".sh")) or \
                re.fullmatch(r"phase1_frankel_vendor.*\.py", name):
            return "Frankel vendor preparation wrapper"
        if ("native-candidate" in name or "conformance-candidate" in name) and \
                name.endswith((".py", ".sh")):
            return "candidate image wrapper"
    if "org.gradle.launcher.daemon.bootstrap.GradleDaemon" in arguments:
        return "Gradle daemon"
    if "org.jetbrains.kotlin.daemon.KotlinCompileDaemon" in arguments:
        return "Kotlin compiler daemon"
    if "generate-all" in arguments and any("/vendor/adevtool/" in item for item in arguments):
        return "adevtool vendor generation"
    if any(Path(item).name == "run-build.sh" and "/vendor/adevtool/" in item
           for item in arguments):
        return "adevtool dependency build"
    if any(name in {"docker", "buildx"} for name in names) and \
            ("build" in arguments or "buildx" in arguments):
        return "Docker image build"
    if "prepare-vendor" in arguments and "release-build.sh" in names:
        return "Frankel vendor preparation wrapper"
    return None


def ancestors(proc_root=Path("/proc")):
    result = set()
    current = os.getpid()
    while current > 0 and current not in result:
        result.add(current)
        raw = (proc_root / str(current) / "stat").read_text()
        current = int(raw.rpartition(") ")[2].split()[1])
    return result


def live_process_lanes(proc_root=Path("/proc"), ignored=None):
    ignored = ancestors(proc_root) if ignored is None else set(ignored)
    result = []
    for item in proc_root.iterdir():
        if not item.name.isdecimal() or int(item.name) in ignored:
            continue
        try:
            raw_stat = _bounded_read(item / "stat", 4096)
            state = raw_stat.decode("ascii").rpartition(") ")[2].split()[0]
            if state in {"Z", "X"}:
                continue
            raw = _bounded_read(item / "cmdline", MAX_CMDLINE)
        except OSError as error:
            if error.errno in {errno.ENOENT, errno.ESRCH}:
                continue
            raise Refusal(f"Cannot authenticate process {item.name}: {error}") from error
        require(not raw or raw.endswith(b"\0"), f"Malformed process cmdline: {item.name}")
        try:
            argv = [part.decode() for part in raw.split(b"\0") if part]
        except UnicodeDecodeError as error:
            raise Refusal(f"Non-UTF-8 process cmdline: {item.name}") from error
        if not argv:
            continue
        kind = process_kind(argv)
        if kind:
            result.append({"pid": int(item.name), "lane": kind, "argv": argv})
    return sorted(result, key=lambda row: row["pid"])


def _mounts_by_destination(rows, label):
    require(isinstance(rows, list), f"{label} mounts are not a list")
    result = {}
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get("Destination"), str) and
                row["Destination"] and row["Destination"] not in result,
                f"{label} contains malformed or duplicate mounts")
        result[row["Destination"]] = row
    require(len(result) == len(rows), f"{label} mount cardinality differs")
    return result


def _debug_top_rows(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_DEBUG_TOP,
            "Preserved-debug process listing is empty or oversized")
    try:
        lines = raw.decode().splitlines()
    except UnicodeDecodeError as error:
        raise Refusal("Preserved-debug process listing is not UTF-8") from error
    require(lines and lines[0].split() == ["PID", "PPID", "COMMAND", "COMMAND"],
            "Preserved-debug process header differs")
    rows = [line.split(None, 3) for line in lines[1:] if line.strip()]
    require(all(len(row) == 4 and row[0].isdecimal() and row[1].isdecimal() for row in rows),
            "Malformed preserved-debug process row")
    return sorted(rows)


def validate_debug_exception(info, config, environment):
    payload, reference = capture_regular(config.debug_proof, 64 * 1024)
    require(reference["sha256"] == config.debug_proof_sha256,
            "Preserved-debug proof identity differs")
    proof = unique_json(payload, "preserved-debug proof")
    require(proof.get("schema") == 1 and
            proof.get("scope") == "read-only-preserved-debug-sleep-adb-not-guest" and
            proof.get("no_container_mutation") is True and
            proof.get("independent_current_top_required_before_any_guest") is True,
            "Preserved-debug proof scope differs")
    wrapped = unique_json(b'{"rows":' + proof["inspect_result"]["output"].encode() + b"}",
                          "preserved-debug inspect wrapper")
    rows = wrapped["rows"]
    require(isinstance(rows, list) and len(rows) == 1 and rows[0].get("Id") == config.debug_id,
            "Preserved-debug identity differs")
    expected = rows[0]
    for key in ("Id", "Image", "Name", "Path", "Args", "Config", "HostConfig", "State"):
        require(info.get(key) == expected.get(key), f"Preserved-debug profile changed: {key}")
    require(_mounts_by_destination(info.get("Mounts"), "current preserved-debug") ==
            _mounts_by_destination(expected.get("Mounts"), "reviewed preserved-debug"),
            "Preserved-debug profile changed: Mounts")
    command = ["docker", "top", config.debug_id, "-eo", "pid,ppid,comm,args"]
    require(proof.get("top_command") == command, "Preserved-debug top command differs")
    current = docker_checked(["top", config.debug_id, "-eo", "pid,ppid,comm,args"], environment)
    require(current == proof["top_result"]["output"].encode() and
            _debug_top_rows(current) == _debug_top_rows(proof["top_result"]["output"].encode()),
            "Preserved-debug process epoch differs")
    require(all(row[2] in {"sleep", "adb"} and
                (row[3] == "sleep infinity" or row[3].startswith("adb -L tcp:5037 "))
                for row in _debug_top_rows(current)),
            "Preserved-debug container is not exact sleep plus ADB")


def container_kind(info):
    require(isinstance(info, dict), "Malformed running-container inspection")
    if info.get("State", {}).get("Running") is not True:
        return None
    config, host, mounts = info.get("Config"), info.get("HostConfig"), info.get("Mounts")
    require(isinstance(config, dict) and isinstance(host, dict) and isinstance(mounts, list),
            "Malformed running-container profile")
    devices = host.get("Devices") or []
    require(isinstance(devices, list), "Malformed running-container devices")
    if any(isinstance(row, dict) and
           "/dev/kvm" in {row.get("PathOnHost"), row.get("PathInContainer")}
           for row in devices):
        return "running KVM guest container"
    if any(isinstance(row, dict) and "/dev/kvm" in {row.get("Source"), row.get("Destination")}
           for row in mounts):
        return "running KVM guest container"
    name = info.get("Name")
    require(isinstance(name, str) and name.startswith("/"), "Malformed container name")
    labels = config.get("Labels") or {}
    require(isinstance(labels, dict), "Malformed container labels")
    command = []
    for value in (config.get("Entrypoint"), config.get("Cmd")):
        if isinstance(value, list):
            command.extend(item for item in value if isinstance(item, str))
        elif isinstance(value, str):
            command.append(value)
    if command and process_kind(command) in {"Android emulator", "KVM guest", "QEMU guest"}:
        return "running VM container"
    prefixes = ("/wonad-upstream-", "/wonad-phase1-x86-", "/wonad-phase1-frankel-",
                "/wonad-phase1-conformance-", "/wonad-phase1-native-", "/wonad-native-",
                "/wonad-laptop", "/wonad-phase1-client-", "/wonad-phase1-successor-")
    if name.startswith(prefixes) or any(key in labels for key in (
            "org.wonad.phase1-fresh-conformance", "org.wonad.phase1-upstream-guest",
            "org.wonad.phase1.native-matrix", "org.wonad.phase1.vendor-attempt")):
        return "running Wonad build/test/VM container"
    return None


def running_container_lanes(config, environment):
    def inventory():
        raw = docker_checked(["container", "ls", "--filter", "status=running", "--quiet",
                              "--no-trunc"], environment)
        try:
            identities = [line.decode("ascii") for line in raw.splitlines() if line]
        except UnicodeDecodeError as error:
            raise Refusal("Non-ASCII running-container identity") from error
        rows = []
        for identity in identities:
            require(re.fullmatch(r"[0-9a-f]{64}", identity),
                    "Malformed running-container identity")
            info, _ = docker_inspect(identity, environment)
            require(info.get("Id") == identity, "Running-container inspect identity differs")
            kind = container_kind(info)
            if kind is not None:
                rows.append((identity, info, kind))
        return rows

    first = inventory()
    debug = [row for row in first if row[0] == config.debug_id]
    if debug:
        require(len(debug) == 1 and debug[0][2] == "running KVM guest container",
                "Preserved-debug lane classification differs")
        validate_debug_exception(debug[0][1], config, environment)
        second = inventory()
        second_debug = [row for row in second if row[0] == config.debug_id]
        require(len(second_debug) == 1 and
                second_debug[0][2] == "running KVM guest container",
                "Preserved-debug lane disappeared or changed")
        validate_debug_exception(second_debug[0][1], config, environment)
        first = second
    return [{"container": identity, "name": info.get("Name"), "lane": kind}
            for identity, info, kind in first if identity != config.debug_id]


def resources(config, environment):
    lines = Path("/proc/meminfo").read_text(encoding="ascii").splitlines()
    memory = {}
    for name in ("MemTotal", "MemAvailable"):
        rows = [line for line in lines if line.startswith(name + ":")]
        require(len(rows) == 1, f"Host memory lacks unique {name} observation")
        match = re.fullmatch(name + r":\s+([0-9]+)\s+kB", rows[0], re.ASCII)
        require(match is not None, f"Invalid {name} decimal/unit observation")
        value = int(match.group(1)) * 1024
        require(value > 0, f"Invalid non-positive {name} observation")
        memory[name] = value
    total, available = memory["MemTotal"], memory["MemAvailable"]
    require(available <= total, "Host MemAvailable exceeds physical MemTotal")
    require(total >= MEMORY,
            f"Vendor preparation needs >=48 GiB physical MemTotal; observed {total}")
    require(available >= MIN_MEM_AVAILABLE,
            f"Vendor preparation needs >=42 GiB MemAvailable; observed {available}")
    source_fs = os.statvfs(config.source)
    free = source_fs.f_bavail * source_fs.f_frsize
    require(free >= MIN_SOURCE_FREE,
            f"Vendor preparation needs >=64 GiB source/work free; observed {free}")
    require(source_fs.f_fsid == os.statvfs(config.work.parent).f_fsid,
            "Source and FICLONE workspace are not on one filesystem")
    require(cpu_set(Path("/sys/devices/system/cpu/online").read_text()) >= {0, 1, 2, 3} and
            set(os.sched_getaffinity(0)) >= {0, 1, 2, 3}, "CPUs 0-3 are not online/allowed")
    lanes = live_process_lanes()
    lanes.extend(running_container_lanes(config, environment))
    require(not lanes, "Relevant build/test/VM lanes are live: " + json.dumps(lanes))
    return {"mem_total_bytes": total, "mem_available_bytes": available,
            "source_and_work_free_bytes": free,
            "cpus_online_and_allowed": [0, 1, 2, 3], "observed_live_lanes": lanes,
            "limits_are_conservative_unmeasured": True}


def validate_cache(config):
    payload, receipt_ref = capture_regular(config.cache_receipt, 64 * 1024)
    require(receipt_ref["sha256"] == config.cache_receipt_sha256,
            "Factory-cache receipt identity differs")
    receipt = unique_json(payload, "factory-cache receipt")
    require(set(receipt) == {"schema", "kind", "scope", "runtime_qualified", "result",
                             "source_authority", "archive", "transfer", "verification",
                             "disk", "inventory", "negative_claims", "next_step"},
            "Factory-cache receipt schema differs")
    require(receipt.get("schema") == 1 and
            receipt.get("kind") == "phase1_frankel_public_factory_archive_download_receipt_v1" and
            receipt.get("scope") == "authenticated public prerequisite archive cache only" and
            receipt.get("result") == "downloaded_and_sha256_authenticated" and
            receipt.get("runtime_qualified") is False, "Factory-cache receipt role differs")
    authority = receipt.get("source_authority")
    require(isinstance(authority, dict) and set(authority) == {
                "preflight", "baseline_root", "adevtool_commit", "build_index_sha256",
                "configured_build_id", "url_derivation"} and
            authority.get("baseline_root") == str(config.source) and
            authority.get("adevtool_commit") == config.adevtool_commit and
            authority.get("build_index_sha256") ==
                config.source_inputs["vendor/adevtool/config/build-index/build-index-main.yml"] and
            authority.get("configured_build_id") == config.factory_build_id and
            authority.get("url_derivation") ==
                "pristine adevtool DEFAULT_BASE_DOWNLOAD_URL plus the filename in the exact indexed Frankel factory row",
            "Factory-cache source authority differs")
    archive_row = receipt.get("archive")
    require(isinstance(archive_row, dict) and archive_row.get("filename") == config.archive_name and
            archive_row.get("path") == str(config.cache / config.archive_name) and
            archive_row.get("sha256") == config.archive_sha256 and
            archive_row.get("bytes") == config.archive_bytes and
            archive_row.get("symlink") is False and archive_row.get("fsynced_before_receipt") is True,
            "Factory-cache archive authority differs")
    require(archive_row.get("url") == "https://dl.google.com/dl/android/aosp/" +
            config.archive_name and archive_row.get("partial_path_absent_after_promotion") is True,
            "Factory-cache archive URL/promotion evidence differs")
    require(isinstance(archive_row.get("mode"), str) and
            re.fullmatch(r"0[0-7]{3}", archive_row["mode"]),
            "Factory-cache archive mode is malformed")
    cache = directory(config.cache, uid=os.getuid(), gid=os.getgid())
    inventory = receipt.get("inventory")
    require(isinstance(inventory, list) and inventory and
            all(isinstance(item, str) and Path(item).name == item for item in inventory) and
            sorted(item.name for item in config.cache.iterdir()) == sorted(inventory),
            "Factory-cache on-disk inventory differs")
    transfer = receipt.get("transfer")
    require(isinstance(transfer, dict) and transfer.get("exit_code") == 0 and
            transfer.get("http_code") == 200 and transfer.get("effective_url") ==
            archive_row.get("url") and transfer.get("size_download") == config.archive_bytes,
            "Factory-cache transfer result differs")
    verification = receipt.get("verification")
    require(isinstance(verification, dict) and
            verification.get("partial_size_check_passed") is True and
            verification.get("partial_sha256_check_passed") is True and
            verification.get("final_sha256_recheck_passed") is True and
            verification.get("post_transfer_strict_header_parse_passed") is True,
            "Factory-cache verification result differs")
    disk = receipt.get("disk")
    require(isinstance(disk, dict) and disk.get("reserve_preserved") is True and
            isinstance(disk.get("post_transfer_free_bytes"), int) and
            isinstance(disk.get("fixed_reserve_bytes"), int) and
            disk["post_transfer_free_bytes"] >= disk["fixed_reserve_bytes"] > 0,
            "Factory-cache disk-reserve evidence differs")
    negative = receipt.get("negative_claims")
    require(isinstance(negative, dict) and set(negative) == {
                "archive_extracted", "archive_copied_into_source_tree",
                "vendor_preparation_run", "source_staged_or_modified", "container_started",
                "compiler_or_build_started", "release_keys_generated_or_used",
                "image_signed_or_published", "ota_published", "guest_started",
                "phone_or_hardware_qualified"} and
            all(value is False for value in negative.values()),
            "Factory-cache negative claims differ")
    archive = config.cache / config.archive_name
    value = archive.lstat()
    require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and not archive.is_symlink() and
            archive.resolve(strict=True) == archive and value.st_size == config.archive_bytes and
            value.st_dev == archive_row.get("device") and value.st_ino == archive_row.get("inode") and
            value.st_uid == archive_row.get("uid") and value.st_gid == archive_row.get("gid") and
            stat.S_IMODE(value.st_mode) == int(str(archive_row.get("mode")), 8),
            "Factory-cache archive stat identity differs")
    return {"directory": cache, "receipt": receipt_ref,
            "archive": {"path": str(archive), "device": value.st_dev, "inode": value.st_ino,
                        "bytes": value.st_size, "mode": stat.S_IMODE(value.st_mode),
                        "uid": value.st_uid, "gid": value.st_gid, "nlink": value.st_nlink},
            "archive_sha256_from_authenticated_receipt": config.archive_sha256,
            "archive_bytes_not_rehashed_by_host_admission": True}


def reviewed_adevtool_targets(paths_payload):
    text = paths_payload.decode()
    match = re.search(r"let knownPrograms = \[(.*?)\n\s*\]", text, re.DOTALL)
    require(match is not None, "Cannot find adevtool knownPrograms")
    values = tuple(re.findall(r"'([^']+)'", match.group(1)))
    require(values == EXPECTED_ADEVTOOL_TARGETS and len(values) == 14,
            "Adevtool dependency target inventory differs")
    require("args: ['sdk_phone64_x86_64', outDir, ...knownPrograms]" in text,
            "Adevtool build product/OUT/target grammar differs")
    return values


def source_caches_absent(source, *, require_output_absent):
    forbidden = ("out_adevtool_deps", "vendor/adevtool/node_modules", "vendor/adevtool/lib",
                 "vendor/adevtool/dist", "vendor/adevtool/.cache", "vendor/adevtool/cache",
                 "vendor/adevtool/.yarn")
    for relative in forbidden:
        require(not os.path.lexists(source / relative), f"Vendor cache remains: {relative}")
    dl = source / "vendor/adevtool/dl"
    require(sorted(item.name for item in dl.iterdir()) == [".find-ignore"],
            "Only the tracked adevtool download marker may remain")
    if require_output_absent:
        require(not os.path.lexists(source / "vendor/google_devices/frankel"),
                "Frankel vendor output must be absent before generation")
    return {"regenerable_cache_absent": True, "generated_vendor_required_absent": require_output_absent}


def source_topology(config, *, output_may_exist):
    identities = source_directory_identities(config)
    out = config.source / "out"
    require(not any(out.iterdir()), "Dedicated source out/ must remain empty")
    for relative in ("external/wonad", ".wonad-updater-stage.json", "keys", "private-keys",
                     "private_keys", "secrets"):
        require(not os.path.lexists(config.source / relative),
                f"Unexpected staged/private source content: {relative}")
    generated = config.source / "vendor/google_devices/frankel"
    if output_may_exist and os.path.lexists(generated):
        directory(generated, uid=os.getuid(), gid=os.getgid())
    else:
        require(not os.path.lexists(generated),
                "Frankel vendor output must be absent before generation")
    return {"directory_identities": identities, "out_empty": True,
            "staging_and_private_roots_absent": True,
            "generated_vendor_may_exist": output_may_exist}


def dependency_handoff_api():
    """Replay the verifier embedded in the already authenticated builder input."""
    payload_bytes, _ = capture_regular(GENERATOR, MAX_INPUT)
    text = payload_bytes.decode()
    start = '/usr/bin/python3 - "$expected_adevtool_commit" <<\'WONAD_DEPENDENCY_HANDOFF_PY\'\n'
    end = '\nWONAD_DEPENDENCY_HANDOFF_PY\n'
    require(text.count(start) == 1 and text.count(end) == 1,
            "Dependency handoff verifier boundary differs")
    code = text.split(start, 1)[1].split(end, 1)[0]
    module = types.ModuleType("reviewed_adevtool_dependency_handoff")
    exec(compile(code, str(GENERATOR) + "::dependency-handoff", "exec"), module.__dict__)
    require(module.TARGETS == EXPECTED_ADEVTOOL_TARGETS,
            "Dependency handoff target inventory differs")
    return module


def verify_dependency_evidence(config):
    """Authenticate retained raw build streams and all fourteen program bytes.

    The producer's source dependency OUT is deliberately removed after exact
    container-stop proof. These small retained copies make its successful
    dependency handoff independently replayable without retaining that graph.
    """
    api = dependency_handoff_api()
    root = config.work / "wonad-dependency-build"
    directory(root, uid=os.getuid(), gid=os.getgid())
    directory(root / "programs", uid=os.getuid(), gid=os.getgid())
    payload_bytes, receipt_ref = capture_regular(root / "receipt.json")
    receipt = unique_json(payload_bytes, "adevtool dependency handoff")
    require(set(receipt) == {
        "schema", "kind", "status", "adevtool_commit", "command", "targets",
        "upstream_script_sha256", "upstream_paths_sha256", "skip_flag_scope",
        "compiler_exit_code", "programs", "stdout", "stderr", "classification"},
        "Dependency handoff receipt fields differ")
    require(type(receipt["schema"]) is int and receipt["schema"] == 1 and
            receipt["kind"] == "phase1_adevtool_dependency_handoff_v1" and
            receipt["status"] == "built_and_verified" and
            receipt["adevtool_commit"] == config.adevtool_commit and
            receipt["command"] == api.COMMAND and
            receipt["targets"] == list(EXPECTED_ADEVTOOL_TARGETS) and
            receipt["upstream_script_sha256"] == api.SCRIPT_SHA and
            receipt["upstream_paths_sha256"] == api.PATHS_SHA and
            receipt["skip_flag_scope"] == "redundant second build only after fresh full build",
            "Dependency handoff authority differs")
    streams, stream_refs = {}, {}
    for name, limit in (("stdout", api.STDOUT_LIMIT), ("stderr", api.STDERR_LIMIT)):
        contents, ref = capture_regular(root / (name + ".raw"), limit)
        expected = {**ref, "path": "/adevtool-images/wonad-dependency-build/" + name + ".raw"}
        require(receipt[name] == expected, "Dependency raw " + name + " binding differs")
        streams[name], stream_refs[name] = contents, ref
    try:
        classification = api.classify_transcripts(
            receipt["compiler_exit_code"], streams["stdout"], streams["stderr"])
    except (RuntimeError, UnicodeError) as error:
        raise Refusal("Dependency transcript verification failed: " + str(error)) from error
    require(receipt["classification"] == classification,
            "Dependency transcript classification differs")
    require(isinstance(receipt["programs"], dict) and
            set(receipt["programs"]) == set(EXPECTED_ADEVTOOL_TARGETS),
            "Dependency program inventory differs")
    programs = {}
    for name in EXPECTED_ADEVTOOL_TARGETS:
        _, ref = capture_regular(root / "programs" / name, 128 * 1024 * 1024)
        require(ref["bytes"] > 0, "Retained dependency program is empty")
        expected = {
            "installed_path": "/grapheneos/out_adevtool_deps/host/linux-x86/bin/" + name,
            "retained": {**ref, "path": "/adevtool-images/wonad-dependency-build/programs/" + name}}
        require(receipt["programs"][name] == expected,
                "Retained dependency program binding differs: " + name)
        programs[name] = ref
    require({item.name for item in root.iterdir()} ==
            {"receipt.json", "stdout.raw", "stderr.raw", "programs"} and
            {item.name for item in (root / "programs").iterdir()} == set(EXPECTED_ADEVTOOL_TARGETS),
            "Unexpected retained dependency content")
    return {"receipt": receipt_ref, "streams": stream_refs,
            "classification": classification, "programs": programs,
            "fresh_full_dependency_build_verified": True}


def verify_generated_vendor(config):
    dependencies = verify_dependency_evidence(config)
    root = config.source / "vendor/google_devices/frankel"
    directory(root, uid=os.getuid(), gid=os.getgid())
    for relative in ("Android.mk", "AndroidProducts.mk", "BoardConfig.mk", "README.md",
                     "frankel.mk", "adevtool-version-check.mk"):
        path = root / relative
        value = path.lstat()
        require(stat.S_ISREG(value.st_mode) and not path.is_symlink(),
                f"Generated Frankel output differs: {relative}")
    for relative in ("proprietary", "firmware"):
        directory(root / relative, uid=os.getuid(), gid=os.getgid())
    expected = (f"ifneq ($(shell git -C vendor/adevtool rev-parse HEAD),{config.adevtool_commit})\n"
                "  $(error frankel vendor module is outdated. Run `adevtool generate-all -d frankel` to update it)\n"
                "endif")
    require((root / "adevtool-version-check.mk").read_text() == expected,
            "Generated adevtool version guard differs")
    return {"path": str(root), "required_files": ["Android.mk", "AndroidProducts.mk",
            "BoardConfig.mk", "README.md", "frankel.mk", "adevtool-version-check.mk"],
            "required_directories": ["proprietary", "firmware"],
            "adevtool_version_commit": config.adevtool_commit,
            "dependency_build": dependencies}


def source_authority(config, modules, lock_payload, *, output_may_exist,
                     regenerable_caches_may_exist=False):
    provenance, checkout, sources, health, locality = modules
    ledger = provenance.host_tool_ledger()
    topology = source_topology(config, output_may_exist=output_may_exist)
    problems = health.check(config.source)
    require(not problems, "Checkout health differs: " + "\n".join(problems[:8]))
    lock = unique_json(lock_payload, "GrapheneOS lock")
    sources.verify(config.source / ".repo/manifests", config.source / "frameworks/base",
                   config.repo / "android/platform/allowed_signers", lock)
    tracked = checkout.verify(config.source, jobs=32)
    critical = {"packages/apps/Launcher3": lock["launcher3"]["commit"],
                "packages/apps/Updater": lock["updater"]["commit"],
                "device/generic/goldfish": lock["emulator_goldfish"]["commit"]}
    for relative, expected in critical.items():
        actual = provenance.git_bytes(config.source / relative, "rev-parse", "HEAD").decode().strip()
        require(actual == expected, f"Pinned project revision differs: {relative}")
    actual_adevtool = provenance.git_bytes(
        config.source / "vendor/adevtool", "rev-parse", "HEAD").decode().strip()
    require(actual_adevtool == config.adevtool_commit, "Pinned adevtool revision differs")
    source_refs, payloads = captured_inventory(config.source, config.source_inputs, "source")
    reviewed_adevtool_targets(payloads["vendor/adevtool/src/config/paths.ts"])
    if regenerable_caches_may_exist:
        require(not os.path.lexists(config.source / "vendor/google_devices/frankel")
                if not output_may_exist else True,
                "Frankel vendor output must be absent before generation")
    else:
        source_caches_absent(config.source, require_output_absent=not output_may_exist)
    return {"host_tools": ledger, "checkout": tracked, "source_inputs": source_refs,
            "topology": topology,
            "adevtool_commit": actual_adevtool,
            "generated_vendor_may_exist": output_may_exist,
            "regenerable_caches_may_exist": regenerable_caches_may_exist}


def load_authority_modules(config, repo_payloads):
    def load(relative, name):
        return load_captured_module(repo_payloads[relative], config.repo / relative, name)
    return (load("android/tools/phase1_provenance.py", "phase1_vendor_provenance"),
            load("android/tools/verify_checkout.py", "phase1_vendor_checkout"),
            load("android/tools/verify_sources.py", "phase1_vendor_sources"),
            load("android/tools/checkout_health.py", "phase1_vendor_health"),
            load("android/tools/docker_locality_proof.py", "phase1_vendor_locality"))


def prepare_reflink(config, *, ioctl_fn=None):
    validate_cache(config)
    fresh(config.work)
    archive = config.cache / config.archive_name
    before_path = archive.lstat()
    os.mkdir(config.work, 0o700)
    parent_fd = os.open(config.work.parent, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY |
                        os.O_NOFOLLOW)
    work_fd = source_fd = destination_fd = None
    try:
        os.fsync(parent_fd)
        work_fd = os.open(config.work, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY |
                          os.O_NOFOLLOW)
        source_fd = os.open(archive, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        source_before = os.fstat(source_fd)
        destination = config.work / config.archive_name
        destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        (ioctl_fn or fcntl.ioctl)(destination_fd, FICLONE, source_fd)
        os.fchmod(destination_fd, 0o444)
        os.fsync(destination_fd)
        destination_stat = os.fstat(destination_fd)
        require(_same_stat(source_before, os.fstat(source_fd)),
                "Factory archive changed during FICLONE")
        require(stat.S_ISREG(destination_stat.st_mode) and destination_stat.st_nlink == 1 and
                destination_stat.st_dev == source_before.st_dev and
                destination_stat.st_ino != source_before.st_ino and
                destination_stat.st_size == source_before.st_size and
                stat.S_IMODE(destination_stat.st_mode) == 0o444,
                "FICLONE destination identity differs")
        os.fsync(work_fd)
    finally:
        for descriptor in (destination_fd, source_fd, work_fd, parent_fd):
            if descriptor is not None:
                os.close(descriptor)
    require(_same_stat(before_path, archive.lstat()), "Factory archive changed during FICLONE")
    return {"directory": directory(config.work),
            "archive": {"path": str(config.work / config.archive_name),
                        "bytes": config.archive_bytes,
                        "sha256_from_authenticated_receipt": config.archive_sha256,
                        "adevtool_consumption_and_recheck_pending": True},
            "creation": "FICLONE only; no copy/download fallback"}


def builder_environment(config):
    return [
        "PATH=/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/tmp/wonad-vendor-home", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TMPDIR=/tmp",
        "YARN_CACHE_FOLDER=/tmp/wonad-vendor-yarn-cache",
        "ADEVTOOL_IMG_DOWNLOAD_DIR=/adevtool-images",
        "WONAD_GRAPHENEOS_RELEASE_SOURCE=/grapheneos", "WONAD_VENDOR_DEVICE=frankel",
        "WONAD_YARN_BIN=/usr/bin/yarnpkg", f"WONAD_ADEVTOOL_COMMIT={config.adevtool_commit}",
        "NINJA_HIGHMEM_NUM_JOBS=1", "PYTHONDONTWRITEBYTECODE=1",
        "GIT_OPTIONAL_LOCKS=0", "GIT_NO_LAZY_FETCH=1",
    ]


def payload(config):
    return ["-i", *builder_environment(config), "/bin/bash", "--noprofile", "--norc", "-e",
            "/wonad/android/platform/generate-frankel-vendor.sh"]


def create_command(config, nonce):
    require(re.fullmatch(r"[0-9a-f]{64}", nonce), "Attempt nonce is malformed")
    return [*DOCKER, "create", "--name", config.container, "--platform", "linux/amd64",
            "--network", "bridge", "--attach", "stdout", "--attach", "stderr",
            "--user", "1000:1000", "--cap-drop", "ALL", "--security-opt", "label=disable",
            "--security-opt", "no-new-privileges=true", "--read-only", "--memory", str(MEMORY),
            "--memory-swap", str(MEMORY), "--cpus", "4", "--cpuset-cpus", "0-3",
            "--pids-limit", "2048", "--restart", "no", "--tmpfs", "/tmp:" + TMPFS,
            "--workdir", "/grapheneos", "--entrypoint", "/usr/bin/env",
            "--label", "org.wonad.phase1.vendor-attempt=" + nonce,
            "--label", "org.wonad.phase1.vendor-mode=prepare",
            "--volume", f"{config.source}:/grapheneos:rw",
            "--volume", f"{config.repo}:/wonad:ro",
            "--volume", f"{config.work}:/adevtool-images:rw",
            config.builder_image, *payload(config)]


def _expected_mounts(config):
    return {
        "/grapheneos": {"Type": "bind", "Source": str(config.source),
                        "Destination": "/grapheneos", "Mode": "rw", "RW": True,
                        "Propagation": "rprivate"},
        "/wonad": {"Type": "bind", "Source": str(config.repo),
                   "Destination": "/wonad", "Mode": "ro", "RW": False,
                   "Propagation": "rprivate"},
        "/adevtool-images": {"Type": "bind", "Source": str(config.work),
                             "Destination": "/adevtool-images", "Mode": "rw", "RW": True,
                             "Propagation": "rprivate"},
    }


def validate_container(info, config, identity, nonce, *, stopped):
    require(re.fullmatch(r"[0-9a-f]{64}", identity) and info.get("Id") == identity and
            info.get("Name") == "/" + config.container and info.get("Image") == config.builder_image,
            "Owned container identity differs")
    cfg, host, state = info.get("Config"), info.get("HostConfig"), info.get("State")
    require(isinstance(cfg, dict) and isinstance(host, dict) and isinstance(state, dict),
            "Owned container profile is malformed")
    require(cfg.get("Image") == config.builder_image and cfg.get("User") == "1000:1000" and
            cfg.get("WorkingDir") == "/grapheneos" and cfg.get("Entrypoint") == ["/usr/bin/env"] and
            cfg.get("Cmd") == payload(config) and cfg.get("Labels") == {
                "org.wonad.phase1.vendor-attempt": nonce,
                "org.wonad.phase1.vendor-mode": "prepare"},
            "Owned container config differs")
    require(info.get("Path") == "/usr/bin/env" and info.get("Args") == payload(config),
            "Owned container executable/argument projection differs")
    require(cfg.get("AttachStdin") is False and cfg.get("AttachStdout") is True and
            cfg.get("AttachStderr") is True and cfg.get("OpenStdin") is False and
            cfg.get("StdinOnce") is False and cfg.get("Tty") is False,
            "Owned container stdio/TTY profile differs")
    expected_host = {"Memory": MEMORY, "MemorySwap": MEMORY, "NanoCpus": 4_000_000_000,
                     "CpusetCpus": "0-3", "PidsLimit": 2048, "ReadonlyRootfs": True,
                     "NetworkMode": "bridge", "Privileged": False, "AutoRemove": False,
                     "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                     "Tmpfs": {"/tmp": TMPFS}, "CapDrop": ["ALL"],
                     "SecurityOpt": ["label=disable", "no-new-privileges=true"],
                     "Binds": [f"{config.source}:/grapheneos:rw",
                               f"{config.repo}:/wonad:ro",
                               f"{config.work}:/adevtool-images:rw"]}
    for key, value in expected_host.items():
        if key == "Binds":
            require(isinstance(host.get(key), list) and len(host[key]) == 3 and
                    sorted(host[key]) == sorted(value), "Owned container bind grammar differs")
        else:
            require(host.get(key) == value, f"Owned container HostConfig differs: {key}")
    for key in ("CapAdd", "Devices", "DeviceRequests", "DeviceCgroupRules", "GroupAdd",
                "PortBindings", "VolumesFrom", "Links", "ExtraHosts"):
        require(host.get(key) in (None, [], {}), f"Unexpected container authority: {key}")
    require(host.get("PidMode") == "" and host.get("IpcMode") == "private" and
            host.get("UTSMode") == "" and host.get("UsernsMode") == "" and
            not cfg.get("ExposedPorts") and not cfg.get("Volumes"),
            "Unexpected container namespace/port/volume")
    require(_mounts_by_destination(info.get("Mounts"), "owned container") == _expected_mounts(config),
            "Owned container mount profile differs")
    if stopped:
        require(state.get("Status") == "exited" and state.get("Running") is False and
                state.get("Paused") is False and state.get("Restarting") is False and
                state.get("Dead") is False and type(state.get("Pid")) is int and
                state.get("Pid") == 0 and type(state.get("OOMKilled")) is bool and
                type(state.get("ExitCode")) is int and
                isinstance(state.get("StartedAt"), str) and
                state["StartedAt"] not in ("", "0001-01-01T00:00:00Z") and
                isinstance(state.get("FinishedAt"), str) and
                state["FinishedAt"] not in ("", "0001-01-01T00:00:00Z"),
                "Owned container is not authoritatively stopped")
    else:
        require(state.get("Status") == "created" and state.get("Running") is False and
                state.get("Paused") is False and state.get("Restarting") is False and
                state.get("Dead") is False and state.get("OOMKilled") is False and
                state.get("Pid") == 0 and state.get("ExitCode") == 0 and
                state.get("StartedAt") == "0001-01-01T00:00:00Z" and
                state.get("FinishedAt") == "0001-01-01T00:00:00Z",
                "Owned container was started before created-state validation")
    return True


def acquire_lock(path, config):
    payload_bytes = canonical({"schema": 1, "kind": "phase1_frankel_vendor_attempt_lock_v1",
                               "pid": os.getpid(), "source": str(config.source),
                               "container": config.container, "created_unix": int(time.time())})
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC |
                         os.O_NOFOLLOW, 0o600)
    count = os.write(descriptor, payload_bytes)
    require(count == len(payload_bytes), "Short attempt-lock write")
    os.fsync(descriptor)
    return descriptor


def acquire_source_lock(source):
    descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def error_record(error):
    if error is None:
        return None
    return {"class": type(error).__name__, "message": str(error)}


def outcome_status(primary_exit, primary_error, cleanup_error):
    if primary_error is not None:
        return "failed_exception"
    if primary_exit not in (None, 0):
        return "failed_builder"
    if cleanup_error is not None:
        return "failed_cleanup"
    return "generated"


def require_successful_stopped_build(primary_exit, stopped, stopped_inspect):
    """Build success is separate from exact terminal-state authority to clean caches."""
    require(stopped is True and isinstance(stopped_inspect, dict) and
            type(primary_exit) is int and primary_exit == 0 and
            type(stopped_inspect.get("exit_code")) is int and
            stopped_inspect["exit_code"] == 0 and
            stopped_inspect.get("oom_killed") is False,
            "Vendor generation requires proven stopped zero exit without OOM")


def source_cleanup_is_safe(create_attempted, container_identity, authoritatively_stopped):
    """Cleanup is safe before create, or after exact-ID stopped validation only."""
    if not create_attempted:
        return True
    return (isinstance(container_identity, str) and
            re.fullmatch(r"[0-9a-f]{64}", container_identity) is not None and
            authoritatively_stopped is True)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check-only", action="store_true")
    action.add_argument("--run", action="store_true")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--builder-image", required=True)
    parser.add_argument("--adevtool-commit", required=True)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--cache-receipt", required=True, type=Path)
    parser.add_argument("--cache-receipt-sha256", required=True)
    parser.add_argument("--archive-name", required=True)
    parser.add_argument("--factory-build-id", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--archive-bytes", required=True, type=int)
    parser.add_argument("--source-input", action="append", default=[])
    parser.add_argument("--repo-input", action="append", default=[])
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--attempt-lock", required=True, type=Path)
    parser.add_argument("--container", required=True)
    parser.add_argument("--debug-id")
    parser.add_argument("--debug-proof", type=Path)
    parser.add_argument("--debug-proof-sha256")
    return parser


def config_from_args(args):
    for key in ("cache_receipt_sha256", "archive_sha256"):
        require(re.fullmatch(r"[0-9a-f]{64}", getattr(args, key)), f"Malformed {key}")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", args.builder_image),
            "Builder image must be an immutable sha256 ID")
    require(re.fullmatch(r"[0-9a-f]{40}", args.adevtool_commit), "Malformed adevtool commit")
    require(args.archive_bytes > 0 and Path(args.archive_name).name == args.archive_name,
            "Malformed archive identity")
    require(re.fullmatch(r"[A-Z0-9.]+", args.factory_build_id),
            "Malformed factory build ID")
    require(re.fullmatch(r"wonad-phase1-frankel-vendor-[a-z0-9-]+", args.container),
            "Malformed container name")
    source = args.source.resolve(strict=True)
    repo = args.repo.resolve(strict=True)
    cache = args.cache.resolve(strict=True)
    cache_receipt = args.cache_receipt.resolve(strict=True)
    require(source != repo and repo == ROOT and not source.is_symlink() and
            (source / ".repo").is_dir(), "Source/repository roots differ from the reviewed topology")
    require(cache.is_dir() and not cache.is_symlink() and cache_receipt.parent == cache,
            "Factory-cache receipt must be an ordinary member of the canonical cache")
    pairs = (args.debug_id, args.debug_proof, args.debug_proof_sha256)
    require(all(value is None for value in pairs) or
            (re.fullmatch(r"[0-9a-f]{64}", args.debug_id or "") and args.debug_proof and
             re.fullmatch(r"[0-9a-f]{64}", args.debug_proof_sha256 or "")),
            "Preserved-debug identity/proof arguments must be supplied together")
    args.source = source
    args.repo = repo
    args.cache = cache
    args.cache_receipt = cache_receipt
    args.source_inputs = parse_pin_rows(args.source_input, REQUIRED_SOURCE_INPUTS, "source")
    args.repo_inputs = parse_pin_rows(args.repo_input, REQUIRED_REPO_INPUTS, "repository")
    outputs = (args.work, args.log, args.preflight, args.result, args.attempt_lock)
    require(len({str(path) for path in outputs}) == len(outputs), "Output paths must be distinct")
    for path in (args.work, args.log, args.preflight, args.result, args.attempt_lock):
        require(path.is_absolute(), f"Output must be absolute: {path}")
        parent = path.parent.resolve(strict=True)
        require(parent != source and source not in parent.parents and
                parent != repo and repo not in parent.parents and
                parent != args.cache and args.cache not in parent.parents,
                f"Output must remain outside source/repository/cache: {path}")
    return args


def initial_inputs(config):
    repo_refs, repo_payloads = captured_inventory(config.repo, config.repo_inputs, "repository")
    require(repo_refs["android/tools/run_frankel_vendor.py"]["path"] == str(Path(__file__).resolve()),
            "Executing runner path differs from its authenticated input")
    cache = validate_cache(config)
    return repo_refs, repo_payloads, cache


def docker_authority(config, locality, environment):
    cli, socket, context, daemon = locality.trusted_local_docker(environment)
    raw = docker_checked(["image", "inspect", config.builder_image], environment)
    rows = unique_json(b'{"rows":' + raw + b"}", "builder inspect wrapper")["rows"]
    require(isinstance(rows, list) and len(rows) == 1 and
            rows[0].get("Id") == config.builder_image and rows[0].get("Os") == "linux" and
            rows[0].get("Architecture") == "amd64", "Builder image identity/platform differs")
    return {"cli": cli, "socket": socket, "context": context, "daemon": daemon,
            "builder_image": config.builder_image}


def run_builder(config, environment, argv, identity):
    descriptor = os.open(config.log, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            result = subprocess.run([*DOCKER, "start", "--attach", identity], env=environment,
                                    check=False, stdout=stream, stderr=subprocess.STDOUT)
            stream.flush()
            os.fsync(stream.fileno())
        return result.returncode
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def execute(config):
    """Execute one fresh attempt. Tests may replace the OS/Docker seams."""
    check_only = not config.run
    for path in (config.work, config.log, config.preflight, config.result, config.attempt_lock):
        fresh(path)
    with host_environment() as environment:
        repo_refs, repo_payloads, cache = initial_inputs(config)
        modules = load_authority_modules(config, repo_payloads)
        docker = docker_authority(config, modules[4], environment)
        lock_payload = repo_payloads["android/grapheneos.lock.json"]
        first_source = source_authority(
            config, modules, lock_payload, output_may_exist=False,
            regenerable_caches_may_exist=True)
        source_identities = first_source["topology"]["directory_identities"]
        missing_container(config.container, environment)
        first_resources = resources(config, environment)
        if check_only:
            print("PASS: read-only Frankel vendor admission; no outputs, cleanup or container")
            print(json.dumps(first_resources, sort_keys=True))
            return 0

        source_lock_fd = acquire_source_lock(config.source)
        lock_fd = None
        try:
            lock_fd = acquire_lock(config.attempt_lock, config)
            attempt_lock_initial = capture_open_regular(config.attempt_lock, lock_fd)
            require_source_directory_identities(config, source_identities, source_lock_fd)
        except BaseException:
            if lock_fd is not None:
                os.close(lock_fd)
            os.close(source_lock_fd)
            raise
        primary_error = None
        primary_exit = None
        cleanup_before = None
        cleanup_after = None
        cleanup_error = None
        identity = None
        create_attempted = False
        nonce = secrets.token_hex(32)
        stopped = False
        stopped_proof_error = None
        created_inspect_ref = stopped_inspect_ref = None
        clone = second_source = second_resources = None
        attempt_lock_final = None
        attempt_lock_error = None
        try:
            try:
                require_source_directory_identities(
                    config, source_identities, source_lock_fd)
                require(capture_open_regular(config.attempt_lock, lock_fd) ==
                        attempt_lock_initial, "Attempt-lock identity changed before cleanup")
                cleanup_before = modules[0].clean_vendor_cache(config.source)
                require_source_directory_identities(
                    config, source_identities, source_lock_fd)
                source_caches_absent(config.source, require_output_absent=True)
                second_source = source_authority(
                    config, modules, lock_payload, output_may_exist=False)
                require(second_source["topology"]["directory_identities"] == source_identities,
                        "Source directory identity changed after initial cleanup")
                clone = prepare_reflink(config)
                final_source = source_authority(
                    config, modules, lock_payload, output_may_exist=False)
                require(second_source == final_source, "Source authority changed before launch")
                final_repo_refs, _ = captured_inventory(
                    config.repo, config.repo_inputs, "repository")
                require(repo_refs == final_repo_refs,
                        "Repository helper inputs changed before launch")
                require(cache == validate_cache(config), "Factory cache changed before launch")
                second_resources = resources(config, environment)
                missing_container(config.container, environment)
                create_argv = create_command(config, nonce)
                write_new(config.preflight, {
                    "schema": 1, "kind": "phase1_frankel_vendor_host_builder_preflight_v1",
                    "source": str(config.source), "repository_inputs": repo_refs,
                    "factory_cache": cache, "docker_authority": docker,
                    "first_source": first_source,
                    "second_source": second_source, "first_admission": first_resources,
                    "second_admission": second_resources, "cleanup_before": cleanup_before,
                    "reflink_workspace": clone, "create_argv": create_argv,
                    "start_argv": [*DOCKER, "start", "--attach", "<exact-created-id>"],
                    "nonce": nonce, "two_complete_admissions": True,
                    "host_cleanup_not_builder_cleanup": True,
                    "archive_copy_or_download_fallback": False,
                    "not_vendor_success_or_source_freeze": True,
                })
                require_source_directory_identities(
                    config, source_identities, source_lock_fd)
                require(capture_open_regular(config.attempt_lock, lock_fd) ==
                        attempt_lock_initial, "Attempt-lock identity changed before create")
                create_attempted = True
                raw_identity = docker_checked(create_argv[len(DOCKER):], environment)
                identity = raw_identity.decode().strip()
                require(re.fullmatch(r"[0-9a-f]{64}", identity), "Created ID is malformed")
                created, created_raw = docker_inspect(identity, environment)
                validate_container(created, config, identity, nonce, stopped=False)
                created_inspect_ref = {"sha256": hashlib.sha256(created_raw).hexdigest(),
                                       "bytes": len(created_raw)}
                primary_exit = run_builder(config, environment, create_argv, identity)
            except BaseException as error:
                primary_error = error

            if identity is not None:
                try:
                    final_info, final_raw = docker_inspect(identity, environment)
                    validate_container(final_info, config, identity, nonce, stopped=True)
                    stopped = True
                    stopped_inspect_ref = {"sha256": hashlib.sha256(final_raw).hexdigest(),
                                           "bytes": len(final_raw),
                                           "exit_code": final_info["State"]["ExitCode"],
                                           "oom_killed": final_info["State"]["OOMKilled"]}
                    if primary_error is None:
                        require(primary_exit == final_info["State"]["ExitCode"],
                                "Docker start exit differs from stopped-container exit")
                except BaseException as error:
                    stopped_proof_error = error
                    if primary_error is None:
                        primary_error = error

            # Never delete source paths while the builder may still be using them.
            if source_cleanup_is_safe(create_attempted, identity, stopped):
                try:
                    require_source_directory_identities(
                        config, source_identities, source_lock_fd)
                    require(capture_open_regular(config.attempt_lock, lock_fd) ==
                            attempt_lock_initial,
                            "Attempt-lock identity changed before final cleanup")
                    cleanup_after = modules[0].clean_vendor_cache(config.source)
                    require_source_directory_identities(
                        config, source_identities, source_lock_fd)
                    source_caches_absent(config.source, require_output_absent=False)
                    final_authority = source_authority(
                        config, modules, lock_payload, output_may_exist=True)
                    require(final_authority["topology"]["directory_identities"] ==
                            source_identities,
                            "Source directory identity changed during final cleanup")
                except BaseException as error:
                    cleanup_error = error
            else:
                cleanup_error = Refusal("cleanup pending: exact owned container is not proven stopped")

            try:
                attempt_lock_final = capture_open_regular(config.attempt_lock, lock_fd)
                require(attempt_lock_final == attempt_lock_initial,
                        "Attempt-lock identity changed before result")
            except BaseException as error:
                attempt_lock_error = error
                if cleanup_error is None:
                    cleanup_error = error

            status = outcome_status(primary_exit, primary_error, cleanup_error)
            generated = None
            if status == "generated":
                try:
                    require_successful_stopped_build(primary_exit, stopped, stopped_inspect_ref)
                    generated = verify_generated_vendor(config)
                except BaseException as error:
                    primary_error = error
                    status = outcome_status(primary_exit, primary_error, cleanup_error)
            result = {
                "schema": 1, "kind": "phase1_frankel_vendor_host_builder_result_v1",
                "status": status, "runtime_qualified": False,
                "source": str(config.source), "container": {"name": config.container,
                    "id": identity, "nonce": nonce, "create_attempted": create_attempted,
                    "authoritatively_stopped": stopped,
                    "created_inspect": created_inspect_ref, "stopped_inspect": stopped_inspect_ref,
                    "stop_proof_exception": error_record(stopped_proof_error), "retained": True},
                "primary": {"builder_exit_code": primary_exit,
                            "exception": error_record(primary_error)},
                "cleanup": {"before_removed": cleanup_before, "after_removed": cleanup_after,
                            "exception": error_record(cleanup_error),
                            "never_ran_while_container_might_be_live": True},
                "inputs": {"repository": repo_refs, "cache": cache,
                           "preflight": capture_regular(config.preflight)[1]
                           if config.preflight.exists() else None,
                           "attempt_lock": {"initial": attempt_lock_initial,
                                            "final": attempt_lock_final,
                                            "binding_exception":
                                                error_record(attempt_lock_error)},
                           "source_directory_identities": source_identities},
                "work": clone, "generated_vendor": generated,
                "negative_claims": {"source_freeze": False, "arm_build": False,
                                    "signing": False, "runtime_qualification": False,
                                    "container_removed": False},
            }
            write_new(config.result, result)
        finally:
            os.close(lock_fd)
            os.close(source_lock_fd)

        if isinstance(primary_error, (KeyboardInterrupt, SystemExit)):
            raise primary_error
        if primary_error is not None or cleanup_error is not None:
            return 2
        return primary_exit or 0


def main(argv=None):
    try:
        args = config_from_args(build_parser().parse_args(argv))
        return execute(args)
    except KeyboardInterrupt:
        raise
    except SystemExit:
        raise
    except (Refusal, OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError) as error:
        print("Frankel vendor runner refused: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
