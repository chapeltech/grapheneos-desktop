#!/usr/bin/python3
"""Bounded read-only startup diagnostics for one root-authorized API guest.

This program is deliberately not a runtime producer or auditor.  It cannot
start, stop, signal, configure, unlock, or inject input into Android.  It reads
one exact already-running container through five reviewed diagnostics and
seals the results as ``READ_ONLY_DIAGNOSTIC_NOT_RUNTIME_EVIDENCE_OR_PASS``.

The production CLI remains inert until a create-only ``authorization.json``
with an independently supplied SHA-256 is present beside this file and the
explicit root-authorization switch is supplied.
"""
from __future__ import annotations

import argparse
import dataclasses
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time
from typing import Any


HERE = Path(__file__).absolute().parent
ROOT = Path("/u/elric/tree/wonad")
EVIDENCE_ROOT = HERE / "evidence"
AUTHORIZATION_PATH = HERE / "authorization.json"
PAIR_DRIVER = Path(
    "/u/elric/tree/wonad-phase1-build-evidence/"
    "run-phase1-custom7-api-recents-packet6-20261011-5.py"
)
SELECTION_PATH = Path(
    "/u/elric/tree/wonad-phase1-build-evidence/"
    "phase1-custom7-api-recents-packet6-selection-20261011-5.json"
)
ACCEPTANCE_SOURCE = ROOT / "android/tools/phase1_conformance_acceptance.py"
ACCEPTANCE_SHA256 = "ede7566d7227a014bd984678d5e5c39a090824edfb0b250f2392728014da99af"
LOCALITY_SOURCE = ROOT / "android/tools/docker_locality_proof.py"
LOCALITY_SHA256 = "09b68ceabeb83ed997608a427f8bd5e4196a229d0e3ffd5fc59a98cff85da780"
API_STATE_DIRECTORY = (
    ROOT / "android/out/phase1-evidence-custom7-5/"
    "runtime-api-packet6-20261011-5/emulator-state"
)
PRODUCT = Path(
    "/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-5/"
    "target/product/emu64x"
)
PACKET_SHA256 = "09f786a9e86ada4576be8ace27997959bca7c959f45651d5376afa7aeaab4211"
DOCKER = Path("/usr/bin/docker")
ENDPOINT = "unix:///var/run/docker.sock"
SERIAL = "emulator-5580"
LABEL = "org.wonad.phase1-fresh-conformance"
SCOPE = "READ_ONLY_DIAGNOSTIC_NOT_RUNTIME_EVIDENCE_OR_PASS"
KIND = "wonad-phase1-api-startup-watch-diagnostic-v1"
AUTH_KIND = "wonad-phase1-api-startup-watch-authorization-v1"
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX32 = re.compile(r"[0-9a-f]{32}")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}")
BOOT_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
MAX_OUTPUT = 512 * 1024
PROCESS_TIMEOUT = 3.0
BUNDLE_TIMEOUT = 10.0
SAMPLE_OFFSETS = (0.0, 4.0, 9.0)
TRIGGER_TIMEOUT = 12.0
POLL_INTERVAL = 0.20
CALLBACKS = {"onSnapshot", "onCommand", "onResult", "onRevoked"}
OPERATIONS = {
    "getApiVersion", "getCapabilities", "openSession", "applyFrame", "focusTask",
    "closeTask", "enableShortcuts", "heartbeat", "release", "enableExternalUi",
    "showShell", "launcherPage", "showLauncher", "selectLauncher",
    "showTransferPicker", "applySignedFrame",
}
PRE_TRIGGER_PHASES = {"created", "binding", "waiting-initial-snapshot"}
TRIGGER_PHASE = "enabling-external-ui"


class WatchError(ValueError):
    pass


def require(value: Any, message: str) -> None:
    if not value:
        raise WatchError(message)


def strict_object(rows):
    result = {}
    for key, value in rows:
        require(key not in result, "Duplicate JSON field: " + key)
        result[key] = value
    return result


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_ref_from_bytes(path: Path, value: bytes) -> dict:
    return {"path": str(path), "sha256": digest_bytes(value), "bytes": len(value)}


def stable_bytes(path: Path, *, maximum: int = 16 * 1024 * 1024) -> bytes:
    """Read one literal regular file without following a pathname replacement."""
    raw = path.absolute()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(raw, flags)
    except OSError as error:
        raise WatchError("Missing/aliased authority file: " + str(raw)) from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), "Authority is not a regular file: " + str(raw))
        pieces, total = [], 0
        while True:
            piece = os.read(descriptor, 65536)
            if not piece:
                break
            total += len(piece)
            require(total <= maximum, "Authority file exceeds bounded read: " + str(raw))
            pieces.append(piece)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "Authority changed during read: " + str(raw))
    try:
        current = os.lstat(raw)
    except FileNotFoundError as error:
        raise WatchError("Authority disappeared after read: " + str(raw)) from error
    require(not stat.S_ISLNK(current.st_mode) and
            (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "Authority pathname changed during read: " + str(raw))
    return b"".join(pieces)


def parse_json_bytes(value: bytes, label: str) -> Any:
    try:
        text = value.decode("utf-8")
        return json.loads(text, object_pairs_hook=strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError, WatchError) as error:
        raise WatchError("Malformed " + label + ": " + str(error)) from error


def write_new(path: Path, value: bytes, mode: int = 0o600) -> dict:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, mode)
    try:
        offset = 0
        while offset < len(value):
            count = os.write(descriptor, value[offset:])
            require(count > 0, "Short write while sealing " + str(path))
            offset += count
        os.fsync(descriptor)
        observed = os.fstat(descriptor)
        require(observed.st_size == len(value), "Sealed file size changed: " + str(path))
    finally:
        os.close(descriptor)
    return {"path": path.name, "sha256": digest_bytes(value), "bytes": len(value)}


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                         getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@dataclasses.dataclass(frozen=True)
class Capture:
    argv: tuple[str, ...]
    started_monotonic_ns: int
    ended_monotonic_ns: int
    returncode: int
    output: bytes
    timed_out: bool = False
    oversized: bool = False


@dataclasses.dataclass(frozen=True)
class Policy:
    pair_driver: Path = PAIR_DRIVER
    selection: Path = SELECTION_PATH
    acceptance_source: Path = ACCEPTANCE_SOURCE
    acceptance_sha256: str = ACCEPTANCE_SHA256
    locality_source: Path = LOCALITY_SOURCE
    locality_sha256: str = LOCALITY_SHA256
    state_directory: Path = API_STATE_DIRECTORY
    product: Path = PRODUCT
    packet_sha256: str = PACKET_SHA256
    evidence_root: Path = EVIDENCE_ROOT
    authorization_path: Path = AUTHORIZATION_PATH
    watcher_source: Path = Path(__file__).absolute()


class ProductionBackend:
    """Exact local Docker read surface; no mutating Docker subcommand exists."""

    def __init__(self):
        forbidden = sorted(key for key in os.environ
                           if key.startswith("DOCKER_") or
                           key in {"CONTAINER_HOST", "CONTAINER_CONTEXT"})
        require(not forbidden, "Docker endpoint overrides are forbidden: " + ", ".join(forbidden))
        home = os.environ.get("HOME")
        require(isinstance(home, str) and home.startswith("/") and "\x00" not in home,
                "A literal absolute HOME is required for Docker context selection")
        self.environment = {"HOME": home, "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}

    @staticmethod
    def _node(path: Path, expected_type, uid: int, gid: int, mode: int,
              realpath: Path) -> dict:
        try:
            before = os.lstat(path)
            resolved = Path(os.path.realpath(path))
            after = os.lstat(path)
        except OSError as error:
            raise WatchError("Cannot inspect trusted Docker node: " + str(path)) from error
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size",
                  "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, field) == getattr(after, field) for field in fields) and
                expected_type(before.st_mode) and before.st_uid == uid and before.st_gid == gid and
                stat.S_IMODE(before.st_mode) == mode and resolved == realpath,
                "Trusted Docker node identity differs: " + str(path))
        return {"path": str(path), "realpath": str(resolved), "device": before.st_dev,
                "inode": before.st_ino, "mode": before.st_mode, "uid": before.st_uid,
                "gid": before.st_gid}

    def locality(self) -> tuple[dict, list[tuple[str, Capture]]]:
        try:
            docker_gid = grp.getgrnam("docker").gr_gid
        except KeyError as error:
            raise WatchError("The local docker group does not exist") from error
        static = {
            "cli": self._node(DOCKER, stat.S_ISREG, 0, 0, 0o755, DOCKER),
            "socket": self._node(Path("/var/run/docker.sock"), stat.S_ISSOCK, 0,
                                 docker_gid, 0o660, Path("/run/docker.sock")),
        }
        require(os.path.samefile("/var/run/docker.sock", "/run/docker.sock"),
                "Docker socket is not the exact local /run/docker.sock node")
        probes = [
            ("docker-context-show", [str(DOCKER), "context", "show"]),
            ("docker-context-inspect", [str(DOCKER), "context", "inspect", "default"]),
            ("docker-version", [str(DOCKER), "--host", ENDPOINT, "version", "--format",
                                "{{json .}}"]),
            ("docker-info", [str(DOCKER), "--host", ENDPOINT, "info", "--format",
                             "{{json .}}"]),
        ]
        return static, [(role, self._run(argv, PROCESS_TIMEOUT)) for role, argv in probes]

    def kvm_gid(self) -> int:
        value = os.stat("/dev/kvm", follow_symlinks=False)
        require(stat.S_ISCHR(value.st_mode), "/dev/kvm is not a character device")
        return value.st_gid

    def now_ns(self) -> int:
        return time.monotonic_ns()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def _run(self, argv: list[str], timeout: float) -> Capture:
        require(0 < timeout <= PROCESS_TIMEOUT, "Invalid bounded process timeout")
        started = self.now_ns()
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   env=self.environment, close_fds=True)
        require(process.stdout is not None, "Could not capture Docker output")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        output = bytearray()
        timed_out = oversized = False
        deadline = time.monotonic() + timeout
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                events = selector.select(min(remaining, 0.10))
                if not events:
                    if process.poll() is not None:
                        # Drain the final pipe bytes on the next select/read.
                        events = selector.select(0)
                        if not events:
                            break
                    continue
                for key, _mask in events:
                    piece = os.read(key.fd, 65536)
                    if not piece:
                        selector.unregister(key.fileobj)
                        continue
                    room = MAX_OUTPUT - len(output)
                    if len(piece) > room:
                        output.extend(piece[:max(0, room)])
                        oversized = True
                        break
                    output.extend(piece)
                if oversized:
                    break
        finally:
            selector.close()
        if timed_out or oversized:
            # Kill and reap only this host-side Docker CLI.  Never signal or stop
            # the container, emulator, adb server, or producer process.
            if process.poll() is None:
                process.kill()
            process.wait()
        else:
            try:
                process.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                process.wait()
        return Capture(tuple(argv), started, self.now_ns(), int(process.returncode),
                       bytes(output), timed_out, oversized)

    def inspect(self, container: str, timeout: float = PROCESS_TIMEOUT) -> Capture:
        return self._run([str(DOCKER), "--host", ENDPOINT, "container", "inspect", container], timeout)

    def guest(self, container: str, command: list[str], timeout: float = PROCESS_TIMEOUT) -> Capture:
        return self._run([str(DOCKER), "--host", ENDPOINT, "exec", container,
                          "adb", "-s", SERIAL, *command], timeout)


def validate_ref(row: Any, path: Path, expected_sha256: str | None = None) -> tuple[dict, bytes]:
    require(isinstance(row, dict) and set(row) == {"path", "sha256", "bytes"},
            "Malformed authority file reference")
    require(row["path"] == str(path) and HEX64.fullmatch(str(row["sha256"])) and
            type(row["bytes"]) is int and row["bytes"] > 0,
            "Authority file reference differs from the reviewed literal path")
    value = stable_bytes(path)
    observed = file_ref_from_bytes(path, value)
    require(row == observed, "Authority file bytes differ: " + str(path))
    if expected_sha256 is not None:
        require(row["sha256"] == expected_sha256,
                "Authority file is not the reviewed version: " + str(path))
    return observed, value


def validate_selection(value: Any, authorization: dict, policy: Policy) -> None:
    keys = {"schema", "scope", "native_image_id", "derived_image_id", "native_manifest",
            "native_manifest_sha256", "derived_manifest", "derived_manifest_sha256", "product",
            "packet_receipt_sha256", "baseline_receipt_sha256", "custom_receipt_sha256",
            "comparison_sha256"}
    require(isinstance(value, dict) and set(value) == keys and
            type(value["schema"]) is int and value["schema"] == 1 and
            value["scope"] == "custom7-packet6-two-separate-fresh-guests-not-runtime-qualified" and
            value["derived_image_id"] == authorization["container"]["image_id"] and
            value["product"] == str(policy.product) and
            value["packet_receipt_sha256"] == policy.packet_sha256 and
            all(HEX64.fullmatch(str(value[key])) for key in
                ("native_manifest_sha256", "derived_manifest_sha256", "packet_receipt_sha256",
                 "baseline_receipt_sha256", "custom_receipt_sha256", "comparison_sha256")) and
            IMAGE.fullmatch(str(value["native_image_id"])) and
            IMAGE.fullmatch(str(value["derived_image_id"])),
            "Selection does not bind the reviewed custom7/packet6 API guest")


def load_authorization(path: Path, expected_sha256: str, policy: Policy) -> tuple[dict, dict]:
    require(HEX64.fullmatch(expected_sha256) is not None, "Expected authorization SHA-256 is malformed")
    raw = stable_bytes(path)
    require(digest_bytes(raw) == expected_sha256, "Authorization SHA-256 differs")
    value = parse_json_bytes(raw, "authorization")
    require(isinstance(value, dict) and set(value) == {
                "schema", "kind", "scope", "pair_driver", "selection", "container"} and
            type(value["schema"]) is int and value["schema"] == 1 and
            value["kind"] == AUTH_KIND and value["scope"] == SCOPE,
            "Malformed startup-watch authorization")
    container = value["container"]
    require(isinstance(container, dict) and set(container) == {
                "id", "name", "nonce", "image_id", "boot_id", "run", "state_directory",
                "user", "kvm_group"} and
            HEX64.fullmatch(str(container["id"])) and HEX32.fullmatch(str(container["nonce"])) and
            container["name"] == "/wonad-phase1-conformance-" + container["nonce"][:12] and
            IMAGE.fullmatch(str(container["image_id"])) and BOOT_ID.fullmatch(str(container["boot_id"])) and
            HEX32.fullmatch(str(container["run"])) and
            container["state_directory"] == str(policy.state_directory) and
            container["user"] == "1000:1000" and
            isinstance(container["kvm_group"], str) and container["kvm_group"].isdecimal(),
            "Malformed or nonliteral live-container authorization")
    pair_ref, _pair = validate_ref(value["pair_driver"], policy.pair_driver)
    selection_ref, selection_raw = validate_ref(value["selection"], policy.selection)
    selection = parse_json_bytes(selection_raw, "selection")
    validate_selection(selection, value, policy)
    acceptance_raw = stable_bytes(policy.acceptance_source)
    locality_raw = stable_bytes(policy.locality_source)
    require(digest_bytes(acceptance_raw) == policy.acceptance_sha256,
            "Reviewed conformance container profile source changed")
    require(digest_bytes(locality_raw) == policy.locality_sha256,
            "Reviewed local-Docker authority source changed")
    watcher_raw = stable_bytes(policy.watcher_source)
    authority = {
        "authorization": file_ref_from_bytes(path, raw),
        "watcher": file_ref_from_bytes(policy.watcher_source, watcher_raw),
        "pair_driver": pair_ref,
        "selection": selection_ref,
        "container_profile_source": file_ref_from_bytes(policy.acceptance_source, acceptance_raw),
        "docker_locality_source": file_ref_from_bytes(policy.locality_source, locality_raw),
    }
    return value, authority


def parse_inspect(capture: Capture) -> dict:
    require(not capture.timed_out and not capture.oversized and capture.returncode == 0,
            "Owned-container inspect failed, timed out, or exceeded its bound")
    values = parse_json_bytes(capture.output, "owned-container inspect")
    require(isinstance(values, list) and len(values) == 1 and isinstance(values[0], dict),
            "Owned-container inspect is missing or ambiguous")
    return values[0]


def validate_locality(static: Any, captures: dict[str, Capture]) -> dict:
    node_fields = {"path", "realpath", "device", "inode", "mode", "uid", "gid"}
    require(isinstance(static, dict) and set(static) == {"cli", "socket"} and
            all(isinstance(static[key], dict) and set(static[key]) == node_fields
                for key in ("cli", "socket")),
            "Malformed local-Docker node identity")
    cli, socket = static["cli"], static["socket"]
    require(cli["path"] == cli["realpath"] == str(DOCKER) and cli["uid"] == cli["gid"] == 0 and
            cli["mode"] == (stat.S_IFREG | 0o755) and
            socket["path"] == "/var/run/docker.sock" and
            socket["realpath"] == "/run/docker.sock" and socket["uid"] == 0 and
            socket["mode"] == (stat.S_IFSOCK | 0o660) and
            all(type(row[key]) is int for row in (cli, socket)
                for key in ("device", "inode", "mode", "uid", "gid")),
            "Local Docker CLI/socket identity differs")
    require(set(captures) == {"docker-context-show", "docker-context-inspect",
                              "docker-version", "docker-info"},
            "Incomplete local-Docker probe set")
    try:
        selected = captures["docker-context-show"].output.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise WatchError("Docker context selection is not UTF-8") from error
    contexts = parse_json_bytes(captures["docker-context-inspect"].output,
                                "Docker context inspect")
    version = parse_json_bytes(captures["docker-version"].output, "Docker version")
    info = parse_json_bytes(captures["docker-info"].output, "Docker info")
    require(selected == "default" and isinstance(contexts, list) and len(contexts) == 1 and
            isinstance(contexts[0], dict), "Selected Docker context is not exact default")
    context = contexts[0]
    endpoint = context.get("Endpoints", {}).get("docker", {})
    require(context.get("Name") == "default" and context.get("Metadata") == {} and
            endpoint == {"Host": ENDPOINT, "SkipTLSVerify": False} and
            context.get("TLSMaterial") == {},
            "Built-in default Docker context is not the exact local Unix endpoint")
    require(isinstance(version, dict) and isinstance(info, dict) and
            version.get("Client", {}).get("Os") == "linux" and
            version.get("Server", {}).get("Os") == "linux" and
            info.get("OSType") == "linux" and
            isinstance(info.get("ID"), str) and bool(info["ID"]) and
            isinstance(info.get("DockerRootDir"), str) and info["DockerRootDir"].startswith("/") and
            info.get("ClientInfo", {}).get("Context") == "default",
            "Local Docker daemon identity is incomplete")
    return {
        "endpoint": ENDPOINT, "cli": cli, "socket": socket,
        "context": {"selected": selected, "name": context["Name"],
                    "endpoint": endpoint["Host"],
                    "skip_tls_verify": endpoint["SkipTLSVerify"],
                    "tls_material": context["TLSMaterial"]},
        "daemon": {"id": info["ID"], "name": info.get("Name"),
                   "server_version": info.get("ServerVersion"),
                   "kernel_version": info.get("KernelVersion"),
                   "os": info["OSType"], "architecture": info.get("Architecture"),
                   "root_dir": info["DockerRootDir"],
                   "client_version": version.get("Client", {}).get("Version"),
                   "client_context": info.get("ClientInfo", {}).get("Context")},
    }


def validate_container(info: dict, authorization: dict, *, require_running: bool) -> dict:
    expected = authorization["container"]
    config, host, state = info.get("Config"), info.get("HostConfig"), info.get("State")
    mounts = info.get("Mounts")
    require(all(isinstance(row, dict) for row in (config, host, state)) and
            isinstance(mounts, list) and len(mounts) == 1,
            "Malformed owned-container inspect profile")
    required_host = {"CapAdd", "DeviceRequests", "DeviceCgroupRules", "PidMode", "IpcMode",
        "CgroupnsMode", "UTSMode", "UsernsMode", "VolumesFrom", "MemorySwap",
        "ReadonlyRootfs", "AutoRemove", "RestartPolicy", "PublishAllPorts",
        "MemoryReservation", "PortBindings"}
    require(required_host <= set(host), "Owned-container inspect omitted isolation fields")
    mount = mounts[0]
    limits = host.get("Ulimits")
    require(info.get("Id") == expected["id"] and info.get("Name") == expected["name"] and
            info.get("Image") == expected["image_id"] and
            config.get("Labels", {}).get(LABEL) == expected["nonce"] and
            config.get("User") == expected["user"], "Live container identity differs")
    require(isinstance(mount, dict) and mount.get("Type") == "bind" and
            mount.get("Source") == expected["state_directory"] and mount.get("Destination") == "/state" and
            mount.get("Mode") == "rw,Z" and mount.get("RW") is True and
            mount.get("Propagation") == "rprivate" and
            host.get("Binds") == [expected["state_directory"] + ":/state:rw,Z"],
            "Live container state bind differs")
    require(host.get("NetworkMode") == "none" and host.get("Privileged") is False and
            host.get("PortBindings") in (None, {}) and host.get("PublishAllPorts") is False and
            host.get("CapAdd") in (None, []) and host.get("CapDrop") == ["ALL"] and
            host.get("SecurityOpt") == ["no-new-privileges=true"] and
            host.get("DeviceRequests") in (None, []) and host.get("DeviceCgroupRules") in (None, []) and
            host.get("VolumesFrom") in (None, []) and host.get("PidMode") == "" and
            host.get("IpcMode") == "private" and host.get("CgroupnsMode") == "private" and
            host.get("UTSMode") == "" and host.get("UsernsMode") == "" and
            host.get("ReadonlyRootfs") is False and host.get("AutoRemove") is False and
            isinstance(host.get("RestartPolicy"), dict) and
            type(host["RestartPolicy"].get("MaximumRetryCount")) is int and
            host.get("RestartPolicy") == {"Name": "no", "MaximumRetryCount": 0},
            "Live container privilege/network/namespace profile differs")
    require(host.get("GroupAdd") == [expected["kvm_group"]] and
            host.get("Devices") == [{"PathOnHost": "/dev/kvm", "PathInContainer": "/dev/kvm",
                                     "CgroupPermissions": "rwm"}] and
            host.get("PidsLimit") == 1024 and host.get("Memory") == 8 * 1024**3 and
            host.get("MemorySwap") == 16 * 1024**3 and
            type(host.get("MemoryReservation")) is int and host.get("MemoryReservation") == 0 and
            host.get("NanoCpus") == 12_000_000_000 and host.get("ShmSize") == 512 * 1024**2 and
            host.get("Tmpfs") == {"/tmp": "rw,nosuid,nodev,size=2g"},
            "Live container device/resource profile differs")
    require(isinstance(limits, list) and len(limits) == 2 and
            all(isinstance(row, dict) and set(row) == {"Name", "Hard", "Soft"} and
                isinstance(row["Name"], str) and type(row["Hard"]) is int and
                type(row["Soft"]) is int for row in limits) and
            sorted(limits, key=lambda row: row.get("Name", "")) == [
                {"Name": "core", "Hard": 0, "Soft": 0},
                {"Name": "nofile", "Hard": 65536, "Soft": 65536}],
            "Live container ulimit profile differs")
    require(type(state.get("Running")) is bool and type(state.get("OOMKilled")) is bool and
            type(state.get("Paused")) is bool and type(state.get("Restarting")) is bool and
            type(state.get("Dead")) is bool and type(state.get("Pid")) is int,
            "Live container state fields are missing or untyped")
    require(state.get("OOMKilled") is False and state.get("Paused") is False and
            state.get("Restarting") is False and state.get("Dead") is False,
            "Live container is OOM-killed, paused, restarting, or dead")
    if require_running:
        require(state.get("Running") is True and state.get("Status") == "running" and state.get("Pid") > 0,
                "Authorized API container is not running")
    projection = {
        "id": info["Id"], "name": info["Name"], "image": info["Image"],
        "nonce": config["Labels"][LABEL], "user": config["User"], "mount": mount,
        "host": {key: host.get(key) for key in sorted(required_host | {
            "Binds", "NetworkMode", "Privileged", "CapDrop", "SecurityOpt", "GroupAdd", "Devices",
            "PidsLimit", "Memory", "NanoCpus", "ShmSize", "Tmpfs", "Ulimits"})},
        "state": {key: state.get(key) for key in
                  ("Status", "Running", "Paused", "Restarting", "OOMKilled", "Dead", "Pid")},
    }
    return projection


def parse_status(raw: bytes, expected_run: str) -> dict:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise WatchError("Conformance status is not UTF-8") from error
    rows = re.findall(r"^WONAD_CONFORMANCE_STATUS (\{.*\})$", text, re.M)
    require(len(rows) == 1, "Missing/ambiguous WONAD_CONFORMANCE_STATUS")
    value = parse_json_bytes(rows[0].encode(), "Conformance status")
    keys = {"schema", "run", "mode", "state", "phase", "started_elapsed_ms",
            "updated_elapsed_ms", "api_version", "capabilities", "generation", "display_ids",
            "heartbeat_count", "operations", "callbacks", "facades", "failure"}
    require(isinstance(value, dict) and set(value) == keys and
            type(value["schema"]) is int and value["schema"] == 1 and
            value["run"] == expected_run and value["mode"] == "full" and
            value["state"] in {"running", "failed", "passed"} and
            isinstance(value["phase"], str) and re.fullmatch(r"[a-z0-9-]{1,64}", value["phase"]) and
            type(value["started_elapsed_ms"]) is int and value["started_elapsed_ms"] > 0 and
            type(value["updated_elapsed_ms"]) is int and
            value["updated_elapsed_ms"] >= value["started_elapsed_ms"] and
            type(value["api_version"]) is int and value["api_version"] >= 0 and
            type(value["capabilities"]) is int and value["capabilities"] >= 0 and
            type(value["generation"]) is int and value["generation"] >= 0 and
            isinstance(value["display_ids"], list) and
            all(type(item) is int and item > 0 for item in value["display_ids"]) and
            value["display_ids"] == sorted(set(value["display_ids"])) and
            type(value["heartbeat_count"]) is int and value["heartbeat_count"] >= 0 and
            isinstance(value["operations"], list) and
            all(isinstance(item, str) and item in OPERATIONS for item in value["operations"]) and
            len(value["operations"]) == len(set(value["operations"])) and
            isinstance(value["callbacks"], dict) and set(value["callbacks"]) == CALLBACKS and
            all(type(item) is int and item >= 0 for item in value["callbacks"].values()) and
            isinstance(value["facades"], list) and len(value["facades"]) <= 64 and
            all(re.fullmatch(r"(?:ExternalHomeActivity|ExternalShellActivity|LauncherActivity):"
                             r"(?:valid|rejected)", str(item)) for item in value["facades"]) and
            ((value["state"] == "failed" and isinstance(value["failure"], str)) or
             (value["state"] != "failed" and value["failure"] is None)),
            "Malformed or foreign full-conformance status")
    return value


def trigger_ready(value: dict) -> bool:
    return (value["state"] == "running" and value["phase"] == TRIGGER_PHASE and
            value["api_version"] == 3 and value["generation"] > 0 and
            bool(value["display_ids"]) and value["callbacks"]["onSnapshot"] > 0 and
            {"getApiVersion", "getCapabilities", "openSession", "enableExternalUi", "showShell"}
                <= set(value["operations"]))


def startup_advanced(value: dict) -> bool:
    return value["state"] == "passed" or (value["state"] == "running" and
        value["phase"] not in PRE_TRIGGER_PHASES | {TRIGGER_PHASE})


class Recorder:
    def __init__(self, root: Path):
        self.root = root
        self.raw = root / "raw"
        self.rows = root / "rows"
        os.mkdir(root, 0o700)
        os.mkdir(self.raw, 0o700)
        os.mkdir(self.rows, 0o700)
        fsync_directory(root.parent)
        self.records = []

    def capture(self, role: str, value: Capture) -> dict:
        require(re.fullmatch(r"[a-z0-9-]{1,64}", role), "Invalid observation role")
        ordinal = len(self.records)
        stem = f"{ordinal:03d}-{role}"
        raw_ref = write_new(self.raw / (stem + ".raw"), value.output)
        raw_ref["path"] = "raw/" + raw_ref["path"]
        row = {
            "schema": 1, "kind": "wonad-phase1-api-startup-watch-command-v1", "scope": SCOPE,
            "ordinal": ordinal, "role": role, "argv": list(value.argv),
            "started_monotonic_ns": value.started_monotonic_ns,
            "ended_monotonic_ns": value.ended_monotonic_ns,
            "returncode": value.returncode, "timed_out": value.timed_out,
            "oversized": value.oversized, "raw": raw_ref,
        }
        row_bytes = canonical(row)
        row_ref = write_new(self.rows / (stem + ".json"), row_bytes)
        row_ref["path"] = "rows/" + row_ref["path"]
        record = {"role": role, "row": row_ref, "raw": raw_ref,
                  "started_monotonic_ns": value.started_monotonic_ns,
                  "ended_monotonic_ns": value.ended_monotonic_ns,
                  "returncode": value.returncode, "timed_out": value.timed_out,
                  "oversized": value.oversized}
        self.records.append(record)
        return record

    def seal(self, name: str, value: dict) -> dict:
        result = write_new(self.root / name, canonical(value))
        fsync_directory(self.raw)
        fsync_directory(self.rows)
        fsync_directory(self.root)
        return result


class Watcher:
    SERVICE = ["shell", "dumpsys", "activity", "service", "org.wonad.desktop/.ConformanceService"]
    ACTIVITIES = ["shell", "dumpsys", "activity", "activities"]
    WINDOWS = ["shell", "dumpsys", "window", "windows"]
    SYSTEMUI = ["shell", "dumpsys", "activity", "service", "com.android.systemui/.SystemUIService"]
    LOGCAT = ["logcat", "-b", "main", "-d", "-v", "threadtime", "-t", "400", "-s",
              "WonadNativeBroker:V", "WonadUi:V", "WonadNative:V",
              "ActivityTaskManager:W", "*:S"]
    BOOT = ["shell", "cat", "/proc/sys/kernel/random/boot_id"]

    def __init__(self, authorization: dict, authority: dict, backend, recorder: Recorder,
                 policy: Policy):
        self.authorization = authorization
        self.authority = authority
        self.backend = backend
        self.recorder = recorder
        self.policy = policy
        self.container = authorization["container"]["id"]
        self.expected_boot = authorization["container"]["boot_id"]
        self.expected_run = authorization["container"]["run"]
        self.samples = []

    def checked(self, role: str, capture: Capture) -> Capture:
        self.recorder.capture(role, capture)
        require(capture.ended_monotonic_ns >= capture.started_monotonic_ns,
                "Command observation time regressed")
        require(len(capture.output) <= MAX_OUTPUT, "Backend returned output beyond sealed bound")
        require(not capture.timed_out, role + " timed out")
        require(not capture.oversized, role + " exceeded 512KiB")
        require(capture.returncode == 0, role + " returned nonzero status")
        return capture

    def inspect(self, role: str, require_running: bool) -> dict:
        capture = self.checked(role, self.backend.inspect(self.container, PROCESS_TIMEOUT))
        return validate_container(parse_inspect(capture), self.authorization,
                                  require_running=require_running)

    def guest(self, role: str, command: list[str], timeout: float = PROCESS_TIMEOUT) -> Capture:
        return self.checked(role, self.backend.guest(self.container, command, timeout))

    def boot(self, role: str) -> None:
        capture = self.guest(role, self.BOOT)
        try:
            value = capture.output.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise WatchError("Guest boot ID is not ASCII") from error
        require(value == self.expected_boot, "Guest boot identity differs")

    def status(self, role: str, timeout: float = PROCESS_TIMEOUT) -> tuple[Capture, dict]:
        capture = self.guest(role, self.SERVICE, timeout)
        return capture, parse_status(capture.output, self.expected_run)

    def wait_trigger(self) -> tuple[str, Capture | None, dict | None]:
        deadline = self.backend.now_ns() + int(TRIGGER_TIMEOUT * 1_000_000_000)
        ordinal = 0
        while self.backend.now_ns() <= deadline:
            capture, value = self.status(f"trigger-status-{ordinal:02d}")
            if trigger_ready(value):
                return "triggered", capture, value
            if value["state"] in {"failed", "passed"}:
                return "terminal-before-trigger", capture, value
            if startup_advanced(value):
                return "startup-advanced", capture, value
            ordinal += 1
            remaining = (deadline - self.backend.now_ns()) / 1_000_000_000
            if remaining <= 0:
                break
            self.backend.sleep(min(POLL_INTERVAL, remaining))
        return "trigger-timeout", None, None

    def sample(self, ordinal: int, target_ns: int, first_status: Capture | None,
               first_value: dict | None) -> tuple[bool, str]:
        remaining = (target_ns - self.backend.now_ns()) / 1_000_000_000
        if remaining > 0:
            self.backend.sleep(remaining)
        bundle_start = self.backend.now_ns()
        if first_status is None:
            status_capture, status = self.status(f"sample-{ordinal}-status")
        else:
            status_capture, status = first_status, first_value
        assert status is not None
        sample = {"ordinal": ordinal, "target_offset_seconds": SAMPLE_OFFSETS[ordinal],
                  "started_monotonic_ns": bundle_start, "status": status, "observations": []}
        # The trigger status was already sealed.  Subsequent status reads are
        # sealed by status(); record references by ordinal range below.
        sample["observations"].append("status")
        if startup_advanced(status):
            sample["ended_monotonic_ns"] = self.backend.now_ns()
            sample["disposition"] = "startup-advanced"
            self.samples.append(sample)
            return False, "startup-advanced"
        terminal = status["state"] in {"failed", "passed"}
        commands = [
            (f"sample-{ordinal}-activities", self.ACTIVITIES),
            (f"sample-{ordinal}-windows", self.WINDOWS),
            (f"sample-{ordinal}-systemui", self.SYSTEMUI),
            (f"sample-{ordinal}-logcat", self.LOGCAT),
        ]
        for role, command in commands:
            left = BUNDLE_TIMEOUT - ((self.backend.now_ns() - bundle_start) / 1_000_000_000)
            require(left > 0, "Diagnostic bundle exceeded ten seconds")
            self.guest(role, command, min(PROCESS_TIMEOUT, left))
            sample["observations"].append(role.rsplit("-", 1)[-1])
        sample["ended_monotonic_ns"] = self.backend.now_ns()
        require(sample["ended_monotonic_ns"] - bundle_start <= int(BUNDLE_TIMEOUT * 1_000_000_000),
                "Diagnostic bundle exceeded ten seconds")
        sample["disposition"] = "terminal-captured" if terminal else "startup-sampled"
        self.samples.append(sample)
        return not terminal, sample["disposition"]

    def run(self) -> dict:
        locality_static, locality_rows = self.backend.locality()
        locality_captures = {
            role: self.checked(role, capture) for role, capture in locality_rows
        }
        locality = validate_locality(locality_static, locality_captures)
        actual_gid = self.backend.kvm_gid()
        require(str(actual_gid) == self.authorization["container"]["kvm_group"],
                "Authorized KVM group differs from the live host")
        initial_profile = self.inspect("initial-container-inspect", True)
        self.boot("initial-boot-id")
        disposition, first_capture, first_value = self.wait_trigger()
        if disposition == "triggered":
            base = self.backend.now_ns()
            keep = True
            for ordinal, offset in enumerate(SAMPLE_OFFSETS):
                if not keep:
                    break
                keep, disposition = self.sample(
                    ordinal, base + int(offset * 1_000_000_000),
                    first_capture if ordinal == 0 else None,
                    first_value if ordinal == 0 else None,
                )
        final_profile = None
        final_boot_checked = False
        final_capture = self.backend.inspect(self.container, PROCESS_TIMEOUT)
        self.recorder.capture("final-container-inspect", final_capture)
        if not final_capture.timed_out and not final_capture.oversized and final_capture.returncode == 0:
            final_profile = validate_container(parse_inspect(final_capture), self.authorization,
                                               require_running=False)
            if final_profile["state"]["Running"]:
                self.boot("final-boot-id")
                final_boot_checked = True
        # Recheck every authority input after the observations.  No current
        # pathname is trusted solely because it matched before Docker reads.
        final_authority, _ = load_authorization(
            self.policy.authorization_path,
            self.authority["authorization"]["sha256"], self.policy)
        require(final_authority == self.authorization,
                "Authorization changed during the diagnostic")
        return {
            "schema": 1, "kind": KIND, "scope": SCOPE,
            "diagnostic_only": True, "runtime_pass": False, "release_qualification": False,
            "disposition": disposition, "authority": self.authority,
            "local_docker": locality, "container": self.authorization["container"],
            "initial_profile": initial_profile, "final_profile": final_profile,
            "final_boot_checked": final_boot_checked,
            "sampling": {"maximum_samples": 3, "offset_seconds": list(SAMPLE_OFFSETS),
                         "process_timeout_seconds": PROCESS_TIMEOUT,
                         "bundle_timeout_seconds": BUNDLE_TIMEOUT,
                         "maximum_output_bytes_per_process": MAX_OUTPUT},
            "samples": self.samples, "commands": self.recorder.records,
            "limitations": [
                "Read-only point samples are diagnostic and cannot prove runtime acceptance.",
                "The full-mode ledger exposes callback counts, not callback snapshot payloads.",
                "No guest was started, stopped, signalled, configured, unlocked, or given input by this watcher.",
            ],
        }


def execute(authorization_path: Path, expected_sha256: str, backend,
            policy: Policy = Policy()) -> int:
    authorization, authority = load_authorization(authorization_path, expected_sha256, policy)
    require(policy.evidence_root == EVIDENCE_ROOT or policy.evidence_root.parent.exists(),
            "Evidence parent does not exist")
    recorder = Recorder(policy.evidence_root)
    try:
        result = Watcher(authorization, authority, backend, recorder, policy).run()
        recorder.seal("receipt.json", result)
        return 0
    except BaseException as error:
        failure = {
            "schema": 1, "kind": KIND, "scope": SCOPE,
            "diagnostic_only": True, "runtime_pass": False, "release_qualification": False,
            "failure": {"class": error.__class__.__name__, "message": str(error)[:2048]},
            "authority": authority, "commands": recorder.records,
            "limitations": ["This failure is not a runtime result and authorizes no guest restart."],
        }
        try:
            recorder.seal("failure.json", failure)
        except BaseException:
            pass
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--expected-authorization-sha256", required=True)
    parser.add_argument("--execute-after-root-authorization", action="store_true")
    args = parser.parse_args(argv)
    require(args.execute_after_root_authorization,
            "Explicit root-authorized diagnostic switch is required")
    require(args.authorization.absolute() == AUTHORIZATION_PATH and
            args.authorization.resolve(strict=True) == AUTHORIZATION_PATH and
            not args.authorization.is_symlink(),
            "Use only the reviewed create-only authorization path")
    require(os.getuid() == os.getgid() == 1000, "Use the owned UID/GID1000 host lane")
    require(not EVIDENCE_ROOT.exists() and not EVIDENCE_ROOT.is_symlink(),
            "Preserve prior diagnostic evidence; use a reviewed successor watcher")
    return execute(args.authorization, args.expected_authorization_sha256, ProductionBackend())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except WatchError as error:
        print("startup watch refused: " + str(error), file=sys.stderr)
        raise SystemExit(2)
