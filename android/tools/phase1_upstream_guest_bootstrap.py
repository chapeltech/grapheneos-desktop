#!/usr/bin/env python3
"""Start one fresh, headless Phase-1 emulator in the pinned runtime image.

This file is mounted read-only by run_phase1_upstream_guest.py.  It deliberately
does not install packages, change Android settings, grant consent, or create an
external display.  Its only TCP listeners may be the loopback console/ADB pair.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import struct
import sys
import time
import traceback


STATE = Path("/state")
PRODUCT = Path("/product")
READY = STATE / "upstream-guest-ready.json"
ERROR = STATE / "bootstrap-error.txt"
EXPECTED_PORTS = {5580, 5581}
DISABLED_NETWORK_FEATURES = (
    "WiFiPacketStream", "Uwb", "BluetoothEmulation", "ModemSimulator",
    "NetsimWebUi", "NetsimCliUi",
)
SHA256 = re.compile(r"[0-9a-f]{64}")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def canonical_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def write_json_new(path: Path, value):
    payload = canonical_bytes(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            require(written > 0, "Short evidence write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def decode_address(family: str, raw: str):
    if family == "ipv4":
        require(len(raw) == 8, "Invalid /proc IPv4 address")
        return str(ipaddress.IPv4Address(bytes.fromhex(raw)[::-1]))
    require(family == "ipv6" and len(raw) == 32, "Invalid /proc IPv6 address")
    packed = b"".join(bytes.fromhex(raw[index:index + 8])[::-1]
                      for index in range(0, 32, 8))
    return str(ipaddress.IPv6Address(packed))


def proc_tcp_rows(proc=Path("/proc")):
    """Return LISTEN sockets owned by processes visible in this PID namespace."""
    sockets = {}
    for family, relative in (("ipv4", "net/tcp"), ("ipv6", "net/tcp6")):
        lines = (proc / relative).read_text().splitlines()
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "0A":
                continue
            address_raw, port_raw = fields[1].split(":", 1)
            inode = fields[9]
            sockets.setdefault(inode, []).append({
                "family": family,
                "address": decode_address(family, address_raw),
                "port": int(port_raw, 16),
                "inode": inode,
            })

    rows = []
    for process in sorted(proc.iterdir(), key=lambda path: path.name):
        if not process.name.isdigit():
            continue
        try:
            command = (process / "cmdline").read_bytes().rstrip(b"\0").replace(
                b"\0", b" ").decode("utf-8", "replace")
            descriptors = list((process / "fd").iterdir())
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            match = re.fullmatch(r"socket:\[([0-9]+)\]", target)
            if not match:
                continue
            for socket_row in sockets.get(match.group(1), ()):
                rows.append({"pid": int(process.name), "command": command,
                             **socket_row})
    unique = {(row["pid"], row["inode"], row["family"], row["address"], row["port"]): row
              for row in rows}
    return sorted(unique.values(), key=lambda row: (
        row["port"], row["family"], row["address"], row["pid"], row["inode"]))


def validate_listener_inventory(rows):
    require(isinstance(rows, list) and rows, "No emulator TCP listeners were observed")
    ports = set()
    for row in rows:
        require(isinstance(row, dict) and set(row) == {
                    "pid", "command", "family", "address", "port", "inode"} and
                type(row["pid"]) is int and row["pid"] > 0 and
                isinstance(row["command"], str) and row["command"] and
                row["family"] in {"ipv4", "ipv6"} and
                row["address"] in {"127.0.0.1", "::1"} and
                type(row["port"]) is int and row["port"] in EXPECTED_PORTS and
                isinstance(row["inode"], str) and row["inode"].isdigit(),
                "A container process exposed an unexpected TCP listener")
        ports.add(row["port"])
    require(ports == EXPECTED_PORTS,
            "The exact loopback console/ADB listener pair is not ready")
    return rows


def emulator_command(session_class, images: Path, userdata: Path):
    args = session_class.emulator_command(images, userdata)
    try:
        index = args.index("-port")
    except ValueError as error:
        raise RuntimeError("Pinned Session command lacks its reviewed -port option") from error
    require(args[index:index + 2] == ["-port", "5580"],
            "Pinned Session command changed its emulator port")
    args[index:index + 2] = ["-ports", "5580,5581"]
    args[args.index("-gpu") + 1] = "lavapipe"
    for feature in DISABLED_NETWORK_FEATURES:
        args.extend(["-feature", "-" + feature])
    args.append("-no-window")
    require("-grpc" not in args and "-port" not in args and
            args.count("-ports") == 1 and args[args.index("-ports") + 1] == "5580,5581",
            "Emulator command does not explicitly suppress the default gRPC path")
    return args


def validate_starting_state():
    require(STATE.is_dir() and not STATE.is_symlink(), "State bind is not a literal directory")
    names = sorted(path.name for path in STATE.iterdir())
    require(names == [".wonad-upstream-guest-owner"],
            "Fresh state contains an unexpected prelaunch entry")
    marker = STATE / names[0]
    node = marker.lstat()
    require(stat.S_ISREG(node.st_mode) and not marker.is_symlink() and
            node.st_size <= 4096, "State ownership marker is invalid")
    owner = json.loads(marker.read_text())
    require(owner.get("kind") == "wonad-phase1-upstream-guest-owner" and
            SHA256.fullmatch(str(owner.get("build_receipt_sha256", ""))) and
            owner.get("role") in {"baseline", "custom"},
            "State ownership marker is not authenticated")
    require(owner["role"] == os.environ.get("WONAD_BUILD_ROLE") and
            owner["build_receipt_sha256"] == os.environ.get("WONAD_BUILD_RECEIPT_SHA256"),
            "State ownership marker differs from launch environment")
    return owner


def wait_for_listeners(session, timeout=90):
    deadline = time.monotonic() + timeout
    last = []
    while time.monotonic() < deadline:
        session.check_children()
        last = proc_tcp_rows()
        if last:
            unexpected = [row for row in last if row["port"] not in EXPECTED_PORTS or
                          row["address"] not in {"127.0.0.1", "::1"}]
            require(not unexpected,
                    "Emulator/netsim/gRPC exposed an unnecessary TCP listener: " +
                    json.dumps(unexpected, sort_keys=True))
            if {row["port"] for row in last} == EXPECTED_PORTS:
                return validate_listener_inventory(last)
        time.sleep(0.1)
    raise RuntimeError("Timed out waiting for exact loopback console/ADB listeners: " +
                       json.dumps(last, sort_keys=True))


def main():
    sys.path.insert(0, "/opt/wonad")
    from session import (Session, prepare_avd, prepare_system_images,
                         prepare_userdata, validate_product)

    os.umask(0o077)
    owner = validate_starting_state()
    fingerprint = validate_product(PRODUCT)
    require(fingerprint == os.environ.get("WONAD_EXPECTED_FINGERPRINT"),
            "Mounted product fingerprint differs from authenticated receipt")
    for directory in ("emulator", "android", "tmp", "home", "runtime"):
        (STATE / directory).mkdir(mode=0o700)
    images = prepare_system_images(STATE, PRODUCT)
    prepare_avd(STATE, PRODUCT)
    userdata = prepare_userdata(STATE, PRODUCT)
    args = emulator_command(Session, images, userdata)
    os.environ["ANDROID_EMU_LAVAPIPE_GL_MODE_LLVMPIPE"] = "1"
    os.environ["WONAD_VIEWER_TRANSPORT"] = "headless"

    session = Session()
    signal.signal(signal.SIGTERM, session.stop)
    signal.signal(signal.SIGINT, session.stop)
    try:
        # Lavapipe still requires an EGL-capable X server.  This server is
        # private to the container and explicitly has no TCP transport.
        auth = STATE / "xauthority"
        fields = (b"", b"99", b"MIT-MAGIC-COOKIE-1", secrets.token_bytes(16))
        auth.write_bytes(struct.pack(">H", 65535) + b"".join(
            struct.pack(">H", len(field)) + field for field in fields))
        auth.chmod(0o600)
        os.environ.update({"DISPLAY": ":99", "XAUTHORITY": str(auth)})
        session.start("xvfb", ["Xvfb", ":99", "-screen", "0", "1280x1024x24",
                               "-nolisten", "tcp", "-auth", str(auth)])
        deadline = time.monotonic() + 15
        while not Path("/tmp/.X11-unix/X99").exists():
            session.check_children()
            require(time.monotonic() < deadline, "Private Xvfb did not start")
            time.sleep(0.1)
        emulator = session.start("emulator", args)
        listeners = wait_for_listeners(session)
        ready = {
            "schema": 1,
            "kind": "wonad-phase1-upstream-guest-bootstrap",
            "role": owner["role"],
            "build_receipt_sha256": owner["build_receipt_sha256"],
            "expected_fingerprint": fingerprint,
            "serial": "emulator-5580",
            "emulator_pid": emulator.pid,
            "emulator_argv": args,
            "network": {
                "namespace": "host-by-reviewed-launcher",
                "listeners": listeners,
                "allowed": ["127.0.0.1/::1:5580-console", "127.0.0.1/::1:5581-adb"],
                "grpc": "disabled-by-explicit--ports",
                "netsim_features": {feature: False for feature in DISABLED_NETWORK_FEATURES},
                "xvfb_tcp": False,
            },
            "policy": {
                "apk_install": False, "settings_write": False, "consent": False,
                "external_display": False,
            },
            "ready_monotonic_ns": time.monotonic_ns(),
        }
        write_json_new(READY, ready)
        while not session.stopping:
            session.check_children()
            # Fail if any child later opens an unreviewed TCP listener.
            validate_listener_inventory(proc_tcp_rows())
            time.sleep(0.5)
    finally:
        session.close()


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        try:
            if not os.path.lexists(ERROR):
                with ERROR.open("x") as stream:
                    traceback.print_exc(file=stream)
                    stream.flush()
                    os.fsync(stream.fileno())
        finally:
            raise
