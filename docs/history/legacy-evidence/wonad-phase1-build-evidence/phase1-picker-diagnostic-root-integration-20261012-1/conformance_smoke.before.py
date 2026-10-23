#!/usr/bin/env python3
"""Run the signed, policy-free v3 conformance APK against a real OS broker."""

import argparse
import json
import re
import secrets
import subprocess
import time
from pathlib import Path

PACKAGE = "org.wonad.desktop"
CONTROL = PACKAGE + "/.ConformanceControlActivity"
SERVICE = PACKAGE + "/.ConformanceService"
MARKER = "WONAD_CONFORMANCE_STATUS "
SYSTEMUI = "com.android.systemui"
TRANSFER_TITLE = "Wonad: Move from phone"
TRANSFER_PHASE = "wait-transfer-back"
PICKER_TIMEOUT = 15.0
PICKER_COMMAND_TIMEOUT = 3.0
PICKER_POLL_INTERVAL = 0.25


def parse_status(output: str) -> dict:
    rows = [line.split(MARKER, 1)[1] for line in output.splitlines() if MARKER in line]
    if not rows:
        raise ValueError("conformance service did not publish its dumpsys marker")
    value = json.loads(rows[-1])
    if value.get("schema") != 1 or value.get("state") not in {"idle", "running", "passed", "failed"}:
        raise ValueError("invalid conformance status schema")
    return value


def choose_display(output: str) -> int:
    displays = sorted({int(value) for value in re.findall(r"\bmDisplayId\s*=\s*(\d+)\b", output)})
    external = [value for value in displays if value > 0]
    if not external:
        raise ValueError("no non-default display is attached")
    return external[0]


def systemui_uid(output: str) -> int:
    # PackageManager filters by substring and therefore returns SystemUI RRO
    # packages too. Only the exact user-0 package line identifies its UID.
    matches = re.findall(r"^package:com\.android\.systemui uid:([1-9]\d*)$", output, re.M)
    if len(matches) != 1:
        raise ValueError("cannot identify the exact SystemUI package UID")
    return int(matches[0])


def _phone_focus_token(displays: str) -> str | None:
    headers = list(re.finditer(
        r"^[ \t]*Display: mDisplayId=(\d+)(?: \(organized\))?[ \t]*$", displays, re.M))
    phone = [index for index, match in enumerate(headers) if match.group(1) == "0"]
    if len(phone) != 1:
        return None
    index = phone[0]
    start = headers[index].end()
    end = headers[index + 1].start() if index + 1 < len(headers) else len(displays)
    section = displays[start:end]
    rows = re.findall(r"^[ \t]*mCurrentFocus=(.+?)[ \t]*$", section, re.M)
    if len(rows) != 1:
        return None
    focus = re.fullmatch(r"Window\{([0-9a-f]+) u(\d+) (.+)\}", rows[0])
    if focus is None or focus.group(2) != "0" or focus.group(3) != TRANSFER_TITLE:
        return None
    return focus.group(1)


def _window_blocks(windows: str) -> list[tuple[re.Match, str]]:
    headers = list(re.finditer(
        r"^[ \t]*Window #\d+ Window\{([0-9a-f]+) u(\d+) (.+)\}:[ \t]*$", windows, re.M))
    return [(match, windows[match.start():
            headers[index + 1].start() if index + 1 < len(headers) else len(windows)])
            for index, match in enumerate(headers)]


def focused_transfer_picker(displays: str, windows: str, uid: int) -> bool:
    """Recognize one drawn, focused, secure SystemUI phone transfer picker.

    ``dumpsys window windows`` has the global top-focused display but not this
    branch's per-display ``mCurrentFocus``. Join the exact native Window token
    from ``dumpsys window displays`` to its one full WindowState block.
    """
    if type(uid) is not int or uid <= 0:
        return False
    token = _phone_focus_token(displays)
    top = re.findall(r"^[ \t]*mTopFocusedDisplayId=(\d+)[ \t]*$", windows, re.M)
    matches = [(header, block) for header, block in _window_blocks(windows)
               if header.group(2) == "0" and header.group(3) == TRANSFER_TITLE]
    if token is None or top != ["0"] or len(matches) != 1:
        return False
    header, block = matches[0]
    if header.group(1) != token:
        return False
    attrs = re.findall(r"^[ \t]*mAttrs=(.*?)(?=^[ \t]*Requested w=)", block, re.M | re.S)
    return len(attrs) == 1 and all((
        re.search(r"^[ \t]*mDisplayId=0(?:[ \t]|$)", block, re.M),
        re.search(r"^[ \t]*mOwnerUid=" + str(uid) +
                  r"\b[^\n]*\bpackage=" + re.escape(SYSTEMUI) + r"(?=\s|$)", block, re.M),
        re.search(r"\bty=SYSTEM_DIALOG\b", attrs[0]),
        re.search(r"\bSECURE\b", attrs[0]),
        re.search(r"^[ \t]*mHasSurface=true\b", block, re.M),
        re.search(r"^[ \t]*Surface: shown=true[ \t]+mDrawState=HAS_DRAWN\b", block, re.M),
        re.search(r"^[ \t]*isOnScreen=true[ \t]*$", block, re.M),
        re.search(r"^[ \t]*isVisible=true[ \t]*$", block, re.M),
    ))


def _require_transfer_phase(status: dict, run: str) -> None:
    if (not isinstance(status, dict) or status.get("run") != run or
            status.get("state") != "running" or status.get("phase") != TRANSFER_PHASE):
        raise RuntimeError("conformance run left the exact transfer-picker phase")


def cancel_focused_transfer_picker(device, run: str, *, timeout: float = PICKER_TIMEOUT,
                                   command_timeout: float = PICKER_COMMAND_TIMEOUT,
                                   poll_interval: float = PICKER_POLL_INTERVAL,
                                   monotonic=time.monotonic, sleep=time.sleep) -> None:
    if not (timeout > 0 and command_timeout > 0 and poll_interval > 0):
        raise ValueError("transfer-picker polling bounds must be positive")
    deadline = monotonic() + timeout

    def bounded_timeout() -> float:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("secure focused SystemUI transfer picker did not appear")
        return min(command_timeout, remaining)

    uid = systemui_uid(device.shell(
        "cmd", "package", "list", "packages", "-U", "--user", "0", SYSTEMUI,
        timeout=bounded_timeout()))
    while monotonic() < deadline:
        before = device.status(timeout=bounded_timeout())
        _require_transfer_phase(before, run)
        displays = device.shell("dumpsys", "window", "displays", timeout=bounded_timeout())
        windows = device.shell("dumpsys", "window", "windows", timeout=bounded_timeout())
        after = device.status(timeout=bounded_timeout())
        _require_transfer_phase(after, run)
        if focused_transfer_picker(displays, windows, uid):
            device.shell("input", "keyboard", "-d", "0", "keyevent", "KEYCODE_ESCAPE",
                         timeout=bounded_timeout())
            return
        sleep(min(poll_interval, max(0.0, deadline - monotonic())))
    raise TimeoutError("secure focused SystemUI transfer picker did not appear")


class Device:
    def __init__(self, adb: str, serial: str | None):
        self.prefix = [adb] + (["-s", serial] if serial else [])

    def call(self, *args: str, timeout: int = 30) -> str:
        result = subprocess.run(self.prefix + list(args), text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout)
        if result.returncode:
            raise RuntimeError("adb command failed: " + " ".join(args) + "\n" + result.stdout)
        return result.stdout

    def shell(self, *args: str, timeout: int = 30) -> str:
        return self.call("shell", *args, timeout=timeout)

    def status(self, timeout: int | float = 30) -> dict:
        return parse_status(self.shell("dumpsys", "activity", "service", SERVICE,
                                       timeout=timeout))

    def instrument(self, run: str) -> subprocess.Popen:
        return subprocess.Popen(self.prefix + ["shell", "am", "instrument", "-w", "-r",
            "-e", "run", run, "-e", "mode", "full",
            PACKAGE + "/.ConformanceInstrumentation"], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--serial")
    parser.add_argument("--apk", type=Path, help="release-signed conformance APK to install with -r")
    parser.add_argument("--fixture-apk", type=Path, help="separately signed ordinary fixture APK")
    parser.add_argument("--display-id", type=int)
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()
    if args.display_id is not None and args.display_id <= 0:
        parser.error("--display-id must be a non-default display")
    device = Device(args.adb, args.serial)
    for apk in (args.fixture_apk, args.apk):
        if apk:
            if not apk.is_file():
                parser.error(f"APK does not exist: {apk}")
            device.call("install", "-r", str(apk), timeout=120)

    display = args.display_id or choose_display(device.shell("dumpsys", "display"))
    # Separate ordinary fixtures are the only managed application tasks. The
    # broker must exclude org.wonad.desktop itself from its snapshot.
    for activity in (".OneActivity", ".TwoActivity"):
        device.shell("am", "start", "--display", str(display), "-n", "org.wonad.fixture/" + activity)

    run = secrets.token_hex(16)
    instrument = device.instrument(run)
    deadline = time.monotonic() + args.timeout
    shortcut = False
    transfer = False
    last = None
    while time.monotonic() < deadline:
        try:
            status = device.status()
        except (RuntimeError, ValueError):
            if instrument.poll() is not None:
                output = instrument.communicate()[0]
                raise RuntimeError("conformance instrumentation exited before publishing status\n" + output)
            time.sleep(0.1)
            continue
        if status.get("run") not in (None, run):
            raise RuntimeError("dumpsys reported a different conformance run")
        summary = (status.get("state"), status.get("phase"))
        if summary != last:
            print(json.dumps(status, sort_keys=True), flush=True)
            last = summary
        if status.get("state") == "failed":
            instrument.terminate()
            raise RuntimeError(status.get("failure") or "conformance run failed")
        if status.get("state") == "passed":
            output = instrument.communicate(timeout=15)[0]
            if instrument.returncode != 0 or "INSTRUMENTATION_CODE: -1" not in output:
                raise RuntimeError("instrumentation did not confirm the passing dump\n" + output)
            print(json.dumps(status, sort_keys=True, indent=2))
            return 0
        phase = status.get("phase")
        if phase == "wait-shortcut" and not shortcut:
            # Restore genuine external focus after starting the phone control UI,
            # then inject the documented Ctrl+Meta+J chord on that exact display.
            device.shell("am", "start", "--display", str(display), "-n",
                         "org.wonad.fixture/.OneActivity")
            device.shell("input", "keyboard", "-d", str(display), "keycombination", "-t", "120",
                         "KEYCODE_CTRL_LEFT", "KEYCODE_META_LEFT", "KEYCODE_J")
            shortcut = True
        if phase == "wait-transfer-back" and not transfer:
            # Send the sole cancel only after WindowManager proves the exact
            # secure, drawn SystemUI dialog matches the observed phone focus.
            cancel_focused_transfer_picker(device, run)
            transfer = True
        time.sleep(0.25)
    instrument.kill()
    raise TimeoutError(f"conformance run {run} did not finish in {args.timeout}s")


if __name__ == "__main__":
    raise SystemExit(main())
