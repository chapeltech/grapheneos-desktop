#!/usr/bin/env python3
"""Run the signed, policy-free v3 conformance APK against a real OS broker."""

import argparse
import base64
import hashlib
import math
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


PICKER_DIAGNOSTIC_MARKER = "WONAD_PICKER_DIAGNOSTIC "


class PickerDiagnosticLimit(RuntimeError):
    pass


class PickerJournal:
    """Bound retained diagnostics, NOT subprocess capture peak RSS or Android execution."""
    def __init__(self, run, start, deadline, clock, *, emit=None, runner=None,
                 max_events=128, max_raw=512 * 1024, max_bytes=4 * 1024 * 1024):
        if (not isinstance(run, str) or not run or any(type(value) is not int or value <= 0
                for value in (max_events, max_raw, max_bytes)) or max_events < 4 or
                max_bytes < 4096):
            raise ValueError("invalid picker diagnostic bounds")
        self.run, self.start, self.deadline, self.clock = run, start, deadline, clock
        self.emit = emit or (lambda line: print(line, flush=True))
        self.runner = runner or subprocess.run
        self.max_events, self.max_raw, self.max_bytes = max_events, max_raw, max_bytes
        self.sequence = self.total = 0
        self.role, self.iteration = "uid", 0
        self.terminal_emitted = False

    def remaining(self):
        now = self.clock()
        if not math.isfinite(now) or now < self.start:
            raise ValueError("invalid/regressing picker monotonic clock")
        return now, self.deadline - now

    def record(self, kind, *, terminal=False, **fields):
        now, remaining = self.remaining()
        value = dict(schema=1, diagnostic="picker_raw_observation", sequence=self.sequence + 1,
                     run=self.run, kind=kind, started_monotonic=self.start,
                     observed_monotonic=now, deadline_monotonic=self.deadline,
                     remaining_seconds=remaining, role=self.role, iteration=self.iteration, **fields)
        line = PICKER_DIAGNOSTIC_MARKER + json.dumps(value, sort_keys=True,
                    separators=(",", ":"), allow_nan=False)
        size = len(line.encode()) + 1
        if (self.sequence >= self.max_events - (0 if terminal else 1) or
                self.total + size > self.max_bytes - (0 if terminal else 2048)):
            raise PickerDiagnosticLimit("picker diagnostic event/encoded-byte budget exhausted")
        self.emit(line)
        self.sequence += 1
        self.total += size
        if terminal:
            self.terminal_emitted = True

    def reserve_command(self):
        # Reserve worst allowed raw result + bounded metadata BEFORE another read/input.
        needed = 4 * ((self.max_raw + 2) // 3) + 8192
        if self.sequence + 3 >= self.max_events or self.total + needed > self.max_bytes - 2048:
            raise PickerDiagnosticLimit("insufficient journal budget before picker command")

    def raw_fields(self, raw):
        raw = raw if isinstance(raw, bytes) else (raw or "").encode()
        value = dict(raw_bytes=len(raw), raw_sha256=hashlib.sha256(raw).hexdigest())
        if len(raw) > self.max_raw:
            self.record("raw_limit", raw_retained=False, **value)
            raise PickerDiagnosticLimit("picker command raw output exceeded retention bound")
        value["raw_base64"] = base64.b64encode(raw).decode("ascii")
        value["raw_retained"] = True
        return value

    def call(self, argv, timeout):
        if (not isinstance(argv, list) or not argv or
                any(not isinstance(value, str) for value in argv)):
            raise ValueError("invalid picker command argv")
        self.reserve_command()
        started, remaining = self.remaining()
        if remaining <= 0:
            raise TimeoutError("secure focused SystemUI transfer picker did not appear")
        actual_timeout = min(timeout, remaining)
        self.record("command_start", argv=argv, command_started_monotonic=started,
                    requested_timeout_seconds=timeout, timeout_seconds=actual_timeout)
        # Journaling overhead counts against the SAME deadline, never grants a fresh timeout.
        _, remaining = self.remaining()
        if remaining <= 0:
            raise TimeoutError("secure focused SystemUI transfer picker did not appear")
        actual_timeout = min(actual_timeout, remaining)
        try:
            result = self.runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 timeout=actual_timeout)
        except subprocess.TimeoutExpired as error:
            try:
                self.record("command_end", argv=argv, command_started_monotonic=started,
                            timeout_seconds=actual_timeout, returncode=None, timed_out=True,
                            **self.raw_fields(error.output))
            except Exception:
                # Preserve the ORIGINAL timeout rather than hiding it under a retention failure.
                try:
                    self.record("timeout_partial_not_retained", argv=argv, timed_out=True)
                except Exception:
                    pass
            raise
        except BaseException as error:
            try:
                self.record("command_end", argv=argv, command_started_monotonic=started,
                            timeout_seconds=actual_timeout, returncode=None, timed_out=False,
                            command_exception_type=type(error).__name__, raw_available=False)
            except Exception:
                pass
            raise
        raw = result.stdout if isinstance(result.stdout, bytes) else (result.stdout or "").encode()
        original_error = None if result.returncode == 0 else RuntimeError(
            "adb command failed: " + " ".join(argv) + "\n" + raw.decode("utf-8", "replace"))
        try:
            self.record("command_end", argv=argv, command_started_monotonic=started,
                        timeout_seconds=actual_timeout, returncode=result.returncode, timed_out=False,
                        **self.raw_fields(raw))
        except Exception:
            if original_error is not None:
                try:
                    self.record("nonzero_raw_not_retained", argv=argv, returncode=result.returncode)
                except Exception:
                    pass
                raise original_error
            raise
        if original_error is not None:
            raise original_error
        # Same newline normalization as the original text=True subprocess path, AFTER raw sealing.
        return raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")

    def finish(self, error=None):
        if self.terminal_emitted:
            return
        fields = dict(result="completed" if error is None else "failed")
        if error is not None:
            message = str(error).encode("utf-8", "replace")
            fields.update(exception_type=type(error).__name__, exception_message=str(error)[:256],
                          exception_message_bytes=len(message),
                          exception_message_sha256=hashlib.sha256(message).hexdigest())
        self.record("terminal", terminal=True, **fields)


def picker_rejection_reasons(displays: str, windows: str, uid: int) -> list[str]:
    """Diagnostic classifier only; the UNCHANGED secure predicate remains the input authority."""
    reasons = []
    if type(uid) is not int or uid <= 0:
        reasons.append("invalid_systemui_uid")
    headers = list(re.finditer(
        r"^[ \t]*Display: mDisplayId=(\d+)(?: \(organized\))?[ \t]*$", displays, re.M))
    phone = [index for index, match in enumerate(headers) if match.group(1) == "0"]
    if len(phone) != 1:
        reasons.append("phone_display_absent_or_ambiguous")
    token = _phone_focus_token(displays)
    if token is None:
        reasons.append("phone_focus_absent_ambiguous_wrong_user_or_title")
    top = re.findall(r"^[ \t]*mTopFocusedDisplayId=(\d+)[ \t]*$", windows, re.M)
    if top != ["0"]:
        reasons.append("global_top_focus_not_unique_phone0")
    matches = [(header, block) for header, block in _window_blocks(windows)
               if header.group(2) == "0" and header.group(3) == TRANSFER_TITLE]
    if len(matches) != 1:
        reasons.append("picker_window_absent_or_ambiguous")
        return reasons
    header, block = matches[0]
    if header.group(1) != token:
        reasons.append("phone_focus_window_token_mismatch")
    attrs = re.findall(r"^[ \t]*mAttrs=(.*?)(?=^[ \t]*Requested w=)", block, re.M | re.S)
    if len(attrs) != 1:
        reasons.append("window_attributes_absent_or_ambiguous")
    else:
        for name, pattern in (("not_system_dialog", r"\bty=SYSTEM_DIALOG\b"),
                              ("not_secure", r"\bSECURE\b")):
            if re.search(pattern, attrs[0]) is None:
                reasons.append(name)
    for name, pattern in (
        ("window_not_phone0", r"^[ \t]*mDisplayId=0(?:[ \t]|$)"),
        ("wrong_systemui_owner_uid_or_package", r"^[ \t]*mOwnerUid=" + str(uid) +
            r"\b[^\n]*\bpackage=" + re.escape(SYSTEMUI) + r"(?=\s|$)"),
        ("no_surface", r"^[ \t]*mHasSurface=true\b"),
        ("not_shown_and_drawn", r"^[ \t]*Surface: shown=true[ \t]+mDrawState=HAS_DRAWN\b"),
        ("not_on_screen", r"^[ \t]*isOnScreen=true[ \t]*$"),
        ("not_visible", r"^[ \t]*isVisible=true[ \t]*$"),
    ):
        if re.search(pattern, block, re.M) is None:
            reasons.append(name)
    return reasons


def cancel_focused_transfer_picker(device, run: str, *, timeout: float = PICKER_TIMEOUT,
                                   command_timeout: float = PICKER_COMMAND_TIMEOUT,
                                   poll_interval: float = PICKER_POLL_INTERVAL,
                                   monotonic=time.monotonic, sleep=time.sleep,
                                   diagnostic_emit=None, diagnostic_runner=None,
                                   diagnostic_bounds=None) -> None:
    if (any(type(value) not in {int, float} or not math.isfinite(value) or value <= 0
            for value in (timeout, command_timeout, poll_interval))):
        raise ValueError("transfer-picker polling bounds must be positive")
    start = monotonic()
    if not math.isfinite(start) or start < 0:
        raise ValueError("invalid picker monotonic start")
    deadline = start + timeout
    if not math.isfinite(deadline):
        raise ValueError("invalid picker deadline")
    journal = PickerJournal(run, start, deadline, monotonic, emit=diagnostic_emit,
                            runner=diagnostic_runner, **(diagnostic_bounds or {}))
    absent = object()
    previous = getattr(device, "_picker_diagnostics", absent)
    device._picker_diagnostics = journal
    error = None
    try:
        journal.record("begin", picker_timeout_seconds=timeout,
                       per_command_cap_seconds=command_timeout)

        def bounded_timeout() -> float:
            _, remaining = journal.remaining()
            if remaining <= 0:
                raise TimeoutError("secure focused SystemUI transfer picker did not appear")
            return min(command_timeout, remaining)

        uid = systemui_uid(device.shell(
            "cmd", "package", "list", "packages", "-U", "--user", "0", SYSTEMUI,
            timeout=bounded_timeout()))
        journal.record("systemui_identity", uid=uid)
        while monotonic() < deadline:
            journal.iteration += 1
            journal.role = "before_status"
            before = device.status(timeout=bounded_timeout())
            journal.record("parsed_status", value=before)
            _require_transfer_phase(before, run)
            journal.role = "window_displays"
            displays = device.shell("dumpsys", "window", "displays", timeout=bounded_timeout())
            journal.role = "window_windows"
            windows = device.shell("dumpsys", "window", "windows", timeout=bounded_timeout())
            journal.role = "after_status"
            after = device.status(timeout=bounded_timeout())
            journal.record("parsed_status", value=after)
            _require_transfer_phase(after, run)
            ready = focused_transfer_picker(displays, windows, uid)
            reasons = picker_rejection_reasons(displays, windows, uid)
            if ready != (reasons == []):
                raise RuntimeError("picker diagnostic classifier disagrees with unchanged secure predicate")
            journal.record("predicate", ready=ready, rejection_reasons=reasons)
            if ready:
                journal.role = "sole_escape"
                journal.reserve_command()
                journal.record("decision", action="authorize_sole_display0_escape")
                device.shell("input", "keyboard", "-d", "0", "keyevent", "KEYCODE_ESCAPE",
                             timeout=bounded_timeout())
                return
            sleep(min(poll_interval, max(0.0, deadline - monotonic())))
        raise TimeoutError("secure focused SystemUI transfer picker did not appear")
    except BaseException as failure:
        error = failure
        raise
    finally:
        if previous is absent:
            del device._picker_diagnostics
        else:
            device._picker_diagnostics = previous
        try:
            journal.finish(error)
        except Exception:
            if error is None:
                raise
            # Diagnostic final-emission failure must never erase the primary command/predicate error.

class Device:
    def __init__(self, adb: str, serial: str | None):
        self.prefix = [adb] + (["-s", serial] if serial else [])

    def call(self, *args: str, timeout: int = 30) -> str:
        journal = getattr(self, "_picker_diagnostics", None)
        if journal is not None:
            return journal.call(self.prefix + list(args), timeout)
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
