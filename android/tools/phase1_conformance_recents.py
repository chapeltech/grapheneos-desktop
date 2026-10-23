#!/usr/bin/env python3
"""Produce sealed Phase-1 Recents evidence with the policy-free client.

This host orchestrator joins one already-booted fresh conformance candidate
container after the conformance and ordinary fixture APKs have been installed
and consented.  It creates its own conformance instrumentation run, attaches
three mixed emulator displays, and drives only ordinary Launcher/Recents UI,
keyboard/mouse input and emulator hotplug.  It never invokes an Android task
move/remove API, writes secure settings, or calls the private Wonad service.

The independent auditor reconstructs all claims from the sealed raw evidence;
the producer's final ``passed`` value is not trusted.
"""
from __future__ import annotations

import argparse
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

import phase1_conformance_recents_acceptance as acceptance


SERIAL = acceptance.SERIAL
APP = acceptance.APP
FIXTURE = acceptance.FIXTURE
SERVICE = APP + "/.ConformanceService"
INSTRUMENTATION = APP + "/.ConformanceInstrumentation"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value) -> bytes:
    return acceptance.canonical(value)


def write_new(path: Path, payload: bytes):
    require(path.parent.is_dir() and not path.exists() and not path.is_symlink(),
            "Refusing to overwrite evidence: " + str(path))
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def failed_file_ref(path: Path, maximum: int = 128 * 1024 * 1024) -> dict:
    """Bind an honest, possibly empty failed stream; never used for PASS evidence."""
    require(path.is_absolute() and type(maximum) is int and maximum > 0,
            "Invalid failed-only evidence path or bound")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not path.is_symlink() and
            path.resolve(strict=True) == path and 0 <= before.st_size <= maximum,
            "Invalid failed-only evidence file: " + str(path))
    fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    identity = lambda value: tuple(getattr(value, key) for key in fields)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode) and
                identity(before) == identity(os.fstat(stream.fileno())),
                "Failed-only evidence changed before read: " + str(path))
        payload = stream.read(maximum + 1)
        after_fd = os.fstat(stream.fileno())
        after_path = path.lstat()
        require(len(payload) == before.st_size and len(payload) <= maximum and
                identity(before) == identity(after_fd) == identity(after_path),
                "Failed-only evidence changed while being read: " + str(path))
    return {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}


class Producer:
    def __init__(self, container: str, image: str, boot_id: str, fingerprint: str,
                 output: Path, timeout: int):
        require(re.fullmatch(r"[0-9a-f]{64}", container) and
                acceptance.IMAGE_ID.fullmatch(image) and acceptance.BOOT_ID.fullmatch(boot_id),
                "Exact container/image/boot identities are required")
        require(isinstance(fingerprint, str) and fingerprint and "\n" not in fingerprint,
                "Exact build fingerprint is required")
        require(30 <= timeout <= 600, "Per-transition timeout must be 30..600 seconds")
        self.container = container
        self.image = image
        self.boot_id = boot_id
        self.fingerprint = fingerprint
        self.output = output
        self.timeout = timeout
        self.run = secrets.token_hex(16)
        self.conformance_run = secrets.token_hex(16)
        self.initial_nonce = secrets.token_hex(16)
        self.trace = []
        self.stages = []
        self.instrument = None
        self.instrument_file = None
        self.background_cleanup = None
        self.instrument_path = output / "identity" / "instrumentation.txt"
        self.candidate = None
        self.privileged_packages = None

    def _record(self, row):
        row = {"sequence": len(self.trace), **row}
        self.trace.append(row)
        return row

    def command(self, argv, *, timeout=60, allowed=(0,), evidence=None, binary=False):
        argv = list(map(str, argv))
        started = time.monotonic_ns()
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout, text=not binary)
        payload = result.stdout if binary else result.stdout.encode()
        row = {"kind": "command", "argv": argv, "returncode": result.returncode,
               "started_monotonic_ns": started, "ended_monotonic_ns": time.monotonic_ns()}
        if evidence is None:
            row["output"] = result.stdout.decode(errors="replace") if binary else result.stdout
        else:
            path = self.output / evidence
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_new(path, payload)
            row.update(evidence=evidence, output_sha256=hashlib.sha256(payload).hexdigest())
        self._record(row)
        require(result.returncode in allowed,
                "Command failed (%d): %s\n%s" % (result.returncode, " ".join(argv),
                 payload.decode(errors="replace")))
        return payload if binary else result.stdout.strip()

    def docker(self, *args, **kwargs):
        return self.command(["docker", *args], **kwargs)

    def adb(self, *args, **kwargs):
        return self.docker("exec", self.container, "adb", "-s", SERIAL, *args, **kwargs)

    def shell(self, *args, **kwargs):
        return self.adb("shell", *args, **kwargs)

    def read(self, relative, *shell_args, timeout=60):
        return self.shell(*shell_args, timeout=timeout, evidence=relative)

    def wait(self, label, action, timeout=None):
        deadline = time.monotonic() + (timeout or self.timeout)
        last = None
        while time.monotonic() < deadline:
            try:
                value = action()
                if value:
                    return value
            except (ValueError, acceptance.EvidenceError, json.JSONDecodeError) as error:
                last = error
            time.sleep(.25)
        raise TimeoutError(label + " did not settle" + (": " + str(last) if last else ""))

    def inspect_container(self):
        raw = self.docker("container", "inspect", self.container)
        rows = json.loads(raw, object_pairs_hook=acceptance.strict_object)
        require(len(rows) == 1 and rows[0].get("Id") == self.container and
                rows[0].get("Image") == self.image and rows[0].get("State", {}).get("Running") is True and
                rows[0].get("HostConfig", {}).get("NetworkMode") == "none" and
                rows[0].get("HostConfig", {}).get("Privileged") is False and
                "ALL" in rows[0].get("HostConfig", {}).get("CapDrop", []) and
                any(str(item).startswith("no-new-privileges")
                    for item in rows[0].get("HostConfig", {}).get("SecurityOpt", [])) and
                not any(mount.get("Destination") == "/opt/wonad" or
                        str(mount.get("Destination", "")).startswith("/opt/wonad/")
                        for mount in rows[0].get("Mounts", [])),
                "Selected container is not the exact isolated running candidate")
        self.docker("exec", self.container, "cat", "/opt/wonad/manifest.json")
        manifest_raw = self.trace[-1]["output"]
        self.candidate = acceptance.candidate_manifest(manifest_raw, self.fingerprint)
        bundle_paths = ["/opt/wonad/manifest.json", *acceptance.BUNDLED_APKS.values()]
        bundle_hashes = acceptance.sha256sum_output(
            self.docker("exec", self.container, "sha256sum", *bundle_paths), bundle_paths)
        require(bundle_hashes["/opt/wonad/manifest.json"] ==
                    hashlib.sha256(manifest_raw.encode()).hexdigest() and
                all(bundle_hashes[path] == self.candidate["artifacts"][
                    "conformance" if package == APP else "fixture"]["sha256"]
                    for package, path in acceptance.BUNDLED_APKS.items()),
                "Candidate manifest/APK root filesystem bytes changed")
        require(self.shell("cat", "/proc/sys/kernel/random/boot_id") == self.boot_id and
                self.shell("getprop", "ro.build.fingerprint") == self.fingerprint and
                self.shell("getprop", "sys.boot_completed") == "1" and
                self.shell("getenforce") == "Enforcing" and
                self.shell("am", "get-current-user") == "0",
                "Running guest differs from the selected boot/build/user/enforcement identity")
        for package, role in ((APP, "conformance"), (FIXTURE, "fixture")):
            values = self.shell("pm", "path", package).splitlines()
            require(len(values) == 1 and values[0].startswith("package:/"),
                    "Required fresh conformance artifact is absent: " + package)
            installed = values[0].removeprefix("package:")
            hashes = acceptance.sha256sum_output(self.shell("sha256sum", installed), [installed])
            require(hashes[installed] == self.candidate["artifacts"][role]["sha256"],
                    "Installed package bytes differ from bundled candidate: " + package)
        self.privileged_packages = {}
        system_image = self.candidate["product_images"][acceptance.SYSTEM_IMAGE]
        for package, path in acceptance.PRIVILEGED_SYSTEM_PACKAGES.items():
            observed_path = acceptance.active_system_package_path(
                self.shell("pm", "path", package), package)
            require(observed_path == path, "Active privileged package path changed")
            hashes = acceptance.sha256sum_output(self.shell("sha256sum", path), [path])
            if package == acceptance.SYSTEMUI:
                require(hashes[path] == self.candidate["os_artifacts"][acceptance.SYSTEMUI],
                        "Running SystemUI bytes differ from candidate")
            self.privileged_packages[package] = {"path": path, "sha256": hashes[path],
                "system_image_sha256": system_image, "active_system_package": True}
        for role, path in acceptance.OS_GUEST_PATHS.items():
            if role == acceptance.SYSTEMUI:
                continue
            hashes = acceptance.sha256sum_output(self.shell("sha256sum", path), [path])
            require(hashes[path] == self.candidate["os_artifacts"][role],
                    "Running guest OS artifact differs from candidate: " + role)
        changes = self.docker("container", "diff", self.container).splitlines()
        require(not any(re.fullmatch(r"[ACD] /opt/wonad(?:/.*)?", line) for line in changes),
                "Candidate /opt/wonad root filesystem changed after image creation")
        require(self.shell("settings", "--user", "0", "get", "secure",
                           "wonad_external_desktop_enabled") == "1",
                "Wonad consent must already be enabled by the enclosing genuine-UI lane")
        # A dedicated run starts from no prior client session or external display.
        status = acceptance.inactive_conformance_status(
            self.shell("dumpsys", "activity", "service", SERVICE))
        displays = acceptance.logical_displays(self.shell("dumpsys", "display"))
        require(not displays, "Dedicated Recents run requires no pre-existing external display")

    def package_identities(self):
        path = "identity/package-uids.txt"
        # Scope every lookup to the already-proved active owner user.  The
        # reverse reads prove that each ordinary client UID belongs to exactly
        # one installed package rather than a shared/special identity.
        rows, inputs, uids = [], [], {}
        for package in (APP, FIXTURE, acceptance.LAUNCHER, acceptance.SYSTEMUI):
            self.shell("cmd", "package", "list", "packages", "-U",
                       "--user", 0, package)
            inputs.append(len(self.trace) - 1)
            # Use the journaled raw bytes, not shell()'s stripped return; the
            # positional PackageManager filter also returns overlay packages.
            exact = acceptance.package_manager_uid_row(self.trace[-1]["output"], package)
            rows.append(exact)
            uids[package] = int(exact.rsplit(":", 1)[1])
        require(all(acceptance.FIRST_APPLICATION_UID <= uids[package] <=
                    acceptance.LAST_APPLICATION_UID for package in (APP, FIXTURE)) and
                len(set(uids.values())) == len(uids),
                "Client/fixture lacks a distinct ordinary active-user application UID")
        for package in (APP, FIXTURE):
            output = self.shell("cmd", "package", "list", "packages", "-U",
                                "--user", 0, "--uid", uids[package])
            inputs.append(len(self.trace) - 1)
            require(output.splitlines() == [rows[(APP, FIXTURE,
                    acceptance.LAUNCHER, acceptance.SYSTEMUI).index(package)]],
                    "Client/fixture UID is shared or not owned by the exact package")
        payload = ("\n".join(rows) + "\n").encode()
        target = self.output / path
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_new(target, payload)
        # The combine operation is explicit evidence construction, not a guest
        # observation.  The auditor rechecks all forward and reverse commands.
        self._record({"kind": "derived", "inputs": inputs, "evidence": path,
                      "output_sha256": hashlib.sha256(payload).hexdigest()})
        return acceptance.package_uids(payload.decode())

    def protected_processes(self):
        result = {}
        for name in ("system_server", acceptance.SYSTEMUI, acceptance.LAUNCHER):
            raw_pid = self.shell("pidof", name)
            require(re.fullmatch(r"[1-9][0-9]*", raw_pid) is not None,
                    "Missing/ambiguous protected process: " + name)
            pid = int(raw_pid)
            raw_stat = self.shell("su", "0", "cat", "/proc/%d/stat" % pid)
            match = re.fullmatch(r"([1-9][0-9]*) \(.*\) [A-Z] (.+)\n?", raw_stat)
            fields = match[2].split() if match is not None else []
            require(match is not None and int(match[1]) == pid and len(fields) > 18 and
                    re.fullmatch(r"[1-9][0-9]*", fields[18]) is not None,
                    "Malformed protected process epoch: " + name)
            result[name] = {"pid": pid, "start_ticks": int(fields[18])}
        return result

    def displays(self):
        return acceptance.logical_displays(self.shell("dumpsys", "display"))

    def attach(self, slot):
        width, height, density = acceptance.DISPLAY_SPECS[slot]
        raw = self.adb("emu", "multidisplay", "add", slot, width, height, density, 132165)
        require("OK" in raw and "KO:" not in raw, "Could not attach emulator slot " + str(slot))
        return self.wait("connector slot " + str(slot), lambda: next((row for row in self.displays().values()
            if row["slot"] == slot), None))

    def detach(self, slot):
        raw = self.adb("emu", "multidisplay", "del", slot)
        require("OK" in raw and "KO:" not in raw, "Could not detach emulator slot " + str(slot))
        return self.wait("connector removal " + str(slot),
                         lambda: not any(row["slot"] == slot for row in self.displays().values()))

    def fixture(self):
        raw = self.shell("dumpsys", "activity", FIXTURE)
        return acceptance.fixture_records(raw)[0]

    @staticmethod
    def remaining_timeout(deadline_ns, maximum=30):
        require(type(deadline_ns) is int and deadline_ns > 0,
                "Invalid phone Overview deadline")
        remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            raise TimeoutError("Phone focus/Overview sequence exhausted its bounded deadline")
        return min(maximum, remaining)

    def hierarchy(self, evidence=None, *, deadline_ns=None):
        remote = "/data/local/tmp/wonad-phase1-recents-" + secrets.token_hex(8) + ".xml"
        def timeout():
            return 60 if deadline_ns is None else self.remaining_timeout(deadline_ns)
        try:
            self.shell("uiautomator", "dump", remote, timeout=timeout())
            return self.adb("exec-out", "cat", remote, evidence=evidence, timeout=timeout())
        finally:
            self.shell("rm", "--", remote, allowed=(0, 1), timeout=timeout())

    def start_instrumentation(self, first, second):
        # Two ordinary fixture tasks seed the initial broker catalogue.  They
        # are setup, not the tasks whose Recents transfers are claimed.
        for display, activity in ((first, ".OneActivity"), (second, ".TwoActivity")):
            self.shell("am", "start", "-W", "--display", display, "-n", FIXTURE + "/" + activity)
        self.instrument_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(not self.instrument_path.exists(), "Instrumentation evidence already exists")
        self.instrument_file = self.instrument_path.open("xb")
        argv = ["docker", "exec", self.container, "adb", "-s", SERIAL, "shell", "am", "instrument",
                "-w", "-r", "-e", "run", self.conformance_run, "-e", "mode", "runtime",
                "-e", "nonce", self.initial_nonce, "-e", "phase", "start", INSTRUMENTATION]
        identity = "instrumentation-" + self.conformance_run
        self._record({"kind": "background_start", "id": identity, "argv": argv,
                      "started_monotonic_ns": time.monotonic_ns()})
        self.instrument = subprocess.Popen(argv, stdout=self.instrument_file, stderr=subprocess.STDOUT)
        return self.wait("policy-free runtime readiness", self.wait_runtime_ready, timeout=180)

    def status(self):
        return acceptance.runtime_status(self.shell("dumpsys", "activity", "service", SERVICE))

    def wait_runtime_ready(self):
        value = self.status()
        if value.get("state") == "failed":
            raise ValueError("Conformance runtime failed before Recents: " + str(value.get("failure")))
        handshake = value.get("handshake")
        snapshot = value.get("snapshot") or {}
        if value.get("run") == self.conformance_run and value.get("state") == "ready" and \
                value.get("runtime_readiness") == {
                    "ready": True, "session_open": True, "reopen_required": False} and \
                handshake == {"nonce": self.initial_nonce, "phase": "start", "result": "accepted"} and \
                sorted(row["display_id"] for row in snapshot.get("display_incarnations", [])) == \
                sorted(self.displays()):
            return value
        return False

    def runtime_command(self, phase):
        require(phase in {"checkpoint", "copy-observed", "stop"},
                "Unsupported policy-free runtime phase")
        if phase != "stop":
            self.wait("runtime topology settlement", self.runtime_topology_ready, timeout=120)
        nonce = secrets.token_hex(16)
        raw = self.shell("dumpsys", "activity", "service", SERVICE,
                         "runtime-command", self.conformance_run, nonce, phase)
        marker = "WONAD_CONFORMANCE_CONTROL accepted %s %s %s" % (
            self.conformance_run, nonce, phase)
        require(sum(line.strip() == marker for line in raw.splitlines()) == 1,
                "Runtime rejected exact host handshake")
        def accepted():
            value = self.status()
            require(value.get("run") == self.conformance_run,
                    "Runtime status switched to another run")
            handshake = value.get("handshake")
            if handshake == {"nonce": nonce, "phase": phase, "result": "rejected"}:
                raise ValueError(value.get("control_error") or "Runtime instruction rejected")
            if handshake != {"nonce": nonce, "phase": phase, "result": "accepted"}:
                return False
            if phase == "stop":
                return value if value.get("state") == "stopped" else False
            return value if value.get("state") == "ready" and value.get("runtime_readiness") == {
                "ready": True, "session_open": True, "reopen_required": False} else False
        return self.wait("runtime " + phase + " acknowledgement", accepted, timeout=120)

    def runtime_topology_ready(self):
        value = self.status()
        snapshot = value.get("snapshot") or {}
        actual = sorted(row["display_id"] for row in snapshot.get("display_incarnations", []))
        return value if value.get("state") == "ready" and value.get("runtime_readiness") == {
            "ready": True, "session_open": True, "reopen_required": False} and \
            actual == sorted(self.displays()) else False

    def runtime_topology_blocked(self):
        value = self.status()
        snapshot = value.get("snapshot") or {}
        rows = snapshot.get("display_incarnations", [])
        actual = sorted(row["display_id"] for row in rows)
        generation = snapshot.get("generation")
        return value if value.get("state") == "running" and value.get("phase") == "syncing-shells" and \
            value.get("runtime_readiness") == {
                "ready": False, "session_open": True, "reopen_required": False} and \
            snapshot.get("interaction_blocked") is True and type(generation) is int and \
            all(row.get("shell_generation") == generation for row in rows) and \
            actual == sorted(self.displays()) else False

    def runtime_task_ready(self, component, display):
        value = self.runtime_topology_ready()
        if not value:
            return False
        record = self.fixture().get(component)
        if record is None or record.get("display") != display:
            return False
        snapshot = value["snapshot"]
        display_tokens = {row["display_id"]: row["token"]
                          for row in snapshot["display_incarnations"]}
        rows = [row for row in snapshot["tasks"] if row["package_name"] == FIXTURE and
                row["title"] == acceptance.TASK_TITLES.get(component) and row["visible"] is True and
                row["input_enabled"] is True and
                row["display_token"] == display_tokens.get(display) and
                row["bounds"] == [record[name] for name in ("left", "top", "right", "bottom")]]
        return value if len(rows) == 1 else False

    def finish_instrumentation(self):
        terminal = self.runtime_command("stop")
        try:
            returncode = self.instrument.wait(timeout=30)
        except subprocess.TimeoutExpired as error:
            raise TimeoutError("Instrumentation did not exit after terminal service state") from error
        self.instrument_file.flush(); os.fsync(self.instrument_file.fileno()); self.instrument_file.close()
        self.instrument_file = None
        payload = acceptance.stable_bytes(self.instrument_path)
        self._record({"kind": "background_finish", "id": "instrumentation-" + self.conformance_run,
            "returncode": returncode, "ended_monotonic_ns": time.monotonic_ns(),
            "evidence": "identity/instrumentation.txt", "output_sha256": hashlib.sha256(payload).hexdigest()})
        self.instrument = None
        require(returncode == 0, "Runtime instrumentation did not exit cleanly")
        return terminal

    def home(self):
        self.shell("input", "keyboard", "-d", 0, "keyevent", "KEYCODE_HOME")

    def enter_phone_overview(self, stage_name):
        """One normal phone focus tap and one toggle; never retry a toggle or guess a card."""
        require(stage_name in acceptance.SELECTION_STAGES or stage_name == "task_remove_card",
                "Unexpected phone Overview stage")
        prefix = "phone-overview/" + stage_name + "/"
        deadline = time.monotonic_ns() + acceptance.PHONE_OVERVIEW_TIMEOUT_NS
        def read(relative, *command):
            return self.read(prefix + relative, *command, timeout=self.remaining_timeout(deadline))
        def input_command(*command):
            return self.shell("input", *command, timeout=self.remaining_timeout(deadline))
        def pause():
            time.sleep(self.remaining_timeout(deadline, maximum=.25))
        resolved = read("resolve.txt", *acceptance.PHONE_HOME_RESOLVE)
        require(resolved == acceptance.PHONE_HOME_COMPONENT,
                "The normal phone HOME does not resolve to the pinned Launcher")
        # Use the exact first command's recorded start as the authoritative
        # epoch, not an unreported timestamp taken after HOME or a slow read.
        deadline = self.trace[-1]["started_monotonic_ns"] + acceptance.PHONE_OVERVIEW_TIMEOUT_NS
        input_command("keyboard", "-d", 0, "keyevent", "KEYCODE_HOME")
        point = None
        for attempt in range(acceptance.PHONE_OVERVIEW_ATTEMPTS):
            xml = self.hierarchy(evidence=prefix + "home-%02d.xml" % attempt, deadline_ns=deadline)
            try:
                point = acceptance.phone_home_workspace(xml)
                break
            except acceptance.EvidenceError:
                if attempt + 1 == acceptance.PHONE_OVERVIEW_ATTEMPTS or time.monotonic_ns() >= deadline:
                    raise
                pause()
        require(point is not None, "Normal phone Home did not settle")
        # Retain the previously-unobserved routing chronology, even when the
        # ordinary pointer event or subsequent focus/readiness check fails.
        for kind, command in (("activities", ("activity", "activities")),
                              ("displays", ("window", "displays")),
                              ("windows", ("window", "windows"))):
            read("before-" + kind + ".txt", "dumpsys", *command)
        input_command("mouse", "-d", 0, "tap", *point)
        for attempt in range(acceptance.PHONE_OVERVIEW_ATTEMPTS):
            raw = [read("focus-%02d-%s.txt" % (attempt, kind), "dumpsys", *command)
                   for kind, command in (("activities", ("activity", "activities")),
                                         ("displays", ("window", "displays")),
                                         ("windows", ("window", "windows")))]
            try:
                acceptance.phone_home_focus(*raw)
                break
            except acceptance.EvidenceError:
                if attempt + 1 == acceptance.PHONE_OVERVIEW_ATTEMPTS or time.monotonic_ns() >= deadline:
                    raise
                pause()
        before_tis = read("before-tis.txt", *acceptance.PHONE_TIS_DUMP)
        acceptance.phone_tis_state(before_tis)
        self.shell(*acceptance.PHONE_OVERVIEW_LOG, timeout=self.remaining_timeout(deadline))
        self.remaining_timeout(deadline)
        input_command("keyboard", "-d", 0, "keyevent", "KEYCODE_APP_SWITCH")
        after_switch = [read("after-switch-" + kind + ".txt", "dumpsys", *command)
                        for kind, command in (("activities", ("activity", "activities")),
                                              ("displays", ("window", "displays")),
                                              ("windows", ("window", "windows")))]
        require(acceptance.focused_display(after_switch[2]) == 0,
                "Phone Overview toggle moved native global focus away from display 0")
        after_tis = read("after-switch-tis.txt", *acceptance.PHONE_TIS_DUMP)
        acceptance.phone_tis_state(after_tis)
        self.shell(*acceptance.PHONE_OVERVIEW_LOG, timeout=self.remaining_timeout(deadline))
        for attempt in range(acceptance.PHONE_OVERVIEW_ATTEMPTS):
            xml = self.hierarchy(evidence=prefix + "overview-%02d.xml" % attempt, deadline_ns=deadline)
            try:
                acceptance.phone_overview(xml)
                self.remaining_timeout(deadline)
                return xml
            except acceptance.EvidenceError:
                if attempt + 1 == acceptance.PHONE_OVERVIEW_ATTEMPTS or time.monotonic_ns() >= deadline:
                    raise
                pause()

    def launch_phone(self, component, stage_name, launch_index=0):
        require(stage_name in acceptance.LAUNCH_PLAN and
                acceptance.LAUNCH_PLAN[stage_name][launch_index] == component,
                "Unexpected ordinary Launcher launch plan")
        require(component not in self.fixture(),
                "Scenario component already existed before its ordinary Launcher launch")
        label = acceptance.LABELS[component]
        self.home()
        self.shell("input", "keyboard", "-d", 0, "keyevent", "KEYCODE_ALL_APPS")
        found = None
        for attempt in range(8):
            xml = self.hierarchy()
            try:
                found = acceptance.launcher_icon(xml, label)
                break
            except acceptance.EvidenceError:
                if attempt == 7:
                    raise
                self.shell("input", "touchscreen", "-d", 0, "swipe", 540, 2050, 540, 650, 450)
        ordinal = acceptance.STAGES.index(stage_name)
        evidence = "launches/%02d-%s-%d.xml" % (ordinal, stage_name, launch_index)
        # Re-read and seal the stable drawer before deriving the actual tap;
        # the auditor rejects an inline label or an unbound coordinate.
        xml = self.hierarchy(evidence=evidence)
        found = acceptance.launcher_icon(xml, label)
        self.shell("input", "touchscreen", "-d", 0, "tap", *found)
        return self.wait("phone task " + component, lambda:
            self.fixture().get(component) if self.fixture().get(component, {}).get("display") == 0 else False)

    def open_menu(self, component, stage_name, *, send=True, trace_start=None):
        # The runtime checkpoint must precede Recents: the genuine protected
        # phone UI intentionally publishes interactionBlocked=true, at which
        # point a checkpoint is correctly rejected rather than acknowledged.
        if send:
            self.runtime_command("checkpoint")
        self.enter_phone_overview(stage_name)
        label = acceptance.RECENTS_LABELS[component]
        centered = None
        for attempt in range(12):
            value = self.hierarchy()
            acceptance.phone_overview(value)
            try:
                centered = value, acceptance.recents_card(value, label)[0]
                break
            except acceptance.EvidenceError:
                if attempt == 11:
                    raise
                time.sleep(.25)
        require(centered is not None, "Recents card did not settle: " + component)
        selection = "selections/%02d-%s.xml" % (len(self.stages), stage_name)
        selection_start = len(self.trace) if trace_start is None else trace_start
        xml = self.hierarchy(evidence=selection)
        acceptance.phone_overview(xml)
        chip = acceptance.recents_card(xml, label)[0]
        self.shell("input", "touchscreen", "-d", 0, "tap", *chip)
        def ready():
            value = self.hierarchy()
            acceptance.launcher_control(value, "Screenshot")
            acceptance.launcher_control(value, "Split screen")
            point = acceptance.launcher_control(value, "Send to Wonad", required=send)
            if not send:
                require(point is None, "Unavailable menu still exposes Send to Wonad")
            return value
        self.wait("Recents task menu " + component, ready)
        return {"path": selection, "trace_start": selection_start}

    def focus_slot(self, slot):
        row = next(value for value in self.displays().values() if value["slot"] == slot)
        self.shell("input", "mouse", "-d", row["display"], "tap",
                   row["width"] // 2, row["height"] // 2)
        self.wait("external focus slot " + str(slot), lambda:
            acceptance.focused_display(self.shell("dumpsys", "window", "windows")) == row["display"])
        return row

    def _frame(self, relative, slot):
        if slot == 0:
            self.adb("exec-out", "screencap", "-p", timeout=60, evidence=relative, binary=True)
            return
        remote = "/state/phase1-recents-" + self.run + "-" + secrets.token_hex(4) + "-" + str(slot)
        self.docker("exec", self.container, "mkdir", "-m", "700", "--", remote)
        try:
            response = self.adb("emu", "screenrecord", "screenshot", "--display", slot, remote)
            require("OK" in response and "KO:" not in response, "Emulator framebuffer capture failed")
            names = self.docker("exec", self.container, "find", remote, "-maxdepth", "1", "-type", "f",
                                "-name", "*.png", "-printf", "%f\\n").splitlines()
            require(len(names) == 1 and re.fullmatch(r"[A-Za-z0-9_.-]+\.png", names[0]),
                    "Emulator produced an ambiguous framebuffer")
            target = self.output / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            require(not target.exists(), "Framebuffer evidence already exists")
            argv = ["docker", "cp", self.container + ":" + remote + "/" + names[0], str(target)]
            started = time.monotonic_ns()
            result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
            require(result.returncode == 0, "Could not copy emulator framebuffer: " + result.stdout)
            payload = acceptance.stable_bytes(target)
            self._record({"kind": "command", "argv": argv, "returncode": result.returncode,
                "started_monotonic_ns": started, "ended_monotonic_ns": time.monotonic_ns(),
                "evidence": relative, "output_sha256": hashlib.sha256(payload).hexdigest()})
        finally:
            self.docker("exec", self.container, "rm", "-rf", "--", remote)

    def capture(self, name, selection=None):
        require(name == acceptance.STAGES[len(self.stages)], "Recents stage order changed")
        directory = "stages/%02d-%s" % (len(self.stages), name)
        require(selection is None or (isinstance(selection, dict) and
                set(selection) == {"path", "trace_start"} and
                isinstance(selection["path"], str) and type(selection["trace_start"]) is int),
                "Malformed pending Recents selection")
        start = len(self.trace) if selection is None else selection["trace_start"]
        critical_screenshot = name == "screenshot_activated"
        if name in acceptance.BLOCKED_STAGES and not critical_screenshot:
            self.wait("runtime protected-UI observation for " + name,
                      self.runtime_topology_blocked, timeout=120)
        settled_phase = {
            "baseline": "checkpoint",
            "transfer_1_done": "checkpoint",
            "transfer_2_done": "checkpoint",
            "transfer_3_done": "checkpoint",
            "selected_display_rejected": "checkpoint",
            "same_slot_rejected": "checkpoint",
            "split_activated": "checkpoint",
        }.get(name)
        if settled_phase is not None:
            self.runtime_command(settled_phase)
        files = {
            "activities": directory + "/activities.txt",
            "fixture": directory + "/fixture.txt",
            "windows": directory + "/windows.txt",
            "input": directory + "/input.txt",
            "display": directory + "/display.txt",
            "conformance": directory + "/conformance.txt",
            "systemui": directory + "/systemui.txt",
            "log": directory + "/log.txt",
            "hierarchy": directory + "/hierarchy.xml",
        }
        phone_frame = directory + "/frame-0.png"
        if critical_screenshot:
            # The stock screenshot overlay is intentionally ephemeral.  Seal
            # its native window and real phone pixels before slower dumpsys,
            # UIAutomator and external-frame observations can outlive it.
            self.read(files["windows"], "dumpsys", "window", "windows")
            self._frame(phone_frame, 0)
            raw_status = self.read(files["conformance"], "dumpsys", "activity", "service", SERVICE)
            status = acceptance.runtime_status(raw_status)
            require(status.get("run") == self.conformance_run and
                    status.get("state") == "running" and status.get("phase") == "syncing-shells" and
                    status.get("runtime_readiness") == {
                        "ready": False, "session_open": True, "reopen_required": False} and
                    status.get("snapshot", {}).get("interaction_blocked") is True,
                    "Screenshot critical bundle lacks its live blocked runtime status")
            self.read(files["log"], "logcat", "-b", "main", "-b", "events", "-d", "-v",
                      "threadtime", "-t", "4000", timeout=90)
        self.read(files["activities"], "dumpsys", "activity", "activities")
        self.read(files["fixture"], "dumpsys", "activity", FIXTURE)
        if not critical_screenshot:
            self.read(files["windows"], "dumpsys", "window", "windows")
        self.read(files["input"], "dumpsys", "input")
        self.read(files["display"], "dumpsys", "display")
        if not critical_screenshot:
            self.read(files["conformance"], "dumpsys", "activity", "service", SERVICE)
        self.read(files["systemui"], "dumpsys", "activity", "service",
                  acceptance.SYSTEMUI + "/.SystemUIService")
        if not critical_screenshot:
            self.read(files["log"], "logcat", "-b", "main", "-b", "events", "-d", "-v",
                      "threadtime", "-t", "4000", timeout=90)
        remote = "/data/local/tmp/wonad-phase1-recents-capture-" + self.run + "-" + str(len(self.stages)) + ".xml"
        try:
            self.shell("uiautomator", "dump", remote)
            self.adb("exec-out", "cat", remote, evidence=files["hierarchy"])
        finally:
            self.shell("rm", "--", remote, allowed=(0, 1))
        topology = acceptance.logical_displays((self.output / files["display"]).read_text())
        frames = {"0": phone_frame}
        for row in topology.values():
            frames[str(row["slot"])] = directory + "/frame-%d.png" % row["slot"]
        for slot, relative in frames.items():
            if critical_screenshot and slot == "0":
                continue
            self._frame(relative, int(slot))
        row = {"name": name, "ordinal": len(self.stages), "trace_start": start,
               "trace_end": len(self.trace), "files": files, "frames": frames,
               "selection": selection["path"] if selection is not None else None}
        self.stages.append(row)
        print("Phase-1 conformance Recents %d/%d: %s" %
              (len(self.stages), len(acceptance.STAGES), name), flush=True)
        return row

    def extend(self, row):
        row["trace_end"] = len(self.trace)

    def ensure_phone(self, component):
        return self.wait("exact phone fixture " + component,
            lambda: self.fixture().get(component) if self.fixture().get(component, {}).get("display") == 0 else False)

    def run_scenarios(self):
        protected_before = self.protected_processes()
        uids = self.package_identities()
        attached = [self.attach(slot) for slot in (1, 2, 3)]
        status = self.start_instrumentation(attached[0]["display"], attached[1]["display"])
        require({row["display_id"] for row in status["snapshot"]["display_incarnations"]} ==
                {row["display"] for row in attached},
                "Conformance client did not bind all three mixed displays")
        self.capture("baseline")

        component = acceptance.COMPONENTS["cancel"]
        stage_start = len(self.trace)
        self.launch_phone(component, "cancel_menu")
        selection = self.open_menu(component, "cancel_menu", trace_start=stage_start)
        self.capture("cancel_menu", selection)
        cancelled = {"trace_start": len(self.trace)}
        self.shell("input", "keyboard", "-d", 0, "keyevent", "KEYCODE_BACK")
        self.wait("Back dismissal", lambda:
            acceptance.launcher_control(self.hierarchy(), "Send to Wonad", required=False) is None)
        row = self.capture("cancelled"); row["trace_start"] = cancelled["trace_start"]

        component = acceptance.COMPONENTS["removed"]
        stage_start = len(self.trace)
        self.launch_phone(component, "task_remove_card")
        self.runtime_command("checkpoint")
        self.enter_phone_overview("task_remove_card")
        def removal_card():
            xml = self.hierarchy()
            acceptance.phone_overview(xml)
            return xml, acceptance.recents_card(xml, acceptance.RECENTS_LABELS[component], chip=False)[1]
        xml, box = self.wait("removal card", lambda:
            removal_card())
        row = self.capture("task_remove_card"); row["trace_start"] = stage_start
        x, y = (box[0] + box[2]) // 2, (box[1] + box[3]) // 2
        self.shell(*acceptance.LOG_CLEAR)
        self.shell("input", "touchscreen", "-d", 0, "swipe", x, y, x, 120, 500)
        self.extend(row)
        self.wait("ordinary Recents task removal", lambda: component not in self.fixture())
        self.capture("task_removed")

        for slot in (1, 2, 3):
            component = acceptance.COMPONENTS[f"transfer_{slot}"]
            stage_name = f"transfer_{slot}_menu"
            stage_start = len(self.trace)
            self.launch_phone(component, stage_name)
            self.focus_slot(slot)
            selection = self.open_menu(component, stage_name, trace_start=stage_start)
            row = self.capture(stage_name, selection)
            point = acceptance.launcher_control((self.output / row["files"]["hierarchy"]).read_text(),
                                                "Send to Wonad")
            self.shell(*acceptance.LOG_CLEAR)
            self.shell("input", "touchscreen", "-d", 0, "tap", *point); self.extend(row)
            destination = next(value["display"] for value in self.displays().values()
                               if value["slot"] == slot)
            self.wait("exact transfer to slot " + str(slot), lambda:
                self.fixture().get(component) if self.fixture().get(component, {}).get("display") == destination else False)
            self.wait("broker observation for exact transfer to slot " + str(slot),
                      lambda: self.runtime_task_ready(component, destination), timeout=120)
            self.capture(f"transfer_{slot}_done")

        component = acceptance.COMPONENTS["selected_removed"]
        stage_start = len(self.trace)
        self.launch_phone(component, "selected_display_menu")
        self.focus_slot(2)
        selection = self.open_menu(component, "selected_display_menu", trace_start=stage_start)
        menu = self.capture("selected_display_menu", selection)
        point = acceptance.launcher_control((self.output / menu["files"]["hierarchy"]).read_text(), "Send to Wonad")
        removed_start = len(self.trace)
        self.detach(2)
        row = self.capture("selected_display_removed"); row["trace_start"] = removed_start
        start = len(self.trace)
        self.shell(*acceptance.LOG_CLEAR)
        self.shell("input", "touchscreen", "-d", 0, "tap", *point)
        self.ensure_phone(component)
        self.wait("removed-display action dismissal", lambda:
            acceptance.launcher_control(self.hierarchy(), "Send to Wonad", required=False) is None)
        self.home()
        row = self.capture("selected_display_rejected"); row["trace_start"] = start

        component = acceptance.COMPONENTS["same_slot"]
        stage_start = len(self.trace)
        self.launch_phone(component, "same_slot_menu")
        self.focus_slot(3)
        selection = self.open_menu(component, "same_slot_menu", trace_start=stage_start)
        menu = self.capture("same_slot_menu", selection)
        point = acceptance.launcher_control((self.output / menu["files"]["hierarchy"]).read_text(), "Send to Wonad")
        removed_start = len(self.trace)
        self.detach(3)
        row = self.capture("same_slot_removed"); row["trace_start"] = removed_start
        readded_start = len(self.trace)
        self.attach(3)
        row = self.capture("same_slot_readded"); row["trace_start"] = readded_start
        start = len(self.trace)
        self.shell(*acceptance.LOG_CLEAR)
        self.shell("input", "touchscreen", "-d", 0, "tap", *point)
        self.ensure_phone(component)
        self.wait("same-slot stale action dismissal", lambda:
            acceptance.launcher_control(self.hierarchy(), "Send to Wonad", required=False) is None)
        self.home()
        row = self.capture("same_slot_rejected"); row["trace_start"] = start

        component = acceptance.COMPONENTS["screenshot"]
        stage_start = len(self.trace)
        self.launch_phone(component, "screenshot_menu")
        self.focus_slot(1)
        selection = self.open_menu(component, "screenshot_menu", trace_start=stage_start)
        row = self.capture("screenshot_menu", selection)
        point = acceptance.launcher_control((self.output / row["files"]["hierarchy"]).read_text(), "Screenshot")
        self.shell(*acceptance.LOG_CLEAR)
        self.shell("input", "touchscreen", "-d", 0, "tap", *point); self.extend(row)
        def screenshot_ready():
            raw = self.shell("dumpsys", "window", "windows")
            try:
                acceptance.screenshot_window({"raw": {"windows": raw}}, uids[acceptance.SYSTEMUI])
                return raw
            except acceptance.EvidenceError:
                return False
        self.wait("SystemUI Screenshot activation", screenshot_ready)
        self.capture("screenshot_activated")

        primary, secondary = (acceptance.COMPONENTS[name] for name in
                              ("split_primary", "split_secondary"))
        stage_start = len(self.trace)
        self.launch_phone(primary, "split_menu", 0)
        self.launch_phone(secondary, "split_menu", 1)
        selection = self.open_menu(primary, "split_menu", trace_start=stage_start)
        row = self.capture("split_menu", selection)
        point = acceptance.launcher_control((self.output / row["files"]["hierarchy"]).read_text(), "Split screen")
        self.shell(*acceptance.LOG_CLEAR)
        self.shell("input", "touchscreen", "-d", 0, "tap", *point); self.extend(row)
        self.wait("split second-task selection", lambda:
            acceptance.recents_card(self.hierarchy(), acceptance.RECENTS_LABELS[secondary], chip=False))
        row = self.capture("split_select")
        point = acceptance.recents_card((self.output / row["files"]["hierarchy"]).read_text(),
                                        acceptance.RECENTS_LABELS[secondary], chip=False)[0]
        self.shell("input", "touchscreen", "-d", 0, "tap", *point); self.extend(row)
        def split_ready():
            records = self.fixture()
            if not all(records.get(value, {}).get("display") == 0 for value in (primary, secondary)):
                return False
            raw = self.shell("dumpsys", "activity", "activities")
            return raw if len(re.findall(r"(?i)windowingMode=(?:multi-window|6)", raw)) >= 2 else False
        self.wait("two exact phone tasks in split screen", split_ready)
        self.capture("split_activated")

        stop_start = len(self.trace)
        self.finish_instrumentation()
        component = acceptance.COMPONENTS["unavailable"]
        selection = self.open_menu(component, "unavailable", send=False, trace_start=stop_start)
        self.capture("unavailable", selection)
        require(self.protected_processes() == protected_before,
                "A protected phone process changed across the Recents lane")
        require(len(self.stages) == len(acceptance.STAGES), "Incomplete Recents stage sequence")
        return uids

    def stop_background(self):
        status = {"stop_background_called": True, "terminate_sent": False,
                  "kill_sent": False, "returncode": None,
                  "output_closed": self.instrument_file is None, "error": None,
                  "process_scope": "host_docker_exec_adb_only_not_android_stop_proof"}
        self.background_cleanup = status
        try:
            if self.instrument is not None:
                returncode = self.instrument.poll()
                if returncode is None:
                    self.instrument.terminate(); status["terminate_sent"] = True
                    try:
                        returncode = self.instrument.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        self.instrument.kill(); status["kill_sent"] = True
                        returncode = self.instrument.wait(timeout=10)
                require(type(returncode) is int, "Missing exact background process return code")
                status["returncode"] = returncode
            if self.instrument_file is not None:
                self.instrument_file.flush(); os.fsync(self.instrument_file.fileno())
                self.instrument_file.close(); self.instrument_file = None
        except BaseException as error:
            status["error"] = str(error)
            raise
        finally:
            status["output_closed"] = self.instrument_file is None

    def seal_sources(self):
        rows = {}
        for relative in ("android/tools/phase1_conformance_recents.py",
                         "android/tools/phase1_conformance_recents_acceptance.py"):
            source = Path(__file__).resolve().parents[2] / relative
            target = self.output / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_new(target, source.read_bytes())
            rows[relative] = {"path": relative, **acceptance.file_ref(target)}
        return rows

    def seal_failure(self, error, cleanup_error=None):
        """Retain the original inner journal, including rejected raw dumps.

        Both the standalone CLI and fresh-guest wrapper use this path.  A
        failed run never creates a PASS report or overwrites existing evidence.
        Call after stopping background instrumentation so its output is closed.
        """
        journal = self.output / "commands.json"
        payload = canonical(self.trace)
        if journal.exists():
            require(not journal.is_symlink() and acceptance.stable_bytes(journal) == payload,
                    "Existing failed command journal differs; preserve it")
        else:
            write_new(journal, payload)
        failure = {"status": "failed_not_qualified", "error": str(error),
            "container_id": self.container, "image_id": self.image, "boot_id": self.boot_id,
            "commands": {"path": "commands.json", **acceptance.file_ref(journal)},
            "cleanup_error": cleanup_error}
        instrumentation = self.output / "identity/instrumentation.txt"
        if os.path.lexists(instrumentation):
            require(not instrumentation.is_symlink(), "Aliased failed instrumentation evidence")
            require(getattr(self, "instrument_file", None) is None and
                    (getattr(self, "instrument", None) is None or self.instrument.poll() is not None),
                    "Stop background instrumentation before sealing its failed stream")
            failure["instrumentation"] = {"path": "identity/instrumentation.txt",
                                           **failed_file_ref(instrumentation)}
            terminal_finish = any(row.get("kind") == "background_finish" for row in self.trace)
            failure["instrumentation_status"] = {
                "completeness": "terminal_process_finish_recorded_unqualified" if terminal_finish
                    else "partial_no_terminal_finish",
                "terminal_finish_recorded": terminal_finish, "terminal_success_qualified": False,
                "start_recorded": any(row.get("kind") == "background_start" for row in self.trace),
                "background_cleanup": getattr(self, "background_cleanup", None),
            }
        target = self.output / "failure.json"
        write_new(target, canonical(failure))
        return {"path": "failure.json", **acceptance.file_ref(target)}

    def seal(self, uids):
        write_new(self.output / "commands.json", canonical(self.trace))
        sources = self.seal_sources()
        evidence = {}
        for path in sorted(self.output.rglob("*")):
            if path.is_file() and path.name not in ("report.json", "failure.json"):
                require(not path.is_symlink(), "Special evidence file")
                evidence[path.relative_to(self.output).as_posix()] = acceptance.file_ref(path)
        report = {
            "schema": acceptance.SCHEMA, "kind": acceptance.KIND, "scope": acceptance.SCOPE,
            "status": "passed", "api": 3, "run": self.run,
            "conformance_run": self.conformance_run, "container_id": self.container,
            "image_id": self.image, "boot_id": self.boot_id, "serial": SERIAL,
            "fingerprint": self.fingerprint, "uids": uids,
            "privileged_packages": self.privileged_packages,
            "producer_source": sources["android/tools/phase1_conformance_recents.py"],
            "auditor_source": sources["android/tools/phase1_conformance_recents_acceptance.py"],
            "commands": "commands.json", "stages": self.stages,
            "gates": {name: "passed" for name in (
                "three_mixed_displays", "exact_task_each_destination", "back_cancellation",
                "task_removal", "selected_display_removal_fail_closed",
                "same_slot_new_incarnation_fail_closed", "unavailable_session",
                "screenshot_activation", "split_screen_two_phone_tasks",
                "protected_process_continuity", "guest_os_and_apk_identity")},
            "runtime_qualified": False, "qualification_claimed": False,
            "evidence_files": evidence,
        }
        write_new(self.output / "report.json", canonical(report))
        acceptance.audit_report(self.output / "report.json")
        return report

    def execute(self):
        self.inspect_container()
        uids = self.run_scenarios()
        return self.seal(uids)


def literal_output(path: Path) -> Path:
    value = path.absolute()
    root = Path(__file__).resolve().parents[1] / "out"
    require(value.parent.exists() and value.parent.resolve(strict=True) == value.parent and
            value.is_relative_to(root) and value != root and not value.exists() and not value.is_symlink(),
            "Use one new literal directory beneath android/out")
    value.mkdir(mode=0o700)
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container-id", required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--boot-id", required=True)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--transition-timeout", type=int, default=90)
    args = parser.parse_args(argv)
    output = literal_output(args.output)
    producer = Producer(args.container_id, args.image_id, args.boot_id, args.fingerprint,
                        output, args.transition_timeout)
    try:
        report = producer.execute()
        print(json.dumps(report, sort_keys=True))
        print(hashlib.sha256((output / "report.json").read_bytes()).hexdigest())
        return 0
    except Exception as error:
        cleanup_error = None
        try:
            producer.stop_background()
        except Exception as caught:
            cleanup_error = str(caught)
        try:
            producer.seal_failure(error, cleanup_error)
        except Exception as caught:
            print("phase1_conformance_recents.py: failure evidence could not be sealed: " +
                  str(caught), file=sys.stderr)
        print("phase1_conformance_recents.py: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
