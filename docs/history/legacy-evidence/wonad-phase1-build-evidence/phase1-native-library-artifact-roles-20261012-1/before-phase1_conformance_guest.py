#!/usr/bin/env python3
"""Run full v3 conformance in one newly-created, exact-image emulator guest.

No product APK is present in this candidate and no existing userdata is used.
Consent is granted only by tapping the real SystemUI UI.  This lane neither
installs nor executes the platform fault harness; it proves that the exact
harness signer matches exact custom SystemUI and records that narrower scope.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "android/container"))
from build import inspect_image
from phase1_conformance_common import (BOOT_ID, IMAGE_ID, REPORT_KIND, REPORT_SCOPE, canonical,
    file_ref, load, sha256, strict_object, terminal_status_from_log, validate_manifest, validate_status)
import phase1_emulator_client_packet as packet_tool

_builder_spec = importlib.util.spec_from_file_location("phase1_conformance_candidate_builder",
    ROOT / "android/container/build-phase1-conformance-candidate.py")
candidate_builder = importlib.util.module_from_spec(_builder_spec)
_builder_spec.loader.exec_module(candidate_builder)

SERIAL = "emulator-5580"
LABEL = "org.wonad.phase1-fresh-conformance"
APP = "org.wonad.desktop"
FIXTURE = "org.wonad.fixture"
FAULT = "org.wonad.desktop.transitionfault"
SETTINGS = "com.android.systemui/org.wonad.desktop.broker.WonadSettingsActivity"
HOME_ACTION = "android.intent.action.MAIN"
HOME_CATEGORY = "android.intent.category.HOME"
PHONE_HOME_ACTIVITIES = "phone-home-activities.txt"
PHONE_HOME_WINDOWS = "phone-home-windows.txt"
OS_GUEST_PATHS = {
    "com.android.systemui": "/system_ext/priv-app/SystemUI/SystemUI.apk",
    "os_broker_native": "/system_ext/lib64/libwonad_broker_jni.so",
    "os_input_native": "/system/lib64/libwonad_input_jni.so",
    "os_services": "/system/framework/services.jar",
    "os_framework": "/system/framework/framework.jar",
}
PROTECTED = {"system_server", "com.android.systemui", "com.android.launcher3"}
FIRST_APPLICATION_UID = 10000
LAST_APPLICATION_UID = 19999
PRELAUNCH_USERDATA_EVIDENCE = "prelaunch-userdata.json"
PRELAUNCH_USERDATA_KIND = "wonad-phase1-prelaunch-userdata-v1"
PRELAUNCH_LOCAL_EVENT = "prelaunch_userdata"


def require(value, message):
    if not value:
        raise ValueError(message)


def write_new(path: Path, value):
    with path.open("xb") as output:
        output.write(canonical(value))


def write_new_durable(path: Path, value):
    """Exclusively create and durably publish one canonical evidence file."""
    data = canonical(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, "Short write while sealing evidence: " + str(path))
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                        getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return file_ref(path)


def write_new_raw_durable(path: Path, data: str):
    """Exclusively and durably publish exact raw command output."""
    require(isinstance(data, str) and data, "Refusing to seal empty raw evidence")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        raw = memoryview(data.encode())
        while raw:
            written = os.write(descriptor, raw)
            require(written > 0, "Short write while sealing evidence: " + str(path))
            raw = raw[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                        getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def parse_home_component(raw: str) -> tuple[str, str]:
    """Return the exact resolved short and fully-qualified HOME component."""
    rows = raw.splitlines()
    match = re.fullmatch(
        r"([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)/"
        r"(\.[A-Za-z0-9_.$]+|[A-Za-z][A-Za-z0-9_.$]*)",
        rows[0] if len(rows) == 1 else "")
    require(match is not None and match.group(1) != "com.android.systemui",
            "Missing/ambiguous non-SystemUI user-0 HOME component")
    package, activity = match.groups()
    full = package + "/" + (package + activity if activity.startswith(".") else activity)
    return rows[0], full


def phone_home_proof(component: str, full_component: str,
                     activities: str, windows: str):
    """Validate a current, focused, visible user-0 HOME on physical display 0."""
    display_sections = re.findall(
        r"^Display #0 \(activities from top to bottom\):\n(.*?)(?=^Display #[0-9]+ |\Z)",
        activities, re.M | re.S)
    require(len(display_sections) == 1, "Missing/ambiguous display-0 activity stack")
    display = display_sections[0]
    task = re.search(r"^[ \t]*\* Task\{[^\n}]*\btype=home\b[^\n}]*\bU=0\b"
                     r"[^\n}]*\bvisible=true\b[^\n}]*\bvisibleRequested=true\b", display, re.M)
    top = re.findall(r"^[ \t]*topResumedActivity=ActivityRecord\{[^\n}]*\bu0\s+([^\s}]+)",
                     display, re.M)
    require(task is not None and top == [component],
            "Display 0 does not have the resolved user-0 HOME top-resumed")
    blocks = re.findall(
        r"^[ \t]*\* Hist[ \t]+#\d+: ActivityRecord\{[^\n}]*\bu0\s+" + re.escape(component) +
        r"[^\n]*\n(.*?)(?=^[ \t]*\* Hist[ \t]+#\d+:|^[ \t]*\* Task\{|^Display #[0-9]+ |\Z)",
        display, re.M | re.S)
    require(len(blocks) == 1 and
            re.search(r"^[ \t]*mActivityComponent=" + re.escape(component) + r"[ \t]*$", blocks[0], re.M) and
            re.search(r"^[ \t]*state=RESUMED finishing=false[ \t]*$", blocks[0], re.M) and
            re.search(r"^[ \t]*mActivityType=home[ \t]*$", blocks[0], re.M) and
            re.search(r"^[ \t]*mVisibleRequested=true mVisible=true mClientVisible=true"
                      r" reportedDrawn=true reportedVisible=true[ \t]*$", blocks[0], re.M) and
            re.search(r"^[ \t]*nowVisible=true lastVisibleTime=\S+[ \t]*$", blocks[0], re.M),
            "Resolved HOME Activity is not resumed, drawn and fully visible")
    display_zero = re.findall(
        r"^[ \t]*Display: mDisplayId=0(?: \([^\n]*\))?\n(.*?)(?=^[ \t]*Display: mDisplayId=[0-9]+|\Z)",
        activities, re.M | re.S)
    require(len(display_zero) == 1 and
            re.findall(r"^[ \t]*mCurrentFocus=Window\{[^\n}]*\bu0\s+([^\s}]+)",
                       display_zero[0], re.M) == [full_component] and
            re.findall(r"^[ \t]*mFocusedApp=ActivityRecord\{[^\n}]*\bu0\s+([^\s}]+)",
                       display_zero[0], re.M) == [component] and
            re.findall(r"^[ \t]*ResumedActivity: ActivityRecord\{[^\n}]*\bu0\s+([^\s}]+)",
                       activities, re.M) == [component],
            "Resolved HOME is not the unique focused/resumed display-0 Activity")
    focused_displays = re.findall(r"^[ \t]*mTopFocusedDisplayId=(\d+)[ \t]*$", windows, re.M)
    require(focused_displays == ["0"], "WindowManager top focus is not uniquely display 0")
    live = set()
    for match in re.finditer(
            r"^[ \t]*(?:Window #\d+|#\d+) Window\{([0-9a-f]+) u0 " +
            re.escape(full_component) + r"\}:\n(.*?)(?=^[ \t]*(?:Window #\d+|#\d+) Window\{|\Z)",
            windows, re.M | re.S):
        block = match.group(2)
        if (re.search(r"^[ \t]*mDisplayId=0\b", block, re.M) and
                re.search(r"^[ \t]*mHasSurface=true\b", block, re.M) and
                re.search(r"^[ \t]*isOnScreen=true[ \t]*$", block, re.M) and
                re.search(r"^[ \t]*isVisible=true[ \t]*$", block, re.M)):
            live.add(match.group(1))
    require(len(live) == 1, "Resolved HOME lacks one visible surfaced display-0 window")


def source_identity(path: Path) -> dict:
    """Return an exact identity for a reviewed source beneath this repository."""
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path and path.is_file() and not path.is_symlink() and
            path.is_relative_to(ROOT), "Authority source is not one literal repository file")
    return {"path": path.relative_to(ROOT).as_posix(), **file_ref(path)}


def _directory_identity(path: Path) -> dict:
    path = path.absolute()
    value = os.lstat(path)
    require(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode),
            "Fresh userdata path is not a literal directory: " + str(path))
    return {"path": str(path), "dev": value.st_dev, "ino": value.st_ino,
            "mode": stat.S_IMODE(value.st_mode), "uid": value.st_uid, "gid": value.st_gid}


def _fresh_userdata_inventory(state: Path, temporary: Path) -> tuple[dict, dict, list[dict]]:
    """Observe the exact recursively-empty prelaunch state tree."""
    state_identity = _directory_identity(state)
    temporary_identity = _directory_identity(temporary)
    with os.scandir(state) as stream:
        entries = list(stream)
    require(len(entries) == 1 and entries[0].name == "tmp" and
            entries[0].is_dir(follow_symlinks=False) and not entries[0].is_symlink(),
            "Fresh userdata must contain exactly one literal tmp directory")
    entry = entries[0].stat(follow_symlinks=False)
    require((entry.st_dev, entry.st_ino) ==
            (temporary_identity["dev"], temporary_identity["ino"]),
            "Fresh userdata tmp identity changed during inventory")
    with os.scandir(temporary) as stream:
        children = list(stream)
    require(not children, "Fresh userdata tmp directory was not empty")
    return state_identity, temporary_identity, [
        {"path": "tmp", "kind": "directory", "children": []},
    ]


def prelaunch_summary(record: dict, evidence: Path, relative_path: str) -> dict:
    """Project sealed prelaunch observations into a wrapper report."""
    require(isinstance(record, dict) and record.get("kind") == PRELAUNCH_USERDATA_KIND,
            "Missing sealed prelaunch userdata observation")
    return {**record, "evidence": {"path": relative_path, **file_ref(evidence)}}


def validate_prelaunch_userdata(record: dict, evidence: Path, state: Path,
                                authority: dict, *, require_empty=False) -> dict:
    """Reopen the record and recheck identities without assuming state stays empty."""
    required = {"schema", "kind", "timeline", "state", "tmp", "inventory", "authority"}
    require(isinstance(record, dict) and set(record) == required and
            type(record["schema"]) is int and record["schema"] == 1 and
            record["kind"] == PRELAUNCH_USERDATA_KIND and record["authority"] == authority and
            evidence.read_bytes() == canonical(record) and load(evidence) == record,
            "Malformed or changed sealed prelaunch userdata evidence")
    timeline = record["timeline"]
    names = ("create_started_monotonic_ns", "state_created_monotonic_ns",
             "tmp_created_monotonic_ns", "inventory_observed_monotonic_ns")
    require(isinstance(timeline, dict) and set(timeline) == set(names) and
            all(type(timeline[name]) is int and timeline[name] > 0 for name in names) and
            [timeline[name] for name in names] == sorted(timeline[name] for name in names),
            "Malformed prelaunch userdata observation timeline")
    require(record["inventory"] == [
                {"path": "tmp", "kind": "directory", "children": []},
            ], "Malformed prelaunch userdata inventory")
    current_state = _directory_identity(state)
    current_tmp = _directory_identity(state / "tmp")
    require(record["state"] == current_state and record["tmp"] == current_tmp,
            "Retained userdata directory identity differs from prelaunch")
    if require_empty:
        observed_state, observed_tmp, current_inventory = _fresh_userdata_inventory(
            state, state / "tmp")
        require(record["state"] == observed_state and record["tmp"] == observed_tmp and
                record["inventory"] == current_inventory,
                "Fresh userdata differs from its exact empty prelaunch inventory")
    return record


def literal_directory(path: Path) -> Path:
    raw = path.absolute()
    require(raw.resolve(strict=True) == raw and raw.is_dir() and not raw.is_symlink(),
            "Select one literal existing directory: " + str(raw))
    return raw


class Producer:
    def __init__(self, image: str, product: Path, packet: Path, receipt_sha256: str, output: Path,
                 *, authority: dict | None = None):
        self.image, self.product, self.packet = image, product, packet
        self.receipt_sha256, self.output = receipt_sha256, output
        self.run = secrets.token_hex(16)
        self.container = None
        self.state = output / "emulator-state"
        self.trace = []
        self.manifest = None
        self.evidence = {}
        common = source_identity(Path(__file__).resolve())
        self.authority = authority if authority is not None else {
            "runner": common, "guest_common": common,
        }
        require(isinstance(self.authority, dict) and
                set(self.authority) == {"runner", "guest_common"} and
                self.authority["guest_common"] == common,
                "Prelaunch authority does not bind the current guest implementation")
        for role, source in self.authority.items():
            require(isinstance(source, dict) and set(source) == {"path", "sha256", "bytes"} and
                    isinstance(source["path"], str) and source["path"].startswith("android/tools/") and
                    re.fullmatch(r"[0-9a-f]{64}", str(source["sha256"])) and
                    type(source["bytes"]) is int and source["bytes"] > 0,
                    "Malformed prelaunch authority source: " + role)
        # Detach the sealed value from any caller-owned mutable dictionary.
        self.authority = json.loads(canonical(self.authority))
        self.prelaunch_userdata = None
        self.prelaunch_userdata_ref = None

    def command(self, argv, *, timeout=60, allowed=(0,), evidence=None,
                journal_timeout=False):
        argv = list(map(str, argv))
        started = time.monotonic_ns()
        try:
            result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    timeout=timeout, text=True)
        except subprocess.TimeoutExpired as error:
            if journal_timeout:
                output = error.stdout or ""
                if isinstance(output, bytes):
                    output = output.decode(errors="replace")
                self.trace.append({"argv": argv, "returncode": None, "timed_out": True,
                    "timeout_seconds": timeout, "started_monotonic_ns": started,
                    "ended_monotonic_ns": time.monotonic_ns(), "output": output})
            raise
        row = {"argv": argv, "returncode": result.returncode, "started_monotonic_ns": started,
               "ended_monotonic_ns": time.monotonic_ns()}
        if evidence is None:
            row["output"] = result.stdout
        else:
            path = self.output / evidence
            require(not path.exists(), "Refusing to overwrite evidence: " + evidence)
            path.write_text(result.stdout)
            row["evidence"] = evidence
            row["output_sha256"] = sha256(path)
        self.trace.append(row)
        require(result.returncode in allowed,
                "Command failed (%d): %s\n%s" % (result.returncode, " ".join(argv), result.stdout))
        return result.stdout.strip()

    def docker(self, *args, **kwargs):
        return self.command(["docker", *args], **kwargs)

    def adb(self, *args, **kwargs):
        require(self.container is not None, "No owned guest")
        return self.docker("exec", self.container, "adb", "-s", SERIAL, *args, **kwargs)

    def shell(self, *args, **kwargs):
        return self.adb("shell", *args, **kwargs)

    def image_manifest(self):
        require(IMAGE_ID.fullmatch(self.image) is not None and inspect_image(self.image)["Id"] == self.image,
                "Use one immutable local conformance candidate image ID")
        raw = self.docker("run", "--rm", "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,nosuid,size=64m", self.image, "verify", timeout=120)
        banner, separator, document = raw.partition("\n")
        require(banner == "Verifying fresh-guest Phase-1 conformance candidate…" and separator,
                "Candidate did not run its dedicated offline verifier")
        value = json.loads(document, object_pairs_hook=strict_object)
        validate_manifest(value)
        write_new(self.output / "image-manifest.json", value)
        self.manifest = value

    def inputs(self):
        receipt = load(self.packet / "receipt.json")
        packet_tool.validate_receipt(self.packet, receipt, self.receipt_sha256, live_tools=False)
        require(self.manifest["packet"]["receipt_sha256"] == self.receipt_sha256,
                "Candidate and selected packet receipt differ")
        shutil.copyfile(self.packet / "receipt.json", self.output / "packet-receipt.json")
        require(sha256(self.output / "packet-receipt.json") == self.receipt_sha256,
                "Copied packet receipt differs")
        for role, filename in {"conformance": "conformance.apk", "fixture": "fixture.apk", "fault": "fault.apk"}.items():
            record = receipt["artifacts"][role]
            require(file_ref(self.packet / filename) == {"sha256": record["sha256"], "bytes": record["bytes"]} and
                    self.manifest["artifacts"][role]["sha256"] == record["sha256"],
                    "Candidate/packet artifact differs: " + role)
        product_manifest = self.docker("run", "--rm", "--network", "none", "--read-only",
            "--entrypoint", "cat", self.image, "/opt/wonad/product-candidate-manifest.json")
        value = json.loads(product_manifest, object_pairs_hook=strict_object)
        require(__import__("hashlib").sha256(canonical(value)).hexdigest() ==
                self.manifest["base_product_candidate"]["manifest_sha256"],
                "Bundled product candidate manifest differs")
        products, os_artifacts = candidate_builder.verify_product(self.product, value)
        require(products == self.manifest["product_images"] and
                os_artifacts == self.manifest["os_artifacts"],
                "Selected strict custom product differs from candidate")
        write_new(self.output / "product-candidate-manifest.json", value)

    def owned(self, running=True):
        require(self.container is not None, "No owned conformance container")
        raw = self.docker("container", "inspect", self.container)
        rows = json.loads(raw)
        require(isinstance(rows, list) and len(rows) == 1, "Missing owned conformance container")
        info = rows[0]
        mounts = {item["Destination"]: (item["Source"], item["RW"]) for item in info["Mounts"]}
        host = info["HostConfig"]
        require(info["Id"] == self.container and info["Image"] == self.image and
                info["Config"]["Labels"].get(LABEL) == self.run and
                mounts.get("/state") == (str(self.state), True) and set(mounts) - {"/state", "/tmp"} == set() and
                host["NetworkMode"] == "none" and host["Privileged"] is False and
                not host.get("PortBindings") and info["State"]["Running"] is running,
                "Owned fresh-guest isolation changed")
        return info

    def seal_prelaunch_userdata(self):
        """Atomically create, inventory and seal the state mounted by Docker."""
        require(self.prelaunch_userdata is None and self.prelaunch_userdata_ref is None and
                not (self.output / PRELAUNCH_USERDATA_EVIDENCE).exists(),
                "Prelaunch userdata evidence already exists")
        timeline = {"create_started_monotonic_ns": time.monotonic_ns()}
        try:
            self.state.mkdir(mode=0o700)
        except FileExistsError as error:
            raise ValueError("Refusing preexisting fresh userdata directory: " + str(self.state)) from error
        timeline["state_created_monotonic_ns"] = time.monotonic_ns()
        created_state = _directory_identity(self.state)
        temporary = self.state / "tmp"
        try:
            temporary.mkdir(mode=0o700)
        except FileExistsError as error:
            raise ValueError("Refusing preexisting fresh userdata tmp directory: " + str(temporary)) from error
        timeline["tmp_created_monotonic_ns"] = time.monotonic_ns()
        created_tmp = _directory_identity(temporary)
        state, tmp, inventory = _fresh_userdata_inventory(self.state, temporary)
        require(state == created_state and tmp == created_tmp,
                "Fresh userdata identity changed after exclusive creation")
        require(state["mode"] == tmp["mode"] == 0o700 and
                state["uid"] == tmp["uid"] == os.getuid() and
                state["gid"] == tmp["gid"] == os.getgid(),
                "Fresh userdata ownership or private mode changed")
        timeline["inventory_observed_monotonic_ns"] = time.monotonic_ns()
        record = {"schema": 1, "kind": PRELAUNCH_USERDATA_KIND, "timeline": timeline,
                  "state": state, "tmp": tmp, "inventory": inventory,
                  "authority": self.authority}
        evidence = self.output / PRELAUNCH_USERDATA_EVIDENCE
        seal_started = time.monotonic_ns()
        reference = write_new_durable(evidence, record)
        validate_prelaunch_userdata(record, evidence, self.state, self.authority,
                                    require_empty=True)
        seal_ended = time.monotonic_ns()
        self.trace.append({"kind": "local_evidence", "name": PRELAUNCH_LOCAL_EVENT,
            "started_monotonic_ns": seal_started, "ended_monotonic_ns": seal_ended,
            "evidence": PRELAUNCH_USERDATA_EVIDENCE,
            "output_sha256": reference["sha256"], "bytes": reference["bytes"]})
        self.prelaunch_userdata = record
        self.prelaunch_userdata_ref = reference
        return record

    def start(self):
        self.seal_prelaunch_userdata()
        name = "wonad-phase1-conformance-" + self.run[:12]
        identity = self.docker("run", "-d", "--name", name, "--label", LABEL + "=" + self.run,
            "--network", "none", "--device", "/dev/kvm", "--group-add", Path("/dev/kvm").stat().st_gid,
            "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop=ALL",
            "--security-opt", "no-new-privileges=true", "--pids-limit", 1024, "--memory", "8g",
            "--cpus", 12, "--shm-size", "512m", "--ulimit", "nofile=65536:65536",
            "--ulimit", "core=0:0", "--tmpfs", "/tmp:rw,nosuid,nodev,size=2g",
            "--volume", f"{self.state}:/state:rw,Z", "--env", "HOME=/state", "--env", "TMPDIR=/state/tmp",
            "--env", "WONAD_VIEWER_TRANSPORT=vnc", "--entrypoint", "python3", self.image,
            "/opt/wonad/session.py")
        require(re.fullmatch(r"[0-9a-f]{64}", identity) is not None, "Docker returned no exact container ID")
        self.container = identity
        self.owned()
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            require(self.owned()["State"]["Running"], "Fresh conformance emulator exited during boot")
            try:
                if self.shell("getprop", "sys.boot_completed", timeout=10,
                              journal_timeout=True) == "1":
                    break
            except (subprocess.SubprocessError, ValueError):
                pass
            time.sleep(2)
        else:
            raise TimeoutError("Fresh conformance emulator boot timed out")

    def package_path(self, package):
        value = self.shell("pm", "path", package, allowed=(0, 1))
        require(not value or re.fullmatch(r"package:/[A-Za-z0-9_+/.=~-]+", value),
                "Ambiguous package path: " + package)
        return value.removeprefix("package:") if value else None

    def process(self, name):
        value = self.shell("pidof", name)
        require(re.fullmatch(r"[1-9][0-9]*", value) is not None, "Missing/ambiguous protected process: " + name)
        pid = int(value)
        raw = self.shell("su", "0", "cat", f"/proc/{pid}/stat")
        match = re.fullmatch(r"([1-9][0-9]*) \(.*\) [A-Z] (.+)\n?", raw)
        fields = match[2].split() if match is not None else []
        # The suffix begins with proc(5) field 4; starttime is field 22.
        require(match is not None and int(match[1]) == pid and len(fields) > 18 and
                re.fullmatch(r"[1-9][0-9]*", fields[18]) is not None,
                "Cannot identify protected process epoch: " + name)
        return {"pid": pid, "start_ticks": int(fields[18])}

    def keyguard(self):
        raw = self.shell("dumpsys", "activity", "service", "com.android.systemui/.SystemUIService")
        blocks = re.findall(r"^\s*KeyguardStateController:\n((?:[ \t]+[^\n]+\n)+)", raw, re.M)
        require(len(blocks) == 1, "Missing/ambiguous keyguard state")
        result = {}
        for field in ("mShowing", "mSecure", "mCanDismissLockScreen"):
            values = re.findall(r"^\s*" + field + r": (true|false)\s*$", blocks[0], re.M)
            require(len(values) == 1, "Missing keyguard field: " + field)
            result[field] = values[0] == "true"
        return result

    def unlock(self):
        for _ in range(3):
            state = self.keyguard()
            require(not state["mSecure"], "Fresh emulator unexpectedly requires a credential")
            self.shell("input", "keyboard", "-d", 0, "keyevent", "KEYCODE_WAKEUP")
            if not state["mShowing"]:
                return
            time.sleep(1)
            self.shell("input", "touchscreen", "-d", 0, "swipe", 540, 1800, 540, 400, 600)
            time.sleep(1)
        require(not self.keyguard()["mShowing"], "Credential-free keyguard did not dismiss")

    def packages(self):
        return {package: self.package_path(package) for package in (APP, FIXTURE, FAULT)}

    def guest_artifacts(self):
        result = {}
        for role, path in OS_GUEST_PATHS.items():
            value = self.shell("sha256sum", path).split()
            require(len(value) == 2 and value[1] == path and re.fullmatch(r"[0-9a-f]{64}", value[0]),
                    "Cannot identify guest OS artifact: " + role)
            result[role] = value[0]
        require(result == self.manifest["os_artifacts"], "Running guest OS differs from candidate manifest")
        return result

    def attach_display(self):
        result = self.adb("emu", "multidisplay", "add", 1, 1920, 1080, 160, 132165)
        require("OK" in result and "KO:" not in result, "Exact conformance display attachment failed")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            raw = self.shell("dumpsys", "display")
            values = sorted({int(item) for item in re.findall(r"\bmDisplayId\s*=\s*(\d+)\b", raw) if int(item) > 0})
            if len(values) == 1:
                (self.output / "display.txt").write_text(raw)
                return values[0]
            time.sleep(.5)
        raise ValueError("Exactly one external conformance display did not appear")

    def install(self, role, package):
        archive = "/opt/wonad/phase1-conformance/" + role + ".apk"
        require(self.package_path(package) is None, "Fresh install target unexpectedly exists: " + package)
        result = self.adb("install", "--user", 0, archive, timeout=180)
        require("Success" in result.splitlines(), "Normal fresh APK install failed: " + role)
        path = self.package_path(package)
        require(path is not None, "Fresh APK did not become installed: " + role)
        value = self.shell("sha256sum", path).split()[0]
        require(value == self.manifest["artifacts"][role]["sha256"], "Installed APK bytes differ: " + role)
        return {"path": path, "sha256": value}

    def package_identities(self):
        """Prove both freshly installed clients have private user-0 app UIDs."""
        result = {}
        for package in (FIXTURE, APP):
            raw = self.shell("cmd", "package", "list", "packages", "-U",
                             "--user", 0, package)
            rows = raw.splitlines()
            match = re.fullmatch(r"package:" + re.escape(package) + r" uid:(\d+)",
                                 rows[0] if len(rows) == 1 else "")
            require(match is not None, "Missing/ambiguous user-0 package UID: " + package)
            uid = int(match.group(1))
            require(FIRST_APPLICATION_UID <= uid <= LAST_APPLICATION_UID,
                    "Fresh client lacks an ordinary user-0 application UID: " + package)
            reverse = self.shell("cmd", "package", "list", "packages", "-U",
                                 "--user", 0, "--uid", uid)
            require(reverse.splitlines() == rows,
                    "Fresh client UID is shared or owned by another package: " + package)
            result[package] = uid
        require(len(set(result.values())) == len(result),
                "Fresh client and fixture share one application UID")
        return result

    def enable_consent(self):
        require(self.shell("settings", "--user", 0, "get", "secure", "wonad_external_desktop_enabled") != "1",
                "Fresh guest unexpectedly had Wonad consent")
        self.shell("am", "start", "-W", "--display", 0, "-n", SETTINGS)
        time.sleep(1)
        remote = "/data/local/tmp/wonad-phase1-consent-" + self.run + ".xml"
        try:
            self.shell("uiautomator", "dump", "--compressed", remote)
            raw = self.adb("exec-out", "cat", remote)
            (self.output / "consent-hierarchy.xml").write_text(raw)
        finally:
            self.shell("rm", "--", remote, allowed=(0, 1))
        start, end = raw.find("<?xml"), raw.rfind("</hierarchy>")
        require(start >= 0 and end >= start, "Missing SystemUI consent hierarchy")
        tree = ET.fromstring(raw[start:end + len("</hierarchy>")])
        nodes = [node for node in tree.iter("node") if node.get("package") == "com.android.systemui" and
                 node.get("text", "").casefold() == "enable wonad desktop" and
                 node.get("enabled") == "true" and node.get("clickable") == "true"]
        require(len(nodes) == 1, "Missing/ambiguous genuine SystemUI consent control")
        bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", nodes[0].get("bounds", ""))
        require(bounds is not None, "Invalid SystemUI consent bounds")
        left, top, right, bottom = map(int, bounds.groups())
        require(0 <= left < right <= 1080 and 0 <= top < bottom <= 2400, "Consent control is off phone display")
        point = [(left + right) // 2, (top + bottom) // 2]
        self.shell("input", "touchscreen", "-d", 0, "tap", *point)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.shell("settings", "--user", 0, "get", "secure", "wonad_external_desktop_enabled") == "1":
                resolved = self.shell("cmd", "package", "resolve-activity", "--components",
                    "--user", 0, "-a", HOME_ACTION, "-c", HOME_CATEGORY, timeout=5)
                component, full_component = parse_home_component(resolved)
                self.shell("input", "keyboard", "-d", 0, "keyevent", "KEYCODE_HOME", timeout=5)
                home_deadline = time.monotonic() + 15
                last_error = "no phone HOME observation"
                while time.monotonic() < home_deadline:
                    remaining = home_deadline - time.monotonic()
                    require(remaining > 0, "Phone HOME proof exceeded fifteen seconds")
                    activities = self.shell("dumpsys", "activity", "activities",
                                            timeout=min(5, remaining))
                    activities_raw = self.trace[-1]["output"]
                    remaining = home_deadline - time.monotonic()
                    require(remaining > 0, "Phone HOME proof exceeded fifteen seconds")
                    windows = self.shell("dumpsys", "window", "windows",
                                         timeout=min(5, remaining))
                    windows_raw = self.trace[-1]["output"]
                    try:
                        phone_home_proof(component, full_component, activities, windows)
                    except ValueError as error:
                        last_error = str(error)
                        time.sleep(.25)
                        continue
                    require(time.monotonic() <= home_deadline,
                            "Phone HOME proof completed after its fifteen-second deadline")
                    write_new_raw_durable(self.output / PHONE_HOME_ACTIVITIES, activities_raw)
                    write_new_raw_durable(self.output / PHONE_HOME_WINDOWS, windows_raw)
                    return point
                raise ValueError("Phone did not return to focused HOME within fifteen seconds: " +
                                 last_error)
            time.sleep(.25)
        raise ValueError("Genuine SystemUI consent action did not take effect")

    def state_record(self, packages, processes, *, display_id=None, installed=None, consent_point=None):
        boot = self.shell("cat", "/proc/sys/kernel/random/boot_id")
        require(BOOT_ID.fullmatch(boot) is not None, "Invalid guest boot ID")
        return {"boot_id": boot, "fingerprint": self.shell("getprop", "ro.build.fingerprint"),
            "abi": self.shell("getprop", "ro.product.cpu.abi"), "enforcing": self.shell("getenforce"),
            "current_user": self.shell("am", "get-current-user"),
            "consent": self.shell("settings", "--user", 0, "get", "secure", "wonad_external_desktop_enabled"),
            "packages": packages, "protected_processes": processes, "display_id": display_id,
            "installed": installed, "consent_point": consent_point,
            "os_artifacts": self.guest_artifacts()}

    def run_guest(self):
        packages = self.packages()
        require(packages == {APP: None, FIXTURE: None, FAULT: None},
                "Fresh guest contains a target/fixture/fault package")
        self.unlock()
        require(self.shell("am", "get-current-user") == "0" and
                re.findall(r"UserInfo\{([0-9]+):", self.shell("pm", "list", "users")) == ["0"],
                "Fresh conformance guest is not sole owner user 0")
        # Establish the protected phone-process epoch before external-display
        # attachment, APK installation and user consent.  The terminal sample
        # therefore covers the entire OS-glue exercise, not just instrumentation.
        processes = {name: self.process(name) for name in
                     ("system_server", "com.android.systemui", "com.android.launcher3")}
        display = self.attach_display()
        installed = {FIXTURE: self.install("fixture", FIXTURE), APP: self.install("conformance", APP)}
        require(self.package_path(FAULT) is None, "Platform fault harness must remain uninstalled in this lane")
        self.package_identities()
        consent_point = self.enable_consent()
        before = self.state_record(packages, processes, display_id=display,
                                   installed=installed, consent_point=consent_point)
        require(before["fingerprint"] == self.manifest["fingerprint"] and before["abi"] == "x86_64" and
                before["enforcing"] == "Enforcing" and before["consent"] == "1",
                "Fresh guest identity/enforcement/consent differs")
        write_new(self.output / "before.json", before)

        self.docker("exec", self.container, "python3",
            "/opt/wonad/phase1-conformance/conformance_smoke.py", "--adb", "adb", "--serial", SERIAL,
            "--display-id", display, "--timeout", 360, timeout=420, evidence="conformance.log")
        terminal = terminal_status_from_log((self.output / "conformance.log").read_text())
        validate_status(terminal, display_id=display)
        raw_status = self.shell("dumpsys", "activity", "service", APP + "/.ConformanceService")
        marker = "WONAD_CONFORMANCE_STATUS "
        rows = [line.split(marker, 1)[1] for line in raw_status.splitlines() if marker in line]
        require(len(rows) == 1 and json.loads(rows[0]) == terminal, "Canonical service dump differs from driver log")
        write_new(self.output / "terminal-status.json", terminal)

        after_packages = self.packages()
        after_processes = {name: self.process(name) for name in processes}
        after = self.state_record(after_packages, after_processes, display_id=display,
            installed={APP: {"path": after_packages[APP], "sha256": self.shell("sha256sum", after_packages[APP]).split()[0]},
                       FIXTURE: {"path": after_packages[FIXTURE], "sha256": self.shell("sha256sum", after_packages[FIXTURE]).split()[0]},
                       FAULT: None})
        require(after["boot_id"] == before["boot_id"] and after["protected_processes"] == processes and
                after["fingerprint"] == before["fingerprint"] and after["enforcing"] == "Enforcing" and
                after["consent"] == "1" and after_packages[FAULT] is None and
                after["installed"][APP]["sha256"] == self.manifest["artifacts"]["conformance"]["sha256"] and
                after["installed"][FIXTURE]["sha256"] == self.manifest["artifacts"]["fixture"]["sha256"],
                "Conformance changed boot/protected processes/consent/artifact identities")
        write_new(self.output / "after.json", after)
        self.shell("logcat", "-b", "events", "-d", "-v", "threadtime",
                   "am_anr:I", "am_crash:I", "*:S", timeout=60, evidence="protected-events.txt")
        events = (self.output / "protected-events.txt").read_text()
        failures = [match.groups() for match in re.finditer(
            r"\b(am_(?:anr|crash))\s*:\s*\[\s*[^,\]\n]+\s*,\s*[^,\]\n]+\s*,\s*([^,\]\n]+)", events)]
        require(not any(process.strip().split(":", 1)[0] in PROTECTED for _, process in failures),
                "Protected phone process crash/ANR occurred during fresh guest boot/conformance")
        return before, after, terminal

    def stop(self):
        if self.container is None:
            return False
        info = self.owned()
        if info["State"]["Running"]:
            self.docker("stop", "-t", 30, self.container, timeout=45)
        self.owned(running=False)
        return True

    def seal(self):
        write_new(self.output / "commands.json", self.trace)
        records = {}
        for path in sorted(self.output.iterdir()):
            if path.name in ("report.json", "failure.json") or path.is_dir():
                continue
            require(path.is_file() and not path.is_symlink(), "Special conformance evidence file")
            records[path.name] = file_ref(path)
        return records

    def execute(self):
        self.image_manifest()
        self.inputs()
        self.start()
        before, after, terminal = self.run_guest()
        container = self.container
        stopped = self.stop()
        evidence = self.seal()
        report = {"schema": 1, "kind": REPORT_KIND, "scope": REPORT_SCOPE,
            "status": "passed", "api": 3, "run": terminal["run"], "image_id": self.image,
            "fingerprint": self.manifest["fingerprint"], "container": container,
            "container_run": self.run,
            "boot_id": before["boot_id"], "display_id": before["display_id"],
            "packet_receipt_sha256": self.receipt_sha256,
            "product_images": self.manifest["product_images"], "os_artifacts": self.manifest["os_artifacts"],
            "artifacts": self.manifest["artifacts"], "terminal_status": terminal,
            "gates": {"fresh_userdata_and_absent_packages": "passed", "ordinary_ui_consent": "passed",
                "full_v3_operations_callbacks_capabilities_and_facades": "passed",
                "protected_process_continuity": "passed",
                "platform_fault_injection": "identity_verified_only_not_run"},
            "runtime_qualified": False, "qualification_claimed": False,
            "fault_apk_installed": False, "downgrade_or_uninstall_used": False,
            "settings_state_seeded": False, "container_stopped": stopped,
            "userdata_retained_path": str(self.state), "evidence_files": evidence}
        write_new(self.output / "report.json", report)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--product", required=True, type=Path)
    parser.add_argument("--packet", required=True, type=Path)
    parser.add_argument("--expected-receipt-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    product, packet = literal_directory(args.product), literal_directory(args.packet)
    output = args.output.absolute()
    require(output.resolve() == output and output.is_relative_to(ROOT / "android/out") and output != ROOT / "android/out" and
            not output.exists() and not output.is_symlink(), "Use a fresh literal android/out child")
    output.mkdir(mode=0o700, parents=True)
    producer = Producer(args.image, product, packet, args.expected_receipt_sha256, output)
    try:
        report = producer.execute()
        print(json.dumps(report, sort_keys=True))
    except Exception as error:
        try:
            producer.stop()
        except Exception as stop_error:
            producer.trace.append({"cleanup_error": str(stop_error)})
        try:
            if not (output / "commands.json").exists():
                write_new(output / "commands.json", producer.trace)
            write_new(output / "failure.json", {"status": "failed_not_qualified", "error": str(error),
                                                  "container": producer.container})
        except Exception:
            pass
        raise


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError,
            ET.ParseError, TimeoutError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        raise SystemExit(1)
