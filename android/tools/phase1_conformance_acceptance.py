#!/usr/bin/env python3
"""Independent auditor for the fresh-guest Phase-1 conformance lane.

The auditor reopens raw status/command/UI evidence, revalidates the full client
packet and custom product, reruns only offline image/APK identity checks, and
rejects downgrade, uninstall, settings seeding, product-APK substitution or an
unstated fault-injection claim.  It never starts Android.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "android/container"))
from build import inspect_image
from phase1_conformance_common import (BOOT_ID, IMAGE_ID, REPORT_KIND, REPORT_SCOPE, RUN,
    artifact_subset, canonical, canonical_sha256, file_ref, load, sha256, terminal_status_from_log,
    strict_object, validate_manifest, validate_status)
import phase1_emulator_client_packet as packet_tool

_builder_spec = importlib.util.spec_from_file_location("phase1_conformance_candidate_builder",
    ROOT / "android/container/build-phase1-conformance-candidate.py")
builder = importlib.util.module_from_spec(_builder_spec)
_builder_spec.loader.exec_module(builder)

SERIAL = "emulator-5580"
APP = "org.wonad.desktop"
FIXTURE = "org.wonad.fixture"
FAULT = "org.wonad.desktop.transitionfault"
LABEL = "org.wonad.phase1-fresh-conformance"
FIRST_APPLICATION_UID = 10000
LAST_APPLICATION_UID = 19999
HOME_ACTION = "android.intent.action.MAIN"
HOME_CATEGORY = "android.intent.category.HOME"
PHONE_HOME_ACTIVITIES = "phone-home-activities.txt"
PHONE_HOME_WINDOWS = "phone-home-windows.txt"
PROTECTED_PROCESS_NAMES = ("system_server", "com.android.systemui", "com.android.launcher3", "com.android.phone")
GUEST_OS_ARTIFACTS = {
    "com.android.systemui": "/system_ext/priv-app/SystemUI/SystemUI.apk",
    "os_broker_native": "/system_ext/lib64/libwonad_broker_jni.so",
    "os_input_native": "/system/lib64/libwonad_input_jni.so",
    "os_input_dispatcher": "/system/lib64/libinputflinger.so",
    "os_android_servers": "/system/lib64/libandroid_servers.so",
    "os_services": "/system/framework/services.jar",
    "os_framework": "/system/framework/framework.jar",
}
GUEST_OS_PATHS = set(GUEST_OS_ARTIFACTS.values())
EVIDENCE = {"after.json", "before.json", "commands.json", "conformance.log", "consent-hierarchy.xml",
            "display.txt", "image-manifest.json", "packet-receipt.json",
            "product-candidate-manifest.json", "protected-events.txt", "terminal-status.json",
            "prelaunch-userdata.json", PHONE_HOME_ACTIVITIES, PHONE_HOME_WINDOWS}


def require(value, message):
    if not value:
        raise ValueError(message)


def installed_apk_path(value):
    return isinstance(value, str) and re.fullmatch(
        r"/data/app/(?:[A-Za-z0-9_+=.~-]+/)+base\.apk", value) is not None and \
        all(part not in {".", ".."} for part in value.split("/"))


def parse_home_component(raw: str) -> tuple[str, str]:
    rows = raw.splitlines()
    match = re.fullmatch(
        r"([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)/"
        r"(\.[A-Za-z0-9_.$]+|[A-Za-z][A-Za-z0-9_.$]*)",
        rows[0] if len(rows) == 1 else "")
    require(match is not None and match.group(1) != "com.android.systemui",
            "Missing/ambiguous non-SystemUI user-0 HOME component")
    package, activity = match.groups()
    return rows[0], package + "/" + (package + activity if activity.startswith(".") else activity)


def phone_home_proof(component: str, full_component: str,
                     activities: str, windows: str):
    """Independently validate the sealed post-consent phone HOME observations."""
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
    require(re.findall(r"^[ \t]*mTopFocusedDisplayId=(\d+)[ \t]*$", windows, re.M) == ["0"],
            "WindowManager top focus is not uniquely display 0")
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


def traced_phone_home(adb_rows, directory: Path, enabled_index: int, boundary: int):
    """Bind the final successful raw HOME proof to its exact post-consent commands."""
    resolve = [
        (index, row) for index, command, row in adb_rows if command ==
        ["shell", "cmd", "package", "resolve-activity", "--components", "--user", "0",
         "-a", HOME_ACTION, "-c", HOME_CATEGORY]
    ]
    home = [
        (index, row) for index, command, row in adb_rows if command ==
        ["shell", "input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME"]
    ]
    activity_rows = [(index, row) for index, command, row in adb_rows
                     if command == ["shell", "dumpsys", "activity", "activities"]]
    window_rows = [(index, row) for index, command, row in adb_rows
                   if command == ["shell", "dumpsys", "window", "windows"]]
    require(len(resolve) == len(home) == 1 and activity_rows and
            len(activity_rows) == len(window_rows),
            "Missing/ambiguous post-consent phone HOME command sequence")
    component, full_component = parse_home_component(resolve[0][1].get("output", "").strip())
    require(enabled_index < resolve[0][0] < home[0][0] < activity_rows[0][0] and
            all(activity_rows[offset][0] + 1 == window_rows[offset][0] and
                window_rows[offset][0] < boundary
                for offset in range(len(activity_rows))) and
            home[0][1]["returncode"] == resolve[0][1]["returncode"] == 0 and
            window_rows[-1][1]["ended_monotonic_ns"] -
                home[0][1]["ended_monotonic_ns"] <= 15_000_000_000,
            "Phone HOME proof is misordered or exceeded fifteen seconds")
    sealed_activities = (directory / PHONE_HOME_ACTIVITIES).read_text()
    sealed_windows = (directory / PHONE_HOME_WINDOWS).read_text()
    valid = []
    for offset, ((activity_index, activity), (window_index, window)) in enumerate(
            zip(activity_rows, window_rows)):
        require(activity["returncode"] == window["returncode"] == 0,
                "Phone HOME proof observation failed")
        try:
            phone_home_proof(component, full_component,
                             activity.get("output", ""), window.get("output", ""))
        except ValueError:
            continue
        valid.append(offset)
    require(valid == [len(activity_rows) - 1] and
            activity_rows[-1][1].get("output") == sealed_activities and
            window_rows[-1][1].get("output") == sealed_windows,
            "Sealed phone HOME proof is stale, duplicated or differs from the final observation")
    return component


def prelaunch_userdata(directory: Path, row: dict, launch: dict, user: str):
    """Independently bind exclusive creation observations to retained inodes."""
    path = directory / "prelaunch-userdata.json"
    record = load(path)
    require(isinstance(record, dict) and set(record) == {
        "schema", "kind", "timeline", "state", "tmp", "inventory", "authority"} and
        type(record["schema"]) is int and record["schema"] == 1 and
        record["kind"] == "wonad-phase1-prelaunch-userdata-v1" and
        path.read_bytes() == canonical(record), "Malformed canonical prelaunch userdata record")
    require(row["output_sha256"] == sha256(path) and
            type(row["bytes"]) is int and row["bytes"] == path.stat().st_size,
            "Prelaunch userdata trace does not bind exact sealed bytes")
    timeline = record["timeline"]
    names = ("create_started_monotonic_ns", "state_created_monotonic_ns",
             "tmp_created_monotonic_ns", "inventory_observed_monotonic_ns")
    require(isinstance(timeline, dict) and set(timeline) == set(names) and
            all(type(timeline[name]) is int and timeline[name] > 0 for name in names) and
            [timeline[name] for name in names] == sorted(timeline[name] for name in names) and
            timeline[names[-1]] <= row["started_monotonic_ns"] <= row["ended_monotonic_ns"] <=
                launch["started_monotonic_ns"],
            "Prelaunch userdata was not created, inventoried and sealed before launch")
    require(record["inventory"] == [{"path": "tmp", "kind": "directory", "children": []}],
            "Prelaunch userdata inventory was not exactly an empty tmp directory")
    uid, gid = map(int, user.split(":"))
    for name, expected in (("state", directory / "emulator-state"),
                           ("tmp", directory / "emulator-state/tmp")):
        identity = record[name]
        observed = os.lstat(expected)
        require(isinstance(identity, dict) and set(identity) == {
            "path", "dev", "ino", "mode", "uid", "gid"} and
            all(type(identity[key]) is int for key in ("dev", "ino", "mode", "uid", "gid")) and
            stat.S_ISDIR(observed.st_mode) and not stat.S_ISLNK(observed.st_mode) and
            identity == {"path": str(expected), "dev": observed.st_dev, "ino": observed.st_ino,
                "mode": stat.S_IMODE(observed.st_mode), "uid": observed.st_uid, "gid": observed.st_gid} and
            identity["mode"] == 0o700 and identity["uid"] == uid and identity["gid"] == gid,
            "Retained userdata identity/ownership differs from exclusive prelaunch creation")
    source = ROOT / "android/tools/phase1_conformance_guest.py"
    authority = {"path": "android/tools/phase1_conformance_guest.py", **file_ref(source)}
    require(record["authority"] == {"runner": authority, "guest_common": authority},
            "Prelaunch userdata does not bind the reviewed API guest implementation")
    return record


def inspected_container(row: dict, report: dict, directory: Path, user: str, kvm_group: str):
    values = json.loads(row.get("output", ""), object_pairs_hook=strict_object)
    require(isinstance(values, list) and len(values) == 1 and isinstance(values[0], dict),
            "Ambiguous owned-container inspection")
    info = values[0]
    config, host, state = info.get("Config", {}), info.get("HostConfig", {}), info.get("State", {})
    require(all(isinstance(value, dict) for value in (config, host, state)) and
            isinstance(info.get("Mounts"), list) and len(info["Mounts"]) == 1,
            "Malformed owned-container identity/isolation")
    require(all(key in host for key in ("CapAdd", "DeviceRequests", "DeviceCgroupRules", "PidMode",
            "IpcMode", "CgroupnsMode", "UTSMode", "UsernsMode", "VolumesFrom", "MemorySwap",
            "ReadonlyRootfs", "AutoRemove", "RestartPolicy", "PublishAllPorts", "MemoryReservation",
            "PortBindings")) and
            host["CapAdd"] in (None, []) and host["DeviceRequests"] in (None, []) and
            host["DeviceCgroupRules"] in (None, []) and host["VolumesFrom"] in (None, []) and
            host["PidMode"] == host["UTSMode"] == host["UsernsMode"] == "" and
            host["IpcMode"] == host["CgroupnsMode"] == "private" and
            host["MemorySwap"] == 16 * 1024**3 and host["ReadonlyRootfs"] is False and
            host["AutoRemove"] is False and host["PublishAllPorts"] is False and
            type(host["MemoryReservation"]) is int and host["MemoryReservation"] == 0 and
            host["PortBindings"] in (None, {}) and
            isinstance(host["RestartPolicy"], dict) and
            type(host["RestartPolicy"].get("MaximumRetryCount")) is int and
            host["RestartPolicy"] == {"Name": "no", "MaximumRetryCount": 0},
            "Owned-container privilege/namespace/swap isolation changed")
    mount = info["Mounts"][0]
    limits = host.get("Ulimits")
    require(isinstance(limits, list) and len(limits) == 2 and
            all(isinstance(item, dict) and set(item) == {"Name", "Hard", "Soft"} and
                isinstance(item["Name"], str) and type(item["Hard"]) is int and
                type(item["Soft"]) is int for item in limits),
            "Malformed owned-container resource limits")
    require(info.get("Id") == report["container"] and info.get("Image") == report["image_id"] and
            config.get("Labels", {}).get(LABEL) == report["container_run"] and config.get("User") == user and
            isinstance(mount, dict) and mount.get("Destination") == "/state" and
            mount.get("Source") == str(directory / "emulator-state") and mount.get("RW") is True and
            mount.get("Type") == "bind" and mount.get("Mode") == "rw,Z" and
            mount.get("Propagation") == "rprivate" and
            host.get("Binds") == [str(directory / "emulator-state") + ":/state:rw,Z"] and
            host.get("NetworkMode") == "none" and host.get("Privileged") is False and
            not host.get("PortBindings") and host.get("CapDrop") == ["ALL"] and
            host.get("SecurityOpt") == ["no-new-privileges=true"] and host.get("GroupAdd") == [kvm_group] and
            host.get("Devices") == [{"PathOnHost": "/dev/kvm", "PathInContainer": "/dev/kvm",
                                    "CgroupPermissions": "rwm"}] and
            host.get("PidsLimit") == 1024 and host.get("Memory") == 8 * 1024 ** 3 and
            host.get("NanoCpus") == 12_000_000_000 and host.get("ShmSize") == 512 * 1024 ** 2 and
            host.get("Tmpfs") == {"/tmp": "rw,nosuid,nodev,size=2g"} and
            sorted(limits, key=lambda item: item["Name"]) == [
                {"Name": "core", "Hard": 0, "Soft": 0},
                {"Name": "nofile", "Hard": 65536, "Soft": 65536}] and
            type(state.get("Running")) is bool,
            "Owned-container identity/isolation/resource profile changed")
    return state["Running"]


def literal_directory(path: Path) -> Path:
    raw = path.absolute()
    require(raw.resolve(strict=True) == raw and raw.is_dir() and not raw.is_symlink(),
            "Select one literal existing directory: " + str(raw))
    return raw


def bind_files(directory: Path, records: dict):
    entries = list(directory.iterdir())
    require(all(path.name == "report.json" or path.name in EVIDENCE or
                path.name == "emulator-state" for path in entries),
            "Unexpected fresh-guest evidence path")
    actual = {path.name: file_ref(path) for path in entries
              if path.name in EVIDENCE}
    require(set(actual) == EVIDENCE and actual == records,
            "Fresh-guest evidence file set/bytes changed")
    directories = [path for path in directory.iterdir() if path.is_dir()]
    require(len(directories) == 1 and directories[0].name == "emulator-state" and
            not directories[0].is_symlink(), "Unexpected or missing retained userdata directory")


def candidate_offline(image: str, expected: dict):
    require(IMAGE_ID.fullmatch(str(image)) and inspect_image(image)["Id"] == image,
            "Conformance report image is unavailable or mutable")
    output = subprocess.check_output(["docker", "run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,size=64m", image, "verify"], text=True, timeout=120)
    banner, separator, document = output.partition("\n")
    require(banner == "Verifying fresh-guest Phase-1 conformance candidate…" and separator and
            json.loads(document, object_pairs_hook=strict_object) == expected,
            "Current candidate offline verifier differs from sealed evidence")
    subprocess.run(["docker", "run", "--rm", "--network", "none", "--read-only",
        "--entrypoint", "/bin/sh", image, "-ec", "test ! -e /opt/wonad/wonad.apk"], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)


def reviewed_adb_command(command: list[str], report: dict) -> bool:
    """Bound the producer's direct adb surface; the conformance child is source-bound separately."""
    remote = "/data/local/tmp/wonad-phase1-consent-" + report["container_run"] + ".xml"
    exact = {
        ("shell", "getprop", "sys.boot_completed"),
        ("shell", "getprop", "ro.build.fingerprint"),
        ("shell", "getprop", "ro.product.cpu.abi"),
        ("shell", "getenforce"),
        ("shell", "cat", "/proc/sys/kernel/random/boot_id"),
        ("shell", "am", "get-current-user"),
        ("shell", "pm", "list", "users"),
        ("shell", "dumpsys", "display"),
        ("shell", "dumpsys", "activity", "service", "com.android.systemui/.SystemUIService"),
        ("shell", "dumpsys", "activity", "service", APP + "/.ConformanceService"),
        ("emu", "multidisplay", "add", "1", "1920", "1080", "160", "132165"),
        ("shell", "settings", "--user", "0", "get", "secure", "wonad_external_desktop_enabled"),
        ("shell", "am", "start", "-W", "--display", "0", "-n",
         "com.android.systemui/org.wonad.desktop.broker.WonadSettingsActivity"),
        ("shell", "cmd", "package", "resolve-activity", "--components", "--user", "0",
         "-a", HOME_ACTION, "-c", HOME_CATEGORY),
        ("shell", "input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME"),
        ("shell", "dumpsys", "activity", "activities"),
        ("shell", "dumpsys", "window", "windows"),
        ("shell", "input", "keyboard", "-d", "0", "keyevent", "KEYCODE_WAKEUP"),
        ("shell", "input", "touchscreen", "-d", "0", "swipe", "540", "1800", "540", "400", "600"),
        ("shell", "uiautomator", "dump", "--compressed", remote),
        ("exec-out", "cat", remote),
        ("shell", "rm", "--", remote),
        ("shell", "logcat", "-b", "events", "-d", "-v", "threadtime",
         "am_anr:I", "am_crash:I", "*:S"),
    }
    if tuple(command) in exact:
        return True
    if command[:8] == ["shell", "cmd", "package", "list", "packages", "-U", "--user", "0"]:
        if len(command) == 9:
            return command[8] in {APP, FIXTURE}
        if len(command) == 10 and command[8] == "--uid":
            return re.fullmatch(r"[0-9]+", command[9]) is not None
        return False
    if command[:3] == ["shell", "pm", "path"] and len(command) == 4:
        return command[3] in (APP, FIXTURE, FAULT)
    if command[:3] == ["install", "--user", "0"] and len(command) == 4:
        return command[3] in ("/opt/wonad/phase1-conformance/fixture.apk",
                              "/opt/wonad/phase1-conformance/conformance.apk")
    if command[:2] == ["shell", "sha256sum"] and len(command) == 3:
        return command[2] in GUEST_OS_PATHS or installed_apk_path(command[2])
    if command[:2] == ["shell", "pidof"] and len(command) == 3:
        return command[2] in PROTECTED_PROCESS_NAMES
    if command[:3] == ["shell", "su", "0"] and len(command) == 5 and command[3] == "cat":
        return re.fullmatch(r"/proc/[1-9][0-9]*/stat", command[4]) is not None
    if command[:6] == ["shell", "input", "touchscreen", "-d", "0", "tap"] and len(command) == 8:
        return all(re.fullmatch(r"[0-9]+", item) for item in command[6:])
    return False


def parse_trace(path: Path, report: dict, directory: Path):
    trace = load(path)
    require(isinstance(trace, list) and trace, "Missing command trace")
    remote = "/data/local/tmp/wonad-phase1-consent-" + report["container_run"] + ".xml"
    prior = 0
    adb_rows, installs, starts, taps, conformance, stops, final_inspects, launches = [], [], [], [], [], [], [], []
    ui_dumps, ui_reads, ui_removals = [], [], []
    verifier_runs, manifest_reads, local_rows = [], [], []
    for ordinal, row in enumerate(trace):
        if isinstance(row, dict) and row.get("kind") == "local_evidence":
            require(set(row) == {"kind", "name", "started_monotonic_ns", "ended_monotonic_ns",
                                "evidence", "output_sha256", "bytes"} and
                    row["name"] == "prelaunch_userdata" and row["evidence"] == "prelaunch-userdata.json" and
                    type(row["started_monotonic_ns"]) is int and type(row["ended_monotonic_ns"]) is int and
                    prior <= row["started_monotonic_ns"] <= row["ended_monotonic_ns"],
                    "Malformed/overlapping local prelaunch evidence trace")
            prior = row["ended_monotonic_ns"]
            local_rows.append((ordinal, row))
            continue
        timeout = isinstance(row, dict) and row.get("timed_out") is True
        require(isinstance(row, dict) and set(row) in (
            {"argv", "returncode", "started_monotonic_ns", "ended_monotonic_ns", "output"},
            {"argv", "returncode", "started_monotonic_ns", "ended_monotonic_ns", "evidence", "output_sha256"},
            {"argv", "returncode", "started_monotonic_ns", "ended_monotonic_ns", "output", "timed_out",
             "timeout_seconds"}) and
            isinstance(row["argv"], list) and row["argv"] and all(isinstance(item, str) for item in row["argv"]) and
            ((not timeout and type(row["returncode"]) is int and row["returncode"] in (0, 1)) or
             (timeout and row["returncode"] is None and type(row["timeout_seconds"]) is int and
              row["timeout_seconds"] == 10 and row["argv"] ==
                ["docker", "exec", report["container"], "adb", "-s", SERIAL,
                 "shell", "getprop", "sys.boot_completed"])) and
            ("timed_out" not in row or timeout) and
            ("output" not in row or isinstance(row["output"], str)) and
            type(row["started_monotonic_ns"]) is int and type(row["ended_monotonic_ns"]) is int and
            prior <= row["started_monotonic_ns"] <= row["ended_monotonic_ns"], "Malformed/overlapping command trace")
        require(not timeout or row["ended_monotonic_ns"] - row["started_monotonic_ns"] >= 10_000_000_000,
                "Typed Android boot timeout did not observe its ten-second deadline")
        prior = row["ended_monotonic_ns"]
        if "evidence" in row:
            require(row["evidence"] in {"conformance.log", "protected-events.txt"} and
                    row["output_sha256"] == sha256(directory / row["evidence"]),
                    "Command externalized unbound evidence")
        argv = row["argv"]
        if argv[:3] == ["docker", "run", "-d"]:
            launches.append((ordinal, argv))
        elif argv == ["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs",
                      "/tmp:rw,nosuid,size=64m", report["image_id"], "verify"]:
            verifier_runs.append((ordinal, argv))
        elif argv == ["docker", "run", "--rm", "--network", "none", "--read-only", "--entrypoint",
                      "cat", report["image_id"], "/opt/wonad/product-candidate-manifest.json"]:
            manifest_reads.append((ordinal, argv))
        if argv[:3] == ["docker", "container", "inspect"]:
            require(argv == ["docker", "container", "inspect", report["container"]],
                    "Trace inspected a foreign container")
            final_inspects.append((ordinal, row))
        if argv[:2] == ["docker", "stop"]:
            stops.append((ordinal, argv))
        if argv[:4] == ["docker", "exec", report["container"], "adb"]:
            index = 3
            require(argv[index:index + 3] == ["adb", "-s", SERIAL], "Host command used a different adb target")
            command = argv[index + 3:]
            adb_rows.append((ordinal, command, row))
            lowered = [item.lower() for item in command]
            require(not (command[:1] == ["uninstall"] or "--downgrade" in lowered or
                         (command[:1] == ["install"] and "-d" in lowered) or
                         command[:3] in (["shell", "pm", "clear"], ["shell", "pm", "uninstall"]) or
                         command[:5] in (["shell", "settings", "--user", "0", "put"],
                                         ["shell", "settings", "--user", "0", "delete"],
                                         ["shell", "settings", "--user", "0", "reset"])),
                    "Trace used downgrade/uninstall/data-clear/settings seeding")
            if command[:1] == ["install"]:
                require("-r" not in command and "--replace" not in command, "Fresh install silently became replacement")
                installs.append((ordinal, command))
            require(reviewed_adb_command(command, report),
                    "Trace contains an unreviewed direct adb operation")
            if command[:4] == ["shell", "am", "start", "-W"]:
                starts.append((ordinal, command))
            if command[:5] == ["shell", "input", "touchscreen", "-d", "0"] and "tap" in command:
                taps.append((ordinal, command))
            if command == ["shell", "uiautomator", "dump", "--compressed", remote]:
                ui_dumps.append((ordinal, row))
            if command == ["exec-out", "cat", remote]:
                ui_reads.append((ordinal, row))
            if command == ["shell", "rm", "--", remote]:
                ui_removals.append((ordinal, row))
            if row["returncode"] != 0:
                require(command[:3] == ["shell", "pm", "path"] or
                        command == ["shell", "getprop", "sys.boot_completed"] or
                        command == ["shell", "rm", "--", remote],
                        "A required direct adb observation/action failed")
        if argv[:4] == ["docker", "exec", report["container"], "python3"]:
            if len(argv) > 4 and argv[4] == "/opt/wonad/phase1-conformance/conformance_smoke.py":
                conformance.append((ordinal, argv))
        if argv[:3] == ["docker", "exec", report["container"]]:
            require(argv[:4] == ["docker", "exec", report["container"], "adb"] or
                    argv[:4] == ["docker", "exec", report["container"], "python3"],
                    "Trace contains an unreviewed direct command in the guest container")
        if argv[:2] == ["docker", "run"]:
            require(argv[:3] == ["docker", "run", "-d"] or
                    any(argv == recorded for _, recorded in verifier_runs + manifest_reads),
                    "Trace contains an unreviewed auxiliary container run")
        require(argv[:1] == ["docker"] and (
            argv[:2] == ["docker", "run"] or
            argv[:3] == ["docker", "container", "inspect"] or
            argv[:3] == ["docker", "exec", report["container"]] or
            argv[:2] == ["docker", "stop"]),
            "Trace contains an unreviewed host/container operation")
        if row["returncode"] != 0:
            require(argv[:4] == ["docker", "exec", report["container"], "adb"],
                    "A required Docker operation failed")

    require(len(verifier_runs) == 1 and len(manifest_reads) == 1 and len(launches) == 1,
            "Trace lacks the exact pre-boot offline identity reads")
    launch_index, launch = launches[0]
    verifier_index, _ = verifier_runs[0]
    manifest_index, _ = manifest_reads[0]
    require(verifier_index < manifest_index < launch_index,
            "Offline candidate verifier/manifest reads did not precede guest launch")
    require(len(local_rows) == 1 and local_rows[0][0] == launch_index - 1 and
            manifest_index < local_rows[0][0] and
            trace[launch_index].get("output", "").strip() == report["container"],
            "Trace lacks the exact prelaunch seal/owned Docker launch identity")
    banner, separator, document = trace[verifier_index].get("output", "").partition("\n")
    require(banner == "Verifying fresh-guest Phase-1 conformance candidate…" and separator and
            json.loads(document, object_pairs_hook=strict_object) == load(directory / "image-manifest.json") and
            json.loads(trace[manifest_index].get("output", ""), object_pairs_hook=strict_object) ==
                load(directory / "product-candidate-manifest.json"),
            "Raw offline candidate/manifest readback differs from sealed identities")
    try:
        kvm_group = launch[launch.index("--group-add") + 1]
        user = launch[launch.index("--user") + 1]
    except (ValueError, IndexError) as error:
        raise ValueError("Trace lacks the bounded KVM/user identity") from error
    require(re.fullmatch(r"[0-9]+", kvm_group) and re.fullmatch(r"[0-9]+:[0-9]+", user),
            "Trace has an invalid KVM/user identity")
    expected_launch = ["docker", "run", "-d", "--name",
        "wonad-phase1-conformance-" + report["container_run"][:12],
        "--label", LABEL + "=" + report["container_run"], "--network", "none",
        "--device", "/dev/kvm", "--group-add", kvm_group, "--user", user,
        "--cap-drop=ALL", "--security-opt", "no-new-privileges=true", "--pids-limit", "1024",
        "--memory", "8g", "--cpus", "12", "--shm-size", "512m",
        "--ulimit", "nofile=65536:65536", "--ulimit", "core=0:0",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=2g",
        "--volume", str(directory / "emulator-state") + ":/state:rw,Z",
        "--env", "HOME=/state", "--env", "TMPDIR=/state/tmp",
        "--env", "WONAD_VIEWER_TRANSPORT=vnc", "--entrypoint", "python3",
        report["image_id"], "/opt/wonad/session.py"]
    require(launch == expected_launch, "Trace lacks one isolated exact-image/fresh-state guest launch")
    prelaunch = prelaunch_userdata(directory, local_rows[0][1], trace[launch_index], user)
    require(trace[manifest_index]["ended_monotonic_ns"] <=
                prelaunch["timeline"]["create_started_monotonic_ns"],
            "Fresh userdata was created before offline product verification")
    require(len(installs) == 2 and [row[1] for row in installs] == [
        ["install", "--user", "0", "/opt/wonad/phase1-conformance/fixture.apk"],
        ["install", "--user", "0", "/opt/wonad/phase1-conformance/conformance.apk"],
    ], "Trace lacks the two exact non-replacement fresh installs")
    require(not any("fault.apk" in item for _, argv, _ in adb_rows for item in argv),
            "Fault APK was used by the positive conformance lane")
    package_checks = {package: [(index, row) for index, command, row in adb_rows
        if command == ["shell", "pm", "path", package]] for package in (APP, FIXTURE, FAULT)}
    require(all(package_checks.values()) and max(rows[0][0] for rows in package_checks.values()) < installs[0][0] and
            all(rows[0][1].get("output", "").strip() == "" for rows in package_checks.values()),
            "Package absence was not observed before either fresh install")
    require(any(command == ["shell", "am", "start", "-W", "--display", "0", "-n",
                                 "com.android.systemui/org.wonad.desktop.broker.WonadSettingsActivity"]
                for _, command in starts), "Real SystemUI consent Activity was not launched")
    require(len(conformance) == 1 and conformance[0][1] ==
            ["docker", "exec", report["container"], "python3",
             "/opt/wonad/phase1-conformance/conformance_smoke.py", "--adb", "adb", "--serial", SERIAL,
             "--display-id", str(report["display_id"]), "--timeout", "360"],
            "Conformance did not use already-fresh exact installs")
    conformance_index = conformance[0][0]
    attach = [(index, command) for index, command, _ in adb_rows if command ==
              ["emu", "multidisplay", "add", "1", "1920", "1080", "160", "132165"]]
    require(len(attach) == 1 and launch_index < attach[0][0] < installs[0][0] < conformance_index,
            "Trace lacks the exact pre-install external display attachment")
    display_raw = (directory / "display.txt").read_text()
    display_rows = [(index, row.get("output", "")) for index, command, row in adb_rows
                    if command == ["shell", "dumpsys", "display"] and row.get("output") == display_raw]
    all_display_rows = [index for index, command, _ in adb_rows
                        if command == ["shell", "dumpsys", "display"]]
    display_ids = sorted({int(value) for value in re.findall(r"\bmDisplayId\s*=\s*(\d+)\b", display_raw)})
    require(display_rows and all_display_rows[-1] == display_rows[-1][0] and
            display_rows[-1][0] < installs[0][0] and 0 in display_ids and
            [value for value in display_ids if value > 0] == [report["display_id"]],
            "Raw display evidence does not prove exactly one selected external display")
    consent_start = [index for index, command in starts if command ==
        ["shell", "am", "start", "-W", "--display", "0", "-n",
         "com.android.systemui/org.wonad.desktop.broker.WonadSettingsActivity"]]
    consent_taps = [(index, command) for index, command in taps]
    setting_reads = [(index, row.get("output", "").strip()) for index, command, row in adb_rows if command ==
        ["shell", "settings", "--user", "0", "get", "secure", "wonad_external_desktop_enabled"]]
    require(len(consent_start) == 1 and len(consent_taps) == 1 and
            len(ui_dumps) == len(ui_reads) == len(ui_removals) == 1 and
            any(installs[-1][0] < index < consent_start[0] and value != "1"
                for index, value in setting_reads) and
            consent_start[0] < ui_dumps[0][0] < ui_reads[0][0] < ui_removals[0][0] <
                consent_taps[0][0] < conformance_index and
            ui_reads[0][1].get("output", "").strip() ==
                (directory / "consent-hierarchy.xml").read_text() and
            any(consent_taps[0][0] < index < conformance_index and value == "1"
                for index, value in setting_reads),
            "Trace does not prove disabled-to-enabled consent through the genuine phone UI")
    enabled = [(index, value) for index, value in setting_reads
               if consent_taps[0][0] < index < conformance_index and value == "1"]
    require(enabled, "Trace lacks post-tap consent enablement")
    traced_phone_home(adb_rows, directory, enabled[0][0], conformance_index)
    event_commands = [row for row in trace if row.get("evidence") == "protected-events.txt"]
    require(len(event_commands) == 1 and event_commands[0]["argv"] ==
            ["docker", "exec", report["container"], "adb", "-s", SERIAL, "shell", "logcat", "-b",
             "events", "-d", "-v", "threadtime", "am_anr:I", "am_crash:I", "*:S"],
            "Protected crash/ANR event readback is missing/ambiguous")
    require(len(stops) == 1 and stops[0][1] == ["docker", "stop", "-t", "30", report["container"]],
            "Owned container stop is missing/ambiguous")
    require(final_inspects and conformance_index < stops[0][0] < final_inspects[-1][0] == len(trace) - 1 and
            trace[stops[0][0]].get("output", "").strip() == report["container"],
            "Owned container stop did not precede its terminal inspection")
    boot_polls = [index for index, command, _ in adb_rows
                  if command == ["shell", "getprop", "sys.boot_completed"]]
    expected_inspections = [launch_index + 1, *[index - 1 for index in boot_polls],
                            stops[0][0] - 1, len(trace) - 1]
    require(boot_polls and len(set(expected_inspections)) == len(boot_polls) + 3 and
            [index for index, _ in final_inspects] == expected_inspections,
            "Raw running/boot/pre-stop container inspection chronology changed")
    require(stops[0][0] - 2 == next(index for index, row in enumerate(trace)
                                  if row.get("evidence") == "protected-events.txt"),
            "Protected events were not read after terminal state and immediately before owned shutdown")
    states = [inspected_container(row, report, directory, user, kvm_group)
              for _, row in final_inspects]
    require(states[:-1] == [True] * (len(states) - 1) and states[-1] is False,
            "Raw owned-container running/stopped state contradicted guest execution")
    return [row for row in trace if row.get("kind") != "local_evidence"]


def traced_protected_epochs(trace: list[dict], report: dict) -> dict:
    """Reconstruct both protected-process epochs from raw pidof/proc commands."""
    prefix = ["docker", "exec", report["container"], "adb", "-s", SERIAL]
    conformance = [index for index, row in enumerate(trace)
                   if row["argv"][:4] == ["docker", "exec", report["container"], "python3"] and
                   len(row["argv"]) > 4 and
                   row["argv"][4] == "/opt/wonad/phase1-conformance/conformance_smoke.py"]
    require(len(conformance) == 1, "Cannot divide protected-process observations around conformance")
    boundary = conformance[0]
    names = PROTECTED_PROCESS_NAMES
    result = {"before": {}, "after": {}}
    positions = {"before": {}, "after": {}}
    consumed_stats = set()
    all_stats = set()
    for index, row in enumerate(trace):
        argv = row["argv"]
        if argv[:len(prefix) + 4] == prefix + ["shell", "su", "0", "cat"]:
            all_stats.add(index)
        for name in names:
            if argv != prefix + ["shell", "pidof", name]:
                continue
            require(row["returncode"] == 0 and index + 1 < len(trace),
                    "Protected pid observation failed: " + name)
            pid_text = row.get("output", "").strip()
            require(re.fullmatch(r"[1-9][0-9]*", pid_text) is not None,
                    "Protected pid observation is missing/ambiguous: " + name)
            pid = int(pid_text)
            stat = trace[index + 1]
            expected = prefix + ["shell", "su", "0", "cat", f"/proc/{pid}/stat"]
            require(stat["argv"] == expected and stat["returncode"] == 0,
                    "Protected pid/proc observation pair changed: " + name)
            match = re.fullmatch(r"([1-9][0-9]*) \(.*\) [A-Z] (.+)\n?", stat.get("output", ""))
            fields = match[2].split() if match is not None else []
            require(match is not None and int(match[1]) == pid and len(fields) > 18 and
                    re.fullmatch(r"[1-9][0-9]*", fields[18]) is not None,
                    "Protected process epoch is malformed: " + name)
            side = "before" if index < boundary else "after"
            require(name not in result[side], "Duplicate protected process epoch: " + side + "/" + name)
            result[side][name] = {"pid": pid, "start_ticks": int(fields[18])}
            positions[side][name] = index
            consumed_stats.add(index + 1)
    attach = [index for index, row in enumerate(trace)
              if row["argv"] == prefix + ["emu", "multidisplay", "add", "1", "1920", "1080", "160", "132165"]]
    require(all(set(value) == set(names) for value in result.values()) and
            consumed_stats == all_stats and len(attach) == 1 and
            max(positions["before"].values(), default=boundary) < attach[0] < boundary and
            min(positions["after"].values(), default=boundary) > boundary,
            "Incomplete or unpaired protected-process continuity evidence")
    return result


def state(value, *, before, manifest, report):
    required = {"boot_id", "fingerprint", "abi", "enforcing", "current_user", "consent", "packages",
                "protected_processes", "display_id", "installed", "consent_point", "os_artifacts"}
    require(isinstance(value, dict) and set(value) == required and BOOT_ID.fullmatch(str(value["boot_id"])) and
            value["fingerprint"] == manifest["fingerprint"] and value["abi"] == "x86_64" and
            value["enforcing"] == "Enforcing" and value["current_user"] == "0" and value["consent"] == "1" and
            value["display_id"] == report["display_id"] and value["os_artifacts"] == manifest["os_artifacts"] and
            isinstance(value["protected_processes"], dict) and set(value["protected_processes"]) ==
                set(PROTECTED_PROCESS_NAMES) and
            all(isinstance(epoch, dict) and set(epoch) == {"pid", "start_ticks"} and
                type(epoch["pid"]) is int and epoch["pid"] > 0 and
                type(epoch["start_ticks"]) is int and epoch["start_ticks"] > 0
                for epoch in value["protected_processes"].values()) and
            len({epoch["pid"] for epoch in value["protected_processes"].values()}) == len(PROTECTED_PROCESS_NAMES),
            "Malformed fresh-guest state evidence")
    require(isinstance(value["packages"], dict) and set(value["packages"]) == {APP, FIXTURE, FAULT} and
            isinstance(value["installed"], dict) and set(value["installed"]) ==
                ({APP, FIXTURE} if before else {APP, FIXTURE, FAULT}),
            "Malformed installed package state")
    for package, role in ((APP, "conformance"), (FIXTURE, "fixture")):
        installed = value["installed"][package]
        require(isinstance(installed, dict) and set(installed) == {"path", "sha256"} and
                installed_apk_path(installed["path"]) and
                installed["sha256"] == manifest["artifacts"][role]["sha256"] and
                (before or value["packages"][package] == installed["path"]),
                "Installed package identity differs from exact candidate: " + package)
    require(value["installed"][APP]["path"] != value["installed"][FIXTURE]["path"],
            "Distinct installed packages share one APK path")
    if before:
        require(value["packages"] == {APP: None, FIXTURE: None, FAULT: None} and
                isinstance(value["consent_point"], list) and len(value["consent_point"]) == 2 and
                all(type(item) is int for item in value["consent_point"]) and
                isinstance(value["installed"], dict) and set(value["installed"]) == {APP, FIXTURE},
                "Fresh guest did not begin from absent target packages or genuine UI consent")
    else:
        require(value["consent_point"] is None and value["packages"][FAULT] is None and
                value["installed"].get(FAULT) is None and
                value["installed"][APP]["sha256"] == manifest["artifacts"]["conformance"]["sha256"] and
                value["installed"][FIXTURE]["sha256"] == manifest["artifacts"]["fixture"]["sha256"],
                "Terminal installed package identities changed")
    return value


def traced_guest_state(trace, report, before, after, manifest):
    """Reconstruct identity/OS and installed APKs, never trust state summaries."""
    prefix = ["docker", "exec", report["container"], "adb", "-s", SERIAL]
    boundary = next(index for index, row in enumerate(trace) if row["argv"][:5] ==
        ["docker", "exec", report["container"], "python3",
         "/opt/wonad/phase1-conformance/conformance_smoke.py"])
    commands = [
        ("boot_id", ["shell", "cat", "/proc/sys/kernel/random/boot_id"]),
        ("fingerprint", ["shell", "getprop", "ro.build.fingerprint"]),
        ("abi", ["shell", "getprop", "ro.product.cpu.abi"]),
        ("enforcing", ["shell", "getenforce"]),
        ("current_user", ["shell", "am", "get-current-user"]),
        ("consent", ["shell", "settings", "--user", "0", "get", "secure",
                     "wonad_external_desktop_enabled"]),
    ]
    boot_rows = [index for index, row in enumerate(trace)
                 if row["argv"] == prefix + commands[0][1]]
    require(len(boot_rows) == 2 and boot_rows[0] < boundary < boot_rows[1],
            "Missing/ambiguous raw guest identity bundles around conformance")
    for offset, (_, command) in enumerate(commands[:4]):
        actual = {index for index, row in enumerate(trace) if row["argv"] == prefix + command}
        require(actual == {start + offset for start in boot_rows},
                "Extra or missing raw guest identity observation: " + command[-1])
    consumed_hashes = set()
    for side, start, summary in zip(("before", "after"), boot_rows, (before, after)):
        length = len(commands) + len(GUEST_OS_ARTIFACTS)
        require(start + length <= len(trace) and
                (start + length <= boundary if side == "before" else start > boundary),
                "Raw guest identity bundle crosses the conformance boundary")
        for offset, (field, command) in enumerate(commands):
            row = trace[start + offset]
            require(row["argv"] == prefix + command and row["returncode"] == 0 and
                    isinstance(row.get("output"), str) and row["output"].strip() == summary[field],
                    "Raw guest identity differs from summary: " + side + "/" + field)
        for offset, (role, path) in enumerate(GUEST_OS_ARTIFACTS.items(), len(commands)):
            row = trace[start + offset]
            require(row["argv"] == prefix + ["shell", "sha256sum", path] and
                    row["returncode"] == 0 and isinstance(row.get("output"), str) and
                    row["output"].strip().split() == [summary["os_artifacts"][role], path],
                    "Raw guest OS bytes differ from summary: " + side + "/" + role)
            consumed_hashes.add(start + offset)

    installed_at = {}
    for package, role in ((FIXTURE, "fixture"), (APP, "conformance")):
        installs = [index for index, row in enumerate(trace) if row["argv"] ==
                    prefix + ["install", "--user", "0", "/opt/wonad/phase1-conformance/" + role + ".apk"]]
        require(len(installs) == 1, "Missing/ambiguous installed package: " + package)
        install = installs[0]
        installed_at[package] = install
        require(install + 2 < boot_rows[0] and trace[install]["returncode"] == 0 and
                "Success" in trace[install].get("output", "").splitlines(),
                "Fresh installed APK lacks successful native installation")
        path_row, hash_row = trace[install + 1:install + 3]
        path = before["installed"][package]["path"]
        require(path_row["argv"] == prefix + ["shell", "pm", "path", package] and
                path_row["returncode"] == 0 and path_row.get("output", "").strip() == "package:" + path and
                hash_row["argv"] == prefix + ["shell", "sha256sum", path] and
                hash_row["returncode"] == 0 and hash_row.get("output", "").strip().split() ==
                    [before["installed"][package]["sha256"], path] and
                after["installed"][package] == before["installed"][package],
                "Installed APK summary differs from raw fresh-install path/bytes: " + package)
        consumed_hashes.add(install + 2)
        checks = [(index, row) for index, row in enumerate(trace)
                  if row["argv"] == prefix + ["shell", "pm", "path", package]]
        require(checks and all(
            row.get("output", "").strip() == ("" if index < install else "package:" + path)
            for index, row in checks), "Raw installed package path changed: " + package)
        terminal_checks = [(index, row) for index, row in checks if boundary < index < boot_rows[1]]
        hashes = [(index, row) for index, row in enumerate(trace) if boundary < index < boot_rows[1] and
                  row["argv"] == prefix + ["shell", "sha256sum", path]]
        require(len(terminal_checks) == len(hashes) == 1 and
                terminal_checks[0][0] < hashes[0][0] and hashes[0][1]["returncode"] == 0 and
                hashes[0][1].get("output", "").strip().split() ==
                    [after["installed"][package]["sha256"], path],
                "Missing/changed terminal installed APK readback: " + package)
        consumed_hashes.add(hashes[0][0])

    # The exact package bytes bind the signer/no-shared-UID manifest identity;
    # these native PackageManager reads independently bind its assigned user-0
    # UID and prove no other installed package owns that UID.
    identity_prefix = prefix + ["shell", "cmd", "package", "list", "packages"]
    identity_rows = [(index, row) for index, row in enumerate(trace)
                     if row["argv"][:len(identity_prefix)] == identity_prefix]
    observed_uids = {}
    after_both_installs = max(installed_at.values()) + 2
    for package, role in ((FIXTURE, "fixture"), (APP, "conformance")):
        forward_argv = identity_prefix + ["-U", "--user", "0", package]
        forwards = [(index, row) for index, row in identity_rows if row["argv"] == forward_argv]
        require(len(forwards) == 1 and forwards[0][1]["returncode"] == 0 and
                after_both_installs < forwards[0][0] < boot_rows[0],
                "Missing/misordered raw user-0 package UID: " + package)
        lines = forwards[0][1].get("output", "").splitlines()
        match = re.fullmatch(r"package:" + re.escape(package) + r" uid:(\d+)",
                             lines[0] if len(lines) == 1 else "")
        require(match is not None, "Ambiguous raw user-0 package UID: " + package)
        uid = int(match.group(1))
        require(FIRST_APPLICATION_UID <= uid <= LAST_APPLICATION_UID,
                "Installed client lacks an ordinary application UID for active user 0: " + package)
        reverse_argv = identity_prefix + ["-U", "--user", "0", "--uid", str(uid)]
        reverse = [(index, row) for index, row in identity_rows if row["argv"] == reverse_argv]
        require(len(reverse) == 1 and forwards[0][0] < reverse[0][0] < boot_rows[0] and
                reverse[0][1]["returncode"] == 0 and
                reverse[0][1].get("output", "").splitlines() == lines,
                "Package UID is shared, cross-user or not reverse-bound: " + package)
        artifact = manifest["artifacts"][role]
        require(before["installed"][package]["sha256"] == artifact["sha256"] and
                artifact["shared_uid"] is False and artifact["privileged_manifest"] is False and
                (package != APP or artifact["certificate_der_sha256"] ==
                    manifest["artifacts"]["wonad"]["certificate_der_sha256"]),
                "Package UID is not joined to the exact normal signed APK: " + package)
        observed_uids[package] = uid
    require(len(set(observed_uids.values())) == 2 and len(identity_rows) == 4,
            "Client/fixture UID alias or unpaired package identity observation")

    fault = [(index, row) for index, row in enumerate(trace)
             if row["argv"] == prefix + ["shell", "pm", "path", FAULT]]
    require(fault and all(row.get("output", "").strip() == "" for _, row in fault) and
            sum(boundary < index < boot_rows[1] for index, _ in fault) == 1,
            "Fault APK absence was not reobserved after conformance")
    all_hashes = {index for index, row in enumerate(trace)
                  if row["argv"][:len(prefix) + 2] == prefix + ["shell", "sha256sum"]}
    require(consumed_hashes == all_hashes, "Unpaired guest OS/APK hash observation")

    attach = next(index for index, row in enumerate(trace) if row["argv"] ==
        prefix + ["emu", "multidisplay", "add", "1", "1920", "1080", "160", "132165"])
    users = [(index, row) for index, row in enumerate(trace) if row["argv"] ==
             prefix + ["shell", "pm", "list", "users"]]
    current = [(index, row) for index, row in enumerate(trace) if row["argv"] ==
               prefix + ["shell", "am", "get-current-user"]]
    bundle_current = {start + 4 for start in boot_rows}
    preflight = [(index, row) for index, row in current if index not in bundle_current]
    require(len(users) == len(preflight) == 1 and len(current) == 3 and
            preflight[0][0] < users[0][0] < attach and
            re.findall(r"UserInfo\{([0-9]+):", users[0][1].get("output", "")) == ["0"] and
            all(row["returncode"] == 0 and row.get("output", "").strip() == "0" for _, row in current),
            "Raw owner-user preflight differs from sole active owner 0")
    keyguards = [(index, row) for index, row in enumerate(trace) if row["argv"] ==
                 prefix + ["shell", "dumpsys", "activity", "service", "com.android.systemui/.SystemUIService"]]
    showing = []
    require(keyguards and all(index < preflight[0][0] for index, _ in keyguards),
            "Unpaired or late phone keyguard observation")
    for _, row in keyguards:
        blocks = re.findall(r"^\s*KeyguardStateController:\n((?:[ \t]+[^\n]+\n)+)",
                            row.get("output", "").rstrip() + "\n", re.M)
        require(len(blocks) == 1, "Missing/ambiguous raw phone keyguard state")
        fields = {}
        for field in ("mShowing", "mSecure", "mCanDismissLockScreen"):
            values = re.findall(r"^\s*" + field + r": (true|false)\s*$", blocks[0], re.M)
            require(len(values) == 1, "Missing/ambiguous raw keyguard field: " + field)
            fields[field] = values[0]
        require(fields["mSecure"] == "false", "Fresh phone unexpectedly required a credential")
        showing.append(fields["mShowing"])
    require(showing[-1] == "false", "Raw phone keyguard did not dismiss before owner preflight")
    first_package = min(index for index, row in enumerate(trace) if
        row["argv"][:len(prefix) + 3] == prefix + ["shell", "pm", "path"])
    boot_polls = [(index, row) for index, row in enumerate(trace) if row["argv"] ==
                  prefix + ["shell", "getprop", "sys.boot_completed"]]
    launch = next(index for index, row in enumerate(trace) if row["argv"][:3] == ["docker", "run", "-d"])
    require(boot_polls and all(launch < index < first_package for index, _ in boot_polls) and
            boot_polls[-1][1]["returncode"] == 0 and
            boot_polls[-1][1].get("output", "").strip() == "1" and
            all(row["returncode"] != 0 or row.get("output", "").strip() != "1"
                for _, row in boot_polls[:-1]),
            "Final raw Android boot poll did not complete before package preflight")
    setting = prefix + commands[5][1]
    setting_rows = [(index, row) for index, row in enumerate(trace) if row["argv"] == setting]
    bundle_settings = {start + 5 for start in boot_rows}
    consent_start = next(index for index, row in enumerate(trace) if row["argv"] ==
        prefix + ["shell", "am", "start", "-W", "--display", "0", "-n",
                  "com.android.systemui/org.wonad.desktop.broker.WonadSettingsActivity"])
    tap = next(index for index, row in enumerate(trace) if row["argv"][:len(prefix) + 6] ==
               prefix + ["shell", "input", "touchscreen", "-d", "0", "tap"])
    disabled = [(index, row) for index, row in setting_rows if index not in bundle_settings and
                index < consent_start]
    enabled = [(index, row) for index, row in setting_rows if tap < index < boot_rows[0]]
    require(len(disabled) == 1 and disabled[0][1].get("output", "").strip() in {"null", "0"} and
            enabled and enabled[-1][1].get("output", "").strip() == "1" and
            all(row.get("output", "").strip() in {"null", "0"} for _, row in enabled[:-1]) and
            {index for index, _ in setting_rows} == bundle_settings |
                {index for index, _ in disabled + enabled},
            "Unpaired or contradictory raw consent observation")
    display_rows = [(index, row) for index, row in enumerate(trace) if row["argv"] ==
                    prefix + ["shell", "dumpsys", "display"]]
    first_install = min(index for index, row in enumerate(trace)
                        if row["argv"][:len(prefix) + 1] == prefix + ["install"])
    require(display_rows and all(attach < index < first_install for index, _ in display_rows),
            "Unpaired or late external display observation")

    service = [(index, row) for index, row in enumerate(trace) if row["argv"] ==
               prefix + ["shell", "dumpsys", "activity", "service", APP + "/.ConformanceService"]]
    require(len(service) == 1 and boundary < service[0][0] < boot_rows[1],
            "Missing/ambiguous raw terminal conformance service dump")
    marker = "WONAD_CONFORMANCE_STATUS "
    status = [line.split(marker, 1)[1] for line in service[0][1].get("output", "").splitlines()
              if marker in line]
    require(len(status) == 1 and json.loads(status[0], object_pairs_hook=strict_object) ==
            report["terminal_status"], "Raw terminal service dump differs from canonical status")
    event_rows = [index for index, row in enumerate(trace) if row.get("evidence") == "protected-events.txt"]
    stop_rows = [index for index, row in enumerate(trace) if row["argv"][:2] == ["docker", "stop"]]
    event_command = prefix + ["shell", "logcat", "-b", "events", "-d", "-v", "threadtime",
                              "am_anr:I", "am_crash:I", "*:S"]
    event_reads = [index for index, row in enumerate(trace) if row["argv"] == event_command]
    adb_indices = [index for index, row in enumerate(trace) if row["argv"][:len(prefix)] == prefix]
    require(len(event_rows) == len(stop_rows) == 1 and
            event_rows == event_reads and adb_indices[-1] == event_rows[0] and
            boot_rows[1] + len(commands) + len(GUEST_OS_ARTIFACTS) <= event_rows[0] < stop_rows[0],
            "Protected events were not read after terminal state and before guest stop")


def consent_ui(path: Path, before: dict):
    raw = path.read_text()
    start, end = raw.find("<?xml"), raw.rfind("</hierarchy>")
    require(start >= 0 and end >= start, "Missing raw consent hierarchy")
    tree = ET.fromstring(raw[start:end + len("</hierarchy>")])
    nodes = [node for node in tree.iter("node") if node.get("package") == "com.android.systemui" and
             node.get("text", "").casefold() == "enable wonad desktop" and node.get("enabled") == "true" and
             node.get("clickable") == "true"]
    require(len(nodes) == 1, "Sealed hierarchy lacks unique genuine SystemUI consent")
    bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", nodes[0].get("bounds", ""))
    require(bounds is not None, "Malformed consent bounds")
    left, top, right, bottom = map(int, bounds.groups())
    require(0 <= left < right <= 1080 and 0 <= top < bottom <= 2400 and
            before["consent_point"] == [(left + right) // 2, (top + bottom) // 2],
            "Recorded consent tap differs from raw genuine control")


def protected_failures(raw: str):
    protected = set(PROTECTED_PROCESS_NAMES)
    rows = []
    for match in re.finditer(
            r"\b(am_(?:anr|crash))\s*:\s*\[\s*[^,\]\n]+\s*,\s*[^,\]\n]+\s*,\s*([^,\]\n]+)", raw):
        process = match[2].strip().split(":", 1)[0]
        if process in protected:
            rows.append({"kind": match[1], "process": process})
    return rows


def audit_report(report_path: Path, product: Path, packet: Path, expected_receipt_sha256: str,
                 *, external_checks=True):
    raw_report = report_path.absolute()
    require(raw_report.resolve(strict=True) == raw_report and raw_report.is_file() and
            not raw_report.is_symlink(), "Select one literal fresh-guest report file")
    report_path = raw_report
    directory = report_path.parent
    report = load(report_path)
    required = {"schema", "kind", "scope", "status", "api", "run", "image_id", "fingerprint",
        "container", "container_run", "boot_id", "display_id", "packet_receipt_sha256", "product_images", "os_artifacts",
        "artifacts", "terminal_status", "gates", "runtime_qualified", "qualification_claimed",
        "fault_apk_installed", "downgrade_or_uninstall_used", "settings_state_seeded", "container_stopped",
        "userdata_retained_path", "evidence_files"}
    require(isinstance(report, dict) and set(report) == required and type(report["schema"]) is int and
            report["schema"] == 1 and report["kind"] == REPORT_KIND and report["scope"] == REPORT_SCOPE and
            report["status"] == "passed" and type(report["api"]) is int and report["api"] == 3 and
            RUN.fullmatch(str(report["run"])) and RUN.fullmatch(str(report["container_run"])) and
            IMAGE_ID.fullmatch(str(report["image_id"])) and
            re.fullmatch(r"[0-9a-f]{64}", str(report["container"])) and BOOT_ID.fullmatch(str(report["boot_id"])) and
            type(report["display_id"]) is int and report["display_id"] > 0 and
            report["runtime_qualified"] is False and report["qualification_claimed"] is False and
            report["fault_apk_installed"] is False and report["downgrade_or_uninstall_used"] is False and
            report["settings_state_seeded"] is False and report["container_stopped"] is True and
            report["gates"] == {"fresh_userdata_and_absent_packages": "passed", "ordinary_ui_consent": "passed",
                "full_v3_operations_callbacks_capabilities_and_facades": "passed",
                "protected_process_continuity": "passed",
                "platform_fault_injection": "identity_verified_only_not_run"},
            "Malformed or overclaimed fresh-guest conformance report")
    require(report["userdata_retained_path"] == str(directory / "emulator-state"),
            "Report points at another userdata directory")
    bind_files(directory, report["evidence_files"])

    manifest = load(directory / "image-manifest.json")
    validate_manifest(manifest)
    require(report["fingerprint"] == manifest["fingerprint"] and report["product_images"] == manifest["product_images"] and
            report["os_artifacts"] == manifest["os_artifacts"] and report["artifacts"] == manifest["artifacts"] and
            report["packet_receipt_sha256"] == manifest["packet"]["receipt_sha256"] == expected_receipt_sha256,
            "Report differs from exact candidate/packet identities")
    product_manifest = load(directory / "product-candidate-manifest.json")
    require(canonical_sha256(product_manifest) == manifest["base_product_candidate"]["manifest_sha256"] and
            product_manifest.get("scope") == manifest["base_product_candidate"]["scope"] and
            canonical_sha256(builder.validate_phase1_base_evidence(product_manifest, product)) ==
                manifest["base_product_candidate"]["phase1_build_evidence_sha256"],
            "Base product candidate manifest binding changed")

    receipt = load(packet / "receipt.json")
    packet_tool.validate_receipt(packet, receipt, expected_receipt_sha256, live_tools=False)
    require(sha256(directory / "packet-receipt.json") == expected_receipt_sha256 and
            load(directory / "packet-receipt.json") == receipt, "Sealed packet receipt differs")
    for role, filename in {"wonad": "wonad.apk", "conformance": "conformance.apk",
                           "fixture": "fixture.apk", "fault": "fault.apk"}.items():
        require(file_ref(packet / filename) == {"sha256": manifest["artifacts"][role]["sha256"],
                                                "bytes": manifest["artifacts"][role]["bytes"]} and
                manifest["artifacts"][role] == artifact_subset(receipt["artifacts"][role], role),
                "Selected packet artifact differs: " + role)
    products, os_artifacts = builder.verify_product(product, product_manifest)
    require(products == manifest["product_images"] and os_artifacts == manifest["os_artifacts"],
            "Selected strict custom product differs from fresh-guest manifest")

    before = state(load(directory / "before.json"), before=True, manifest=manifest, report=report)
    after = state(load(directory / "after.json"), before=False, manifest=manifest, report=report)
    require(before["boot_id"] == after["boot_id"] == report["boot_id"] and
            before["protected_processes"] == after["protected_processes"],
            "Boot/protected-process identity changed across conformance")
    require(not protected_failures((directory / "protected-events.txt").read_text()),
            "Protected phone process crash/ANR exists in sealed fresh-boot events")
    consent_ui(directory / "consent-hierarchy.xml", before)
    terminal = validate_status(load(directory / "terminal-status.json"), report["run"], report["display_id"])
    raw_terminal = validate_status(terminal_status_from_log((directory / "conformance.log").read_text()),
                                   report["run"], report["display_id"])
    require(terminal == raw_terminal == report["terminal_status"],
            "Terminal conformance status differs from raw producer log")
    trace = parse_trace(directory / "commands.json", report, directory)
    traced_guest_state(trace, report, before, after, manifest)
    raw_epochs = traced_protected_epochs(trace, report)
    require(raw_epochs["before"] == before["protected_processes"] and
            raw_epochs["after"] == after["protected_processes"],
            "Summarized protected-process epochs differ from raw command evidence")
    expected_tap = ["shell", "input", "touchscreen", "-d", "0", "tap",
                    *map(str, before["consent_point"])]
    traced_taps = []
    for row in trace:
        argv = row["argv"]
        if argv[:4] == ["docker", "exec", report["container"], "adb"]:
            index = 3
            if argv[index:index + 3] == ["adb", "-s", SERIAL] and argv[index + 3:] == expected_tap:
                traced_taps.append(row)
    require(len(traced_taps) == 1, "Trace tap differs from the genuine sealed SystemUI consent control")

    source_paths = {"conformance_smoke.py": ROOT / "android/tools/conformance_smoke.py",
        "common.py": ROOT / "android/tools/phase1_conformance_common.py",
        "driver.py": ROOT / "android/tools/phase1_conformance_guest.py",
        "acceptance.py": Path(__file__).resolve()}
    for name, path in source_paths.items():
        require(sha256(path) == manifest["files"]["/opt/wonad/phase1-conformance/" + name],
                "Auditor/producer source differs from exact candidate: " + name)
    if external_checks:
        candidate_offline(report["image_id"], manifest)
        current_base = builder.base_manifest(manifest["base_product_candidate"]["image_id"])
        require(current_base == product_manifest and
                current_base["files"].get("/opt/wonad/wonad.apk") ==
                    manifest["base_product_candidate"]["product_apk_sha256"],
                "Current immutable product candidate differs from its sealed exact manifest")
        derived = inspect_image(report["image_id"])
        base_image = inspect_image(manifest["base_product_candidate"]["image_id"])
        builder.validate_derived_image(base_image, derived)
        signer = builder.systemui_signer(
            product, receipt, manifest["os_artifacts"]["com.android.systemui"])
        require(signer == manifest["systemui_fault_identity"]["systemui_signer_sha256"],
                "Independent SystemUI signer readback differs from fault identity")
    return {"status": "accepted_fresh_guest_conformance_not_runtime_qualification",
            "image_id": report["image_id"], "run": report["run"], "boot_id": report["boot_id"],
            "report_sha256": sha256(report_path), "fault_injection": "not_run"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--product", required=True, type=Path)
    parser.add_argument("--packet", required=True, type=Path)
    parser.add_argument("--expected-receipt-sha256", required=True)
    args = parser.parse_args()
    result = audit_report(args.report, literal_directory(args.product), literal_directory(args.packet),
                          args.expected_receipt_sha256)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError, ET.ParseError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        raise SystemExit(1)
