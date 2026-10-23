#!/usr/bin/env python3
"""Independently audit the fresh guest surrounding the Phase-1 Recents lane.

The Recents auditor proves the window/task semantics.  This auditor proves the
separate wrapper facts which that child cannot prove: a new exact-image guest,
absent APKs, ordinary SystemUI consent, stable protected-process epochs and OS
bytes, containment of the child run between those observations, and exact
owned-container teardown.  It replays product/packet/image identity rather
than trusting the wrapper's booleans.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "android/container"))

from build import inspect_image  # noqa: E402
from phase1_conformance_common import (BOOT_ID, IMAGE_ID, RUN, artifact_subset, canonical,  # noqa: E402
    canonical_sha256, file_ref, load, sha256, strict_object, validate_manifest)
import phase1_conformance_acceptance as api_acceptance  # noqa: E402
import phase1_conformance_guest as fresh  # noqa: E402
import phase1_conformance_recents_acceptance as recents_acceptance  # noqa: E402
import phase1_emulator_client_packet as packet_tool  # noqa: E402


KIND = "wonad-phase1-fresh-guest-recents-orchestration"
STATUS = "passed_bounded_recents_orchestration_not_runtime_or_hardware_qualified"
SERIAL = fresh.SERIAL
APP, FIXTURE, FAULT = fresh.APP, fresh.FIXTURE, fresh.FAULT
LABEL = fresh.LABEL
PROTECTED = frozenset(fresh.PROTECTED)
GUEST_FILES = {
    "after.json", "before.json", "commands.json", "consent-hierarchy.xml",
    "image-manifest.json", "packet-receipt.json",
    "prelaunch-userdata.json", "product-candidate-manifest.json", "protected-events.txt",
    fresh.PHONE_HOME_ACTIVITIES, fresh.PHONE_HOME_WINDOWS,
}
GUEST_OS_PATHS = frozenset(fresh.OS_GUEST_PATHS.values())
HEX64 = re.compile(r"[0-9a-f]{64}")


class EvidenceError(ValueError):
    """Fresh Recents orchestration evidence failed closed."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def literal_directory(path: Path) -> Path:
    value = Path(path).absolute()
    require(value.resolve(strict=True) == value and value.is_dir() and not value.is_symlink(),
            "Select one literal existing directory: " + str(value))
    return value


def literal_report(path: Path) -> Path:
    value = Path(path).absolute()
    require(value.parent.resolve(strict=True) == value.parent and value.is_file() and
            not value.is_symlink(), "Select one literal fresh-Recents wrapper report")
    return value


def _child(root: Path, relative: str, label: str, *, directory=False) -> Path:
    require(isinstance(relative, str) and PurePosixPath(relative).as_posix() == relative and
            not PurePosixPath(relative).is_absolute() and
            all(part not in {"", ".", ".."} for part in PurePosixPath(relative).parts),
            "Unsafe " + label + " path")
    value = root.joinpath(*PurePosixPath(relative).parts)
    require(not value.is_symlink() and
            (value.is_dir() if directory else value.is_file()), "Missing/special " + label)
    require(value.resolve(strict=True).is_relative_to(root), label + " escapes its evidence root")
    return value


def _bind_guest(directory: Path, records: dict):
    require(isinstance(records, dict), "Missing guest setup evidence inventory")
    entries = list(directory.iterdir())
    require(all(path.name in GUEST_FILES | {"emulator-state"} for path in entries),
            "Unexpected fresh-Recents guest evidence path")
    actual = {path.name: file_ref(path) for path in entries if path.name in GUEST_FILES}
    require(set(actual) == GUEST_FILES and actual == records,
            "Fresh-Recents guest evidence inventory/bytes changed")
    retained = [path for path in entries if path.is_dir()]
    require(len(retained) == 1 and retained[0].name == "emulator-state" and
            not retained[0].is_symlink(), "Missing/aliased retained fresh userdata")


def _epoch(value, label):
    require(isinstance(value, dict) and set(value) == {"pid", "start_ticks"} and
            type(value["pid"]) is int and value["pid"] > 0 and
            type(value["start_ticks"]) is int and value["start_ticks"] > 0,
            "Malformed protected-process epoch: " + label)
    return value


def _state(value, *, before: bool, manifest: dict, report: dict):
    required = {"boot_id", "fingerprint", "abi", "enforcing", "current_user", "consent",
                "packages", "protected_processes", "display_id", "installed",
                "consent_point", "os_artifacts"}
    require(isinstance(value, dict) and set(value) == required and
            BOOT_ID.fullmatch(str(value["boot_id"])) and
            value["boot_id"] == report["boot_id"] and
            value["fingerprint"] == report["fingerprint"] == manifest["fingerprint"] and
            value["abi"] == "x86_64" and value["enforcing"] == "Enforcing" and
            value["current_user"] == "0" and value["consent"] == "1" and
            value["display_id"] is None and value["os_artifacts"] == manifest["os_artifacts"] and
            isinstance(value["protected_processes"], dict) and
            set(value["protected_processes"]) == PROTECTED,
            "Malformed fresh-Recents guest state")
    for name, epoch in value["protected_processes"].items():
        _epoch(epoch, name)
    require(len({row["pid"] for row in value["protected_processes"].values()}) == len(PROTECTED),
            "Protected processes have ambiguous PIDs")
    packages, installed = value["packages"], value["installed"]
    require(isinstance(packages, dict) and set(packages) == {APP, FIXTURE, FAULT} and
            isinstance(installed, dict) and set(installed) == {APP, FIXTURE},
            "Malformed fresh-Recents package inventory")
    for package, role in ((APP, "conformance"), (FIXTURE, "fixture")):
        row = installed[package]
        require(isinstance(row, dict) and set(row) == {"path", "sha256"} and
                api_acceptance.installed_apk_path(row["path"]) and
                row["sha256"] == manifest["artifacts"][role]["sha256"],
                "Installed APK identity changed: " + package)
    require(installed[APP]["path"] != installed[FIXTURE]["path"],
            "Distinct installed packages share one APK path")
    if before:
        require(packages == {APP: None, FIXTURE: None, FAULT: None} and
                isinstance(value["consent_point"], list) and
                len(value["consent_point"]) == 2 and
                all(type(item) is int for item in value["consent_point"]),
                "Recents guest was seeded or did not start from absent packages")
    else:
        require(packages == {APP: installed[APP]["path"],
                             FIXTURE: installed[FIXTURE]["path"], FAULT: None} and
                value["consent_point"] is None,
                "Terminal Recents package inventory changed")
    return value


def _trace_row(row, prior: int, directory: Path):
    keys = set(row) if isinstance(row, dict) else set()
    require(keys in (
        {"argv", "returncode", "started_monotonic_ns", "ended_monotonic_ns", "output"},
        {"argv", "returncode", "started_monotonic_ns", "ended_monotonic_ns",
         "evidence", "output_sha256"},
        {"argv", "returncode", "timed_out", "timeout_seconds",
         "started_monotonic_ns", "ended_monotonic_ns", "output"},
        {"kind", "name", "started_monotonic_ns", "ended_monotonic_ns",
         "evidence", "output_sha256", "bytes"}), "Malformed command journal row")
    local = row.get("kind") == "local_evidence"
    timeout = row.get("timed_out") is True
    require((local or (isinstance(row.get("argv"), list) and row["argv"] and
                       all(isinstance(item, str) for item in row["argv"]))) and
            (local or timeout or
             (type(row.get("returncode")) is int and row["returncode"] in (0, 1))) and
            type(row["started_monotonic_ns"]) is int and
            type(row["ended_monotonic_ns"]) is int and
            prior <= row["started_monotonic_ns"] <= row["ended_monotonic_ns"],
            "Malformed/overlapping command journal")
    if timeout:
        require(row["returncode"] is None and row["timeout_seconds"] == 10 and
                isinstance(row["output"], str) and
                row["ended_monotonic_ns"] - row["started_monotonic_ns"] >=
                    row["timeout_seconds"] * 1_000_000_000,
                "Malformed timed-out command journal row")
    if local:
        require(row["name"] == fresh.PRELAUNCH_LOCAL_EVENT and
                row["evidence"] == fresh.PRELAUNCH_USERDATA_EVIDENCE and
                type(row["bytes"]) is int and row["bytes"] > 0 and
                row["bytes"] == (directory / row["evidence"]).stat().st_size and
                row["output_sha256"] == sha256(directory / row["evidence"]),
                "Malformed/unbound prelaunch local-evidence row")
    if "evidence" in row:
        require(local or (row["evidence"] == "protected-events.txt" and
                          row["output_sha256"] == sha256(directory / row["evidence"])),
                "Command externalized unbound evidence")
    return row["ended_monotonic_ns"]


def _authority_identity() -> dict:
    paths = {
        "runner": ROOT / "android/tools/run_phase1_conformance_recents_guest.py",
        "guest_common": ROOT / "android/tools/phase1_conformance_guest.py",
    }
    return {role: {"path": path.relative_to(ROOT).as_posix(), **file_ref(path)}
            for role, path in paths.items()}


def _directory_identity(path: Path) -> dict:
    value = os.lstat(path)
    require(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode),
            "Retained userdata path is not a literal directory")
    return {"path": str(path), "dev": value.st_dev, "ino": value.st_ino,
            "mode": stat.S_IMODE(value.st_mode), "uid": value.st_uid, "gid": value.st_gid}


def _prelaunch_state(report: dict, guest: Path) -> dict:
    raw_path = guest / fresh.PRELAUNCH_USERDATA_EVIDENCE
    raw = load(raw_path)
    authority = _authority_identity()
    required = {"schema", "kind", "timeline", "state", "tmp", "inventory", "authority"}
    require(isinstance(raw, dict) and set(raw) == required and raw["schema"] == 1 and
            raw["kind"] == fresh.PRELAUNCH_USERDATA_KIND and raw["authority"] == authority and
            report["authority"] == authority and raw_path.read_bytes() == canonical(raw),
            "Malformed or unreviewed prelaunch userdata authority")
    names = ("create_started_monotonic_ns", "state_created_monotonic_ns",
             "tmp_created_monotonic_ns", "inventory_observed_monotonic_ns")
    timeline = raw["timeline"]
    require(isinstance(timeline, dict) and set(timeline) == set(names) and
            all(type(timeline[name]) is int and timeline[name] > 0 for name in names) and
            [timeline[name] for name in names] == sorted(timeline[name] for name in names) and
            raw["inventory"] == [{"path": "tmp", "kind": "directory", "children": []}],
            "Malformed prelaunch userdata timeline/inventory")
    state_path = guest / "emulator-state"
    require(raw["state"] == _directory_identity(state_path) and
            raw["tmp"] == _directory_identity(state_path / "tmp") and
            raw["state"]["mode"] == raw["tmp"]["mode"] == 0o700 and
            raw["state"]["uid"] == raw["tmp"]["uid"] and
            raw["state"]["gid"] == raw["tmp"]["gid"] and
            raw["state"]["path"] == report["userdata_retained_path"] and
            raw["tmp"]["path"] == report["userdata_retained_path"] + "/tmp",
            "Retained userdata identity differs from its sealed prelaunch observation")
    expected = {**raw, "evidence": {
        "path": "guest/" + fresh.PRELAUNCH_USERDATA_EVIDENCE,
        **file_ref(raw_path),
    }}
    require(report["prelaunch_state"] == expected,
            "Wrapper prelaunch summary differs from sealed raw observation")
    return raw


def _reviewed_adb(command: list[str], container_run: str) -> bool:
    remote = "/data/local/tmp/wonad-phase1-consent-" + container_run + ".xml"
    exact = {
        ("shell", "getprop", "sys.boot_completed"),
        ("shell", "getprop", "ro.build.fingerprint"),
        ("shell", "getprop", "ro.product.cpu.abi"),
        ("shell", "getenforce"),
        ("shell", "cat", "/proc/sys/kernel/random/boot_id"),
        ("shell", "am", "get-current-user"),
        ("shell", "pm", "list", "users"),
        ("shell", "dumpsys", "activity", "service", "com.android.systemui/.SystemUIService"),
        ("shell", "settings", "--user", "0", "get", "secure",
         "wonad_external_desktop_enabled"),
        ("shell", "am", "start", "-W", "--display", "0", "-n", fresh.SETTINGS),
        ("shell", "cmd", "package", "resolve-activity", "--components", "--user", "0",
         "-a", fresh.HOME_ACTION, "-c", fresh.HOME_CATEGORY),
        ("shell", "input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME"),
        ("shell", "dumpsys", "activity", "activities"),
        ("shell", "dumpsys", "window", "windows"),
        ("shell", "input", "keyboard", "-d", "0", "keyevent", "KEYCODE_WAKEUP"),
        ("shell", "input", "touchscreen", "-d", "0", "swipe",
         "540", "1800", "540", "400", "600"),
        ("shell", "uiautomator", "dump", "--compressed", remote),
        ("exec-out", "cat", remote),
        ("shell", "rm", "--", remote),
        ("shell", "logcat", "-b", "events", "-d", "-v", "threadtime",
         "am_anr:I", "am_crash:I", "*:S"),
    }
    if tuple(command) in exact:
        return True
    if command[:3] == ["shell", "pm", "path"] and len(command) == 4:
        return command[3] in {APP, FIXTURE, FAULT}
    if command[:3] == ["install", "--user", "0"] and len(command) == 4:
        return command[3] in {
            "/opt/wonad/phase1-conformance/fixture.apk",
            "/opt/wonad/phase1-conformance/conformance.apk",
        }
    if command[:2] == ["shell", "sha256sum"] and len(command) == 3:
        return command[2] in GUEST_OS_PATHS or api_acceptance.installed_apk_path(command[2])
    if command[:2] == ["shell", "pidof"] and len(command) == 3:
        return command[2] in PROTECTED
    if command[:4] == ["shell", "su", "0", "cat"] and len(command) == 5:
        return re.fullmatch(r"/proc/[1-9][0-9]*/stat", command[4]) is not None
    if command[:6] == ["shell", "input", "touchscreen", "-d", "0", "tap"] and len(command) == 8:
        return all(re.fullmatch(r"[0-9]+", item) for item in command[6:])
    return False


def _inspect_row(row: dict, report: dict, directory: Path, container_run: str,
                 expected_user: str, expected_kvm_group: str):
    try:
        values = json.loads(row.get("output", ""), object_pairs_hook=strict_object)
    except json.JSONDecodeError as error:
        raise EvidenceError("Malformed owned-container inspection") from error
    require(isinstance(values, list) and len(values) == 1, "Ambiguous owned-container inspection")
    info = values[0]
    raw_mounts = info.get("Mounts", [])
    valid_mounts = (isinstance(raw_mounts, list) and len(raw_mounts) == 1 and
                    all(isinstance(item, dict) for item in raw_mounts))
    mounts = ({item.get("Destination"): (item.get("Type"), item.get("Source"),
                                         item.get("RW"), item.get("Mode"),
                                         item.get("Propagation"))
               for item in raw_mounts} if valid_mounts else {})
    config = info.get("Config", {})
    host = info.get("HostConfig", {})
    devices = host.get("Devices")
    ulimits = host.get("Ulimits")
    port_bindings = host.get("PortBindings")
    valid_port_bindings = ("PortBindings" in host and
                           (port_bindings is None or
                            (type(port_bindings) is dict and not port_bindings)))
    restart_policy = host.get("RestartPolicy")
    valid_restart_policy = (
        isinstance(restart_policy, dict) and
        set(restart_policy) == {"Name", "MaximumRetryCount"} and
        restart_policy["Name"] == "no" and
        type(restart_policy["MaximumRetryCount"]) is int and
        restart_policy["MaximumRetryCount"] == 0)
    valid_ulimits = (isinstance(ulimits, list) and
                     all(isinstance(item, dict) and
                         set(item) == {"Name", "Hard", "Soft"} and
                         isinstance(item["Name"], str) and
                         type(item["Hard"]) is int and type(item["Soft"]) is int
                         for item in ulimits))
    ulimits_by_name = ({item["Name"]: {"Hard": item["Hard"], "Soft": item["Soft"]}
                        for item in ulimits} if valid_ulimits else {})
    require(info.get("Id") == report["container_id"] and
            info.get("Image") == report["image_id"] and
            config.get("Labels", {}).get(LABEL) == container_run and
            config.get("User") == expected_user and
            valid_mounts and
            mounts == {"/state": ("bind", str(directory / "emulator-state"), True,
                                   "rw,Z", "rprivate")} and
            host.get("Binds") == [str(directory / "emulator-state") + ":/state:rw,Z"] and
            host.get("NetworkMode") == "none" and host.get("Privileged") is False and
            valid_port_bindings and host.get("PublishAllPorts") is False and
            host.get("CapAdd") is None and host.get("CapDrop") == ["ALL"] and
            host.get("SecurityOpt") == ["no-new-privileges=true"] and
            host.get("PidMode") == "" and host.get("IpcMode") == "private" and
            host.get("UTSMode") == "" and host.get("UsernsMode") == "" and
            host.get("CgroupnsMode") == "private" and
            host.get("VolumesFrom") is None and host.get("AutoRemove") is False and
            host.get("ReadonlyRootfs") is False and
            valid_restart_policy and
            host.get("GroupAdd") == [expected_kvm_group] and
            devices == [{"PathOnHost": "/dev/kvm", "PathInContainer": "/dev/kvm",
                         "CgroupPermissions": "rwm"}] and
            host.get("DeviceRequests") is None and host.get("DeviceCgroupRules") is None and
            host.get("PidsLimit") == 1024 and host.get("Memory") == 8 * 1024 ** 3 and
            host.get("MemorySwap") == 16 * 1024 ** 3 and
            "MemoryReservation" in host and
            type(host.get("MemoryReservation")) is int and
            host.get("MemoryReservation") == 0 and host.get("OomKillDisable") is False and
            host.get("NanoCpus") == 12_000_000_000 and
            host.get("ShmSize") == 512 * 1024 ** 2 and
            host.get("Tmpfs") == {"/tmp": "rw,nosuid,nodev,size=2g"} and
            valid_ulimits and len(ulimits) == len(ulimits_by_name) == 2 and
            ulimits_by_name == {
                "core": {"Hard": 0, "Soft": 0},
                "nofile": {"Hard": 65536, "Soft": 65536},
            } and
            isinstance(info.get("State", {}).get("Running"), bool),
            "Owned-container identity/isolation changed")
    return info["State"]["Running"]


def _process_epochs(rows: list[dict], prefix: list[str]):
    result = {name: [] for name in PROTECTED}
    positions = {name: [] for name in PROTECTED}
    consumed = set()
    stat_rows = set()
    for index, row in enumerate(rows):
        argv = row.get("argv", [])
        if argv[:len(prefix) + 4] == prefix + ["shell", "su", "0", "cat"]:
            stat_rows.add(index)
        if argv[:len(prefix) + 2] != prefix + ["shell", "pidof"] or len(argv) != len(prefix) + 3:
            continue
        name = argv[-1]
        require(name in PROTECTED and index + 1 < len(rows), "Unreviewed protected PID observation")
        raw_pid = row.get("output", "").strip()
        require(row["returncode"] == 0 and re.fullmatch(r"[1-9][0-9]*", raw_pid),
                "Missing/ambiguous protected PID: " + name)
        pid = int(raw_pid)
        stat_row = rows[index + 1]
        require(stat_row["argv"] == prefix + ["shell", "su", "0", "cat", f"/proc/{pid}/stat"] and
                stat_row["returncode"] == 0, "Unpaired protected process observation: " + name)
        match = re.fullmatch(r"([1-9][0-9]*) \(.*\) [A-Z] (.+)\n?", stat_row.get("output", ""))
        fields = match[2].split() if match else []
        require(match is not None and int(match[1]) == pid and len(fields) > 18 and
                re.fullmatch(r"[1-9][0-9]*", fields[18]),
                "Malformed protected process stat: " + name)
        result[name].append({"pid": pid, "start_ticks": int(fields[18])})
        positions[name].append((index, index + 1))
        consumed.add(index + 1)
    require(consumed == stat_rows and all(len(values) == 2 for values in result.values()),
            "Protected process epochs are missing, extra or unpaired")
    return ({"before": {name: result[name][0] for name in PROTECTED},
             "after": {name: result[name][1] for name in PROTECTED}}, positions)


def _command_trace(path: Path, report: dict, directory: Path, manifest: dict,
                   before: dict, after: dict, prelaunch: dict):
    rows = load(path)
    require(isinstance(rows, list) and rows, "Missing fresh-Recents command journal")
    prior = 0
    for row in rows:
        prior = _trace_row(row, prior, directory)

    container = report["container_id"]
    prefix = ["docker", "exec", container, "adb", "-s", SERIAL]
    launches, verifier, manifest_reads, local, inspections, stops, adb_rows = [], [], [], [], [], [], []
    for index, row in enumerate(rows):
        if row.get("kind") == "local_evidence":
            local.append((index, row))
            continue
        argv = row["argv"]
        if argv[:3] == ["docker", "run", "-d"]:
            launches.append((index, row))
        elif argv == ["docker", "run", "--rm", "--network", "none", "--read-only",
                      "--tmpfs", "/tmp:rw,nosuid,size=64m", report["image_id"], "verify"]:
            verifier.append((index, row))
        elif argv == ["docker", "run", "--rm", "--network", "none", "--read-only",
                      "--entrypoint", "cat", report["image_id"],
                      "/opt/wonad/product-candidate-manifest.json"]:
            manifest_reads.append((index, row))
        elif argv == ["docker", "container", "inspect", container]:
            inspections.append((index, row))
        elif argv[:2] == ["docker", "stop"]:
            stops.append((index, row))
        elif argv[:len(prefix)] == prefix:
            command = argv[len(prefix):]
            lowered = [item.lower() for item in command]
            require(not (command[:1] == ["uninstall"] or "--downgrade" in lowered or
                         (command[:1] == ["install"] and ("-d" in lowered or "-r" in lowered or
                                                          "--replace" in lowered)) or
                         command[:3] in (["shell", "pm", "clear"],
                                         ["shell", "pm", "uninstall"]) or
                         command[:5] in (["shell", "settings", "--user", "0", "put"],
                                         ["shell", "settings", "--user", "0", "delete"],
                                         ["shell", "settings", "--user", "0", "reset"])),
                    "Journal used replacement/downgrade/uninstall/data-clear/settings seeding")
            adb_rows.append((index, command, row))
        else:
            require(False, "Journal contains an unreviewed host/container operation")

    require(len(launches) == len(verifier) == len(manifest_reads) == len(local) == 1,
            "Journal lacks exact one-time image verification/manifest/prelaunch/launch")
    launch_index, launch_row = launches[0]
    require(verifier[0][0] < manifest_reads[0][0] < launch_index and
            verifier[0][1]["returncode"] == manifest_reads[0][1]["returncode"] ==
                launch_row["returncode"] == 0,
            "Candidate verification/manifest must succeed before fresh guest launch")
    local_index, local_row = local[0]
    require(manifest_reads[0][0] < local_index and local_index + 1 == launch_index and
            manifest_reads[0][1]["ended_monotonic_ns"] <=
                prelaunch["timeline"]["create_started_monotonic_ns"] and
            prelaunch["timeline"]["inventory_observed_monotonic_ns"] <=
                local_row["started_monotonic_ns"] <= local_row["ended_monotonic_ns"] <=
                launch_row["started_monotonic_ns"],
            "Sealed empty-userdata observation must immediately precede guest launch")
    launch = launch_row["argv"]
    try:
        label = launch[launch.index("--label") + 1]
        kvm_group = launch[launch.index("--group-add") + 1]
        user = launch[launch.index("--user") + 1]
    except (ValueError, IndexError) as error:
        raise EvidenceError("Fresh-Recents launch lacks bounded identity") from error
    prefix_label = LABEL + "="
    container_run = label.removeprefix(prefix_label) if label.startswith(prefix_label) else ""
    require(RUN.fullmatch(container_run or "") and re.fullmatch(r"[0-9]+", kvm_group) and
            re.fullmatch(r"[0-9]+:[0-9]+", user), "Malformed fresh-Recents launch identity")
    expected_launch = ["docker", "run", "-d", "--name",
        "wonad-phase1-conformance-" + container_run[:12], "--label", label,
        "--network", "none", "--device", "/dev/kvm", "--group-add", kvm_group,
        "--user", user, "--cap-drop=ALL", "--security-opt", "no-new-privileges=true",
        "--pids-limit", "1024", "--memory", "8g", "--cpus", "12", "--shm-size", "512m",
        "--ulimit", "nofile=65536:65536", "--ulimit", "core=0:0",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=2g",
        "--volume", str(directory / "emulator-state") + ":/state:rw,Z",
        "--env", "HOME=/state", "--env", "TMPDIR=/state/tmp",
        "--env", "WONAD_VIEWER_TRANSPORT=vnc", "--entrypoint", "python3",
        report["image_id"], "/opt/wonad/session.py"]
    require(launch == expected_launch and launch_row.get("output", "").strip() == container,
            "Journal lacks the exact isolated fresh-state guest launch")
    launch_uid, launch_gid = map(int, user.split(":"))
    require((prelaunch["state"]["uid"], prelaunch["state"]["gid"]) ==
            (launch_uid, launch_gid),
            "Fresh userdata ownership differs from the unprivileged launch user")

    # Recheck the remote path now that the untrusted launch token is known.
    for _index, command, row in adb_rows:
        require(_reviewed_adb(command, container_run), "Journal contains an unreviewed direct adb command")
        if row.get("timed_out") is True:
            require(command == ["shell", "getprop", "sys.boot_completed"],
                    "Only a pre-boot completion poll may time out")
        elif row["returncode"] != 0:
            remote = "/data/local/tmp/wonad-phase1-consent-" + container_run + ".xml"
            require(command == ["shell", "getprop", "sys.boot_completed"] or
                    command[:3] == ["shell", "pm", "path"] or
                    command == ["shell", "rm", "--", remote],
                    "A required direct adb observation/action failed")

    banner, separator, document = verifier[0][1].get("output", "").partition("\n")
    require(banner == "Verifying fresh-guest Phase-1 conformance candidate…" and separator and
            json.loads(document, object_pairs_hook=strict_object) == manifest and
            manifest["files"].get("/opt/wonad/phase1-conformance/driver.py") ==
                prelaunch["authority"]["guest_common"]["sha256"],
            "Journal offline verifier output differs from sealed candidate manifest")
    product_manifest = load(directory / "product-candidate-manifest.json")
    require(json.loads(manifest_reads[0][1].get("output", ""),
                       object_pairs_hook=strict_object) == product_manifest,
            "Journal bundled-product read differs from sealed manifest")

    require(inspections and len(stops) == 1 and
            stops[0][1]["argv"] == ["docker", "stop", "-t", "30", container] and
            stops[0][1].get("output", "").strip() == container,
            "Owned-container teardown is missing or ambiguous")
    states = [_inspect_row(row, report, directory, container_run, user, kvm_group)
              for _index, row in inspections]
    require(inspections[0][0] == launch_index + 1 and states[-1] is False and all(states[:-1]) and
            inspections[-1][0] > stops[0][0] and all(index < stops[0][0] for index, _ in inspections[:-1]),
            "Owned container was not continuously running then exactly stopped")

    installs = [(index, command) for index, command, _row in adb_rows if command[:1] == ["install"]]
    require([command for _index, command in installs] == [
        ["install", "--user", "0", "/opt/wonad/phase1-conformance/fixture.apk"],
        ["install", "--user", "0", "/opt/wonad/phase1-conformance/conformance.apk"],
    ], "Journal lacks the two exact non-replacement fresh installs")
    require(all("Success" in rows[index].get("output", "").splitlines()
                for index, _command in installs),
            "A fresh APK install did not return Success")
    require(not any("fault.apk" in item for _index, command, _row in adb_rows for item in command),
            "Fault APK was used in the Recents lane")

    # The final consecutive package-path triplet is finish_guest's first
    # action.  It is the outer trace boundary around the separately recorded
    # Recents child timeline.
    wanted = [["shell", "pm", "path", package] for package in (APP, FIXTURE, FAULT)]
    triplets = [index for index in range(len(rows) - 2)
                if all(rows[index + offset].get("argv", [])[:len(prefix)] == prefix
                       for offset in range(3)) and
                   [rows[index + offset]["argv"][len(prefix):]
                    for offset in range(3)] == wanted]
    require(len(triplets) == 2, "Cannot delimit exact fresh setup from terminal Recents checks")
    terminal_start = triplets[-1]
    require(terminal_start > installs[-1][0], "Terminal package checks do not follow fresh installs")

    boot_polls = [(index, row) for index, command, row in adb_rows
                  if command == ["shell", "getprop", "sys.boot_completed"]]
    boot_inspections = inspections[1:1 + len(boot_polls)]
    require(boot_polls and
            all((row.get("timed_out") is True and row["returncode"] is None) or
                (row.get("timed_out") is None and row["returncode"] in (0, 1))
                for _index, row in boot_polls) and
            boot_polls[-1][1].get("timed_out") is None and
            boot_polls[-1][1]["returncode"] == 0 and
            boot_polls[-1][1].get("output", "").strip() == "1" and
            all(row.get("timed_out") is True or row["returncode"] != 0 or
                row.get("output", "").strip() in {"", "0"}
                for _index, row in boot_polls[:-1]) and
            launch_index < boot_polls[0][0] and boot_polls[-1][0] < triplets[0] and
            len(inspections) == len(boot_polls) + 3,
            "Raw boot polling never proved this fresh guest completed boot")
    require(all(inspect_index + 1 == poll_index
                for (inspect_index, _row), (poll_index, _poll)
                in zip(boot_inspections, boot_polls)),
            "Each boot attempt must immediately follow an owned-running inspection")
    keyguard_command = ["shell", "dumpsys", "activity", "service",
                        "com.android.systemui/.SystemUIService"]
    keyguards = [(index, row.get("output", "")) for index, command, row in adb_rows
                 if command == keyguard_command]
    wakes = [(index, row) for index, command, row in adb_rows
             if command == ["shell", "input", "keyboard", "-d", "0", "keyevent", "KEYCODE_WAKEUP"]]
    swipes = [index for index, command, _row in adb_rows if command ==
              ["shell", "input", "touchscreen", "-d", "0", "swipe",
               "540", "1800", "540", "400", "600"]]
    parsed_keyguards = []
    for index, raw in keyguards:
        fields = {}
        for field in ("mShowing", "mSecure", "mCanDismissLockScreen"):
            values = re.findall(r"^\s*" + field + r": (true|false)\s*$", raw, re.M)
            require(len(values) == 1, "Malformed raw keyguard observation")
            fields[field] = values[0] == "true"
        parsed_keyguards.append((index, fields))
    maximal = (len(parsed_keyguards) == 4 and
               all(fields["mShowing"] for _index, fields in parsed_keyguards[:3]) and
               parsed_keyguards[3][1]["mShowing"] is False)
    require(1 <= len(parsed_keyguards) <= 4 and (len(parsed_keyguards) < 4 or maximal) and
            len(wakes) == len(parsed_keyguards) - (1 if maximal else 0) and
            all(not fields["mSecure"] for _index, fields in parsed_keyguards) and
            parsed_keyguards[-1][1]["mShowing"] is False and
            triplets[0] + 2 < parsed_keyguards[0][0] and
            all(keyguard[0] < wake[0] < terminal_start
                for keyguard, wake in zip(parsed_keyguards[:len(wakes)], wakes)) and
            len(swipes) == sum(fields["mShowing"] for _index, fields in parsed_keyguards),
            "Raw keyguard/wake sequence does not prove a credential-free unlocked phone")
    for ordinal, (index, fields) in enumerate(parsed_keyguards):
        if fields["mShowing"]:
            next_keyguard = parsed_keyguards[ordinal + 1][0]
            require(any(wakes[ordinal][0] < swipe < next_keyguard for swipe in swipes),
                    "Showing keyguard was not dismissed before its next observation")

    for package in (APP, FIXTURE, FAULT):
        checks = [(index, row.get("output", "").strip()) for index, command, row in adb_rows
                  if command == ["shell", "pm", "path", package]]
        require(len(checks) == (3 if package == FAULT else 4) and
                checks[0][0] < installs[0][0] and checks[0][1] == "",
                "Raw package journal does not prove initial absence: " + package)
        if package == FAULT:
            require(all(not value for _index, value in checks) and
                    installs[-1][0] < checks[1][0] < terminal_start <= checks[2][0],
                    "Fault APK appeared or was not checked across the full guest")
        else:
            install_index = next(index for index, command in installs
                                 if command[-1].endswith(
                                     "conformance.apk" if package == APP else "fixture.apk"))
            expected_path = "package:" + after["packages"][package]
            require(checks[1][1] == "" and checks[2][1] == checks[3][1] == expected_path and
                    checks[1][0] < install_index < checks[2][0] < terminal_start <= checks[3][0],
                    "Raw package journal does not prove preinstall absence and exact postinstall/terminal APK: " +
                    package)
    for package in (APP, FIXTURE):
        path = after["packages"][package]
        expected = after["installed"][package]["sha256"]
        observed = [(index, row.get("output", "").split()) for index, command, row in adb_rows
                    if command == ["shell", "sha256sum", path]]
        require(len(observed) == 2 and all(value == [expected, path] for _index, value in observed) and
                observed[0][0] < terminal_start <= observed[1][0],
                "Raw installed APK bytes changed: " + package)

    remote = "/data/local/tmp/wonad-phase1-consent-" + container_run + ".xml"
    commands = lambda wanted: [(index, row) for index, command, row in adb_rows if command == wanted]
    consent_start = commands(["shell", "am", "start", "-W", "--display", "0", "-n", fresh.SETTINGS])
    dumps = commands(["shell", "uiautomator", "dump", "--compressed", remote])
    reads = commands(["exec-out", "cat", remote])
    removes = commands(["shell", "rm", "--", remote])
    tap = commands(["shell", "input", "touchscreen", "-d", "0", "tap",
                    *map(str, before["consent_point"])])
    all_taps = [(index, command) for index, command, _row in adb_rows
                if command[:6] == ["shell", "input", "touchscreen", "-d", "0", "tap"]]
    settings = [(index, row.get("output", "").strip()) for index, command, row in adb_rows
                if command == ["shell", "settings", "--user", "0", "get", "secure",
                               "wonad_external_desktop_enabled"]]
    require(len(consent_start) == len(dumps) == len(reads) == len(removes) == len(tap) ==
            len(all_taps) == 1 and
            installs[-1][0] < consent_start[0][0] < terminal_start and
            any(index < consent_start[0][0] and value != "1" for index, value in settings) and
            consent_start[0][0] < dumps[0][0] < reads[0][0] < removes[0][0] < tap[0][0] and
            reads[0][1].get("output", "").strip() ==
                (directory / "consent-hierarchy.xml").read_text().strip() and
            any(tap[0][0] < index < terminal_start and value == "1" for index, value in settings) and
            any(index >= terminal_start and value == "1" for index, value in settings),
            "Journal does not prove disabled-to-enabled genuine SystemUI consent")
    enabled = [(index, value) for index, value in settings
               if tap[0][0] < index < terminal_start and value == "1"]
    require(enabled, "Journal lacks post-tap consent enablement")
    api_acceptance.traced_phone_home(adb_rows, directory, enabled[0][0], terminal_start)

    users = commands(["shell", "pm", "list", "users"])
    require(len(users) == 1 and
            re.findall(r"UserInfo\{([0-9]+):", users[0][1].get("output", "")) == ["0"],
            "Raw guest journal does not prove sole owner user 0")
    current_users = [(index, row.get("output", "").strip()) for index, command, row in adb_rows
                     if command == ["shell", "am", "get-current-user"]]
    require(len(current_users) == 3 and all(value == "0" for _index, value in current_users) and
            current_users[0][0] < current_users[1][0] < terminal_start <= current_users[2][0],
            "Raw current-user observations do not bracket Recents as owner user 0")
    expected_raw = {
        ("shell", "getprop", "ro.build.fingerprint"): report["fingerprint"],
        ("shell", "getprop", "ro.product.cpu.abi"): "x86_64",
        ("shell", "getenforce"): "Enforcing",
        ("shell", "cat", "/proc/sys/kernel/random/boot_id"): report["boot_id"],
    }
    for command, value in expected_raw.items():
        observed = [(index, row.get("output", "").strip()) for index, actual, row in adb_rows
                    if tuple(actual) == command]
        require(len(observed) == 2 and [item for _index, item in observed] == [value, value] and
                observed[0][0] < terminal_start <= observed[1][0],
                "Raw guest identity changed: " + " ".join(command))
    for guest_path in sorted(GUEST_OS_PATHS):
        expected = next(digest for role, digest in manifest["os_artifacts"].items()
                        if fresh.OS_GUEST_PATHS[role] == guest_path)
        observed = [(index, row.get("output", "").split()) for index, command, row in adb_rows
                    if command == ["shell", "sha256sum", guest_path]]
        require(len(observed) == 2 and
                all(value == [expected, guest_path] for _index, value in observed) and
                observed[0][0] < terminal_start <= observed[1][0],
                "Raw guest OS bytes changed: " + guest_path)
    expected_hash_commands = Counter(
        [("shell", "sha256sum", after["packages"][package])
         for package in (APP, FIXTURE) for _ in range(2)] +
        [("shell", "sha256sum", guest_path)
         for guest_path in GUEST_OS_PATHS for _ in range(2)])
    actual_hash_commands = Counter(tuple(command) for _index, command, _row in adb_rows
                                   if command[:2] == ["shell", "sha256sum"])
    require(actual_hash_commands == expected_hash_commands,
            "Journal contains missing, extra or substituted guest hash observations")

    epochs, epoch_positions = _process_epochs(rows, prefix)
    require(epochs["before"] == before["protected_processes"] and
            epochs["after"] == after["protected_processes"] and
            epochs["before"] == epochs["after"],
            "Raw protected-process epochs changed across Recents")
    require(max(pairs[0][1] for pairs in epoch_positions.values()) < installs[0][0],
            "Protected-process setup epochs were not established before APK installation")
    events = [(index, row) for index, command, row in adb_rows
              if command == ["shell", "logcat", "-b", "events", "-d", "-v", "threadtime",
                             "am_anr:I", "am_crash:I", "*:S"]]
    require(len(events) == 1 and events[0][1].get("evidence") == "protected-events.txt" and
            events[0][0] + 1 == inspections[-2][0] < stops[0][0],
            "Terminal protected-event readback is missing or precedes terminal observations")

    require(all(rows[pairs[0][1]]["ended_monotonic_ns"] <=
                    rows[terminal_start - 1]["ended_monotonic_ns"] and
                rows[pairs[1][0]]["started_monotonic_ns"] >=
                    rows[terminal_start]["started_monotonic_ns"]
                for pairs in epoch_positions.values()),
            "Protected-process epochs do not bracket the Recents child interval")
    return {"rows": rows, "container_run": container_run,
            "authority": prelaunch["authority"],
            "child_window": (rows[terminal_start - 1]["ended_monotonic_ns"],
                             rows[terminal_start]["started_monotonic_ns"]) }


def _child_trace_window(path: Path, low: int, high: int):
    rows = load(path)
    require(isinstance(rows, list) and rows, "Missing Recents child command trace")
    prior, background = low, {}
    for sequence, row in enumerate(rows):
        require(isinstance(row, dict) and row.get("sequence") == sequence and
                row.get("kind") in {"command", "background_start", "background_finish", "derived"},
                "Malformed/reordered Recents child timeline")
        kind = row["kind"]
        if kind == "command":
            require(type(row.get("started_monotonic_ns")) is int and
                    type(row.get("ended_monotonic_ns")) is int and
                    prior <= row["started_monotonic_ns"] <= row["ended_monotonic_ns"] <= high,
                    "Recents child execution is outside the fresh setup/terminal window")
            prior = row["ended_monotonic_ns"]
        elif kind == "background_start":
            identity = row.get("id")
            require(isinstance(identity, str) and identity and identity not in background and
                    type(row.get("started_monotonic_ns")) is int and
                    prior <= row["started_monotonic_ns"] <= high,
                    "Recents background start is outside the fresh guest window")
            background[identity] = row["started_monotonic_ns"]
            prior = row["started_monotonic_ns"]
        elif kind == "background_finish":
            identity = row.get("id")
            require(identity in background and type(row.get("ended_monotonic_ns")) is int and
                    prior <= row["ended_monotonic_ns"] <= high and
                    background.pop(identity) <= row["ended_monotonic_ns"],
                    "Recents background finish is outside the fresh guest window")
            prior = row["ended_monotonic_ns"]
        else:
            require("started_monotonic_ns" not in row and "ended_monotonic_ns" not in row,
                    "Derived Recents evidence must not invent a timestamp")
    require(not background, "Recents background work escaped the fresh guest window")


def _external_identity(report: dict, manifest: dict, product_manifest: dict,
                       product: Path, receipt: dict):
    api_acceptance.candidate_offline(report["image_id"], manifest)
    current_base = api_acceptance.builder.base_manifest(
        manifest["base_product_candidate"]["image_id"])
    require(current_base == product_manifest and
            current_base["files"].get("/opt/wonad/wonad.apk") ==
                manifest["base_product_candidate"]["product_apk_sha256"],
            "Current immutable product candidate differs from sealed base")
    derived = inspect_image(report["image_id"])
    base = inspect_image(manifest["base_product_candidate"]["image_id"])
    api_acceptance.builder.validate_derived_image(base, derived)
    signer = api_acceptance.builder.systemui_signer(
        product, receipt, manifest["os_artifacts"]["com.android.systemui"])
    require(signer == manifest["systemui_fault_identity"]["systemui_signer_sha256"],
            "Independent SystemUI signer readback differs from sealed identity")


def audit_report(report_path: Path, product: Path, packet: Path,
                 expected_receipt_sha256: str, *, external_checks=True) -> dict:
    report_path = literal_report(report_path)
    product, packet = literal_directory(product), literal_directory(packet)
    root = report_path.parent
    require({path.name for path in root.iterdir()} == {"report.json", "guest", "recents"},
            "Fresh-Recents wrapper has unexpected/missing top-level evidence")
    guest = _child(root, "guest", "guest setup evidence", directory=True)
    recents = _child(root, "recents", "Recents evidence", directory=True)
    report = load(report_path)
    required = {"schema", "kind", "status", "image_id", "container_id", "boot_id",
        "fingerprint", "packet_receipt_sha256", "recents_report", "recents_audit",
        "product_images", "os_artifacts", "artifacts", "guest_setup_evidence",
        "prelaunch_state", "authority", "ordinary_ui_consent", "settings_state_seeded",
        "fault_apk_installed", "container_stopped", "userdata_retained_path",
        "runtime_qualified", "qualification_claimed"}
    require(isinstance(report, dict) and set(report) == required and
            type(report["schema"]) is int and report["schema"] == 1 and
            report["kind"] == KIND and report["status"] == STATUS and
            IMAGE_ID.fullmatch(str(report["image_id"])) and
            HEX64.fullmatch(str(report["container_id"])) and
            BOOT_ID.fullmatch(str(report["boot_id"])) and
            isinstance(report["fingerprint"], str) and report["fingerprint"] and
            report["ordinary_ui_consent"] is True and
            report["settings_state_seeded"] is False and report["fault_apk_installed"] is False and
            report["container_stopped"] is True and report["runtime_qualified"] is False and
            report["qualification_claimed"] is False and
            report["userdata_retained_path"] == str(guest / "emulator-state") and
            report["packet_receipt_sha256"] == expected_receipt_sha256 and
            HEX64.fullmatch(str(expected_receipt_sha256)),
            "Malformed/overclaimed fresh-Recents wrapper report")
    _bind_guest(guest, report["guest_setup_evidence"])
    prelaunch = _prelaunch_state(report, guest)

    manifest = load(guest / "image-manifest.json")
    validate_manifest(manifest)
    require(report["image_id"] and report["fingerprint"] == manifest["fingerprint"] and
            report["product_images"] == manifest["product_images"] and
            report["os_artifacts"] == manifest["os_artifacts"] and
            report["artifacts"] == manifest["artifacts"] and
            report["packet_receipt_sha256"] == manifest["packet"]["receipt_sha256"],
            "Wrapper differs from its exact candidate/packet identities")
    product_manifest = load(guest / "product-candidate-manifest.json")
    evidence = api_acceptance.builder.validate_phase1_base_evidence(product_manifest, product)
    require(canonical_sha256(product_manifest) ==
                manifest["base_product_candidate"]["manifest_sha256"] and
            canonical_sha256(evidence) ==
                manifest["base_product_candidate"]["phase1_build_evidence_sha256"],
            "Base product build-evidence binding changed")
    products, os_artifacts = api_acceptance.builder.verify_product(product, product_manifest)
    require(products == manifest["product_images"] and os_artifacts == manifest["os_artifacts"],
            "Selected custom product differs from Recents candidate")

    receipt = load(packet / "receipt.json")
    packet_tool.validate_receipt(packet, receipt, expected_receipt_sha256, live_tools=False)
    require(sha256(guest / "packet-receipt.json") == expected_receipt_sha256 and
            load(guest / "packet-receipt.json") == receipt,
            "Sealed Recents packet receipt differs from selected packet")
    for role, filename in {"wonad": "wonad.apk", "conformance": "conformance.apk",
                           "fixture": "fixture.apk", "fault": "fault.apk"}.items():
        require(file_ref(packet / filename) == {
                    "sha256": manifest["artifacts"][role]["sha256"],
                    "bytes": manifest["artifacts"][role]["bytes"]} and
                manifest["artifacts"][role] == artifact_subset(receipt["artifacts"][role], role),
                "Selected packet artifact differs: " + role)

    before = _state(load(guest / "before.json"), before=True,
                    manifest=manifest, report=report)
    after = _state(load(guest / "after.json"), before=False,
                   manifest=manifest, report=report)
    require(before["protected_processes"] == after["protected_processes"] and
            before["installed"] == after["installed"] and
            before["os_artifacts"] == after["os_artifacts"],
            "Recents changed protected epochs or exact OS/APK bytes")
    try:
        api_acceptance.consent_ui(guest / "consent-hierarchy.xml", before)
    except (ValueError, ET.ParseError) as error:
        raise EvidenceError("Invalid genuine SystemUI consent evidence: " + str(error)) from error
    require(not api_acceptance.protected_failures((guest / "protected-events.txt").read_text()),
            "Protected process crash/ANR exists in terminal fresh-Recents events")

    trace = _command_trace(guest / "commands.json", report, guest, manifest, before, after,
                           prelaunch)
    child_ref = report["recents_report"]
    require(isinstance(child_ref, dict) and set(child_ref) == {"path", "sha256", "bytes"} and
            child_ref["path"] == "recents/report.json" and
            child_ref["sha256"] == sha256(recents / "report.json") and
            child_ref["bytes"] == (recents / "report.json").stat().st_size,
            "Wrapper's Recents report reference changed")
    try:
        audited = recents_acceptance.audit_report(recents / "report.json", child_ref["sha256"])
    except Exception as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise EvidenceError("Independent Recents child audit failed: " + str(error)) from error
    require(report["recents_audit"] == audited,
            "Wrapper's Recents audit summary differs from independent replay")
    child = load(recents / "report.json")
    require(child.get("container_id") == report["container_id"] and
            child.get("image_id") == report["image_id"] and child.get("boot_id") == report["boot_id"] and
            child.get("fingerprint") == report["fingerprint"] and
            child.get("run") == audited["run"] and
            child.get("conformance_run") == audited["conformance_run"] and
            child.get("run") != child.get("conformance_run"),
            "Recents child belongs to another image/container/boot/run")
    low, high = trace["child_window"]
    _child_trace_window(recents / "commands.json", low, high)

    if external_checks:
        _external_identity(report, manifest, product_manifest, product, receipt)
    require(_authority_identity() == trace["authority"],
            "Reviewed fresh-Recents authority changed during independent replay")
    return {
        "status": "accepted_fresh_recents_guest_not_runtime_or_hardware_qualification",
        "image_id": report["image_id"],
        "base_image_id": manifest["base_product_candidate"]["image_id"],
        "container_id": report["container_id"], "run": trace["container_run"],
        "boot_id": report["boot_id"], "fingerprint": report["fingerprint"],
        "recents_run": child["run"], "conformance_run": child["conformance_run"],
        "report_sha256": sha256(report_path), "recents_report_sha256": child_ref["sha256"],
        "packet_receipt_sha256": expected_receipt_sha256,
        "product_manifest_sha256": canonical_sha256(product_manifest),
        "phase1_build_evidence_sha256": canonical_sha256(evidence),
        "authority": trace["authority"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--product", required=True, type=Path)
    parser.add_argument("--packet", required=True, type=Path)
    parser.add_argument("--expected-receipt-sha256", required=True)
    arguments = parser.parse_args(argv)
    try:
        result = audit_report(arguments.report, arguments.product, arguments.packet,
                              arguments.expected_receipt_sha256)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (EvidenceError, ValueError, OSError, subprocess.SubprocessError,
            json.JSONDecodeError, UnicodeError, ET.ParseError) as error:
        print("phase1_conformance_recents_guest_acceptance.py: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
