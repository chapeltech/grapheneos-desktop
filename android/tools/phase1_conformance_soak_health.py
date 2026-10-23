#!/usr/bin/env python3
"""Owned read-only raw health observer for a future policy-free conformance soak.

Explicit userdebug observer authority only: su0 cat /proc stat/status and ls fd,
plus su0 service list for actual radio interface descriptors. No guest mutation.
"""
from pathlib import Path
import hashlib
import os
import re
import stat
import time

import phase1_conformance_soak_contract as contract
import native_phone_health as phone
from phase1_conformance_common import file_ref

require = contract.require
OBSERVER = "explicit_read_only_userdebug_root_proc_stat_status_fd_radio_registry_ordinary_adb_diagnostics"
PROCESS_TABLE_COMMAND = ("ps", "-A", "-w", "-o", "UID,PID,NAME")
EVENTS_COMMAND = ("logcat", "-b", "events", "-d", "-v", "threadtime", "am_anr:I", "am_crash:I", "*:S")


def raw_observation_ref(path, *, command=(), returncode=None):
    """Only a successful exact filtered event read may have zero bytes.

    Empty PID, UID, resource, radio and boot observations still fail. Callers
    separately bind the command to the actual owned transport/trace window.
    The ordinary artifact/source file_ref remains nonempty-only.
    """
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path and path.is_file() and not path.is_symlink(),
        "Missing/aliased original health observation")
    if path.stat().st_size:
        return file_ref(path)
    require(tuple(command) == EVENTS_COMMAND and type(returncode) is int and returncode == 0,
        "Empty health observation is not a successful exact filtered event read")
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(descriptor)
        require(stat.S_ISREG(opened.st_mode) and before.st_size == opened.st_size == 0 and
            (before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino) and os.read(descriptor, 1) == b"",
            "Empty event evidence changed while opening")
    finally:
        os.close(descriptor)
    after = path.lstat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
        "Empty event evidence changed while reading")
    return {"sha256": hashlib.sha256(b"").hexdigest(), "bytes": 0}


def validate_process_uids(value):
    """An admission input, never a UID guessed from an ambiguous process name."""
    require(isinstance(value, dict) and set(value) == set(contract.PROCESS_NAMES) and
        all(type(uid) is int and 0 < uid <= 2**31 - 1 for uid in value.values()) and
        value["system_server"] == 1000, "Exact admitted five-role UID closure required")
    return dict(value)


def qualified_pid(pidof_raw, table_raw, name, uid):
    """Select only the admitted UID from the complete, untruncated numeric ps.

Other users may run the same package. Their appearance/disappearance is not
authority for changing the monitored user's process. The selected process must
occur in BOTH original observations; /proc start-time and UID are fenced later.
"""
    require(type(uid) is int and uid > 0 and name in contract.PROCESS_NAMES.values(),
        "Unknown qualified process identity")
    pids = pidof_raw.split()
    require(pids and all(re.fullmatch(r"[1-9][0-9]*", pid) for pid in pids) and
        len(pids) == len(set(pids)), "Invalid original pidof candidate inventory")
    lines = table_raw.splitlines()
    require(lines and lines[0].split() == ["UID", "PID", "NAME"],
        "Missing numeric untruncated process table")
    rows = []
    for line in lines[1:]:
        match = re.fullmatch(r"\s*(0|[1-9][0-9]*)\s+([1-9][0-9]*)\s+(\S(?:.*\S)?)\s*", line)
        require(match is not None, "Malformed original numeric process row")
        rows.append((int(match[1]), int(match[2]), match[3]))
    require(rows and len({row[1] for row in rows}) == len(rows), "Duplicate/empty process table PID inventory")
    matches = [pid for owner, pid, process in rows if owner == uid and process == name]
    require(len(matches) == 1 and str(matches[0]) in pids,
        "Missing/ambiguous admitted UID process in original pidof and ps")
    return matches[0]


def proc_epoch(raw, pid):
    return phone.phone_epoch(raw, pid)


def task_counts(raw):
    sections = re.split(r"^ActivityTaskSupervisor state:\s*$", raw, flags=re.M)
    require(len(sections) == 2 and sections[0].count("ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)") == 1,
        "Missing authoritative task/root inventory")
    tasks = re.findall(r"^\s+\* Task\{\S+ #(\d+) ", sections[0], re.M)
    roots = re.findall(r"^  \* Task\{\S+ #(\d+) ", sections[0], re.M)
    require(len(tasks) == len(set(tasks)) and len(roots) == len(set(roots)), "Duplicate task/root identity")
    return {"tasks": len(tasks), "roots": len(roots)}


def status_field(raw, field, expression, message):
    # Count ALL occurrences first, not just lines whose value already parses.
    # A valid field followed by a malformed duplicate is not a valid /proc
    # observation. Indented duplicates must not become invisible either.
    lines = [line for line in raw.splitlines() if line.lstrip().startswith(field + ":")]
    require(len(lines) == 1, message)
    match = re.fullmatch(expression, lines[0])
    require(match is not None, message)
    return match.groups()


def process_metric(raw, expected_pid, *, name=None, expected_uid=None):
    fields = {"pid_before", "stat_before", "status", "fd", "stat_after", "pid_after"}
    qualified = expected_uid is not None
    require(set(raw) == fields | ({"ps_before", "ps_after"} if qualified else set()), "Incomplete process fence")
    if qualified:
        before_pid = qualified_pid(raw["pid_before"], raw["ps_before"], name, expected_uid)
        after_pid = qualified_pid(raw["pid_after"], raw["ps_after"], name, expected_uid)
        message = "Selected /proc status UID differs from admission"
        uids = status_field(raw["status"], "Uid",
            r"Uid:[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]*", message)
        require(uids == (str(expected_uid),) * 4, message)
    else:
        before_pid, after_pid = phone.phone_pid(raw["pid_before"]), phone.phone_pid(raw["pid_after"])
    require(before_pid == after_pid == expected_pid, "PID recycled while reading resource metric")
    before, after = proc_epoch(raw["stat_before"], expected_pid), proc_epoch(raw["stat_after"], expected_pid)
    require(before == after, "Process start-time epoch changed inside resource observation")
    message = "Invalid raw PID/FD/RSS resource observation"
    rss = status_field(raw["status"], "VmRSS", r"VmRSS:[ \t]+([1-9][0-9]*) kB", message)
    pids = status_field(raw["status"], "Pid", r"Pid:[ \t]+([1-9][0-9]*)", message)
    fds = raw["fd"].splitlines()
    require(pids == (str(expected_pid),) and fds and
        all(re.fullmatch(r"[0-9]+", item) for item in fds) and len(fds) == len(set(fds)), message)
    return {**before, "rss_kib": int(rss[0]), "fd_count": len(fds),
        **({"uid": expected_uid} if qualified else {})}


def read_new(test, relative, *command):
    output = Path(test.output).absolute(); path = output / relative
    require(not path.exists() and not path.is_symlink() and path.is_relative_to(output), "Never replace original health observation")
    lo = len(test.trace); test.read(relative, *command)
    require(len(test.trace) == lo + 1 and path.is_file() and not path.is_symlink(), "Owned traced raw observation was not retained")
    record = test.trace[lo]
    expected = ["docker", "exec", test.container, "adb", "-s", "emulator-5580", "shell", *map(str, command)]
    require(record.get("kind") == "command" and record.get("argv") == expected and record.get("returncode") == 0 and
        record.get("evidence") == relative, "Unowned/failed health command")
    reference = raw_observation_ref(path, command=command, returncode=record["returncode"])
    require(record.get("output_sha256") == reference["sha256"], "Original health read bytes changed")
    return path.read_text(), {"path": relative, "trace_index": lo, **reference}


def observe(test, ordinal, *, monotonic_ns=time.monotonic_ns, realtime_ns=time.time_ns, process_uids=None):
    require(type(ordinal) is int and ordinal >= 1, "Unique positive health attempt required")
    admitted_uids = None if process_uids is None else validate_process_uids(process_uids)
    directory = f"soak-health/sample-{ordinal:06d}"
    require(not (test.output / directory).exists(), "Never reuse successful or failed health attempt")
    began, real_began = monotonic_ns(), realtime_ns()
    files, values = {}, {}
    def read(name, *command):
        raw, record = read_new(test, directory + "/" + name + ".txt", *command)
        files[name] = record; values[name] = raw; return raw
    boot_before = phone.boot_identity(read("boot-before", "cat", "/proc/sys/kernel/random/boot_id"))
    require(read("boot-completed", "getprop", "sys.boot_completed").strip() == "1", "Boot not complete")
    processes = {}
    for role, name in contract.PROCESS_NAMES.items():
        pid_before = read(role + "-pid-before", "pidof", name)
        raw = {"pid_before": pid_before}
        if admitted_uids is None:
            pid = phone.phone_pid(pid_before)
        else:
            raw["ps_before"] = read(role + "-ps-before", *PROCESS_TABLE_COMMAND)
            pid = qualified_pid(pid_before, raw["ps_before"], name, admitted_uids[role])
        raw.update({"stat_before": read(role + "-stat-before", "su", "0", "cat", f"/proc/{pid}/stat"),
            "status": read(role + "-status", "su", "0", "cat", f"/proc/{pid}/status"),
            "fd": read(role + "-fd", "su", "0", "ls", "-1", f"/proc/{pid}/fd"),
            "stat_after": read(role + "-stat-after", "su", "0", "cat", f"/proc/{pid}/stat"),
            "pid_after": read(role + "-pid-after", "pidof", name)})
        if admitted_uids is not None:
            raw["ps_after"] = read(role + "-ps-after", *PROCESS_TABLE_COMMAND)
        processes[role] = process_metric(raw, pid, name=name,
            expected_uid=None if admitted_uids is None else admitted_uids[role])
    require(len({row["pid"] for row in processes.values()}) == len(processes), "Protected roles share a PID")
    counts = task_counts(read("activities", "dumpsys", "activity", "activities"))
    read("windows", "dumpsys", "window", "windows")
    read("input", "dumpsys", "input")
    read("events", *EVENTS_COMMAND)
    port = phone.modem_port(read("modem-port", "getprop", phone.MODEM_PROPERTY))
    services = phone.radio_services(read("radio-services", "su", "0", "service", "list"))
    boot_after = phone.boot_identity(read("boot-after", "cat", "/proc/sys/kernel/random/boot_id"))
    require(boot_before == boot_after, "Android reboot during health sample")
    ended, real_ended = monotonic_ns(), realtime_ns()
    require(0 <= ended - began <= contract.HEALTH_POLICY["maximum_sample_collection_ns"] and
        abs((ended - began) - (real_ended - real_began)) <= contract.HEALTH_POLICY["maximum_sample_clock_divergence_ns"],
        "Invalid sample clock/collection duration")
    return {"ordinal": ordinal, "observer": OBSERVER, "container_id": test.container, "image_id": test.image,
        "boot_id": boot_before, "began_monotonic_ns": began, "ended_monotonic_ns": ended,
        "began_realtime_ns": real_began, "ended_realtime_ns": real_ended,
        "processes": processes, "counts": counts, "modem_port": port, "radio_services": services, "files": files,
        **({"process_uid_bindings": admitted_uids} if admitted_uids is not None else {})}
