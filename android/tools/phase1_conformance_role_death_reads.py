"""Shared private exact-role collection; raw failures remain failures."""
import re
import time
from pathlib import Path
import phase1_conformance_role_death_health as intents
import phase1_conformance_replacement_health as original
health = original.health
core_audit = original.core_audit
require = original.require
raw_ref = intents.raw_ref

def role_selection(pidof_raw, table_raw, uid, role):
    """Strict numeric table, including absence; no UID-wide PID wildcard."""
    tokens = pidof_raw.split()
    require(all(re.fullmatch(r"[1-9][0-9]*", token) for token in tokens) and len(tokens) == len(set(tokens)),
            "Malformed/duplicate client pidof inventory")
    lines = table_raw.splitlines()
    require(lines and lines[0].split() == ["UID", "PID", "NAME"], "Missing original numeric ps table")
    rows = []
    for line in lines[1:]:
        match = re.fullmatch(r"\s*(0|[1-9][0-9]*)\s+([1-9][0-9]*)\s+(\S(?:.*\S)?)\s*", line)
        require(match is not None, "Malformed original client ps row")
        rows.append((int(match[1]), int(match[2]), match[3]))
    require(rows and len({row[1] for row in rows}) == len(rows), "Empty/duplicate ps inventory")
    selected = [pid for owner, pid, name in rows if owner == uid and name == health.contract.PROCESS_NAMES[role]]
    require(len(selected) <= 1 and (not selected or str(selected[0]) in tokens), "Ambiguous/missing client PID/UID join")
    # pidof may include other users, but every token must have this exact name
    # in the independently captured numeric table.
    require(set(map(int, tokens)) == {pid for _owner, pid, name in rows if name == health.contract.PROCESS_NAMES[role]},
            "Client pidof/ps inventory differs")
    return selected[0] if selected else None
def absent_read(trace, row, intent, container, *, selected_epoch=None):
    """Only actual exit1+empty pidof or exact ENOENT from this client PID.
    Timeout/permission denial/transport/parser failures are never intentional.
    """
    require(row.get("kind") == "command" and type(row.get("returncode")) is int and row["returncode"] == 1 and
            type(row.get("started_monotonic_ns")) is int and type(row.get("ended_monotonic_ns")) is int,
            "Not an original client-absence read")
    role = intent["role"]
    command = row.get("argv")
    prefix = ["docker", "exec", container, "adb", "-s", "emulator-5580", "shell"]
    require(isinstance(command, list) and command[:7] == prefix and isinstance(row.get("evidence"), str) and
            re.fullmatch(r"soak-health/sample-[0-9]{6}/" + re.escape(role) + r"-(?:pid-before|pid-after|stat-before|stat-after|status|fd)\.txt", row["evidence"]),
            "Failure was not an exact original client health command")
    suffix = command[7:]
    if suffix == ["pidof", health.contract.PROCESS_NAMES[role]]:
        return "pidof_absent"
    pid = (intent["before"] if selected_epoch is None else original.epoch(selected_epoch))["pid"]
    paths = {f"/proc/{pid}/stat", f"/proc/{pid}/status", f"/proc/{pid}/fd"}
    require(len(suffix) in (4, 5) and suffix[:2] == ["su", "0"] and suffix[-1] in paths and
            (suffix[2:3] == ["cat"] and suffix[-1] != f"/proc/{pid}/fd" or
             suffix[2:4] == ["ls", "-1"] and suffix[-1] == f"/proc/{pid}/fd"),
            "Failed proc read belongs to another PID/role")
    return "proc_enoent"

def observed_failure_epoch(reader, ordinal, uid, role):
    """Provisional exact raw observation, NOT authority to accept a new epoch.

    A retiring canary/new process can interrupt a proc read too. Its earlier
    numeric UID+PID+stat proof is retained and later MUST match the independently
    reopened actor incarnation AND precise command interval. Without stat-before
    there is no defensible unknown PID/start epoch, so only old-PID absence works.
    """
    prefix = f"soak-health/sample-{ordinal:06d}/"
    values = {}
    for name in (role + "-pid-before", role + "-ps-before", role + "-stat-before"):
        rows = [row for row in reader.trace if row.get("evidence") == prefix + name + ".txt" and row.get("returncode") == 0]
        if not rows: return None
        require(len(rows) == 1, "Observed interrupted client prefix was duplicated")
        row = rows[0]; path = Path(reader.output) / row["evidence"]
        require(raw_ref(path)["sha256"] == row["output_sha256"], "Observed interrupted client prefix changed")
        values[name] = path.read_text()
    pid = health.qualified_pid(values[role + "-pid-before"], values[role + "-ps-before"],
        health.contract.PROCESS_NAMES[role], uid)
    expected = ["docker", "exec", reader.container, "adb", "-s", "emulator-5580", "shell", "su", "0", "cat", f"/proc/{pid}/stat"]
    require(rows[0]["argv"] == expected, "Observed interrupted stat belongs to another process")
    return health.proc_epoch(values[role + "-stat-before"], pid)


CROSSING_FIELDS = ("pid_before", "ps_before", "stat_before", "status", "fd", "stat_after", "pid_after", "ps_after")


def crossed_values(values, rows, ordinal, uid, intent, container):
    """Only six consistent old resource reads followed by two new PID joins.

    This is NOT a complete metric or replacement authority. Keep the old raw
    RSS/FD as a partial, and the new PID as membership only until a full new
    metric and an independently reopened owned action bind its start epoch.
    """
    role = intent["role"]
    require(type(ordinal) is int and ordinal > 0 and type(uid) is int and uid > 0 and
            role in intents.SCENARIO_ROLES.values() and set(values) == set(CROSSING_FIELDS) and len(rows) == 8,
            "Exact affected-role eight-read crossing required")
    name = health.contract.PROCESS_NAMES[role]
    old_pid = role_selection(values["pid_before"], values["ps_before"], uid, role)
    new_pid = role_selection(values["pid_after"], values["ps_after"], uid, role)
    require(old_pid is not None and new_pid is not None and old_pid != new_pid, "Crossing needs distinct exact same-UID/name old/new PIDs")
    before = health.proc_epoch(values["stat_before"], old_pid)
    require(before == health.proc_epoch(values["stat_after"], old_pid) == original.epoch(intent["before"]),
            "Crossing old stat epochs differ from the owned original epoch")
    expected_commands = {
        "pid_before": ["pidof", name], "ps_before": list(health.PROCESS_TABLE_COMMAND),
        "stat_before": ["su", "0", "cat", f"/proc/{old_pid}/stat"],
        "status": ["su", "0", "cat", f"/proc/{old_pid}/status"],
        "fd": ["su", "0", "ls", "-1", f"/proc/{old_pid}/fd"],
        "stat_after": ["su", "0", "cat", f"/proc/{old_pid}/stat"],
        "pid_after": ["pidof", name], "ps_after": list(health.PROCESS_TABLE_COMMAND),
    }
    prefix = ["docker", "exec", container, "adb", "-s", "emulator-5580", "shell"]
    previous = 0
    indices = []
    for field, row in zip(CROSSING_FIELDS, rows):
        require(row.get("kind") == "command" and type(row.get("returncode")) is int and row["returncode"] == 0 and
                type(row.get("sequence")) is int and row["sequence"] >= 0 and
                type(row.get("started_monotonic_ns")) is int and type(row.get("ended_monotonic_ns")) is int and
                0 < row["started_monotonic_ns"] <= row["ended_monotonic_ns"] and
                previous <= row["started_monotonic_ns"], "Crossing command clock/type/exit changed")
        require(row["argv"] == prefix + expected_commands[field] and row["evidence"] ==
                f"soak-health/sample-{ordinal:06d}/{role}-" + field.replace("_", "-") + ".txt",
                "Crossing command owner/PID/role/path changed")
        previous = row["ended_monotonic_ns"]; indices.append(row["sequence"])
    require(indices == list(range(indices[0], indices[0] + 8)), "Crossing original eight reads are not contiguous")
    uid_fields = health.status_field(values["status"], "Uid",
        r"Uid:[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]*", "Crossing old status UID changed")
    pid_fields = health.status_field(values["status"], "Pid", r"Pid:[ \t]+([1-9][0-9]*)", "Crossing old status PID changed")
    rss_fields = health.status_field(values["status"], "VmRSS", r"VmRSS:[ \t]+([1-9][0-9]*) kB", "Crossing old VmRSS invalid")
    require(uid_fields == (str(uid),) * 4 and pid_fields == (str(old_pid),), "Crossing old raw UID/PID differs")
    fds = values["fd"].splitlines()
    require(fds and all(re.fullmatch(r"[0-9]+", token) for token in fds) and len(fds) == len(set(fds)), "Crossing old FD inventory invalid")
    try:
        health.process_metric(values, old_pid, name=name, expected_uid=uid)
    except ValueError as error:
        require(str(error) == "PID recycled while reading resource metric", "Crossing does not reproduce the exact original strict PID failure")
    else:
        raise ValueError("Crossing cannot relabel a successful strict metric")
    return dict(kind="all_successful_old_resources_new_pid_join_not_complete_metric", role=role,
        old_metric={**before, "uid": uid, "rss_kib": int(rss_fields[0]), "fd_count": len(fds)}, new_pid=new_pid,
        trace_indices=indices, old_metric_began_monotonic_ns=rows[0]["started_monotonic_ns"],
        old_metric_ended_monotonic_ns=rows[5]["ended_monotonic_ns"],
        new_join_began_monotonic_ns=rows[6]["started_monotonic_ns"], new_join_ended_monotonic_ns=rows[7]["ended_monotonic_ns"])


def crossed_role_fence(reader, ordinal, uid, intent):
    """Reopen every original successful read, not a parser-error summary."""
    rows, values = [], {}
    for field in CROSSING_FIELDS:
        relative = f"soak-health/sample-{ordinal:06d}/{intent['role']}-" + field.replace("_", "-") + ".txt"
        matches = [row for row in reader.trace if row.get("evidence") == relative]
        require(len(matches) == 1, "Crossing raw read missing/duplicated")
        row = matches[0]; path = Path(reader.output) / relative
        require(raw_ref(path)["sha256"] == row["output_sha256"], "Crossing original raw bytes changed")
        rows.append(row); values[field] = path.read_text()
    return crossed_values(values, rows, ordinal, uid, intent, reader.container)


def bind_crossing_to_action(crossing, leg):
    """Old resources end PRE-KILL, never at the expanded eight-read boundary."""
    require(crossing["role"] == leg["role"] and
            {key: crossing["old_metric"][key] for key in original.EPOCH_FIELDS} == leg["before"] and
            crossing["old_metric"]["uid"] == leg["role_uid"] and crossing["new_pid"] == leg["after"]["pid"] and
            crossing["old_metric_ended_monotonic_ns"] <= leg["absent_begin_monotonic_ns"] and
            max(leg["old_end_monotonic_ns"], leg["new_start_monotonic_ns"]) <= crossing["new_join_began_monotonic_ns"] <=
            crossing["new_join_ended_monotonic_ns"] <= leg["ended_monotonic_ns"] <= leg["deadline_monotonic_ns"],
            "Crossing lacks independently owned pre-kill resources/new endpoint/bounded action")

def read_actual(reader, relative_path, command, *, allow_absence=False, role=None):
    """Retain actual nonzero command bytes without re-labelling them successful."""
    index = len(reader.trace)
    reader.command(["docker", "exec", reader.container, "adb", "-s", "emulator-5580", "shell", *command],
                   evidence=relative_path, allowed=(0, 1) if allow_absence else (0,))
    require(len(reader.trace) == index + 1, "Missing original supplement command")
    row = reader.trace[index]
    path = Path(reader.output) / relative_path
    raw = path.read_text()
    reference = (health.raw_observation_ref(path, command=command, returncode=row["returncode"])
        if tuple(command) == health.EVENTS_COMMAND else raw_ref(path,
            allow_empty=allow_absence and row["returncode"] == 1 and command == ["pidof", health.contract.PROCESS_NAMES[role]]))
    return raw, dict(path=relative_path, trace_index=index, **reference), row["returncode"]

def protected_supplement(reader, ordinal, uid_bindings, intent, *, monotonic_ns=time.monotonic_ns, realtime_ns=time.time_ns):
    """All four protected roles + actual boot/radio/tasks/events; NO client RSS/FD
    invented. Additional pidof+ps witness proves only current UID membership.
    """
    affected = intent['role']
    uids = health.validate_process_uids(uid_bindings)
    base = f"replacement-guards/attempt-{ordinal:06d}"
    files, raw = {}, {}
    began, real_began = monotonic_ns(), realtime_ns()
    def read(name, *command, allow_absence=False):
        value, ref, code = read_actual(reader, base + "/" + name + ".txt", list(command), allow_absence=allow_absence, role=affected)
        files[name] = ref; raw[name] = value
        require(code == 0 or allow_absence and code == 1 and value.strip() == "", "Malformed absence/failed protected read")
        return value
    boot = health.phone.boot_identity(read("boot-before", "cat", "/proc/sys/kernel/random/boot_id"))
    require(read("boot-completed", "getprop", "sys.boot_completed").strip() == "1", "Boot incomplete")
    processes = {}
    for role, name in health.contract.PROCESS_NAMES.items():
        if role == affected: continue
        values = {"pid_before": read(role + "-pid-before", "pidof", name),
                  "ps_before": read(role + "-ps-before", *health.PROCESS_TABLE_COMMAND)}
        pid = health.qualified_pid(values["pid_before"], values["ps_before"], name, uids[role])
        for field, command in (("stat_before", ["su", "0", "cat", f"/proc/{pid}/stat"]),
                               ("status", ["su", "0", "cat", f"/proc/{pid}/status"]),
                               ("fd", ["su", "0", "ls", "-1", f"/proc/{pid}/fd"]),
                               ("stat_after", ["su", "0", "cat", f"/proc/{pid}/stat"]),
                               ("pid_after", ["pidof", name]), ("ps_after", list(health.PROCESS_TABLE_COMMAND))):
            values[field] = read(role + "-" + field.replace("_", "-"), *command)
        processes[role] = health.process_metric(values, pid, name=name, expected_uid=uids[role])
    client_raw = {"pid_before": read(affected + "-pid-before", "pidof", health.contract.PROCESS_NAMES[affected], allow_absence=True),
                  "ps_before": read(affected + "-ps-before", *health.PROCESS_TABLE_COMMAND)}
    client_pid = role_selection(client_raw["pid_before"], client_raw["ps_before"], uids[affected], affected)
    if client_pid is not None:
        for field, command in (("stat_before", ["su", "0", "cat", f"/proc/{client_pid}/stat"]),
                               ("status", ["su", "0", "cat", f"/proc/{client_pid}/status"]),
                               ("fd", ["su", "0", "ls", "-1", f"/proc/{client_pid}/fd"]),
                               ("stat_after", ["su", "0", "cat", f"/proc/{client_pid}/stat"])):
            client_raw[field] = read(affected + "-" + field.replace("_", "-"), *command)
    client_raw["pid_after"] = read(affected + "-pid-after", "pidof", health.contract.PROCESS_NAMES[affected], allow_absence=True)
    client_raw["ps_after"] = read(affected + "-ps-after", *health.PROCESS_TABLE_COMMAND)
    require(role_selection(client_raw["pid_after"], client_raw["ps_after"], uids[affected], affected) == client_pid,
            "Client changed during protected supplement")
    role_metric = None if client_pid is None else health.process_metric(client_raw, client_pid,
        name=health.contract.PROCESS_NAMES[affected], expected_uid=uids[affected])
    if role_metric is not None: processes[affected] = role_metric
    counts = health.task_counts(read("activities", "dumpsys", "activity", "activities"))
    read("windows", "dumpsys", "window", "windows"); read("input", "dumpsys", "input")
    read("events", *health.EVENTS_COMMAND)
    port = health.phone.modem_port(read("modem-port", "getprop", health.phone.MODEM_PROPERTY))
    radio = health.phone.radio_services(read("radio-services", "su", "0", "service", "list"))
    require(health.phone.boot_identity(read("boot-after", "cat", "/proc/sys/kernel/random/boot_id")) == boot, "Boot changed during partial observation")
    require(not core_audit.protected_events(raw["events"]), "Protected crash/ANR during replacement supplement")
    ended, real_ended = monotonic_ns(), realtime_ns()
    require(0 <= ended - began <= health.contract.HEALTH_POLICY["maximum_sample_collection_ns"] and
        abs((ended - began) - (real_ended - real_began)) <= health.contract.HEALTH_POLICY["maximum_sample_clock_divergence_ns"],
        "Supplement clock/collection bound changed")
    return dict(schema=1, kind="interrupted_exact_role_with_actual_four_role_health_not_qualified", ordinal=ordinal,
        affected_role=affected, permit_id=intent["permit_id"], boot_id=boot, container_id=reader.container, image_id=reader.image,
        process_uid_bindings=uids, processes=processes, role_metric=role_metric,
        counts=counts, modem_port=port, radio_services=radio, files=files, began_monotonic_ns=began, ended_monotonic_ns=ended,
        began_realtime_ns=real_began, ended_realtime_ns=real_ended, runtime_qualified=False)



