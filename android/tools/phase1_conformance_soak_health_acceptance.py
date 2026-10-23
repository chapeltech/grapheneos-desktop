#!/usr/bin/env python3
"""Independent raw health/epoch/resource core. Disturbance semantic audit pending.

This module cannot certify the complete 24-hour conformance campaign. It reopens
original observed files/command rows, never accepts resource/PID summary alone.
"""
from pathlib import Path
import re

import phase1_conformance_soak_contract as contract
import phase1_conformance_soak_health as observer
from phase1_conformance_common import file_ref

require = contract.require


def audit_sample(directory, row, trace, *, process_uids=None):
    directory = Path(directory).absolute()
    require(directory.is_dir() and directory.resolve(strict=True) == directory and not directory.is_symlink(),
        "Literal canonical original sample directory required")
    admitted_uids = None if process_uids is None else observer.validate_process_uids(process_uids)
    if "process_uid_bindings" in row:
        observer.validate_process_uids(row["process_uid_bindings"])
    require((admitted_uids is None and "process_uid_bindings" not in row or
        admitted_uids is not None and row.get("process_uid_bindings") == admitted_uids),
        "Sample UID selection lacks matching independent admission")
    require(type(row["ordinal"]) is int and row["ordinal"] > 0,
        "Sample ordinal must be a positive exact integer")
    require(row["observer"] == observer.OBSERVER and set(row["processes"]) == set(contract.PROCESS_NAMES), "Wrong observer/process closure")
    prefix = f"soak-health/sample-{row['ordinal']:06d}/"
    raw, indices = {}, []
    for name, record in sorted(row["files"].items(), key=lambda item: item[1]["trace_index"]):
        relative = record["path"]; path = directory / relative
        index = record["trace_index"]; indices.append(index)
        require(type(index) is int and 0 <= index < len(trace), "Missing traced original read")
        command = trace[index]
        require(relative == prefix + name + ".txt" and path.resolve(strict=True) == path and path.is_relative_to(directory) and
            not path.is_symlink() and observer.raw_observation_ref(path,
                command=command.get("argv", [])[7:] if name == "events" else (), returncode=command.get("returncode")) ==
                {key: record[key] for key in ("sha256", "bytes")}, "Original sample file changed/aliased")
        require(command.get("kind") == "command" and command.get("returncode") == 0 and command.get("evidence") == relative and
            command.get("output_sha256") == record["sha256"] and
            row["began_monotonic_ns"] <= command["started_monotonic_ns"] <= command["ended_monotonic_ns"] <= row["ended_monotonic_ns"],
            "Sample read not inside exact owned health window")
        raw[name] = path.read_text()
    require(indices == list(range(indices[0], indices[0] + len(indices))), "Original health reads were interleaved/reordered")
    expected = [("boot-before", ["cat", "/proc/sys/kernel/random/boot_id"]), ("boot-completed", ["getprop", "sys.boot_completed"])]
    processes = {}
    for role, name in contract.PROCESS_NAMES.items():
        values = {field: raw[role + "-" + field.replace("_", "-")] for field in
            (("pid_before", "stat_before", "status", "fd", "stat_after", "pid_after") +
             (() if admitted_uids is None else ("ps_before", "ps_after")))}
        pid = (observer.phone.phone_pid(values["pid_before"]) if admitted_uids is None else
            observer.qualified_pid(values["pid_before"], values["ps_before"], name, admitted_uids[role]))
        processes[role] = observer.process_metric(values, pid, name=name,
            expected_uid=None if admitted_uids is None else admitted_uids[role])
        expected += [(role + "-pid-before", ["pidof", name])]
        if admitted_uids is not None:
            expected += [(role + "-ps-before", list(observer.PROCESS_TABLE_COMMAND))]
        expected += [
            (role + "-stat-before", ["su", "0", "cat", f"/proc/{pid}/stat"]),
            (role + "-status", ["su", "0", "cat", f"/proc/{pid}/status"]),
            (role + "-fd", ["su", "0", "ls", "-1", f"/proc/{pid}/fd"]),
            (role + "-stat-after", ["su", "0", "cat", f"/proc/{pid}/stat"]), (role + "-pid-after", ["pidof", name])]
        if admitted_uids is not None:
            expected += [(role + "-ps-after", list(observer.PROCESS_TABLE_COMMAND))]
    expected += [("activities", ["dumpsys", "activity", "activities"]), ("windows", ["dumpsys", "window", "windows"]),
        ("input", ["dumpsys", "input"]), ("events", list(observer.EVENTS_COMMAND)),
        ("modem-port", ["getprop", observer.phone.MODEM_PROPERTY]), ("radio-services", ["su", "0", "service", "list"]),
        ("boot-after", ["cat", "/proc/sys/kernel/random/boot_id"])]
    require(list(raw) == [name for name, _ in expected] and processes == row["processes"], "Metric/order summary differs from original")
    prefix_argv = ["docker", "exec", row["container_id"], "adb", "-s", "emulator-5580", "shell"]
    require(all(trace[index]["argv"] == prefix_argv + command for index, (_name, command) in zip(indices, expected)),
        "Wrong read-only command or guest owner")
    require(len({value["pid"] for value in processes.values()}) == len(processes) and
        observer.phone.boot_identity(raw["boot-before"]) == observer.phone.boot_identity(raw["boot-after"]) == row["boot_id"] and
        raw["boot-completed"].strip() == "1" and observer.task_counts(raw["activities"]) == row["counts"] and
        observer.phone.modem_port(raw["modem-port"]) == row["modem_port"] and
        observer.phone.radio_services(raw["radio-services"]) == row["radio_services"], "Raw boot/task/phone/radio identity differs")
    return row


def audit_resources(samples, checkpoints, transitions, clocks):
    """Derive resource/epoch continuity after every sample was raw-audited.

Explicit transitions must be independently tied to real disturbance actions by
the still-pending scenario auditor; this function does NOT authorize them itself.
"""
    policy = contract.HEALTH_POLICY
    require(len(samples) >= 2 and samples[0]["ordinal"] == 1 and
        [row["ordinal"] for row in samples] == list(range(1, len(samples) + 1)), "Missing original sample attempt")
    start, end, real_start, real_end = clocks
    require(all(type(value) is int and value > 0 for value in clocks) and
        contract.DURATION_SECONDS * 1_000_000_000 <= end - start <= contract.MAX_CAMPAIGN_NS and
        real_end - real_start >= contract.DURATION_SECONDS * 1_000_000_000 and
        abs((end - start) - (real_end - real_start)) <= policy["maximum_sample_clock_divergence_ns"], "Original whole-boot dual clocks incomplete")
    require(samples[-1]["ended_monotonic_ns"] - samples[0]["began_monotonic_ns"] >= contract.DURATION_SECONDS * 1_000_000_000,
        "Successful raw samples do not span a genuine 24 hours")
    require(samples[0]["began_monotonic_ns"] - start <= policy["maximum_sample_edge_ns"] and
        end - samples[-1]["ended_monotonic_ns"] <= policy["maximum_sample_edge_ns"], "Unobserved sample edge")
    baseline = samples[0]; previous = None; epochs = {}; used_transitions = set()
    uid_bindings = baseline.get("process_uid_bindings")
    if uid_bindings is not None:
        observer.validate_process_uids(uid_bindings)
    for sample in samples:
        require(sample.get("process_uid_bindings") == uid_bindings and
            (uid_bindings is None or all(type(sample["processes"][role].get("uid")) is int and
                sample["processes"][role]["uid"] == uid for role, uid in uid_bindings.items())),
            "Admitted process UID changed across whole-boot health observations")
        require((sample["boot_id"], sample["container_id"], sample["image_id"], sample["modem_port"], sample["radio_services"]) ==
            (baseline["boot_id"], baseline["container_id"], baseline["image_id"], baseline["modem_port"], baseline["radio_services"]),
            "Reboot/foreign image/guest or phone radio identity changed")
        begin, finish = sample["began_monotonic_ns"], sample["ended_monotonic_ns"]
        require(start <= begin <= finish <= end and finish - begin <= policy["maximum_sample_collection_ns"] and
            abs((finish - begin) - (sample["ended_realtime_ns"] - sample["began_realtime_ns"])) <= policy["maximum_sample_clock_divergence_ns"] and
            (previous is None or previous["ended_monotonic_ns"] <= begin and
                begin - previous["ended_monotonic_ns"] <= policy["maximum_sample_gap_ns"]), "Invalid sample gap/collection/clock order")
        for role, value in sample["processes"].items():
            epoch = value["pid"], value["start_ticks"]
            if previous is not None:
                old = previous["processes"][role]
                old_epoch = old["pid"], old["start_ticks"]
                if old_epoch != epoch:
                    matches = [(index, row) for index, row in enumerate(transitions) if row["role"] == role and
                        row["before"] == {key: old[key] for key in ("pid", "start_ticks")} and
                        row["after"] == {key: value[key] for key in ("pid", "start_ticks")} and
                        previous["began_monotonic_ns"] <= row["began_monotonic_ns"] < row["ended_monotonic_ns"] <= finish]
                    require(role not in {"system_server", "phone"} and len(matches) == 1 and matches[0][0] not in used_transitions,
                        "Unexpected/missing/duplicate protected epoch transition: " + role)
                    used_transitions.add(matches[0][0])
            first = epochs.setdefault((role, *epoch), value)
            require(value["fd_count"] - first["fd_count"] <= policy["maximum_fd_growth_per_incarnation"] and
                value["rss_kib"] - first["rss_kib"] <= policy["maximum_rss_growth_kib_per_incarnation"], "Per-epoch FD/RSS bound exceeded")
        require(sample["counts"]["tasks"] - baseline["counts"]["tasks"] <= policy["maximum_task_growth_per_run"] and
            sample["counts"]["roots"] - baseline["counts"]["roots"] <= policy["maximum_root_growth_per_run"], "Intermediate task/root residual exceeded")
        previous = sample
    require(used_transitions == set(range(len(transitions))), "Unobserved or invented planned epoch transition")
    require(len(checkpoints) >= contract.MINIMUM_ROUNDS + 1 and checkpoints[0]["round"] == 0 and
        [row["round"] for row in checkpoints] == list(range(len(checkpoints))), "Missing whole-boot settled round checkpoints")
    initial, used_samples = checkpoints[0], set()
    for checkpoint in checkpoints:
        selected = [row for row in samples if checkpoint["began_monotonic_ns"] <= row["began_monotonic_ns"] and
            row["ended_monotonic_ns"] <= checkpoint["ended_monotonic_ns"]]
        require(len(selected) >= 2 and selected[-1]["ended_monotonic_ns"] - selected[0]["began_monotonic_ns"] >= 1_000_000_000 and
            all(row["ordinal"] not in used_samples for row in selected), "Settled checkpoint missing two unique raw samples")
        used_samples.update(row["ordinal"] for row in selected)
        expected = {role: {key: selected[0]["processes"][role][key] for key in ("pid", "start_ticks")} for role in contract.PROCESS_NAMES}
        require(checkpoint["epochs"] == expected and all({role: {key: row["processes"][role][key] for key in ("pid", "start_ticks")}
            for role in contract.PROCESS_NAMES} == expected for row in selected), "Settled checkpoint changed process epoch")
        if checkpoint["round"] == 0:
            derived_baseline = {role: {"fd_count": min(row["processes"][role]["fd_count"] for row in selected),
                "rss_kib": min(row["processes"][role]["rss_kib"] for row in selected)} for role in contract.PROCESS_NAMES}
            require(initial["resource_baseline"] == derived_baseline, "Settled resource baseline differs from original samples")
        for role in contract.PROCESS_NAMES:
            fd_floor = min(row["processes"][role]["fd_count"] for row in selected)
            rss_floor = min(row["processes"][role]["rss_kib"] for row in selected)
            require(fd_floor - initial["resource_baseline"][role]["fd_count"] <= policy["maximum_cumulative_fd_residual"] and
                rss_floor - initial["resource_baseline"][role]["rss_kib"] <= policy["maximum_cumulative_rss_residual_kib"],
                "Cumulative settled FD/RSS residual exceeded across replacement epochs")
    return {"status": "raw_resource_core_passed_not_complete_soak", "samples": len(samples),
        "runtime_qualified": False, "qualification_claimed": False}


def protected_events(raw):
    result = []
    pattern = re.compile(r"\b(am_(?:anr|crash))\s*:\s*\[\s*[0-9]+\s*,\s*([1-9][0-9]*)\s*,\s*([^,\]\n]+)\s*,")
    protected = {*contract.PROCESS_NAMES.values(), "org.wonad.fixture"}
    for line in raw.splitlines():
        match = pattern.search(line)
        require(match is not None or not re.search(r"\bam_(?:anr|crash)\s*:\s*\[", line), "Malformed structured crash/ANR event")
        if match and match[3].strip().split(":", 1)[0] in protected:
            result.append({"kind": match[1], "pid": int(match[2]), "process": match[3].strip(), "line": line})
    return result


def audit_complete_campaign(*args, **kwargs):
    raise NotImplementedError(contract.IMPLEMENTATION_STATUS + ": all nine raw disturbance/action validators remain required")
