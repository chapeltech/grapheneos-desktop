"""Independent raw role-death health replay; default observers stay strict."""
from pathlib import Path
import copy
import json
import importlib
from phase1_conformance_common import canonical

import phase1_conformance_role_death_health as producer
import phase1_conformance_role_death_reads as reads
import phase1_conformance_replacement_health_acceptance as old
health = old.health
core = old.core
sampling = old.sampling
require = old.require
ROLES = old.ROLES
literal = old.literal
exact_int = old.exact_int
file_ref = old.file_ref
load = old.load


def authenticate_actions(root, references, identity, uids, action_contracts, *, current_client_inputs=None):
    legs = []; seen = set()
    modules = {"client_death": "phase1_conformance_soak_client_death_acceptance",
               "systemui_death": "phase1_conformance_soak_systemui_death_acceptance",
               "malformed_calls": "phase1_conformance_soak_malformed_calls_acceptance"}
    require(type(action_contracts) is dict, "Externally admitted action contracts required")
    # The current installed member is an admission input, never authority
    # copied from an action's self-reported version/UID/chain summary.
    selected_clients = {} if current_client_inputs is None else current_client_inputs
    require(type(selected_clients) is dict and
            set(selected_clients) <= {ref["path"] for ref in references},
            "External current-client inputs must belong to original actions")
    for relative, selected in selected_clients.items():
        producer.relative(relative)
        require(type(selected) is dict and set(selected) == {"chain", "uid"} and
                type(selected["uid"]) is int and selected["uid"] == uids["client"] and
                type(selected["chain"]) in {list, tuple},
                "Exact external original client UID/chain required")
    for ref in references:
        require(type(ref) is dict and set(ref) == {"path", "sha256", "bytes"}, "Original sealed action reference required")
        path = literal(root, ref["path"])
        require(ref["path"] not in seen and file_ref(path) == {k:ref[k] for k in ("sha256","bytes")}, "Changed/replayed action")
        seen.add(ref["path"])
        report = load(path); scenario = report.get("scenario")
        require(scenario in modules and ref["path"] in action_contracts, "Unsupported/unadmitted role-death action")
        auditor = importlib.import_module(modules[scenario])
        selected = selected_clients.get(ref["path"])
        arguments = {} if selected is None else {
            "client_chain": selected["chain"], "client_uid": selected["uid"]}
        verdict = auditor.audit_action(path, action_contracts[ref["path"]], identity, **arguments)
        # The current client/malformed auditors return a scenario, whereas the
        # SystemUI auditor returns status. Each has just independently reopened
        # and validated the exact original report and raw journal above. Do not
        # invent a common status field or silently accept arbitrary return data.
        common_fields = {"runtime_qualified", "whole_campaign_complete", "processes", "transition"}
        if scenario == "systemui_death":
            require(set(verdict) == common_fields | {"status"} and verdict["status"] == auditor.STATUS,
                    "Exact SystemUI raw-auditor verdict required")
        else:
            require(set(verdict) == common_fields | {"scenario"} and verdict["scenario"] == scenario,
                    "Exact client/malformed raw-auditor verdict required")
        require(report["status"] == auditor.STATUS, "Original audited action status changed")
        leg = verdict["transition"]
        fields = {"action_nonce","scenario","role","role_uid","permit_id","before","after","started_monotonic_ns",
            "ended_monotonic_ns","deadline_monotonic_ns","absent_begin_monotonic_ns","absent_end_monotonic_ns",
            "old_end_monotonic_ns","new_start_monotonic_ns","action_relative","recovered_stage_relative"}
        require(verdict["runtime_qualified"] is False and verdict["whole_campaign_complete"] is False and
                type(leg) is dict and set(leg) == fields and leg["scenario"] == scenario and
                producer.SCENARIO_ROLES[scenario] == leg["role"] and leg["role_uid"] == uids[leg["role"]] and
                type(leg["role_uid"]) is int and leg["action_relative"] == ref["path"], "Audited transition scope changed")
        producer.epoch(leg["before"]); producer.epoch(leg["after"])
        for key in fields:
            if key.endswith("monotonic_ns"): exact_int(leg[key], minimum=1)
        require(leg["before"] != leg["after"] and leg["started_monotonic_ns"] <= leg["absent_begin_monotonic_ns"] <=
                leg["absent_end_monotonic_ns"] <= leg["ended_monotonic_ns"] <= leg["deadline_monotonic_ns"] and
                leg["deadline_monotonic_ns"] == leg["started_monotonic_ns"] + producer.MAX_ROLE_DEATH_NS and
                leg["started_monotonic_ns"] <= leg["new_start_monotonic_ns"] <= leg["absent_end_monotonic_ns"] and
                leg["started_monotonic_ns"] <= leg["old_end_monotonic_ns"] <= leg["absent_end_monotonic_ns"],
                "Audited original transition interval expanded")
        legs.append(leg)
    require(legs and len({r["permit_id"] for r in legs}) == len(legs), "Unique role-death actions required")
    legs.sort(key=lambda r:r["started_monotonic_ns"])
    for a,b in zip(legs,legs[1:]): require(a["ended_monotonic_ns"] <= b["started_monotonic_ns"], "Overlapping role-death actions")
    for role in ROLES:
        selected = [r for r in legs if r["role"] == role]
        for a,b in zip(selected,selected[1:]): require(a["after"] == b["before"], "Per-role original epoch chain changed")
    return legs


def admit_role(role, metric, began, ended, legs, initial):
    require(type(began) is int and type(ended) is int and began <= ended, "Original metric interval required")
    observed = producer.epoch({k:metric[k] for k in producer.EPOCH_FIELDS})
    selected = [leg for leg in legs if leg["role"] == role]
    if not selected:
        require(observed == initial[role], "Protected non-replaced role epoch changed")
        return
    require(initial[role] == selected[0]["before"], "Original baseline differs from first owned role")
    if observed == selected[0]["before"] and ended <= selected[0]["old_end_monotonic_ns"]: return
    for index, leg in enumerate(selected):
        limit = selected[index+1]["old_end_monotonic_ns"] if index+1 < len(selected) else None
        if observed == leg["after"] and leg["new_start_monotonic_ns"] <= began and (limit is None or ended <= limit): return
    raise ValueError("Unproved exact role incarnation/interval; UID-wide wildcard forbidden")


class RawReads:
    def __init__(self, root, trace, identity):
        self.root, self.trace, self.identity = root, trace, identity
        self.used, self.files = set(), set()
        prior = 0
        for index, row in enumerate(trace):
            require(row.get("kind") == "command" and type(row.get("sequence")) is int and row["sequence"] == index and
                    type(row.get("returncode")) is int and row["returncode"] in (0, 1) and
                    prior <= exact_int(row["started_monotonic_ns"], minimum=1) <= exact_int(row["ended_monotonic_ns"], minimum=1),
                    "Lost/failed/interleaved original read-only journal")
            prior = row["ended_monotonic_ns"]

    def read(self, index, relative, suffix, *, allowed=(0,), window=None):
        exact_int(index)
        require(index < len(self.trace) and index not in self.used, "Raw read missing/reused")
        row = self.trace[index]
        prefix = ["docker", "exec", self.identity["container_id"], "adb", "-s", "emulator-5580", "shell"]
        require(row["argv"] == prefix + list(suffix) and row["evidence"] == relative and row["returncode"] in allowed,
                "Original read-only command/owner/returncode changed")
        path = literal(self.root, relative)
        reference = (health.raw_observation_ref(path, command=suffix, returncode=row["returncode"])
            if tuple(suffix) == health.EVENTS_COMMAND else producer.raw_ref(path, allow_empty=row["returncode"] == 1 and list(suffix) ==
                ["pidof", suffix[-1]] and suffix[-1] in [health.contract.PROCESS_NAMES[r] for r in producer.SCENARIO_ROLES.values()]))
        require(reference["sha256"] == row["output_sha256"], "Original raw read bytes changed")
        if window is not None:
            require(window[0] <= row["started_monotonic_ns"] <= row["ended_monotonic_ns"] <= window[1],
                    "Raw read escaped its original observation window")
        self.used.add(index); self.files.add(relative)
        return path.read_text(), row

    def guard(self, index, ordinal, window):
        exact_int(index)
        require(index < len(self.trace) and index not in self.used, "Owner guard missing/reused")
        row = self.trace[index]; relative = f"guards/{ordinal:06d}.json"
        require(row["argv"] == ["docker", "container", "inspect", self.identity["container_id"]] and
                row["returncode"] == 0 and row["evidence"] == relative and
                window[0] <= row["started_monotonic_ns"] <= row["ended_monotonic_ns"] <= window[1] and
                file_ref(literal(self.root, relative))["sha256"] == row["output_sha256"], "Original owned guard changed")
        infos = load(literal(self.root, relative))
        require(type(infos) is list and len(infos) == 1, "Ambiguous original container owner")
        sampling.verify_owner(infos[0], self.identity)
        self.used.add(index); self.files.add(relative)


def replay_supplement(raw_reader, row, intent, uids):
    """Re-run actual observer against retained bytes; summaries confer no proof."""
    require(row["kind"] == "interrupted_exact_role_with_actual_four_role_health_not_qualified" and row["affected_role"] == intent["role"] and
            type(row["schema"]) is int and row["schema"] == 1 and
            row["runtime_qualified"] is False and row["permit_id"] == intent["permit_id"] and
            row["process_uid_bindings"] == uids, "Supplement type/admission changed")
    indices = [record["trace_index"] for record in row["files"].values()]
    require(indices and sorted(indices) == list(range(min(indices), max(indices) + 1)), "Supplement raw reads lost/interleaved")
    cursor = min(indices)
    class Replay:
        container = raw_reader.identity["container_id"]
        image = raw_reader.identity["image_id"]
        output = raw_reader.root
        trace = []
        def command(self, argv, *, evidence, allowed):
            nonlocal cursor
            require(argv[:7] == ["docker", "exec", self.container, "adb", "-s", "emulator-5580", "shell"],
                    "Replay transport owner changed")
            _value, command = raw_reader.read(cursor, evidence, argv[7:], allowed=allowed,
                window=(row["began_monotonic_ns"], row["ended_monotonic_ns"]))
            self.trace.append(command); cursor += 1
    # Recorded clocks are explicit injection into a read-only deterministic
    # replay, not replacements for missing original clock observations.
    mono = iter([row["began_monotonic_ns"], row["ended_monotonic_ns"]])
    real = iter([row["began_realtime_ns"], row["ended_realtime_ns"]])
    result = reads.protected_supplement(Replay(), row["ordinal"], uids, intent,
        monotonic_ns=lambda: next(mono), realtime_ns=lambda: next(real))
    # Replayed refs use local trace offsets; compare the original global indices
    # after reattaching the exact contiguous original positions.
    for ref in result["files"].values(): ref["trace_index"] += min(indices)
    require(cursor == max(indices) + 1 and result == row, "Supplement summary differs from original raw observation")
    return result


class OriginalAbsence(Exception):
    pass


def replay_interrupted(raw_reader, attempt, first, last, leg, uids):
    """Execute the original strict49 parser up to exactly its original failure."""
    affected = leg["role"]
    ordinal = attempt["ordinal"]
    cursor, captured = first, {}
    def read(name, *command):
        nonlocal cursor
        require(cursor <= last, "Original interrupted read prefix was incomplete")
        relative = f"soak-health/sample-{ordinal:06d}/" + name + ".txt"
        value, row = raw_reader.read(cursor, relative, command, allowed=(0, 1),
            window=(attempt["began_monotonic_ns"], attempt["ended_monotonic_ns"]))
        cursor += 1
        if row["returncode"] != 0:
            require(cursor == last + 1 and leg["absent_begin_monotonic_ns"] <= row["started_monotonic_ns"] <=
                    row["ended_monotonic_ns"] <= leg["absent_end_monotonic_ns"], "Absent read outside genuine mutation/recovery")
            selected_epoch = None
            if affected + "-stat-before" in captured:
                selected_pid = health.qualified_pid(captured[affected + "-pid-before"], captured[affected + "-ps-before"],
                    health.contract.PROCESS_NAMES[affected], uids[affected])
                selected_epoch = health.proc_epoch(captured[affected + "-stat-before"], selected_pid)
            category = reads.absent_read([], row, leg, raw_reader.identity["container_id"], selected_epoch=selected_epoch)
            if category == "pidof_absent": require(value.strip() == "", "Nonempty failed pidof is not absence")
            else:
                import re
                require(re.fullmatch(r"(?:cat|ls): " + re.escape(row["argv"][-1]) + r": No such file or directory\n?", value),
                        "Arbitrary proc error is not actual absence")
            raise OriginalAbsence()
        captured[name] = value
        return value
    try:
        require(health.phone.boot_identity(read("boot-before", "cat", "/proc/sys/kernel/random/boot_id")) ==
                raw_reader.identity["boot_id"] and read("boot-completed", "getprop", "sys.boot_completed").strip() == "1",
                "Original partial attempt lost boot identity")
        for role, name in health.contract.PROCESS_NAMES.items():
            values = dict(pid_before=read(role + "-pid-before", "pidof", name),
                          ps_before=read(role + "-ps-before", *health.PROCESS_TABLE_COMMAND))
            pid = health.qualified_pid(values["pid_before"], values["ps_before"], name, uids[role])
            for field, command in (("stat_before", ["su", "0", "cat", f"/proc/{pid}/stat"]),
                                   ("status", ["su", "0", "cat", f"/proc/{pid}/status"]),
                                   ("fd", ["su", "0", "ls", "-1", f"/proc/{pid}/fd"]),
                                   ("stat_after", ["su", "0", "cat", f"/proc/{pid}/stat"]),
                                   ("pid_after", ["pidof", name]), ("ps_after", list(health.PROCESS_TABLE_COMMAND))):
                values[field] = read(role + "-" + field.replace("_", "-"), *command)
            health.process_metric(values, pid, name=name, expected_uid=uids[role])
    except OriginalAbsence:
        pass
    else:
        raise ValueError("Claimed interrupted observation did not reproduce original client absence")
    require(cursor == last + 1, "Omitted interrupted original health read")
    # Earlier complete role observations cannot hide a resource spike merely
    # because a subsequent client read failed. Keep them as genuine extra metrics.
    metrics = {}
    for role, name in health.contract.PROCESS_NAMES.items():
        fields = ("pid_before", "ps_before", "stat_before", "status", "fd", "stat_after", "pid_after", "ps_after")
        keys = [role + "-" + field.replace("_", "-") for field in fields]
        if all(key in captured for key in keys):
            values = {field: captured[key] for field, key in zip(fields, keys)}
            pid = health.qualified_pid(values["pid_before"], values["ps_before"], name, uids[role])
            metrics[role] = health.process_metric(values, pid, name=name, expected_uid=uids[role])
    # A partial client status/fd read is not a complete metric, but an observed
    # spike must still be accounted for against the proven stat-before epoch.
    if affected + "-stat-before" in captured:
        pid = health.qualified_pid(captured[affected + "-pid-before"], captured[affected + "-ps-before"],
                                  health.contract.PROCESS_NAMES[affected], uids[affected])
        partial = {**health.proc_epoch(captured[affected + "-stat-before"], pid), "uid": uids[affected]}
        if affected + "-status" in captured:
            # Parse only genuinely present status fields. No missing FD read or
            # after-stat/pid witness is manufactured even as an intermediate.
            status = captured[affected + "-status"]
            uid_fields = health.status_field(status, "Uid",
                r"Uid:[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]*", "Partial client status UID changed")
            pid_fields = health.status_field(status, "Pid", r"Pid:[ \t]+([1-9][0-9]*)", "Partial client status PID changed")
            rss_fields = health.status_field(status, "VmRSS", r"VmRSS:[ \t]+([1-9][0-9]*) kB", "Partial client VmRSS changed")
            require(uid_fields == (str(uids[affected]),) * 4 and pid_fields == (str(pid),), "Partial client raw UID/PID differs")
            partial["rss_kib"] = int(rss_fields[0])
        if affected + "-fd" in captured:
            import re
            tokens = captured[affected + "-fd"].splitlines()
            require(tokens and all(re.fullmatch(r"[0-9]+", token) for token in tokens) and len(set(tokens)) == len(tokens),
                    "Malformed original partial FD inventory")
            partial["fd_count"] = len(tokens)
        metrics[affected] = partial
    return metrics


def replay_crossed(raw_reader, attempt, first, last, leg, uids):
    """Reproduce only the strict all-exit0 old-resource/new-PID failure.

    Earlier protected metrics are retained; affected RSS/FD end at the actual
    old stat-after command, not at either of the replacement PID join reads.
    """
    require(attempt["error"] == "PID recycled while reading resource metric", "Not the original strict crossing failure")
    cursor = first
    def read(name, *command):
        nonlocal cursor
        require(cursor <= last, "Original crossed read prefix incomplete")
        relative = f"soak-health/sample-{attempt['ordinal']:06d}/" + name + ".txt"
        payload, row = raw_reader.read(cursor, relative, command,
            window=(attempt["began_monotonic_ns"], attempt["ended_monotonic_ns"]))
        cursor += 1
        return payload, row
    require(health.phone.boot_identity(read("boot-before", "cat", "/proc/sys/kernel/random/boot_id")[0]) ==
            raw_reader.identity["boot_id"] and read("boot-completed", "getprop", "sys.boot_completed")[0].strip() == "1",
            "Original crossed attempt lost boot identity")
    metrics = {}
    for role, name in health.contract.PROCESS_NAMES.items():
        values, rows = {}, []
        def role_read(field, *command):
            payload, row = read(role + "-" + field.replace("_", "-"), *command)
            values[field] = payload; rows.append(row)
        role_read("pid_before", "pidof", name)
        role_read("ps_before", *health.PROCESS_TABLE_COMMAND)
        pid = health.qualified_pid(values["pid_before"], values["ps_before"], name, uids[role])
        for field, command in (("stat_before", ["su", "0", "cat", f"/proc/{pid}/stat"]),
                               ("status", ["su", "0", "cat", f"/proc/{pid}/status"]),
                               ("fd", ["su", "0", "ls", "-1", f"/proc/{pid}/fd"]),
                               ("stat_after", ["su", "0", "cat", f"/proc/{pid}/stat"]),
                               ("pid_after", ["pidof", name]), ("ps_after", list(health.PROCESS_TABLE_COMMAND))):
            role_read(field, *command)
        if role == leg["role"]:
            require(cursor == last + 1, "Crossing was not the final original affected-role eight reads")
            crossing = reads.crossed_values(values, rows, attempt["ordinal"], uids[role], leg, raw_reader.identity["container_id"])
            reads.bind_crossing_to_action(crossing, leg)
            metrics[role] = crossing["old_metric"]
            return metrics, crossing
        metrics[role] = health.process_metric(values, pid, name=name, expected_uid=uids[role])
    raise ValueError("Claimed crossing did not reproduce the original affected-role failure")


def bind_intents(root, records, legs):
    values = producer.validate_durable_intents(root, records)
    require(len(values) == len(legs), "Original intents/actions cardinality changed")
    files = set()
    for record in values:
        selected = [leg for leg in legs if leg["permit_id"] == record["permit_id"]]
        require(len(selected) == 1 and all(record[k] == selected[0][k] for k in set(record).intersection(selected[0])),
                "Provisional intent differs from independently reopened raw action")
        files.update("role-death-" + record["permit_id"] + "-" + suffix + ".json" for suffix in ("begin","end"))
    return files


def audit_stream(campaign_root, sampler_relative, *, identity, process_uids, actions, action_contracts,
                 current_client_inputs=None):
    """Bounded source-ready consumer; never claims 24h or complete campaign."""
    campaign_root = Path(campaign_root).absolute()
    producer.relative(sampler_relative)
    root = campaign_root / sampler_relative
    require(root.resolve(strict=True) == root and root.is_dir() and not root.is_symlink(), "Canonical original sampler required")
    uids = health.validate_process_uids(process_uids)
    value = load(literal(root, "sampler.json"))
    require(value["kind"] == "exact_role_death_continuous_health_v1" and
            value["status"] == "retained_replacement_health_not_qualified" and
            value["runtime_qualified"] is False and value["qualification_claimed"] is False and
            value["observer"] == health.OBSERVER and value["identity"] == identity and value["process_uid_bindings"] == uids,
            "Replacement sampler identity/status/admission changed")
    require(value.get("host_sources") == producer.role_source_bindings(), "Replacement health runtime source closure changed")
    require(1 <= exact_int(value["interval_seconds"], minimum=1) <= 300 and
            all(type(value[key]) is int and value[key] > 0 for key in
                ("began_monotonic_ns", "ended_monotonic_ns", "began_realtime_ns", "ended_realtime_ns")),
            "Original sampler interval/dual clock types changed")
    legs = authenticate_actions(campaign_root, actions, identity, uids, action_contracts,
                                current_client_inputs=current_client_inputs)
    require(all(value["began_monotonic_ns"] <= leg["started_monotonic_ns"] < leg["ended_monotonic_ns"] <=
                value["ended_monotonic_ns"] for leg in legs), "Continuous sampler did not cover original action lifetime")
    files = bind_intents(root, value["role_death_intents"], legs) | {"sampler.json", "commands.json"}
    trace = load(literal(root, "commands.json")); raw = RawReads(root, trace, identity)
    require(trace and value["began_monotonic_ns"] <= trace[0]["started_monotonic_ns"] and
            trace[-1]["ended_monotonic_ns"] <= value["ended_monotonic_ns"], "Raw read journal escaped original sampler lifetime")
    attempts, observations = value["attempts"], []
    initial = None
    require(len(attempts) >= 2 and [exact_int(row["ordinal"], minimum=1) for row in attempts] == list(range(1, len(attempts) + 1)),
            "Original attempt omitted/renumbered")
    for attempt in attempts:
        ordinal = attempt["ordinal"]
        started, ended = f"attempt-{ordinal:06d}-started.json", f"attempt-{ordinal:06d}-ended.json"
        require(load(literal(root, started)) == {"ordinal": ordinal, "began_monotonic_ns": attempt["began_monotonic_ns"]} and
                load(literal(root, ended)) == attempt, "Original attempt start/failure record changed")
        files.update((started, ended))
        begin, finish = exact_int(attempt["began_monotonic_ns"], minimum=1), exact_int(attempt["ended_monotonic_ns"], minimum=1)
        require(value["began_monotonic_ns"] <= begin <= finish <= value["ended_monotonic_ns"], "Attempt escaped sampler lifetime")
        guards = [index for index, row in enumerate(trace) if row.get("evidence") == f"guards/{ordinal:06d}.json"]
        require(len(guards) == 1, "Original attempt owner guard missing/duplicated")
        guard = guards[0]; raw.guard(guard, ordinal, (begin, finish))
        extra_metrics = {}; extra_windows = {}; crossing = None
        if attempt["status"] == "passed_raw_health_observation":
            require(attempt["error"] is None and attempt["sample"] == f"sample-{ordinal:06d}.json", "Successful original attempt changed")
            path = literal(root, attempt["sample"])
            require(file_ref(path) == attempt["sample_ref"], "Original successful sample bytes changed")
            row = core.audit_sample(root, load(path), trace, process_uids=uids)
            indices = sorted(ref["trace_index"] for ref in row["files"].values())
            require(indices[0] == guard + 1 and not raw.used.intersection(indices), "Original sample reads reordered/reused")
            raw.used.update(indices); files.add(attempt["sample"]); raw.files.update(ref["path"] for ref in row["files"].values())
            require(not core.protected_events(literal(root, row["files"]["events"]["path"]).read_text()), "Protected crash/ANR in original sample")
            require(begin <= row["began_monotonic_ns"] <= row["ended_monotonic_ns"] <= finish, "Sample escaped original attempt")
            if initial is None:
                require(ordinal == 1, "Missing complete original baseline")
                initial = {role: producer.epoch({k:metric[k] for k in producer.EPOCH_FIELDS}) for role,metric in row["processes"].items()}
            for role, metric in row["processes"].items():
                indices = [ref["trace_index"] for name, ref in row["files"].items() if name.startswith(role + "-")]
                admit_role(role, metric, trace[min(indices)]["started_monotonic_ns"], trace[max(indices)]["ended_monotonic_ns"], legs, initial)
        else:
            require(attempt["status"] == "failed" and isinstance(attempt["error"], str) and attempt["error"] and attempt["sample"] is None,
                    "Interrupted attempt was relabelled successful")
            pending_name = f"attempt-{ordinal:06d}-pending-role-death.json"
            pending = load(literal(root, pending_name)); files.add(pending_name)
            require(pending["status"] == "pending_original_action_and_raw_health_admission" and pending["runtime_qualified"] is False and
                    pending["original_attempt"] == attempt, "Original failure dropped/rewritten")
            matches = [leg for leg in legs if leg["permit_id"] == pending["permit_id"]]
            require(len(matches) == 1, "Interrupted original attempt lacks independently authenticated action")
            leg = matches[0]; affected = leg["role"]; last = exact_int(pending["failed_trace_index"])
            failure_kind = pending.get("failure_kind", "absence")
            require(failure_kind in ("absence", "all_successful_affected_role_crossing"), "Unknown provisional failure kind")
            if failure_kind == "all_successful_affected_role_crossing":
                extra_metrics, crossing = replay_crossed(raw, attempt, guard + 1, last, leg, uids)
                require(canonical(pending.get("crossing")) == canonical(crossing), "Provisional crossing summary differs from exact original raw")
                producer.epoch(pending["failed_role_epoch"])
                extra_windows[affected] = (crossing["old_metric_began_monotonic_ns"], crossing["old_metric_ended_monotonic_ns"])
            else:
                require("crossing" not in pending, "Absence cannot import a crossed metric")
                extra_metrics = replay_interrupted(raw, attempt, guard + 1, last, leg, uids)
            observed_epoch = None if affected not in extra_metrics else {key: extra_metrics[affected][key] for key in producer.EPOCH_FIELDS}
            require(pending.get("failed_role_epoch") == observed_epoch, "Provisional interrupted client epoch differs from raw UID/stat prefix")
            if affected in extra_metrics:
                client_indices = [index for index in range(guard + 1, last) if trace[index]["returncode"] == 0 and
                                  trace[index]["evidence"].rsplit("/", 1)[-1].startswith(affected + "-")]
                require(client_indices, "Partial client metric lacks original command identity")
                metric_window = extra_windows.get(affected, (trace[client_indices[0]]["started_monotonic_ns"],
                                                           trace[client_indices[-1]]["ended_monotonic_ns"]))
                admit_role(affected, extra_metrics[affected], *metric_window, legs, initial)
            supplement_name = f"attempt-{ordinal:06d}-role-death-supplement.json"
            require(pending["supplement"] == supplement_name and file_ref(literal(root, supplement_name)) == pending["supplement_ref"],
                    "Original protected supplement seal changed")
            files.add(supplement_name); row = load(literal(root, supplement_name))
            require(min(ref["trace_index"] for ref in row["files"].values()) == last + 1 and row["ordinal"] == ordinal,
                    "Interrupted attempt/supplement join changed")
            replay_supplement(raw, row, leg, uids)
            require(finish <= row["began_monotonic_ns"] <= row["ended_monotonic_ns"], "Supplement precedes its original failed attempt")
            if crossing is not None:
                require(row["role_metric"] is not None and
                        producer.epoch({key: row["role_metric"][key] for key in producer.EPOCH_FIELDS}) == leg["after"] and
                        row["role_metric"]["uid"] == leg["role_uid"] and row["ended_monotonic_ns"] <= leg["deadline_monotonic_ns"],
                        "Crossing requires independently owned full new role metric inside fixed deadline")
            if row["role_metric"] is None:
                require(affected not in row["processes"] and leg["absent_begin_monotonic_ns"] <= row["began_monotonic_ns"],
                        "Missing client metric not inside genuine bounded action")
                require(row["ended_monotonic_ns"] <= leg["absent_end_monotonic_ns"], "Missing client supplement outside genuine recovery interval")
            else:
                indices = [ref["trace_index"] for name, ref in row["files"].items() if name.startswith(affected + "-")]
                admit_role(affected, row["role_metric"], trace[min(indices)]["started_monotonic_ns"], trace[max(indices)]["ended_monotonic_ns"], legs, initial)
            for role,metric in row["processes"].items():
                indices = [ref["trace_index"] for name,ref in row["files"].items() if name.startswith(role + "-")]
                admit_role(role, metric, trace[min(indices)]["started_monotonic_ns"], trace[max(indices)]["ended_monotonic_ns"], legs, initial)
            for role,metric in extra_metrics.items():
                indices = [index for index in range(guard+1,last) if trace[index].get("evidence","").rsplit("/",1)[-1].startswith(role + "-") and trace[index]["returncode"] == 0]
                require(indices, "Partial metric lacks original command interval")
                metric_window = extra_windows.get(role, (trace[min(indices)]["started_monotonic_ns"],trace[max(indices)]["ended_monotonic_ns"]))
                admit_role(role,metric,*metric_window,legs,initial)
        require(row["boot_id"] == identity["boot_id"] and row["container_id"] == identity["container_id"] and row["image_id"] == identity["image_id"],
                "Foreign core supplement/sample identity")
        require(all(type(row[key]) is int and row[key] > 0 for key in
                ("ordinal", "began_monotonic_ns", "ended_monotonic_ns", "began_realtime_ns", "ended_realtime_ns")) and
                set(row["counts"]) == {"tasks", "roots"} and all(type(value) is int and value >= 0 for value in row["counts"].values()),
                "Original observation clock/count types changed")
        require(row["ended_monotonic_ns"] <= value["ended_monotonic_ns"], "Protected supplement escaped sampler lifetime")
        observations.append({**row, "attempt_began_monotonic_ns": begin, "extra_metrics": extra_metrics,
                             "interrupted": attempt["status"] == "failed"})
    files.update(raw.files)
    require(raw.used == set(range(len(trace))), "Unconsumed original read/failed attempt")
    require({str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()} == files and
            not any(path.is_symlink() for path in root.rglob("*")), "Unreferenced failure/raw file or aliased ancestry omitted")
    require(not observations[0]["interrupted"] and not observations[-1]["interrupted"], "Complete original/recovered resource edges required")
    for role in ROLES:
        selected = [leg for leg in legs if leg["role"] == role]
        if selected:
            require(producer.epoch({k:observations[0]["processes"][role][k] for k in producer.EPOCH_FIELDS}) == selected[0]["before"] and
                    producer.epoch({k:observations[-1]["processes"][role][k] for k in producer.EPOCH_FIELDS}) == selected[-1]["after"],
                    "Lost original/final role resource edges")
    return observations, legs, value


def audit_resources(observations, checkpoints, legs, clocks, *, require_24h=True):
    """ALL original attempt ordinals, including partials; global floor never resets.

    The bounded mode is explicitly non-qualified and exists for host controls;
    full 24h resource replay still is NOT a nine-action semantic campaign verdict.
    """
    policy = health.contract.HEALTH_POLICY
    require(type(require_24h) is bool, "Explicit bounded/full resource mode required")
    require(len(observations) >= 2 and [exact_int(row["ordinal"], minimum=1) for row in observations] ==
            list(range(1, len(observations) + 1)), "Resource replay omitted original attempt")
    start, end, real_start, real_end = (exact_int(value, minimum=1) for value in clocks)
    require(start < end and real_start < real_end and abs((end - start) - (real_end - real_start)) <=
            policy["maximum_sample_clock_divergence_ns"] and end - start <= health.contract.MAX_CAMPAIGN_NS,
            "Original resource dual clocks changed")
    if require_24h:
        require(end - start >= health.contract.DURATION_SECONDS * 10**9 and real_end - real_start >= health.contract.DURATION_SECONDS * 10**9 and
                observations[-1]["ended_monotonic_ns"] - observations[0]["began_monotonic_ns"] >= health.contract.DURATION_SECONDS * 10**9,
                "Original resource observations do not span genuine 24h")
    require(not observations[0]["interrupted"] and not observations[-1]["interrupted"] and
            observations[0]["began_monotonic_ns"] - start <= policy["maximum_sample_edge_ns"] and
            end - observations[-1]["ended_monotonic_ns"] <= policy["maximum_sample_edge_ns"], "Missing complete original resource edges")
    baseline = observations[0]; incarnations = {}; previous = None
    initial_epochs = {role: producer.epoch({key: baseline["processes"][role][key] for key in producer.EPOCH_FIELDS}) for role in ROLES}
    for row in observations:
        require(row["process_uid_bindings"] == baseline["process_uid_bindings"] and
                (row["boot_id"], row["container_id"], row["image_id"], row["modem_port"], row["radio_services"]) ==
                (baseline["boot_id"], baseline["container_id"], baseline["image_id"], baseline["modem_port"], baseline["radio_services"]),
                "Original UID/boot/guest/radio closure changed")
        begin, finish = row["attempt_began_monotonic_ns"], row["ended_monotonic_ns"]
        require(start <= begin <= row["began_monotonic_ns"] <= finish <= end and finish - begin <= policy["maximum_sample_collection_ns"] and
                abs((finish - row["began_monotonic_ns"]) - (row["ended_realtime_ns"] - row["began_realtime_ns"])) <= policy["maximum_sample_clock_divergence_ns"] and
                (previous is None or previous["ended_monotonic_ns"] <= begin and begin - previous["ended_monotonic_ns"] <= policy["maximum_sample_gap_ns"]),
                "Original attempt gap/collection/dual clocks changed")
        require(set(row["processes"]) == (set(ROLES)-{row["affected_role"]} if row["interrupted"] and row.get("role_metric") is None else set(ROLES)),
                "Missing protected metric or invented client metric")
        for metrics in (row["extra_metrics"], row["processes"]):
            for role, value in metrics.items():
                require(value["uid"] == baseline["process_uid_bindings"][role] and type(value["uid"]) is int, "Resource role UID changed")
                observed = producer.epoch({key: value[key] for key in producer.EPOCH_FIELDS})
                selected_legs = [leg for leg in legs if leg["role"] == role]
                if not selected_legs:
                    require(observed == initial_epochs[role], "Protected core role epoch changed: " + role)
                else:
                    require(initial_epochs[role] == selected_legs[0]["before"] and observed in
                            [selected_legs[0]["before"], *[leg["after"] for leg in selected_legs]],
                            "Unproved resource role incarnation")
                key = (role, observed["pid"], observed["start_ticks"])
                first = incarnations.setdefault(key, {})
                for field, limit in (("fd_count", policy["maximum_fd_growth_per_incarnation"]),
                                     ("rss_kib", policy["maximum_rss_growth_kib_per_incarnation"])):
                    if field in value:
                        exact_int(value[field])
                        floor = first.setdefault(field, value[field])
                        require(value[field] - floor <= limit, "Observed partial/per-incarnation resource bound exceeded")
        require(row["counts"]["tasks"] - baseline["counts"]["tasks"] <= policy["maximum_task_growth_per_run"] and
                row["counts"]["roots"] - baseline["counts"]["roots"] <= policy["maximum_root_growth_per_run"], "Task/root residual exceeded")
        previous = row
    require(len(checkpoints) >= (health.contract.MINIMUM_ROUNDS + 1 if require_24h else 2) and
            [exact_int(row["round"]) for row in checkpoints] == list(range(len(checkpoints))), "Missing original settled checkpoints")
    used = set(); global_floor = None; previous_checkpoint_end = start
    for index, checkpoint in enumerate(checkpoints):
        checkpoint_begin = exact_int(checkpoint["began_monotonic_ns"], minimum=1)
        checkpoint_end = exact_int(checkpoint["ended_monotonic_ns"], minimum=1)
        require(start <= previous_checkpoint_end <= checkpoint_begin < checkpoint_end <= end and
                checkpoint_end - checkpoint_begin <= health.contract.MAX_CHECKPOINT_NS,
                "Original settled checkpoint order/duration/lifetime changed")
        previous_checkpoint_end = checkpoint_end
        selected = [row for row in observations if checkpoint["began_monotonic_ns"] <= row["began_monotonic_ns"] and
                    row["ended_monotonic_ns"] <= checkpoint["ended_monotonic_ns"]]
        require(len(selected) >= 2 and all(not row["interrupted"] for row in selected) and
                selected[-1]["ended_monotonic_ns"] - selected[0]["began_monotonic_ns"] >= policy["minimum_stable_span_ns"] and
                not used.intersection(row["ordinal"] for row in selected), "Settled checkpoint reused/missing complete genuine samples")
        used.update(row["ordinal"] for row in selected)
        if index == len(checkpoints) - 1:
            require(checkpoint_begin >= legs[-1]["ended_monotonic_ns"] and selected[-1]["ordinal"] == observations[-1]["ordinal"],
                    "Final settled checkpoint omitted terminal recovered observations/cumulative residual")
        epochs = {role: {key: selected[0]["processes"][role][key] for key in producer.EPOCH_FIELDS} for role in ROLES}
        require(type(checkpoint["epochs"]) is dict and set(checkpoint["epochs"]) == set(ROLES), "Exact checkpoint epoch schema required")
        for checkpoint_epoch in checkpoint["epochs"].values(): producer.epoch(checkpoint_epoch)
        require(checkpoint["epochs"] == epochs and all({role: {key: row["processes"][role][key] for key in producer.EPOCH_FIELDS}
                for role in ROLES} == epochs for row in selected), "Settled checkpoint incarnation changed")
        floor = {role: {field: min(row["processes"][role][field] for row in selected) for field in ("fd_count", "rss_kib")} for role in ROLES}
        if global_floor is None:
            require(type(checkpoint["resource_baseline"]) is dict and set(checkpoint["resource_baseline"]) == set(ROLES) and
                    all(type(v) is dict and set(v) == {"fd_count","rss_kib"} and all(type(n) is int and n >= 0 for n in v.values())
                        for v in checkpoint["resource_baseline"].values()), "Exact typed original cumulative baseline required")
            require(checkpoint["resource_baseline"] == floor, "Original settled baseline does not rederive from raw")
            require(selected[0]["ordinal"] == 1 and checkpoint["ended_monotonic_ns"] <= legs[0]["started_monotonic_ns"],
                    "Cumulative baseline must precede original mutation; late/reset baseline forbidden")
            global_floor = copy.deepcopy(floor)
        for role in ROLES:
            require(floor[role]["fd_count"] - global_floor[role]["fd_count"] <= policy["maximum_cumulative_fd_residual"] and
                    floor[role]["rss_kib"] - global_floor[role]["rss_kib"] <= policy["maximum_cumulative_rss_residual_kib"],
                    "Cumulative residual exceeded across replacements; baseline reset forbidden")
    return dict(status="raw_role_death_health_resource_core_not_complete_campaign", attempts=len(observations),
                interrupted_attempts=sum(row["interrupted"] for row in observations), runtime_qualified=False,
                qualification_claimed=False, whole_campaign_complete=False, genuine_24h_resource_span_checked=require_24h)




def audit_role_death_health(campaign_root, sampler_relative, *, identity, process_uids, actions,
                           action_contracts, checkpoints, require_24h=True, current_client_inputs=None):
    observations, legs, value = audit_stream(campaign_root, sampler_relative, identity=identity,
        process_uids=process_uids, actions=actions, action_contracts=action_contracts,
        current_client_inputs=current_client_inputs)
    clocks = tuple(value[k] for k in ("began_monotonic_ns", "ended_monotonic_ns", "began_realtime_ns", "ended_realtime_ns"))
    return audit_resources(observations, checkpoints, legs, clocks, require_24h=require_24h)




