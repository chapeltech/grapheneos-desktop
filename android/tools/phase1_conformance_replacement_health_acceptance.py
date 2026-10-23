"""Independent APK-replacement health replay, not full nine-action admission.

Every original attempt and raw command is consumed. Interruptions retain their
failed status; a narrowly authenticated action permits only missing CLIENT
metrics, never missing core observations or a new cumulative resource baseline.
"""
from pathlib import Path
import copy
import json

import phase1_conformance_replacement_health as producer
import phase1_conformance_soak_health as health
import phase1_conformance_soak_health_acceptance as core
import phase1_conformance_soak_sampler as sampling
import phase1_conformance_soak_apk_update_acceptance as action_audit
import conformance_update_canary_epoch as canary
from phase1_conformance_common import file_ref, load

require = health.require
ROLES = tuple(health.contract.PROCESS_NAMES)
PROTECTED = tuple(role for role in ROLES if role != "client")


def literal(root, relative):
    root = Path(root).absolute()
    producer.relative(relative)
    path = root / relative
    require(root.resolve(strict=True) == root and path.resolve(strict=True) == path and
            path.is_file() and not path.is_symlink(), "Original evidence ancestry changed/aliased")
    return path


def exact_int(value, *, minimum=0):
    require(type(value) is int and value >= minimum, "Original exact integer required")
    return value


def authenticate_actions(root, references, identity, uids):
    """Full actor source/APK/raw proof FIRST, not a caller supplied epoch list."""
    legs, seen = [], set()
    for reference in references:
        require(type(reference) is dict and set(reference) == {"path", "sha256", "bytes"}, "Sealed original action reference required")
        path = literal(root, reference["path"])
        require(file_ref(path) == {key: reference[key] for key in ("sha256", "bytes")} and path not in seen,
                "Action bytes changed/replayed")
        seen.add(path)
        report = load(path)
        verdict = action_audit.audit_action(root, report)
        require(verdict["status"] == action_audit.STATUS and report.get("health_permit_hooked") is True and
                report["identity"] == identity, "Health transition lacks independently reopened exact owned action")
        trace = load(literal(root, report["trace"]))
        for index, replacement in enumerate(report["replacements"]):
            before, after = (producer.epoch(worker["epoch"]) for worker in report["workers"][index:index + 2])
            for key in ("started_monotonic_ns", "ended_monotonic_ns"):
                exact_int(replacement[key], minimum=1)
                exact_int(report["stages"][index + 1][key], minimum=1)
            exact_int(report["workers"][index]["ended_monotonic_ns"], minimum=1)
            exact_int(report["workers"][index + 1]["started_monotonic_ns"], minimum=1)
            marker = literal(root, replacement["marker"]).read_text()
            descriptor = replacement["canary"]
            command_index = exact_int(descriptor["command_index"])
            require(command_index < len(trace), "Missing original canary command")
            actual = canary.command_receipt(marker, uids["client"], replacement["marker"], report["trace"], trace[command_index])
            require(actual == descriptor and replacement["canary_epoch"] == {**actual["epoch"], "uid": uids["client"]},
                    "Intermediate canary epoch/clock descriptor changed")
            installs = [row for row in trace if row.get("evidence") == replacement["install"]]
            require(len(installs) == 1, "Missing unique original APK mutation command")
            install = installs[0]
            recovered = load(literal(root, replacement["recovered_stage_relative"]))
            require(recovered == report["stages"][index + 1], "Recovered raw stage changed")
            package_raw = literal(root, recovered["package"]["uids"][action_audit.APP]).read_text()
            require(action_audit.scene_audit.raw_audit.package_manager_uid_row(package_raw, action_audit.APP) ==
                    f"package:{action_audit.APP} uid:{uids['client']}", "Action role UID differs from independent health admission")
            legs.append(dict(action_nonce=report["action_nonce"], leg=index, role="client", role_uid=uids["client"],
                permit_id=replacement["permit_id"], before=before, after=after, canary=actual,
                started_monotonic_ns=replacement["started_monotonic_ns"],
                ended_monotonic_ns=replacement["ended_monotonic_ns"],
                deadline_monotonic_ns=replacement["started_monotonic_ns"] + producer.MAX_REPLACEMENT_NS,
                absent_begin_monotonic_ns=install["started_monotonic_ns"],
                absent_end_monotonic_ns=recovered["ended_monotonic_ns"],
                old_end_monotonic_ns=report["workers"][index]["ended_monotonic_ns"],
                new_start_monotonic_ns=report["workers"][index + 1]["started_monotonic_ns"],
                action_relative=reference["path"], recovered_stage_relative=replacement["recovered_stage_relative"]))
    require(legs and len({leg["permit_id"] for leg in legs}) == len(legs), "No unique original replacement action permits")
    legs.sort(key=lambda row: row["started_monotonic_ns"])
    for old, new in zip(legs, legs[1:]):
        require(old["ended_monotonic_ns"] <= new["started_monotonic_ns"] and old["after"] == new["before"],
                "Original action replacement chain overlaps/differs")
    return legs


def bind_intents(root, records, legs):
    require(type(records) is list and len(records) == len(legs), "Missing/invented provisional replacement intent")
    by_id = {row["permit_id"]: row for row in legs}
    files = set()
    for record in records:
        handle = record["permit_id"]
        require(handle in by_id, "Provisional permit lacks actual source-matched action")
        leg = by_id.pop(handle)
        require(set(record) == {"schema", "kind", "permit_id", "action_nonce", "leg", "role", "role_uid", "before",
                "started_monotonic_ns", "observed_begin_monotonic_ns", "deadline_monotonic_ns", "action_relative",
                "status", "after", "ended_monotonic_ns", "recovered_stage_relative"} and
                record["schema"] == 1 and type(record["schema"]) is int and
                record["kind"] == "provisional_client_replacement_intent" and
                record["status"] == "pending_original_action_raw_audit", "Provisional intent vocabulary changed")
        producer.epoch(record["before"]); producer.epoch(record["after"])
        for key in ("started_monotonic_ns", "deadline_monotonic_ns", "ended_monotonic_ns"):
            exact_int(record[key], minimum=1)
        for key in ("permit_id", "action_nonce", "leg", "role", "role_uid", "before", "after", "started_monotonic_ns",
                    "deadline_monotonic_ns", "ended_monotonic_ns", "action_relative", "recovered_stage_relative"):
            require(record[key] == leg[key] and (key not in ("leg", "role_uid") or type(record[key]) is int),
                    "Provisional permit differs from exact original action: " + key)
        require(record["started_monotonic_ns"] <= exact_int(record["observed_begin_monotonic_ns"], minimum=1) <=
                leg["absent_begin_monotonic_ns"], "Permit was not armed BEFORE original mutation")
        begin = {key: value for key, value in record.items() if key not in {"after", "ended_monotonic_ns", "recovered_stage_relative"}}
        names = ("permit-" + handle + "-begin.json", "permit-" + handle + "-end.json")
        # The original publisher emits exact canonical JSON. Equality after
        # decoding would let separately resealed float/bool values compare equal
        # to strict integer authority in sampler.records. Check BOTH original
        # durable byte bodies against the already strict-typed normalized dicts.
        require(literal(root, names[0]).read_bytes() == producer.common.canonical(begin) and
                literal(root, names[1]).read_bytes() == producer.common.canonical(record),
                "Original durable arm/close records changed")
        files.update(names)
    require(not by_id, "Original action permit omitted")
    return files


def admit_client(value, began, ended, legs):
    observed = producer.epoch({key: value[key] for key in producer.EPOCH_FIELDS})
    require(type(began) is int and type(ended) is int and began <= ended, "Client observation clock changed")
    # Intermediate self-target instrumentation is an EXACT compiled incarnation,
    # admitted only inside its actual command, not over the replacement interval.
    for leg in legs:
        if observed == leg["canary"]["epoch"]:
            require(leg["canary"]["started_monotonic_ns"] <= began <= ended <= leg["canary"]["ended_monotonic_ns"],
                    "Canary incarnation observed outside its exact command")
            return
    if observed == legs[0]["before"] and ended <= legs[0]["old_end_monotonic_ns"]:
        return
    for index, leg in enumerate(legs):
        limit = legs[index + 1]["old_end_monotonic_ns"] if index + 1 < len(legs) else None
        if observed == leg["after"] and leg["new_start_monotonic_ns"] <= began and (limit is None or ended <= limit):
            return
    raise ValueError("Unproved client incarnation/interval; UID-wide replacement wildcard is forbidden")


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
                ["pidof", health.contract.PROCESS_NAMES["client"]]))
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
    require(row["kind"] == "interrupted_client_with_actual_four_role_health_not_qualified" and
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
    result = producer.protected_supplement(Replay(), row["ordinal"], uids, intent,
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
            if "client-stat-before" in captured:
                selected_pid = health.qualified_pid(captured["client-pid-before"], captured["client-ps-before"],
                    health.contract.PROCESS_NAMES["client"], uids["client"])
                selected_epoch = health.proc_epoch(captured["client-stat-before"], selected_pid)
            category = producer.absent_read([], row, leg, raw_reader.identity["container_id"], selected_epoch=selected_epoch)
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
    if "client-stat-before" in captured:
        pid = health.qualified_pid(captured["client-pid-before"], captured["client-ps-before"],
                                  health.contract.PROCESS_NAMES["client"], uids["client"])
        partial = {**health.proc_epoch(captured["client-stat-before"], pid), "uid": uids["client"]}
        if "client-status" in captured:
            # Parse only genuinely present status fields. No missing FD read or
            # after-stat/pid witness is manufactured even as an intermediate.
            status = captured["client-status"]
            uid_fields = health.status_field(status, "Uid",
                r"Uid:[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]*", "Partial client status UID changed")
            pid_fields = health.status_field(status, "Pid", r"Pid:[ \t]+([1-9][0-9]*)", "Partial client status PID changed")
            rss_fields = health.status_field(status, "VmRSS", r"VmRSS:[ \t]+([1-9][0-9]*) kB", "Partial client VmRSS changed")
            require(uid_fields == (str(uids["client"]),) * 4 and pid_fields == (str(pid),), "Partial client raw UID/PID differs")
            partial["rss_kib"] = int(rss_fields[0])
        if "client-fd" in captured:
            import re
            tokens = captured["client-fd"].splitlines()
            require(tokens and all(re.fullmatch(r"[0-9]+", token) for token in tokens) and len(set(tokens)) == len(tokens),
                    "Malformed original partial FD inventory")
            partial["fd_count"] = len(tokens)
        metrics["client"] = partial
    return metrics


def audit_stream(campaign_root, sampler_relative, *, identity, process_uids, actions):
    """Bounded source-ready consumer; never claims 24h or complete campaign."""
    campaign_root = Path(campaign_root).absolute()
    producer.relative(sampler_relative)
    root = campaign_root / sampler_relative
    require(root.resolve(strict=True) == root and root.is_dir() and not root.is_symlink(), "Canonical original sampler required")
    uids = health.validate_process_uids(process_uids)
    value = load(literal(root, "sampler.json"))
    require(value["kind"] == "replacement_aware_continuous_health_v1" and
            value["status"] == "retained_replacement_health_not_qualified" and
            value["runtime_qualified"] is False and value["qualification_claimed"] is False and
            value["observer"] == health.OBSERVER and value["identity"] == identity and value["process_uid_bindings"] == uids,
            "Replacement sampler identity/status/admission changed")
    require(value.get("host_sources") == producer.source_bindings(), "Replacement health runtime source closure changed")
    require(1 <= exact_int(value["interval_seconds"], minimum=1) <= 300 and
            all(type(value[key]) is int and value[key] > 0 for key in
                ("began_monotonic_ns", "ended_monotonic_ns", "began_realtime_ns", "ended_realtime_ns")),
            "Original sampler interval/dual clock types changed")
    legs = authenticate_actions(campaign_root, actions, identity, uids)
    require(all(value["began_monotonic_ns"] <= leg["started_monotonic_ns"] < leg["ended_monotonic_ns"] <=
                value["ended_monotonic_ns"] for leg in legs), "Continuous sampler did not cover original action lifetime")
    files = bind_intents(root, value["replacement_intents"], legs) | {"sampler.json", "commands.json"}
    trace = load(literal(root, "commands.json")); raw = RawReads(root, trace, identity)
    require(trace and value["began_monotonic_ns"] <= trace[0]["started_monotonic_ns"] and
            trace[-1]["ended_monotonic_ns"] <= value["ended_monotonic_ns"], "Raw read journal escaped original sampler lifetime")
    attempts, observations = value["attempts"], []
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
        extra_metrics = {}
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
            client_indices = [ref["trace_index"] for name, ref in row["files"].items() if name.startswith("client-")]
            admit_client(row["processes"]["client"], trace[min(client_indices)]["started_monotonic_ns"],
                         trace[max(client_indices)]["ended_monotonic_ns"], legs)
        else:
            require(attempt["status"] == "failed" and isinstance(attempt["error"], str) and attempt["error"] and attempt["sample"] is None,
                    "Interrupted attempt was relabelled successful")
            pending_name = f"attempt-{ordinal:06d}-pending-replacement.json"
            pending = load(literal(root, pending_name)); files.add(pending_name)
            require(pending["status"] == "pending_original_action_and_raw_health_admission" and pending["runtime_qualified"] is False and
                    pending["original_attempt"] == attempt, "Original failure dropped/rewritten")
            matches = [leg for leg in legs if leg["permit_id"] == pending["permit_id"]]
            require(len(matches) == 1, "Interrupted original attempt lacks independently authenticated action")
            leg = matches[0]; last = exact_int(pending["failed_trace_index"])
            extra_metrics = replay_interrupted(raw, attempt, guard + 1, last, leg, uids)
            observed_epoch = None if "client" not in extra_metrics else {key: extra_metrics["client"][key] for key in producer.EPOCH_FIELDS}
            require(pending.get("failed_client_epoch") == observed_epoch, "Provisional interrupted client epoch differs from raw UID/stat prefix")
            if "client" in extra_metrics:
                client_indices = [index for index in range(guard + 1, last) if trace[index]["returncode"] == 0 and
                                  trace[index]["evidence"].rsplit("/", 1)[-1].startswith("client-")]
                require(client_indices, "Partial client metric lacks original command identity")
                admit_client(extra_metrics["client"], trace[client_indices[0]]["started_monotonic_ns"],
                             trace[client_indices[-1]]["ended_monotonic_ns"], legs)
            supplement_name = f"attempt-{ordinal:06d}-replacement-supplement.json"
            require(pending["supplement"] == supplement_name and file_ref(literal(root, supplement_name)) == pending["supplement_ref"],
                    "Original protected supplement seal changed")
            files.add(supplement_name); row = load(literal(root, supplement_name))
            require(min(ref["trace_index"] for ref in row["files"].values()) == last + 1 and row["ordinal"] == ordinal,
                    "Interrupted attempt/supplement join changed")
            replay_supplement(raw, row, leg, uids)
            require(finish <= row["began_monotonic_ns"] <= row["ended_monotonic_ns"], "Supplement precedes its original failed attempt")
            if row["client_metric"] is None:
                require("client" not in row["processes"] and leg["absent_begin_monotonic_ns"] <= row["began_monotonic_ns"],
                        "Missing client metric not inside genuine bounded action")
                require(row["ended_monotonic_ns"] <= leg["absent_end_monotonic_ns"], "Missing client supplement outside genuine recovery interval")
            else:
                indices = [ref["trace_index"] for name, ref in row["files"].items() if name.startswith("client-")]
                admit_client(row["client_metric"], trace[min(indices)]["started_monotonic_ns"], trace[max(indices)]["ended_monotonic_ns"], legs)
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
    require(not observations[0]["interrupted"] and not observations[-1]["interrupted"] and
            {key: observations[0]["processes"]["client"][key] for key in producer.EPOCH_FIELDS} == legs[0]["before"] and
            {key: observations[-1]["processes"]["client"][key] for key in producer.EPOCH_FIELDS} == legs[-1]["after"],
            "Continuous stream lost original/recovered client resource edges")
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
        require(set(row["processes"]) == (set(PROTECTED) if row["interrupted"] and row.get("client_metric") is None else set(ROLES)),
                "Missing protected metric or invented client metric")
        for metrics in (row["extra_metrics"], row["processes"]):
            for role, value in metrics.items():
                require(value["uid"] == baseline["process_uid_bindings"][role] and type(value["uid"]) is int, "Resource role UID changed")
                observed = producer.epoch({key: value[key] for key in producer.EPOCH_FIELDS})
                if role != "client": require(observed == initial_epochs[role], "APK update changed protected core epoch: " + role)
                else:
                    # Exact command-time incarnation admission has already run
                    # in audit_stream. Here reject arbitrary summary epochs too.
                    require(observed in [legs[0]["before"], *[leg["after"] for leg in legs], *[leg["canary"]["epoch"] for leg in legs]],
                            "Unproved resource client incarnation")
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
        require(checkpoint["epochs"] == epochs and all({role: {key: row["processes"][role][key] for key in producer.EPOCH_FIELDS}
                for role in ROLES} == epochs for row in selected), "Settled checkpoint incarnation changed")
        floor = {role: {field: min(row["processes"][role][field] for row in selected) for field in ("fd_count", "rss_kib")} for role in ROLES}
        if global_floor is None:
            require(checkpoint["resource_baseline"] == floor, "Original settled baseline does not rederive from raw")
            require(selected[0]["ordinal"] == 1 and checkpoint["ended_monotonic_ns"] <= legs[0]["started_monotonic_ns"],
                    "Cumulative baseline must precede original mutation; late/reset baseline forbidden")
            global_floor = copy.deepcopy(floor)
        for role in ROLES:
            require(floor[role]["fd_count"] - global_floor[role]["fd_count"] <= policy["maximum_cumulative_fd_residual"] and
                    floor[role]["rss_kib"] - global_floor[role]["rss_kib"] <= policy["maximum_cumulative_rss_residual_kib"],
                    "Cumulative residual exceeded across replacements; baseline reset forbidden")
    return dict(status="raw_apk_replacement_health_resource_core_not_complete_campaign", attempts=len(observations),
                interrupted_attempts=sum(row["interrupted"] for row in observations), runtime_qualified=False,
                qualification_claimed=False, whole_campaign_complete=False, genuine_24h_resource_span_checked=require_24h)


def audit_replacement_health(campaign_root, sampler_relative, *, identity, process_uids, actions, checkpoints, require_24h=True):
    """Reviewed entry: never accepts caller-provided metric/transition summaries.

    Checkpoints are original sealed references, not caller-supplied baselines;
    their resource/epoch values are rederived from the fully reopened stream.
    Nine-action semantic admission remains the responsibility of the full
    campaign, so this deliberately never returns runtime qualification.
    """
    rows, legs, value = audit_stream(campaign_root, sampler_relative, identity=identity,
        process_uids=process_uids, actions=actions)
    parsed = []
    seen = set()
    for ref in checkpoints:
        require(type(ref) is dict and set(ref) == {"path", "sha256", "bytes"}, "Original settled checkpoint reference required")
        path = literal(Path(campaign_root).absolute(), ref["path"])
        require(path not in seen and file_ref(path) == {key: ref[key] for key in ("sha256", "bytes")}, "Checkpoint changed/replayed")
        seen.add(path); parsed.append(load(path))
    clocks = tuple(value[key] for key in ("began_monotonic_ns", "ended_monotonic_ns", "began_realtime_ns", "ended_realtime_ns"))
    verdict = audit_resources(rows, parsed, legs, clocks, require_24h=require_24h)
    return {**verdict, "auditor": {"path": str(Path(__file__).resolve()), **file_ref(Path(__file__))},
            "sampler": {"path": sampler_relative + "/sampler.json", **file_ref(Path(campaign_root) / sampler_relative / "sampler.json")},
            "source_bindings": value["host_sources"], "original_actions": copy.deepcopy(actions),
            "original_checkpoints": copy.deepcopy(checkpoints)}
