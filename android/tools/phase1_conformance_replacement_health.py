"""Explicit private APK-replacement health seam; defaults remain untouched.

Intents permit RETENTION/CONTINUATION, never qualification. Missing metrics are
null and failed commands remain original failures. Independent action+health
replay must approve every pending interval before any campaign can be admitted.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import secrets
import threading
import time

import phase1_conformance_soak_health as health
import phase1_conformance_soak_sampler as sampling
import phase1_conformance_soak_health_acceptance as core_audit
from phase1_conformance_common import file_ref, load
import phase1_conformance_common as common

require = health.require
lane = sampling.lane
MAX_REPLACEMENT_NS = 180_000_000_000  # Original reviewed actor bound, never caller-expanded.
NONCE = re.compile(r"[0-9a-f]{32}")
EPOCH_FIELDS = {"pid", "start_ticks"}


def source_bindings():
    modules = {"replacement_sampler": __file__, "strict_sampler": sampling.__file__,
               "health_observer": health.__file__, "health_auditor": core_audit.__file__,
               "health_contract": health.contract.__file__, "common": common.__file__,
               "phone_raw_parser": health.phone.__file__, "owner_raw_auditor": sampling.owned_audit.__file__,
               "clean_boot": sampling.lane.__file__, "guest_common": sampling.lane.fresh.__file__,
               "raw_transport": sampling.lane.mechanics.__file__}
    return {role: {"path": str(Path(path).resolve(strict=True)), **file_ref(Path(path))} for role, path in modules.items()}


def epoch(value):
    require(type(value) is dict and set(value) == EPOCH_FIELDS and
            all(type(v) is int and v > 0 for v in value.values()), "Exact positive PID/start epoch required")
    return dict(value)


def relative(value):
    require(isinstance(value, str) and value and not Path(value).is_absolute() and
            all(part not in ("", ".", "..") for part in value.split("/")), "Canonical original evidence path required")
    return value


def raw_ref(path, *, allow_empty=False):
    """Zero bytes are evidence only for an explicit actual exit1 pidof."""
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.resolve(strict=True) == path.absolute(),
            "Original raw path changed/aliased")
    payload = path.read_bytes()
    require(payload or allow_empty, "Empty successful raw evidence is forbidden")
    return {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}


def client_selection(pidof_raw, table_raw, uid):
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
    selected = [pid for owner, pid, name in rows if owner == uid and name == health.contract.PROCESS_NAMES["client"]]
    require(len(selected) <= 1 and (not selected or str(selected[0]) in tokens), "Ambiguous/missing client PID/UID join")
    # pidof may include other users, but every token must have this exact name
    # in the independently captured numeric table.
    require(set(map(int, tokens)) == {pid for _owner, pid, name in rows if name == health.contract.PROCESS_NAMES["client"]},
            "Client pidof/ps inventory differs")
    return selected[0] if selected else None


class ReplacementIntents:
    def __init__(self, output, uid_bindings, *, clock=time.monotonic_ns):
        self.output = Path(output)
        self.uids = health.validate_process_uids(uid_bindings)
        self.clock = clock
        self.lock = threading.RLock()
        self.records = []
        self.active = None
        self.latest_complete_client = None
        self.latest_complete_epochs = None
        self.publication_revision = 0

    def observe_complete(self, sample, *, publication_revision=None):
        with self.lock:
            if publication_revision is None: publication_revision = self.publication_revision
            require(type(publication_revision) is int and 0 <= publication_revision <= self.publication_revision,
                    "Original sample publication revision changed")
            require(sample.get("process_uid_bindings") == self.uids, "Normal sample lost independently admitted UID closure")
            client = sample["processes"]["client"]
            require(client.get("uid") == self.uids["client"], "Normal client UID changed")
            epochs = {role: {key: value[key] for key in EPOCH_FIELDS} for role, value in sample["processes"].items()}
            if self.latest_complete_epochs is not None:
                require(all(epochs[role] == self.latest_complete_epochs[role] for role in ("system_server", "phone")),
                        "Protected phone/system_server epoch replacement is never allowed")
                if self.active is not None:
                    require(all(epochs[role] == self.latest_complete_epochs[role] for role in epochs if role != "client"),
                            "APK update may replace only its exact client role")
            self.latest_complete_epochs = epochs
            if self.active is None and publication_revision == self.publication_revision:
                self.latest_complete_client = epochs["client"]

    def begin_client_replacement(self, action_nonce, leg, *, role_uid, before, started_monotonic_ns, action_relative):
        with self.lock:
            require(isinstance(action_nonce, str) and NONCE.fullmatch(action_nonce) is not None and
                    type(leg) is int and leg in (0, 1), "Exact action nonce/leg required")
            require(self.active is None and role_uid == self.uids["client"] and type(role_uid) is int,
                    "Only one exact admitted client replacement may be provisional")
            before = epoch(before)
            require(self.latest_complete_client == before, "Action old epoch differs from last complete raw client sample")
            previous = [r for r in self.records if r["action_nonce"] == action_nonce]
            require(len(previous) == leg and (not previous or previous[-1].get("after") == before), "Replacement leg replay/chain changed")
            now = self.clock()
            require(type(started_monotonic_ns) is int and 0 < started_monotonic_ns <= now <= started_monotonic_ns + MAX_REPLACEMENT_NS,
                    "Original fixed replacement clock bound required")
            handle = secrets.token_hex(16)
            record = dict(schema=1, kind="provisional_client_replacement_intent", permit_id=handle,
                action_nonce=action_nonce, leg=leg, role="client", role_uid=role_uid, before=before,
                started_monotonic_ns=started_monotonic_ns, observed_begin_monotonic_ns=now,
                deadline_monotonic_ns=started_monotonic_ns + MAX_REPLACEMENT_NS,
                action_relative=relative(action_relative), status="pending_original_action_raw_audit")
            sampling.lane.fresh.write_new_durable(self.output / ("permit-" + handle + "-begin.json"), record)
            self.records.append(record); self.active = handle
            self.publication_revision += 1
            return handle

    def end_client_replacement(self, permit_id, *, after, ended_monotonic_ns, action_relative, recovered_stage_relative):
        with self.lock:
            require(self.active == permit_id and isinstance(permit_id, str), "Foreign/replayed replacement permit")
            record = self.records[-1]
            require(record["permit_id"] == permit_id and action_relative == record["action_relative"], "Replacement action changed")
            after = epoch(after)
            require(after != record["before"] and type(ended_monotonic_ns) is int and
                    record["observed_begin_monotonic_ns"] <= ended_monotonic_ns <= record["deadline_monotonic_ns"] and
                    ended_monotonic_ns <= self.clock(), "Original replacement recovery bound/epoch changed")
            completed = {**record, "after": after, "ended_monotonic_ns": ended_monotonic_ns,
                         "recovered_stage_relative": relative(recovered_stage_relative)}
            sampling.lane.fresh.write_new_durable(self.output / ("permit-" + permit_id + "-end.json"), completed)
            self.records[-1] = completed; self.active = None
            self.publication_revision += 1
            # Provisional endpoint only: final health auditor must independently
            # rederive it from genuine raw actor stage+install/worker proof.
            self.latest_complete_client = after

    def matching(self, began, ended):
        with self.lock:
            matches = [r for r in self.records if r["started_monotonic_ns"] <= began <= ended <=
                       r.get("ended_monotonic_ns", r["deadline_monotonic_ns"])]
            require(len(matches) == 1, "Interrupted client read lacks one original bounded replacement intent")
            return copy.deepcopy(matches[0])


def absent_read(trace, row, intent, container, *, selected_epoch=None):
    """Only actual exit1+empty pidof or exact ENOENT from this client PID.
    Timeout/permission denial/transport/parser failures are never intentional.
    """
    require(row.get("kind") == "command" and type(row.get("returncode")) is int and row["returncode"] == 1 and
            type(row.get("started_monotonic_ns")) is int and type(row.get("ended_monotonic_ns")) is int,
            "Not an original client-absence read")
    command = row.get("argv")
    prefix = ["docker", "exec", container, "adb", "-s", "emulator-5580", "shell"]
    require(isinstance(command, list) and command[:7] == prefix and isinstance(row.get("evidence"), str) and
            re.fullmatch(r"soak-health/sample-[0-9]{6}/client-(?:pid-before|pid-after|stat-before|stat-after|status|fd)\.txt", row["evidence"]),
            "Failure was not an exact original client health command")
    suffix = command[7:]
    if suffix == ["pidof", health.contract.PROCESS_NAMES["client"]]:
        return "pidof_absent"
    pid = (intent["before"] if selected_epoch is None else epoch(selected_epoch))["pid"]
    paths = {f"/proc/{pid}/stat", f"/proc/{pid}/status", f"/proc/{pid}/fd"}
    require(len(suffix) in (4, 5) and suffix[:2] == ["su", "0"] and suffix[-1] in paths and
            (suffix[2:3] == ["cat"] and suffix[-1] != f"/proc/{pid}/fd" or
             suffix[2:4] == ["ls", "-1"] and suffix[-1] == f"/proc/{pid}/fd"),
            "Failed proc read belongs to another PID/role")
    return "proc_enoent"


def observed_failure_epoch(reader, ordinal, uid):
    """Provisional exact raw observation, NOT authority to accept a new epoch.

    A retiring canary/new process can interrupt a proc read too. Its earlier
    numeric UID+PID+stat proof is retained and later MUST match the independently
    reopened actor incarnation AND precise command interval. Without stat-before
    there is no defensible unknown PID/start epoch, so only old-PID absence works.
    """
    prefix = f"soak-health/sample-{ordinal:06d}/"
    values = {}
    for name in ("client-pid-before", "client-ps-before", "client-stat-before"):
        rows = [row for row in reader.trace if row.get("evidence") == prefix + name + ".txt" and row.get("returncode") == 0]
        if not rows: return None
        require(len(rows) == 1, "Observed interrupted client prefix was duplicated")
        row = rows[0]; path = Path(reader.output) / row["evidence"]
        require(raw_ref(path)["sha256"] == row["output_sha256"], "Observed interrupted client prefix changed")
        values[name] = path.read_text()
    pid = health.qualified_pid(values["client-pid-before"], values["client-ps-before"],
        health.contract.PROCESS_NAMES["client"], uid)
    expected = ["docker", "exec", reader.container, "adb", "-s", "emulator-5580", "shell", "su", "0", "cat", f"/proc/{pid}/stat"]
    require(rows[0]["argv"] == expected, "Observed interrupted stat belongs to another process")
    return health.proc_epoch(values["client-stat-before"], pid)


def read_actual(reader, relative_path, command, *, allow_absence=False):
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
            allow_empty=allow_absence and row["returncode"] == 1 and command == ["pidof", health.contract.PROCESS_NAMES["client"]]))
    return raw, dict(path=relative_path, trace_index=index, **reference), row["returncode"]


def protected_supplement(reader, ordinal, uid_bindings, intent, *, monotonic_ns=time.monotonic_ns, realtime_ns=time.time_ns):
    """All four protected roles + actual boot/radio/tasks/events; NO client RSS/FD
    invented. Additional pidof+ps witness proves only current UID membership.
    """
    uids = health.validate_process_uids(uid_bindings)
    base = f"replacement-guards/attempt-{ordinal:06d}"
    files, raw = {}, {}
    began, real_began = monotonic_ns(), realtime_ns()
    def read(name, *command, allow_absence=False):
        value, ref, code = read_actual(reader, base + "/" + name + ".txt", list(command), allow_absence=allow_absence)
        files[name] = ref; raw[name] = value
        require(code == 0 or allow_absence and code == 1 and value.strip() == "", "Malformed absence/failed protected read")
        return value
    boot = health.phone.boot_identity(read("boot-before", "cat", "/proc/sys/kernel/random/boot_id"))
    require(read("boot-completed", "getprop", "sys.boot_completed").strip() == "1", "Boot incomplete")
    processes = {}
    for role, name in health.contract.PROCESS_NAMES.items():
        if role == "client": continue
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
    client_raw = {"pid_before": read("client-pid-before", "pidof", health.contract.PROCESS_NAMES["client"], allow_absence=True),
                  "ps_before": read("client-ps-before", *health.PROCESS_TABLE_COMMAND)}
    client_pid = client_selection(client_raw["pid_before"], client_raw["ps_before"], uids["client"])
    if client_pid is not None:
        for field, command in (("stat_before", ["su", "0", "cat", f"/proc/{client_pid}/stat"]),
                               ("status", ["su", "0", "cat", f"/proc/{client_pid}/status"]),
                               ("fd", ["su", "0", "ls", "-1", f"/proc/{client_pid}/fd"]),
                               ("stat_after", ["su", "0", "cat", f"/proc/{client_pid}/stat"])):
            client_raw[field] = read("client-" + field.replace("_", "-"), *command)
    client_raw["pid_after"] = read("client-pid-after", "pidof", health.contract.PROCESS_NAMES["client"], allow_absence=True)
    client_raw["ps_after"] = read("client-ps-after", *health.PROCESS_TABLE_COMMAND)
    require(client_selection(client_raw["pid_after"], client_raw["ps_after"], uids["client"]) == client_pid,
            "Client changed during protected supplement")
    client_metric = None if client_pid is None else health.process_metric(client_raw, client_pid,
        name=health.contract.PROCESS_NAMES["client"], expected_uid=uids["client"])
    if client_metric is not None: processes["client"] = client_metric
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
    return dict(schema=1, kind="interrupted_client_with_actual_four_role_health_not_qualified", ordinal=ordinal,
        permit_id=intent["permit_id"], boot_id=boot, container_id=reader.container, image_id=reader.image,
        process_uid_bindings=uids, processes=processes, client_metric=client_metric,
        counts=counts, modem_port=port, radio_services=radio, files=files, began_monotonic_ns=began, ended_monotonic_ns=ended,
        began_realtime_ns=real_began, ended_realtime_ns=real_ended, runtime_qualified=False)


class ReplacementAwareSampler(sampling.ContinuousSampler):
    """Explicit opt-in new diagnostic type, never changes default39/49 class."""
    def __init__(self, *args, process_uids, **kwargs):
        super().__init__(*args, process_uids=process_uids, **kwargs)
        self.intents = ReplacementIntents(self.output, self.process_uids)
        self.started_realtime_ns = None
        self.admission_ready = threading.Event()

    def start(self):
        require(self.thread is None, "Never replace continuous health worker")
        self.started_realtime_ns = time.time_ns()
        self.started_ns = time.monotonic_ns()
        self.thread = threading.Thread(target=self._loop, name="policy-free-health-observer", daemon=False)
        self.thread.start()
        # Inherited first_event marks only raw observation completion, BEFORE
        # this subclass's exact baseline/provisional ownership admission.
        require(self.admission_ready.wait(540), "First admitted health observation did not finish within bounded collection")
        self.check()

    def _loop(self):
        try:
            while not self.stop_event.is_set():
                self._sample()
                if self.error is not None or self.stop_event.wait(self.interval_seconds): return
        except BaseException as error:
            self.error = error
            self.admission_ready.set(); self.first_event.set()

    def begin_client_replacement(self, *args, **kwargs): return self.intents.begin_client_replacement(*args, **kwargs)
    def end_client_replacement(self, *args, **kwargs): return self.intents.end_client_replacement(*args, **kwargs)

    def _sample(self):
        try:
            self._sample_admitted()
        except BaseException as error:
            self.error = error
            raise
        finally:
            self.admission_ready.set()

    def _sample_admitted(self):
        with self.intents.lock:
            publication_revision = self.intents.publication_revision
        super()._sample()
        attempt = self.attempts[-1]
        if self.error is None:
            self.intents.observe_complete(load(self.output / attempt["sample"]), publication_revision=publication_revision)
            return
        original = self.error
        try:
            failed = self.reader.trace[-1]
            intent = self.intents.matching(failed["started_monotonic_ns"], failed["ended_monotonic_ns"])
            selected_epoch = observed_failure_epoch(self.reader, attempt["ordinal"], self.process_uids["client"])
            category = absent_read(self.reader.trace, failed, intent, self.identity["container_id"], selected_epoch=selected_epoch)
            raw = (self.output / failed["evidence"]).read_text()
            if category == "pidof_absent": require(raw.strip() == "", "Nonempty failed pidof is not absence")
            else:
                path = failed["argv"][-1]
                require(re.fullmatch(r"(?:cat|ls): " + re.escape(path) + r": No such file or directory\n?", raw) is not None,
                        "Permission/transport/arbitrary proc error is not intentional absence")
            supplement = protected_supplement(self.reader, attempt["ordinal"], self.process_uids, intent)
            if supplement["client_metric"] is None:
                # A fully present recovered client can complete this ordinary
                # bounded read after actor close; a MISSING metric cannot.
                current = self.intents.matching(supplement["began_monotonic_ns"], supplement["ended_monotonic_ns"])
                require(current["permit_id"] == intent["permit_id"], "Missing client supplement escaped original intent")
            require(supplement["boot_id"] == self.identity["boot_id"], "Supplement observed another boot")
            require(self.intents.latest_complete_epochs is not None and all(
                {key: value[key] for key in EPOCH_FIELDS} == self.intents.latest_complete_epochs[role]
                for role, value in supplement["processes"].items() if role != "client"), "APK replacement changed a protected core epoch")
            relative_path = f"attempt-{attempt['ordinal']:06d}-replacement-supplement.json"
            sampling.lane.fresh.write_new_durable(self.output / relative_path, supplement)
            # Preserve original FAILED attempt-start/end files and its original
            # error/sample=null. A separate durable sidecar tracks provisional
            # continuation; never replace/reseal the original failed attempt.
            sampling.lane.fresh.write_new_durable(self.output / f"attempt-{attempt['ordinal']:06d}-pending-replacement.json",
                dict(status="pending_original_action_and_raw_health_admission", original_attempt=copy.deepcopy(attempt),
                     permit_id=intent["permit_id"], failed_trace_index=failed.get("sequence", self.reader.trace.index(failed)),
                     failed_client_epoch=selected_epoch,
                     supplement=relative_path, supplement_ref=file_ref(self.output / relative_path), runtime_qualified=False))
            self.error = None  # Only provisional scheduling continuation, NOT health acceptance.
        except Exception as rejection:
            sampling.lane.fresh.write_new_durable(self.output / f"attempt-{attempt['ordinal']:06d}-replacement-rejected.json",
                dict(status="failed_not_qualified", original_error=str(original), replacement_error=str(rejection),
                     original_attempt=copy.deepcopy(attempt), runtime_qualified=False))
            self.error = original

    def stop(self):
        require(self.thread is not None, "Continuous health worker was never started")
        if self.sealed_result is not None:
            require(self.error is None, "Continuous raw sampler failed: " + str(self.error))
            return self.sealed_result
        self.stop_event.set(); self.thread.join(self.stop_timeout_seconds)
        if self.thread.is_alive():
            self.cancel_event.set(); self.thread.join(65)
        if self.thread.is_alive():
            # A failed drain must be durable even before teardown makes an
            # outstanding owned read fail. This is a failure snapshot, never
            # a replacement successful journal or a counted health sample.
            self.stop_failures += 1
            self.error = self.error or ValueError("Read-only worker did not stop; owned guest cleanup must still run")
            lane.fresh.write_new_durable(self.output / f"stop-failure-{self.stop_failures:06d}.json", {
                "status": "failed_observer_drain_not_qualified", "error": str(self.error),
                "observed_monotonic_ns": time.monotonic_ns(), "identity": self.identity,
                "cancel_requested": self.cancel_event.is_set(), "worker_alive": True,
                "attempts_snapshot": list(self.attempts), "commands_snapshot": list(self.reader.trace)})
            raise self.error
        self.ended_ns = time.monotonic_ns()
        ended_realtime_ns = time.time_ns()
        lane.fresh.write_new_durable(self.output / "commands.json", self.reader.trace)
        result = {"observer": health.OBSERVER, "identity": self.identity, "interval_seconds": self.interval_seconds,
            "began_monotonic_ns": self.started_ns, "ended_monotonic_ns": self.ended_ns, "attempts": self.attempts,
            "began_realtime_ns": self.started_realtime_ns, "ended_realtime_ns": ended_realtime_ns,
            "kind": "replacement_aware_continuous_health_v1",
            "status": "retained_replacement_health_not_qualified" if self.error is None else "failed_not_qualified",
            "runtime_qualified": False, "qualification_claimed": False,
            "replacement_intents": copy.deepcopy(self.intents.records),
            "host_sources": source_bindings(),
            **({"process_uid_bindings": self.process_uids} if self.process_uids is not None else {})}
        lane.fresh.write_new_durable(self.output / "sampler.json", result)
        self.sealed_result = result
        require(self.error is None, "Continuous raw sampler failed: " + str(self.error))
        return result

