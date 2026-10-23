"""Explicit bounded role-death intents; not a health qualification waiver.

The ordinary39/UID49 observer is unchanged. Consumers must reopen a scenario's
original actor/raw audit before admitting ANY replacement or interrupted read.
"""
import copy
import secrets
import threading
import time
from pathlib import Path

import phase1_conformance_replacement_health as original
import phase1_conformance_soak_sampler as sampling

require = original.require
MAX_ROLE_DEATH_NS = 180_000_000_000
SCENARIO_ROLES = {"client_death": "client", "systemui_death": "systemui",
                  "malformed_calls": "client"}
epoch = original.epoch
relative = original.relative
def raw_ref(path, *, allow_empty=False):
    from phase1_conformance_observations import empty_ref
    path = Path(path).absolute()
    require(type(allow_empty) is bool and path.resolve(strict=True) == path and path.is_file() and not path.is_symlink(),
            "Original canonical regular role evidence required")
    if path.stat().st_size: return original.common.file_ref(path)
    require(allow_empty, "Empty role evidence requires independently verified exit1 pidof")
    return empty_ref(path)


class RoleDeathIntents:
    def __init__(self, output, uid_bindings, *, clock=time.monotonic_ns):
        self.output = Path(output)
        self.uids = original.health.validate_process_uids(uid_bindings)
        self.clock = clock
        self.lock = threading.RLock()
        self.records = []
        self.active = None
        self.latest_complete_epochs = None
        self.publication_revision = 0

    def observe_complete(self, sample, *, publication_revision):
        with self.lock:
            require(type(publication_revision) is int and 0 <= publication_revision <= self.publication_revision,
                    "Original publication revision required")
            require(sample.get("process_uid_bindings") == self.uids, "Admitted UID closure changed")
            epochs = {}
            require(set(sample["processes"]) == set(self.uids), "Complete five-role raw sample required")
            for role, value in sample["processes"].items():
                require(type(value["uid"]) is int and value["uid"] == self.uids[role], "Raw role UID changed")
                epochs[role] = original.epoch({key: value[key] for key in original.EPOCH_FIELDS})
            active = next((r for r in self.records if r["permit_id"] == self.active), None)
            if self.latest_complete_epochs is not None:
                for role in self.uids:
                    if publication_revision != self.publication_revision:
                        known = [r for r in self.records if r["role"] == role]
                        admitted = [self.latest_complete_epochs[role], *[r["before"] for r in known],
                                    *[r["after"] for r in known if "after" in r]]
                        if active is None or role != active["role"]:
                            require(epochs[role] in admitted, "Delayed sample changed an unproved role")
                        continue
                    if active is None or role != active["role"]:
                        require(epochs[role] == self.latest_complete_epochs[role], "Unplanned role epoch replacement")
            # A delayed raw sample cannot overwrite a newer provisional endpoint.
            if publication_revision == self.publication_revision and self.active is None:
                self.latest_complete_epochs = epochs

    def begin_role_death(self, action_nonce, scenario, *, role, role_uid, before,
                         started_monotonic_ns, action_relative):
        with self.lock:
            require(type(scenario) is str and scenario in SCENARIO_ROLES and SCENARIO_ROLES[scenario] == role and
                    type(role_uid) is int and role_uid == self.uids[role], "Exact allowed scenario/role UID required")
            require(type(action_nonce) is str and original.NONCE.fullmatch(action_nonce) is not None and
                    not any(r["action_nonce"] == action_nonce for r in self.records) and self.active is None,
                    "Foreign/replayed/overlapping role-death intent")
            before = original.epoch(before)
            require(self.latest_complete_epochs is not None and self.latest_complete_epochs[role] == before,
                    "Old role epoch differs from original complete health sample")
            now = self.clock()
            require(type(started_monotonic_ns) is int and type(now) is int and
                    0 < started_monotonic_ns <= now <= started_monotonic_ns + MAX_ROLE_DEATH_NS,
                    "Fixed original role-death deadline required")
            handle = secrets.token_hex(16)
            record = dict(schema=1, kind="provisional_exact_role_death_intent", permit_id=handle,
                action_nonce=action_nonce, scenario=scenario, role=role, role_uid=role_uid, before=before,
                started_monotonic_ns=started_monotonic_ns, observed_begin_monotonic_ns=now,
                deadline_monotonic_ns=started_monotonic_ns + MAX_ROLE_DEATH_NS,
                action_relative=original.relative(action_relative), status="pending_original_action_raw_audit")
            sampling.lane.fresh.write_new_durable(self.output / ("role-death-" + handle + "-begin.json"), record)
            self.records.append(record); self.active = handle; self.publication_revision += 1
            return handle

    def end_role_death(self, permit_id, *, after, ended_monotonic_ns,
                       action_relative, recovered_stage_relative):
        with self.lock:
            require(type(permit_id) is str and self.active == permit_id, "Foreign/replayed role-death close")
            record = self.records[-1]
            after = original.epoch(after)
            require(record["permit_id"] == permit_id and record["action_relative"] == action_relative and
                    after != record["before"] and type(ended_monotonic_ns) is int and
                    record["observed_begin_monotonic_ns"] <= ended_monotonic_ns <= record["deadline_monotonic_ns"] and
                    ended_monotonic_ns <= self.clock(), "Exact bounded provisional endpoint required")
            completed = {**record, "after": after, "ended_monotonic_ns": ended_monotonic_ns,
                         "recovered_stage_relative": original.relative(recovered_stage_relative)}
            sampling.lane.fresh.write_new_durable(self.output / ("role-death-" + permit_id + "-end.json"), completed)
            self.records[-1] = completed; self.active = None; self.publication_revision += 1
            self.latest_complete_epochs[record["role"]] = after

    def matching(self, began, ended):
        with self.lock:
            require(type(began) is int and type(ended) is int, "Exact raw attempt clocks required")
            rows = [r for r in self.records if r["started_monotonic_ns"] <= began <= ended <=
                    r.get("ended_monotonic_ns", r["deadline_monotonic_ns"])]
            require(len(rows) == 1, "Interrupted role read lacks one exact intent")
            return copy.deepcopy(rows[0])


def validate_durable_intents(root, records):
    """Canonical bytes, not float==int equality, authenticate original arms/closes."""
    from phase1_conformance_common import canonical
    require(type(records) is list and records, "Original role-death records missing")
    seen = set()
    for record in records:
        required = {"schema", "kind", "permit_id", "action_nonce", "scenario", "role", "role_uid", "before",
            "started_monotonic_ns", "observed_begin_monotonic_ns", "deadline_monotonic_ns", "action_relative", "status",
            "after", "ended_monotonic_ns", "recovered_stage_relative"}
        require(type(record) is dict and set(record) == required and record["schema"] == 1 and
                type(record["schema"]) is int and record["kind"] == "provisional_exact_role_death_intent" and
                record["status"] == "pending_original_action_raw_audit", "Exact closed intent schema required")
        require(SCENARIO_ROLES.get(record["scenario"]) == record["role"] and
                type(record["role_uid"]) is int and 0 < record["role_uid"] <= 2**31-1,
                "Allowed role/UID required")
        for key in ("permit_id", "action_nonce"):
            require(type(record[key]) is str and original.NONCE.fullmatch(record[key]), "Exact intent nonce required")
        require(record["permit_id"] not in seen, "Replayed role-death permit"); seen.add(record["permit_id"])
        original.epoch(record["before"]); original.epoch(record["after"])
        require(record["before"] != record["after"], "Original and replacement epochs equal")
        clocks = [record[key] for key in ("started_monotonic_ns", "observed_begin_monotonic_ns", "ended_monotonic_ns", "deadline_monotonic_ns")]
        require(all(type(v) is int and v > 0 for v in clocks) and clocks == sorted(clocks) and
                clocks[-1] == clocks[0] + MAX_ROLE_DEATH_NS, "Exact fixed intent interval required")
        for key in ("action_relative", "recovered_stage_relative"): original.relative(record[key])
        arm = {k: v for k, v in record.items() if k not in {"after", "ended_monotonic_ns", "recovered_stage_relative"}}
        for suffix, body in (("begin", arm), ("end", record)):
            path = Path(root) / ("role-death-" + record["permit_id"] + "-" + suffix + ".json")
            require(path.resolve(strict=True) == path.absolute() and not path.is_symlink() and
                    path.read_bytes() == canonical(body), "Original durable role-death bytes changed")
    return copy.deepcopy(records)


import json
import re
import phase1_conformance_role_death_reads as reads
health = original.health
lane = sampling.lane
EPOCH_FIELDS = original.EPOCH_FIELDS
file_ref = original.common.file_ref
load = original.common.load


def role_source_bindings():
    sources = original.source_bindings()
    for role, path in {"role_death_sampler": __file__, "role_death_reads": reads.__file__,
                       "role_death_auditor": Path(__file__).with_name("phase1_conformance_role_death_health_acceptance.py")}.items():
        sources[role] = {"path": str(Path(path).resolve(strict=True)), **file_ref(Path(path))}
    return sources


class RoleDeathAwareSampler(sampling.ContinuousSampler):
    """Explicit opt-in new diagnostic type, never changes default39/49 class."""
    def __init__(self, *args, process_uids, **kwargs):
        super().__init__(*args, process_uids=process_uids, **kwargs)
        self.intents = RoleDeathIntents(self.output, self.process_uids)
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

    def begin_role_death(self, *args, **kwargs): return self.intents.begin_role_death(*args, **kwargs)
    def end_role_death(self, *args, **kwargs): return self.intents.end_role_death(*args, **kwargs)

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
            role = intent["role"]
            crossing = None
            if type(failed.get("returncode")) is int and failed["returncode"] == 0:
                # Not a generic ValueError waiver: reopen all eight original
                # successful commands and reproduce only the strict PID error.
                require(type(original) is ValueError and str(original) == attempt["error"] ==
                        "PID recycled while reading resource metric", "Not the exact original crossed-PID metric failure")
                crossing = reads.crossed_role_fence(self.reader, attempt["ordinal"], self.process_uids[role], intent)
                require(crossing["trace_indices"][-1] == failed["sequence"] and
                        intent["started_monotonic_ns"] <= crossing["new_join_began_monotonic_ns"] <=
                        crossing["new_join_ended_monotonic_ns"] <= intent.get("ended_monotonic_ns", intent["deadline_monotonic_ns"]),
                        "Crossing escaped the exact provisional role interval")
                selected_epoch = {key: crossing["old_metric"][key] for key in EPOCH_FIELDS}
            else:
                selected_epoch = reads.observed_failure_epoch(self.reader, attempt["ordinal"], self.process_uids[role], role)
                category = reads.absent_read(self.reader.trace, failed, intent, self.identity["container_id"], selected_epoch=selected_epoch)
                raw = (self.output / failed["evidence"]).read_text()
                if category == "pidof_absent": require(raw.strip() == "", "Nonempty failed pidof is not absence")
                else:
                    path = failed["argv"][-1]
                    require(re.fullmatch(r"(?:cat|ls): " + re.escape(path) + r": No such file or directory\n?", raw) is not None,
                            "Permission/transport/arbitrary proc error is not intentional absence")
            supplement = reads.protected_supplement(self.reader, attempt["ordinal"], self.process_uids, intent)
            if crossing is not None:
                require(supplement["role_metric"] is not None and supplement["role_metric"]["pid"] == crossing["new_pid"] and
                        supplement["ended_monotonic_ns"] <= intent["deadline_monotonic_ns"],
                        "Crossing requires the actual full new role metric inside the fixed deadline")
            if supplement["role_metric"] is None:
                # A fully present recovered client can complete this ordinary
                # bounded read after actor close; a MISSING metric cannot.
                current = self.intents.matching(supplement["began_monotonic_ns"], supplement["ended_monotonic_ns"])
                require(current["permit_id"] == intent["permit_id"], "Missing client supplement escaped original intent")
            require(supplement["boot_id"] == self.identity["boot_id"], "Supplement observed another boot")
            require(self.intents.latest_complete_epochs is not None and all(
                {key: value[key] for key in EPOCH_FIELDS} == self.intents.latest_complete_epochs[role]
                for role, value in supplement["processes"].items() if role != intent["role"]), "APK replacement changed a protected core epoch")
            relative_path = f"attempt-{attempt['ordinal']:06d}-role-death-supplement.json"
            sampling.lane.fresh.write_new_durable(self.output / relative_path, supplement)
            # Preserve original FAILED attempt-start/end files and its original
            # error/sample=null. A separate durable sidecar tracks provisional
            # continuation; never replace/reseal the original failed attempt.
            sampling.lane.fresh.write_new_durable(self.output / f"attempt-{attempt['ordinal']:06d}-pending-role-death.json",
                dict(status="pending_original_action_and_raw_health_admission", original_attempt=copy.deepcopy(attempt),
                     permit_id=intent["permit_id"], failed_trace_index=failed.get("sequence", self.reader.trace.index(failed)),
                     failed_role_epoch=selected_epoch,
                     supplement=relative_path, supplement_ref=file_ref(self.output / relative_path), runtime_qualified=False,
                     **({"failure_kind": "all_successful_affected_role_crossing", "crossing": crossing} if crossing is not None else {})))
            self.error = None  # Only provisional scheduling continuation, NOT health acceptance.
        except Exception as rejection:
            sampling.lane.fresh.write_new_durable(self.output / f"attempt-{attempt['ordinal']:06d}-role-death-rejected.json",
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
            "kind": "exact_role_death_continuous_health_v1",
            "status": "retained_replacement_health_not_qualified" if self.error is None else "failed_not_qualified",
            "runtime_qualified": False, "qualification_claimed": False,
            "role_death_intents": copy.deepcopy(self.intents.records),
            "host_sources": role_source_bindings(),
            **({"process_uid_bindings": self.process_uids} if self.process_uids is not None else {})}
        lane.fresh.write_new_durable(self.output / "sampler.json", result)
        self.sealed_result = result
        require(self.error is None, "Continuous raw sampler failed: " + str(self.error))
        return result


