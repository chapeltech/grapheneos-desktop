#!/usr/bin/env python3
"""Continuous owned read-only sampler with a separate raw command journal.

The journal is independent of the hotplug action stream: concurrent adb reads
must never interleave or silently re-sequence the original action evidence.
"""
from pathlib import Path
import json
import hashlib
import subprocess
import threading
import time

import phase1_conformance_clean_boot as lane
import phase1_conformance_soak_health as health
import phase1_conformance_recents_guest_acceptance as owned_audit
from phase1_conformance_common import canonical, file_ref, load

require = lane.require


def verify_owner(info, identity):
    owned_audit._inspect_row({"output": json.dumps([info])}, identity, Path(identity["userdata_path"]).parent,
        identity["container_run"], identity["user"], identity["kvm_group"])
    state = info["State"]
    require(state["Running"] is True and all(state.get(field) is False for field in ("Paused", "Restarting", "Dead", "OOMKilled")) and
        type(state.get("Pid")) is int and state["Pid"] > 0 and state["Pid"] == identity["container_pid"] and
        type(info.get("RestartCount")) is int and info["RestartCount"] == 0,
        "Sampler actual container lifecycle/restart changed")


class Reader(lane.mechanics.Producer):
    """Reuses only the original traced read transport, never action methods."""
    collection_deadline = None
    cancel_event = None

    def command(self, argv, *, timeout=60, allowed=(0,), evidence=None, binary=False):
        require(not binary, "Read-only sampler transport accepts text observations only")
        require(self.cancel_event is None or not self.cancel_event.is_set(), "Read-only sampler cancelled between commands")
        argv = list(map(str, argv))
        began = time.monotonic_ns()
        limit = min(timeout, 60)
        if self.collection_deadline is not None:
            remaining = self.collection_deadline - time.monotonic()
            require(remaining > 0, "Original bounded sample collection deadline reached")
            limit = min(limit, remaining)
        deadline = time.monotonic() + limit
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except OSError as error:
            # No process or stdout exists: retain the attempted exact command,
            # not an invented successful read or a fabricated empty payload.
            self._record({"kind": "command_start_failure", "argv": argv,
                "error": str(error), "exception_type": type(error).__name__,
                "errno": error.errno, "process_started": False,
                "started_monotonic_ns": began, "ended_monotonic_ns": time.monotonic_ns()})
            raise
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self.cancel_event is not None and self.cancel_event.is_set():
                    process.kill()
                    partial, _ = process.communicate(timeout=5)
                    raise subprocess.TimeoutExpired(argv, limit, output=partial)
                try:
                    raw, _ = process.communicate(timeout=min(.25, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
            record = {"kind": "command", "argv": argv, "returncode": process.returncode,
                "started_monotonic_ns": began, "ended_monotonic_ns": time.monotonic_ns()}
            if evidence is not None:
                path = self.output / evidence; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                lane.mechanics.write_new(path, raw.encode())
                record.update(evidence=evidence, output_sha256=hashlib.sha256(raw.encode()).hexdigest())
            else: record["output"] = raw
            self._record(record)
            require(process.returncode in allowed, "Required original read-only sampler command failed: " + " ".join(argv))
            return raw.strip()
        except subprocess.TimeoutExpired as error:
            partial = error.stdout or ""
            if isinstance(partial, bytes): partial = partial.decode(errors="replace")
            record = {"kind": "command_failure", "argv": list(map(str, argv)), "error": str(error),
                "started_monotonic_ns": began, "ended_monotonic_ns": time.monotonic_ns(), "partial_output": partial}
            relative = evidence
            if relative and partial:
                path = self.output / relative; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                lane.fresh.write_new_raw_durable(path, partial)
                record.update(evidence=relative, output_sha256=hashlib.sha256(partial.encode()).hexdigest())
            self._record(record)
            raise
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


class ContinuousSampler:
    def __init__(self, identity, output, *, interval_seconds=30, stop_timeout_seconds=90, process_uids=None):
        require(type(interval_seconds) is int and 1 <= interval_seconds <= 300, "Sampler interval must remain bounded")
        self.identity, self.output = identity, Path(output)
        self.process_uids = None if process_uids is None else health.validate_process_uids(process_uids)
        require(not self.output.exists() and not self.output.is_symlink(), "Never reuse sampler output")
        self.output.mkdir(mode=0o700)
        self.reader = Reader(identity["container_id"], identity["image_id"], identity["boot_id"],
            identity["fingerprint"], self.output, 60)
        self.interval_seconds, self.stop_timeout_seconds = interval_seconds, stop_timeout_seconds
        self.stop_event = threading.Event(); self.first_event = threading.Event()
        self.cancel_event = threading.Event(); self.reader.cancel_event = self.cancel_event
        self.thread = None; self.error = None; self.attempts = []
        self.started_ns = None; self.ended_ns = None
        self.sealed_result = None
        self.stop_failures = 0

    def _sample(self):
        ordinal = len(self.attempts) + 1
        require(type(ordinal) is int and ordinal > 0, "Actual sample ordinal must be a positive exact integer")
        began = time.monotonic_ns()
        lane.fresh.write_new_durable(self.output / f"attempt-{ordinal:06d}-started.json",
            {"ordinal": ordinal, "began_monotonic_ns": began})
        row = {"ordinal": ordinal, "began_monotonic_ns": began, "status": "failed", "error": None, "sample": None}
        try:
            self.reader.collection_deadline = time.monotonic() + 480
            guard = f"guards/{ordinal:06d}.json"
            raw = self.reader.docker("container", "inspect", self.identity["container_id"], evidence=guard)
            infos = json.loads(raw)
            require(isinstance(infos, list) and len(infos) == 1, "Ambiguous sampler owned container")
            verify_owner(infos[0], self.identity)
            sample = health.observe(self.reader, ordinal, process_uids=self.process_uids)
            require(sample["boot_id"] == self.identity["boot_id"], "Sampler observed another Android boot")
            relative = f"sample-{ordinal:06d}.json"
            lane.fresh.write_new_durable(self.output / relative, sample)
            row.update(status="passed_raw_health_observation", guard=guard, sample=relative,
                sample_ref=file_ref(self.output / relative))
        except Exception as error:
            row["error"] = str(error); self.error = error
        finally:
            row["ended_monotonic_ns"] = time.monotonic_ns()
            self.attempts.append(row)
            lane.fresh.write_new_durable(self.output / f"attempt-{ordinal:06d}-ended.json", row)
            self.first_event.set()

    def _loop(self):
        try:
            while not self.stop_event.is_set():
                self._sample()
                if self.error is not None or self.stop_event.wait(self.interval_seconds): return
        except BaseException as error:
            self.error = error; self.first_event.set()

    def start(self):
        require(self.thread is None, "Never replace continuous health worker")
        self.started_ns = time.monotonic_ns()
        self.thread = threading.Thread(target=self._loop, name="policy-free-health-observer", daemon=False)
        self.thread.start()
        require(self.first_event.wait(540), "First health observation did not finish within bounded collection")
        self.check()

    def check(self):
        require(self.error is None, "Continuous raw sampler failed: " + str(self.error))
        require(self.thread is not None and self.thread.is_alive() and not self.stop_event.is_set(), "Continuous health worker exited unexpectedly")

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
        lane.fresh.write_new_durable(self.output / "commands.json", self.reader.trace)
        result = {"observer": health.OBSERVER, "identity": self.identity, "interval_seconds": self.interval_seconds,
            "began_monotonic_ns": self.started_ns, "ended_monotonic_ns": self.ended_ns, "attempts": self.attempts,
            "status": "passed_bounded_sampler_not_24h" if self.error is None else "failed_not_qualified",
            **({"process_uid_bindings": self.process_uids} if self.process_uids is not None else {})}
        lane.fresh.write_new_durable(self.output / "sampler.json", result)
        self.sealed_result = result
        require(self.error is None, "Continuous raw sampler failed: " + str(self.error))
        return result
