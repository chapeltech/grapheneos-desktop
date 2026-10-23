#!/usr/bin/env python3
"""One ordinary fresh conformance-only boot: three monitors, exactly 20 cycles.

No DesktopService, product layout, privileged task-move API, setting repair or
userdata reuse. A nonce-gated runtime replays only exact observed placements.
The held instrumentation process/output is owned until explicit stop/cleanup.
This producer does not implement or claim the 3-boot aggregate or 24-hour soak.
"""
from pathlib import Path
import json
import os
import re
import secrets
import subprocess
import sys
import time

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parents[1]
sys.path.insert(0, str(TOOLS))
import conformance_runtime as runtime
import phase1_conformance_clean_boot_acceptance as acceptance
import phase1_conformance_guest as fresh
# The read-only candidate builder prepends its original helper search paths.
# Restore our reviewed host source location before importing the reused stream.
sys.path.insert(0, str(TOOLS))
import phase1_conformance_recents as mechanics
import phase1_conformance_recents_acceptance as raw_audit
from phase1_conformance_common import canonical, file_ref, load, sha256
import phase1_conformance_observations as observations

CLIENT_FILES = tuple("android/conformance/src/main/kotlin/org/wonad/desktop/" + name for name in (
    "ConformanceContract.kt", "ConformanceRuntimeRunner.kt", "ConformanceRuntimeLedger.kt",
    "ConformanceObservedReplay.kt", "ConformanceExpectedRevocation.kt"))


def require(value, message):
    acceptance.require(value, message)


def bind_client_sources(packet):
    """Require the selected signed packet to contain the newly compiled probe."""
    freeze_path = packet / "evidence/compile-input/source-freeze.json"
    freeze = load(freeze_path)
    expected = {relative: file_ref(ROOT / relative) for relative in CLIENT_FILES}
    require(all(freeze.get("files", {}).get(relative) == record for relative, record in expected.items()),
            "Selected packet predates exact observed-replay client; rebuild unsigned conformance/packet/image first")
    return {"source_freeze": file_ref(freeze_path), "files": expected}


class Producer(mechanics.Producer):
    def __init__(self, *args, core_epochs, **kwargs):
        super().__init__(*args, **kwargs)
        require(set(core_epochs) == set(acceptance.OS_NAMES), "All four core OS epochs required before setup")
        self.core_epochs = core_epochs
        self.expected_processes = None
        self.phases = []
        self.capture_names = acceptance.PHASE_NAMES
        self.populated_rounds = 0
        self.populated_round_active = False
        self.deadline_ns = time.monotonic_ns() + acceptance.MAX_BOOT_NS
        self.phone_component = raw_audit.PHONE_HOME_COMPONENT
        self.uids = None

    def alive(self):
        require(time.monotonic_ns() < self.deadline_ns, "Bounded clean boot timed out")
        require(self.instrument is not None and self.instrument.poll() is None,
                "Held policy-free instrumentation ended unexpectedly")

    def wait(self, label, predicate, timeout=None):
        limit = time.monotonic_ns() + int((timeout or self.timeout) * 1_000_000_000)
        limit = min(limit, self.deadline_ns)
        last = None
        while time.monotonic_ns() < limit:
            if self.instrument is not None:
                self.alive()
            try:
                result = predicate()
            except (ValueError, json.JSONDecodeError) as error:
                last = error; result = False
            if result: return result
            time.sleep(.2)
        raise TimeoutError("Timed out waiting for " + label + (": " + str(last) if last else ""))

    def status(self):
        value = runtime.parse_status(self.shell("dumpsys", "activity", "service", runtime.SERVICE))
        require(value["run"] == self.conformance_run and value["failure"] is None,
                "Policy-free runtime failed or switched run")
        return value

    def runtime_command(self, phase):
        require(phase in runtime.PHASES and phase != "expect-revocation", "Unreviewed runtime phase")
        if phase != "stop":
            self.wait("current ready topology", self.runtime_topology_ready)
        nonce = secrets.token_hex(16)
        raw = self.shell("dumpsys", "activity", "service", runtime.SERVICE,
                         "runtime-command", self.conformance_run, nonce, phase)
        marker = runtime.CONTROL_MARKER + f"accepted {self.conformance_run} {nonce} {phase}"
        require(sum(line.strip() == marker for line in raw.splitlines()) == 1, "Exact runtime host nonce rejected")
        def acknowledged():
            value = self.status()
            handshake = {"nonce": nonce, "phase": phase, "result": "accepted"}
            if value["handshake"] == {**handshake, "result": "rejected"}:
                raise ValueError("Runtime rejected bounded phase: " + str(value["control_error"]))
            if value["handshake"] != handshake: return False
            return value if value["state"] == ("stopped" if phase == "stop" else "ready") else False
        return self.wait("exact " + phase + " acknowledgement", acknowledged)

    def start_runtime(self):
        require(self.instrument is None and not self.instrument_path.exists(), "Never replace a held instrumentation stream")
        self.instrument_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.instrument_file = self.instrument_path.open("xb")
        argv = ["docker", "exec", self.container, "adb", "-s", runtime_serial(), "shell", "am", "instrument", "-w", "-r",
                "-e", "run", self.conformance_run, "-e", "mode", "runtime", "-e", "nonce", self.initial_nonce,
                "-e", "phase", "start", runtime.RUNNER]
        self._record({"kind": "background_start", "id": "instrumentation-" + self.conformance_run,
                      "argv": argv, "started_monotonic_ns": time.monotonic_ns()})
        self.instrument = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=self.instrument_file,
                                           stderr=subprocess.STDOUT, start_new_session=True)
        return self.wait("policy-free held runtime", self.wait_runtime_ready, timeout=180)

    def populate(self):
        for slot, component in acceptance.COMPONENTS.items():
            row = next(row for row in self.displays().values() if row["slot"] == slot)
            self.shell("am", "start", "-W", "--user", 0, "--display", row["display"], "-n", component)
        self.home()
        self.wait("all three exact fixture tasks", lambda: self.records() if
                  set(self.records()) == set(acceptance.COMPONENTS.values()) else False)

    def records(self, final=False):
        raw = self.shell("dumpsys", "activity", acceptance.FIXTURE)
        activities = self.shell("dumpsys", "activity", "activities")
        return acceptance.fixture_lifetimes(raw, activities, self.uids[acceptance.FIXTURE], phone_only=final)[0]

    def runtime_task_ready(self, component, display):
        value = self.runtime_topology_ready()
        if not value: return False
        record = self.records().get(component)
        if record is None or record["native_display"] != display or record["display"] != display:
            return False
        stage = {"records": {component: record}, "status": value,
                 "broker_displays": {row["display_id"]: row for row in value["snapshot"]["display_incarnations"]}}
        return value if raw_audit.runtime_task(stage, component, required=False) is not None else False

    def observe_epochs(self, directory):
        rows = {}
        for index, name in enumerate(acceptance.PROCESS_NAMES):
            base = f"{directory}/process-{index}"
            pidof, before, after = base + "-pidof.txt", base + "-before.txt", base + "-after.txt"
            value = self.read(pidof, "pidof", name)
            require(re.fullmatch(r"[1-9][0-9]*", value), "Missing protected role: " + name)
            pid = int(value)
            raw_before = self.read(before, "su", "0", "cat", f"/proc/{pid}/stat")
            raw_after = self.read(after, "su", "0", "cat", f"/proc/{pid}/stat")
            epoch = acceptance.proc_epoch(raw_before, pid)
            require(epoch == acceptance.proc_epoch(raw_after, pid),
                    "PID reused while collecting protected process")
            rows[name] = {**epoch, "pidof": pidof, "before": before, "after": after}
        epochs = {name: {field: value[field] for field in ("pid", "start_ticks")} for name, value in rows.items()}
        require({name: epochs[name] for name in acceptance.OS_NAMES} == self.core_epochs,
                "Protected core OS/phone process changed during boot/setup/runtime")
        require(self.expected_processes in (None, epochs), "Conformance client process epoch changed")
        self.expected_processes = epochs
        return rows

    def capture_phase(self, name):
        require(len(self.phases) < len(self.capture_names) and name == self.capture_names[len(self.phases)],
                "Clean-boot phase order changed")
        self.alive()
        directory = f"stages/{len(self.phases):03d}-{name}"
        files = {kind: directory + "/" + kind + ".txt" for kind in
                 ("activities", "fixture", "windows", "window_displays", "input", "display", "conformance", "events")}
        commands = {
            "activities": ("dumpsys", "activity", "activities"),
            "fixture": ("dumpsys", "activity", acceptance.FIXTURE),
            "windows": ("dumpsys", "window", "windows"), "input": ("dumpsys", "input"),
            "window_displays": ("dumpsys", "window", "displays"),
            "display": ("dumpsys", "display"),
            "conformance": ("dumpsys", "activity", "service", runtime.SERVICE),
            "events": ("logcat", "-b", "events", "-d", "-v", "threadtime", "am_anr:I", "am_crash:I", "*:S"),
        }
        started = time.monotonic_ns(); trace_start = len(self.trace)
        for kind, command in commands.items(): self.read(files[kind], *command)
        processes = self.observe_epochs(directory)
        displays = raw_audit.logical_displays((self.output / files["display"]).read_text())
        frames = {"0": directory + "/frame-0.png", **{str(row["slot"]): directory + f"/frame-{row['slot']}.png"
                  for row in displays.values()}}
        for slot, relative in frames.items(): self._frame(relative, int(slot))
        row = {"name": name, "files": files, "processes": processes, "frames": frames,
               "trace_start": trace_start, "trace_end": len(self.trace),
               "started_monotonic_ns": started, "ended_monotonic_ns": time.monotonic_ns()}
        self.phases.append(row)
        evidence = {path.relative_to(self.output).as_posix(): observations.command_ref(path, self.output, self.trace, self.container)
                    for path in self.output.rglob("*") if path.is_file()}
        parsed = acceptance.parse_stage(self.output, row, evidence, self.uids)
        print("Policy-free clean-boot phase " + name + " captured", flush=True)
        return parsed

    def delivered(self, component, display, final=False):
        before = self.records(final)[component]
        point = ((before["left"] + before["right"]) // 2, (before["top"] + before["bottom"]) // 2)
        self.shell("input", "mouse", "-d", display, "tap", *point)
        self.wait("exact fixture pointer focus", lambda: self.records(final).get(component) if
            self.records(final).get(component, {}).get("focused") is True and
            raw_audit.focused_display(self.shell("dumpsys", "window", "windows")) == display else False)
        self.shell("input", "keyboard", "-d", display, "keyevent", "KEYCODE_B")
        self.wait("one delivered ordinary key and mouse", lambda: self.records(final).get(component) if
            self.records(final).get(component, {}).get("key_downs") == before["key_downs"] + 1 and
            self.records(final).get(component, {}).get("mouse_downs") == before["mouse_downs"] + 1 else False)

    def populated_hotplug_round(self, expected, *, phase_prefix="", observed_initial=None):
        """Repeat the original 20 populated actions on the SAME held runtime.

The caller must supply the exact current lease's observed component/token map.
This does not create a guest, launch replacement tasks, stop instrumentation or
claim a complete soak. A full campaign separately audits round-prefixed stages.
"""
        require(isinstance(expected, dict), "Exact current observed fixture token map required")
        expected = dict(expected)
        require(set(expected) == set(acceptance.COMPONENTS.values()) and
            all(type(token) is int and token > 0 for token in expected.values()) and
            len(set(expected.values())) == len(expected), "Exact current observed fixture token map required")
        require(isinstance(phase_prefix, str) and (phase_prefix == "" or re.fullmatch(r"round-[1-9][0-9]*-", phase_prefix) is not None),
            "Hotplug phase prefix must identify one exact positive round")
        first = len(self.phases)
        if phase_prefix:
            require(not self.populated_round_active and observed_initial is None and phase_prefix == f"round-{self.populated_rounds + 1}-" and
                (self.populated_rounds == 0 and not self.phases or self.populated_rounds > 0 and
                 len(self.phases) == len(self.capture_names)),
                "Never reuse a round or replace incomplete clean-boot/round evidence")
            self.capture_names = tuple(row["name"] for row in self.phases) + tuple(
                phase_prefix + name for name in acceptance.PHASE_NAMES[:61])
            self.populated_round_active = True
            observed_initial = self.capture_phase(phase_prefix + "initial")
        else:
            require(self.populated_rounds == 0 and self.capture_names == acceptance.PHASE_NAMES and
                len(self.phases) == 1 and self.phases[0]["name"] == "initial" and observed_initial is not None,
                "Bounded cycles require their actual initial clean-boot observation")
        require(acceptance.task_tokens(observed_initial) == expected,
                "Fixture token map does not match the actual current lease observation")
        for cycle, slot in acceptance.slot_plan():
            self.runtime_command("remember-observed")
            self.capture_phase(phase_prefix + f"cycle-{cycle:02d}-before")
            self.detach(slot)
            self.wait("two ready surviving monitors", self.runtime_topology_ready)
            component = acceptance.COMPONENTS[slot]
            token = expected[component]
            def parked():
                value = self.status()
                tasks = [task for task in value["snapshot"]["tasks"] if task["token"] == token]
                return value if len(tasks) == 1 and not tasks[0]["visible"] and not tasks[0]["input_enabled"] else False
            self.wait("exact departed task parks hidden", parked)
            # Negative control is ordinary input to its CURRENT native host,
            # never a stale Android display ID or an invented task token.
            hidden = self.records()[component]
            self.shell("input", "keyboard", "-d", hidden["native_display"], "keyevent", "KEYCODE_B")
            self.shell("input", "mouse", "-d", hidden["native_display"], "tap",
                       (hidden["left"] + hidden["right"]) // 2, (hidden["top"] + hidden["bottom"]) // 2)
            time.sleep(1)
            self.home(); self.capture_phase(phase_prefix + f"cycle-{cycle:02d}-parked")
            self.attach(slot); self.wait("new ready connector incarnation", self.runtime_topology_ready)
            self.runtime_command("restore-observed")
            destination = next(row["display"] for row in self.displays().values() if row["slot"] == slot)
            self.wait("restored exact observed fixture placement", lambda: self.runtime_task_ready(component, destination))
            self.delivered(component, destination)
            self.home(); self.capture_phase(phase_prefix + f"cycle-{cycle:02d}-restored")
            print(f"Policy-free populated hotplug {cycle}/20 slot {slot} passed", flush=True)
        if phase_prefix:
            self.populated_rounds += 1
            self.populated_round_active = False
        return self.phases[first:]

    def exercise(self):
        self.inspect_container()
        self.uids = self.package_identities()
        for slot in (1, 2, 3): self.attach(slot)
        self.populate(); self.start_runtime()
        initial = self.capture_phase("initial")
        self.populated_hotplug_round(acceptance.task_tokens(initial), observed_initial=initial)
        self.home()
        for slot in (3, 2, 1): self.detach(slot)
        self.wait("terminal undock revocation", lambda: self.status() if self.status()["state"] == "waiting-reopen" else False)
        self.capture_phase("undocked")
        # Select the already-existing exact phone Task from stock Recents;
        # do not recreate it with am-start or a task-ID manipulation command.
        self.enter_phone_overview("cancel_menu")
        for attempt in range(12):
            relative = f"phone-recovery/recents-{attempt:02d}.xml"
            xml = self.hierarchy(evidence=relative)
            try:
                point, _ = raw_audit.recents_card(xml, raw_audit.LABELS[acceptance.COMPONENTS[1]], chip=False)
                break
            except ValueError:
                if attempt == 11: raise
                self.shell("input", "touchscreen", "-d", 0, "swipe", 180, 1100, 900, 1100, 500)
        self.shell("input", "touchscreen", "-d", 0, "tap", *point)
        self.wait("former exact external task resumes on phone", lambda: self.records(True).get(acceptance.COMPONENTS[1]) if
            self.records(True).get(acceptance.COMPONENTS[1], {}).get("focused") else False)
        self.delivered(acceptance.COMPONENTS[1], 0, final=True)
        self.capture_phase("phone-resumed"); self.home()
        self.wait("ordinary phone Home focus recovery", lambda:
            raw_audit.focused_display(self.shell("dumpsys", "window", "windows")) == 0)
        self.capture_phase("phone-home")
        terminal = self.finish_instrumentation()
        raw_audit.instrumentation_success(self.instrument_path.read_text(), self.conformance_run)
        return terminal


def runtime_serial():
    return fresh.SERIAL


def run_guest(image, product, packet, receipt_sha256, output, transition_timeout=120):
    require(30 <= transition_timeout <= 120, "Bounded transition timeout must be 30..120 seconds")
    require(not output.exists() and output.parent.resolve(strict=True) == output.parent, "Never reuse clean-boot output/userdata")
    client_sources = bind_client_sources(packet)
    sources = {name: {"path": str(Path(module.__file__).resolve()), **file_ref(Path(module.__file__).resolve())}
               for name, module in {"producer": sys.modules[__name__], "auditor": acceptance,
                   "runtime_status": runtime, "fresh_guest": fresh, "stream_mechanics": mechanics,
                   "raw_window_pixel_audit": raw_audit, "raw_observations": observations}.items()}
    output.mkdir(mode=0o700)
    authority = {"runner": fresh.source_identity(Path(__file__).resolve()),
                 "guest_common": fresh.source_identity(Path(fresh.__file__).resolve())}
    guest = fresh.Producer(image, product, packet, receipt_sha256, output, authority=authority)
    child = None; report = None; error = None; started = time.monotonic_ns()
    try:
        guest.image_manifest(); guest.inputs(); guest.start()
        # The current conformance candidate has a verify-only entrypoint. This
        # uses its ordinary bundled session.py, pristine image assets and newly
        # sealed userdata, NOT product run-local or a repair/update override.
        import run_phase1_conformance_recents_guest as wrapper
        before = wrapper.prepare_guest(guest)
        child_dir = output / "runtime"; child_dir.mkdir(mode=0o700)
        child = Producer(guest.container, image, before["boot_id"], before["fingerprint"], child_dir,
                         transition_timeout, core_epochs=before["protected_processes"])
        child.deadline_ns = started + acceptance.MAX_BOOT_NS
        terminal = child.exercise()
        after = wrapper.finish_guest(guest, before)
        mechanics.write_new(child_dir / "commands.json", canonical(child.trace))
        report = {"schema": 1, "kind": acceptance.KIND, "scope": acceptance.SCOPE,
            "status": "passed_one_clean_boot_not_runtime_qualified", "image_id": image,
            "boot_id": before["boot_id"], "container_id": guest.container, "container_run": guest.run,
            "conformance_run": child.conformance_run, "boot_count": 1, "cycles": 20,
            "fingerprint": before["fingerprint"], "authority": authority,
            "packet": str(packet), "product": str(product), "packet_receipt_sha256": receipt_sha256,
            "prelaunch_state": guest.prelaunch_userdata,
            "runtime_qualified": False, "qualification_claimed": False,
            "started_monotonic_ns": started, "ended_monotonic_ns": time.monotonic_ns(),
            "before": before, "after": after, "terminal": terminal, "uids": child.uids,
            "stages": child.phases, "client_sources": client_sources, "container_stopped": False}
        report["source_files"] = sources
    except BaseException as caught:
        error = caught
    finally:
        cleanup_errors = []
        if child is not None:
            try: child.stop_background()
            except Exception as caught: cleanup_errors.append(str(caught))
        if guest.container is not None:
            try:
                stopped = guest.stop()
                require(stopped, "Owned guest was not stopped")
            except Exception as caught: cleanup_errors.append(str(caught))
        fresh.write_new(output / "commands.json", guest.trace)
        if error is not None or cleanup_errors:
            failure = {"status": "failed_not_qualified", "error": str(error), "cleanup_errors": cleanup_errors,
                       "image_id": image, "container_id": guest.container, "runtime_qualified": False}
            if child is not None:
                child.seal_failure(error or ValueError("Owned cleanup failed"), "; ".join(cleanup_errors) or None)
            fresh.write_new(output / "failure.json", failure)
        elif report is not None:
            report["container_stopped"] = True
            report["ended_monotonic_ns"] = time.monotonic_ns()
            contexts = [(output, guest.trace, True), (output / "runtime", child.trace, False)]
            report["runtime_evidence"] = observations.inventory(output / "runtime", output / "runtime",
                [(output / "runtime", child.trace, False)], guest.container)
            report["evidence_files"] = observations.inventory(output, output, contexts, guest.container,
                exclude=(output / "report.json",))
            fresh.write_new(output / "candidate-report.json", report)
    if error is not None: raise error
    require(not cleanup_errors and report is not None, "Owned cleanup failed")
    try:
        acceptance.audit_report(output / "candidate-report.json")
    except Exception as error:
        fresh.write_new(output / "failure.json", {"status": "failed_independent_audit_not_qualified",
            "error": str(error), "container_id": guest.container, "container_stopped": True,
            "runtime_qualified": False, "qualification_claimed": False,
            "candidate_report": file_ref(output / "candidate-report.json")})
        raise
    require(not (output / "report.json").exists(), "Never overwrite a final clean-boot report")
    (output / "candidate-report.json").rename(output / "report.json")
    return report


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--product", type=Path, required=True)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--receipt-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--transition-timeout", type=int, default=120)
    args = parser.parse_args(argv)
    report = run_guest(args.image, args.product.resolve(strict=True), args.packet.resolve(strict=True),
                       args.receipt_sha256, args.output.absolute(), args.transition_timeout)
    print(json.dumps(report, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
