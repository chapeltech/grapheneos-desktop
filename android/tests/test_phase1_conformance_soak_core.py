"""Host-only unfinished soak core controls; no real guest or 24h evidence."""
from pathlib import Path
import copy
import hashlib
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import phase1_conformance_soak_contract as contract
import phase1_conformance_soak_health as observer
import phase1_conformance_soak_health_acceptance as audit
from phase1_conformance_common import canonical


def stat(pid, ticks, *, after=False):
    fields = ["1"] * 19; fields[10] = "44" if after else "33"; fields[18] = str(ticks)
    return f"{pid} (process name with spaces) {'R' if after else 'S'} " + " ".join(fields) + "\n"


class FakeObservedTest:
    """Explicit synthetic read transport, not a real owned Android guest."""
    container, image = "a" * 64, "sha256:" + "b" * 64
    boot = "12345678-1234-1234-1234-123456789abc"
    def __init__(self, output): self.output, self.trace, self.tick = output, [], 100
    def read(self, relative, *args):
        if args[0] == "pidof": raw = str(list(contract.PROCESS_NAMES.values()).index(args[1]) + 1001) + "\n"
        elif args[:3] == ("su", "0", "cat"):
            pid = int(args[-1].split("/")[2])
            if args[-1].endswith("stat"): raw = stat(pid, pid + 100, after=relative.endswith("stat-after.txt"))
            else: raw = f"Pid:\t{pid}\nVmRSS:\t1024 kB\n"
        elif args[:4] == ("su", "0", "ls", "-1"): raw = "0\n1\n2\n"
        elif args[-1] == "/proc/sys/kernel/random/boot_id": raw = self.boot + "\n"
        elif args == ("getprop", "sys.boot_completed"): raw = "1\n"
        elif args == ("getprop", observer.phone.MODEM_PROPERTY): raw = "/dev/vport3p1\n"
        elif args == ("su", "0", "service", "list"):
            raw = "\n".join(f"{index}\t{name}: [{descriptor}]" for index, (name, descriptor) in enumerate(observer.phone.RADIO_SERVICES.items())) + "\n"
        elif args == ("dumpsys", "activity", "activities"):
            raw = "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\nDisplay #0 (activities from top to bottom):\n  * Task{abc #1 type=home}\nActivityTaskSupervisor state:\n"
        else: raw = "--------- beginning of synthetic raw diagnostics\n"
        path = self.output / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(raw)
        self.trace.append({"kind": "command", "argv": ["docker", "exec", self.container, "adb", "-s", "emulator-5580", "shell", *args],
            "returncode": 0, "evidence": relative, "output_sha256": hashlib.sha256(raw.encode()).hexdigest(),
            "started_monotonic_ns": self.tick, "ended_monotonic_ns": self.tick + 1})
        self.tick += 2; return raw.strip()


class SoakCoreTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_original_fixed_duration_scenarios_and_stable_phone_contract(self):
        self.assertEqual(contract.DURATION_SECONDS, 86400); self.assertEqual(contract.MINIMUM_ROUNDS, 3)
        self.assertEqual(len(contract.SCENARIOS), 9); self.assertEqual(set(contract.MISSING), set(contract.SCENARIOS))
        self.assertTrue(all("phone" not in roles and "system_server" not in roles for roles in contract.RESTART_POLICY.values()))
        self.assertTrue(contract.should_continue(1, 2, 86400_000_000_001))
        self.assertFalse(contract.should_continue(1, 3, 86400_000_000_001))

    def test_pending_driver_fails_before_any_sample_or_mutation(self):
        with self.assertRaisesRegex(NotImplementedError, "incomplete_disturbance"):
            contract.schedule_complete_rounds(contract.PendingDisturbanceDrivers())
        with self.assertRaisesRegex(NotImplementedError, "all nine"):
            audit.audit_complete_campaign({"status": "passed"})

    def test_epoch_transition_rejects_unplanned_phone_and_missing_required_replacement(self):
        before = {role: {"pid": index + 1, "start_ticks": index + 101} for index, role in enumerate(contract.PROCESS_NAMES)}
        after = copy.deepcopy(before); after["phone"]["start_ticks"] += 1
        with self.assertRaisesRegex(ValueError, "Unexpected protected.*phone"):
            contract.epoch_transitions("systemui_death", before, after)
        with self.assertRaisesRegex(ValueError, "Required actual"):
            contract.epoch_transitions("systemui_death", before, before)
        after = copy.deepcopy(before); after["systemui"]["start_ticks"] += 1
        self.assertEqual(contract.epoch_transitions("systemui_death", before, after)[0]["role"], "systemui")

    def sample(self):
        test = FakeObservedTest(self.root)
        times = iter([1, 1000]); real = iter([10000, 10999])
        row = observer.observe(test, 1, monotonic_ns=lambda: next(times), realtime_ns=lambda: next(real))
        return test, row

    def test_raw_observer_retains_changed_cpu_stat_reads_and_independent_audit_reopens_them(self):
        test, row = self.sample()
        # Canonical JSON reorders dict keys; audit must use actual trace order.
        serialized = json.loads(canonical(row))
        self.assertEqual(audit.audit_sample(self.root, serialized, test.trace)["processes"], row["processes"])
        self.assertEqual(len(test.trace), 39)
        self.assertEqual(row["radio_services"], observer.phone.RADIO_SERVICES)
        self.assertEqual(row["observer"], observer.OBSERVER)
        with self.assertRaisesRegex(ValueError, "reuse successful or failed"):
            observer.observe(test, 1)

    def test_raw_summary_or_read_authority_substitution_fails(self):
        test, row = self.sample(); changed = copy.deepcopy(row); changed["processes"]["phone"]["rss_kib"] += 1
        with self.assertRaisesRegex(ValueError, "summary differs"): audit.audit_sample(self.root, changed, test.trace)
        altered_trace = copy.deepcopy(test.trace); altered_trace[2]["argv"] = ["unowned", "read"]
        with self.assertRaisesRegex(ValueError, "Wrong read-only command"): audit.audit_sample(self.root, row, altered_trace)

    def test_start_ticks_not_whole_stat_bytes_and_pid_refencing_are_mandatory(self):
        raw = {"pid_before": "20\n", "pid_after": "20\n", "stat_before": stat(20, 200),
            "stat_after": stat(20, 200, after=True), "status": "Pid:\t20\nVmRSS:\t1024 kB\n", "fd": "0\n1\n"}
        self.assertEqual(observer.process_metric(raw, 20)["start_ticks"], 200)
        recycled = {**raw, "stat_after": stat(20, 201)}
        with self.assertRaisesRegex(ValueError, "epoch changed"): observer.process_metric(recycled, 20)
        with self.assertRaisesRegex(ValueError, "PID recycled"): observer.process_metric({**raw, "pid_after": "21\n"}, 20)
        with self.assertRaisesRegex(ValueError, "Invalid raw"): observer.process_metric({**raw, "fd": "0\n0\n"}, 20)

    def test_structured_events_do_not_confuse_filter_echo_and_do_include_phone(self):
        self.assertEqual(audit.protected_events("shell,v2 logcat am_anr:I am_crash:I\n"), [])
        for kind in ("am_anr", "am_crash"):
            self.assertEqual(audit.protected_events(f"10-13 12:00:01 I {kind}: [0,404,com.android.phone,1,reason]\n")[0]["pid"], 404)
        with self.assertRaisesRegex(ValueError, "Malformed structured"):
            audit.protected_events("I am_anr: [0,invalid,com.android.phone,1,reason]\n")

    def resources(self):
        samples = []
        for index in range(289):
            began = 1 + index * 300_000_000_000
            processes = {role: {"pid": number + 100, "start_ticks": number + 1000, "fd_count": 10, "rss_kib": 1000}
                for number, role in enumerate(contract.PROCESS_NAMES)}
            samples.append({"ordinal": index + 1, "image_id": "sha256:" + "a" * 64, "container_id": "b" * 64,
                "boot_id": FakeObservedTest.boot, "modem_port": "/dev/vport3p1", "radio_services": observer.phone.RADIO_SERVICES,
                "began_monotonic_ns": began, "ended_monotonic_ns": began + 2_000_000_000,
                "began_realtime_ns": began + 10000, "ended_realtime_ns": began + 2_000_010_000,
                "processes": processes, "counts": {"tasks": 10, "roots": 5}})
        checkpoints = []
        for ordinal, index in enumerate((0, 96, 192, 287)):
            selected = samples[index:index + 2]
            checkpoints.append({"round": ordinal, "began_monotonic_ns": selected[0]["began_monotonic_ns"],
                "ended_monotonic_ns": selected[-1]["ended_monotonic_ns"],
                "epochs": {role: {key: value[key] for key in ("pid", "start_ticks")} for role, value in selected[0]["processes"].items()},
                "resource_baseline": {role: {"fd_count": 10, "rss_kib": 1000} for role in contract.PROCESS_NAMES}})
        clocks = (1, samples[-1]["ended_monotonic_ns"], 10001, samples[-1]["ended_realtime_ns"])
        return samples, checkpoints, clocks

    def test_synthetic_24h_resource_core_is_explicitly_not_complete_soak(self):
        samples, checkpoints, clocks = self.resources()
        result = audit.audit_resources(samples, checkpoints, [], clocks)
        self.assertFalse(result["runtime_qualified"]); self.assertIn("not_complete_soak", result["status"])

    def test_intermediate_resource_peak_is_not_hidden_by_final_baseline(self):
        samples, checkpoints, clocks = self.resources(); samples[90]["processes"]["client"]["fd_count"] = 75
        with self.assertRaisesRegex(ValueError, "Per-epoch"): audit.audit_resources(samples, checkpoints, [], clocks)
        samples, checkpoints, clocks = self.resources(); samples[90]["counts"]["roots"] += 9
        with self.assertRaisesRegex(ValueError, "Intermediate task/root"): audit.audit_resources(samples, checkpoints, [], clocks)

    def test_gap_or_short_sample_span_cannot_claim_24h(self):
        samples, checkpoints, clocks = self.resources(); del samples[90:94]
        for index, row in enumerate(samples): row["ordinal"] = index + 1
        with self.assertRaisesRegex(ValueError, "sample gap"): audit.audit_resources(samples, checkpoints, [], clocks)
        samples, checkpoints, clocks = self.resources(); samples[-1]["ended_monotonic_ns"] -= 3_000_000_000
        with self.assertRaisesRegex(ValueError, "span a genuine"): audit.audit_resources(samples, checkpoints, [], clocks)

    def test_epoch_replacement_cannot_reset_cumulative_settled_leak_baseline(self):
        samples, checkpoints, clocks = self.resources()
        for row in samples[96:]: row["processes"]["client"].update(pid=777, start_ticks=7777, fd_count=75)
        transition = {"role": "client", "before": {"pid": 103, "start_ticks": 1003},
            "after": {"pid": 777, "start_ticks": 7777}, "began_monotonic_ns": samples[95]["ended_monotonic_ns"],
            "ended_monotonic_ns": samples[96]["began_monotonic_ns"]}
        for row in checkpoints[1:]: row["epochs"]["client"] = transition["after"]
        with self.assertRaisesRegex(ValueError, "Cumulative settled"):
            audit.audit_resources(samples, checkpoints, [transition], clocks)

    def test_unauthorized_core_phone_replacement_or_fake_baseline_is_rejected(self):
        samples, checkpoints, clocks = self.resources(); samples[96]["processes"]["phone"]["start_ticks"] += 1
        with self.assertRaisesRegex(ValueError, "protected epoch transition: phone"):
            audit.audit_resources(samples, checkpoints, [], clocks)
        samples, checkpoints, clocks = self.resources(); checkpoints[0]["resource_baseline"]["client"]["fd_count"] = 1000
        with self.assertRaisesRegex(ValueError, "baseline differs"): audit.audit_resources(samples, checkpoints, [], clocks)


if __name__ == "__main__": unittest.main(verbosity=2)
