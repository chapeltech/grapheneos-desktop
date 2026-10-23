"""Fail-closed orchestration tests; fake producers are never runtime PASS."""
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "android/tools"))
import run_phase1_runtime_qualification as runtime
import native_persistent_soak as persistent_producer
import native_persistent_soak_acceptance as persistent_acceptance


class Clock:
    def __init__(self, step):
        self.value, self.step = 1_000_000_000 - step, step

    def __call__(self):
        self.value += self.step
        return self.value


class RuntimeQualificationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.admission = dict(schema=1, api=3, kind=runtime.KIND, scope=runtime.SCOPE,
            inputs={"path": "/immutable/inputs.json", "sha256": "1" * 64},
            qualification={"path": "/immutable/qualification.json", "sha256": "2" * 64},
            image_id="sha256:" + "a" * 64, duration_seconds=1, production_requested=False,
            startup_boots=3, populated_hotplug_cycles_per_boot=20,
            persistent_single_guest=True, minimum_complete_rounds=3,
            soak_scenarios=list(runtime.SOAK_SCENARIOS), health_policy=dict(runtime.HEALTH_POLICY),
            clock_policy=dict(runtime.CLOCK_POLICY),
            source_sha256={}, guests_started=False)
        self.admission_path = self.root / "admission.json"
        runtime.write_new(self.admission_path, self.admission)
        self.plan, self.qualified = {"plan": True}, {"qualified": True}
        self.counter = 0
        self.health_cursor = 10_000_000_000

    def health(self, run_dir, name, *, fd_growth=1, rss_growth=16, span=2_000_000_000,
               container=None, boot_id=None, task_growth=0, root_growth=0, sample_count=2):
        directory = run_dir.parent / (run_dir.name + "-health")
        directory.mkdir()
        container = container or "b" * 64
        boot_id = boot_id or "11111111-1111-1111-1111-111111111111"
        files = {}
        processes = []
        began = self.health_cursor
        points = [began + 1_000_000_000 + (span * index // (sample_count - 1))
                  for index in range(sample_count)]
        for sequence, when in enumerate(points, 1):
            metrics = {}
            pid_files = {}
            for number, label in enumerate(runtime.PROCESS_NAMES, 1):
                prefix = "sample-%06d" % sequence
                status = f"{prefix}-{label}-{100 + number}-status.txt"
                stat_before = f"{prefix}-{label}-{100 + number}-stat-before.txt"
                stat_after = f"{prefix}-{label}-{100 + number}-stat-after.txt"
                fd = f"{prefix}-{label}-{100 + number}-fd.txt"
                final = sequence == sample_count
                (directory / status).write_text("Pid:\t%d\nVmRSS:\t%d kB\n" %
                    (100 + number, 1000 + (rss_growth if final else 0)))
                start_ticks = 10000 + number
                stat_value = ("%d (%s) S %s\n" %
                    (100 + number, label, " ".join(["1"] * 18 + [str(start_ticks)])))
                (directory / stat_before).write_text(stat_value)
                (directory / stat_after).write_text(stat_value)
                count = 10 + (fd_growth if final else 0)
                (directory / fd).write_text("".join(f"{item}\n" for item in range(count)))
                metrics[label] = [dict(pid=100 + number, start_ticks=start_ticks, rss_kib=1000 +
                    (rss_growth if final else 0), fd_count=count, status=status,
                    stat_before=stat_before, stat_after=stat_after, fd=fd)]
                pid_file = f"{prefix}-{label}-pidof.txt"
                (directory / pid_file).write_text(str(100 + number) + "\n")
                pid_files[label] = pid_file
            prefix = "sample-%06d" % sequence
            boot = f"{prefix}-boot-id.txt"; completed = f"{prefix}-boot-completed.txt"
            activities = f"{prefix}-activities.txt"
            events = f"{prefix}-events.txt"
            (directory / boot).write_text(boot_id + "\n")
            (directory / completed).write_text("1\n")
            task_count = task_growth if sequence == 2 else 0
            root_count = root_growth if sequence == 2 else 0
            roots = "".join(f"  * Task{{x{item} #{item} name=root }}\n" for item in range(1, root_count + 1))
            children = "".join(f"    * Task{{y{item} #{root_count + item} rootTaskId=1 }}\n"
                               for item in range(1, task_count - root_count + 1))
            (directory / activities).write_text(
                "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n" + roots + children +
                "ActivityTaskSupervisor state:\n")
            (directory / events).write_text("" if name != runtime.PERSISTENT_SOAK else "".join(
                "am_crash: [0, %d, com.android.systemui, deliberate]\n" % item for item in range(1, 4)))
            processes.append(dict(sequence=sequence, attempt=sequence, monotonic_ns=when,
                completed_monotonic_ns=when + 1_000_000, realtime_ns=when,
                completed_realtime_ns=when + 1_000_000,
                container=container, boot_id=boot_id,
                boot_completed=True, processes=metrics, pid_files=pid_files,
                task_count=task_count, root_count=root_count,
                boot_file=boot, completed_file=completed, activities_file=activities,
                events_file=events))
        files = runtime.seal_files(directory)
        ended = points[-1] + 1_001_000_000
        value = dict(schema=1, api=3, scope="phase1_read_only_fd_rss_task_root_samples",
            observer=runtime.HEALTH_OBSERVER, producer=name,
            candidate_image=self.admission["image_id"], container=container,
            policy=dict(runtime.HEALTH_POLICY), began_monotonic_ns=began, ended_monotonic_ns=ended,
            sample_seconds=1,
            samples=processes, failed_sample_attempts=[], files=files)
        runtime.write_new(directory / "health.json", value)
        self.health_cursor = ended + 1_000_000_000
        return directory / "health.json"

    def fake_runner(self, name, command, run_dir, log, image, timeout, sample):
        self.counter += 1
        container = "%064x" % self.counter
        boot_id = "%08x-0000-0000-0000-%012x" % (self.counter, self.counter)
        run_dir.mkdir()
        log.write_text("fake producer; orchestration test only\n")
        health = self.health(run_dir, name, container=container, boot_id=boot_id,
                             sample_count=4 if name == runtime.PERSISTENT_SOAK else 2,
                             span=4_000_000_000 if name == runtime.PERSISTENT_SOAK else 2_000_000_000)
        report = {"fake_original": name, "ordinal": self.counter}
        if name == runtime.PERSISTENT_SOAK:
            report["fake_semantic"] = self.semantic(json.loads(health.read_text()), 3)
        runtime.write_new(run_dir / "report.json", report)
        return dict(exit_code=0, report=runtime.reference(run_dir / "report.json"),
                    health=runtime.reference(health), log=runtime.reference(log),
                    summary=runtime.inspect_health(json.loads(health.read_text()), health.parent))

    def patches(self):
        def command(plan, parent, name, duration_seconds=None, sample_seconds=15):
            return [sys.executable, "fake-producer.py", name, "--output", str(parent / name)]

        def audit(name, path, qualified, **unused):
            value = json.loads(path.read_text())
            ordinal = value["ordinal"]
            row = ("run-%d" % ordinal, "%08x-0000-0000-0000-%012x" % (ordinal, ordinal),
                   "%064x" % ordinal)
            semantic = {"auditor": "fake-only"}
            if name == runtime.PERSISTENT_SOAK:
                semantic["summary"] = value["fake_semantic"]
            return row, semantic

        return (patch.object(runtime, "_sealed_inputs",
                             return_value=(self.plan, self.qualified, Path("/input"), Path("/qualification"))),
                patch.object(runtime.matrix, "check_lane_inputs"),
                patch.object(runtime.matrix, "check_inputs"),
                patch.object(runtime, "command_for", side_effect=command),
                patch.object(runtime, "audit_original", side_effect=audit))

    def semantic(self, health, rounds):
        samples = health["samples"]
        selected = samples[-(rounds + 1):]
        return dict(run="ignored", boot_id=health["samples"][0]["boot_id"],
            container=health["container"], image_id=health["candidate_image"],
            duration_seconds=self.admission["duration_seconds"],
            began_monotonic_ns=samples[0]["monotonic_ns"],
            ended_monotonic_ns=samples[-1]["completed_monotonic_ns"], rounds=rounds,
            restart_windows=[], authorized_epoch_windows=[], checkpoints=[dict(round=index,
                began_monotonic_ns=sample["monotonic_ns"],
                ended_monotonic_ns=sample["completed_monotonic_ns"] + 1,
                task_count=sample["task_count"], root_count=sample["root_count"],
                processes={label: [dict(pid=item["pid"], start_ticks=item["start_ticks"])
                    for item in rows] for label, rows in sample["processes"].items()},
                evidence="fake") for index, sample in enumerate(selected)],
            report_sha256="0" * 64)

    def persistent_report(self):
        directory = self.root / ("persistent-report-%d" % len(list(self.root.glob("persistent-report-*"))))
        directory.mkdir(); (directory / "persistent").mkdir()
        run, boot, container = "1" * 32, "11111111-1111-1111-1111-111111111111", "c" * 64
        image = self.admission["image_id"]
        base = {
            "system_server": [dict(pid=10, start_ticks=100)],
            "systemui": [dict(pid=20, start_ticks=200)],
            "launcher": [dict(pid=30, start_ticks=300)],
            "wonad": [dict(pid=40, start_ticks=400)],
            "phone": [dict(pid=50, start_ticks=500)],
        }
        current, scenarios, cursor = copy.deepcopy(base), [], 2_000_000_000
        baseline_evidence = "persistent/baseline.json"
        runtime.write_new(directory / baseline_evidence, {"settled": "baseline"})
        baseline_checkpoint = dict(began_monotonic_ns=1_800_000_000,
            ended_monotonic_ns=1_900_000_000, task_count=3, root_count=2,
            processes=copy.deepcopy(base), evidence=baseline_evidence)
        restart_number = 0
        for name in persistent_acceptance.SCENARIOS:
            before = copy.deepcopy(current); began = cursor; cursor += 100_000_000
            restarts = []
            roles = persistent_acceptance.REQUIRED_RESTART.get(name, set())
            for role in sorted(roles):
                restart_number += 1; old = copy.deepcopy(current[role][0])
                current[role] = [dict(pid=old["pid"] + restart_number,
                                      start_ticks=old["start_ticks"] + restart_number)]
                restarts.append(dict(role=role, monotonic_ns=cursor,
                                     before=old, after=copy.deepcopy(current[role][0])))
            evidence = "persistent/" + name + ".json"
            runtime.write_new(directory / evidence, {"actual": name})
            scenarios.append(dict(name=name, began_monotonic_ns=began,
                ended_monotonic_ns=cursor, boot_id=boot, process_before=before,
                process_after=copy.deepcopy(current), restarts=restarts, evidence=evidence))
        checkpoint_begin = cursor; cursor += 100_000_000
        checkpoint_evidence = "persistent/checkpoint.json"
        runtime.write_new(directory / checkpoint_evidence, {"settled": True})
        checkpoint = dict(began_monotonic_ns=checkpoint_begin, ended_monotonic_ns=cursor,
            task_count=3, root_count=2, processes=copy.deepcopy(current), evidence=checkpoint_evidence)
        runtime.write_new(directory / "commands.json", [])
        files = {str(path.relative_to(directory)): runtime.checksum(path)
                 for path in sorted(directory.rglob("*")) if path.is_file()}
        startup = dict(run=run, boot_id=boot, container=container, image_id=image,
                       fingerprint="test/fingerprint", container_stopped=True)
        envelope = dict(schema=1, api=3, run=run, boot_id=boot, container=container,
            fingerprint="test/fingerprint", owned_container_stopped=True,
            artifacts_unchanged=False, nontransition_artifacts_unchanged=True,
            reference_unchanged=True, authorized_apk_transitions=[dict(round=1,
                candidate_sha256="a" * 64, restored_sha256="b" * 64)], evidence_files=files)
        report = dict(schema=1, api=3, scope=persistent_acceptance.SCOPE,
            native_persistent_soak="passed", run=run, boot_id=boot, container=container,
            image_id=image, fingerprint="test/fingerprint", duration_seconds=1, minimum_rounds=1,
            started_monotonic_ns=1_000_000_000, ended_monotonic_ns=max(cursor, 2_000_000_000),
            started_realtime_ns=10_000_000_000,
            ended_realtime_ns=10_000_000_000 + max(cursor, 2_000_000_000) - 1_000_000_000,
            baseline_checkpoint=baseline_checkpoint,
            rounds=[dict(ordinal=1, began_monotonic_ns=2_000_000_000,
                         ended_monotonic_ns=cursor, scenarios=scenarios, checkpoint=checkpoint)],
            startup=startup, container_stopped=True, native_acceptance_evidence=envelope,
            evidence_files=files)
        runtime.write_new(directory / "report.json", report)
        return directory / "report.json", report

    def campaign(self, *, clock=None, runner=None, startup_timeout=60, soak_timeout=None):
        output = self.root / ("campaign-%d" % len(list(self.root.glob("campaign-*"))))
        output.mkdir()
        campaign_admission = output / "admission.json"
        runtime.write_new(campaign_admission, self.admission)
        contexts = self.patches()
        selected_clock = clock or Clock(2_000_000_000)
        with contexts[0], contexts[1], contexts[2], contexts[3], contexts[4], \
             patch.object(runtime, "qualification_identities", side_effect=lambda unused: []), \
             patch.object(runtime, "validate_record_timeline", return_value=0):
            value = runtime.execute_campaign(self.admission, campaign_admission, output,
                startup_timeout, soak_timeout or max(60, self.admission["duration_seconds"]), 1,
                run_one=runner or self.fake_runner, monotonic_ns=selected_clock,
                realtime_ns=selected_clock)
        return value, output

    def test_short_campaign_runs_three_startups_and_one_persistent_guest(self):
        value, output = self.campaign()
        self.assertEqual(value["runtime_qualification"], "passed")
        self.assertEqual(value["production_acceptance"], "not_passed")
        self.assertTrue(value["diagnostic_only"])
        self.assertEqual([row["producer"] for row in value["startup_runs"]], list(runtime.STARTUPS))
        self.assertEqual(value["soak_run"]["producer"], runtime.PERSISTENT_SOAK)
        index = json.loads((output / "evidence-index.json").read_text())
        self.assertEqual(index["soak_rounds"], 3)
        self.assertEqual(len(index["records"]), 4)
        self.assertEqual(len({row["identity"]["container"] for row in index["records"]}), len(index["records"]))

    def test_production_requires_exactly_24_hours_and_three_complete_rounds(self):
        with self.assertRaisesRegex(ValueError, "exactly a 24-hour"):
            runtime.bind_admission(Path("/missing"), Path("/missing"), runtime.PRODUCTION_SECONDS - 1, True)
        self.admission["duration_seconds"] = runtime.PRODUCTION_SECONDS
        self.admission["production_requested"] = True
        self.admission_path.unlink(); runtime.write_new(self.admission_path, self.admission)
        def long_runner(name, command, run_dir, log, image, timeout, sample):
            self.counter += 1
            container = "%064x" % self.counter
            boot_id = "%08x-0000-0000-0000-%012x" % (self.counter, self.counter)
            run_dir.mkdir()
            log.write_text("fake long producer; orchestration test only\n")
            health = self.health(run_dir, name, container=container, boot_id=boot_id,
                span=(runtime.PRODUCTION_SECONDS + 2) * 1_000_000_000 if name == runtime.PERSISTENT_SOAK
                else 2_000_000_000, sample_count=150 if name == runtime.PERSISTENT_SOAK else 2)
            report = {"fake_original": name, "ordinal": self.counter}
            if name == runtime.PERSISTENT_SOAK:
                report["fake_semantic"] = self.semantic(json.loads(health.read_text()), 3)
            runtime.write_new(run_dir / "report.json", report)
            return dict(exit_code=0, report=runtime.reference(run_dir / "report.json"),
                        health=runtime.reference(health), log=runtime.reference(log),
                        summary=runtime.inspect_health(json.loads(health.read_text()), health.parent))

        value, _ = self.campaign(clock=Clock(runtime.PRODUCTION_SECONDS * 1_000_000_000),
                                 runner=long_runner)
        self.assertEqual(value["runtime_qualification"], "passed")
        self.assertEqual(value["production_acceptance"], "passed")
        self.assertFalse(value["diagnostic_only"])
        self.assertEqual(value["soak_rounds"], 3)
        self.assertEqual(value["soak_run"]["producer"], runtime.PERSISTENT_SOAK)

    def test_fast_clock_cannot_replace_24_hours_of_successful_resource_sampling(self):
        self.admission["duration_seconds"] = runtime.PRODUCTION_SECONDS
        self.admission["production_requested"] = True
        self.admission_path.unlink(); runtime.write_new(self.admission_path, self.admission)

        value, _ = self.campaign(clock=Clock(runtime.PRODUCTION_SECONDS * 1_000_000_000),
                                 runner=self.fake_runner)
        self.assertEqual(value["runtime_qualification"], "not_passed")
        self.assertIn("sampled soak duration", value["error"])

    def test_original_failure_or_input_drift_never_produces_an_index_or_pass(self):
        def fail(name, *args):
            if name == runtime.PERSISTENT_SOAK:
                raise ValueError("actual original failed")
            return self.fake_runner(name, *args)

        value, output = self.campaign(runner=fail)
        self.assertEqual(value["runtime_qualification"], "not_passed")
        self.assertIn("actual original failed", value["error"])
        self.assertFalse((output / "evidence-index.json").exists())

        output = self.root / "drift"; output.mkdir()
        checks = [(self.plan, self.qualified, Path("/i"), Path("/q"))] * 3 + [ValueError("input drift")]
        contexts = self.patches()
        with patch.object(runtime, "_sealed_inputs", side_effect=checks), contexts[1], contexts[2], contexts[3], contexts[4], \
             patch.object(runtime, "qualification_identities", side_effect=lambda unused: []):
            value = runtime.execute_campaign(self.admission, self.admission_path, output, 60, 60, 1,
                run_one=self.fake_runner, monotonic_ns=Clock(2_000_000_000))
        self.assertEqual(value["runtime_qualification"], "not_passed")
        self.assertIn("input drift", value["error"])

    def test_zero_exit_fake_without_complete_terminal_receipt_never_passes(self):
        def incomplete(name, *arguments):
            terminal = self.fake_runner(name, *arguments)
            terminal.pop("summary")
            return terminal

        value, output = self.campaign(runner=incomplete)
        self.assertEqual(value["runtime_qualification"], "not_passed")
        self.assertIn("terminal receipt", value["error"])
        self.assertFalse((output / "evidence-index.json").exists())

    def test_health_evidence_rejects_tamper_missing_samples_and_growth(self):
        run = self.root / "one"; run.mkdir()
        path = self.health(run, "startup_1")
        value = json.loads(path.read_text())
        summary = runtime.inspect_health(value, path.parent)
        self.assertEqual(summary["samples"], 2)
        target = path.parent / next(iter(value["files"]))
        original = target.read_bytes(); target.write_bytes(original + b"tamper")
        with self.assertRaisesRegex(ValueError, "bytes changed"):
            runtime.inspect_health(value, path.parent)
        target.write_bytes(original)

        bad = copy.deepcopy(value); bad["samples"] = bad["samples"][:1]
        with self.assertRaisesRegex(ValueError, "Insufficient"):
            runtime.inspect_health(bad, path.parent)
        fd_run = self.root / "fd-growing"; fd_run.mkdir()
        fd_path = self.health(fd_run, "startup_1", fd_growth=65)
        bad = json.loads(fd_path.read_text())
        with self.assertRaisesRegex(ValueError, "Unbounded FD/RSS"):
            runtime.inspect_health(bad, fd_path.parent)
        growing = self.root / "growing"; growing.mkdir()
        growing_path = self.health(growing, "startup_1", task_growth=13)
        bad = json.loads(growing_path.read_text())
        with self.assertRaisesRegex(ValueError, "task/root"):
            runtime.inspect_health(bad, growing_path.parent)

    def test_health_rejects_duplicate_omitted_sparse_and_peak_resource_evidence(self):
        run = self.root / "health-adversarial"; run.mkdir()
        path = self.health(run, "startup_1", sample_count=3)
        value = json.loads(path.read_text())

        duplicate = copy.deepcopy(value)
        duplicate["samples"][1]["processes"]["wonad"][0]["status"] = \
            duplicate["samples"][0]["processes"]["wonad"][0]["status"]
        with self.assertRaisesRegex(ValueError, "reused/misnamed"):
            runtime.inspect_health(duplicate, path.parent)

        sparse = copy.deepcopy(value)
        prior = sparse["samples"][0]
        current = sparse["samples"][1]
        current["monotonic_ns"] = prior["completed_monotonic_ns"] + \
            runtime.HEALTH_POLICY["maximum_sample_gap_ns"] + 1
        current["completed_monotonic_ns"] = current["monotonic_ns"] + 1_000_000
        current["realtime_ns"] = current["monotonic_ns"]
        current["completed_realtime_ns"] = current["completed_monotonic_ns"]
        sparse["samples"][2]["monotonic_ns"] = current["completed_monotonic_ns"] + 1
        sparse["samples"][2]["completed_monotonic_ns"] = sparse["samples"][2]["monotonic_ns"] + 1_000_000
        sparse["samples"][2]["realtime_ns"] = sparse["samples"][2]["monotonic_ns"]
        sparse["samples"][2]["completed_realtime_ns"] = sparse["samples"][2]["completed_monotonic_ns"]
        sparse["ended_monotonic_ns"] = sparse["samples"][2]["completed_monotonic_ns"] + 1_000_000
        with self.assertRaisesRegex(ValueError, "sequence/coverage"):
            runtime.inspect_health(sparse, path.parent)

        crash = copy.deepcopy(value)
        events = crash["samples"][1]["events_file"]
        (path.parent / events).write_text("am_anr: [0, 123, system_server, blocked]\n")
        crash["files"] = runtime.seal_files(path.parent)
        with self.assertRaisesRegex(ValueError, "crashed or ANRed"):
            runtime.inspect_health(crash, path.parent)
        (path.parent / events).write_text("")

        (path.parent / "unbound-observation.txt").write_text("not referenced by any attempt\n")
        extra = copy.deepcopy(value); extra["files"] = runtime.seal_files(path.parent)
        with self.assertRaisesRegex(ValueError, "unreferenced"):
            runtime.inspect_health(extra, path.parent)
        (path.parent / "unbound-observation.txt").unlink()

        peak = copy.deepcopy(value)
        metric = peak["samples"][1]["processes"]["wonad"][0]
        metric["fd_count"] = runtime.HEALTH_POLICY["maximum_fd_growth_per_incarnation"] + 20
        (path.parent / metric["fd"]).write_text("".join(
            "%d\n" % number for number in range(metric["fd_count"])))
        peak["files"] = runtime.seal_files(path.parent)
        with self.assertRaisesRegex(ValueError, "Unbounded FD/RSS"):
            runtime.inspect_health(peak, path.parent)

    def test_candidate_inventory_rejects_descendant_image_matches(self):
        container = "c" * 64
        image = "sha256:" + "a" * 64
        with patch.object(runtime, "_docker", side_effect=[container, "sha256:" + "b" * 64]):
            with self.assertRaisesRegex(ValueError, "not an exact"):
                runtime.candidate_containers(image)

    def test_qualified_backend_identity_cannot_be_reused_as_fresh_runtime(self):
        gates = {name: {"path": "/" + name, "sha256": "a" * 64}
                 for name in runtime.matrix.GATES}
        qualified = {"evidence": {"gates": gates}}
        report = {"native_acceptance_evidence": {}}
        with patch.object(runtime, "read_bound", return_value=(report, Path("/bound"))), \
             patch.object(runtime, "identity", return_value=("run", "boot", "container")):
            with self.assertRaisesRegex(ValueError, "already reuses"):
                runtime.qualification_identities(qualified)

    def test_timeline_rejects_overlap_and_sampled_duration_inflation(self):
        records = [
            {"health_summary": {"began_monotonic_ns": 10, "ended_monotonic_ns": 20,
                                "sampled_span_ns": 9}},
            {"health_summary": {"began_monotonic_ns": 19, "ended_monotonic_ns": 30,
                                "sampled_span_ns": 10}},
        ]
        with self.assertRaisesRegex(ValueError, "overlap"):
            runtime.validate_record_timeline(records, 1, 10, 0, 40)
        records[1]["health_summary"]["began_monotonic_ns"] = 20
        with self.assertRaisesRegex(ValueError, "duration/timeline"):
            runtime.validate_record_timeline(records, 1, 11, 0, 40)

    def test_protected_process_sampler_is_disclosed_read_only_su0(self):
        raw = self.root / "raw"; raw.mkdir()
        outputs = ["123\n", "Name:\tsystem_server\nPid:\t123\nVmRSS:\t4096 kB\n",
                   "123 (system_server) S " + " ".join(["1"] * 18 + ["999"]) + "\n",
                   "0\n1\n2\n",
                   "123 (system_server) S " + " ".join(["1"] * 18 + ["999"]) + "\n"]
        with patch.object(runtime, "docker_exec", side_effect=outputs) as execute:
            rows = runtime._process_metric("a" * 64, "system_server", "system_server", raw, "sample")
        self.assertEqual(rows[0]["rss_kib"], 4096); self.assertEqual(rows[0]["fd_count"], 3)
        commands = [call.args[1] for call in execute.call_args_list]
        self.assertEqual(commands[0][-2:], ["pidof", "system_server"])
        self.assertEqual(commands[1][4:7], ["su", "0", "cat"])
        self.assertEqual(commands[2][4:7], ["su", "0", "cat"])
        self.assertEqual(commands[3][4:8], ["su", "0", "ls", "-1"])
        self.assertEqual(commands[4][4:7], ["su", "0", "cat"])
        forbidden = {"input", "settings", "install", "uninstall", "start", "stop", "kill"}
        self.assertFalse(any(forbidden & set(command) for command in commands))
        reused = outputs[:-1] + ["123 (system_server) S " +
                                 " ".join(["1"] * 18 + ["1000"]) + "\n"]
        with patch.object(runtime, "docker_exec", side_effect=reused), \
             self.assertRaisesRegex(ValueError, "Incomplete FD/RSS"):
            runtime._process_metric("a" * 64, "system_server", "system_server", raw, "reused")

    def test_phone_role_preserves_original_inventory_and_runtime_requirements(self):
        roles = ("system_server", "systemui", "launcher", "wonad", "phone")
        self.assertEqual(tuple(runtime.PROCESS_NAMES), roles)
        self.assertEqual(persistent_producer.PROCESS_NAMES, runtime.PROCESS_NAMES)
        self.assertEqual(persistent_acceptance.ROLES, roles)
        self.assertEqual(runtime.PROCESS_NAMES["phone"], "com.android.phone")
        self.assertFalse(any("phone" in allowed for allowed in persistent_acceptance.RESTART_POLICY.values()))
        self.assertEqual(runtime.PRODUCTION_SECONDS, 86400)
        self.assertEqual(len(runtime.STARTUPS), 3)
        self.assertEqual(self.admission["populated_hotplug_cycles_per_boot"], 20)
        self.assertEqual(self.admission["minimum_complete_rounds"], 3)

    def test_health_sampler_collects_phone_independently_with_pid_starttime_fence(self):
        raw = self.root / "phone-sampler"; raw.mkdir()
        stat = "123 (com.android.phone) S " + " ".join(["1"] * 18 + ["999"]) + "\n"
        outputs = ["123\n", "Name:\tcom.android.phone\nPid:\t123\nVmRSS:\t4096 kB\n",
                   stat, "0\n1\n2\n", stat]
        with patch.object(runtime, "docker_exec", side_effect=outputs) as execute:
            rows = runtime._process_metric("a" * 64, "phone", "com.android.phone", raw, "sample")
        self.assertEqual((rows[0]["pid"], rows[0]["start_ticks"]), (123, 999))
        self.assertEqual(execute.call_args_list[0].args[1][-2:], ["pidof", "com.android.phone"])
        self.assertEqual(execute.call_args_list[2].args[1][-1], "/proc/123/stat")
        self.assertEqual(execute.call_args_list[4].args[1][-1], "/proc/123/stat")
        for pidof in ("", "123 123\n"):
            with self.subTest(pidof=pidof), patch.object(runtime, "docker_exec", return_value=pidof), \
                 self.assertRaisesRegex(ValueError, "Missing/ambiguous"):
                runtime._process_metric("a" * 64, "phone", "com.android.phone", raw, "missing")
        changed_stat = stat.replace("999", "1000")
        with patch.object(runtime, "docker_exec", side_effect=outputs[:-1] + [changed_stat]), \
             self.assertRaisesRegex(ValueError, "process-epoch observation for phone"):
            runtime._process_metric("a" * 64, "phone", "com.android.phone", raw, "reused")

        boot = "11111111-1111-1111-1111-111111111111\n"
        activities = "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\nActivityTaskSupervisor state:\n"
        with patch.object(runtime, "docker_exec", side_effect=[boot, "1\n", activities, ""]), \
             patch.object(runtime, "_process_metric", return_value=rows) as collect:
            sample = runtime.health_sample("a" * 64, raw, 1)
        self.assertEqual(set(sample["processes"]), set(runtime.PROCESS_NAMES))
        self.assertEqual(collect.call_args_list[-1].args[1:3], ("phone", "com.android.phone"))
        self.assertEqual(sample["pid_files"]["phone"], "sample-000001-phone-pidof.txt")

    def test_health_requires_phone_inventory_and_one_unchanged_epoch(self):
        for producer in ("startup_1", runtime.PERSISTENT_SOAK):
            with self.subTest(producer=producer):
                run = self.root / ("phone-health-" + producer); run.mkdir()
                path = self.health(run, producer, sample_count=3)
                original = json.loads(path.read_text())
                for field in ("processes", "pid_files"):
                    missing = copy.deepcopy(original)
                    del missing["samples"][1][field]["phone"]
                    with self.assertRaisesRegex(ValueError, "Incomplete task/root/process"):
                        runtime.inspect_health(missing, path.parent)
                multiple = copy.deepcopy(original)
                multiple["samples"][1]["processes"]["phone"] *= 2
                with self.assertRaisesRegex(ValueError, "one com.android.phone"):
                    runtime.inspect_health(multiple, path.parent)
                changed = copy.deepcopy(original)
                metric = changed["samples"][-1]["processes"]["phone"][0]
                old = metric["start_ticks"]; metric["start_ticks"] += 1
                for field in ("stat_before", "stat_after"):
                    target = path.parent / metric[field]
                    target.write_text(target.read_text().replace(str(old) + "\n", str(old + 1) + "\n"))
                changed["files"] = runtime.seal_files(path.parent)
                with self.assertRaisesRegex(ValueError, "com.android.phone changed epoch"):
                    runtime.inspect_health(changed, path.parent)

    def test_health_rejects_phone_crash_and_anr_in_startup_and_soak(self):
        for producer in ("startup_1", runtime.PERSISTENT_SOAK):
            run = self.root / ("phone-events-" + producer); run.mkdir()
            path = self.health(run, producer)
            original = json.loads(path.read_text())
            for kind in ("am_crash", "am_anr"):
                for process in ("com.android.phone", "com.android.phone:worker"):
                    with self.subTest(producer=producer, kind=kind, process=process):
                        event = f"{kind}: [0, 123, {process}, unexpected]\n"
                        self.assertEqual(runtime.protected_failures(event)[0]["process"], process)
                        changed = copy.deepcopy(original)
                        (path.parent / changed["samples"][0]["events_file"]).write_text(event)
                        changed["files"] = runtime.seal_files(path.parent)
                        with self.assertRaisesRegex(ValueError, "crash/ANR|crashed or ANRed"):
                            runtime.inspect_health(changed, path.parent)

    def test_health_applies_resource_growth_limits_to_phone(self):
        run = self.root / "phone-resource-growth"; run.mkdir()
        path = self.health(run, "startup_1", sample_count=3)
        changed = json.loads(path.read_text())
        metric = changed["samples"][1]["processes"]["phone"][0]
        metric["fd_count"] += runtime.HEALTH_POLICY["maximum_fd_growth_per_incarnation"] + 1
        (path.parent / metric["fd"]).write_text("".join(f"{number}\n" for number in range(metric["fd_count"])))
        changed["files"] = runtime.seal_files(path.parent)
        with self.assertRaisesRegex(ValueError, "Unbounded FD/RSS growth for phone"):
            runtime.inspect_health(changed, path.parent)

    def test_reused_identity_is_rejected_even_when_fake_reports_exit_zero(self):
        contexts = self.patches()
        output = self.root / "reuse"; output.mkdir()
        def same_runner(name, command, run_dir, log, image, timeout, sample):
            self.counter += 1; run_dir.mkdir()
            runtime.write_new(run_dir / "report.json", {"fake_original": name, "ordinal": self.counter})
            log.write_text("fake same-identity producer\n")
            health = self.health(run_dir, name, container="c" * 64,
                                 boot_id="11111111-1111-1111-1111-111111111111")
            return dict(exit_code=0, report=runtime.reference(run_dir / "report.json"),
                        health=runtime.reference(health), log=runtime.reference(log),
                        summary=runtime.inspect_health(json.loads(health.read_text()), health.parent))
        with contexts[0], contexts[1], contexts[2], contexts[3], patch.object(runtime, "audit_original",
                return_value=(("same", "11111111-1111-1111-1111-111111111111", "c" * 64), {})), \
             patch.object(runtime, "qualification_identities", side_effect=lambda unused: []):
            value = runtime.execute_campaign(self.admission, self.admission_path, output, 60, 60, 1,
                run_one=same_runner, monotonic_ns=Clock(2_000_000_000))
        self.assertEqual(value["runtime_qualification"], "not_passed")
        self.assertIn("reused", value["error"])

    def test_offline_verifier_reaudits_originals_and_rejects_bound_byte_tamper(self):
        value, output = self.campaign()
        self.assertEqual(value["runtime_qualification"], "passed")

        def command(plan, parent, name, duration_seconds=None, sample_seconds=15):
            return [sys.executable, "fake-producer.py", name, "--output", str(parent / name)]

        def audit(name, path, qualified, **unused):
            value = json.loads(path.read_text()); ordinal = value["ordinal"]
            row = ("run-%d" % ordinal, "%08x-0000-0000-0000-%012x" % (ordinal, ordinal),
                   "%064x" % ordinal)
            semantic = {"auditor": "fake-only"}
            if name == runtime.PERSISTENT_SOAK: semantic["summary"] = value["fake_semantic"]
            return row, semantic

        with patch.object(runtime, "check_admission",
                          return_value=(self.plan, self.qualified, Path("/i"), Path("/q"))), \
             patch.object(runtime.matrix, "check_inputs"), \
             patch.object(runtime, "command_for", side_effect=command), \
             patch.object(runtime, "audit_original", side_effect=audit), \
             patch.object(runtime, "qualification_identities", side_effect=lambda unused: []), \
             patch.object(runtime, "validate_record_timeline", return_value=0):
            verified = runtime.verify_result(output / "result.json")
            self.assertEqual(verified["runtime_qualification"], "passed")
            log = Path(value["startup_runs"][0]["log"]["path"])
            log.write_text(log.read_text() + "tampered\n")
            with self.assertRaisesRegex(ValueError, "log changed"):
                runtime.verify_result(output / "result.json")

    def test_offline_verifier_rejects_stale_cross_lane_path_even_with_rehashed_wrappers(self):
        value, output = self.campaign()
        self.assertEqual(value["runtime_qualification"], "passed")
        index_path = output / "evidence-index.json"
        result_path = output / "result.json"
        index = json.loads(index_path.read_text())
        result = json.loads(result_path.read_text())
        index["records"][0]["report"] = index["records"][1]["report"]
        index_path.unlink(); runtime.write_new(index_path, index)
        result["evidence_index"] = runtime.reference(index_path)
        result_path.unlink(); runtime.write_new(result_path, result)

        with patch.object(runtime, "check_admission",
                          return_value=(self.plan, self.qualified, Path("/i"), Path("/q"))), \
             patch.object(runtime.matrix, "check_inputs"), \
             patch.object(runtime, "qualification_identities", side_effect=lambda unused: []):
            with self.assertRaisesRegex(ValueError, "left/reused"):
                runtime.verify_result(result_path)

    def test_offline_verifier_rejects_rehashed_truncated_sampled_duration(self):
        value, output = self.campaign()
        self.assertEqual(value["runtime_qualification"], "passed")
        index_path = output / "evidence-index.json"
        result_path = output / "result.json"
        index = json.loads(index_path.read_text())
        result = json.loads(result_path.read_text())
        index["soak_sampled_ns"] = 0
        index_path.unlink(); runtime.write_new(index_path, index)
        result["soak_sampled_ns"] = 0
        result["evidence_index"] = runtime.reference(index_path)
        result_path.unlink(); runtime.write_new(result_path, result)

        with patch.object(runtime, "check_admission",
                          return_value=(self.plan, self.qualified, Path("/i"), Path("/q"))):
            with self.assertRaisesRegex(ValueError, "dual-clock/sampled"):
                runtime.verify_result(result_path)

    def test_offline_verifier_rejects_rehashed_round_count_inflation(self):
        value, output = self.campaign()
        self.assertEqual(value["runtime_qualification"], "passed")
        index_path, result_path = output / "evidence-index.json", output / "result.json"
        index, result = json.loads(index_path.read_text()), json.loads(result_path.read_text())
        index["soak_rounds"] += 100; result["soak_rounds"] = index["soak_rounds"]
        index_path.unlink(); runtime.write_new(index_path, index)
        result["evidence_index"] = runtime.reference(index_path)
        result_path.unlink(); runtime.write_new(result_path, result)
        contexts = self.patches()
        with patch.object(runtime, "check_admission",
                          return_value=(self.plan, self.qualified, Path("/i"), Path("/q"))), \
             contexts[2], contexts[3], contexts[4], \
             patch.object(runtime, "qualification_identities", side_effect=lambda unused: []), \
             patch.object(runtime, "validate_record_timeline", return_value=0):
            with self.assertRaisesRegex(ValueError, "round count differs"):
                runtime.verify_result(result_path)

    def test_strict_json_and_admission_reject_ambiguous_extra_fields(self):
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"schema":1,"schema":1}\n')
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
            runtime.load(duplicate)
        bad = copy.deepcopy(self.admission); bad["production_override"] = True
        with patch.object(runtime.matrix, "source_records", return_value={}):
            with self.assertRaisesRegex(ValueError, "Malformed/stale"):
                runtime.check_admission(bad)

    def test_command_inventory_is_only_existing_exact_image_producers(self):
        # This inspects dispatch, not Android execution.  The selected names
        # and output route must remain those frozen by run_native_matrix.
        fake = {name: ["python", name, "--output", "/tmp/root/" + name]
                for name in runtime.STARTUPS}
        with patch.object(runtime.matrix, "commands", return_value=fake):
            for name in runtime.STARTUPS:
                self.assertIs(runtime.command_for({}, Path("/tmp/root"), name), fake[name])
            plan = {"image": {"image_id": self.admission["image_id"]},
                    "trees": {"product": {"path": "/product"}},
                    "files": {name: {"path": "/" + name} for name in
                              ("apk", "fixture_apk", "security_apk", "update_preparation")}}
            persistent = runtime.command_for(plan, Path("/tmp/root"), runtime.PERSISTENT_SOAK, 86400)
            self.assertIn("native_persistent_soak.py", persistent[1])
            self.assertEqual(persistent[persistent.index("--duration-seconds") + 1], "86400")
            with self.assertRaisesRegex(ValueError, "Unknown"):
                runtime.command_for({}, Path("/tmp/root"), "legacy")

    def test_parser_exposes_separate_bounded_startup_and_soak_timeouts(self):
        parser = runtime.argument_parser()
        required = ["run", "--inputs", "/inputs", "--qualification", "/qualification",
                    "--output", "/output", "--duration-seconds", "86400"]
        defaults = parser.parse_args(required)
        self.assertEqual(defaults.startup_timeout_seconds,
                         runtime.DEFAULT_STARTUP_TIMEOUT_SECONDS)
        self.assertEqual(defaults.soak_timeout_seconds, 0)
        explicit = parser.parse_args(required + ["--startup-timeout-seconds", "600",
                                                  "--soak-timeout-seconds", "90000"])
        self.assertEqual((explicit.startup_timeout_seconds, explicit.soak_timeout_seconds),
                         (600, 90000))
        with patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(required + ["--producer-timeout", "90000"])

    def test_campaign_dispatches_short_startup_and_long_soak_deadlines(self):
        observed = []

        def recording_runner(name, command, run_dir, log, image, timeout, sample):
            observed.append((name, timeout, sample))
            return self.fake_runner(name, command, run_dir, log, image, timeout, sample)

        value, _ = self.campaign(runner=recording_runner, startup_timeout=600,
                                 soak_timeout=14401)
        self.assertEqual(value["runtime_qualification"], "passed")
        self.assertEqual(observed, [(name, 600, 1) for name in runtime.STARTUPS] +
                                   [(runtime.PERSISTENT_SOAK, 14401, 1)])

    def test_timeout_validation_rejects_cross_lane_and_type_confusion(self):
        valid = (1, runtime.DEFAULT_STARTUP_TIMEOUT_SECONDS,
                 1 + runtime.SOAK_TIMEOUT_GRACE_SECONDS, 15)
        runtime.validate_producer_timeouts(*valid)
        invalid = [
            (1, runtime.MIN_PRODUCER_TIMEOUT_SECONDS - 1, valid[2], 15),
            (1, runtime.MAX_STARTUP_TIMEOUT_SECONDS + 1, valid[2], 15),
            (runtime.PRODUCTION_SECONDS, 600, runtime.PRODUCTION_SECONDS - 1, 15),
            (1, 600, 1 + runtime.SOAK_TIMEOUT_GRACE_SECONDS + 1, 15),
            (1, True, valid[2], 15),
            (1, 600, True, 15),
            (1, 600, valid[2], True),
        ]
        for arguments in invalid:
            with self.subTest(arguments=arguments), \
                 self.assertRaisesRegex(ValueError, "timeout or sample interval"):
                runtime.validate_producer_timeouts(*arguments)

    def test_admission_binds_verify_qualification_source_without_comparing_its_wrapper_field(self):
        product = self.root / "product"; product.mkdir()
        plan = {"trees": {"product": {"path": str(product)}},
                "image": {"image_id": self.admission["image_id"]},
                "files": {"apk": {"sha256": "a" * 64}, "fixture_apk": {"sha256": "f" * 64}}}
        inputs = self.root / "inputs.json"; runtime.write_new(inputs, plan)
        recorded = {"candidate_runtime": {"image_id": self.admission["image_id"]},
                    "artifact_sha256": {runtime.APP: "a" * 64, runtime.FIXTURE: "f" * 64}}
        qualification = self.root / "qualification.json"; runtime.write_new(qualification, recorded)
        admitted = {**self.admission, "inputs": runtime.reference(inputs),
                    "qualification": runtime.reference(qualification), "source_sha256": {}}
        verified = {**recorded, "qualification_source": runtime.reference(qualification)}
        with patch.object(runtime.matrix, "source_records", return_value={}), \
             patch.object(runtime.matrix, "check_inputs"), \
             patch.object(runtime, "verify_qualification", return_value=verified):
            actual, qualified, _, _ = runtime.check_admission(admitted)
            self.assertEqual(actual, plan); self.assertEqual(qualified, verified)
            bad = copy.deepcopy(verified); bad["qualification_source"] = {"path": "/wrong", "sha256": "0" * 64}
            with patch.object(runtime, "verify_qualification", return_value=bad), \
                 self.assertRaisesRegex(ValueError, "candidate drift"):
                runtime.check_admission(admitted)

    def test_persistent_report_rejects_fake_time_unauthorized_epoch_and_tamper(self):
        path, original = self.persistent_report()
        summary = persistent_acceptance.audit_report(path, expected_duration=1,
                                                      expected_image=self.admission["image_id"])
        self.assertEqual(summary["rounds"], 1)
        self.assertEqual(summary["boot_id"], original["boot_id"])

        truncated = copy.deepcopy(original)
        truncated["ended_monotonic_ns"] = truncated["started_monotonic_ns"] + 999_999_999
        truncated_path = path.parent / "truncated.json"
        runtime.write_new(truncated_path, truncated)
        with self.assertRaisesRegex(ValueError, "dual-clock duration"):
            persistent_acceptance.audit_report(truncated_path)

        unauthorized = copy.deepcopy(original)
        hotplug = unauthorized["rounds"][0]["scenarios"][0]
        hotplug["process_after"]["systemui"] = [dict(pid=999, start_ticks=999)]
        unauthorized_path = path.parent / "unauthorized.json"
        runtime.write_new(unauthorized_path, unauthorized)
        with self.assertRaisesRegex(ValueError, "without an exact restart journal"):
            persistent_acceptance.audit_report(unauthorized_path)

        target = path.parent / original["rounds"][0]["scenarios"][0]["evidence"]
        target.write_text(target.read_text() + "tampered\n")
        with self.assertRaisesRegex(ValueError, "Evidence bytes changed"):
            persistent_acceptance.audit_report(path)

    def test_persistent_loop_uses_monotonic_time_and_minimum_rounds(self):
        self.assertTrue(persistent_producer.should_continue(1_000_000_000, 86400, 3, 3,
                                                            86_400_999_999_999))
        self.assertFalse(persistent_producer.should_continue(1_000_000_000, 86400, 3, 3,
                                                             86_401_000_000_000))
        self.assertTrue(persistent_producer.should_continue(1_000_000_000, 1, 2, 3,
                                                            9_000_000_000))
        with self.assertRaisesRegex(ValueError, "loop clock"):
            persistent_producer.should_continue(10, 1, 3, 3, 9)

    def test_persistent_producer_samples_phone_and_rejects_epoch_replacement(self):
        guest = object.__new__(persistent_producer.PersistentGuest)
        guest.phone_epoch = None
        epochs = {role: (index + 10, index + 100) for index, role in enumerate(persistent_acceptance.ROLES)}
        calls = []
        def shell(*command):
            calls.append(command)
            if command[0] == "pidof":
                role = next(role for role, name in persistent_producer.PROCESS_NAMES.items() if name == command[1])
                return str(epochs[role][0])
            pid = int(command[-1].split("/")[2])
            ticks = next(ticks for candidate, ticks in epochs.values() if candidate == pid)
            return f"{pid} (process) S " + " ".join(["1"] * 18 + [str(ticks)]) + "\n"
        guest.test = unittest.mock.Mock()
        guest.test.shell.side_effect = shell
        rows = guest.processes()
        self.assertEqual(set(rows), set(persistent_acceptance.ROLES))
        self.assertEqual(rows["phone"], [dict(zip(("pid", "start_ticks"), epochs["phone"]))])
        self.assertIn(("pidof", "com.android.phone"), calls)
        self.assertIn(("su", "0", "cat", f"/proc/{epochs['phone'][0]}/stat"), calls)
        self.assertEqual(guest.processes(), rows)
        pid, ticks = epochs["phone"]
        epochs["phone"] = (pid, ticks + 1)
        with self.assertRaisesRegex(ValueError, "com.android.phone changed"):
            guest.processes()
        guest.test.shell.side_effect = lambda *command: "" if command == ("pidof", "com.android.phone") else shell(*command)
        with self.assertRaisesRegex(ValueError, "Missing/ambiguous persistent process: phone"):
            guest.processes()

    def test_persistent_producer_rejects_unplanned_phone_scenario_restart(self):
        guest = object.__new__(persistent_producer.PersistentGuest)
        guest.guard = lambda: None
        guest.action = lambda name, detail: None
        guest.monotonic_ns = Clock(100)
        before = {role: [dict(pid=index + 1, start_ticks=index + 100)]
                  for index, role in enumerate(persistent_acceptance.ROLES)}
        after = copy.deepcopy(before); after["phone"][0]["start_ticks"] += 1
        guest.processes = unittest.mock.Mock(side_effect=[before, after])
        with self.assertRaisesRegex(ValueError, "Unexpected protected restart during hotplug: phone"):
            guest.scenario(1, "hotplug")

    def test_persistent_auditor_requires_phone_and_forbids_restart_journal(self):
        path, original = self.persistent_report()
        self.assertEqual(persistent_acceptance.audit_report(path)["rounds"], 1)
        cases = []
        missing = copy.deepcopy(original)
        del missing["baseline_checkpoint"]["processes"]["phone"]
        cases.append((missing, "Incomplete persistent protected-process inventory"))
        multiple = copy.deepcopy(original)
        multiple["baseline_checkpoint"]["processes"]["phone"].append(dict(pid=51, start_ticks=501))
        cases.append((multiple, "one com.android.phone"))
        restarted = copy.deepcopy(original)
        item = restarted["rounds"][0]["scenarios"][0]
        old = copy.deepcopy(item["process_before"]["phone"][0])
        new = dict(pid=old["pid"], start_ticks=old["start_ticks"] + 1)
        item["process_after"]["phone"] = [new]
        item["restarts"] = [dict(role="phone", monotonic_ns=item["ended_monotonic_ns"], before=old, after=new)]
        cases.append((restarted, "com.android.phone changed"))
        for index, (report, message) in enumerate(cases):
            with self.subTest(message=message):
                rejected = path.parent / f"phone-rejected-{index}.json"
                runtime.write_new(rejected, report)
                with self.assertRaisesRegex(ValueError, message):
                    persistent_acceptance.audit_report(rejected)

    def test_independent_persistent_health_rejects_even_authorized_phone_window(self):
        run = self.root / "phone-forged-window"; run.mkdir()
        path = self.health(run, runtime.PERSISTENT_SOAK, sample_count=4, span=4_000_000_000)
        health = json.loads(path.read_text()); summary = runtime.inspect_health(health, path.parent)
        semantic = self.semantic(health, 3)
        changed = copy.deepcopy(health)
        changed["samples"][2]["processes"]["phone"][0]["start_ticks"] += 1
        semantic["authorized_epoch_windows"] = [dict(role="phone",
            began_monotonic_ns=semantic["began_monotonic_ns"], ended_monotonic_ns=semantic["ended_monotonic_ns"])]
        with self.assertRaisesRegex(ValueError, "outside an intentional persistent scenario: phone"):
            runtime.audit_persistent_health(changed, summary, semantic)
        incomplete = copy.deepcopy(summary); del incomplete["epochs"]["phone"]
        with self.assertRaisesRegex(ValueError, "com.android.phone did not remain one epoch"):
            runtime.audit_persistent_health(health, incomplete, semantic)

    def test_persistent_checkpoint_fences_both_ends_of_settled_window(self):
        guest = object.__new__(persistent_producer.PersistentGuest)
        guest.evidence = self.root / "checkpoint-fence"; guest.evidence.mkdir()
        guest.boot_id = "11111111-1111-1111-1111-111111111111"
        guest.checkpoint_seconds = 40
        guest.monotonic_ns = Clock(100)
        guest.sleep = lambda seconds: self.assertEqual(seconds, 40)
        guest.settle = lambda: {"monitors": [1]}
        guest.task_counts = unittest.mock.Mock(side_effect=[(3, 2, "before"), (3, 2, "after")])
        stable = {role: [dict(pid=index + 1, start_ticks=100 + index)]
                  for index, role in enumerate(persistent_acceptance.ROLES)}
        guest.processes = unittest.mock.Mock(side_effect=[copy.deepcopy(stable), copy.deepcopy(stable)])
        checkpoint = guest.checkpoint(0)
        self.assertEqual(checkpoint["processes"], stable)
        raw = json.loads((guest.evidence / "round-000000-checkpoint.json").read_text())
        self.assertEqual((raw["activities_before"], raw["activities_after"]), ("before", "after"))

        changed = copy.deepcopy(stable)
        changed["wonad"][0]["start_ticks"] += 1
        guest.monotonic_ns = Clock(100)
        guest.task_counts = unittest.mock.Mock(side_effect=[(3, 2, "before"), (3, 2, "after")])
        guest.processes = unittest.mock.Mock(side_effect=[copy.deepcopy(stable), changed])
        with self.assertRaisesRegex(ValueError, "changed during settled checkpoint"):
            guest.checkpoint(1)

    def test_persistent_health_rejects_epoch_outside_window_and_cumulative_residual(self):
        run = self.root / "persistent-health"; run.mkdir()
        path = self.health(run, runtime.PERSISTENT_SOAK, sample_count=4, span=4_000_000_000)
        health = json.loads(path.read_text()); summary = runtime.inspect_health(health, path.parent)
        semantic = self.semantic(health, 3)
        accepted = runtime.audit_persistent_health(health, summary, semantic)
        self.assertEqual(len(accepted["checkpoint_samples"]), 4)

        missing_crash = copy.deepcopy(summary)
        missing_crash["protected_events"] = missing_crash["protected_events"][:-1]
        with self.assertRaisesRegex(ValueError, "crash/ANR count"):
            runtime.audit_persistent_health(health, missing_crash, semantic)

        changed = copy.deepcopy(health)
        changed["samples"][2]["processes"]["systemui"][0].update(pid=999, start_ticks=999)
        with self.assertRaisesRegex(ValueError, "outside an intentional"):
            runtime.audit_persistent_health(changed, summary, semantic)

        growing = copy.deepcopy(health)
        growing["samples"][-1]["processes"]["wonad"][0]["fd_count"] += \
            runtime.HEALTH_POLICY["maximum_cumulative_fd_residual"] + 1
        with self.assertRaisesRegex(ValueError, "cumulative FD/RSS"):
            runtime.audit_persistent_health(growing, summary, semantic)

    def test_output_writer_never_overwrites_evidence(self):
        path = self.root / "sealed.json"
        runtime.write_new(path, {"first": True})
        with self.assertRaises(FileExistsError):
            runtime.write_new(path, {"second": True})
        self.assertEqual(json.loads(path.read_text()), {"first": True})


if __name__ == "__main__":
    unittest.main()
