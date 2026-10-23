#!/usr/bin/env python3
"""Original raw audit of the implemented hotplug/sampler slice, NOT a full soak."""
from pathlib import Path
import json

import phase1_conformance_clean_boot as lane
import phase1_conformance_soak_contract as contract
import phase1_conformance_soak_sampler as sampling
import phase1_conformance_soak_health_acceptance as health_audit
import phase1_conformance_recents_guest_acceptance as owned_audit
from phase1_conformance_common import canonical, file_ref, load, validate_manifest
import phase1_conformance_observations as observations

KIND = "phase1_policy_free_soak_populated_hotplug_slice_v1"
SCOPE = "one_authenticated_fresh_conformance_guest_continuous_raw_health_twenty_populated_three_monitor_cycles"
STATUS = "passed_bounded_hotplug_health_slice_not_whole_campaign"
require = lane.require


def audit_sampler(directory, report, child_window, stages):
    root = directory / "sampler"
    value = load(root / "sampler.json")
    require(value == report["sampler"] and value["status"] == "passed_bounded_sampler_not_24h" and
        value["observer"] == sampling.health.OBSERVER and type(value["interval_seconds"]) is int and 1 <= value["interval_seconds"] <= 300,
        "Sampler original status/observer differs or failed")
    identity = value["identity"]
    state = report["prelaunch_state"]["state"]
    outer_trace = load(directory / "commands.json")
    launch = next(row["argv"] for row in outer_trace if row.get("argv", [])[:3] == ["docker", "run", "-d"])
    running = [json.loads(row["output"])[0] for row in outer_trace if row.get("argv") ==
        ["docker", "container", "inspect", report["container_id"]] and json.loads(row["output"])[0]["State"]["Running"] is True]
    require(running and all(type(info["State"].get("Pid")) is int and info["State"]["Pid"] > 0 and
        info["State"]["Pid"] == running[0]["State"]["Pid"] for info in running), "Original container PID changed before/during slice")
    require(identity == {"container_id": report["container_id"], "image_id": report["image_id"],
        "container_run": report["container_run"], "boot_id": report["boot_id"], "fingerprint": report["fingerprint"],
        "userdata_path": str(directory / "emulator-state"), "user": str(state["uid"]) + ":" + str(state["gid"]),
        "container_pid": running[0]["State"]["Pid"], "kvm_group": launch[launch.index("--group-add") + 1]},
        "Continuous sampler did not observe the actual fresh guest")
    trace = load(root / "commands.json")
    require(isinstance(trace, list) and trace and [row["sequence"] for row in trace] == list(range(len(trace))), "Lost sampler raw journal")
    lo, hi = child_window
    prior, used = 0, set()
    for row in trace:
        require(row["kind"] == "command" and row["returncode"] == 0 and
            lo <= row["started_monotonic_ns"] <= row["ended_monotonic_ns"] <= hi and prior <= row["started_monotonic_ns"],
            "Unsuccessful/interleaved/escaped sampler command")
        prior = row["ended_monotonic_ns"]
    samples, actual_files = [], set()
    attempts = value["attempts"]
    require(len(attempts) >= 2 and all(type(row["ordinal"]) is int and row["ordinal"] > 0 for row in attempts) and
        [row["ordinal"] for row in attempts] == list(range(1, len(attempts) + 1)),
        "Missing continuous sampler attempts/coverage")
    for attempt in attempts:
        ordinal = attempt["ordinal"]
        require(attempt["status"] == "passed_raw_health_observation" and attempt["error"] is None,
            "Failed health attempt cannot be counted or omitted")
        started = f"attempt-{ordinal:06d}-started.json"; ended = f"attempt-{ordinal:06d}-ended.json"
        require(load(root / started) == {"ordinal": ordinal, "began_monotonic_ns": attempt["began_monotonic_ns"]} and
            load(root / ended) == attempt, "Original sampler attempt records differ")
        sample_path = root / attempt["sample"]
        require(attempt["sample"] == f"sample-{ordinal:06d}.json" and file_ref(sample_path) == attempt["sample_ref"], "Sample summary seal changed")
        sample = health_audit.audit_sample(root, load(sample_path), trace)
        require(type(sample["ordinal"]) is int and sample["ordinal"] > 0, "Sample ordinal must be a positive exact integer")
        require(0 < sample["ended_monotonic_ns"] - sample["began_monotonic_ns"] <= contract.HEALTH_POLICY["maximum_sample_collection_ns"] and
            abs((sample["ended_monotonic_ns"] - sample["began_monotonic_ns"]) -
                (sample["ended_realtime_ns"] - sample["began_realtime_ns"])) <= contract.HEALTH_POLICY["maximum_sample_clock_divergence_ns"],
            "Sample collection/dual-clock consistency changed")
        require(sample["ordinal"] == ordinal and sample["boot_id"] == identity["boot_id"] and
            sample["container_id"] == identity["container_id"] and sample["image_id"] == identity["image_id"] and
            value["began_monotonic_ns"] <= attempt["began_monotonic_ns"] <= sample["began_monotonic_ns"] <=
            sample["ended_monotonic_ns"] <= attempt["ended_monotonic_ns"] <= value["ended_monotonic_ns"],
            "Sample/attempt edge does not bind this sampler lifetime")
        indices = [record["trace_index"] for record in sample["files"].values()]
        require(not used.intersection(indices), "One raw sampler read reused")
        used.update(indices)
        guard_index = min(indices) - 1
        guard = trace[guard_index]
        require(guard_index >= 0 and guard_index not in used and guard["argv"] == ["docker", "container", "inspect", identity["container_id"]] and
            guard["evidence"] == attempt["guard"] == f"guards/{ordinal:06d}.json" and
            guard["output_sha256"] == file_ref(root / attempt["guard"])["sha256"], "Sample lacks its exact original owned-container guard")
        infos = load(root / attempt["guard"])
        require(isinstance(infos, list) and len(infos) == 1, "Ambiguous original sampler guard")
        sampling.verify_owner(infos[0], identity); used.add(guard_index)
        actual_files.update({started, ended, attempt["sample"], attempt["guard"],
            *(record["path"] for record in sample["files"].values())})
        require(not health_audit.protected_events((root / sample["files"]["events"]["path"]).read_text()),
            "Unexpected core/phone/client/fixture crash or ANR during hotplug slice")
        samples.append(sample)
    require(used == set(range(len(trace))), "Unreviewed sampler command or omitted attempt")
    actual_files.update({"commands.json", "sampler.json"})
    require({str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()} == actual_files,
        "Unreferenced/failed/extra sampler raw files were omitted")
    policy = contract.HEALTH_POLICY
    runtime_trace = load(directory / "runtime/commands.json")
    stops = [row for row in runtime_trace if row.get("argv", [])[-1:] == ["stop"] and
        "runtime-command" in row.get("argv", [])]
    require(len(stops) == 1 and value["ended_monotonic_ns"] <= stops[0]["started_monotonic_ns"],
        "Sampler continued after normal conformance process retirement")
    require(lo <= value["began_monotonic_ns"] < value["ended_monotonic_ns"] <= hi and
        value["began_monotonic_ns"] <= stages[0]["started_monotonic_ns"] and
        stages[-1]["ended_monotonic_ns"] <= value["ended_monotonic_ns"] and
        samples[0]["began_monotonic_ns"] - value["began_monotonic_ns"] <= policy["maximum_sample_edge_ns"] and
        value["ended_monotonic_ns"] - samples[-1]["ended_monotonic_ns"] <= policy["maximum_sample_edge_ns"] and
        samples[-1]["ended_monotonic_ns"] - samples[0]["began_monotonic_ns"] >= policy["minimum_stable_span_ns"],
        "Continuous sampler misses action edges/held-runtime lifetime")
    baseline = samples[0]
    epochs = {role: {key: row[key] for key in ("pid", "start_ticks")} for role, row in baseline["processes"].items()}
    for index, sample in enumerate(samples):
        require({role: {key: row[key] for key in ("pid", "start_ticks")} for role, row in sample["processes"].items()} == epochs and
            sample["modem_port"] == baseline["modem_port"] and sample["radio_services"] == baseline["radio_services"],
            "Protected process/radio identity changed during hotplug-only slice")
        require(index == 0 or samples[index - 1]["ended_monotonic_ns"] <= sample["began_monotonic_ns"] and
            sample["began_monotonic_ns"] - samples[index - 1]["ended_monotonic_ns"] <= policy["maximum_sample_gap_ns"], "Unobserved continuous health gap")
        for role, metric in sample["processes"].items():
            require(metric["fd_count"] - baseline["processes"][role]["fd_count"] <= policy["maximum_fd_growth_per_incarnation"] and
                metric["rss_kib"] - baseline["processes"][role]["rss_kib"] <= policy["maximum_rss_growth_kib_per_incarnation"],
                "Intermediate FD/RSS growth exceeds original per-epoch bound")
        require(sample["counts"]["tasks"] - baseline["counts"]["tasks"] <= 12 and
            sample["counts"]["roots"] - baseline["counts"]["roots"] <= 8, "Intermediate native task/root growth exceeds original bound")
    expected_core = {"system_server": "system_server", "systemui": "com.android.systemui",
        "launcher": "com.android.launcher3", "phone": "com.android.phone"}
    require(all(epochs[role] == report["before"]["protected_processes"][name] for role, name in expected_core.items()),
        "Sampler epoch differs from actual pre/post fresh-guest baseline")
    require(all(epochs[role] == {key: phase["processes"][name][key] for key in ("pid", "start_ticks")}
        for phase in report["stages"] for role, name in contract.PROCESS_NAMES.items()),
        "Sampler epoch differs from exact held conformance action epochs")
    return {"samples": len(samples), "runtime_qualified": False, "whole_campaign_complete": False}


def audit_report(path):
    import phase1_conformance_soak_hotplug_slice as producer
    path = Path(path).absolute(); require(path.resolve(strict=True) == path and not path.is_symlink(), "Literal original report required")
    directory = path.parent; report = load(path)
    require(report["kind"] == KIND and report["scope"] == SCOPE and report["status"] == STATUS and
        report["runtime_qualified"] is False and report["qualification_claimed"] is False and report["whole_campaign_complete"] is False and
        report["required_campaign_seconds"] == 86400 and report["required_minimum_rounds"] == 3 and
        report["required_scenarios"] == list(contract.SCENARIOS) and report["implemented_scenarios"] == ["hotplug"] and
        report["boot_count"] == 1 and report["cycles"] == 20 and report["container_stopped"] is True and
        not (directory / "failure.json").exists(), "Not a complete bounded slice; whole-soak substitution forbidden")
    require(0 < report["ended_monotonic_ns"] - report["started_monotonic_ns"] <= lane.acceptance.MAX_BOOT_NS, "Slice exceeds original bounded boot")
    files = report["evidence_files"]
    contexts = [(directory, load(directory / "commands.json"), True),
                (directory / "runtime", load(directory / "runtime/commands.json"), False),
                (directory / "sampler", load(directory / "sampler/commands.json"), False)]
    require(all(not target.is_symlink() and (target.is_file() or target.is_dir()) for target in directory.rglob("*")),
        "Unexpected special/symlinked original slice evidence")
    require({str(target.relative_to(directory)) for target in directory.rglob("*") if target.is_file() and target != path} == set(files),
        "Slice raw file inventory omitted original attempts/extra evidence")
    for relative, record in files.items():
        target = directory / relative
        require(not target.is_symlink() and target.resolve(strict=True).is_relative_to(directory) and
                observations.reference_equal(observations.inventory_ref(target, directory, contexts, report["container_id"]), record), "Original evidence bytes/path changed")
    manifest = load(directory / "image-manifest.json"); validate_manifest(manifest)
    require(manifest["product_apk_present"] is False, "Product policy admitted")
    before, after = report["before"], report["after"]
    require(before["boot_id"] == after["boot_id"] == report["boot_id"] and before["protected_processes"] == after["protected_processes"] and
        set(before["protected_processes"]) == set(lane.acceptance.OS_NAMES) and before["os_artifacts"] == after["os_artifacts"] == manifest["os_artifacts"] and
        before["installed"] == after["installed"], "Actual core/phone/OS/client artifacts drifted")
    frozen = load(directory / "contract-before.json")
    require(report["contract"] == frozen == producer.input_contract(report["image_id"], Path(report["product"]),
        Path(report["packet"]), report["packet_receipt_sha256"]), "Authenticated source/SDK/client/tool contract changed")
    lane.acceptance.validate_source_bindings(directory, report, manifest)
    prelaunch = load(directory / "prelaunch-userdata.json")
    expected = {"runner": lane.fresh.source_identity(Path(producer.__file__).resolve()),
        "guest_common": lane.fresh.source_identity(Path(lane.fresh.__file__).resolve())}
    require(prelaunch == report["prelaunch_state"] and prelaunch["authority"] == report["authority"] == expected, "Actual fresh wrapper authority differs")
    lane.fresh.validate_prelaunch_userdata(prelaunch, directory / "prelaunch-userdata.json", directory / "emulator-state", expected)
    owned = owned_audit._command_trace(directory / "commands.json", report, directory, manifest, before, after, prelaunch)
    lane.acceptance.validate_runtime_trace(directory / "runtime", report, owned["child_window"])
    lane.raw_audit.instrumentation_success((directory / "runtime/identity/instrumentation.txt").read_text(), report["conformance_run"])
    parsed = [lane.acceptance.parse_stage(directory / "runtime", row, report["runtime_evidence"], report["uids"]) for row in report["stages"]]
    semantic = lane.acceptance.audit_phases(parsed)
    observed = audit_sampler(directory, report, owned["child_window"], report["stages"])
    return {"status": STATUS, "hotplug": semantic, "health": observed, "runtime_qualified": False, "whole_campaign_complete": False}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expected-report-sha256", required=True); args = parser.parse_args(argv)
    require(file_ref(args.report)["sha256"] == args.expected_report_sha256, "Original report digest changed")
    print(json.dumps(audit_report(args.report), sort_keys=True)); return 0


if __name__ == "__main__": raise SystemExit(main())
