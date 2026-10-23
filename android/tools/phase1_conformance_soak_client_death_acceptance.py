#!/usr/bin/env python3
"""Independent raw client-death attachment audit; never whole-campaign PASS."""
from pathlib import Path
from phase1_conformance_installed_path import installed_apk_path
from io import BytesIO
import json
import re
from PIL import Image

import phase1_conformance_soak_lock_user_acceptance as attached
import phase1_conformance_soak_frozen_client_acceptance as shields
from phase1_conformance_common import file_ref, load

runtime, health, lane = attached.runtime, attached.health, attached.lane
require = runtime.require
KIND = "phase1_policy_free_client_death_attachment_action_v1"
STATUS = "passed_bounded_original_client_death_NOT_whole_campaign"
FAILED = "failed_bounded_client_death_not_qualified"


def observed_ref(path, trace, root, container):
    path, root = attached.observations.canonical_path(path, root)
    if path.stat().st_size: return file_ref(path)
    relative = str(path.relative_to(root)); rows = [row for row in trace if row.get("evidence") == relative]
    if len(rows) == 1 and rows[0].get("argv") == ["docker", "exec", container, "adb", "-s", "emulator-5580", "shell", "pidof", runtime.PACKAGE]:
        row = rows[0]
        require(row.get("kind") == "command" and type(row.get("returncode")) is int and row["returncode"] == 1 and
            row.get("output_sha256") == attached.observations.EMPTY_SHA256, "Empty client absence is not exact failed pidof")
        return attached.observations.empty_ref(path)
    return attached.observed_ref(path, trace, root, container)


def command(root, trace, action, relative, args, *, allowed=0, window=None):
    root = Path(root); target, _root = attached.observations.canonical_path(root / relative, root)
    require(action['scenario'] in {'client_death', 'malformed_calls'}, 'Unreviewed raw death component scenario')
    prefix = f"soak-actions/{action['ordinal']:06d}-{action['scenario']}-{action['nonce']}/"
    require(relative.startswith(prefix), "Foreign client-death observation path")
    rows = [row for row in trace if row.get("evidence") == relative]
    shell = ["docker", "exec", action["identity"]["container_id"], "adb", "-s", "emulator-5580", "shell"]
    require(len(rows) == 1 and rows[0]["kind"] == "command" and type(rows[0]["returncode"]) is int and
        rows[0]["returncode"] == allowed and rows[0]["argv"] == shell + list(map(str, args)) and
        rows[0]["output_sha256"] == observed_ref(target, trace, root, action["identity"]["container_id"])["sha256"],
        "Unbound actual client-death raw command")
    row = rows[0]
    if window:
        require(window["trace_start"] <= row["sequence"] < window["trace_end"] and
            window["began_monotonic_ns"] <= row["started_monotonic_ns"] <= row["ended_monotonic_ns"] <= window["ended_monotonic_ns"],
            "Raw observation escaped exact capture window")
    return target.read_text()


def absence(root, row, action, trace):
    require(set(row["files"]) == {"uid", "pid_before", "ps_before", "pid_after", "ps_after"} and
        type(row["trace_start"]) is int and row["trace_end"] == row["trace_start"] + 5, "Incomplete actual client absence fence")
    uid = attached.package_uid(command(root, trace, action, row["files"]["uid"],
        ("pm", "list", "packages", "-U", "--user", "0", runtime.PACKAGE)), runtime.PACKAGE, 0)
    require(uid == action["uids"][runtime.PACKAGE], "Absence changed authoritative client UID")
    for key in ("pid_before", "pid_after"):
        require(command(root, trace, action, row["files"][key], ("pidof", runtime.PACKAGE), allowed=1) == "",
            "Client absence requires exact exit1/zero-byte pidof, not a guessed missing PID")
    for key in ("ps_before", "ps_after"):
        raw = command(root, trace, action, row["files"][key], health.PROCESS_TABLE_COMMAND)
        lines = raw.splitlines(); require(lines and lines[0].split() == ["UID", "PID", "NAME"], "Malformed numeric process table")
        seen = set()
        for line in lines[1:]:
            match = re.fullmatch(r"\s*([0-9]+)\s+([1-9][0-9]*)\s+(\S+)\s*", line)
            require(match is not None and int(match[2]) not in seen, "Ambiguous process-table absence")
            seen.add(int(match[2]))
            require(int(match[1]) != uid and match[3] != runtime.PACKAGE, "Client or admitted UID remains present during claimed absence")
    sequences = [next(item["sequence"] for item in trace if item.get("evidence") == row["files"][key])
        for key in ("uid", "pid_before", "ps_before", "pid_after", "ps_after")]
    require(sequences == list(range(row["trace_start"], row["trace_end"])), "Reordered actual absence PID/table fence")
    return uid


def dead_instrumentation(raw):
    results = [line.strip() for line in raw.splitlines() if "INSTRUMENTATION_RESULT:" in line]
    codes = [line.strip() for line in raw.splitlines() if "INSTRUMENTATION_CODE:" in line]
    require(results == ["INSTRUMENTATION_RESULT: shortMsg=Process crashed."] and codes == ["INSTRUMENTATION_CODE: 0"] and
        not any(runtime.STATUS_MARKER in line or "INSTRUMENTATION_FAILED:" in line for line in raw.splitlines()),
        "Owned old instrumentation did not report actual Android target death")


def parse_absent_capture(root, row, action, trace):
    import phase1_conformance_soak_client_death_action as producer
    require(row["runtime_status_observed"] is False and row["user"] == 0 and set(row["files"]) == set(producer.ABSENT_COMMANDS),
        "Dead client status cannot be queried/fabricated")
    absence(root, row["absence_before"], action, trace); absence(root, row["absence_after"], action, trace)
    require(row["trace_start"] <= row["absence_before"]["trace_start"] < row["absence_before"]["trace_end"] <=
        row["absence_after"]["trace_start"] < row["absence_after"]["trace_end"] == row["trace_end"], "Absent scene lacks outer process absence fences")
    raw = {key: command(root, trace, action, relative, producer.ABSENT_COMMANDS[key], window=row) for key, relative in row["files"].items()}
    require(raw["current_user"].strip() == "0" and raw["boot"].strip() == action["identity"]["boot_id"] and
        not attached.health_audit.protected_events(raw["events"]) and not lane.acceptance.crash_events(raw["events"]), "Foreign boot/user or real crash/ANR")
    require(set(row["processes"]) == set(health.contract.PROCESS_NAMES) - {"client"}, "Every OTHER four roles remain mandatory; no fake dead metric")
    processes = {}
    for role, metric in row["processes"].items():
        package = health.contract.PROCESS_NAMES[role]
        uid = 1000 if role == "system_server" else attached.package_uid(command(root, trace, action, metric["package_uid"],
            ("pm", "list", "packages", "-U", "--user", "0", package), window=row), package, 0)
        require(set(metric["files"]) == set(producer.FIELDS), "Missing/extra protected process fence")
        values = {}
        for key in producer.FIELDS:
            args = ("pidof", package) if key.startswith("pid") else health.PROCESS_TABLE_COMMAND if key.startswith("ps") else (
                "su", "0", *(("ls", "-1") if key == "fd" else ("cat",)), f"/proc/{metric['pid']}/" + ("stat" if key in ("stat_before", "stat_after") else key))
            values[key] = command(root, trace, action, metric["files"][key], args, window=row)
        sequences = [next(item["sequence"] for item in trace if item.get("evidence") == metric["files"][key]) for key in producer.FIELDS]
        require(sequences == list(range(sequences[0], sequences[0] + 8)), "Reordered protected OS fence")
        actual = attached.process_metric(values, uid, package)
        require(actual == {key: metric[key] for key in actual}, "Protected metric differs from original bytes")
        processes[role] = actual
    require(len({value["pid"] for value in processes.values()}) == 4, "Protected OS roles share PID")
    displays = lane.raw_audit.logical_displays(raw["display"])
    require({item["slot"] for item in displays.values()} == {1, 2, 3}, "Three exact mixed monitors mandatory")
    records, membership, identities = lane.acceptance.fixture_lifetimes(raw["fixture"], raw["activities"], action["uids"][lane.acceptance.FIXTURE])
    require(set(records) == set(lane.acceptance.COMPONENTS.values()), "Original populated Android tasks required")
    frames = {}; require(set(row["frames"]) == {"0", "1", "2", "3"}, "Phone plus three exact black frames required")
    offset = trace[0]["sequence"]
    for slot, relative in row["frames"].items():
        require(relative == f"soak-actions/{action['ordinal']:06d}-{action['scenario']}-{action['nonce']}/captures/{row['name']}/frame-{slot}.png", "Foreign absent frame path")
        lane.raw_audit.validate_frame_trace(trace, row["trace_start"] - offset, row["trace_end"] - offset, root,
            action["identity"]["container_id"], int(slot), relative)
        payload = (Path(root) / relative).read_bytes()
        display = 0 if slot == "0" else next(key for key, value in displays.items() if value["slot"] == int(slot))
        regions = {component: [record[key] for key in ("left", "top", "right", "bottom")]
            for component, record in records.items() if record["native_display"] == display}
        frame = lane.raw_audit.png_info(payload, regions)
        expected = (1080, 2400) if slot == "0" else lane.acceptance.SPECS[int(slot)][:2]
        require((frame["width"], frame["height"]) == expected, "Wrong actual absence frame dimensions")
        with Image.open(BytesIO(payload)) as image:
            extrema = image.convert("RGBA").getextrema()
            frame["opaque_black"] = extrema == ((0, 0), (0, 0), (0, 0), (255, 255))
            frame["rgb_nonblack"] = any(maximum > 0 for _minimum, maximum in extrema[:3])
        frames[int(slot)] = frame
    return {"row": row, "raw": raw, "status": None, "processes": processes, "records": records, "membership": membership,
        "identities": identities, "displays": displays, "frames": frames,
        "modem": health.phone.modem_port(raw["modem"]), "radio": health.phone.radio_services(raw["radio"])}


def audit_action(path, admitted_contract, admitted_identity, *, client_chain=None, client_uid=None):
    return audit_component(path, admitted_contract, admitted_identity, scenario='client_death', client_chain=client_chain, client_uid=client_uid)


def audit_component(path, admitted_contract, admitted_identity, *, scenario, client_chain=None, client_uid=None):
    import phase1_conformance_soak_client_death_action as producer
    require(scenario in {'client_death', 'malformed_calls'}, 'Unreviewed death component audit')
    probe_audit = None; probe = {'reads': set(), 'frames': set()}
    if scenario == 'malformed_calls':
        import phase1_conformance_soak_malformed_calls as producer
        import phase1_conformance_soak_malformed_calls_acceptance as probe_audit
    expected_kind, expected_status, expected_failed = (probe_audit.KIND, probe_audit.STATUS, probe_audit.FAILED) if probe_audit else (KIND, STATUS, FAILED)
    path = Path(path).absolute(); directory = path.parent; root = directory.parents[1]
    require(path.resolve(strict=True) == path and path.name == "attempt-ended.json", "Original literal client-death receipt required")
    action = load(path)
    require(type(action["schema"]) is int and action["schema"] == 1 and action["kind"] == expected_kind and action["scenario"] == scenario and action["status"] == expected_status and
        type(action["ordinal"]) is int and action["ordinal"] > 0 and runtime.HEX32.fullmatch(action["nonce"]) and
        action["identity"] == admitted_identity and action["contract"] == admitted_contract and action["sources"] == producer.source_contract() and
        action["runtime_qualified"] is False and action["whole_campaign_complete"] is False and action["sampler_stopped_by_action"] is False and
        action.get("error") is None, "Failed/foreign/source-drifted whole-campaign client-death claim")
    require(admitted_contract == producer.attached.admission.input_contract(admitted_identity["image_id"], Path(admitted_contract["product"]),
        Path(admitted_contract["packet"]), admitted_contract["packet_receipt"]["sha256"]), "Actual immutable source/image/packet admission changed")
    prefix = f"soak-actions/{action['ordinal']:06d}-{scenario}-{action['nonce']}"
    require(str(directory.relative_to(root)) == prefix and all(not target.is_symlink() and (target.is_file() or target.is_dir())
        for target in directory.rglob("*")), "Aliased original client-death evidence")
    trace = load(directory / "commands.json"); indexed = {row["sequence"]: row for row in trace}
    require(all(type(action[key]) is int for key in ("trace_start", "trace_end", "began_monotonic_ns", "ended_monotonic_ns")) and
        0 <= action["trace_start"] < action["trace_end"] and trace and
        [row["sequence"] for row in trace] == list(range(action["trace_start"], action["trace_end"])) and
        0 < action["ended_monotonic_ns"] - action["began_monotonic_ns"] <= producer.MAX_TRANSITION_NS, "Invalid bounded original journal")
    excluded = root / action["cleanup"]["owned_output"] if not Path(action["cleanup"]["owned_output"]).is_absolute() else Path(action["cleanup"]["owned_output"])
    require(excluded.resolve(strict=True) == directory / "new-worker/held-instrumentation.txt", "Unowned mutable new instrumentation output")
    require({str(target.relative_to(root)) for target in directory.rglob("*") if target.is_file() and target not in (path, excluded)} ==
        set(action["evidence"]), "Lost/extra original client-death evidence")
    for relative, ref in action["evidence"].items(): require(observed_ref(root / relative, trace, root, admitted_identity["container_id"]) == ref, "Original raw bytes changed")
    started = load(directory / "attempt-started.json")
    require(started["status"] == expected_failed and started["captures"] == [] and started["workers"] == [] and
        all(started[key] == action[key] for key in ("schema", "kind", "scenario", "ordinal", "nonce", "run", "identity", "contract", "sources", "uids", "began_monotonic_ns")),
        "Original started client-death attempt substituted")
    prior = action["began_monotonic_ns"]
    for row in trace:
        require(type(row["sequence"]) is int and type(row["started_monotonic_ns"]) is int and type(row["ended_monotonic_ns"]) is int and
            prior <= row["started_monotonic_ns"] <= row["ended_monotonic_ns"] <= action["ended_monotonic_ns"], "Interleaved/untyped original commands")
        prior = row["ended_monotonic_ns"]
        if row.get("evidence"): require(row["output_sha256"] == action["evidence"][row["evidence"]]["sha256"], "Command evidence hash changed")
    require([row["name"] for row in action["captures"]] == ["before", "inactive-0", "inactive-1", "inactive-2", "new-ready", "recovered", "delivered"],
        "All seven original live/absent/recovered stages mandatory")
    require(len(action["workers"]) == 2, "Exactly old and fresh self-target workers required")
    old, new = action["workers"]
    require(old["run"] == action["run"] and runtime.HEX32.fullmatch(old["run"]) and runtime.HEX32.fullmatch(old["nonce"]) and
        runtime.HEX32.fullmatch(new["run"]) and runtime.HEX32.fullmatch(new["nonce"]) and
        old["run"] != new["run"] and old["nonce"] != new["nonce"] and type(old["host_pid"]) is int and type(new["host_pid"]) is int and
        old["host_pid"] > 0 and new["host_pid"] > 0 and old["host_pid"] != new["host_pid"], "Reused/foreign instrumentation identity")
    scenes = []
    for index, row in enumerate(action["captures"]):
        require(all(type(row[key]) is int for key in ("trace_start", "trace_end", "began_monotonic_ns", "ended_monotonic_ns")) and
            action["trace_start"] <= row["trace_start"] < row["trace_end"] <= action["trace_end"] and
            action["began_monotonic_ns"] <= row["began_monotonic_ns"] <= row["ended_monotonic_ns"] <= action["ended_monotonic_ns"], "Invalid original capture window")
        for role, metric in row["processes"].items():
            require(all(type(metric[key]) is int and metric[key] > 0 for key in ("pid", "start_ticks", "uid", "rss_kib", "fd_count")) and
                set(metric["files"]) == set(producer.FIELDS) and (role != "system_server" or metric["package_uid"] is None),
                "Exact typed complete process metrics required")
        scenes.append(parse_absent_capture(root, row, action, trace) if index in (1, 2, 3) else
            attached.parse_capture(root, row, {**action, "run": old["run"] if index == 0 else new["run"]}, trace))
    before, ready, recovered, delivered = scenes[0], scenes[4], scenes[5], scenes[6]
    if probe_audit:
        probe = probe_audit.audit_probe(root, action, trace, before, admitted_contract, admitted_identity)
    for scene in (before, recovered, delivered): attached.ready(scene, action)
    for scene in scenes[1:4]: shields.shield(before, scene, action)
    original, replacement = before["processes"]["client"], ready["processes"]["client"]
    epoch = lambda metric: {key: metric[key] for key in ("pid", "start_ticks")}
    require(all(set(worker["epoch"]) == {"pid", "start_ticks"} and
        all(type(value) is int and value > 0 for value in worker["epoch"].values()) for worker in (old, new)), "Exact typed worker epochs required")
    require(old["epoch"] == epoch(original) and new["epoch"] == epoch(replacement) and old["epoch"] != new["epoch"] and
        original["uid"] == replacement["uid"] == action["uids"][runtime.PACKAGE], "Missing/reused/foreign actual worker epoch")
    for scene in scenes:
        require(scene["displays"] == before["displays"] and scene["identities"] == before["identities"] and
            scene["modem"] == before["modem"] and scene["radio"] == before["radio"], "Native task/display/radio lifetime changed")
        for role, metric in scene["processes"].items():
            base = original if role == "client" and scene is before else replacement if role == "client" else before["processes"][role]
            require(all(metric[key] == base[key] for key in ("pid", "start_ticks", "uid")) and
                metric["fd_count"] - base["fd_count"] <= 64 and metric["rss_kib"] - base["rss_kib"] <= 256 * 1024, "Nonclient protected epoch or resource changed")
        counts, initial = health.task_counts(scene["raw"]["activities"]), health.task_counts(before["raw"]["activities"])
        require(counts["tasks"] - initial["tasks"] <= 12 and counts["roots"] - initial["roots"] <= 8, "Native task/root growth exceeded")
    for scene, delta in ((recovered, 0), (delivered, 1)):
        attached.recovery_layout(before, scene)
        for component, record in scene["records"].items():
            previous = before["records"][component]
            require(all(record[key] == previous[key] for key in ("left", "top", "right", "bottom", "display", "native_display")) and
                all(record[key] == previous[key] + delta for key in ("key_downs", "pointer_downs", "mouse_downs")), "Recovered geometry/input delivery changed")
    shell = ["docker", "exec", admitted_identity["container_id"], "adb", "-s", "emulator-5580", "shell"]
    kill = action["kill_sequence"]
    require(type(kill) is int and indexed[kill]["argv"] == shell + ["su", "0", "kill", "-KILL", str(original["pid"])] and
        indexed[kill]["returncode"] == 0 and type(indexed[kill]["returncode"]) is int, "Death did not target exact old client")
    require(len(action["client_fences"]) == 1, "Exactly one immediately-before-kill client fence required")
    fence = action["client_fences"][0]
    require(fence["label"] == "before-kill" and fence["trace_end"] == kill and fence["trace_start"] == kill - 8 and
        set(fence["files"]) == set(producer.FIELDS), "Kill not immediately UID/PID/start fenced")
    values = {}
    for key in producer.FIELDS:
        args = ("pidof", runtime.PACKAGE) if key.startswith("pid") else health.PROCESS_TABLE_COMMAND if key.startswith("ps") else (
            "su", "0", *(("ls", "-1") if key == "fd" else ("cat",)), f"/proc/{original['pid']}/" + ("stat" if key in ("stat_before", "stat_after") else key))
        values[key] = command(root, trace, action, fence["files"][key], args)
    require([next(row["sequence"] for row in trace if row.get("evidence") == fence["files"][key]) for key in producer.FIELDS] ==
        list(range(kill - 8, kill)) and all(attached.process_metric(values, original["uid"], runtime.PACKAGE)[key] == original[key]
        for key in ("pid", "start_ticks", "uid")), "Old client signal epoch/UID changed")
    uidrow = indexed[kill - 9]
    require(uidrow["argv"] == shell + ["pm", "list", "packages", "-U", "--user", "0", runtime.PACKAGE] and
        attached.package_uid((root / uidrow["evidence"]).read_text(), runtime.PACKAGE, 0) == original["uid"], "Missing fresh authoritative signal UID")
    original_trace = load(directory / "original-runtime-trace.json")
    starts = [row for row in original_trace if row.get("kind") == "background_start" and row.get("id") == "instrumentation-" + old["run"]]
    prefix_argv = shell[:-1]
    require(len(starts) == 1 and starts[0]["sequence"] == old["start_sequence"] and starts[0]["argv"] == producer.workers.audit.runtime_argv(prefix_argv, old) and
        starts[0]["started_monotonic_ns"] == old["started_monotonic_ns"] < action["began_monotonic_ns"], "Original admitted runtime trace missing/foreign")
    adopts = [row for row in trace if row["kind"] == "background_adopt"]
    finishes = [row for row in trace if row["kind"] == "background_finish"]
    new_starts = [row for row in trace if row["kind"] == "background_start"]
    require(len(adopts) == len(finishes) == len(new_starts) == 1 and
        adopts[0]["argv"] == starts[0]["argv"] and adopts[0]["host_pid"] == old["host_pid"] and adopts[0]["output_original"] == old["output_original"] and
        finishes[0]["id"] == "instrumentation-" + old["run"] and finishes[0]["host_pid"] == old["host_pid"] and
        finishes[0]["cause"] == "exact_owned_client_KILL" and finishes[0]["returncode"] == 0 and finishes[0]["evidence"] == old["output"] and
        new_starts[0]["id"] == "instrumentation-" + new["run"] and new_starts[0]["host_pid"] == new["host_pid"] and
        new_starts[0]["argv"] == producer.workers.audit.runtime_argv(prefix_argv, new) and new_starts[0]["started_monotonic_ns"] == new["started_monotonic_ns"] and
        adopts[0]["sequence"] < before["row"]["trace_start"] < kill < finishes[0]["sequence"] < scenes[1]["row"]["trace_start"] and
        scenes[3]["row"]["trace_end"] <= new_starts[0]["sequence"] < ready["row"]["trace_start"], "Missing/reordered actual old terminal/new worker handles")
    dead_instrumentation((root / old["output"]).read_text())
    original_output, _root = attached.observations.canonical_path(root / old["output_original"], root)
    require(original_output.read_bytes() == (root / old["output"]).read_bytes(), "Original owned dead stream differs from retained terminal copy")
    require([item["label"] for item in action["absences"]] == ["dead-first"] + [f"inactive-{index}-{part}" for index in range(3) for part in ("before", "after")],
        "Exact seven independent client-absence fences required")
    for row in action["absences"]:
        absence(root, row, action, trace)
        require(kill < row["trace_start"] < row["trace_end"] <= new_starts[0]["sequence"], "Client absence outside real death/restart interval")
    first_ready_sequence = new["ready_sequence"] + action["trace_start"]
    first_ready_row = indexed[first_ready_sequence]
    require(first_ready_row["kind"] == "command" and first_ready_row["argv"] == shell + ["dumpsys", "activity", "service", runtime.SERVICE] and
        new_starts[0]["sequence"] < first_ready_sequence < ready["row"]["trace_start"], "New initial ready poll not actual/ordered")
    initial = runtime.parse_status(first_ready_row["output"])
    attached.service_owner(first_ready_row["output"], replacement["pid"])
    require(initial["snapshot"]["identity_epoch"] == before["status"]["snapshot"]["identity_epoch"] and
        initial["snapshot"]["generation"] > 0 and initial["snapshot"]["generation"] != before["status"]["snapshot"]["generation"],
        "Client restart changed system_server identityEpoch or reused generation")
    require(initial["run"] == new["run"] and initial["failure"] is None and initial["control_error"] is None and initial["state"] == "ready" and
        initial["runtime_readiness"] == {"ready": True, "session_open": True, "reopen_required": False} and
        initial["handshake"] == {"nonce": new["nonce"], "phase": "start", "result": "accepted"}, "New self-target nonce never genuinely ready")
    copy = action["copied_frame"]; copyrow, ackrow = indexed[copy["command_sequence"]], indexed[copy["ack_sequence"]]
    require(runtime.HEX32.fullmatch(copy["nonce"]) and copy["nonce"] != new["nonce"] and
        copyrow["argv"] == shell + ["dumpsys", "activity", "--user", "0", "service", runtime.SERVICE, "runtime-command", new["run"], copy["nonce"], "copy-observed"] and
        ready["row"]["trace_end"] <= copyrow["sequence"] < ackrow["sequence"] < recovered["row"]["trace_start"], "Missing/extraneous current-token copy command")
    attached.require_control_marker(copyrow["output"], runtime.CONTROL_MARKER + f"accepted {new['run']} {copy['nonce']} copy-observed")
    copied = runtime.parse_status((root / ackrow["evidence"]).read_text())
    require(copied == copy["status"] and copied["run"] == new["run"] and copied["failure"] is None and copied["control_error"] is None and
        copied["state"] == "ready" and copied["handshake"] == {"nonce": copy["nonce"], "phase": "copy-observed", "result": "accepted"} and
        copied["callbacks"]["onResult"] == initial["callbacks"]["onResult"] + 1, "Actual copied-frame RESULT_APPLIED acknowledgement missing")
    for value in (ready["status"], copied, recovered["status"], delivered["status"]):
        require(all(value["snapshot"][key] == initial["snapshot"][key] for key in ("generation", "identity_epoch")) and
            value["snapshot"]["revision"] >= initial["snapshot"]["revision"] and value["callbacks"]["onRevoked"] == 0,
            "Fresh current authority changed or fabricated dead-worker callback")
        require({key: task["token"] for key, task in attached.descriptive_tasks(value["snapshot"]).items()} ==
            {key: task["token"] for key, task in attached.descriptive_tasks(initial["snapshot"]).items()} and
            {row["identity_hint"]: row["token"] for row in value["snapshot"]["display_incarnations"]} ==
            {row["identity_hint"]: row["token"] for row in initial["snapshot"]["display_incarnations"]}, "Substituted old/foreign copy authority")
    for index, scene in enumerate(scenes[1:4]):
        low = kill + 1 if index == 0 else scenes[index]["row"]["trace_end"]
        actual = [row["argv"][len(shell):] for row in trace if low <= row["sequence"] < scene["row"]["trace_start"] and row.get("argv", [])[:len(shell)] == shell and row["argv"][len(shell):][:1] == ["input"]]
        expected = []
        for component, record in before["records"].items():
            expected += [["input", "keyboard", "-d", str(record["native_display"]), "keyevent", "KEYCODE_B"],
                ["input", "mouse", "-d", str(record["native_display"]), "tap", str((record["left"] + record["right"]) // 2), str((record["top"] + record["bottom"]) // 2)]]
        require(actual == expected, "Missing/reordered actual dead-client input challenges")
    client = producer.attached.current_client.audit_action(root, action, trace, admitted_contract, admitted_identity,
        client_chain=client_chain, client_uid=client_uid, defer_command_scan=True)
    member = client["selection"]["member"]
    installed_commands = set(client["sequences"]); privileges = []
    require(len(action["installed"]) == 2, "Exact before/recovered APK bytes required")
    for install in action["installed"]:
        require(set(install) == {"path", "dump", "apk"}, "Incomplete installed APK proof")
        pm = command(root, trace, action, install["path"], ("pm", "path", "--user", "0", runtime.PACKAGE))
        path = installed_apk_path(pm, runtime.PACKAGE, package_row=True)
        privileges.append(producer.workers.audit.installed_package(command(root, trace, action, install["dump"], ("dumpsys", "package", runtime.PACKAGE)), original["uid"], member["version_code"]))
        rows = [row for row in trace if row.get("evidence") == install["apk"]]
        require(len(rows) == 1 and rows[0]["argv"] == prefix_argv + ["exec-out", "cat", path] and rows[0]["returncode"] == 0 and
            file_ref(root / install["apk"]) == member["artifact"], "Actual same admitted APK bytes changed")
        installed_commands.update(next(row["sequence"] for row in trace if row.get("evidence") == relative) for relative in install.values())
    require(privileges[0] == privileges[1], "Installed client privilege state changed")
    require(load(root / action["recovered_stage_relative"]) == recovered["row"] and action["recovered_stage_relative"] == prefix + "/recovered-stage.json", "Provisional recovery stage substituted")
    first_epoch_row = next(row for row in trace if row.get("evidence") == ready["row"]["processes"]["client"]["files"]["ps_after"])
    require(all(type(action[key]) is int for key in ("transition_started_monotonic_ns", "transition_ended_monotonic_ns", "absent_end_monotonic_ns")) and
        runtime.HEX32.fullmatch(action["permit_id"]) and action["began_monotonic_ns"] <= action["transition_started_monotonic_ns"] <=
        indexed[kill]["started_monotonic_ns"] <= indexed[kill]["ended_monotonic_ns"] < action["absent_end_monotonic_ns"] == first_epoch_row["ended_monotonic_ns"] <=
        recovered["row"]["ended_monotonic_ns"] <= action["transition_ended_monotonic_ns"] <= action["transition_started_monotonic_ns"] + producer.MAX_TRANSITION_NS,
        "Untyped/broad/unbounded replacement clocks")
    # Complete command consumption. Exact capture/fence/absence raw reads were
    # re-derived above; no generic su, dumpsys, package or signal whitelist.
    bound_reads = {relative for scene in action["captures"] for relative in scene["files"].values()}
    bound_reads.update(relative for scene in action["captures"] for metric in scene["processes"].values()
        for relative in ([metric["package_uid"]] if metric["package_uid"] else []) + list(metric["files"].values()))
    bound_reads.update(fence["files"].values()); bound_reads.add(uidrow["evidence"])
    bound_reads.update(relative for item in action["absences"] for relative in item["files"].values())
    bound_reads.update(probe['reads'])
    frame_sequences = set()
    for scene in action["captures"]:
        rows = trace[scene["trace_start"] - action["trace_start"]:scene["trace_end"] - action["trace_start"]]
        for frame in scene["frames"].values():
            index = next(index for index, row in enumerate(rows) if row.get("evidence") == frame)
            frame_sequences.update(row["sequence"] for row in (rows[index:index+1] if frame.endswith("frame-0.png") else rows[index-3:index+2]))
    frame_sequences.update(probe['frames'])
    for row in trace:
        sequence, argv = row["sequence"], row.get("argv", [])
        if row["kind"] in {"background_start", "background_finish", "background_adopt"}: continue
        absence_pid_files = {item["files"][key] for item in action["absences"] for key in ("pid_before", "pid_after")}
        require(row["kind"] == "command" and type(row.get("returncode")) is int and
            row["returncode"] == (1 if row.get("evidence") in absence_pid_files else 0), "Failed or unreviewed original action command")
        args = argv[len(shell):] if argv[:len(shell)] == shell else None
        if row.get("evidence") in bound_reads or sequence in frame_sequences or sequence in installed_commands or sequence == kill or sequence in probe.get('commands', set()): continue
        if argv == ["docker", "container", "inspect", admitted_identity["container_id"]]:
            values = json.loads(row["output"]); require(len(values) == 1, "Ambiguous original owner")
            producer.attached.sampler.verify_owner(values[0], admitted_identity)
        elif args in (["cat", "/proc/sys/kernel/random/boot_id"], ["am", "get-current-user"]):
            require(row.get("evidence") and (root / row["evidence"]).read_text().strip() ==
                (admitted_identity["boot_id"] if args[0] == "cat" else "0"), "Owner guard changed")
        elif args in (["dumpsys", "activity", "service", runtime.SERVICE], ["dumpsys", "activity", "--user", "0", "service", runtime.SERVICE]):
            require(sequence > new_starts[0]["sequence"], "Dead service was queried/fabricated")
            raw = (root / row["evidence"]).read_text() if row.get("evidence") else row["output"]
            attached.require_poll_expectation_marker(raw); value = runtime.parse_status(raw)
            require(value["run"] == new["run"] and value["failure"] is None and value["control_error"] is None, "Foreign/failed fresh status")
            attached.service_owner(raw, replacement["pid"])
        elif sequence == copyrow["sequence"]: pass
        elif args and args[0] == "input":
            require(row["returncode"] == 0 and args[1:3] in (["keyboard", "-d"], ["mouse", "-d"]) and args[3].isdigit() and (
                len(args) == 6 and args[4:] in (["keyevent", "KEYCODE_HOME"], ["keyevent", "KEYCODE_B"]) or
                len(args) == 7 and args[4] == "tap" and all(value.isdigit() for value in args[5:])), "Unreviewed death input mutation")
        elif args in (["dumpsys", "activity", lane.acceptance.FIXTURE], ["dumpsys", "activity", "activities"], ["dumpsys", "window", "windows"]):
            require(sequence > recovered["row"]["trace_end"] and row.get("output"), "Inherited delivery read escaped new recovery")
        else: raise ValueError("Unreviewed client-death command/authority: " + " ".join(argv))
    producer.attached.current_client.audit_action(root, action, trace, admitted_contract, admitted_identity,
        client_chain=client_chain, client_uid=client_uid)
    lane.raw_audit.validate_external_copy_inventory(trace, {"stages": action["captures"] + ([action['probe_after']] if probe_audit else [])})
    require(action["cleanup"] == {"owner": "enclosing_original_guest_owner", "signal_retry": False, "sampler_stopped": False,
        "owned_run": new["run"], "owned_output": str(excluded), "host_pid": new["host_pid"]}, "Replacement ownership/cleanup changed")
    transition = {"action_nonce": action["nonce"], "scenario": scenario, "role": "client", "role_uid": original["uid"],
        "permit_id": action["permit_id"], "before": old["epoch"], "after": new["epoch"],
        "started_monotonic_ns": action["transition_started_monotonic_ns"], "ended_monotonic_ns": action["transition_ended_monotonic_ns"],
        "deadline_monotonic_ns": action["transition_started_monotonic_ns"] + producer.MAX_TRANSITION_NS,
        "absent_begin_monotonic_ns": indexed[kill]["started_monotonic_ns"], "absent_end_monotonic_ns": action["absent_end_monotonic_ns"],
        "old_end_monotonic_ns": indexed[kill]["ended_monotonic_ns"], "new_start_monotonic_ns": new_starts[0]["started_monotonic_ns"],
        "action_relative": prefix + "/attempt-ended.json", "recovered_stage_relative": action["recovered_stage_relative"]}
    return {"scenario": scenario, "runtime_qualified": False, "whole_campaign_complete": False,
        "processes": delivered["processes"], "transition": transition}
