#!/usr/bin/env python3
"""Independent original STOP/expiry/CONT evidence, not whole-soak acceptance."""
from pathlib import Path
from io import BytesIO
import json
import re
from PIL import Image

import phase1_conformance_soak_lock_user_acceptance as attached
from phase1_conformance_common import file_ref, load

runtime, health, lane = attached.runtime, attached.health, attached.lane
require = runtime.require
KIND = "phase1_policy_free_frozen_client_attachment_action_v1"
STATUS = "passed_bounded_original_frozen_client_action_NOT_whole_campaign"


def process_state(raw, pid):
    match = re.fullmatch(r"([1-9][0-9]*) \([^\n]*\) ([A-Za-z]) .+\n?", raw)
    require(match is not None and int(match[1]) == pid, "Malformed actual kernel process state")
    return match[2]


def parse_os_capture(root, row, action, trace):
    """Never insert a remembered/fabricated stopped-app status into raw proof."""
    root = Path(root); prefix = f"soak-actions/{action['ordinal']:06d}-frozen_client-{action['nonce']}/captures/{row['name']}/"
    def read(relative, command):
        path = root / relative; rows = [item for item in trace if item.get("evidence") == relative]
        require(relative.startswith(prefix) and path.resolve(strict=True) == path and not path.is_symlink() and
            len(rows) == 1 and rows[0]["kind"] == "command" and rows[0]["returncode"] == 0 and
            rows[0]["argv"] == ["docker", "exec", action["identity"]["container_id"], "adb", "-s", "emulator-5580", "shell", *map(str, command)] and
            rows[0]["output_sha256"] == attached.observations.command_ref(path, root, trace, action["identity"]["container_id"])["sha256"] and
            row["trace_start"] <= rows[0]["sequence"] < row["trace_end"] and
            row["began_monotonic_ns"] <= rows[0]["started_monotonic_ns"] <= rows[0]["ended_monotonic_ns"] <= row["ended_monotonic_ns"],
            "Unbound/aliased original frozen OS observation")
        return path.read_text()
    commands = {"activities": ("dumpsys", "activity", "activities"), "fixture": ("dumpsys", "activity", "--user", "0", lane.acceptance.FIXTURE),
        "windows": ("dumpsys", "window", "windows"), "window_displays": ("dumpsys", "window", "displays"),
        "input": ("dumpsys", "input"), "display": ("dumpsys", "display"),
        "keyguard": ("dumpsys", "activity", "--user", "0", "service", "com.android.systemui/.SystemUIService"),
        "policy": ("dumpsys", "window", "policy"), "current_user": ("am", "get-current-user"), "users": ("dumpsys", "user"),
        "events": ("logcat", "-b", "events", "-d", "-v", "threadtime", "am_anr:I", "am_crash:I", "*:S"),
        "modem": ("getprop", health.phone.MODEM_PROPERTY), "radio": ("su", "0", "service", "list"),
        "boot": ("cat", "/proc/sys/kernel/random/boot_id"), "home_uid": ("pm", "list", "packages", "-U", "--user", "0", lane.raw_audit.LAUNCHER)}
    require(set(row["files"]) == set(commands) and row["runtime_status_observed"] is False and row["user"] == 0,
        "Frozen observation cannot fabricate/query stopped-app status")
    raw = {key: read(row["files"][key], command) for key, command in commands.items()}
    require(raw["current_user"].strip() == "0" and raw["boot"].strip() == action["identity"]["boot_id"] and
        not attached.health_audit.protected_events(raw["events"]) and not lane.acceptance.crash_events(raw["events"]), "Foreign boot/user or real crash/ANR")
    require(set(row["processes"]) == set(health.contract.PROCESS_NAMES), "All five actual process roles required")
    processes = {}
    for role, package in health.contract.PROCESS_NAMES.items():
        metric = row["processes"][role]
        uid = 1000 if role == "system_server" else attached.package_uid(read(metric["package_uid"],
            ("pm", "list", "packages", "-U", "--user", "0", package)), package, 0)
        values = {}
        fields = ("pid_before", "ps_before", "stat_before", "status", "fd", "stat_after", "pid_after", "ps_after")
        require(set(metric["files"]) == set(fields), "Missing/extra original frozen process observations")
        sequences = []
        for key, relative in metric["files"].items():
            command = ("pidof", package) if key.startswith("pid") else health.PROCESS_TABLE_COMMAND if key.startswith("ps") else (
                "su", "0", *(("ls", "-1") if key == "fd" else ("cat",)), f"/proc/{metric['pid']}/" + ("stat" if key in ("stat_before", "stat_after") else key))
            values[key] = read(relative, command)
        for key in fields:
            sequences.append(next(item["sequence"] for item in trace if item.get("evidence") == metric["files"][key]))
        require(sequences == list(range(sequences[0], sequences[0] + 8)), "Reordered original frozen process fences")
        actual = attached.process_metric(values, uid, package)
        require(actual == {key: metric[key] for key in actual}, "Frozen process summary differs from original UID/epoch bytes")
        if role == "client": require(all(process_state(values[key], actual["pid"]) == "T" for key in ("stat_before", "stat_after")), "Original client is not actually stopped")
        processes[role] = actual
    displays = lane.raw_audit.logical_displays(raw["display"])
    require({item["slot"] for item in displays.values()} == {1, 2, 3}, "All three exact connectors required")
    records, membership, identities = lane.acceptance.fixture_lifetimes(raw["fixture"], raw["activities"], action["uids"][lane.acceptance.FIXTURE])
    require(set(records) == set(lane.acceptance.COMPONENTS.values()), "Exact original populated tasks required")
    frames = {}; require(set(row["frames"]) == {"0", "1", "2", "3"}, "Phone plus all three original frames required")
    offset = trace[0]["sequence"]
    for slot, relative in row["frames"].items():
        require(relative == prefix + f"frame-{slot}.png", "Foreign frozen frame path")
        lane.raw_audit.validate_frame_trace(trace, row["trace_start"] - offset, row["trace_end"] - offset, root,
            action["identity"]["container_id"], int(slot), relative)
        display = 0 if slot == "0" else next(value for value, item in displays.items() if item["slot"] == int(slot))
        regions = {component: [record[key] for key in ("left", "top", "right", "bottom")]
            for component, record in records.items() if record["native_display"] == display}
        payload = (root / relative).read_bytes(); frame = lane.raw_audit.png_info(payload, regions)
        expected = (1080, 2400) if slot == "0" else lane.acceptance.SPECS[int(slot)][:2]
        require((frame["width"], frame["height"]) == expected, "Frozen frame dimensions changed")
        with Image.open(BytesIO(payload)) as image:
            frame["opaque_black"] = image.convert("RGBA").getextrema() == ((0, 0), (0, 0), (0, 0), (255, 255))
            frame["rgb_nonblack"] = image.convert("RGB").getextrema() != ((0, 0), (0, 0), (0, 0))
        frames[int(slot)] = frame
    return {"row": row, "raw": raw, "status": None, "processes": processes, "records": records, "identities": identities,
        "membership": membership, "displays": displays, "frames": frames, "modem": health.phone.modem_port(raw["modem"]),
        "radio": health.phone.radio_services(raw["radio"])}


def shield(before, current, action):
    require(current["displays"] == before["displays"] and lane.raw_audit.focused_display(current["raw"]["windows"]) == 0,
        "Frozen expiry changed actual connectors or stole phone focus")
    attached.phone_home_user(current["raw"]["activities"], current["raw"]["window_displays"], current["raw"]["windows"], 0)
    require(attached.lock.keyguard_state(current["raw"]["keyguard"]) == {"mShowing": False, "mSecure": False, "mCanDismissLockScreen": True} and
        attached.lock.phone_awake(current["raw"]["policy"]), "Frozen action changed the ordinary unlocked awake phone")
    require(current["frames"][0]["rgb_nonblack"], "Frozen ordinary awake Home phone image is entirely RGB black")
    for component, record in current["records"].items():
        previous = before["records"][component]
        require(current["identities"][component] == before["identities"][component] and record["lifecycle"] == "stopped" and record["focused"] is False and
            all(record[key] == previous[key] for key in ("key_downs", "pointer_downs", "mouse_downs")), "Frozen old task accepted input or changed lifetime")
    rows, _connections = attached.input_consumers.dispatcher_windows(current["raw"]["input"])
    own = {action["uids"][runtime.PACKAGE], action["uids"][lane.acceptance.FIXTURE]}
    for row in rows:
        flags = set(value.strip() for value in attached.input_consumers.field(row, "inputConfig", r"[^,]+").split("|"))
        uid = int(attached.input_consumers.field(row, "ownerUid", r"[0-9]+"))
        require(not (uid in own and "NOT_VISIBLE" not in flags and ("SPY" in flags or "DROP_INPUT" not in flags)), "Frozen owner retains actual input authority")
        require(not (uid == action["uids"][runtime.PACKAGE] and "SPY" in flags and attached.input_consumers.field(row, "displayId", r"[0-9]+") == "0"), "Frozen owner spy leaked onto phone")
    for display, info in current["displays"].items():
        attached.input_consumers.consumers(current["raw"]["input"], display, info["width"], info["height"], current["processes"]["system_server"]["pid"])
        infrastructure = [row for row in rows if attached.input_consumers.field(row, "displayId", r"[0-9]+") == str(display) and
            attached.input_consumers.field(row, "name", r"[^,]+") == "PointerEventDispatcherOverlay" + str(display) and
            attached.input_consumers.field(row, "ownerUid", r"[0-9]+") == "1000" and
            set(value.strip() for value in attached.input_consumers.field(row, "inputConfig", r"[^,]+").split("|")) == {"NOT_FOCUSABLE", "TRUSTED_OVERLAY", "SPY", "DO_NOT_PILFER"}]
        require(len(infrastructure) == 1 and current["frames"][info["slot"]]["opaque_black"], "Frozen monitor lost OS infrastructure or exact opaque black")
    for block in re.split(r"(?=^\s*Window #\d+ Window\{)", current["raw"]["windows"], flags=re.M):
        owner = re.search(r"\bmOwnerUid=([0-9]+)\b", block)
        require(not (owner and int(owner[1]) in own and all(value in block for value in ("isVisible=true", "isOnScreen=true", "mHasSurface=true"))),
            "Frozen owner retains a surfaced visible native window")


def audit_action(path, admitted_contract, admitted_identity, *, client_chain=None, client_uid=None):
    import phase1_conformance_soak_frozen_client_action as producer
    path = Path(path).absolute(); directory = path.parent; root = directory.parents[1]
    require(path.resolve(strict=True) == path and path.name == "attempt-ended.json", "Literal original frozen attempt required")
    action = load(path)
    require(action["schema"] == 1 and action["kind"] == KIND and action["scenario"] == "frozen_client" and action["status"] == STATUS and
        type(action["ordinal"]) is int and action["ordinal"] > 0 and runtime.HEX32.fullmatch(action["nonce"]) and
        action["identity"] == admitted_identity and action["contract"] == admitted_contract and action["sources"] == producer.source_contract() and
        action["runtime_qualified"] is False and action["whole_campaign_complete"] is False and action.get("error") is None,
        "Failed/foreign/resealed whole-campaign frozen action")
    require(admitted_contract == producer.attached.admission.input_contract(admitted_identity["image_id"], Path(admitted_contract["product"]),
        Path(admitted_contract["packet"]), admitted_contract["packet_receipt"]["sha256"]), "Frozen actual immutable source/packet contract changed")
    require(directory.name == f"{action['ordinal']:06d}-frozen_client-{action['nonce']}" and directory.parent.name == "soak-actions" and
        all(not target.is_symlink() and (target.is_file() or target.is_dir()) for target in directory.rglob("*")), "Aliased frozen original evidence")
    require({str(target.relative_to(root)) for target in directory.rglob("*") if target.is_file() and target != path} == set(action["evidence"]),
        "Lost/extra frozen raw evidence")
    trace = load(directory / "commands.json"); indexed = {row["sequence"]: row for row in trace}
    require(all(type(action[key]) is int for key in ("trace_start", "trace_end", "began_monotonic_ns", "ended_monotonic_ns")) and
        0 <= action["trace_start"] < action["trace_end"] and trace and all(type(row["sequence"]) is int for row in trace) and
        [row["sequence"] for row in trace] == list(range(action["trace_start"], action["trace_end"])), "Incomplete original frozen command journal")
    for relative, ref in action["evidence"].items(): require(attached.observed_ref(root / relative, trace, root, admitted_identity["container_id"]) == ref, "Frozen original bytes changed")
    started = load(directory / "attempt-started.json")
    require(started["status"] == "failed_bounded_frozen_action_not_qualified" and started["captures"] == [] and
        all(started[key] == action[key] for key in ("kind", "scenario", "ordinal", "nonce", "identity", "run", "contract", "sources", "began_monotonic_ns", "timeout_ns")),
        "Frozen original started attempt substituted")
    require(0 < action["ended_monotonic_ns"] - action["began_monotonic_ns"] <= health.contract.MAX_SCENARIO_NS and
        action["timeout_ns"] == producer.client_timeout_ns(), "Frozen action duration/source timeout changed")
    previous = action["began_monotonic_ns"]
    for row in trace:
        require(row["kind"] == "command" and type(row.get("returncode")) is int and row["returncode"] == 0 and
            type(row["started_monotonic_ns"]) is int and type(row["ended_monotonic_ns"]) is int and
            previous <= row["started_monotonic_ns"] <= row["ended_monotonic_ns"] <= action["ended_monotonic_ns"], "Failed/interleaved original frozen command")
        if row.get("evidence"): require(attached.observed_ref(root / row["evidence"], trace, root,
            admitted_identity["container_id"])["sha256"] == row["output_sha256"], "Frozen raw command hash changed")
        previous = row["ended_monotonic_ns"]
    require([row["name"] for row in action["captures"]] == ["before", "inactive-0", "inactive-1", "inactive-2", "recovered", "delivered"], "All original frozen captures required")
    for row in action["captures"]:
        require(all(type(row[key]) is int for key in ("trace_start", "trace_end", "began_monotonic_ns", "ended_monotonic_ns")) and
            action["trace_start"] <= row["trace_start"] < row["trace_end"] <= action["trace_end"] and
            action["began_monotonic_ns"] <= row["began_monotonic_ns"] <= row["ended_monotonic_ns"] <= action["ended_monotonic_ns"],
            "Frozen captures require exact typed bounded original windows")
    scenes = [attached.parse_capture(root, row, action, trace) if index in {0, 4, 5} else parse_os_capture(root, row, action, trace)
        for index, row in enumerate(action["captures"])]
    before, recovered, delivered = scenes[0], scenes[4], scenes[5]
    for scene in (before, recovered, delivered): attached.ready(scene, action)
    for scene in scenes[1:4]: shield(before, scene, action)
    original = before["processes"]["client"]
    require(action["expectation"]["reason"] == 5 and all(action["expectation"][key] == before["status"]["snapshot"][key] for key in ("generation", "identity_epoch")),
        "Frozen expectation is not exact original CLIENT_FAILED lease")
    for scene in scenes:
        require(scene["modem"] == before["modem"] and scene["radio"] == before["radio"], "Frozen phone radio identity changed")
        for role, metric in scene["processes"].items():
            require(all(metric[key] == before["processes"][role][key] for key in ("pid", "start_ticks", "uid")) and
                metric["fd_count"] - before["processes"][role]["fd_count"] <= 64 and
                metric["rss_kib"] - before["processes"][role]["rss_kib"] <= 256 * 1024, "Frozen protected epoch/resource changed")
        counts, base = health.task_counts(scene["raw"]["activities"]), health.task_counts(before["raw"]["activities"])
        require(counts["tasks"] - base["tasks"] <= 12 and counts["roots"] - base["roots"] <= 8, "Frozen native task/root bound exceeded")
        require(scene["identities"] == before["identities"], "Frozen real Android task/activity lifetime changed")
    for scene, delta in ((recovered, 0), (delivered, 1)):
        attached.recovery_layout(before, scene)
        for component, record in scene["records"].items():
            prior = before["records"][component]
            require(all(record[key] == prior[key] for key in ("left", "top", "right", "bottom", "display", "native_display")) and
                all(record[key] == prior[key] + delta for key in ("key_downs", "mouse_downs")), "Frozen recovered geometry/delivery changed")
        require(scene["status"]["callbacks"]["onRevoked"] == before["status"]["callbacks"]["onRevoked"] + 1, "Frozen extra/missing callback")
    require(all(recovered["status"]["snapshot"][key] == delivered["status"]["snapshot"][key] for key in ("generation", "identity_epoch")), "Frozen recovery namespace changed again")
    shell = ["docker", "exec", admitted_identity["container_id"], "adb", "-s", "emulator-5580", "shell"]
    stop, cont = action["stop_trace_index"], action["cont_trace_index"]
    require(type(stop) is int and type(cont) is int and stop < cont and
        indexed[stop]["argv"] == shell + ["su", "0", "kill", "-STOP", str(original["pid"])] and
        indexed[cont]["argv"] == shell + ["su", "0", "kill", "-CONT", str(original["pid"])], "Signals did not target the exact original epoch")
    require(indexed[stop]["ended_monotonic_ns"] + action["timeout_ns"] <= scenes[1]["row"]["began_monotonic_ns"] and
        all(stop < scene["row"]["trace_start"] < scene["row"]["trace_end"] <= cont for scene in scenes[1:4]), "Frozen expiry observations preceded timeout/STOP or followed CONT")
    for fence in action["client_fences"]:
        require(type(fence["trace_start"]) is int and fence["trace_end"] == fence["trace_start"] + 8 and
            all(fence[key] == original[key] for key in ("pid", "start_ticks", "uid")), "Frozen signal fence was fabricated/recycled")
        raw = {}
        fields = ("pid_before", "ps_before", "stat_before", "status", "fd", "stat_after", "pid_after", "ps_after")
        require(set(fence["files"]) == set(fields), "Missing/extra original signal fence")
        for key, relative in fence["files"].items():
            rows = [row for row in trace if row.get("evidence") == relative]
            command = ["pidof", runtime.PACKAGE] if key.startswith("pid") else list(health.PROCESS_TABLE_COMMAND) if key.startswith("ps") else [
                "su", "0", *(("ls", "-1") if key == "fd" else ("cat",)), f"/proc/{original['pid']}/" + ("stat" if key in ("stat_before", "stat_after") else key)]
            require(len(rows) == 1 and rows[0]["argv"] == shell + command and fence["trace_start"] <= rows[0]["sequence"] < fence["trace_end"], "Unbound original signal fence")
            raw[key] = (root / relative).read_text()
        require([next(row["sequence"] for row in trace if row.get("evidence") == fence["files"][key]) for key in fields] ==
            list(range(fence["trace_start"], fence["trace_end"])), "Reordered immediate signal PID/start/UID fence")
        metric = attached.process_metric(raw, original["uid"], runtime.PACKAGE)
        require(all(metric[key] == original[key] for key in ("pid", "start_ticks", "uid")) and
            fence["states"] == [process_state(raw[key], original["pid"]) for key in ("stat_before", "stat_after")], "Original signal UID/epoch/state changed")
        uidrow = indexed[fence["trace_start"] - 1]
        require(uidrow["argv"] == shell + ["pm", "list", "packages", "-U", "--user", "0", runtime.PACKAGE] and
            attached.package_uid((root / uidrow["evidence"]).read_text(), runtime.PACKAGE, 0) == original["uid"], "Signal UID was not freshly admitted")
    for label, boundary in (("before-stop", stop), ("before-cont", cont)):
        fences = [row for row in action["client_fences"] if row["label"] == label]
        require(len(fences) == 1 and fences[0]["trace_end"] == boundary and
            (label != "before-cont" or fences[0]["states"] == ["T", "T"]), "Signal was not immediately fenced against PID reuse")
    controls, statuses = [], []
    client = producer.attached.current_client.audit_action(root, action, trace, admitted_contract, admitted_identity,
        client_chain=client_chain, client_uid=client_uid)
    client_sequences = client["sequences"]
    bound_reads = {relative for scene in action["captures"] for relative in scene["files"].values()}
    bound_reads.update(relative for scene in action["captures"] for metric in scene["processes"].values()
        for relative in ([metric["package_uid"]] if metric["package_uid"] is not None else []) + list(metric["files"].values()))
    bound_reads.update(relative for fence in action["client_fences"] for relative in fence["files"].values())
    bound_reads.update(indexed[fence["trace_start"] - 1]["evidence"] for fence in action["client_fences"])
    frame_sequences = set()
    for scene in action["captures"]:
        for slot, relative in scene["frames"].items():
            index = next(index for index, row in enumerate(trace) if row.get("evidence") == relative)
            frame_sequences.update(trace[at]["sequence"] for at in ([index] if slot == "0" else range(index - 3, index + 2)))
    consumed = set()
    for row in trace:
        argv = row["argv"]; sequence = row["sequence"]
        if argv == ["docker", "container", "inspect", admitted_identity["container_id"]]:
            values = json.loads(row["output"]); require(len(values) == 1, "Ambiguous frozen owner")
            producer.attached.sampler.verify_owner(values[0], admitted_identity); consumed.add(sequence); continue
        args = argv[len(shell):] if argv[:len(shell)] == shell else []
        if args[:7] == ["dumpsys", "activity", "--user", "0", "service", runtime.SERVICE, "runtime-command"]:
            fields = args[7:]; phase = fields[2]
            require(fields[0] == action["run"] and runtime.HEX32.fullmatch(fields[1]) and phase in {"remember-observed", "expect-revocation", "reopen", "restore-observed"} and
                (fields[3:] == list(map(str, (action["expectation"]["generation"], action["expectation"]["identity_epoch"], 5))) if phase == "expect-revocation" else len(fields) == 3) and
                [line.strip() for line in row["output"].splitlines() if runtime.CONTROL_MARKER.rstrip() in line] ==
                    [runtime.CONTROL_MARKER + f"accepted {fields[0]} {fields[1]} {phase}"],
                "Frozen original control malformed/rejected")
            controls.append((sequence, fields)); consumed.add(sequence)
        elif args == ["dumpsys", "activity", "--user", "0", "service", runtime.SERVICE]:
            require(not stop < sequence < cont, "Stopped app status was queried/fabricated during expiry")
            raw = (root / row["evidence"]).read_text(); value = runtime.parse_status(raw)
            attached.service_owner(raw, original["pid"])
            require(value["run"] == action["run"] and value["failure"] is None and value["control_error"] is None, "Frozen held runtime failed")
            statuses.append((sequence, raw, value)); consumed.add(sequence)
        elif args[:3] == ["su", "0", "kill"]:
            require(sequence in {stop, cont}, "Unexpected/extra signal mutation")
            consumed.add(sequence)
        elif args and args[0] == "input":
            require(args[1:3] in (["keyboard", "-d"], ["mouse", "-d"]) and args[3].isdigit() and (
                len(args) == 6 and args[4] == "keyevent" and args[5] in {"KEYCODE_HOME", "KEYCODE_B"} or
                len(args) == 7 and args[4] == "tap" and all(value.isdigit() for value in args[5:])), "Unreviewed frozen input mutation")
            consumed.add(sequence)
        elif sequence in client_sequences: consumed.add(sequence)
        elif row.get("evidence") in bound_reads and argv[:len(shell)] == shell:
            # Exact commands for these original fields were independently
            # rederived by capture/fence parsing above, not prefix-whitelisted.
            consumed.add(sequence)
        elif argv[:len(shell)] == shell and args in (["cat", "/proc/sys/kernel/random/boot_id"], ["am", "get-current-user"]):
            raw = (root / row["evidence"]).read_text()
            require(raw.strip() == (admitted_identity["boot_id"] if args[0] == "cat" else "0"), "Frozen owner guard boot/user changed")
            consumed.add(sequence)
        elif argv[:len(shell)] == shell and args in (["dumpsys", "activity", lane.acceptance.FIXTURE],
            ["dumpsys", "activity", "activities"], ["dumpsys", "window", "windows"]):
            require(sequence > cont and row.get("output"), "Inherited delivery read escaped actual user0 recovery interval")
            consumed.add(sequence)
        elif sequence in frame_sequences: consumed.add(sequence)
        else: raise ValueError("Unreviewed frozen command/authority: " + " ".join(argv))
    require(consumed == set(indexed), "Unconsumed original frozen command")
    require([fields[2] for _index, fields in controls] == ["remember-observed", "expect-revocation", "reopen", "restore-observed"] and
        len({fields[1] for _index, fields in controls}) == 4 and controls[1][0] < stop < cont < controls[2][0], "Frozen exact original control/signal ordering changed")
    arm = controls[1]
    armed = [raw for index, raw, value in statuses if arm[0] < index < stop and value["handshake"] == {"nonce": arm[1][1], "phase": "expect-revocation", "result": "accepted"}]
    require(armed, "No actual armed callback receipt before STOP")
    producer.attached.expectation.require_armed(armed[-1], action["run"], arm[1][1], action["expectation"]["generation"], action["expectation"]["identity_epoch"], 5)
    callbacks = [raw for index, raw, value in statuses if cont < index < controls[2][0] and value["state"] == "waiting-reopen"]
    require(callbacks, "No actual deferred callback observed after CONT")
    producer.attached.expectation.require_consumed(callbacks[0], action["run"], action["expectation"])
    require(runtime.parse_status(callbacks[0])["updated_elapsed_ms"] <= action["expectation"]["deadline_elapsed_ms"], "Frozen actual callback exceeded its one-shot expectation deadline")
    for index, scene in enumerate(scenes[1:4]):
        low = stop + 1 if index == 0 else scenes[index]["row"]["trace_end"]
        high = scene["row"]["trace_start"]
        actual = [row["argv"][len(shell):] for row in trace if low <= row["sequence"] < high and row["argv"][:len(shell)] == shell and row["argv"][len(shell):][:1] == ["input"]]
        expected = []
        for component, record in before["records"].items():
            expected += [["input", "keyboard", "-d", str(record["native_display"]), "keyevent", "KEYCODE_B"],
                ["input", "mouse", "-d", str(record["native_display"]), "tap", str((record["left"] + record["right"]) // 2), str((record["top"] + record["bottom"]) // 2)]]
        require(actual == expected, "Missing/reordered actual stopped keyboard/mouse input challenges")
    reopened = [value["snapshot"] for index, raw, value in statuses if controls[2][0] < index < controls[3][0] and
        value["handshake"] == {"nonce": controls[2][1][1], "phase": "reopen", "result": "accepted"} and value["state"] == "ready"]
    require(reopened, "Missing actual new authorized recovery snapshot")
    new, final = reopened[-1], recovered["status"]["snapshot"]
    require(all(new[key] == final[key] for key in ("generation", "identity_epoch")) and
        {key: task["token"] for key, task in attached.descriptive_tasks(new).items()} == {key: task["token"] for key, task in attached.descriptive_tasks(final).items()} and
        {row["identity_hint"]: row["token"] for row in new["display_incarnations"]} == {row["identity_hint"]: row["token"] for row in final["display_incarnations"]},
        "Frozen recovery substituted old/foreign authority")
    lane.raw_audit.validate_external_copy_inventory(trace, {"stages": action["captures"]})
    require(action["signal_cleanup"] == {"attempted": True, "continued": False}, "Successful frozen action had failed/extra continuation cleanup")
    return {"scenario": "frozen_client", "runtime_qualified": False, "whole_campaign_complete": False,
        "client_epoch": {key: original[key] for key in ("pid", "start_ticks", "uid")}}
