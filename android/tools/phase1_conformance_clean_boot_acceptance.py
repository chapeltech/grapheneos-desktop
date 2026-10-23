#!/usr/bin/env python3
"""Independent raw-evidence audit of ONE policy-free 20-cycle clean boot.

This is not the three-boot aggregate, one-shot API gate, 24-hour soak or release
qualification. No product-policy report is accepted by this auditor.
"""
from pathlib import Path
import json
import re

import conformance_runtime as runtime
import phase1_conformance_recents_acceptance as raw_audit
from phase1_conformance_common import canonical, file_ref, load, sha256, validate_manifest
import phase1_conformance_observations as observations

KIND = "phase1_policy_free_conformance_clean_boot_v1"
SCOPE = "one_fresh_bounded_conformance_only_guest_twenty_populated_connector_cycles"
APP, FIXTURE = runtime.PACKAGE, raw_audit.FIXTURE
OS_NAMES = ("system_server", "com.android.systemui", "com.android.launcher3", "com.android.phone")
PROCESS_NAMES = (*OS_NAMES, APP)
COMPONENTS = {1: FIXTURE + "/.PaletteOneActivity", 2: FIXTURE + "/.PaletteTwoActivity",
              3: FIXTURE + "/.BandedThreeActivity"}
SPECS = dict(raw_audit.DISPLAY_SPECS)
PHASE_NAMES = ("initial", *(f"cycle-{cycle:02d}-{side}" for cycle in range(1, 21)
                          for side in ("before", "parked", "restored")),
               "undocked", "phone-resumed", "phone-home")
MAX_BOOT_NS = 2 * 60 * 60 * 1_000_000_000
MAX_TRANSITION_NS = 120 * 1_000_000_000
CLIENT_FILES = tuple("android/conformance/src/main/kotlin/org/wonad/desktop/" + name for name in (
    "ConformanceContract.kt", "ConformanceRuntimeRunner.kt", "ConformanceRuntimeLedger.kt", "ConformanceObservedReplay.kt",
    "ConformanceExpectedRevocation.kt"))


def require(value, message):
    if not value:
        raise ValueError(message)


def slot_plan():
    return [(cycle, (cycle - 1) % 3 + 1) for cycle in range(1, 21)]


def proc_epoch(raw, pid):
    match = re.fullmatch(r"([1-9][0-9]*) \(.*\) [A-Z] (.+)\n?", raw)
    fields = match[2].split() if match else []
    require(match is not None and int(match[1]) == pid and len(fields) > 18 and
            re.fullmatch(r"[1-9][0-9]*", fields[18]), "Malformed protected process stat")
    return {"pid": pid, "start_ticks": int(fields[18])}


def process_inventory(rows, raw):
    require(isinstance(rows, dict) and set(rows) == set(PROCESS_NAMES),
            "Missing protected OS/phone/conformance-client epoch")
    result = {}
    for name in PROCESS_NAMES:
        record = rows[name]
        require(isinstance(record, dict) and set(record) == {"pid", "start_ticks", "pidof", "before", "after"},
                "Malformed protected epoch record")
        text = raw[record["pidof"]].strip()
        require(re.fullmatch(r"[1-9][0-9]*", text), "Missing/ambiguous protected PID")
        pid = int(text)
        before, after = raw[record["before"]], raw[record["after"]]
        epoch = proc_epoch(before, pid)
        require(epoch == proc_epoch(after, pid) and epoch == {key: record[key] for key in ("pid", "start_ticks")},
                "Protected PID/start-time was reused or summary differs from raw")
        result[name] = epoch
    require(len({row["pid"] for row in result.values()}) == len(PROCESS_NAMES),
            "Protected process PIDs are aliased")
    return result


def native_roots(activities, displays, snapshot, app_uid, fixture_uid):
    sections = re.split(r"^ActivityTaskSupervisor state:\s*$", activities, flags=re.M)
    require(len(sections) == 2 and sections[0].count("ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)") == 1,
            "Missing authoritative task/root inventory")
    result, current, root = {}, None, None
    for line in sections[0].splitlines():
        heading = re.fullmatch(r"Display #(\d+) \(activities from top to bottom\):", line)
        if heading:
            current, root = int(heading[1]), None
            if current in displays:
                require(current not in result, "Duplicate native root display")
                result[current] = []
        match = re.match(r"  \* Task\{([0-9a-f]+) #(\d+) (.*)\}", line)
        if match and current in displays:
            root = {"object": match[1], "task": int(match[2]), "header": match[3], "components": [], "children": []}
            result[current].append(root)
        elif line.startswith("  * Task{"):
            root = None
        if root is not None:
            child = re.match(r"    \* Task\{\S+ #(\d+) .*\brootTaskId=(\d+) ", line)
            if child:
                require(int(child[2]) == root["task"], "Native child/root mismatch")
                root["children"].append(int(child[1]))
            activity = re.search(r"\* Hist\s+#\d+: ActivityRecord\{\S+ u0 (\S+) t\d+\}", line)
            if activity:
                root["components"].append(activity[1])
    require(set(result) == set(displays), "Native root display set differs from actual topology")
    counts = {}
    tokens = {row["display_id"]: row["token"] for row in snapshot["display_incarnations"]} if snapshot else {}
    for display, roots in result.items():
        kinds = []
        for row in roots:
            header = row["header"]
            require(not re.search(r"\bname=(?:Desk|MinimizedDesk_[0-9]+)\b", header), "Stale stock desktop root")
            if "type=home " in header:
                require(any(component.endswith("ExternalHomeActivity") and component.startswith(APP + "/")
                            for component in row["components"]), "External Home root is not conformance owned")
                kind = "home"
            elif "A=" + str(app_uid) + ":" + APP in header:
                require(not row["children"] and len(row["components"]) == 1 and
                        row["components"][0].endswith("ExternalShellActivity"), "Foreign conformance root")
                kind = "shell"
            elif "A=" + str(fixture_uid) + ":" + FIXTURE in header:
                require(not row["children"] and row["components"] and "mode=freeform " in header,
                        "Fixture does not have a direct native freeform root")
                kind = "app"
            else:
                raise ValueError("Unclassified external native root")
            kinds.append(kind)
        expected_apps = sum(task["display_token"] == tokens.get(display) for task in snapshot["tasks"])
        require(kinds.count("home") == kinds.count("shell") == 1 and kinds.count("app") == expected_apps and
                len(kinds) == 2 + expected_apps, "Unbounded or mismatched native root inventory")
        counts[display] = len(kinds)
    root_ids = re.findall(r"^  \* Task\{\S+ #(\d+) ", sections[0], re.M)
    task_ids = re.findall(r"^\s+\* Task\{\S+ #(\d+) ", sections[0], re.M)
    require(len(root_ids) == len(set(root_ids)) and len(task_ids) == len(set(task_ids)), "Duplicate task/root identity")
    return {"external": counts, "total_roots": len(root_ids), "total_tasks": len(task_ids)}


def stock_chrome(windows, inputs, displays):
    blocks = re.split(r"(?=^\s*Window #\d+ Window\{)", windows, flags=re.M)
    forbidden = r"(?:ty=(?:STATUS_BAR|NAVIGATION_BAR)|Taskbar|DesktopWallpaperActivity|DragResizeInputListener|DecorCaption)"
    for block in blocks:
        display = re.search(r"\bmDisplayId=(\d+)\b", block)
        if display and int(display[1]) in displays:
            require(not re.search(forbidden, block), "Stock chrome remains on a claimed monitor")
    for line in inputs.splitlines():
        display = re.search(r"\bdisplayId=(\d+),", line)
        if display and int(display[1]) in displays:
            require(not re.search(r"Taskbar|DesktopWallpaperActivity|DragResizeInputListener|DecorCaption", line),
                    "Stock decoration input remains on a claimed monitor")


def task_tokens(stage):
    result = {}
    for component in COMPONENTS.values():
        task = raw_audit.runtime_task(stage, component)
        result[component] = task["token"]
    require(len(set(result.values())) == len(result), "Opaque fixture task token is aliased")
    return result


def fixture_lifetimes(fixture, activities, uid, *, phone_only=False):
    """Stopped client config may lag authoritative hidden-task migration."""
    membership = {}
    for task, display in re.findall(r"^TASK [^\n]* id=(\d+) userId=0 displayId=(\d+)\(type=[A-Z_]+\)", fixture, re.M):
        task, display = int(task), int(display)
        require(task not in membership, "Duplicate final native task membership")
        membership[task] = display
    records, identities = {}, {}
    primary = activities.split("ActivityTaskSupervisor state:", 1)[0]
    for line in fixture.splitlines():
        marker = next((marker for marker in ("WONAD_PALETTE ", "WONAD_BANDED_PALETTE ") if marker in line), None)
        if marker is None: continue
        record = json.loads(line.split(marker, 1)[1], object_pairs_hook=raw_audit.strict_object)
        component = record.get("component")
        require(component in COMPONENTS.values() and component not in records and
                all(type(record.get(field)) is int for field in ("task", "display", "left", "top", "right", "bottom",
                    "key_downs", "pointer_downs", "mouse_downs", "pid", "uid")) and
                raw_audit.UUID.fullmatch(str(record.get("instance"))) and
                record["task"] in membership and (not phone_only or membership[record["task"]] == 0) and
                record["uid"] == uid and
                (record["display"] == membership[record["task"]] or record.get("lifecycle") == "stopped"),
                "Fixture is not an exact native phone survivor" if phone_only else "Fixture native/config membership disagrees")
        actual_display = membership[record["task"]]
        header = re.findall(r"^  ACTIVITY " + re.escape(component) +
            r" ([0-9a-f]+) pid=([1-9][0-9]*) userId=0 uid=(\d+) displayId=" + str(actual_display) +
            r"\(type=[A-Z_]+\)$", fixture, re.M)
        tasks = re.findall(r"^\s*\* Task\{([0-9a-f]+) #" + str(record["task"]) + r" [^\n]*?\bU=0\b[^\n]*\}", primary, re.M)
        activity = re.findall(r"^\s*\* Hist\s+#\d+: ActivityRecord\{([0-9a-f]+) u0 " + re.escape(component) +
                             r" t" + str(record["task"]) + r"\}", primary, re.M)
        require(len(header) == len(tasks) == len(activity) == 1 and int(header[0][1]) == record["pid"] and
                int(header[0][2]) == uid, "Final Task/ActivityRecord/UID lifetime is unbound")
        # Keep the original client display verbatim. This separately named
        # derived scalar is bound to the authoritative native TASK header.
        records[component] = {**record, "native_display": actual_display}
        identities[component] = {"task": record["task"], "instance": record["instance"], "binder": header[0][0],
            "pid": record["pid"], "uid": uid, "task_object": tasks[0], "activity_record": activity[0]}
    return records, membership, identities


def final_fixture_lifetimes(fixture, activities, uid):
    return fixture_lifetimes(fixture, activities, uid, phone_only=True)


def crash_events(raw):
    """Same bracketed event grammar as the reviewed fresh protected_failures parser.

    A logged adb command containing am_crash:I is not a crash record. Preserve
    the lane's rejection of every genuine recorded crash/ANR, not just OS roles.
    """
    return [{"kind": match[1], "process": match[2].strip()}
            for match in re.finditer(
                r"\b(am_(?:anr|crash))\s*:\s*\[\s*[^,\]\n]+\s*,\s*[^,\]\n]+\s*,\s*([^,\]\n]+)", raw)]


def parse_stage(directory, row, evidence, uids):
    raw = {}
    for relative in [*row["files"].values(), *(record[field] for record in row["processes"].values()
                                              for field in ("pidof", "before", "after"))]:
        require(relative in evidence, "Unbound stage evidence")
        raw[relative] = (directory / relative).read_text()
    files = {name: raw[relative] for name, relative in row["files"].items()}
    displays = raw_audit.logical_displays(files["display"])
    status = runtime.parse_status(files["conformance"])
    # At final undock the ledger correctly retains its last snapshot, but no
    # retained display incarnation grants authority on an absent monitor.
    live = row["name"] not in {"undocked", "phone-resumed", "phone-home"}
    if live:
        require(status["state"] == "ready" and status["runtime_readiness"]["ready"], "Stage runtime is not ready")
        broker = raw_audit.runtime_display_incarnations(status, displays)
        shells = raw_audit.shell_incarnations(files["activities"], files["windows"], files["input"],
            status["snapshot"]["generation"], uids[APP], displays)
        require(set(shells) == set(displays) and all(shells[d]["token"] == broker[d]["token"] for d in displays),
                "Shell does not bind every actual current display incarnation")
    else:
        require(not displays and status["state"] == "waiting-reopen" and
                status["runtime_readiness"] == {"ready": False, "session_open": False, "reopen_required": True},
                "Final undock did not revoke the live session")
        broker = {}
        for block in re.split(r"(?=^\s*Window #\d+ Window\{)", files["windows"], flags=re.M):
            if re.search(r"External(?:Home|Shell)Activity|Wonad pointer observer", block):
                require(not ("isVisible=true" in block and "mHasSurface=true" in block),
                        "External fixed UI escaped onto phone after final undock")
    if live:
        records, membership, identities = fixture_lifetimes(files["fixture"], files["activities"], uids[FIXTURE])
        require(all(record["native_display"] in displays for record in records.values()),
                "Live fixture native membership left every claimed monitor")
    else:
        records, membership, identities = final_fixture_lifetimes(files["fixture"], files["activities"], uids[FIXTURE])
    require(set(records) == set(COMPONENTS.values()), "Populated fixture inventory changed")
    stock_chrome(files["windows"], files["input"], displays)
    roots = native_roots(files["activities"], displays, status["snapshot"] if live else None, uids[APP], uids[FIXTURE])
    processes = process_inventory(row["processes"], raw)
    frames = {}
    require(set(row["frames"]) == {"0", *(str(value["slot"]) for value in displays.values())},
            "Stage framebuffer set does not cover phone and every live monitor")
    for slot, relative in row["frames"].items():
        require(relative in evidence, "Unbound framebuffer")
        display = 0 if slot == "0" else next(display for display, value in displays.items() if value["slot"] == int(slot))
        regions = {component: [record[field] for field in ("left", "top", "right", "bottom")]
                   for component, record in records.items() if record["native_display"] == display}
        frame = raw_audit.png_info((directory / relative).read_bytes(), regions)
        size = (1080, 2400) if slot == "0" else SPECS[int(slot)][:2]
        require((frame["width"], frame["height"]) == size, "Wrong exact framebuffer geometry")
        frames[int(slot)] = frame
    require(not crash_events(files["events"]), "Unexpected crash/ANR in cumulative events")
    if row["name"] != "phone-resumed":
        raw_audit.phone_home_focus(files["activities"], files["window_displays"], files["windows"])
    return {"name": row["name"], "raw": files, "displays": displays, "status": status,
            "broker_displays": broker, "records": records, "membership": membership,
            "identities": identities, "processes": processes, "roots": roots, "frames": frames,
            "focused_display": raw_audit.focused_display(files["windows"])}


def exact_lifetimes(original, stage):
    for component in COMPONENTS.values():
        require(stage["identities"][component] == original["identities"][component],
                "Exact Android Task/ActivityRecord/Binder/UID/process lifetime changed")
        require(stage["records"][component]["instance"] == original["records"][component]["instance"],
                "Fixture Activity instance changed")
    require(stage["processes"] == original["processes"], "Protected OS/phone/client epoch changed")


def exact_round_lifetimes(original, stages):
    generation, epoch = (original["status"]["snapshot"][field] for field in ("generation", "identity_epoch"))
    for stage in stages:
        exact_lifetimes(original, stage)
        snapshot = stage["status"]["snapshot"]
        require((snapshot["generation"], snapshot["identity_epoch"]) == (generation, epoch), "Runtime lease epoch changed")
        require(stage["roots"]["total_roots"] <= original["roots"]["total_roots"] + 8 and
                stage["roots"]["total_tasks"] <= original["roots"]["total_tasks"] + 12, "Unbounded task/root growth")


def audit_populated_cycles(stages, *, phase_prefix=""):
    """Original hotplug predicates, reusable in one held-runtime soak round.

All stages must first be independently parsed from their original raw files.
This proves only one populated round, NOT final unplug or a complete campaign.
"""
    require(isinstance(phase_prefix, str) and (phase_prefix == "" or
        re.fullmatch(r"round-[1-9][0-9]*-", phase_prefix) is not None), "Exact positive hotplug round prefix required")
    require([stage["name"] for stage in stages] == [phase_prefix + name for name in PHASE_NAMES[:61]],
        "Exactly one initial observation and 20 populated three-stage cycles required")
    original = stages[0]
    require({row["slot"] for row in original["displays"].values()} == {1, 2, 3}, "Three simultaneous mixed monitors required")
    tokens = task_tokens(original)
    all_incarnations = {row["token"] for row in original["broker_displays"].values()}
    exact_round_lifetimes(original, stages)
    for offset, (cycle, slot) in enumerate(slot_plan()):
        before, parked, restored = stages[1 + offset * 3:4 + offset * 3]
        prior = next(row for row in before["displays"].values() if row["slot"] == slot)
        new = next(row for row in restored["displays"].values() if row["slot"] == slot)
        require({row["slot"] for row in before["displays"].values()} ==
                {row["slot"] for row in restored["displays"].values()} == {1, 2, 3} and
                {row["slot"] for row in parked["displays"].values()} == {1, 2, 3} - {slot}, "Wrong connector cycle topology")
        old_binding = before["broker_displays"][prior["display"]]
        new_binding = restored["broker_displays"][new["display"]]
        require(new_binding["token"] not in all_incarnations and old_binding["token"] != new_binding["token"] and
                old_binding["identity_hint"] == new_binding["identity_hint"], "Stale display authority or connector identity drift")
        all_incarnations.add(new_binding["token"])
        component = COMPONENTS[slot]
        hidden = next(task for task in parked["status"]["snapshot"]["tasks"] if task["token"] == tokens[component])
        require(not hidden["visible"] and not hidden["input_enabled"] and
                parked["membership"][parked["records"][component]["task"]] in parked["displays"],
                "Departed task was not parked hidden on a surviving claimed monitor")
        require(parked["records"][component]["key_downs"] == before["records"][component]["key_downs"] and
                parked["records"][component]["mouse_downs"] == before["records"][component]["mouse_downs"],
                "Hidden task received ordinary input")
        for frame in parked["frames"].values():
            if frame is not parked["frames"][0]: raw_audit.require_fixture_colors_absent(frame, component)
        require(task_tokens(restored) == tokens, "Redock replaced an opaque task token")
        for item in COMPONENTS.values():
            task = raw_audit.runtime_task(restored, item)
            record = restored["records"][item]
            window = raw_audit.task_window(restored, item, record["task"], record["display"],
                                          record["uid"], restored["identities"][item])
            raw_audit.task_input(restored, item, record["uid"], record["display"], window)
            actual_slot = restored["displays"][record["display"]]["slot"]
            require(actual_slot == next(s for s, value in COMPONENTS.items() if value == item), "Restored task is on wrong connector")
            raw_audit.require_fixture_colors(restored["frames"][actual_slot], item, record)
        require(restored["records"][component]["key_downs"] == before["records"][component]["key_downs"] + 1 and
                restored["records"][component]["mouse_downs"] == before["records"][component]["mouse_downs"] + 1,
                "Redocked exact task lacks one delivered keyboard and mouse input")
    return {"cycles": 20, "connectors": 3, "runtime_qualified": False, "qualification_claimed": False}


def audit_phases(stages):
    require([stage["name"] for stage in stages] == list(PHASE_NAMES), "Exactly 20 populated cycles and final recovery required")
    original = stages[0]
    audit_populated_cycles(stages[:61])
    exact_round_lifetimes(original, stages[61:])
    undocked, resumed, home = stages[-3:]
    require(all(undocked["membership"][row["task"]] == 0 for row in undocked["records"].values()) and
            undocked["focused_display"] == home["focused_display"] == 0,
            "Final undock did not preserve ordinary phone focus and native tasks")
    first = COMPONENTS[1]
    require(resumed["records"][first]["display"] == 0 and resumed["records"][first]["focused"] and
            resumed["records"][first]["key_downs"] == undocked["records"][first]["key_downs"] + 1 and
            resumed["records"][first]["mouse_downs"] == undocked["records"][first]["mouse_downs"] + 1,
            "Former external task lacks ordinary phone input recovery")
    return {"cycles": 20, "connectors": 3, "runtime_qualified": False, "qualification_claimed": False}


def audit_report(path):
    path = Path(path).resolve(strict=True); directory = path.parent; report = load(path)
    require(report.get("kind") == KIND and report.get("scope") == SCOPE and report.get("status") == "passed_one_clean_boot_not_runtime_qualified" and
            report.get("runtime_qualified") is False and report.get("qualification_claimed") is False and
            report.get("boot_count") == 1 and report.get("cycles") == 20 and report.get("container_stopped") is True,
            "Not a complete policy-free clean-boot report")
    require(0 < report["ended_monotonic_ns"] - report["started_monotonic_ns"] <= MAX_BOOT_NS,
            "Clean boot exceeds bounded total runtime")
    evidence = report["evidence_files"]
    contexts = [(directory, load(directory / "commands.json"), True),
                (directory / "runtime", load(directory / "runtime/commands.json"), False)]
    for relative, expected in evidence.items():
        target = directory / relative
        require(not target.is_symlink() and target.resolve(strict=True).is_relative_to(directory) and
                observations.reference_equal(observations.inventory_ref(target, directory, contexts, report["container_id"]), expected), "Evidence bytes/path changed")
    manifest = load(directory / "image-manifest.json"); validate_manifest(manifest)
    require(manifest["product_apk_present"] is False, "Product policy admitted")
    before, after = report["before"], report["after"]
    require(before["boot_id"] == after["boot_id"] == report["boot_id"] and
            before["protected_processes"] == after["protected_processes"] and
            set(before["protected_processes"]) == set(OS_NAMES), "Core OS/phone epoch changed or omitted")
    require(before["os_artifacts"] == after["os_artifacts"] == manifest["os_artifacts"] and
            after["installed"] == before["installed"], "OS or conformance artifact changed")
    validate_source_bindings(directory, report, manifest)
    require(set(report["source_files"]) == {"producer", "auditor", "runtime_status", "fresh_guest", "stream_mechanics", "raw_window_pixel_audit", "raw_observations"},
            "Missing reviewed host source closure")
    for role, source in report["source_files"].items():
        require(set(source) == {"path", "sha256", "bytes"} and Path(source["path"]).is_absolute() and
                file_ref(Path(source["path"])) == {key: source[key] for key in ("sha256", "bytes")},
                "Host source changed from original clean boot: " + role)
    require(report["source_files"]["auditor"]["path"] == str(Path(__file__).resolve()), "Wrong independent auditor source")
    owned = validate_owned_guest(directory, report, manifest)
    validate_runtime_trace(directory / "runtime", report, owned["child_window"])
    raw_audit.instrumentation_success((directory / "runtime/identity/instrumentation.txt").read_text(), report["conformance_run"])
    stages = [parse_stage(directory / "runtime", row, report["runtime_evidence"], report["uids"]) for row in report["stages"]]
    return audit_phases(stages)


def validate_source_bindings(directory, report, manifest):
    # Candidate/packet verification is reopened independently; mutable tag or
    # synthetic host fixture identity cannot stand in for an image binding.
    import phase1_conformance_acceptance as fresh_acceptance
    packet, product = Path(report["packet"]), Path(report["product"])
    receipt = load(packet / "receipt.json")
    fresh_acceptance.packet_tool.validate_receipt(packet, receipt, report["packet_receipt_sha256"], live_tools=False)
    require(sha256(directory / "packet-receipt.json") == report["packet_receipt_sha256"] ==
            manifest["packet"]["receipt_sha256"], "Selected packet binding changed")
    product_manifest = load(directory / "product-candidate-manifest.json")
    products, os_artifacts = fresh_acceptance.builder.verify_product(product, product_manifest)
    require(products == manifest["product_images"] and os_artifacts == manifest["os_artifacts"], "Product OS bytes differ")
    for role, filename in (("conformance", "conformance.apk"), ("fixture", "fixture.apk")):
        require(file_ref(packet / filename) == {key: manifest["artifacts"][role][key] for key in ("sha256", "bytes")},
                "Signed conformance/fixture artifact changed")
    freeze_path = packet / "evidence/compile-input/source-freeze.json"
    require(file_ref(freeze_path) == report["client_sources"]["source_freeze"], "Client compile freeze changed")
    freeze = load(freeze_path)
    require(set(report["client_sources"]["files"]) == set(CLIENT_FILES), "Incomplete exact client source binding")
    for relative, expected in report["client_sources"]["files"].items():
        require(freeze["files"].get(relative) == expected and
                file_ref(Path(__file__).resolve().parents[2] / relative) == expected,
                "Uncompiled or changed client replay source admitted")
    # The freeze is already independently bound to the signed packet's exact
    # unsigned APK payload by validate_receipt. Do not reseal an old packet.
    fresh_acceptance.candidate_offline(report["image_id"], manifest)


def validate_owned_guest(directory, report, manifest):
    import phase1_conformance_guest as fresh
    import phase1_conformance_recents_guest_acceptance as wrapper_audit
    record = load(directory / "prelaunch-userdata.json")
    require(record == report["prelaunch_state"] and record["authority"] == report["authority"], "Prelaunch authority differs")
    expected = {"runner": fresh.source_identity(Path(__file__).with_name("phase1_conformance_clean_boot.py")),
                "guest_common": fresh.source_identity(Path(fresh.__file__).resolve())}
    require(record["authority"] == expected, "Clean-boot sources changed from reviewed authority")
    fresh.validate_prelaunch_userdata(record, directory / "prelaunch-userdata.json", directory / "emulator-state", expected)
    return wrapper_audit._command_trace(directory / "commands.json", report, directory, manifest,
                                       report["before"], report["after"], record)


def validate_runtime_trace(directory, report, outer_window):
    trace = load(directory / "commands.json")
    require(isinstance(trace, list) and trace and [row.get("sequence") for row in trace] == list(range(len(trace))),
            "Missing or reordered runtime journal")
    prefix = ["docker", "exec", report["container_id"], "adb", "-s", "emulator-5580"]
    require(isinstance(outer_window, (tuple, list)) and len(outer_window) == 2 and
            all(type(value) is int for value in outer_window) and
            0 <= outer_window[0] < outer_window[1], "Missing exact outer protected epoch window")
    prior, starts, finishes, claims, identities = 0, [], [], {}, []
    for index, row in enumerate(trace):
        if row.get("kind") == "background_start":
            starts.append(index); began = row["started_monotonic_ns"]; ended = began
            argv = row["argv"]
            require(argv[:len(prefix)] == prefix and argv[-1] == runtime.RUNNER and
                    argv[len(prefix):len(prefix) + 3] == ["shell", "am", "instrument"] and
                    ["-e", "mode", "runtime"] == argv[argv.index("mode") - 1:argv.index("mode") + 2] and
                    report["conformance_run"] in argv, "Not actual held policy-free instrumentation")
        elif row.get("kind") == "background_finish":
            finishes.append(index); began = ended = row["ended_monotonic_ns"]
            require(row["returncode"] == 0 and row["id"] == "instrumentation-" + report["conformance_run"],
                    "Held instrumentation did not finish cleanly")
        elif row.get("kind") == "derived":
            require(row.get("evidence") == "identity/package-uids.txt", "Unreviewed derived runtime evidence")
            identities.append(row)
            continue
        else:
            require(row.get("kind") == "command" and type(row.get("returncode")) is int,
                    "Malformed runtime command")
            began, ended = row["started_monotonic_ns"], row["ended_monotonic_ns"]
            argv = row["argv"]
            require(isinstance(argv, list) and argv and all(isinstance(item, str) for item in argv), "Malformed runtime argv")
            require(not any("DesktopService" in value for value in argv) and
                    not any(value in argv for value in ("move-task", "remove-task", "force-stop", "wm")) and
                    not ("settings" in argv and any(word in argv for word in ("put", "delete", "reset"))),
                    "Product policy or task/settings repair used")
        require(type(began) is int and type(ended) is int and prior <= began <= ended, "Overlapping runtime timeline")
        require(outer_window[0] <= began <= ended <= outer_window[1],
                "Runtime command/process lifetime is outside actual outer protected epoch window")
        prior = ended
        if row.get("evidence"):
            relative = row["evidence"]
            require(relative not in claims and relative in report["runtime_evidence"] and
                    sha256(directory / relative) == row["output_sha256"], "Unbound or reused raw runtime observation")
            claims[relative] = index
    require(len(starts) == len(finishes) == 1 and starts[0] < finishes[0], "Runtime process lifetime was lost/replaced")
    require(len(identities) == 1, "Missing or duplicated authoritative package identity derivation")
    derived_uids = raw_audit.package_identity_derivation(trace, identities[0],
        report["runtime_evidence"], directory, report["container_id"])
    require(derived_uids == report["uids"], "Package UID summary differs from authoritative raw observations")
    commands = {"activities": ["dumpsys", "activity", "activities"], "fixture": ["dumpsys", "activity", FIXTURE],
                "windows": ["dumpsys", "window", "windows"], "window_displays": ["dumpsys", "window", "displays"],
                "input": ["dumpsys", "input"],
                "display": ["dumpsys", "display"], "conformance": ["dumpsys", "activity", "service", runtime.SERVICE],
                "events": ["logcat", "-b", "events", "-d", "-v", "threadtime", "am_anr:I", "am_crash:I", "*:S"]}
    previous_end = starts[0]
    for phase in report["stages"]:
        lo, hi = phase["trace_start"], phase["trace_end"]
        require(previous_end <= lo < hi <= finishes[0] and
                set(phase["files"]) == set(commands), "Stage journal ranges overlap or lose held process")
        previous_end = hi
        for kind, command in commands.items():
            index = claims.get(phase["files"][kind], -1)
            require(lo <= index < hi and trace[index]["argv"] == prefix + ["shell", *command] and
                    trace[index]["returncode"] == 0, "Stage raw command/role differs: " + kind)
        for name, metric in phase["processes"].items():
            indices = [claims.get(metric[field], -1) for field in ("pidof", "before", "after")]
            require(indices == list(range(indices[0], indices[0] + 3)) and lo <= indices[0] < indices[-1] < hi,
                    "Protected PID/proc fencing is not adjacent")
            expected = [prefix + ["shell", "pidof", name],
                        *[prefix + ["shell", "su", "0", "cat", f"/proc/{metric['pid']}/stat"] for _ in range(2)]]
            require([trace[index]["argv"] for index in indices] == expected and
                    all(trace[index]["returncode"] == 0 for index in indices), "Protected epoch command changed")
        for slot, relative in phase["frames"].items():
            index = claims.get(relative, -1)
            require(lo <= index < hi and trace[index]["returncode"] == 0, "Framebuffer not captured inside exact phase")
            argv = trace[index]["argv"]
            if slot == "0":
                require(argv == prefix + ["exec-out", "screencap", "-p"], "Phone framebuffer did not come from real screencap")
            else:
                require(argv[:2] == ["docker", "cp"] and len(argv) == 4 and
                        argv[2].startswith(report["container_id"] + ":/state/phase1-recents-") and
                        Path(argv[3]) == directory / relative, "External framebuffer copy is not owned")
                remote = argv[2].split(":", 1)[1].rsplit("/", 1)[0]
                expected_shot = prefix + ["emu", "screenrecord", "screenshot", "--display", slot, remote]
                shot = [row for row in trace[lo:index] if row.get("argv") == expected_shot]
                require(len(shot) == 1 and shot[0]["returncode"] == 0 and "OK" in shot[0].get("output", "") and
                        "KO:" not in shot[0].get("output", ""), "External frame is not exact console slot capture")
    controls = []
    nonces = set()
    for row in trace:
        argv = row.get("argv", [])
        command_prefix = prefix + ["shell", "dumpsys", "activity", "service", runtime.SERVICE, "runtime-command"]
        if argv[:len(command_prefix)] != command_prefix: continue
        require(len(argv) == len(command_prefix) + 3 and argv[-3] == report["conformance_run"] and
                runtime.HEX32.fullmatch(argv[-2]) and argv[-2] not in nonces and row["returncode"] == 0,
                "Malformed or replayed runtime host nonce")
        nonces.add(argv[-2]); controls.append(argv[-1])
        marker = runtime.CONTROL_MARKER + "accepted " + " ".join(argv[-3:])
        require(sum(line.strip() == marker for line in row.get("output", "").splitlines()) == 1,
                "Raw runtime control was not accepted")
    require(controls == [phase for _ in range(20) for phase in ("remember-observed", "restore-observed")] + ["stop"],
            "Missing explicit observed-replay or owned-stop phase")
    # Reconstruct every one of the twenty connector removals/additions from
    # actual successful console commands, not booleans or a producer counter.
    observed = []
    for row in trace:
        argv = row.get("argv", [])
        if argv[:len(prefix) + 2] == prefix + ["emu", "multidisplay"]:
            command = argv[len(prefix):]
            require(row["returncode"] == 0 and "OK" in row.get("output", "") and "KO:" not in row.get("output", ""),
                    "Emulator connector command failed")
            observed.append(command)
    expected = [["emu", "multidisplay", "add", str(slot), *map(str, SPECS[slot]), "132165"] for slot in (1, 2, 3)]
    for cycle, slot in slot_plan():
        expected += [["emu", "multidisplay", "del", str(slot)],
                     ["emu", "multidisplay", "add", str(slot), *map(str, SPECS[slot]), "132165"]]
    expected += [["emu", "multidisplay", "del", str(slot)] for slot in (3, 2, 1)]
    require(observed == expected, "Not exactly the required three-monitor/20-cycle/final-undock console plan")
    phases = report["stages"]
    # Ordered raw commands must separate BEFORE/PARKED/RESTORED observations;
    # otherwise the right pixels copied from a different cycle could pass.
    for offset, (cycle, slot) in enumerate(slot_plan()):
        before, parked, restored = phases[1 + offset * 3:4 + offset * 3]
        intervals = ((before["trace_end"], parked["trace_start"], "del"),
                     (parked["trace_end"], restored["trace_start"], "add"))
        for lo, hi, operation in intervals:
            expected = prefix + ["emu", "multidisplay", operation, str(slot)]
            if operation == "add": expected += [*map(str, SPECS[slot]), "132165"]
            require(sum(row.get("argv") == expected for row in trace[lo:hi]) == 1,
                    "Physical connector action does not bracket exact cycle phase")
