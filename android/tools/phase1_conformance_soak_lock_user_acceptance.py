#!/usr/bin/env python3
"""Independent original raw semantics for three bounded attachment actions.

Not a full campaign auditor. A caller must supply the independently admitted
original guest contract/identity; an action summary cannot authenticate itself.
"""
from pathlib import Path
from io import BytesIO
import json
import hashlib
import os
import re
import stat
import xml.etree.ElementTree as ET
from PIL import Image

import conformance_runtime as runtime
import phase1_conformance_clean_boot as lane
import phase1_conformance_soak_expectation as expectation
import phase1_conformance_soak_contract as contract
import phase1_conformance_soak_health as health
import phase1_conformance_soak_health_acceptance as health_audit
import native_input_consumers as input_consumers
import lock_smoke as lock
import user_switch_smoke as user_helpers
from phase1_conformance_common import file_ref, load
import phase1_conformance_observations as observations

KIND = "phase1_policy_free_lock_user_attachment_action_v1"
STATUS = "passed_bounded_original_raw_action_not_whole_campaign"
require = runtime.require
MAX_UNLOCK_INPUT_NS = 8_000_000_000  # Conservative input window below stock keyguard's 10000ms.


def phone_asleep(raw):
    """Exact stock KeyguardServiceDelegate spellings, not merely !awake."""
    return re.findall(r"^\s*screenState=(\S+)\s*$", raw, re.M) == ["SCREEN_STATE_OFF"] and \
        re.findall(r"^\s*interactiveState=(\S+)\s*$", raw, re.M) == ["INTERACTIVE_STATE_SLEEP"]


def require_single_marker(raw, marker):
    # Substring membership discovers malformed/prefixed lines for rejection;
    # acceptance requires one COMPLETE stripped line beginning with marker.
    rows = [line.strip() for line in raw.splitlines() if marker.rstrip() in line]
    require(len(rows) == 1 and rows[0].startswith(marker), "Missing/extra/malformed complete original marker")
    return rows[0]


def require_control_marker(raw, expected):
    require(require_single_marker(raw, runtime.CONTROL_MARKER) == expected, "Actual singleton nonce control rejected")


def require_expectation_marker(raw, original=None):
    require_single_marker(raw, expectation.MARKER)
    value = expectation.parse(raw)
    if original is not None:
        require(value is not None and value == {**original, "state": value["state"]},
            "Foreign/missing original exact lease/reason or expectation nonce/deadline")
    return value


def require_poll_expectation_marker(raw, original=None):
    require(not any(runtime.CONTROL_MARKER.rstrip() in line for line in raw.splitlines()),
        "Unexpected control marker in ordinary original poll")
    return require_expectation_marker(raw, original)


def observed_ref(path, trace, root, container=None):
    """Exact events/root diff, or existing strict secondary-package absence."""
    path, root = observations.canonical_path(path, root)
    if path.stat().st_size: return file_ref(path)
    relative = str(path.relative_to(root))
    rows = [row for row in trace if row.get("evidence") == relative]
    # Legacy producer calls supply their whole owned trace. The completed
    # auditor always passes the independently admitted exact container below.
    if container is None:
        owned = {row["argv"][2] for row in trace if row.get("argv", [])[:2] == ["docker", "exec"]}
        require(len(owned) == 1, "Ambiguous original action container")
        container = owned.pop()
    if len(rows) == 1 and rows[0].get("argv") in (
            ["docker", "exec", container, "adb", "-s", "emulator-5580", "shell", *observations.EVENTS],
            ["docker", "container", "diff", container]):
        return observations.command_ref(path, root, trace, container)
    require(len(rows) == 1 and rows[0]["kind"] == "command" and rows[0]["returncode"] == 0 and len(rows[0]["argv"]) == 13 and
        type(rows[0]["returncode"]) is int and rows[0]["output_sha256"] == observations.EMPTY_SHA256 and
        rows[0]["argv"][:6] == ["docker", "exec", container, "adb", "-s", "emulator-5580"] and
        rows[0]["argv"][6:11] == ["shell", "pm", "list", "packages", "--user"] and
        re.fullmatch(r"[1-9][0-9]*", rows[0]["argv"][11]) and 10 <= int(rows[0]["argv"][11]) <= 1000 and
        rows[0]["argv"][12:] == [rows[0]["argv"][12],] and rows[0]["argv"][12] in {runtime.PACKAGE, lane.acceptance.FIXTURE},
        "Empty file is not an original exact owned secondary-package absence")
    return observations.empty_ref(path)


def package_uid(raw, package, user):
    # PackageManagerShellCommand applies its positional filter with contains(),
    # not exact equality. Preserve/validate the complete original response, then
    # select the one exact package rather than mistaking overlays for ambiguity.
    error = "Missing/ambiguous exact package/user UID"
    require(type(raw) is str and type(package) is str and type(user) is int and user >= 0, error)
    lines = raw.splitlines(); seen = {}; target = None
    require(lines and raw in ("\n".join(lines), "\n".join(lines) + "\n"), error)
    for line in lines:
        match = re.fullmatch(r"package:([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*) uid:([1-9][0-9]*)", line)
        require(match is not None, error)
        name, uid = match[1], int(match[2])
        require(package in name and name not in seen and uid <= 2**31 - 1 and uid // 100000 == user, error)
        seen[name] = uid
        if name == package: target = uid
    require(target is not None, error)
    return target


def process_metric(raw, uid, name):
    before = health.qualified_pid(raw["pid_before"], raw["ps_before"], name, uid)
    return health.process_metric(raw, before, name=name, expected_uid=uid)


def service_owner(raw, pid):
    expected = r"^SERVICE " + re.escape(runtime.SERVICE) + r" [0-9a-f]+ pid=" + str(pid) + r" user=0\s*$"
    require(len(re.findall(expected, raw, re.M)) == 1 and len(re.findall(r"^SERVICE [^\n]+$", raw, re.M)) == 1,
        "Runtime marker lacks its unique actual held-client service/process owner")


def audit_role_uid_admission(root, proof, trace, admitted_identity):
    """Re-derive the map handed to the observer, never trust its summary."""
    import phase1_conformance_soak_lock_user_actions as producer
    root = Path(root).absolute()
    require(proof["kind"] == "original_owned_user0_role_uid_admission_v1" and proof["identity"] == admitted_identity and
        proof["sources"] == producer.source_contract(), "Foreign/current-source UID admission")
    files = proof["files"]; consumed = set(); uids, epochs = {}, {}
    def read(role, key, command):
        record = files[role + "-" + key]; index = record["trace_index"]
        require(type(index) is int and 0 <= index < len(trace), "UID admission lacks original trace row")
        target = root / record["path"]; row = trace[index]
        require(not target.is_symlink() and target.resolve(strict=True) == target and target.is_relative_to(root) and
            file_ref(target) == {field: record[field] for field in ("sha256", "bytes")} and
            row["kind"] == "command" and row["returncode"] == 0 and row["evidence"] == record["path"] and
            row["output_sha256"] == record["sha256"] and row["argv"] == ["docker", "exec", admitted_identity["container_id"],
                "adb", "-s", "emulator-5580", "shell", *map(str, command)] and index not in consumed, "Unbound/aliased UID admission raw command")
        consumed.add(index); return target.read_text()
    for role, package in contract.PROCESS_NAMES.items():
        uid = 1000 if role == "system_server" else package_uid(read(role, "package-uid", ("pm", "list", "packages", "-U", "--user", "0", package)), package, 0)
        raw = {"pid_before": read(role, "pid-before", ("pidof", package)), "ps_before": read(role, "ps-before", health.PROCESS_TABLE_COMMAND)}
        pid = health.qualified_pid(raw["pid_before"], raw["ps_before"], package, uid)
        for key, command in (("stat_before", ("su", "0", "cat", f"/proc/{pid}/stat")), ("status", ("su", "0", "cat", f"/proc/{pid}/status")),
            ("fd", ("su", "0", "ls", "-1", f"/proc/{pid}/fd")), ("stat_after", ("su", "0", "cat", f"/proc/{pid}/stat")),
            ("pid_after", ("pidof", package)), ("ps_after", health.PROCESS_TABLE_COMMAND)):
            raw[key] = read(role, key.replace("_", "-"), command)
        metric = process_metric(raw, uid, package); uids[role] = uid; epochs[role] = {key: metric[key] for key in ("pid", "start_ticks")}
    require(uids == proof["role_uids"] and epochs == proof["epochs"] and len(consumed) == len(files), "UID/epoch map differs from original admission")
    return {"role_uids": uids, "epochs": epochs, "runtime_qualified": False}


def phone_home_user(activities, displays, windows, user):
    """Parameterize ONLY Home's exact user field in the original strict audit.

    Before scoped normalization every phone/global native focus must explicitly
    name this actual user. Foreign phone identity cannot become a user0 match.
    No owner fixture/root fields or arbitrary strings are rewritten.
    """
    require(type(user) is int and user >= 0, "Invalid exact Home user")
    if user == 0: return lane.raw_audit.phone_home_focus(activities, displays, windows)
    home, window = lane.raw_audit.PHONE_HOME_COMPONENT, lane.raw_audit.PHONE_HOME_WINDOW
    sections = re.findall(r"^Display #0 \(activities from top to bottom\):\n(.*?)(?=^Display #[0-9]+ |\Z)", activities, re.M | re.S)
    native = re.findall(r"^[ \t]*Display: mDisplayId=0[^\n]*\n(.*?)(?=^[ \t]*Display: mDisplayId=[0-9]+|\Z)", displays, re.M | re.S)
    require(len(sections) == len(native) == 1 and re.findall(r"^[ \t]*topResumedActivity=([^\n]*)$", sections[0], re.M) and
        all(re.fullmatch(r"ActivityRecord\{[0-9a-f]+ u" + str(user) + " " + re.escape(home) + r" t[1-9][0-9]*\}", row.strip())
            for row in re.findall(r"^[ \t]*topResumedActivity=([^\n]*)$", sections[0], re.M) + re.findall(r"^[ \t]*ResumedActivity:([^\n]*)$", activities, re.M)) and
        re.search(r"\bU=" + str(user) + r"\b", sections[0]) and
        re.findall(r"^[ \t]*mCurrentFocus=Window\{[0-9a-f]+ u" + str(user) + " " + re.escape(window) + r"\}\s*$", native[0], re.M) and
        re.findall(r"^[ \t]*mFocusedApp=ActivityRecord\{[0-9a-f]+ u" + str(user) + " " + re.escape(home) + r" t[1-9][0-9]*\}\s*$", native[0], re.M),
        "Secondary phone/Home focus is not exact active-user identity")
    def normalize(raw):
        raw = re.sub(r"\bu" + str(user) + " (?=" + re.escape(home) + " |" + re.escape(window) + r"\})", "u0 ", raw)
        return re.sub(r"(?m)^([ \t]*\* Task\{[^\n}]*\btype=home\b[^\n}]*\bU=)" + str(user) + r"\b", r"\g<1>0", raw)
    return lane.raw_audit.phone_home_focus(normalize(activities), normalize(displays), normalize(windows))


def parse_capture(root, row, action, trace):
    root = Path(root)
    indexed = {record["sequence"]: record for record in trace}; evidence = {}
    def read(relative, args):
        target = root / relative
        expected_prefix = f"soak-actions/{action['ordinal']:06d}-{action['scenario']}-{action['nonce']}/captures/{row['name']}/"
        require(relative.startswith(expected_prefix) and not target.is_symlink() and target.resolve(strict=True).is_relative_to(root), "Aliased action raw evidence")
        rows = [command for command in trace if command.get("evidence") == relative]
        require(len(rows) == 1 and rows[0]["kind"] == "command" and rows[0]["returncode"] == 0 and
            rows[0]["argv"] == ["docker", "exec", action["identity"]["container_id"], "adb", "-s", "emulator-5580", "shell", *map(str, args)] and
            rows[0]["output_sha256"] == observed_ref(target, trace, root, action["identity"]["container_id"])["sha256"] and
            row["trace_start"] <= rows[0]["sequence"] < row["trace_end"] and
            row["began_monotonic_ns"] <= rows[0]["started_monotonic_ns"] <= rows[0]["ended_monotonic_ns"] <= row["ended_monotonic_ns"],
            "Capture does not bind one actual original command/time")
        evidence[relative] = observed_ref(target, trace, root, action["identity"]["container_id"])
        return target.read_text()
    commands = {"activities": ("dumpsys", "activity", "activities"),
        "fixture": ("dumpsys", "activity", "--user", "0", lane.acceptance.FIXTURE),
        "windows": ("dumpsys", "window", "windows"), "window_displays": ("dumpsys", "window", "displays"),
        "input": ("dumpsys", "input"), "display": ("dumpsys", "display"),
        "conformance": ("dumpsys", "activity", "--user", "0", "service", runtime.SERVICE),
        "keyguard": ("dumpsys", "activity", "--user", "0", "service", "com.android.systemui/.SystemUIService"),
        "policy": ("dumpsys", "window", "policy"), "current_user": ("am", "get-current-user"),
        "users": ("dumpsys", "user"), "events": ("logcat", "-b", "events", "-d", "-v", "threadtime", "am_anr:I", "am_crash:I", "*:S"),
        "modem": ("getprop", health.phone.MODEM_PROPERTY), "radio": ("su", "0", "service", "list"),
        "boot": ("cat", "/proc/sys/kernel/random/boot_id")}
    commands["home_uid"] = ("pm", "list", "packages", "-U", "--user", str(row["user"]), lane.raw_audit.LAUNCHER)
    require(set(row["files"]) == set(commands), "Missing raw action observations")
    raw = {key: read(row["files"][key], command) for key, command in commands.items()}
    require_poll_expectation_marker(raw["conformance"], action.get("expectation") if row["name"] != "before" else None)
    require(raw["current_user"].strip() == str(row["user"]) and raw["boot"].strip() == action["identity"]["boot_id"] and
        not health_audit.protected_events(raw["events"]) and not lane.acceptance.crash_events(raw["events"]), "Foreign boot/user or actual crash/ANR")
    processes = {}
    require(set(row["processes"]) == set(contract.PROCESS_NAMES), "All five actual UID/process roles required")
    for role, package in contract.PROCESS_NAMES.items():
        metric = row["processes"][role]
        uid = 1000 if role == "system_server" else package_uid(read(metric["package_uid"],
            ("pm", "list", "packages", "-U", "--user", "0", package)), package, 0)
        values = {}
        for key, relative in metric["files"].items():
            command = ("pidof", package) if key in {"pid_before", "pid_after"} else health.PROCESS_TABLE_COMMAND if key.startswith("ps") else (
                "su", "0", *(("ls", "-1") if key == "fd" else ("cat",)), f"/proc/{metric['pid']}/" + ("stat" if key in {"stat_before", "stat_after"} else key))
            values[key] = read(relative, command)
        actual = process_metric(values, uid, package)
        require(actual == {key: metric[key] for key in actual}, "Process summary/UID differs from actual fenced bytes")
        processes[role] = actual
    require(len({value["pid"] for value in processes.values()}) == 5, "Aliased protected process")
    displays = lane.raw_audit.logical_displays(raw["display"])
    require({value["slot"] for value in displays.values()} == {1, 2, 3}, "All three exact monitors must remain attached")
    records, membership, identities = lane.acceptance.fixture_lifetimes(raw["fixture"], raw["activities"], action["uids"][lane.acceptance.FIXTURE])
    require(set(records) == set(lane.acceptance.COMPONENTS.values()), "Exact populated three-task lifetime inventory required")
    status = runtime.parse_status(raw["conformance"])
    require(status["run"] == action["run"] and status["failure"] is None and status["control_error"] is None, "Held runtime changed/failed")
    service_owner(raw["conformance"], processes["client"]["pid"])
    frames = {}; require(set(row["frames"]) == {"0", "1", "2", "3"}, "Phone plus all three monitor frames required")
    offset = trace[0]["sequence"]
    for slot, relative in row["frames"].items():
        require(relative == f"soak-actions/{action['ordinal']:06d}-{action['scenario']}-{action['nonce']}/captures/{row['name']}/frame-{slot}.png", "Aliased original frame path")
        lane.raw_audit.validate_frame_trace(trace, row["trace_start"] - offset, row["trace_end"] - offset, root,
            action["identity"]["container_id"], int(slot), relative)
        display = 0 if slot == "0" else next(display for display, value in displays.items() if value["slot"] == int(slot))
        regions = {component: [record[field] for field in ("left", "top", "right", "bottom")]
            for component, record in records.items() if record["native_display"] == display}
        payload = (root / relative).read_bytes(); value = lane.raw_audit.png_info(payload, regions)
        expected = (1080, 2400) if slot == "0" else lane.acceptance.SPECS[int(slot)][:2]
        require((value["width"], value["height"]) == expected, "Wrong exact monitor/phone pixels")
        with Image.open(BytesIO(payload)) as image:
            extrema = image.convert("RGBA").getextrema()
            value["opaque_black"] = extrema == ((0, 0), (0, 0), (0, 0), (255, 255))
            value["rgb_nonblack"] = any(maximum > 0 for _minimum, maximum in extrema[:3])
        frames[int(slot)] = value
    return {"row": row, "raw": raw, "status": status, "records": records, "membership": membership,
        "identities": identities, "displays": displays, "processes": processes, "frames": frames,
        "modem": health.phone.modem_port(raw["modem"]), "radio": health.phone.radio_services(raw["radio"]),
        "home_uid": package_uid(raw["home_uid"], lane.raw_audit.LAUNCHER, row["user"])}


def require_task_sink_clearance(stage, component, uid, display, window_token):
    """Reject an intercepting fixed transparent shell sink above the exact app.

    InputDispatcher traverses its per-display window vector front-to-back.
    NO_INPUT_CHANNEL is not a pass-through flag: a selected sink drops motion.
    Only NOT_VISIBLE/NOT_TOUCHABLE make the transparent shell's sink harmless
    here. Ordinary app/dialog sinks keep Android's own touch/crop protection;
    their presence, overlap or flags are not an OS-bridge exemption or defect.
    Retain full raw input and require its original complete ordered inventory.
    """
    rows, _connections = input_consumers.dispatcher_windows(stage['raw']['input'])
    full = component.replace('/.', '/' + lane.acceptance.FIXTURE + '.')
    field = input_consumers.field
    targets = [index for index, row in enumerate(rows) if
        field(row, 'name', r'[^,]+') == window_token + ' ' + full and
        int(field(row, 'displayId', r'[0-9]+')) == display and int(field(row, 'ownerUid', r'[0-9]+')) == uid]
    require(len(targets) == 1 and int(field(rows[targets[0]], 'ownerPid', r'[0-9]+')) == stage['records'][component]['pid'],
        'Missing/foreign actual managed app input layer for sink clearance')
    for row in rows[:targets[0]]:
        if int(field(row, 'displayId', r'[0-9]+')) != display: continue
        name = field(row, 'name', r'[^,]+')
        if 'ActivityRecordInputSink' not in name: continue
        # Discover purported fixed-shell names before requiring the exact
        # source-generated spelling. Do not impose this facade invariant on
        # another app's legitimate tapjacking/cropped Activity input sink.
        if not re.search(r'(?<![A-Za-z0-9_.])' + re.escape(runtime.PACKAGE) +
                r'(?:/|\s).*ExternalShellActivity', name): continue
        parts = field(row, 'inputConfig', r'[^,]+').split(' | ')
        flags = set(parts)
        require(re.fullmatch(r'[0-9a-f]+ ActivityRecordInputSink ' +
                re.escape(runtime.PACKAGE + '/.ExternalShellActivity'), name) and
            len(parts) == len(flags) and all(re.fullmatch(r'[A-Z][A-Z_]+', value) for value in parts) and
            'NO_INPUT_CHANNEL' in flags and 'SPY' not in flags and int(field(row, 'ownerUid', r'[0-9]+')) == 1000 and
            int(field(row, 'ownerPid', r'[0-9]+')) == stage['processes']['system_server']['pid'],
            'Malformed/foreign ActivityRecordInputSink above actual managed app')
        require(flags & {'NOT_TOUCHABLE', 'NOT_VISIBLE'},
            'Active orphan/retired ActivityRecordInputSink above actual managed app: ' + name)


def ready(stage, action):
    raw, status, displays = stage["raw"], stage["status"], stage["displays"]
    require(stage["row"]["user"] == 0 and status["state"] == "ready" and status["runtime_readiness"]["ready"], "Original owner lease is not actually ready")
    stage["broker_displays"] = lane.raw_audit.runtime_display_incarnations(status, displays)
    shells = lane.raw_audit.shell_incarnations(raw["activities"], raw["windows"], raw["input"],
        status["snapshot"]["generation"], action["uids"][runtime.PACKAGE], displays)
    require(set(shells) == set(displays) and all(shells[d]["token"] == stage["broker_displays"][d]["token"] for d in displays), "Actual ready shell/current display mismatch")
    lane.acceptance.stock_chrome(raw["windows"], raw["input"], displays)
    stage["roots"] = lane.acceptance.native_roots(raw["activities"], displays, status["snapshot"], action["uids"][runtime.PACKAGE], action["uids"][lane.acceptance.FIXTURE])
    phone_home_user(raw["activities"], raw["window_displays"], raw["windows"], 0)
    require(stage["frames"][0]["rgb_nonblack"], "Ordinary phone Home frame is entirely black")
    for component, record in stage["records"].items():
        require(record["native_display"] == record["display"] and record["native_display"] in displays, "Ready task left exact native monitor")
        lane.raw_audit.runtime_task(stage, component)
        window = lane.raw_audit.task_window(stage, component, record["task"], record["display"], record["uid"], stage["identities"][component])
        lane.raw_audit.task_input(stage, component, record["uid"], record["display"], window)
        require_task_sink_clearance(stage, component, record['uid'], record['display'], window)
        lane.raw_audit.require_fixture_colors(stage["frames"][displays[record["display"]]["slot"]], component, record)


def inactive(original, stage, action):
    expectation.require_consumed(stage["raw"]["conformance"], action["run"], action["expectation"])
    require(stage["displays"] == original["displays"], "Lock/user transition changed exact connector identity/geometry")
    require(lane.raw_audit.focused_display(stage["raw"]["windows"]) == 0, "Inactive authority stole global phone focus")
    for component, record in stage["records"].items():
        prior = original["records"][component]
        require(stage["identities"][component] == original["identities"][component] and record["focused"] is False and
            record["lifecycle"] == "stopped" and all(record[key] == prior[key] for key in ("task", "instance", "pid", "uid", "key_downs", "pointer_downs", "mouse_downs")),
            "Inactive exact task was replaced, focused, resumed or accepted ordinary input")
    rows, _connections = input_consumers.dispatcher_windows(stage["raw"]["input"])
    for row in rows:
        display = int(input_consumers.field(row, "displayId", r"[0-9]+"))
        flags = set(input_consumers.field(row, "inputConfig", r"[^,]+").split(" | "))
        uid = int(input_consumers.field(row, "ownerUid", r"[0-9]+"))
        require(not (uid in {action["uids"][runtime.PACKAGE], action["uids"][lane.acceptance.FIXTURE]} and
            "NOT_VISIBLE" not in flags and ("SPY" in flags or "DROP_INPUT" not in flags)), "Inactive owner retains real input authority")
        require(not (display == 0 and uid == action["uids"][runtime.PACKAGE] and "SPY" in flags), "Owner spy leaked onto phone")
    for display, info in stage["displays"].items():
        infrastructure = [row for row in rows if input_consumers.field(row, "displayId", r"[0-9]+") == str(display) and
            input_consumers.field(row, "name", r"[^,]+") == "PointerEventDispatcherOverlay" + str(display) and
            input_consumers.field(row, "ownerUid", r"[0-9]+") == "1000" and
            set(value.strip() for value in input_consumers.field(row, "inputConfig", r"[^,]+").split("|")) == {"NOT_FOCUSABLE", "TRUSTED_OVERLAY", "SPY", "DO_NOT_PILFER"}]
        require(len(infrastructure) == 1, "Inactive display lost exact OS pointer-dispatcher infrastructure")
        input_consumers.consumers(stage["raw"]["input"], display, info["width"], info["height"], stage["processes"]["system_server"]["pid"])
        require(stage["frames"][info["slot"]]["opaque_black"], "Inactive external monitor is not exact opaque black")
    for block in re.split(r"(?=^\s*Window #\d+ Window\{)", stage["raw"]["windows"], flags=re.M):
        own = re.search(r"\bmOwnerUid=(" + str(action["uids"][runtime.PACKAGE]) + "|" + str(action["uids"][lane.acceptance.FIXTURE]) + r")\b", block)
        require(not own or not ("isVisible=true" in block and "isOnScreen=true" in block and "mHasSurface=true" in block), "Inactive owner retains a surfaced visible native window")
    if action["scenario"] != "user_switch":
        require(lock.keyguard_state(stage["raw"]["keyguard"]) == {"mShowing": True, "mSecure": True, "mCanDismissLockScreen": False} and
            lock.phone_awake(stage["raw"]["policy"]), "Secure awake original phone keyguard not actually observed")
    else:
        require(stage["row"]["user"] == action["secondary"]["id"], "Foreign inactive user")
        phone_home_user(stage["raw"]["activities"], stage["raw"]["window_displays"], stage["raw"]["windows"], stage["row"]["user"])
        require(stage["frames"][0]["rgb_nonblack"], "Ordinary secondary-user phone Home frame is entirely black")
        require(stage["home_uid"] == stage["row"]["user"] * 100000 + original["home_uid"], "Secondary actual Home UID is foreign")
        windows = re.findall(r"Window #\d+ Window\{[0-9a-f]+ u" + str(stage["row"]["user"]) + " " + re.escape(lane.raw_audit.PHONE_HOME_WINDOW) +
            r"\}:\n(.*?)(?=\s*Window #\d+ Window\{|\Z)", stage["raw"]["windows"], re.S)
        require(len(windows) == 1 and re.search(r"\bmOwnerUid=" + str(stage["home_uid"]) + r"\b", windows[0]), "Secondary Home window does not prove actual active-user UID")


def task_description(task):
    return tuple(task[key] for key in ("package_name", "title", "minimum_width", "minimum_height", "resizable"))


def descriptive_tasks(snapshot):
    values = {task_description(task): task for task in snapshot["tasks"]}
    require(values and len(values) == len(snapshot["tasks"]) and
        len({task["token"] for task in values.values()}) == len(values),
        "Recovery task descriptions/current tokens are missing or ambiguous")
    return values


def recovery_layout(original, current):
    """Compare descriptive layout, never promote remembered opaque authority.

    Android task/activity lifetimes are independently fenced by audit_action.
    Current task/display tokens are obtained only from this actual new lease.
    An epoch is opaque positive identity, not a caller-inferred counter.
    """
    old = original["status"]["snapshot"]; new = current["status"]["snapshot"]
    require(new["generation"] > 0 and new["generation"] != old["generation"] and new["identity_epoch"] > 0 and
        current["displays"] == original["displays"], "Recovery reused generation or changed actual physical connectors")
    # Every attachment using this helper separately forbids system-server
    # restart. APK, SystemUI and lease replacement do not create its identity
    # namespace; accepting a different positive value would waive the SDK.
    require(new["identity_epoch"] == old["identity_epoch"],
        "Recovery changed identityEpoch without a system-server namespace restart")
    previous, live = descriptive_tasks(old), descriptive_tasks(new)
    require(set(previous) == set(live) and len(previous) == len(original["records"]),
        "Recovery changed the complete exact observed task description/constraints inventory")
    for component in original["records"]:
        saved = lane.raw_audit.runtime_task(original, component)
        task = lane.raw_audit.runtime_task(current, component)
        require(task_description(saved) == task_description(task) and
            all(task[key] == saved[key] for key in ("bounds", "visible", "input_enabled", "z_order")),
            "Recovery changed exact saved descriptive geometry/z/visibility/input")
        old_display = next(display for display in old["display_incarnations"] if display["token"] == saved["display_token"])
        destinations = [display for display in new["display_incarnations"] if display["identity_hint"] == old_display["identity_hint"]]
        require(len(destinations) == 1 and task["display_token"] == destinations[0]["token"] and
            all(destinations[0][key] == old_display[key] for key in ("bounds", "density_dpi")),
            "Recovery did not use the current exact physical destination incarnation")


def credential_unlock_trace(root, action, trace, sleep_sequence, pin_text):
    """Derive the fresh ordinary screen/input window from original raw rows."""
    shell = ["docker", "exec", action["identity"]["container_id"], "adb", "-s", "emulator-5580", "shell"]
    sleep_rows = [row for row in trace if row["sequence"] == sleep_sequence]
    require(len(sleep_rows) == 1 and sleep_rows[0]["argv"] == shell +
        ["input", "keyboard", "-d", "0", "keyevent", "KEYCODE_SLEEP"], "Unlock sleep must target exact phone-zero keyboard")
    rows = [row for row in trace if sleep_sequence < row["sequence"] < pin_text["sequence"]]
    wake = [row for row in rows if row["argv"] == shell + ["input", "keyboard", "-d", "0", "keyevent", "KEYCODE_WAKEUP"]]
    swipe = [row for row in rows if row["argv"] == shell + ["input", "touchscreen", "-d", "0", "swipe", "540", "1800", "540", "400", "600"]]
    require(len(wake) == len(swipe) == 1 and wake[0]["sequence"] < swipe[0]["sequence"], "One exact ordinary fresh wake/swipe required")
    wake, swipe = wake[0], swipe[0]
    policy = [row for row in rows if row["argv"] == shell + ["dumpsys", "window", "policy"]]
    asleep = [row for row in policy if row["sequence"] < wake["sequence"]]
    awake = [row for row in policy if wake["sequence"] < row["sequence"] < swipe["sequence"]]
    after = [row for row in policy if swipe["sequence"] < row["sequence"]]
    require(asleep and awake and len(after) == 1, "Missing independently retained sleep/wake/post-swipe policy fences")
    prefix = f"soak-actions/{action['ordinal']:06d}-{action['scenario']}-{action['nonce']}/"
    def raw(row, expected_prefix):
        relative = row.get("evidence", "")
        require(relative.startswith(expected_prefix) and sum(other.get("evidence") == relative for other in trace) == 1,
            "Aliased/missing original unlock read")
        require(observed_ref(root / relative, trace, root, action["identity"]["container_id"])["sha256"] == row["output_sha256"],
            "Original unlock raw bytes changed")
        return (root / relative).read_text()
    require(phone_asleep(raw(asleep[-1], prefix + "reads/")) and
        lock.phone_awake(raw(awake[-1], prefix + "reads/")) and lock.phone_awake(raw(after[0], prefix + "reads/")),
        "Original phone did not complete exact OFF/SLEEP then ON/AWAKE input fences")
    require(asleep[-1]["ended_monotonic_ns"] <= wake["started_monotonic_ns"] and
        awake[-1]["ended_monotonic_ns"] <= swipe["started_monotonic_ns"] and
        swipe["ended_monotonic_ns"] <= after[0]["started_monotonic_ns"] and
        0 < after[0]["ended_monotonic_ns"] - wake["started_monotonic_ns"] < MAX_UNLOCK_INPUT_NS,
        "Original PIN swipe escaped fresh bounded awake input window")
    entries = [row for row in rows if row.get("evidence", "").startswith(prefix + "credential-entry-") and
        row.get("evidence", "").endswith(".xml") and after[0]["sequence"] < row["sequence"]]
    require(entries, "No original system PIN hierarchy before generated credential input")
    found = False
    for row in entries:
        nodes = [node for node in ET.fromstring(raw(row, prefix + "credential-entry-")).iter("node") if
            node.get("package") == "com.android.systemui" and node.get("enabled") == "true" and
            (node.get("password") == "true" or node.get("resource-id", "").endswith(":id/pinEntry"))]
        require(len(nodes) <= 1, "Ambiguous original system PIN field")
        found = found or bool(nodes)
    require(found, "No actual enabled system PIN field before generated credential input")


def trace_semantics(root, action, trace, before, recovered, *, client_sequences=()):
    container = action["identity"]["container_id"]
    shell = ["docker", "exec", container, "adb", "-s", "emulator-5580", "shell"]
    statuses = []; controls = []; triggers = []; privileged = []
    frame_rows = set()
    for capture in action["captures"]:
        for slot, relative in capture["frames"].items():
            indices = [index for index, row in enumerate(trace) if row.get("evidence") == relative]
            require(len(indices) == 1, "One actual frame command required")
            index = indices[0]; frame_rows.update({index} if slot == "0" else range(index - 3, index + 2))
    lane.raw_audit.validate_external_copy_inventory(trace, {"stages": action["captures"]})
    xml_rows = set()
    for index, row in enumerate(trace):
        if not row.get("evidence", "").endswith(".xml"): continue
        argv = row["argv"]; require(index > 0 and index + 1 < len(trace) and argv[:6] == shell[:6] and
            len(argv) == 9 and argv[6:8] == ["exec-out", "cat"] and re.fullmatch(r"/data/local/tmp/wonad-phase1-recents-[0-9a-f]{16}\.xml", argv[8]) and
            trace[index - 1]["argv"] == shell + ["uiautomator", "dump", argv[8]] and
            trace[index + 1]["argv"] == shell + ["rm", "--", argv[8]], "Hierarchy did not originate in exact ordinary dump/read/remove")
        xml_rows.update({index - 1, index, index + 1})
    for local_index, row in enumerate(trace):
        argv = row["argv"]
        require(row["kind"] in {"command", "owned_test_credential"} and type(row.get("returncode")) is int and row["returncode"] == 0, "Failed/foreign action command cannot pass")
        if row.get("evidence"):
            require(observed_ref(root / row["evidence"], trace, root, container)["sha256"] == row["output_sha256"], "Original traced raw bytes changed")
        if row["sequence"] in client_sequences: continue
        if argv == ["docker", "container", "inspect", container]:
            import phase1_conformance_soak_sampler as sampling
            infos = json.loads(row["output"]); require(len(infos) == 1, "Ambiguous action guard")
            sampling.verify_owner(infos[0], action["identity"]); continue
        if argv[:len(shell)] != shell:
            require(local_index in frame_rows or local_index in xml_rows, "Foreign/unconsumed Docker read/write command")
            continue
        args = argv[len(shell):]
        if args[:5] == ["dumpsys", "activity", "--user", "0", "service"] and args[5:] == [runtime.SERVICE]:
            raw = (root / row["evidence"]).read_text() if row.get("evidence") else row["output"]
            value = runtime.parse_status(raw); require(value["run"] == action["run"] and value["failure"] is None and value["control_error"] is None, "Unexpected runtime failure in original polls")
            current_ack = any(value["handshake"] == {"nonce": fields[1], "phase": fields[2], "result": "accepted"}
                for _sequence, fields in controls if fields[2] in {"expect-revocation", "reopen", "restore-observed"})
            require_poll_expectation_marker(raw, action["expectation"] if current_ack else None)
            service_owner(raw, before["processes"]["client"]["pid"])
            statuses.append((row["sequence"], raw, value)); continue
        if args[:7] == ["dumpsys", "activity", "--user", "0", "service", runtime.SERVICE, "runtime-command"]:
            fields = args[7:]; require(len(fields) in (3, 6) and fields[0] == action["run"] and runtime.HEX32.fullmatch(fields[1]), "Malformed/foreign original control")
            phase = fields[2]; require(phase in {"remember-observed", "expect-revocation", "reopen", "restore-observed"}, "Unreviewed control mutation")
            require(fields[3:] == list(map(str, (action["expectation"]["generation"], action["expectation"]["identity_epoch"], action["expectation"]["reason"]))) if phase == "expect-revocation" else len(fields) == 3,
                "Exact generation/epoch/reason fields absent/substituted")
            require_control_marker(row["output"], runtime.CONTROL_MARKER + f"accepted {fields[0]} {fields[1]} {phase}")
            # The enqueue acknowledgement can still dump the previous/null
            # receipt. Exact NEW arming is proven by its subsequent ready ACK.
            require_expectation_marker(row["output"])
            controls.append((row["sequence"], fields)); continue
        if row["kind"] == "owned_test_credential":
            require(action["scenario"] != "user_switch" and args in (["locksettings", "set-pin", "--user", "0", "<owned-test-pin>"],
                ["locksettings", "clear", "--old", "<owned-test-pin>", "--user", "0"], ["input", "keyboard", "-d", "0", "text", "<owned-test-pin>"]), "Credential command escaped owned generated TEST scope")
            privileged.append(args); continue
        if args and args[0] == "input":
            require(len(args) >= 6 and args[1] in {"keyboard", "mouse", "touchscreen"} and args[2] == "-d" and args[3].isdigit(), "Unscoped ordinary input")
            if args[4] == "keyevent":
                require(len(args) == 6 and args[5] in {"KEYCODE_HOME", "KEYCODE_ENTER", "KEYCODE_B", "KEYCODE_SLEEP", "KEYCODE_LOCK", "KEYCODE_WAKEUP"}, "Unreviewed input key")
                if args[5] in {"KEYCODE_SLEEP", "KEYCODE_LOCK"}: triggers.append((row["sequence"], args[5]))
            elif args[4] == "swipe": require(args == ["input", "touchscreen", "-d", "0", "swipe", "540", "1800", "540", "400", "600"], "Unreviewed keyguard swipe")
            else: require(args[4] == "tap" and len(args) == 7 and all(value.isdigit() for value in args[5:]), "Unreviewed input mutation")
            continue
        pids = {str(value["pid"]) for capture in action["captures"] for value in capture["processes"].values()}
        packages = set(contract.PROCESS_NAMES.values()) - {"system_server"}
        secondary = str(action.get("secondary", {}).get("id", -1))
        read_only = (args in (["dumpsys", "activity", "activities"], ["dumpsys", "activity", "--user", "0", lane.acceptance.FIXTURE],
            ["dumpsys", "activity", lane.acceptance.FIXTURE],
            ["dumpsys", "activity", "--user", "0", "service", "com.android.systemui/.SystemUIService"],
            ["dumpsys", "window", "windows"], ["dumpsys", "window", "displays"], ["dumpsys", "window", "policy"],
            ["dumpsys", "input"], ["dumpsys", "display"], ["dumpsys", "user"], list(health.PROCESS_TABLE_COMMAND),
            ["cat", "/proc/sys/kernel/random/boot_id"], ["getprop", health.phone.MODEM_PROPERTY], ["su", "0", "service", "list"],
            ["am", "get-current-user"], ["am", "get-started-user-state", secondary],
            ["logcat", "-b", "events", "-d", "-v", "threadtime", "am_anr:I", "am_crash:I", "*:S"],
            ["locksettings", "get-disabled", "--user", "0"], ["cmd", "package", "resolve-activity", "--brief", "--user", secondary,
                "-a", "android.intent.action.MAIN", "-c", "android.intent.category.HOME"]) or
            len(args) == 7 and args[:6] == ["pm", "list", "packages", "-U", "--user", "0"] and args[-1] in packages or
            len(args) == 2 and args[0] == "pidof" and args[1] in set(contract.PROCESS_NAMES.values()) or
            args == ["pm", "list", "packages", "-U", "--user", secondary, lane.raw_audit.LAUNCHER] or
            len(args) == 6 and args[:5] == ["pm", "list", "packages", "--user", secondary] and args[-1] in {runtime.PACKAGE, lane.acceptance.FIXTURE} or
            args[:3] == ["su", "0", "cat"] and len(args) == 4 and re.fullmatch(r"/proc/(?:" + "|".join(pids) + r")/(?:stat|status)", args[-1]) is not None or
            args[:4] == ["su", "0", "ls", "-1"] and len(args) == 5 and re.fullmatch(r"/proc/(?:" + "|".join(pids) + r")/fd", args[-1]) is not None or
            len(args) == 6 and args[0] == "settings" and args[1] == "--user" and args[2] in {"0", secondary} and
                args[3:5] == ["get", "secure"] and args[5] in {"user_setup_complete", "wonad_external_desktop_enabled"})
        if read_only: continue
        if args[:2] == ["locksettings", "set-disabled"]:
            require(args == ["locksettings", "set-disabled", "--user", "0", action["credential_cleanup"]["original_disabled"]], "Lock configuration restoration is not exact original")
            continue
        if action["scenario"] == "user_switch" and args in (["pm", "create-user", "--for-testing", "Wonad-soak-" + action["nonce"]],
            ["pm", "remove-user", secondary], ["am", "start-user", "-w", secondary], ["am", "stop-user", "-w", "-f", secondary],
            ["am", "switch-user", "-w", secondary], ["am", "switch-user", "-w", "0"]): continue
        if local_index in xml_rows: continue
        raise ValueError("Unreviewed action mutation/read authority: " + " ".join(args))
    require([fields[2] for _index, fields in controls] == ["remember-observed", "expect-revocation", "reopen", "restore-observed"] and
        len({fields[1] for _index, fields in controls}) == 4, "Missing/replayed/skipped original control ordering")
    arm_index, arm = controls[1]
    armed = [(index, raw) for index, raw, value in statuses if arm_index < index < controls[2][0] and value["handshake"] ==
        {"nonce": arm[1], "phase": "expect-revocation", "result": "accepted"} and value["state"] == "ready"]
    require(armed, "No actual armed original receipt before action")
    expectation.require_armed(armed[0][1], action["run"], arm[1], action["expectation"]["generation"], action["expectation"]["identity_epoch"], action["expectation"]["reason"])
    # The authority source is the actual independently retained ready snapshot
    # AFTER ordinary reopen and BEFORE restore, not remembered old tokens.
    reopened = [value for index, raw, value in statuses if controls[2][0] < index < controls[3][0] and
        value["handshake"] == {"nonce": controls[2][1][1], "phase": "reopen", "result": "accepted"} and
        value["state"] == "ready" and value["runtime_readiness"]["ready"]]
    require(reopened, "No actual fresh authorized snapshot before recovery replay")
    admitted = reopened[-1]["snapshot"]; terminal = recovered["status"]["snapshot"]
    require(admitted["generation"] != action["expectation"]["generation"] and admitted["identity_epoch"] > 0 and
        (admitted["generation"], admitted["identity_epoch"]) == (terminal["generation"], terminal["identity_epoch"]),
        "Recovery lease differs from the actual fresh reopen observation")
    admitted_tasks, terminal_tasks = descriptive_tasks(admitted), descriptive_tasks(terminal)
    require(set(admitted_tasks) == set(terminal_tasks) and all(admitted_tasks[key]["token"] == terminal_tasks[key]["token"] for key in admitted_tasks),
        "Recovery substituted old/foreign task authority for actual newly observed tokens")
    admitted_displays = {value["identity_hint"]: value for value in admitted["display_incarnations"]}
    require(len(admitted_displays) == len(admitted["display_incarnations"]) and
        {value["identity_hint"] for value in terminal["display_incarnations"]} == set(admitted_displays) and
        all(value["token"] == admitted_displays[value["identity_hint"]]["token"] for value in terminal["display_incarnations"]),
        "Recovery substituted old/foreign display authority for actual newly observed tokens")
    if action["scenario"] != "user_switch":
        key = "KEYCODE_SLEEP" if action["scenario"] == "credential_sleep" else "KEYCODE_LOCK"
        require(len(triggers) == 2 and triggers[0][1] == key and triggers[1][1] == "KEYCODE_SLEEP" and
            armed[0][0] < triggers[0][0] < action["captures"][1]["trace_start"] and
            action["captures"][3]["trace_end"] <= triggers[1][0] < controls[2][0],
            "Exact initial trigger/final-inactive bounded unlock sleep ordering changed")
        require(privileged == [["locksettings", "set-pin", "--user", "0", "<owned-test-pin>"],
            ["input", "keyboard", "-d", "0", "text", "<owned-test-pin>"], ["locksettings", "clear", "--old", "<owned-test-pin>", "--user", "0"]], "Missing/reordered generated credential creation/unlock/authenticated cleanup")
        credential = [row for row in trace if row["kind"] == "owned_test_credential"]
        credential_unlock_trace(root, action, trace, triggers[1][0], credential[1])
        require("Pin set to '<owned-test-pin>'" in credential[0]["output"].splitlines() and
            "Lock credential cleared" in credential[-1]["output"].splitlines(), "Original LockSettings creation/authenticated cleanup not confirmed")
        disabled = [row for row in trace if row["argv"] == shell + ["locksettings", "get-disabled", "--user", "0"]]
        require(len(disabled) >= 3 and all((root / row["evidence"]).read_text().strip() in {"true", "false"} for row in disabled) and
            (root / disabled[0]["evidence"]).read_text().strip() == (root / disabled[-1]["evidence"]).read_text().strip() == action["credential_cleanup"]["original_disabled"],
            "Original lock configuration not independently restored")
        keyguards = [row for row in trace if row["argv"] == shell + ["dumpsys", "activity", "--user", "0", "service", "com.android.systemui/.SystemUIService"]]
        require(lock.keyguard_state((root / keyguards[0]["evidence"]).read_text()) == {"mShowing": False, "mSecure": False, "mCanDismissLockScreen": True} and
            lock.keyguard_state((root / keyguards[-1]["evidence"]).read_text())["mSecure"] is False, "Existing credential or failed real credential removal")
    else:
        secondary = str(action["secondary"]["id"])
        mutations = [row for row in trace if row["argv"][len(shell):][:2] in (["pm", "create-user"], ["pm", "remove-user"],
            ["am", "start-user"], ["am", "stop-user"], ["am", "switch-user"])]
        require([row["argv"][len(shell):] for row in mutations] == [["pm", "create-user", "--for-testing", "Wonad-soak-" + action["nonce"]],
            ["am", "start-user", "-w", secondary], ["am", "switch-user", "-w", secondary], ["am", "switch-user", "-w", "0"],
            ["am", "switch-user", "-w", "0"], ["am", "stop-user", "-w", "-f", secondary], ["pm", "remove-user", secondary]] and
            mutations[0]["output"].splitlines() == ["Success: created user id " + secondary] and
            mutations[-1]["output"].splitlines() == ["Success: removed user"] and
            armed[0][0] < mutations[2]["sequence"] < controls[2][0] < mutations[-2]["sequence"], "Exact created user/start/switch/restore/stop/remove lifecycle missing or foreign")
        user_reads = [row for row in trace if row["argv"] == shell + ["dumpsys", "user"]]
        baseline = user_helpers.users((root / user_reads[0]["evidence"]).read_text())
        require(set(baseline) == {0} and user_helpers.users((root / user_reads[-1]["evidence"]).read_text()) == baseline,
            "Original exact user inventory was not restored")
        consent = [row for row in trace if row["argv"] == shell + ["settings", "--user", secondary, "get", "secure", "wonad_external_desktop_enabled"]]
        require(len(consent) == 1 and (root / consent[0]["evidence"]).read_text().strip() in {"null", "0"}, "Actual secondary consent was inherited/changed")
        for package in (runtime.PACKAGE, lane.acceptance.FIXTURE):
            absent = [row for row in trace if row["argv"] == shell + ["pm", "list", "packages", "--user", secondary, package]]
            require(len(absent) == 1 and (root / absent[0]["evidence"]).read_bytes() == b"", "Actual secondary application isolation missing")
    return controls


def audit_action(path, admitted_contract, admitted_identity, *, client_chain=None, client_uid=None):
    import phase1_conformance_soak_lock_user_actions as producer
    path = Path(path).absolute(); directory = path.parent; root = directory.parents[1]
    require(path.resolve(strict=True) == path and path.name == "attempt-ended.json", "Literal original ended action required")
    action = load(path)
    require(action["schema"] == 1 and action["kind"] == KIND and action["status"] == STATUS and
        action["scenario"] in producer.SCENARIOS and type(action["ordinal"]) is int and action["ordinal"] > 0 and
        runtime.HEX32.fullmatch(action["nonce"]) and action["identity"] == admitted_identity and action["contract"] == admitted_contract and
        action["runtime_qualified"] is False and action["whole_campaign_complete"] is False and
        action.get("error") is None, "Failed/foreign/whole-campaign substituted action")
    require(admitted_contract == producer.admission.input_contract(admitted_identity["image_id"], Path(admitted_contract["product"]),
        Path(admitted_contract["packet"]), admitted_contract["packet_receipt"]["sha256"]) and action["sources"] == producer.source_contract(), "Authenticated current-source/candidate binding changed")
    require(directory.name == f"{action['ordinal']:06d}-{action['scenario']}-{action['nonce']}" and directory.parent.name == "soak-actions", "Original action path/nonce changed")
    require(all(not target.is_symlink() and (target.is_file() or target.is_dir()) for target in directory.rglob("*")), "Aliased/special action evidence")
    require({str(target.relative_to(root)) for target in directory.rglob("*") if target.is_file() and target != path} == set(action["evidence"]), "Failed/extra/unreported original action files")
    trace = load(directory / "commands.json")
    for relative, record in action["evidence"].items(): require(observations.reference_equal(observed_ref(root / relative, trace, root, admitted_identity["container_id"]), record), "Original action evidence changed")
    started = load(directory / "attempt-started.json")
    require(started["status"] == "failed_bounded_action_not_qualified" and started["captures"] == [] and
        all(started[field] == action[field] for field in ("identity", "run", "sources", "contract", "nonce", "ordinal", "scenario", "began_monotonic_ns")), "Original started attempt substituted")
    require(trace and all(type(row["sequence"]) is int for row in trace) and [row["sequence"] for row in trace] == list(range(action["trace_start"], action["trace_end"])) and
        0 < action["ended_monotonic_ns"] - action["began_monotonic_ns"] <= contract.MAX_SCENARIO_NS, "Lost action journal/time bound")
    prior = action["began_monotonic_ns"]
    for row in trace:
        require(type(row["started_monotonic_ns"]) is int and type(row["ended_monotonic_ns"]) is int and
            prior <= row["started_monotonic_ns"] <= row["ended_monotonic_ns"] <= action["ended_monotonic_ns"], "Escaped/interleaved original action reads")
        prior = row["ended_monotonic_ns"]
    require([row["name"] for row in action["captures"]] == ["before", "inactive-0", "inactive-1", "inactive-2", "recovered", "delivered"], "Missing actual repeated inactive/recovery captures")
    stages = [parse_capture(root, row, action, trace) for row in action["captures"]]
    before, recovered, delivered = stages[0], stages[-2], stages[-1]
    ready(before, action); ready(recovered, action); ready(delivered, action)
    original = before["status"]["snapshot"]
    require(action["expectation"]["generation"] == original["generation"] and action["expectation"]["identity_epoch"] == original["identity_epoch"] and
        action["expectation"]["reason"] == (4 if action["scenario"] == "user_switch" else 3), "Expectation is not the original exact lease/reason")
    for stage in stages[1:4]: inactive(before, stage, action)
    require(all(stage["status"]["updated_elapsed_ms"] <= action["expectation"]["deadline_elapsed_ms"] for stage in stages[1:4]),
        "Actual callback receipt occurred after exact expectation expiry")
    for stage in stages:
        counts, baseline = health.task_counts(stage["raw"]["activities"]), health.task_counts(before["raw"]["activities"])
        require(counts["tasks"] - baseline["tasks"] <= 12 and counts["roots"] - baseline["roots"] <= 8, "Intermediate original task/root bound exceeded")
        require(stage["modem"] == before["modem"] and stage["radio"] == before["radio"], "Phone radio identity changed")
        for role, value in stage["processes"].items():
            require({key: value[key] for key in ("pid", "start_ticks", "uid")} ==
                {key: before["processes"][role][key] for key in ("pid", "start_ticks", "uid")}, "Unexpected protected phone/core/client incarnation")
            require(value["fd_count"] - before["processes"][role]["fd_count"] <= 64 and
                value["rss_kib"] - before["processes"][role]["rss_kib"] <= 256 * 1024, "Intermediate process resource bound exceeded")
        for component in before["records"]:
            require(stage["identities"][component] == before["identities"][component], "Task/Activity/Binder/instance process lifetime changed")
    for stage, delta in ((recovered, 0), (delivered, 1)):
        recovery_layout(before, stage)
        for component, record in stage["records"].items():
            require(all(record[key] == before["records"][component][key] for key in ("left", "top", "right", "bottom", "display", "native_display")) and
                record["key_downs"] == before["records"][component]["key_downs"] + delta and
                record["mouse_downs"] == before["records"][component]["mouse_downs"] + delta, "Recovery changed observed placement/input or omitted actual delivery")
    require(all(recovered["status"]["snapshot"][key] == delivered["status"]["snapshot"][key] for key in ("generation", "identity_epoch")),
        "Recovery client generation/namespace changed again")
    require(all(stage["status"]["callbacks"]["onRevoked"] == before["status"]["callbacks"]["onRevoked"] + 1 for stage in stages[1:]),
        "Unexpected extra/missing actual revocation callback")
    client = producer.current_client.audit_action(root, action, trace, admitted_contract, admitted_identity,
        client_chain=client_chain, client_uid=client_uid, defer_command_scan=True)
    trace_semantics(root, action, trace, before, recovered, client_sequences=client["sequences"])
    producer.current_client.audit_action(root, action, trace, admitted_contract, admitted_identity,
        client_chain=client_chain, client_uid=client_uid)
    shell = ["docker", "exec", action["identity"]["container_id"], "adb", "-s", "emulator-5580", "shell"]
    def external_inputs(low, high):
        displays = {str(display) for display in before["displays"]}
        return [row["argv"][len(shell):] for row in trace if low <= row["sequence"] < high and
            row["argv"][:len(shell)] == shell and row["argv"][len(shell):][:1] == ["input"] and
            len(row["argv"][len(shell):]) >= 4 and row["argv"][len(shell):][3] in displays]
    expected, delivered_inputs = [], []
    for component, record in before["records"].items():
        display = str(record["native_display"])
        key = ["input", "keyboard", "-d", display, "keyevent", "KEYCODE_B"]
        mouse = ["input", "mouse", "-d", display, "tap", str((record["left"] + record["right"]) // 2), str((record["top"] + record["bottom"]) // 2)]
        expected.extend((key, mouse)); delivered_inputs.extend((mouse, key))
    for previous, stage in zip(stages[:3], stages[1:4]):
        require(external_inputs(previous["row"]["trace_end"], stage["row"]["trace_start"]) == expected,
            "Missing/reordered exact ordinary hidden keyboard/mouse challenges on all three monitors")
    require(external_inputs(recovered["row"]["trace_end"], delivered["row"]["trace_start"]) == delivered_inputs,
        "Actual recovery did not deliver each exact ordinary mouse/key challenge")
    if action["scenario"] == "user_switch":
        require(action["user_cleanup"]["removed"] is True and action["user_cleanup"]["restored"] ==
            {str(user): row for user, row in user_helpers.users(before["raw"]["users"]).items()}, "Exact owned user cleanup incomplete")
    else:
        require(action["credential_cleanup"]["created"] is True and action["credential_cleanup"]["removed"] is True,
            "Authenticated TEST credential cleanup incomplete")
    return {"scenario": action["scenario"], "status": STATUS, "runtime_qualified": False, "whole_campaign_complete": False,
        "admitted_role_uids": {role: value["uid"] for role, value in before["processes"].items()}}
