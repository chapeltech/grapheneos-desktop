"""Independent TEST SystemUI-death action replay; never full-campaign admission."""
from pathlib import Path
import re

import conformance_broker_death as death
import phase1_conformance_soak_lock_user_acceptance as base
import phase1_conformance_role_death_health as health_transition
from phase1_conformance_common import file_ref, load

require = base.require
runtime = base.runtime
KIND = "phase1_owned_systemui_binder_death_action_v1"
STATUS = "passed_bounded_systemui_death_original_raw_not_campaign"


def shield(original, stage, action):
    death.require_observed(stage["raw"]["conformance"], action["armed"])
    require(stage["frames"][0]["rgb_nonblack"], "Ordinary awake phone Home is black")
    require(base.lock.phone_awake(stage["raw"]["policy"]), "SystemUI shield must preserve the ordinary awake phone")
    base.phone_home_user(stage["raw"]["activities"], stage["raw"]["window_displays"], stage["raw"]["windows"], 0)
    require(stage["displays"] == original["displays"], "Lock/user transition changed exact connector identity/geometry")
    require(base.lane.raw_audit.focused_display(stage["raw"]["windows"]) == 0, "Inactive authority stole global phone focus")
    for component, record in stage["records"].items():
        prior = original["records"][component]
        require(stage["identities"][component] == original["identities"][component] and record["focused"] is False and
            record["lifecycle"] == "stopped" and all(record[key] == prior[key] for key in ("task", "instance", "pid", "uid", "key_downs", "pointer_downs", "mouse_downs")),
            "Inactive exact task was replaced, focused, resumed or accepted ordinary input")
    rows, _connections = base.input_consumers.dispatcher_windows(stage["raw"]["input"])
    for row in rows:
        display = int(base.input_consumers.field(row, "displayId", r"[0-9]+"))
        flags = set(base.input_consumers.field(row, "inputConfig", r"[^,]+").split(" | "))
        uid = int(base.input_consumers.field(row, "ownerUid", r"[0-9]+"))
        require(not (uid in {action["uids"][runtime.PACKAGE], action["uids"][base.lane.acceptance.FIXTURE]} and
            "NOT_VISIBLE" not in flags and ("SPY" in flags or "DROP_INPUT" not in flags)), "Inactive owner retains real input authority")
        require(not (display == 0 and uid == action["uids"][runtime.PACKAGE] and "SPY" in flags), "Owner spy leaked onto phone")
    for display, info in stage["displays"].items():
        infrastructure = [row for row in rows if base.input_consumers.field(row, "displayId", r"[0-9]+") == str(display) and
            base.input_consumers.field(row, "name", r"[^,]+") == "PointerEventDispatcherOverlay" + str(display) and
            base.input_consumers.field(row, "ownerUid", r"[0-9]+") == "1000" and
            set(value.strip() for value in base.input_consumers.field(row, "inputConfig", r"[^,]+").split("|")) == {"NOT_FOCUSABLE", "TRUSTED_OVERLAY", "SPY", "DO_NOT_PILFER"}]
        require(len(infrastructure) == 1, "Inactive display lost exact OS pointer-dispatcher infrastructure")
        base.input_consumers.consumers(stage["raw"]["input"], display, info["width"], info["height"], stage["processes"]["system_server"]["pid"])
        require(stage["frames"][info["slot"]]["opaque_black"], "Inactive external monitor is not exact opaque black")
    for block in re.split(r"(?=^\s*Window #\d+ Window\{)", stage["raw"]["windows"], flags=re.M):
        own = re.search(r"\bmOwnerUid=(" + str(action["uids"][runtime.PACKAGE]) + "|" + str(action["uids"][base.lane.acceptance.FIXTURE]) + r")\b", block)
        require(not own or not ("isVisible=true" in block and "isOnScreen=true" in block and "mHasSurface=true" in block), "Inactive owner retains a surfaced visible native window")


def recovered(original, stage, action):
    base.ready(stage, action)
    base.recovery_layout(original, stage)
    require(stage["status"]["snapshot"]["identity_epoch"] == original["status"]["snapshot"]["identity_epoch"],
            "SystemUI death changed retained system_server identity namespace")
    require(stage["status"]["callbacks"]["onRevoked"] == original["status"]["callbacks"]["onRevoked"],
            "Local Binder death invented/omitted unexpected SDK revocation")


def consume_command_journal(root, action, trace, stages, consumed):
    """Close the journal over validated captures/actions and exact pure reads.

    A complete file inventory seals bytes; it does not authorize an extra
    command. Frame lifecycles and mutations have already been individually
    validated by their existing semantic auditors before reaching this gate.
    Only the fixed, owned read grammar below may remain as wait/guard polls.
    """
    root = Path(root)
    prefix = ["docker", "exec", action["identity"]["container_id"], "adb", "-s", "emulator-5580", "shell"]
    read_prefix = f"soak-actions/{action['ordinal']:06d}-systemui_death-{action['nonce']}/reads/"
    consumed = set(consumed)
    for stage in stages:
        capture = stage["row"]
        relatives = set(capture["files"].values())
        for metric in capture["processes"].values():
            relatives.update(metric["files"].values())
            if metric["package_uid"] is not None: relatives.add(metric["package_uid"])
        for relative in relatives:
            matches = [row for row in trace if row.get("evidence") == relative]
            require(len(matches) == 1, "Validated capture command missing/duplicated")
            consumed.add(matches[0]["sequence"])
        for slot, relative in capture["frames"].items():
            matches = [index for index, row in enumerate(trace) if row.get("evidence") == relative]
            require(len(matches) == 1, "Validated framebuffer command missing/duplicated")
            index = matches[0]
            # parse_capture has already run the actual exact framebuffer
            # mkdir/capture/find/copy/cleanup validator, including its owner,
            # slot, path, ordering and raw command outputs.
            offsets = (0,) if slot == "0" else (-3, -2, -1, 0, 1)
            consumed.update(trace[index + offset]["sequence"] for offset in offsets)
    readonly = {
        ("cat", "/proc/sys/kernel/random/boot_id"), ("am", "get-current-user"),
        ("dumpsys", "activity", "--user", "0", "service", runtime.SERVICE),
        ("settings", "--user", "0", "get", "secure", "wonad_external_desktop_enabled"),
        ("dumpsys", "activity", "--user", "0", "service", "com.android.systemui/.SystemUIService"),
        ("dumpsys", "window", "policy"), ("dumpsys", "window", "windows"),
        ("dumpsys", "activity", "activities"), ("dumpsys", "activity", base.lane.acceptance.FIXTURE),
    }
    for row in trace:
        if row["sequence"] in consumed: continue
        if row["argv"] == ["docker", "container", "inspect", action["identity"]["container_id"]]:
            import json
            require("evidence" not in row and type(row.get("output")) is str, "Original inline owner guard required")
            values = json.loads(row["output"])
            require(type(values) is list and len(values) == 1, "Ambiguous original action owner guard")
            health_transition.sampling.verify_owner(values[0], action["identity"])
            consumed.add(row["sequence"])
            continue
        require(row["argv"][:len(prefix)] == prefix and tuple(row["argv"][len(prefix):]) in readonly,
                "Unclassified/foreign command in original SystemUI action journal")
        suffix = tuple(row["argv"][len(prefix):])
        if "evidence" in row:
            relative = row["evidence"]
            target = root / relative
            require(type(relative) is str and relative.startswith(read_prefix) and target.resolve(strict=True) == target and
                    base.observed_ref(target, trace, root, action["identity"]["container_id"])["sha256"] == row["output_sha256"],
                    "Original pure-read poll evidence changed/aliased")
            payload = target.read_text()
        else:
            require(type(row.get("output")) is str, "Original inline pure-read output required")
            payload = row["output"]
        if suffix == ("cat", "/proc/sys/kernel/random/boot_id"):
            require(payload.strip() == action["identity"]["boot_id"], "Pure-read guard changed original boot")
        elif suffix == ("am", "get-current-user"):
            require(payload.strip() == "0", "Pure-read guard changed original active user")
        elif suffix == ("dumpsys", "activity", "--user", "0", "service", runtime.SERVICE):
            status = runtime.parse_status(payload)
            require(status["run"] == action["run"] and status["failure"] is None and status["control_error"] is None,
                    "Original pure-read runtime poll failed/changed owner")
            base.require_poll_expectation_marker(payload)
            base.service_owner(payload, stages[0]["processes"]["client"]["pid"])
        consumed.add(row["sequence"])
    require(consumed == {row["sequence"] for row in trace}, "Original SystemUI journal not completely consumed")


def audit_action(path, admitted_contract, admitted_identity, *, client_chain=None, client_uid=None):
    import phase1_conformance_soak_systemui_death as actor
    path = Path(path).absolute(); directory = path.parent; root = directory.parents[1]
    require(path.resolve(strict=True) == path and path.name == "attempt-ended.json", "Literal ended action required")
    action = load(path)
    require(type(action["schema"]) is int and action["schema"] == 1 and action["kind"] == KIND and
            action["status"] == STATUS and action["scenario"] == "systemui_death" and action.get("error") is None and
            action["identity"] == admitted_identity and action["contract"] == admitted_contract and
            action["sources"] == actor.source_contract() and action["runtime_qualified"] is False and
            action["whole_campaign_complete"] is False and action["sampler_stopped_by_action"] is False and
            action["cleanup_owner"] == "enclosing_original_guest_owner", "Failed/foreign/qualified action substituted")
    require(type(action["ordinal"]) is int and action["ordinal"] > 0 and type(action["nonce"]) is str and
            base.runtime.HEX32.fullmatch(action["nonce"]) and
            directory.name == f"{action['ordinal']:06d}-systemui_death-{action['nonce']}" and directory.parent.name == "soak-actions",
            "Original action path/nonce changed")
    require(actor.inherited.admission.input_contract(admitted_identity["image_id"], Path(admitted_contract["product"]),
            Path(admitted_contract["packet"]), admitted_contract["packet_receipt"]["sha256"]) == admitted_contract,
            "Genuine source/image/packet admission changed")
    actor.inherited.admission.lane.bind_client_sources(Path(admitted_contract["packet"]))
    trace = load(directory / "commands.json")
    consumed = set()
    require(trace and [r["sequence"] for r in trace] == list(range(action["trace_start"], action["trace_end"])) and
            all(type(r["sequence"]) is int for r in trace), "Original action command journal lost")
    began, ended = action["began_monotonic_ns"], action["ended_monotonic_ns"]
    require(type(began) is int and type(ended) is int and 0 < ended-began <= base.contract.MAX_SCENARIO_NS,
            "Original bounded action clocks changed")
    previous = began
    for row in trace:
        require(row["kind"] == "command" and type(row["returncode"]) is int and row["returncode"] == 0 and
                type(row["argv"]) is list and all(type(arg) is str for arg in row["argv"]) and
                type(row["started_monotonic_ns"]) is int and type(row["ended_monotonic_ns"]) is int and
                previous <= row["started_monotonic_ns"] <= row["ended_monotonic_ns"] <= ended,
                "Original action clock/command ordering changed")
        previous = row["ended_monotonic_ns"]
    require(all(not p.is_symlink() and (p.is_dir() or p.is_file()) for p in directory.rglob("*")), "Aliased/special evidence")
    expected = base.observations.inventory(directory, root, [(root, trace, False)], admitted_identity["container_id"], exclude=(path,))
    require(expected == action["evidence"], "Original evidence inventory changed")
    started = load(directory / "attempt-started.json")
    require(started["captures"] == [] and started["status"] == "failed_bounded_action_not_qualified" and
            all(started[k] == action[k] for k in ("run", "nonce", "ordinal", "sources", "identity", "contract", "began_monotonic_ns", "worker")),
            "Original started attempt changed")
    prefix = ["docker", "exec", admitted_identity["container_id"], "adb", "-s", "emulator-5580", "shell"]
    worker = action["worker"]
    require(type(worker) is dict and set(worker) == {"host_pid","run","initial_nonce","original_start_relative"} and
            type(worker["host_pid"]) is int and worker["host_pid"] > 0 and worker["run"] == action["run"] and
            type(worker["initial_nonce"]) is str and runtime.HEX32.fullmatch(worker["initial_nonce"]) and
            worker["original_start_relative"] == str(directory.relative_to(root)) + "/held-worker-start.json",
            "Original held worker ownership changed")
    original_start = load(root / worker["original_start_relative"])
    require(original_start["kind"] == "background_start" and original_start["id"] == "instrumentation-" + action["run"] and
            original_start["argv"] == prefix + ["am","instrument","-w","-r","-e","run",action["run"],"-e","mode","runtime",
            "-e","nonce",worker["initial_nonce"],"-e","phase","start",runtime.RUNNER] and
            type(original_start["sequence"]) is int and original_start["sequence"] < action["trace_start"] and
            type(original_start["started_monotonic_ns"]) is int and 0 < original_start["started_monotonic_ns"] <= began,
            "Actual original self-target worker start command missing/foreign")
    def raw(relative, suffix):
        p = root / relative
        require(p.resolve(strict=True) == p and relative.startswith(str(directory.relative_to(root)) + "/reads/"), "Aliased raw action proof")
        rows = [r for r in trace if r.get("evidence") == relative]
        require(len(rows) == 1 and rows[0]["kind"] == "command" and type(rows[0]["returncode"]) is int and
                rows[0]["returncode"] == 0 and rows[0]["argv"] == prefix + list(map(str,suffix)) and
                rows[0]["output_sha256"] == file_ref(p)["sha256"], "Missing actual successful raw proof command")
        consumed.add(rows[0]["sequence"])
        return p.read_text(), rows[0]
    require([r["name"] for r in action["captures"]] == ["before", "inactive-0", "inactive-1", "inactive-2", "recovered", "delivered"],
            "Missing original repeated shields/recovery/delivery captures")
    stages = [base.parse_capture(root, r, action, trace) for r in action["captures"]]
    original, final, delivered = stages[0], stages[-2], stages[-1]
    base.ready(original, action)
    original_snapshot = original["status"]["snapshot"]
    arm = action["armed"]
    arm_args = ("dumpsys", "activity", "--user", "0", "service", base.runtime.SERVICE, "runtime-command", action["run"],
                arm["proof"]["nonce"], "expect-broker-death", original_snapshot["generation"], original_snapshot["identity_epoch"])
    cmd_raw, arm_cmd = raw(arm["command_relative"], arm_args)
    base.require_control_marker(cmd_raw, base.runtime.CONTROL_MARKER + f"accepted {action['run']} {arm['proof']['nonce']} expect-broker-death")
    status_args = ("dumpsys", "activity", "--user", "0", "service", base.runtime.SERVICE)
    armed_raw, armed_row = raw(arm["raw_relative"], status_args)
    actual_arm = death.require_armed(armed_raw, action["run"], arm["proof"]["nonce"], original_snapshot["generation"], original_snapshot["identity_epoch"])
    require({k: arm[k] for k in ("status", "proof")} == actual_arm, "Original registered owner arm summary changed")
    observed_raw, observed_row = raw(action["observed"]["raw_relative"], status_args)
    require({k: action["observed"][k] for k in ("status", "proof")} == death.require_observed(observed_raw, actual_arm),
            "Actual registered Binder callback changed")
    transition = action["transition"]; old = original["processes"]["systemui"]
    require(transition["action_relative"] == str(path.relative_to(root)) and
            transition["recovered_stage_relative"] == str(directory.relative_to(root)) + "/recovered-stage.json",
            "Foreign action/recovered stage path")
    require(all(transition["old"][k] == old[k] for k in ("uid", "pid", "start_ticks")), "Old SystemUI identity changed")
    kill_rows = [r for r in trace if r["sequence"] == transition["kill_sequence"]]
    require(len(kill_rows) == 1 and kill_rows[0]["kind"] == "command" and type(kill_rows[0]["returncode"]) is int and
            kill_rows[0]["returncode"] == 0 and kill_rows[0]["argv"] == prefix + ["su", "0", "kill", "-KILL", str(old["pid"])],
            "Missing exact owned old-SystemUI KILL command")
    kill = kill_rows[0]
    consumed.add(kill["sequence"])
    def fenced(label, suffix):
        rows = [r for r in trace if r.get("evidence", "").endswith("-kill-" + label + ".txt")]
        require(len(rows) == 1, "Original pre-kill UID/process fence missing/duplicated")
        return raw(rows[0]["evidence"], suffix)
    name = base.contract.PROCESS_NAMES["systemui"]
    uid_raw, _uid_row = fenced("package-uid", ("pm", "list", "packages", "-U", "--user", "0", name))
    uid = base.package_uid(uid_raw, name, 0)
    fence = {}; ordered = []
    for field, suffix in (("pid_before", ("pidof", name)), ("ps_before", base.health.PROCESS_TABLE_COMMAND),
        ("stat_before", ("su", "0", "cat", f"/proc/{old['pid']}/stat")),
        ("status", ("su", "0", "cat", f"/proc/{old['pid']}/status")),
        ("fd", ("su", "0", "ls", "-1", f"/proc/{old['pid']}/fd")),
        ("stat_after", ("su", "0", "cat", f"/proc/{old['pid']}/stat")),
        ("pid_after", ("pidof", name)), ("ps_after", base.health.PROCESS_TABLE_COMMAND)):
        fence[field], command = fenced(field.replace("_", "-"), suffix); ordered.append(command["sequence"])
    actual_old = base.process_metric(fence, uid, name)
    require(all(actual_old[k] == old[k] for k in ("uid", "pid", "start_ticks")) and
            ordered == sorted(ordered) and ordered[-1] + 1 == kill["sequence"],
            "KILL was not immediately after exact original UID/PID/start fence")
    require(arm_cmd["sequence"] < armed_row["sequence"] < kill["sequence"] < observed_row["sequence"] < stages[1]["row"]["trace_start"],
            "Death callback is not ordered after genuine owned command and before shields")
    require(type(transition["started_monotonic_ns"]) is int and transition["started_monotonic_ns"] <= kill["started_monotonic_ns"] and
            final["row"]["ended_monotonic_ns"] == transition["ended_monotonic_ns"] <= transition["started_monotonic_ns"] + health_transition.MAX_ROLE_DEATH_NS,
            "Role transition clocks changed")
    for stage in stages[1:4]: shield(original, stage, action)
    recovered(original, final, action); recovered(original, delivered, action)
    new = {k: final["processes"]["systemui"][k] for k in ("pid", "start_ticks")}
    require(new != {k: old[k] for k in new} and transition["after"] == new and
            load(root / transition["recovered_stage_relative"]) == final["row"], "Actual new SystemUI/recovery stage missing")
    controls = [r for r in trace if r["argv"][:len(prefix)+7] == prefix +
        ["dumpsys", "activity", "--user", "0", "service", base.runtime.SERVICE, "runtime-command"]]
    require([r["argv"][len(prefix)+9] for r in controls] == ["expect-broker-death", "reopen", "restore-observed"],
            "Missing/extra/invented recovery control commands")
    prereqs = action["reopen_prerequisites"]
    require(type(prereqs) is dict and set(prereqs) == {"consent","keyguard","policy"}, "Original reopening prerequisites missing")
    consent, consent_row = raw(prereqs["consent"], ("settings","--user","0","get","secure","wonad_external_desktop_enabled"))
    keyguard, keyguard_row = raw(prereqs["keyguard"], ("dumpsys","activity","--user","0","service","com.android.systemui/.SystemUIService"))
    policy, policy_row = raw(prereqs["policy"], ("dumpsys","window","policy"))
    require(consent.strip() == "1" and base.lock.keyguard_state(keyguard) == {
                "mShowing":False,"mSecure":False,"mCanDismissLockScreen":True} and base.lock.phone_awake(policy) and
            stages[3]["row"]["trace_end"] <= consent_row["sequence"] < keyguard_row["sequence"] < policy_row["sequence"] < controls[1]["sequence"],
            "Reopen precedes actual restored authorization prerequisites")
    acknowledgements = []
    for control in controls[1:]:
        fields = control["argv"][len(prefix)+7:]
        require(len(fields) == 3 and fields[0] == action["run"] and type(fields[1]) is str and
                base.runtime.HEX32.fullmatch(fields[1]) and type(control["returncode"]) is int and control["returncode"] == 0,
                "Foreign/malformed ordinary recovery command")
        base.require_control_marker(control["output"], base.runtime.CONTROL_MARKER + "accepted " + " ".join(fields))
        polls = [r for r in trace if control["sequence"] < r["sequence"] < final["row"]["trace_start"] and
                 r["argv"] == prefix + list(status_args) and r.get("evidence")]
        accepted = []
        for poll in polls:
            payload, _ = raw(poll["evidence"], status_args)
            status = base.runtime.parse_status(payload)
            if status["handshake"] == {"nonce":fields[1], "phase":fields[2], "result":"accepted"}:
                require(status["state"] == "ready" and status["runtime_readiness"]["ready"] and
                        status["failure"] is None and status["control_error"] is None and status["run"] == action["run"],
                        "Recovery acknowledgement is not actual ready/APPLIED path")
                accepted.append((poll, status))
        require(accepted, "Actual ordinary recovery acknowledgement missing/rejected")
        acknowledgements.append(accepted[0])
    reopen_ack, restore_ack = acknowledgements
    require(observed_row["sequence"] < controls[1]["sequence"] < reopen_ack[0]["sequence"] < controls[2]["sequence"] <
            restore_ack[0]["sequence"] < final["row"]["trace_start"] and
            restore_ack[1]["callbacks"]["onResult"] == reopen_ack[1]["callbacks"]["onResult"] + 1 and
            all(restore_ack[1]["snapshot"][k] == final["status"]["snapshot"][k] for k in ("generation","identity_epoch")),
            "Missing ordered actual frame completion before recovered capture/permit end")
    for stage in stages:
        counts = base.health.task_counts(stage["raw"]["activities"])
        baseline = base.health.task_counts(original["raw"]["activities"])
        require(counts["tasks"] - baseline["tasks"] <= 12 and counts["roots"] - baseline["roots"] <= 8,
                "Intermediate original task/root bound exceeded")
        require(stage["modem"] == original["modem"] and stage["radio"] == original["radio"], "Protected radio changed")
        for role, value in stage["processes"].items():
            require(value["fd_count"] - original["processes"][role]["fd_count"] <= 64 and
                    value["rss_kib"] - original["processes"][role]["rss_kib"] <= 256 * 1024,
                    "Intermediate original process resource bound exceeded")
            require(value["uid"] == original["processes"][role]["uid"], "Role UID changed")
            expected_epoch = new if role == "systemui" and stage is not original else original["processes"][role]
            require(all(value[k] == expected_epoch[k] for k in ("pid", "start_ticks")), "Unplanned/repeated role replacement")
        for component in original["records"]:
            require(stage["identities"][component] == original["identities"][component], "Original app/task/window lifetime changed")
        require(stage["status"]["callbacks"]["onRevoked"] == original["status"]["callbacks"]["onRevoked"], "SDK terminal fabricated/ignored")
    for stage, delta in ((final,0),(delivered,1)):
        for component, record in stage["records"].items():
            before = original["records"][component]
            require(all(record[k] == before[k] for k in ("left", "top", "right", "bottom", "display", "native_display")) and
                    record["key_downs"] == before["key_downs"] + delta and record["mouse_downs"] == before["mouse_downs"] + delta,
                    "Descriptive restore/input delivery changed")
    require(all(final["status"]["snapshot"][k] == delivered["status"]["snapshot"][k] for k in ("generation","identity_epoch")),
            "Recovered lease changed again")
    expected, delivered_inputs = [], []
    for record in original["records"].values():
        display = str(record["native_display"])
        key = ["input", "keyboard", "-d", display, "keyevent", "KEYCODE_B"]
        mouse = ["input", "mouse", "-d", display, "tap", str((record["left"] + record["right"]) // 2),
                 str((record["top"] + record["bottom"]) // 2)]
        expected.extend((key, mouse)); delivered_inputs.extend((mouse, key))
    def external_inputs(low, high):
        return [row["argv"][len(prefix):] for row in trace if low <= row["sequence"] < high and
                row["argv"][:len(prefix)] == prefix and row["argv"][len(prefix):][:1] == ["input"] and
                row["argv"][len(prefix):] != ["input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME"]]
    for previous, stage in zip(stages[:3], stages[1:4]):
        require(external_inputs(previous["row"]["trace_end"], stage["row"]["trace_start"]) == expected,
                "Missing/reordered exact ordinary hidden keyboard/mouse challenges")
    require(external_inputs(final["row"]["trace_end"], delivered["row"]["trace_start"]) == delivered_inputs,
            "Missing/reordered exact ordinary recovered mouse/key delivery")
    inputs = [row["argv"][len(prefix):] for row in trace if row["argv"][:len(prefix)] == prefix and
              row["argv"][len(prefix):][:1] == ["input"]]
    home = ["input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME"]
    require(inputs == expected * 3 + [home] + delivered_inputs + [home], "Extra/foreign ordinary input command")
    consumed.update(row["sequence"] for row in controls)
    consumed.update(row["sequence"] for row in trace if row["argv"][:len(prefix)] == prefix and
                    row["argv"][len(prefix):][:1] == ["input"])
    client = actor.inherited.current_client.audit_action(root, action, trace, admitted_contract, admitted_identity,
        client_chain=client_chain, client_uid=client_uid, defer_command_scan=True)
    consumed.update(client["sequences"])
    consume_command_journal(root, action, trace, stages, consumed)
    actor.inherited.current_client.audit_action(root, action, trace, admitted_contract, admitted_identity,
        client_chain=client_chain, client_uid=client_uid)
    epoch_path = stages[1]["row"]["processes"]["systemui"]["files"]["ps_after"]
    epoch_rows = [r for r in trace if r.get("evidence") == epoch_path]
    require(len(epoch_rows) == 1, "Missing exact first new-SystemUI epoch fence completion")
    return {"status": STATUS, "runtime_qualified": False, "whole_campaign_complete": False, "processes": delivered["processes"],
            "transition": dict(action_nonce=action["nonce"], scenario="systemui_death", role="systemui", role_uid=old["uid"],
                permit_id=transition["permit_id"], before={k:old[k] for k in new}, after=new,
                started_monotonic_ns=transition["started_monotonic_ns"], ended_monotonic_ns=transition["ended_monotonic_ns"],
                deadline_monotonic_ns=transition["started_monotonic_ns"]+health_transition.MAX_ROLE_DEATH_NS,
                absent_begin_monotonic_ns=kill["started_monotonic_ns"], absent_end_monotonic_ns=epoch_rows[0]["ended_monotonic_ns"],
                old_end_monotonic_ns=kill["ended_monotonic_ns"], new_start_monotonic_ns=kill["started_monotonic_ns"],
                action_relative=str(path.relative_to(root)), recovered_stage_relative=transition["recovered_stage_relative"])}
