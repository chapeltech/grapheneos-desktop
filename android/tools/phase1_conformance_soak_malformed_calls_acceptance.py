#!/usr/bin/env python3
"""Original compiled neutral malformed RPCs + exact client restart component."""
from pathlib import Path
from phase1_conformance_installed_path import installed_apk_path
import re

import phase1_conformance_soak_client_death_acceptance as death
import conformance_malformed_calls as proof
from phase1_conformance_common import file_ref

attached, runtime, health, require = death.attached, death.runtime, death.health, death.require
KIND = "phase1_policy_free_malformed_calls_attachment_action_v1"
STATUS = "passed_bounded_actual_malformed_calls_and_client_restart_NOT_whole_campaign"
FAILED = "failed_bounded_malformed_calls_not_qualified"
absence = death.absence


def audit_probe(root, action, trace, before, contract, identity):
    import phase1_conformance_soak_malformed_calls as actor
    actor.require_compiled_phase(contract)
    root = Path(root); indexed = {row["sequence"]: row for row in trace}; value = action["malformed"]
    after_row = action["probe_after"]
    require(after_row["name"] == "probe-after" and after_row["user"] == 0, "Exact actual after-probe stage missing")
    after = attached.parse_capture(root, after_row, action, trace); attached.ready(after, action)
    require(after["identities"] == before["identities"] and after["displays"] == before["displays"] and
        after["records"] == before["records"] and
        after["modem"] == before["modem"] and after["radio"] == before["radio"], "Rejected calls changed native/phone/process/fixture state")
    for role, metric in after["processes"].items():
        previous = before["processes"][role]
        require(all(metric[key] == previous[key] for key in ('pid', 'start_ticks', 'uid')) and
            metric['fd_count'] - previous['fd_count'] <= 64 and metric['rss_kib'] - previous['rss_kib'] <= 256 * 1024,
            'Rejected calls changed protected epoch or exceeded resource bounds')
    fields = value["foreign"]["files"]; metric = value["foreign"]["metric"]
    require(set(fields) == {"uid", *actor.FIELDS, "path", "apk"}, "Incomplete original foreign identity/APK proof")
    uid = attached.package_uid(death.command(root, trace, action, fields["uid"],
        ("pm", "list", "packages", "-U", "--user", "0", actor.FOREIGN)), actor.FOREIGN, 0)
    raw = {}
    for key in actor.FIELDS:
        args = ("pidof", actor.FOREIGN) if key.startswith("pid") else health.PROCESS_TABLE_COMMAND if key.startswith("ps") else (
            "su", "0", *(("ls", "-1") if key == "fd" else ("cat",)), f"/proc/{metric['pid']}/" + ("stat" if key in ("stat_before", "stat_after") else key))
        raw[key] = death.command(root, trace, action, fields[key], args)
    actual = proof.foreign_metric(raw, uid)
    require(actual == metric and all(type(metric[key]) is int for key in actual), "Foreign metric differs from original epoch/UID bytes")
    sequence = [next(row["sequence"] for row in trace if row.get("evidence") == fields[key]) for key in actor.FIELDS]
    require(sequence == list(range(sequence[0], sequence[0] + 8)), "Reordered original foreign epoch fence")
    apk_path = installed_apk_path(death.command(root, trace, action, fields["path"], ("pm", "path", "--user", "0", actor.FOREIGN)), actor.FOREIGN, package_row=True)
    apk_rows = [row for row in trace if row.get("evidence") == fields["apk"]]
    prefix = ["docker", "exec", identity["container_id"], "adb", "-s", "emulator-5580"]
    require(len(apk_rows) == 1 and apk_rows[0]["kind"] == "command" and type(apk_rows[0]["returncode"]) is int and apk_rows[0]["returncode"] == 0 and
        apk_rows[0]["argv"] == prefix + ["exec-out", "cat", apk_path] and
        file_ref(root / fields["apk"]) == file_ref(Path(contract["packet"]) / "security.apk"), "Foreign APK is not genuine compiled exact packet")
    nonce = value["nonce"]; require(type(nonce) is str and runtime.HEX32.fullmatch(nonce), "Exact malformed nonce missing")
    low, high = value["command_sequence"], value["ack_sequence"]
    initial_files = value['foreign_before']
    require(set(initial_files) == {'path', 'apk'}, 'Missing original installed foreign APK preflight')
    initial_path = installed_apk_path(death.command(root, trace, action, initial_files['path'], ('pm', 'path', '--user', '0', actor.FOREIGN)), actor.FOREIGN, package_row=True)
    initial_apks = [row for row in trace if row.get('evidence') == initial_files['apk']]
    initial_paths = [row for row in trace if row.get('evidence') == initial_files['path']]
    require(len(initial_apks) == len(initial_paths) == 1 and initial_apks[0]['kind'] == 'command' and
        type(initial_apks[0]['returncode']) is int and initial_apks[0]['returncode'] == 0 and
        initial_apks[0]['argv'] == prefix + ['exec-out', 'cat', initial_path] and
        file_ref(root / initial_files['apk']) == file_ref(Path(contract['packet']) / 'security.apk') and
        before['row']['trace_end'] <= initial_paths[0]['sequence'] < initial_apks[0]['sequence'] < low,
        'Foreign compiled APK was not genuinely byte-fenced BEFORE original RPC phase')
    require(type(low) is int and type(high) is int and before["row"]["trace_end"] <= low < high < after_row["trace_start"] and
        indexed[low]["argv"] == prefix + ["shell", "dumpsys", "activity", "--user", "0", "service", runtime.SERVICE, "runtime-command", action["run"], nonce, proof.PHASE],
        "Actual current-owner malformed command/ack not ordered")
    attached.require_control_marker(indexed[low]["output"], runtime.CONTROL_MARKER + f"accepted {action['run']} {nonce} {proof.PHASE}")
    ack = indexed[high]
    require(ack["kind"] == "command" and ack["argv"] == prefix + ["shell", "dumpsys", "activity", "--user", "0", "service", runtime.SERVICE] and ack.get("evidence"), "Malformed ack not actual original service read")
    ack_raw = (root / ack["evidence"]).read_text(); status = runtime.parse_status(ack_raw)
    attached.service_owner(ack_raw, before["processes"]["client"]["pid"])
    require(status["run"] == action["run"] and status["state"] == "ready" and status["failure"] is None and status["control_error"] is None and
        status["handshake"] == {"nonce": nonce, "phase": proof.PHASE, "result": "accepted"}, "Actual rejection phase never completed")
    owner = {key: before["processes"]["client"][key] for key in ("pid", "start_ticks", "uid")}
    foreign = {key: actual[key] for key in ("pid", "start_ticks", "uid")}
    actual_proof = proof.require_completed(ack_raw, run=action["run"], nonce=nonce, owner=owner, foreign=foreign,
        before=before["status"]["snapshot"], after=after["status"]["snapshot"], fingerprint=identity["fingerprint"])
    for key in ('onCommand', 'onResult', 'onRevoked'):
        require(actual_proof['callbacks_before'][key] == before['status']['callbacks'][key] and
            actual_proof['callbacks_after'][key] == status['callbacks'][key] == after['status']['callbacks'][key],
            'Actual TEST callback counts differ from original outer owner ledger')
    require(actual_proof == value["proof"] and proof.parse(after["raw"]["conformance"]) == actual_proof and
        before["status"]["updated_elapsed_ms"] <= actual_proof["began_elapsed_ms"] <= actual_proof["ended_elapsed_ms"] <= status["updated_elapsed_ms"] <= after["status"]["updated_elapsed_ms"],
        "Actual TEST trace escaped outer runtime epoch fences")
    require(after_row["trace_end"] <= sequence[0] - 1 and ("kill_sequence" not in action or apk_rows[0]["sequence"] < action["kill_sequence"]),
        "Foreign proof was not fenced inside live current owner interval")
    reads = set(after_row["files"].values()) | {ack["evidence"]} | set(fields.values()) | set(initial_files.values())
    reads.update(relative for metric in after_row["processes"].values()
        for relative in ([metric["package_uid"]] if metric["package_uid"] else []) + list(metric["files"].values()))
    frames = set(); offset = trace[0]["sequence"]
    rows = trace[after_row["trace_start"] - offset:after_row["trace_end"] - offset]
    for relative in after_row["frames"].values():
        index = next(index for index, row in enumerate(rows) if row.get("evidence") == relative)
        frames.update(row["sequence"] for row in (rows[index:index+1] if relative.endswith("frame-0.png") else rows[index-3:index+2]))
    commands = {low, high, apk_rows[0]["sequence"], initial_apks[0]['sequence']}
    for row in trace:
        if not low < row['sequence'] < high: continue
        require(row['kind'] == 'command' and type(row['returncode']) is int and row['returncode'] == 0 and
            row['argv'] == prefix + ['shell', 'dumpsys', 'activity', '--user', '0', 'service', runtime.SERVICE] and row.get('evidence'),
            'Unreviewed command during actual malformed phase')
        raw = (root / row['evidence']).read_text(); attached.require_poll_expectation_marker(raw)
        attached.service_owner(raw, owner['pid']); current = runtime.parse_status(raw)
        require(current['run'] == action['run'] and current['failure'] is None and current['control_error'] is None and
            all(current['snapshot'][key] == before['status']['snapshot'][key] for key in ('generation', 'identity_epoch')),
            'Malformed poll switched/failed actual owner')
        marker = proof.parse(raw)
        require(marker is None or marker == actual_proof, 'Foreign/replayed malformed proof during live nonce')
        reads.add(row['evidence']); commands.add(row['sequence'])
    return {"reads": reads, "frames": frames, "commands": commands, "proof": actual_proof}


def audit_action(path, admitted_contract, admitted_identity, *, client_chain=None, client_uid=None):
    return death.audit_component(path, admitted_contract, admitted_identity, scenario="malformed_calls", client_chain=client_chain, client_uid=client_uid)
