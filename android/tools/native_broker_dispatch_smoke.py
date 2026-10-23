#!/usr/bin/env python3
"""Actual API3 BrokerDispatch two-second timeout and abandonment smoke.

An ordinary owner calls the public Binder API. A separately platform-signed,
test-only no-restart SystemUI instrumentation delays one unchanged native IWM
identity observation on Shell's real serial executor. The call must time out at
two seconds, the later unreceived Session must be revoked, the exact IWM proxy
must be restored, and a fresh owner must recover the same native task identities.
No production fault hook, adopted identity, existing guest, or API2 receipt can
supply this evidence.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "android/container"))

from apk_update_smoke import BUILD_TOOLS, TOOLS
from build import digest
from fault_runtime_contract import check_fault_runtime
from native_completion_timeout_smoke import fault_manifest
from native_lock_user_security_smoke import (APP, ProbeHost, finish, number, prepare,
    require_process, result_fields, snapshot_proof, statuses, unique_object)
from native_session_security_smoke import freeze_apk
from native_shell_smoke import NativeShellEmulator
from wrong_signer_smoke import signer_digest

SCOPE = "v3_actual_broker_dispatch_2s_timeout_abandonment"
FAULT_SCOPE = "v3_actual_broker_dispatch_2s_timeout_fault"
RUNNER = "org.wonad.desktop.test/org.wonad.desktop.security.NativeBrokerDispatchInstrumentation"
FAULT = "org.wonad.desktop.transitionfault"
FAULT_RUNNER = FAULT + "/" + FAULT + ".NativeCompletionProofInstrumentation"
START = "org.wonad.desktop.test.BROKER_DISPATCH_START"
RESTORED = "org.wonad.desktop.test.BROKER_DISPATCH_PROXY_RESTORED"
CANCEL = FAULT + ".BROKER_DISPATCH_CANCEL"
LAUNCHER_SCOPE = "v3_initial_launcher_page_after_picker_creation_2s_timeout_same_session_recovery"
LAUNCHER_FAULT_SCOPE = "v3_initial_launcher_page_after_picker_creation_2s_timeout_fault"
LAUNCHER_RUNNER = "org.wonad.desktop.test/org.wonad.desktop.security.NativeLauncherPageTimeoutInstrumentation"
LAUNCHER_START = "org.wonad.desktop.test.LAUNCHER_TIMEOUT_START"
LAUNCHER_RESTORED = "org.wonad.desktop.test.LAUNCHER_TIMEOUT_PROXY_RESTORED"


def admission_snapshot(value):
    """Strict first open() callback: displays exist, policy/UI tasks do not."""
    keys = {"generation", "identity_epoch", "revision", "topology_revision", "interaction_blocked",
            "focused_display_token", "focused_token", "displays", "tasks"}
    if not isinstance(value, dict) or set(value) != keys or value.get("tasks") != [] or \
            value.get("interaction_blocked") is not False or \
            type(value.get("focused_display_token")) is not int or value["focused_display_token"] != 0 or \
            type(value.get("focused_token")) is not int or value["focused_token"] != 0:
        raise ValueError("Invalid pre-UI broker admission snapshot")
    for key in ("generation", "identity_epoch", "revision", "topology_revision"):
        if type(value.get(key)) is not int or value[key] <= 0 or value[key] >= 2 ** 63:
            raise ValueError("Invalid pre-UI broker admission identity")
    displays = value.get("displays")
    if not isinstance(displays, list) or not 1 <= len(displays) <= 9:
        raise ValueError("Pre-UI broker admission has no bounded display set")
    tokens, identifiers = set(), set()
    for display in displays:
        if not isinstance(display, dict) or set(display) != {"token", "display_id", "identity_hint",
                "shell_generation", "secure", "bounds"}:
            raise ValueError("Invalid pre-UI display record")
        token, identifier, hint, shell = (display.get(key) for key in
            ("token", "display_id", "identity_hint", "shell_generation"))
        bounds = display.get("bounds")
        if any(type(item) is not int for item in (token, identifier, hint, shell)) or \
                not 0 < token < 2 ** 63 or not 0 < identifier < 2 ** 31 or not 0 < hint < 2 ** 63 or \
                not 0 <= shell < 2 ** 63 or shell == value["generation"] or display.get("secure") is not True or \
                not isinstance(bounds, list) or len(bounds) != 4 or any(type(edge) is not int for edge in bounds) or \
                not 0 <= bounds[0] < bounds[2] <= 32768 or not 0 <= bounds[1] < bounds[3] <= 32768 or \
                token in tokens or identifier in identifiers:
            raise ValueError("Invalid pre-UI native display identity")
        tokens.add(token); identifiers.add(identifier)
    return value


def physical_displays(snapshot):
    return sorted(({key: display[key] for key in ("token", "display_id", "identity_hint", "bounds", "secure")}
                   for display in snapshot["displays"]), key=lambda row: row["display_id"])


def baseline_physical_displays(baseline):
    """Translate native_snapshot()'s validated hexadecimal hint representation."""
    rows = []
    for display, monitor in baseline["monitors"].items():
        hint = monitor.get("identity_hint")
        if type(hint) is not str or re.fullmatch(r"[0-9a-f]{1,16}", hint) is None:
            raise ValueError("Baseline has invalid native display identity hint")
        identity_hint = int(hint, 16)
        if not 0 < identity_hint < 2 ** 63:
            raise ValueError("Baseline has out-of-range native display identity hint")
        rows.append(dict(token=monitor["token"], display_id=display,
            identity_hint=identity_hint, bounds=monitor["area"], secure=True))
    return sorted(rows, key=lambda row: row["display_id"])


def client_phases(output, run, uid):
    rows = statuses(output)
    order = ("client_ready", "timeout_observed", "recovered")
    if len(rows) > len(order):
        raise ValueError("Too many broker-dispatch client phases")
    for index, row in enumerate(rows):
        common = dict(run=run, phase=order[index], api="3", owner_uid=str(uid))
        extras = {"owner_pid"}
        if index:
            extras |= {"generation", "identity_epoch", "evidence"}
        if index == 1:
            extras |= {"elapsed", "revocation_reason"}
        if set(row) != set(common) | extras or any(row.get(key) != value for key, value in common.items()):
            raise ValueError("Unexpected broker-dispatch client phase/identity")
        row["owner_pid"] = number(row["owner_pid"])
        if index:
            row["generation"] = number(row["generation"])
            row["identity_epoch"] = number(row["identity_epoch"])
            raw = json.loads(row["evidence"], object_pairs_hook=unique_object)
            row["evidence"] = snapshot_proof(raw) if index == 2 else admission_snapshot(raw)
            if row["generation"] != row["evidence"]["generation"] or \
                    row["identity_epoch"] != row["evidence"]["identity_epoch"]:
                raise ValueError("Broker-dispatch client phase changed its exact native identity")
        if index == 1:
            row["elapsed"] = number(row["elapsed"])
            row["revocation_reason"] = number(row["revocation_reason"])
            if not 1800 <= row["elapsed"] <= 4000 or row["revocation_reason"] != 5:
                raise ValueError("Public Binder call did not expose exact bounded timeout/abandonment")
        if index and row["owner_pid"] != rows[0]["owner_pid"]:
            raise ValueError("Broker-dispatch owner process changed")
    return rows


def fault_phases(output, run, uid, systemui_uid, systemui_pid):
    rows = statuses(output)
    order = ("injector_ready", "dispatch_delayed", "cleanup_observed")
    if len(rows) > len(order):
        raise ValueError("Too many broker-dispatch fault phases")
    for index, row in enumerate(rows):
        common = dict(run=run, phase=order[index], api="3", owner_uid=str(uid),
            systemui_uid=str(systemui_uid), systemui_pid=str(systemui_pid))
        extras = set()
        if index >= 1: extras |= {"started", "identity_epoch"}
        if index == 2: extras |= {"finished", "elapsed"}
        if set(row) != set(common) | extras or any(row.get(key) != value for key, value in common.items()):
            raise ValueError("Unexpected broker-dispatch fault phase/identity")
        for key in extras: row[key] = number(row[key])
        if index == 2 and (row["finished"] - row["started"] != row["elapsed"] or
                not 4300 <= row["elapsed"] <= 8000):
            raise ValueError("Fault did not delay exactly one real dispatch beyond two seconds")
    return rows


def check_client(output, fingerprint, run, uid, baseline):
    rows = client_phases(output, run, uid)
    if len(rows) != 3:
        raise ValueError("Incomplete broker-dispatch client phases")
    timed, recovered = rows[1:]
    fields = result_fields(output, dict(native_broker_dispatch="passed", scope=SCOPE, api=3, run=run,
        owner_uid=uid, owner_pid=rows[0]["owner_pid"], fingerprint=fingerprint, native_abi="x86_64",
        old_generation=timed["generation"], new_generation=recovered["generation"],
        identity_epoch=recovered["identity_epoch"], dispatch_elapsed=timed["elapsed"], revocation_reason=5,
        timeout_message="Broker did not respond", callbacks_silent="true", proxy_restoration_observed="true"))
    proof = json.loads(fields.get("evidence", ""), object_pairs_hook=unique_object)
    if not isinstance(proof, dict) or set(proof) != {"abandoned", "recovered"}:
        raise ValueError("Invalid broker-dispatch evidence object")
    abandoned = admission_snapshot(proof["abandoned"]); fresh = snapshot_proof(proof["recovered"])
    task_tokens = set(baseline["tasks"])
    expected_displays = baseline_physical_displays(baseline)
    admitted_shells = {display["display_id"]: display["shell_generation"] for display in abandoned["displays"]}
    expected_shells = {display: monitor["shell_generation"] for display, monitor in baseline["monitors"].items()}
    if abandoned != timed["evidence"] or fresh != recovered["evidence"] or \
            abandoned["generation"] == baseline["generation"] or fresh["generation"] in {
                baseline["generation"], abandoned["generation"]} or \
            abandoned["identity_epoch"] != baseline["identity_epoch"] or \
            fresh["identity_epoch"] != abandoned["identity_epoch"] or \
            physical_displays(abandoned) != expected_displays or physical_displays(fresh) != expected_displays or \
            any(admitted_shells[display] not in (0, shell) for display, shell in expected_shells.items()) or \
            {task["token"] for task in fresh["tasks"]} != task_tokens:
        raise ValueError("Timeout/recovery did not preserve exact native identity continuity")
    return dict(fields, evidence=proof, phases=rows)


def check_fault(output, fingerprint, run, uid, systemui_uid, systemui_pid):
    rows = fault_phases(output, run, uid, systemui_uid, systemui_pid)
    if len(rows) != 3:
        raise ValueError("Incomplete broker-dispatch fault phases")
    delayed, cleaned = rows[1:]
    fields = result_fields(output, dict(broker_dispatch_fault="passed", scope=FAULT_SCOPE, api=3, run=run,
        owner_uid=uid, systemui_uid=systemui_uid, systemui_pid=systemui_pid, fingerprint=fingerprint,
        native_abi="x86_64", delay_started=cleaned["started"], delay_finished=cleaned["finished"],
        delay_elapsed=cleaned["elapsed"], identity_epoch=cleaned["identity_epoch"], delay_calls=1,
        session_cleaned="true", proxy_restored="true"))
    if delayed["started"] != cleaned["started"] or delayed["identity_epoch"] != cleaned["identity_epoch"]:
        raise ValueError("Dispatch fault changed the exact delayed native observation")
    return dict(fields, phases=rows)


def launcher_client_phases(output, run, uid):
    rows = statuses(output)
    order = ("client_ready", "timeout_observed", "recovered")
    if len(rows) > len(order):
        raise ValueError("Too many initial-page client phases")
    for index, row in enumerate(rows):
        common = dict(run=run, phase=order[index], api="3", owner_uid=str(uid))
        extras = {"owner_pid", "generation", "identity_epoch", "display_token", "evidence"}
        if index == 1: extras.add("elapsed")
        if index == 2: extras |= {"abandoned_catalogue", "fresh_catalogue"}
        if set(row) != set(common) | extras or any(row.get(key) != value for key, value in common.items()):
            raise ValueError("Unexpected initial-page client phase/identity")
        for key in extras - {"evidence"}: row[key] = number(row[key])
        proof = snapshot_proof(json.loads(row["evidence"], object_pairs_hook=unique_object))
        row["evidence"] = proof
        if len(proof["displays"]) != 1 or any(row[key] != proof[key] for key in ("generation", "identity_epoch")) or \
                row["display_token"] != proof["displays"][0]["token"]:
            raise ValueError("Initial-page client lacks its exact single-display lease")
        if index and any(row[key] != rows[0][key] for key in ("owner_pid", "generation", "identity_epoch", "display_token")):
            raise ValueError("Initial-page cleanup replaced its owner/session")
        if index == 1 and (not 1800 <= row["elapsed"] <= 4000 or proof != rows[0]["evidence"]):
            raise ValueError("Initial-page call did not expose the unchanged two-second timeout")
        if index == 2 and (row["fresh_catalogue"] == row["abandoned_catalogue"] or
                proof["revision"] <= rows[0]["evidence"]["revision"]):
            raise ValueError("Initial-page recovery lacks a distinct fresh catalogue/revision")
    return rows


def launcher_fault_phases(output, run, uid, systemui_uid, systemui_pid, generation, display_token):
    rows = statuses(output)
    order = ("injector_ready", "dispatch_delayed", "cleanup_observed")
    if len(rows) > len(order): raise ValueError("Too many initial-page fault phases")
    for index, row in enumerate(rows):
        common = dict(run=run, phase=order[index], api="3", owner_uid=str(uid),
            systemui_uid=str(systemui_uid), systemui_pid=str(systemui_pid))
        extras = set()
        if index:
            extras |= {"started", "identity_epoch", "generation", "catalogue_id"}
        if index == 1:
            extras |= {"display_token", "selected_after_picker_created"}
        if index == 2:
            extras |= {"finished", "elapsed", "same_session_survived", "initial_picker_cleaned"}
        if set(row) != set(common) | extras or any(row.get(key) != value for key, value in common.items()):
            raise ValueError("Unexpected initial-page fault phase/identity")
        flags = {"selected_after_picker_created", "same_session_survived", "initial_picker_cleaned"} & extras
        if any(row[key] != "true" for key in flags):
            raise ValueError("Initial-page fault lacks exact post-creation cleanup observations")
        for key in extras - flags: row[key] = number(row[key])
        if index and row["generation"] != generation or index == 1 and row["display_token"] != display_token:
            raise ValueError("Initial-page injector selected another lease/display")
        if index == 2 and (any(row[key] != rows[1][key] for key in
                ("started", "identity_epoch", "generation", "catalogue_id")) or
                row["finished"] - row["started"] != row["elapsed"] or not 4300 <= row["elapsed"] <= 8000):
            raise ValueError("Initial-page fault delay/cleanup belongs to another picker")
    return rows


def check_launcher_client(output, fingerprint, run, uid, baseline):
    rows = launcher_client_phases(output, run, uid)
    if len(rows) != 3: raise ValueError("Incomplete initial-page client phases")
    before, timed, recovered = rows
    fields = result_fields(output, dict(native_launcher_page_timeout="passed", scope=LAUNCHER_SCOPE,
        api=3, run=run, owner_uid=uid, owner_pid=before["owner_pid"], fingerprint=fingerprint, native_abi="x86_64",
        generation=before["generation"], identity_epoch=before["identity_epoch"], display_token=before["display_token"],
        dispatch_elapsed=timed["elapsed"], abandoned_catalogue=recovered["abandoned_catalogue"],
        fresh_catalogue=recovered["fresh_catalogue"], replacement_before_cleanup="not_tested",
        proxy_restoration_observed="true"))
    proof = json.loads(fields.get("evidence", ""), object_pairs_hook=unique_object)
    if not isinstance(proof, dict) or set(proof) != {"before", "cleaned", "recovered"}:
        raise ValueError("Invalid initial-page recovery evidence")
    values = [snapshot_proof(proof[key]) for key in ("before", "cleaned", "recovered")]
    if values[0] != before["evidence"] or values[2] != recovered["evidence"] or \
            not values[0]["revision"] < values[1]["revision"] < values[2]["revision"]:
        raise ValueError("Initial-page cleanup/recovery lacks ordered same-session observations")
    expected_displays = baseline_physical_displays(baseline)
    for value in values:
        if value["generation"] != before["generation"] or value["generation"] == baseline["generation"] or \
                value["identity_epoch"] != baseline["identity_epoch"] or \
                value["topology_revision"] != values[0]["topology_revision"] or \
                physical_displays(value) != expected_displays or value["tasks"] != values[0]["tasks"] or \
                {task["token"] for task in value["tasks"]} != set(baseline["tasks"]):
            raise ValueError("Initial-page cleanup changed native session/task/display identity")
    return dict(fields, evidence=proof, phases=rows)


def check_launcher_fault(output, fingerprint, run, uid, systemui_uid, systemui_pid, generation, display_token):
    rows = launcher_fault_phases(output, run, uid, systemui_uid, systemui_pid, generation, display_token)
    if len(rows) != 3: raise ValueError("Incomplete initial-page fault phases")
    cleaned = rows[2]
    fields = result_fields(output, dict(broker_dispatch_fault="passed", scope=LAUNCHER_FAULT_SCOPE, api=3,
        run=run, owner_uid=uid, systemui_uid=systemui_uid, systemui_pid=systemui_pid,
        fingerprint=fingerprint, native_abi="x86_64", delay_started=cleaned["started"],
        delay_finished=cleaned["finished"], delay_elapsed=cleaned["elapsed"],
        identity_epoch=cleaned["identity_epoch"], delay_calls=1, generation=generation,
        display_token=display_token, catalogue_id=cleaned["catalogue_id"], session_cleaned="false",
        same_session_survived="true", initial_picker_cleaned="true", proxy_restored="true",
        replacement_before_cleanup="not_tested"))
    return dict(fields, phases=rows)


class RunningProbe:
    def __init__(self, host, name, runner, arguments=(), no_restart=False):
        self.host = host
        self.path = host.output / (name + ".log")
        self.runner = runner
        self.arguments = tuple(arguments)
        self.no_restart = no_restart
        self.process = None

    def __enter__(self):
        self.host.guard(expected_user=0)
        argv = ["docker", "exec", self.host.identity, "adb", "-s", "emulator-5580", "shell",
                "am", "instrument", "-w", "-r"]
        if self.no_restart: argv.append("--no-restart")
        argv += ["-e", "run", self.host.run]
        for key, value in self.arguments: argv += ["-e", str(key), str(value)]
        argv.append(self.runner)
        with self.path.open("x") as stream:
            self.process = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT, text=True)
        self.host.owner.trace.append(dict(instrumentation_args=argv, log=self.path.name, pid=self.process.pid))
        return self

    def await_phase(self, parser, phase, timeout=50):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            rows = parser(self.path.read_text())
            match = [row for row in rows if row["phase"] == phase]
            if len(match) == 1: return match[0]
            if self.process.poll() is not None:
                raise ValueError("Broker-dispatch probe ended before " + phase + "; see " + self.path.name)
            time.sleep(.1)
        raise ValueError("Broker-dispatch probe did not reach " + phase)

    def finish(self, timeout=50):
        if self.process.wait(timeout=timeout) != 0:
            raise ValueError("Broker-dispatch probe command failed: " + self.path.name)
        return self.path.read_text()

    def __exit__(self, kind, error, traceback):
        if self.process is None or self.process.poll() is not None: return
        self.host.guard()
        if self.no_restart:
            self.host.shell("am", "broadcast", "--user", 0, "-a", CANCEL, "-p", "com.android.systemui",
                            "--es", "run", self.host.run)
            try: self.process.wait(timeout=50)
            except subprocess.TimeoutExpired: pass  # Isolated guest teardown is the safe final boundary.
        else:
            self.host.shell("am", "force-stop", "--user", 0, APP)
            try: self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.terminate(); self.process.wait(timeout=5)


def broadcast(host, action, package, *, catalogue_id=None):
    arguments = ["am", "broadcast", "--user", 0, "-a", action, "-p", package, "--es", "run", host.run]
    if catalogue_id is not None: arguments += ["--el", "catalogue_id", number(catalogue_id)]
    reply = host.shell(*arguments)
    if re.findall(r"^Broadcast completed: result=([0-9-]+)$", reply, re.M) != ["0"]:
        raise ValueError("Nonce-scoped broker-dispatch broadcast failed")


def verify_fault(test, path):
    check_fault_runtime(path)
    # In bundled mode test.product is deliberately None: the installed OS
    # reference lives in NativeEvidence, not an emulator repair mount.
    evidence = test.native_evidence
    systemui = evidence.product / "system_ext/priv-app/SystemUI/SystemUI.apk"
    if digest(systemui) != evidence.initial["artifacts"]["com.android.systemui"]["sha256"]:
        raise ValueError("Dispatch signer reference differs from the actual admitted SystemUI")
    temporary = test.host("docker", "exec", TOOLS, "mktemp", "-d", "/tmp/wonad-dispatch-check.XXXXXXXX")
    if not re.fullmatch(r"/tmp/wonad-dispatch-check\.[A-Za-z0-9]{8}", temporary):
        raise ValueError("Unexpected dispatch fault inspection directory")
    fault, system = temporary + "/fault.apk", temporary + "/SystemUI.apk"
    try:
        test.host("docker", "cp", path, TOOLS + ":" + fault)
        test.host("docker", "cp", systemui, TOOLS + ":" + system)
        certs = [signer_digest(test.host("docker", "exec", TOOLS, BUILD_TOOLS + "apksigner", "verify",
            "--verbose", "--print-certs", value)) for value in (fault, system)]
        if certs[0] != certs[1]:
            raise ValueError("Dispatch injector is not signed by the actual product platform signer")
        manifest = test.host("docker", "exec", TOOLS, BUILD_TOOLS + "aapt2", "dump", "xmltree",
            "--file", "AndroidManifest.xml", fault)
        fault_manifest(manifest)
        return dict(sha256=digest(path), signer_sha256=certs[0], actual_product_systemui_signer_matches=True,
            r8_runtime_relocated=True, runtime_scope=FAULT_SCOPE)
    finally:
        test.host("docker", "exec", TOOLS, "rm", "-f", "--", fault, system)
        test.host("docker", "exec", TOOLS, "rmdir", "--", temporary)


def run_launcher_dispatch(checks, host, baseline, uid, processes):
    """A second mandatory case, without opening a new 23-gate vocabulary entry."""
    client_parser = lambda raw: launcher_client_phases(raw, host.run, uid)
    with RunningProbe(host, "launcher-dispatch-client", LAUNCHER_RUNNER) as client:
        ready = client.await_phase(client_parser, "client_ready")
        require_process(host, ready["owner_pid"], uid, APP)
        generation, display_token = ready["generation"], ready["display_token"]
        fault_parser = lambda raw: launcher_fault_phases(raw, host.run, uid, checks.systemui_uid,
            processes["com.android.systemui"], generation, display_token)
        with RunningProbe(host, "launcher-dispatch-fault", FAULT_RUNNER,
                (("mode", "launcher-dispatch"), ("owner_uid", uid), ("generation", generation),
                 ("display_token", display_token)), no_restart=True) as fault:
            checks.evidence["launcher_injector_ready"] = fault.await_phase(fault_parser, "injector_ready")
            if checks.process_ids() != processes:
                raise ValueError("No-restart initial-page injector changed an OS process")
            broadcast(host, LAUNCHER_START, APP)
            checks.evidence["launcher_dispatch_delayed"] = fault.await_phase(fault_parser, "dispatch_delayed")
            timed = client.await_phase(client_parser, "timeout_observed", timeout=15)
            checks.evidence["launcher_timeout_observed"] = timed
            cleaned = fault.await_phase(fault_parser, "cleanup_observed", timeout=15)
            if timed["identity_epoch"] != cleaned["identity_epoch"] or checks.process_ids() != processes:
                raise ValueError("Initial-page timeout/cleanup lost the native identity/process epoch")
            fault_result = check_launcher_fault(fault.finish(), checks.fingerprint, host.run, uid,
                checks.systemui_uid, processes["com.android.systemui"], generation, display_token)
            checks.evidence["launcher_fault_instrumentation"] = fault_result
            # Only a successful terminal result with exact proxy restoration
            # permits revealing the independently observed orphan catalogue ID.
            broadcast(host, LAUNCHER_RESTORED, APP, catalogue_id=fault_result["catalogue_id"])
        client.await_phase(client_parser, "recovered")
        proof = check_launcher_client(client.finish(), checks.fingerprint, host.run, uid, baseline)
        if int(proof["abandoned_catalogue"]) != int(fault_result["catalogue_id"]) or \
                proof["identity_epoch"] != fault_result["identity_epoch"]:
            raise ValueError("Initial-page owner and injector observed different abandoned catalogues")
        checks.evidence["launcher_instrumentation"] = proof
    return proof


def run_dispatch(test, fixture, security, fault_path):
    checks, host, baseline, identities, display, phone = prepare(test, fixture, security)
    from native_broker_dispatch_os_sources import capture_os_source_binding
    checks.evidence["os_source_binding"] = capture_os_source_binding(test)
    uid, processes = checks.launcher_uid(), checks.process_ids()
    frozen = freeze_apk(fault_path, test.output, "input-broker-dispatch-fault.apk")
    checks.evidence["fault_apk"] = verify_fault(test, frozen)
    remote = "/state/broker-dispatch-fault.apk"
    test.host("docker", "cp", frozen, test.identity + ":" + remote)
    if test.host("docker", "exec", test.identity, "sha256sum", remote).split()[0] != digest(frozen):
        raise ValueError("Dispatch fault APK container copy differs")
    test.command("install", "-t", "--user", 0, remote)
    checks.evidence.update(owner_uid=uid, os_processes=processes, security_apk=checks.installed_test(),
        native_identities=identities)
    client_parser = lambda raw: client_phases(raw, host.run, uid)
    fault_parser = lambda raw: fault_phases(raw, host.run, uid, checks.systemui_uid,
        processes["com.android.systemui"])
    with RunningProbe(host, "broker-dispatch-client", RUNNER) as client:
        ready = client.await_phase(client_parser, "client_ready")
        require_process(host, ready["owner_pid"], uid, APP)
        with RunningProbe(host, "broker-dispatch-fault", FAULT_RUNNER,
                (("mode", "dispatch"), ("owner_uid", uid)), no_restart=True) as fault:
            checks.evidence["dispatch_injector_ready"] = fault.await_phase(fault_parser, "injector_ready")
            if checks.process_ids() != processes:
                raise ValueError("No-restart dispatch injector changed an OS process")
            broadcast(host, START, APP)
            checks.evidence["dispatch_delayed"] = fault.await_phase(fault_parser, "dispatch_delayed")
            timed = client.await_phase(client_parser, "timeout_observed", timeout=15)
            checks.evidence["dispatch_timeout_observed"] = timed
            cleaned = fault.await_phase(fault_parser, "cleanup_observed", timeout=15)
            if timed["identity_epoch"] != cleaned["identity_epoch"] or checks.process_ids() != processes:
                raise ValueError("Fault/client did not observe one exact identity namespace and stable OS processes")
            fault_result = fault.finish()
            checks.evidence["fault_instrumentation"] = check_fault(fault_result, checks.fingerprint, host.run,
                uid, checks.systemui_uid, processes["com.android.systemui"])
            broadcast(host, RESTORED, APP)
        recovered = client.await_phase(client_parser, "recovered")
        checks.evidence["instrumentation"] = check_client(client.finish(), checks.fingerprint, host.run, uid, baseline)
    launcher = run_launcher_dispatch(checks, host, baseline, uid, processes)
    normal = checks.restore(baseline, identities, display, phone)
    proof = checks.evidence["instrumentation"]
    if checks.process_ids() != processes or normal["generation"] in {
            int(proof["old_generation"]), int(proof["new_generation"]), int(launcher["generation"])} or \
            recovered["generation"] != int(proof["new_generation"]):
        raise ValueError("Normal recovery changed OS identity or reused a dispatch-test generation")
    return dict(native_broker_dispatch="passed", api=3, scope=SCOPE,
        actual_public_binder_timeout=True, exact_unreceived_session_abandoned=True,
        initial_launcher_page_timeout=True, exact_unreceived_catalogue_abandoned=True,
        same_launcher_session_recovered=True, replacement_before_cleanup="not_tested",
        exact_proxy_restored=True, normal_client_recovered=True, full_backend_acceptance="not_passed")


def dispatch_source_hashes():
    root = Path(__file__).resolve().parents[2]
    names = (
        "android/tools/native_broker_dispatch_smoke.py",
        "android/tools/native_broker_dispatch_os_sources.py",
        "android/session-security/src/main/AndroidManifest.xml",
        "android/session-security/src/main/kotlin/org/wonad/desktop/security/NativeBrokerDispatchInstrumentation.kt",
        "android/session-security/src/main/kotlin/org/wonad/desktop/security/NativeLauncherPageTimeoutInstrumentation.kt",
        "android/session-security/src/main/kotlin/org/wonad/desktop/security/NativeSecurityClient.kt",
        "android/transition-fault/src/main/kotlin/org/wonad/desktop/transitionfault/NativeCompletionProofInstrumentation.kt",
    )
    return {name: digest(root / name) for name in names}


def bind_sources(test, expected=None):
    actual = dispatch_source_hashes()
    if expected is not None and actual != expected:
        raise ValueError("Dispatch host/instrumentation source changed during emulator boot")
    test.report["test_sources_sha256"].update(actual)


class NativeBrokerDispatchEmulator(NativeShellEmulator):
    def start(self):
        # StartupSmoke creates/replaces its source map during start. Bind the
        # instrumentation after that, preserving its pre-boot hash observation.
        expected = dispatch_source_hashes()
        super().start()
        bind_sources(self, expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="wonad:qubes")
    parser.add_argument("--bundled-product", action="store_true",
                        help="Use immutable image /product; --product is an evidence-only byte reference")
    for name in ("product", "apk", "fixture-apk", "security-apk", "fault-apk", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    import PIL  # Fail before creating a guest if actual framebuffer decoding is unavailable.
    root, output = Path(__file__).resolve().parents[1] / "out", args.output.resolve()
    if output == root or not output.is_relative_to(root): parser.error("Use a fresh output beneath android/out")
    product, apk, fixture, security, fault = [path.resolve(strict=True) for path in
        (args.product, args.apk, args.fixture_apk, args.security_apk, args.fault_apk)]
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    test = NativeBrokerDispatchEmulator(args.image, output, apk,
                              None if args.bundled_product else product, first_attach_only=True)
    if args.bundled_product:
        test.evidence_product = product
    result = dict(native_broker_dispatch="not_passed", api=3, scope=SCOPE,
        full_backend_acceptance="not_passed")
    try:
        result.update(run_dispatch(test, fixture, security, fault))
        test.native_evidence.finish(); test.verify_test_sources()
    except Exception as error:
        result["native_broker_dispatch"] = "not_passed"; result["error"] = str(error); print(str(error), flush=True)
    finally:
        from native_security_acceptance import audit_gate
        finish(test, result, "native_broker_dispatch",
            semantic_audit=lambda report, directory: audit_gate("broker_dispatch", report, directory))
    return 0 if result["native_broker_dispatch"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
