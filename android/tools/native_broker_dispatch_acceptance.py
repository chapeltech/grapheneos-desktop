"""Re-derive the live BrokerDispatch timeout gate from its sealed evidence.

The producer exercises a public ordinary-app Binder call while a separately
signed, no-restart SystemUI instrumentation blocks one real serial-executor
dispatch.  This auditor deliberately does not trust the producer's PASS flags:
it reparses both instrumentation logs, the exact host/guest command trace, the
frozen fault APK and the native before/recovery captures.
"""
import hashlib
import json
from pathlib import Path
import re

from acceptance_audit import APP, FIXTURE, unique_object
from fault_runtime_contract import check_fault_runtime
from native_backend_acceptance import require
from native_broker_dispatch_smoke import (CANCEL, FAULT_RUNNER, FAULT_SCOPE, RESTORED,
    RUNNER, SCOPE, START, check_client, check_fault, LAUNCHER_RUNNER, LAUNCHER_START,
    LAUNCHER_RESTORED, check_launcher_client, check_launcher_fault)
from native_completion_timeout_smoke import fault_manifest
from native_lock_user_security_smoke import fixture_records
from native_session_security_smoke import exact_task_bindings
from native_shell_smoke import native_snapshot
from wrong_signer_smoke import signer_digest

def probe_invocations(trace, container, run, owner_uid):
    """Admit exactly the ordinary client and no-restart SystemUI injector."""
    prefix = ["docker", "exec", container, "adb", "-s", "emulator-5580", "shell",
              "am", "instrument", "-w", "-r"]
    expected = [
        ("broker-dispatch-client.log", prefix + ["-e", "run", run, RUNNER]),
        ("broker-dispatch-fault.log", prefix + ["--no-restart", "-e", "run", run,
            "-e", "mode", "dispatch", "-e", "owner_uid", str(owner_uid), FAULT_RUNNER]),
    ]
    probes = [(index, row) for index, row in enumerate(trace)
              if isinstance(row, dict) and "instrumentation_args" in row and
              row.get("log") in {"broker-dispatch-client.log", "broker-dispatch-fault.log"}]
    require(len(probes) == 2,
            "Broker dispatch evidence is not the two exact independent instrumentations")
    for (_, row), (log, command) in zip(probes, expected):
        require(set(row) == {"instrumentation_args", "log", "pid"} and
                row["instrumentation_args"] == command and row["log"] == log and
                type(row["pid"]) is int and row["pid"] > 0,
                "Broker dispatch instrumentation invocation differs from its exact runner/scope")
    require(probes[0][1]["pid"] != probes[1][1]["pid"],
            "Broker dispatch probes share a host process identity")
    return probes[0][0], probes[1][0]


def broadcast(rows, action, package, run, *, required=True, catalogue_id=None):
    command = ["am", "broadcast", "--user", "0", "-a", action, "-p", package,
               "--es", "run", run]
    if catalogue_id is not None:
        require(type(catalogue_id) is int and 0 < catalogue_id < 2 ** 63,
                "Invalid abandoned catalogue broadcast identity")
        command += ["--el", "catalogue_id", str(catalogue_id)]
    attempts = [(index, args, raw) for index, args, raw in rows if args[:2] == ["am", "broadcast"] and
                "-a" in args and args.index("-a") + 1 < len(args) and args[args.index("-a") + 1] == action]
    matches = [(index, raw) for index, args, raw in attempts if args == command]
    if not required:
        require(not attempts, "Successful broker dispatch evidence used its emergency cancel path")
        return None
    require(len(attempts) == len(matches) == 1 and
            re.findall(r"^Broadcast completed: result=([0-9-]+)$", matches[0][1], re.M) == ["0"],
            "Missing/failed/ambiguous broker dispatch barrier: " + action)
    return matches[0][0]


def fault_artifact(common, directory, checks, trace):
    """Bind the actual test-only APK to product signer, manifest and DEX scope."""
    from native_security_acceptance import sealed

    name = "input-broker-dispatch-fault.apk"
    frozen = sealed(common, directory, name)
    path = directory / name
    check_fault_runtime(path)
    summary = checks.get("fault_apk")
    require(isinstance(summary, dict) and set(summary) == {
        "sha256", "signer_sha256", "actual_product_systemui_signer_matches",
        "r8_runtime_relocated", "runtime_scope"} and
        summary.get("sha256") == hashlib.sha256(frozen).hexdigest() and
        re.fullmatch(r"[0-9a-f]{64}", str(summary.get("signer_sha256"))) is not None and
        summary.get("actual_product_systemui_signer_matches") is True and
        summary.get("r8_runtime_relocated") is True and summary.get("runtime_scope") == FAULT_SCOPE,
        "Broker dispatch fault artifact summary is incomplete or differs from sealed bytes")

    signatures, manifests = {}, []
    for record in trace:
        command = record.get("command", []) if isinstance(record, dict) else []
        if "error" in record or not isinstance(command, list):
            continue
        if len(command) >= 8 and command[:2] == ["docker", "exec"] and \
                str(command[3]).endswith("/apksigner") and \
                command[4:8] == ["verify", "--verbose", "--print-certs", command[-1]]:
            leaf = Path(command[-1]).name
            if leaf in ("fault.apk", "SystemUI.apk"):
                require(leaf not in signatures, "Repeated ambiguous dispatch injector signer read")
                signatures[leaf] = signer_digest(record.get("output", ""))
        if len(command) >= 9 and command[:2] == ["docker", "exec"] and \
                str(command[3]).endswith("/aapt2") and \
                command[4:9] == ["dump", "xmltree", "--file", "AndroidManifest.xml", command[-1]] and \
                Path(command[-1]).name == "fault.apk":
            manifests.append(record.get("output", ""))
    require(set(signatures) == {"fault.apk", "SystemUI.apk"} and
            signatures["fault.apk"] == signatures["SystemUI.apk"] == summary["signer_sha256"] and
            len(manifests) == 1,
            "Broker dispatch injector lacks its exact product signer/manifest observations")
    fault_manifest(manifests[0])
    return summary


def installed_fault(common, directory, trace, before):
    """Prove the sealed injector bytes were copied and installed before probes."""
    container = common["container"]
    name, remote = "input-broker-dispatch-fault.apk", "/state/broker-dispatch-fault.apk"
    digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
    commands = [
        ["docker", "cp", str((directory / name).resolve()), container + ":" + remote],
        ["docker", "exec", container, "sha256sum", remote],
        ["docker", "exec", container, "adb", "-s", "emulator-5580", "install", "-t",
         "--user", "0", remote],
    ]
    matches = []
    for expected in commands:
        found = [(index, row) for index, row in enumerate(trace)
                 if isinstance(row, dict) and row.get("command") == expected]
        require(len(found) == 1 and "error" not in found[0][1],
                "Missing/failed/ambiguous sealed broker dispatch fault installation")
        matches.append(found[0])
    require(matches[0][0] < matches[1][0] < matches[2][0] < before and
            re.fullmatch(re.escape(digest) + r"\s+" + re.escape(remote),
                         str(matches[1][1].get("output", "")).strip()) is not None and
            re.search(r"(?:^|\n)Success(?:\n|$)", str(matches[2][1].get("output", ""))) is not None,
            "Broker dispatch fault bytes/install outcome differ from the sealed APK")
    return matches[2][0]


def installed_security(common, directory, checks, rows):
    """Bind the public instrumentation package to its installed sealed bytes."""
    from native_security_acceptance import sealed

    summary = checks.get("security_apk")
    frozen = sealed(common, directory, "input-native-isolation-security.apk")
    require(isinstance(summary, dict) and set(summary) == {"path", "sha256"} and
            isinstance(summary.get("path"), str) and summary["path"].startswith("/data/app/") and
            summary["sha256"] == hashlib.sha256(frozen).hexdigest(),
            "Broker dispatch public probe APK differs from its sealed input")
    paths = [raw for _, args, raw in rows if args == ["pm", "path", "org.wonad.desktop.test"]]
    require(paths and all(raw == "package:" + summary["path"] for raw in paths),
            "Broker dispatch public probe path differs from PackageManager")
    hashes = [raw for _, args, raw in rows if args == ["sha256sum", summary["path"]]]
    require(hashes and all(re.fullmatch(re.escape(summary["sha256"]) + r"\s+" +
            re.escape(summary["path"]), raw) is not None for raw in hashes),
            "Broker dispatch public probe digest differs from installed bytes")
    return summary


def process_identities(checks, rows, owner_uid, owner_pid):
    """Re-read ordinary owner, system_server and primary SystemUI identities."""
    from native_security_acceptance import observed_system_pid

    processes = checks.get("os_processes")
    require(isinstance(processes, dict) and set(processes) == {
        "system_server", "com.android.systemui"}, "Missing exact broker dispatch OS process identities")
    system_pid = observed_system_pid(checks, rows)
    require(processes["system_server"] == system_pid,
            "Broker dispatch system_server summary differs from actual observations")

    owner_reads = [raw for _, args, raw in rows if
                   args == ["pm", "list", "packages", "-U", "--user", "0", APP]]
    require(owner_reads and all(re.findall(r"^package:" + re.escape(APP) +
            r" uid:([1-9]\d*)$", raw, re.M) == [str(owner_uid)] for raw in owner_reads),
            "Broker dispatch owner UID differs from PackageManager")

    uid_commands = (["cmd", "package", "list", "packages", "-U", "com.android.systemui"],
                    ["pm", "list", "packages", "-U", "--user", "0", "com.android.systemui"])
    ui_reads = [raw for _, args, raw in rows if args in uid_commands]
    ui_values = [re.findall(r"^package:com\.android\.systemui uid:([1-9]\d*)$", raw, re.M)
                 for raw in ui_reads]
    require(ui_values and all(len(value) == 1 and value == ui_values[0] for value in ui_values),
            "Broker dispatch SystemUI UID lacks stable PackageManager observations")
    systemui_uid = int(ui_values[0][0])
    ps = [raw for _, args, raw in rows if args == ["ps", "-A", "-o", "UID,PID,NAME"]]
    ui_processes = [re.findall(r"^\s*([1-9]\d*)\s+([1-9]\d*)\s+com\.android\.systemui\s*$",
                               raw, re.M) for raw in ps]
    require(ps and all(value == [(str(systemui_uid), str(processes["com.android.systemui"]))]
                       for value in ui_processes),
            "Broker dispatch replaced or misidentified the primary SystemUI process")
    require(any(re.findall(r"^\s*" + str(owner_uid) + r"\s+" + str(owner_pid) +
            r"\s+(\S+)\s*$", raw, re.M) == [APP] for raw in ps),
            "Broker dispatch client PID is not the actual ordinary Wonad process")
    return system_pid, systemui_uid, processes["com.android.systemui"]


def launcher_probe_invocations(trace, container, run, owner_uid, generation, display_token):
    prefix = ["docker", "exec", container, "adb", "-s", "emulator-5580", "shell",
              "am", "instrument", "-w", "-r"]
    expected = [
        ("launcher-dispatch-client.log", prefix + ["-e", "run", run, LAUNCHER_RUNNER]),
        ("launcher-dispatch-fault.log", prefix + ["--no-restart", "-e", "run", run,
            "-e", "mode", "launcher-dispatch", "-e", "owner_uid", str(owner_uid),
            "-e", "generation", str(generation), "-e", "display_token", str(display_token), FAULT_RUNNER]),
    ]
    probes = [(index, row) for index, row in enumerate(trace)
              if isinstance(row, dict) and "instrumentation_args" in row]
    require(len(probes) == 4 and [row.get("log") for _, row in probes] == [
        "broker-dispatch-client.log", "broker-dispatch-fault.log", *[log for log, _ in expected]],
        "Broker dispatch requires both exact open-session and initial-page probes")
    for (_, row), (log, command) in zip(probes[2:], expected):
        require(set(row) == {"instrumentation_args", "log", "pid"} and row["log"] == log and
                row["instrumentation_args"] == command and type(row["pid"]) is int and row["pid"] > 0,
                "Initial-page instrumentation differs from exact scope/owner/lease")
    require(len({row["pid"] for _, row in probes}) == 4,
            "Broker dispatch instrumentation host processes were reused")
    return probes[2][0], probes[3][0]


def audit_launcher_case(common, directory, checks, trace, rows, baseline, owner_uid,
                        systemui_uid, systemui_pid, previous_restored):
    from native_security_acceptance import sealed

    source_names = (
        "android/session-security/src/main/AndroidManifest.xml",
        "android/session-security/src/main/kotlin/org/wonad/desktop/security/NativeLauncherPageTimeoutInstrumentation.kt",
        "android/session-security/src/main/kotlin/org/wonad/desktop/security/NativeSecurityClient.kt",
        "android/transition-fault/src/main/kotlin/org/wonad/desktop/transitionfault/NativeCompletionProofInstrumentation.kt",
    )
    root = Path(__file__).resolve().parents[2]
    sources = common.get("test_sources_sha256", {})
    require(all(sources.get(name) == hashlib.sha256((root / name).read_bytes()).hexdigest()
                for name in source_names), "Initial-page source/manifest bindings are missing or changed")
    client = check_launcher_client(sealed(common, directory, "launcher-dispatch-client.log").decode(),
        common["fingerprint"], common["run"], owner_uid, baseline)
    require(client == checks.get("launcher_instrumentation") and
            client["phases"][1] == checks.get("launcher_timeout_observed"),
            "Initial-page client summary differs from its original ordinary probe")
    generation, display_token = int(client["generation"]), int(client["display_token"])
    old = checks.get("instrumentation", {})
    require(isinstance(old, dict) and all(re.fullmatch(r"[1-9][0-9]*", str(old.get(key, "")))
                for key in ("old_generation", "new_generation")),
            "Initial-page case lacks the original open-session evidence")
    require(generation not in {baseline["generation"], int(old["old_generation"]), int(old["new_generation"])},
            "Initial-page case reused an open-session test generation")
    client_index, fault_index = launcher_probe_invocations(trace, common["container"], common["run"],
        owner_uid, generation, display_token)
    process_identities(checks, rows, owner_uid, client["phases"][0]["owner_pid"])
    fault = check_launcher_fault(sealed(common, directory, "launcher-dispatch-fault.log").decode(),
        common["fingerprint"], common["run"], owner_uid, systemui_uid, systemui_pid, generation, display_token)
    require(fault == checks.get("launcher_fault_instrumentation") and
            fault["phases"][0] == checks.get("launcher_injector_ready") and
            fault["phases"][1] == checks.get("launcher_dispatch_delayed") and
            client["identity_epoch"] == fault["identity_epoch"] and
            client["abandoned_catalogue"] == fault["catalogue_id"],
            "Initial-page client/fault summaries do not bind one abandoned native catalogue")
    started = broadcast(rows, LAUNCHER_START, APP, common["run"])
    restored = broadcast(rows, LAUNCHER_RESTORED, APP, common["run"], catalogue_id=int(fault["catalogue_id"]))
    require(previous_restored < client_index < fault_index < started < restored,
            "Initial-page probe/barrier ordering differs from actual commands")
    return client, restored


def audit_dispatch(report, directory, common):
    from native_security_acceptance import (canonical as security_canonical, guest_observations,
        recovery_input, sealed)
    from native_timeout_acceptance import live_capture

    require(type(report.get("api")) is int and report["api"] == 3 and
            report.get("scope") == SCOPE and report.get("native_broker_dispatch") == "passed" and
            report.get("actual_public_binder_timeout") is True and
            report.get("exact_unreceived_session_abandoned") is True and
            report.get("initial_launcher_page_timeout") is True and
            report.get("exact_unreceived_catalogue_abandoned") is True and
            report.get("same_launcher_session_recovered") is True and
            report.get("replacement_before_cleanup") == "not_tested" and
            report.get("exact_proxy_restored") is True and
            report.get("normal_client_recovered") is True and
            report.get("full_backend_acceptance") == "not_passed",
            "Wrong broker dispatch gate/scope/result")
    checks = report.get("startup", {}).get("native_shell_checks")
    require(isinstance(checks, dict), "Missing broker dispatch original native observations")
    trace = json.loads(sealed(common, directory, "commands.json"), object_pairs_hook=unique_object)
    require(isinstance(trace, list), "Malformed broker dispatch command trace")
    rows = guest_observations(trace, common["container"])
    from native_broker_dispatch_os_sources import audit_os_source_binding, audit_dispatch_product_mode
    binding = audit_os_source_binding(report, directory, common, checks, trace)
    audit_dispatch_product_mode(report, directory, common, trace, binding)

    baseline = native_snapshot(sealed(common, directory,
        "native-isolation-before-service.txt").decode(), require_identity_hints=True)
    require(security_canonical(baseline) == checks.get("native-isolation-before", {}).get("snapshot"),
            "Broker dispatch baseline summary differs from its native service dump")
    owner_uid = checks.get("owner_uid")
    require(type(owner_uid) is int and 10000 <= owner_uid < 20000,
            "Broker dispatch owner is not an ordinary user-0 app UID")

    client_raw = sealed(common, directory, "broker-dispatch-client.log").decode()
    client = check_client(client_raw, common["fingerprint"], common["run"], owner_uid, baseline)
    require(client == checks.get("instrumentation") and
            client["phases"][1] == checks.get("dispatch_timeout_observed"),
            "Broker dispatch client summary differs from its original public probe")
    owner_pid = client["phases"][0]["owner_pid"]
    systemui_pid = checks.get("os_processes", {}).get("com.android.systemui")

    owner_index, fault_index = probe_invocations(trace, common["container"], common["run"], owner_uid)
    installed_fault(common, directory, trace, owner_index)
    installed_security(common, directory, checks, rows)
    system_pid, systemui_uid, observed_ui_pid = process_identities(
        checks, rows, owner_uid, owner_pid)
    require(systemui_pid == observed_ui_pid, "Broker dispatch SystemUI PID summary changed")

    fault_raw = sealed(common, directory, "broker-dispatch-fault.log").decode()
    fault = check_fault(fault_raw, common["fingerprint"], common["run"], owner_uid,
                        systemui_uid, systemui_pid)
    require(fault == checks.get("fault_instrumentation") and
            fault["phases"][0] == checks.get("dispatch_injector_ready") and
            fault["phases"][1] == checks.get("dispatch_delayed") and
            client["phases"][1]["identity_epoch"] == fault["phases"][2]["identity_epoch"],
            "Broker dispatch fault summary differs from its original no-restart probe")

    started = broadcast(rows, START, APP, common["run"])
    restored = broadcast(rows, RESTORED, APP, common["run"])
    broadcast(rows, CANCEL, "com.android.systemui", common["run"], required=False)
    require(owner_index < fault_index < started < restored,
            "Broker dispatch probe/barrier ordering differs from the actual trace")
    launcher_client, launcher_restored = audit_launcher_case(common, directory, checks, trace, rows,
        baseline, owner_uid, systemui_uid, systemui_pid, restored)
    fault_artifact(common, directory, checks, trace)

    candidates = []
    for index, args, raw in rows:
        if index >= owner_index or args != ["dumpsys", "activity", FIXTURE]:
            continue
        try:
            records = fixture_records(raw, 0)[0]
            displays = {row["display"] for row in records.values()}
            if set(records) == set(checks.get("native_identities", {})) and len(displays) == 1:
                binding = exact_task_bindings(baseline, records, next(iter(displays)))
                candidates.append((index, records, binding))
        except (KeyError, TypeError, ValueError):
            continue
    require(candidates and security_canonical(candidates[-1][2]) == checks.get("native_identities"),
            "Broker dispatch baseline lacks exact original fixture/native bindings")
    _, original, bindings = candidates[-1]
    live_capture(common, directory, checks, "native-isolation-before", baseline, owner_uid,
                 system_pid, trace, rows, -1, owner_index)

    recovered = native_snapshot(sealed(common, directory,
        "native-security-recovered-service.txt").decode(), require_identity_hints=True)
    require(security_canonical(recovered) == checks.get("recovered_snapshot") and
            recovered["generation"] not in {baseline["generation"],
                int(client["old_generation"]), int(client["new_generation"]), int(launcher_client["generation"])} and
            recovered["identity_epoch"] == baseline["identity_epoch"] and
            recovered["tasks"] == baseline["tasks"] and
            recovered["monitors"] == {display: {**monitor, "shell_generation": recovered["generation"]}
                                      for display, monitor in baseline["monitors"].items()},
            "Normal broker dispatch recovery did not preserve exact native identities/layout")
    live_capture(common, directory, checks, "native-security-recovered", recovered, owner_uid,
                 system_pid, trace, rows, launcher_restored, len(trace))
    delivered = recovery_input(checks, rows, launcher_restored, original, bindings, recovered)
    require(delivered > launcher_restored,
            "Broker dispatch recovery lacks actual post-restoration ordinary input")
    return True
