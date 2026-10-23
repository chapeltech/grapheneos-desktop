"""Adversarial contracts for the live BrokerDispatch evidence auditor."""
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ANDROID = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANDROID / "tools"))
import native_broker_dispatch_acceptance as audit
from native_broker_dispatch_smoke import CANCEL, FAULT_RUNNER, RESTORED, RUNNER, START

CONTAINER = "a" * 64
RUN = "b" * 32
UID = 10123


class NativeBrokerDispatchAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wonad-broker-dispatch-audit-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.common = dict(container=CONTAINER, run=RUN, evidence_files={})

    def bind(self, name, raw):
        path = self.directory / name
        path.write_bytes(raw)
        self.common["evidence_files"][name] = hashlib.sha256(raw).hexdigest()
        return path

    def probes(self):
        prefix = ["docker", "exec", CONTAINER, "adb", "-s", "emulator-5580", "shell",
                  "am", "instrument", "-w", "-r"]
        return [
            dict(instrumentation_args=prefix + ["-e", "run", RUN, RUNNER],
                 log="broker-dispatch-client.log", pid=81),
            dict(instrumentation_args=prefix + ["--no-restart", "-e", "run", RUN,
                "-e", "mode", "dispatch", "-e", "owner_uid", str(UID), FAULT_RUNNER],
                log="broker-dispatch-fault.log", pid=82),
        ]

    def test_exact_two_probe_invocations_are_rederived(self):
        self.assertEqual((0, 1), audit.probe_invocations(self.probes(), CONTAINER, RUN, UID))

    def test_probe_mutations_fail_closed(self):
        mutations = (
            lambda rows: rows.append(copy.deepcopy(rows[1])),
            lambda rows: rows.pop(),
            lambda rows: rows[1]["instrumentation_args"].remove("--no-restart"),
            lambda rows: rows[1]["instrumentation_args"].__setitem__(-1, RUNNER),
            lambda rows: rows[1]["instrumentation_args"].__setitem__(-2, str(UID + 1)),
            lambda rows: rows[1].__setitem__("pid", rows[0]["pid"]),
            lambda rows: rows[0].__setitem__("unbound", True),
        )
        for mutation in mutations:
            rows = self.probes(); mutation(rows)
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                audit.probe_invocations(rows, CONTAINER, RUN, UID)

    def guest_broadcast(self, index, action, package, result="0"):
        return (index, ["am", "broadcast", "--user", "0", "-a", action, "-p", package,
                        "--es", "run", RUN], "Broadcast completed: result=" + result)

    def test_exact_success_barriers_and_absent_cancel_are_required(self):
        rows = [self.guest_broadcast(10, START, "org.wonad.desktop"),
                self.guest_broadcast(20, RESTORED, "org.wonad.desktop")]
        self.assertEqual(10, audit.broadcast(rows, START, "org.wonad.desktop", RUN))
        self.assertEqual(20, audit.broadcast(rows, RESTORED, "org.wonad.desktop", RUN))
        self.assertIsNone(audit.broadcast(rows, CANCEL, "com.android.systemui", RUN, required=False))

    def test_duplicate_failed_wrong_user_and_emergency_cancel_barriers_fail(self):
        good = self.guest_broadcast(10, START, "org.wonad.desktop")
        cases = ([good, copy.deepcopy(good)],
                 [self.guest_broadcast(10, START, "org.wonad.desktop", "1")],
                 [(10, [part for part in good[1] if part != "--user" and part != "0"], good[2])])
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                audit.broadcast(rows, START, "org.wonad.desktop", RUN)
        with self.assertRaisesRegex(ValueError, "emergency cancel"):
            audit.broadcast([self.guest_broadcast(11, CANCEL, "com.android.systemui")],
                            CANCEL, "com.android.systemui", RUN, required=False)

    def fault_install_trace(self, digest):
        source = str((self.directory / "input-broker-dispatch-fault.apk").resolve())
        remote = "/state/broker-dispatch-fault.apk"
        return [
            dict(command=["docker", "cp", source, CONTAINER + ":" + remote], output=""),
            dict(command=["docker", "exec", CONTAINER, "sha256sum", remote],
                 output=digest + "  " + remote),
            dict(command=["docker", "exec", CONTAINER, "adb", "-s", "emulator-5580", "install",
                          "-t", "--user", "0", remote], output="Performing Streamed Install\nSuccess"),
        ]

    def test_fault_install_is_bound_to_sealed_path_bytes_order_and_success(self):
        path = self.bind("input-broker-dispatch-fault.apk", b"fault-apk")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(2, audit.installed_fault(self.common, self.directory,
                                                  self.fault_install_trace(digest), 3))
        for mutation in (
            lambda rows: rows[0]["command"].__setitem__(2, "/tmp/foreign.apk"),
            lambda rows: rows[1].__setitem__("output", "0" * 64 + "  /state/broker-dispatch-fault.apk"),
            lambda rows: rows[2].__setitem__("output", "Failure [INSTALL_FAILED_INVALID_APK]"),
            lambda rows: rows.append(copy.deepcopy(rows[2])),
        ):
            rows = self.fault_install_trace(digest); mutation(rows)
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                audit.installed_fault(self.common, self.directory, rows, 4)
        with self.assertRaises(ValueError):
            audit.installed_fault(self.common, self.directory, self.fault_install_trace(digest), 2)

    def test_fault_artifact_rechecks_bytes_signer_manifest_and_runtime_scope(self):
        raw = b"synthetic unit APK bytes"
        self.bind("input-broker-dispatch-fault.apk", raw)
        signer = "f" * 64
        checks = dict(fault_apk=dict(sha256=hashlib.sha256(raw).hexdigest(), signer_sha256=signer,
            actual_product_systemui_signer_matches=True, r8_runtime_relocated=True,
            runtime_scope=audit.FAULT_SCOPE))
        trace = [
            dict(command=["docker", "exec", "tools", "/sdk/apksigner", "verify", "--verbose",
                          "--print-certs", "/tmp/check/fault.apk"], output="fault signer"),
            dict(command=["docker", "exec", "tools", "/sdk/apksigner", "verify", "--verbose",
                          "--print-certs", "/tmp/check/SystemUI.apk"], output="system signer"),
            dict(command=["docker", "exec", "tools", "/sdk/aapt2", "dump", "xmltree", "--file",
                          "AndroidManifest.xml", "/tmp/check/fault.apk"], output="manifest"),
        ]
        with patch.object(audit, "check_fault_runtime") as runtime, \
                patch.object(audit, "signer_digest", return_value=signer), \
                patch.object(audit, "fault_manifest") as manifest:
            self.assertIs(checks["fault_apk"], audit.fault_artifact(
                self.common, self.directory, checks, trace))
        runtime.assert_called_once_with(self.directory / "input-broker-dispatch-fault.apk")
        manifest.assert_called_once_with("manifest")
        for mutation in (
            lambda value, rows: value["fault_apk"].__setitem__("runtime_scope", "diagnostic"),
            lambda value, rows: value["fault_apk"].__setitem__("r8_runtime_relocated", False),
            lambda value, rows: rows.pop(),
            lambda value, rows: rows.append(copy.deepcopy(rows[0])),
        ):
            changed, records = copy.deepcopy(checks), copy.deepcopy(trace); mutation(changed, records)
            with self.subTest(changed=changed, records=records), \
                    patch.object(audit, "check_fault_runtime"), \
                    patch.object(audit, "signer_digest", return_value=signer), \
                    patch.object(audit, "fault_manifest"), self.assertRaises(ValueError):
                audit.fault_artifact(self.common, self.directory, changed, records)

    def test_public_probe_apk_is_bound_to_installed_path_and_digest(self):
        raw = b"public-probe"
        self.bind("input-native-isolation-security.apk", raw)
        digest = hashlib.sha256(raw).hexdigest(); path = "/data/app/exact/base.apk"
        checks = dict(security_apk=dict(path=path, sha256=digest))
        rows = [(1, ["pm", "path", "org.wonad.desktop.test"], "package:" + path),
                (2, ["sha256sum", path], digest + "  " + path)]
        self.assertEqual(checks["security_apk"],
                         audit.installed_security(self.common, self.directory, checks, rows))
        for mutation in (
            lambda value, observed: value["security_apk"].__setitem__("sha256", "0" * 64),
            lambda value, observed: observed[0].__setitem__(2, "package:/data/app/other/base.apk"),
            lambda value, observed: observed.pop(),
        ):
            changed, observed = copy.deepcopy(checks), [list(row) for row in rows]
            mutation(changed, observed)
            with self.subTest(changed=changed, observed=observed), self.assertRaises(ValueError):
                audit.installed_security(self.common, self.directory, changed,
                                         [tuple(row) for row in observed])

    def process_rows(self):
        ps = ("UID PID NAME\n1000 222 system_server\n1000 333 com.android.systemui\n" +
              str(UID) + " 444 org.wonad.desktop")
        return [(1, ["pidof", "system_server"], "222"),
                (2, ["ps", "-A", "-o", "UID,PID,NAME"], ps),
                (3, ["pm", "list", "packages", "-U", "--user", "0", "org.wonad.desktop"],
                 "package:org.wonad.desktop uid:" + str(UID)),
                (4, ["cmd", "package", "list", "packages", "-U", "com.android.systemui"],
                 "package:com.android.systemui uid:1000"),
                (5, ["pm", "list", "packages", "-U", "--user", "0", "com.android.systemui"],
                 "package:com.android.systemui uid:1000"),
                (6, ["pidof", "system_server"], "222"),
                (7, ["ps", "-A", "-o", "UID,PID,NAME"], ps)]

    def test_os_and_ordinary_process_identities_are_rederived(self):
        checks = dict(os_processes={"system_server": 222, "com.android.systemui": 333})
        self.assertEqual((222, 1000, 333),
                         audit.process_identities(checks, self.process_rows(), UID, 444))
        cases = (
            ({"system_server": 223, "com.android.systemui": 333}, self.process_rows()),
            ({"system_server": 222, "com.android.systemui": 334}, self.process_rows()),
            (checks["os_processes"], [row for row in self.process_rows() if row[1] !=
                                      ["pm", "list", "packages", "-U", "--user", "0",
                                       "org.wonad.desktop"]]),
        )
        for processes, rows in cases:
            with self.subTest(processes=processes), self.assertRaises(ValueError):
                audit.process_identities(dict(os_processes=processes), rows, UID, 444)

    def test_top_level_result_booleans_cannot_replace_raw_evidence(self):
        report = dict(api=3, scope=audit.SCOPE, native_broker_dispatch="passed",
            actual_public_binder_timeout=True, exact_unreceived_session_abandoned=True,
            initial_launcher_page_timeout=True, exact_unreceived_catalogue_abandoned=True,
            same_launcher_session_recovered=True, replacement_before_cleanup="not_tested",
            exact_proxy_restored=True, normal_client_recovered=True,
            full_backend_acceptance="not_passed", startup=dict(native_shell_checks={}))
        mutations = (("api", True), ("scope", "diagnostic"),
                     ("native_broker_dispatch", "not_passed"),
                     ("actual_public_binder_timeout", 1),
                     ("exact_unreceived_session_abandoned", False),
                     ("initial_launcher_page_timeout", False),
                     ("exact_unreceived_catalogue_abandoned", 1),
                     ("same_launcher_session_recovered", None),
                     ("replacement_before_cleanup", "passed"),
                     ("exact_proxy_restored", "true"),
                     ("normal_client_recovered", None),
                     ("full_backend_acceptance", "passed"))
        for field, value in mutations:
            changed = dict(report, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, "Wrong broker"):
                audit.audit_dispatch(changed, self.directory, self.common)
        with self.assertRaisesRegex(ValueError, "observation"):
            audit.audit_dispatch(report, self.directory, self.common)


if __name__ == "__main__":
    unittest.main()
