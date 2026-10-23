"""Strict driver/source coverage for the real BrokerDispatch runtime smoke."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET

ANDROID = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANDROID / "tools"))
import native_broker_dispatch_smoke as dispatch
from test_native_lock_user_driver import RUN, UID, snapshot


def status(**fields):
    return "".join("INSTRUMENTATION_STATUS: " + key + "=" + str(value) + "\n"
                   for key, value in fields.items()) + "INSTRUMENTATION_STATUS_CODE: 1\n"


def client_phase(phase, **changes):
    fields = dict(run=RUN, phase=phase, api=3, owner_uid=UID, owner_pid=1234)
    if phase == "timeout_observed":
        abandoned = snapshot()
        abandoned.update(focused_display_token=0, tasks=[])
        for display in abandoned["displays"]: display["shell_generation"] = 1
        fields.update(elapsed=2010, generation=2, identity_epoch=44, revocation_reason=5,
                      evidence=json.dumps(abandoned, separators=(",", ":")))
    elif phase == "recovered":
        fields.update(generation=3, identity_epoch=44,
                      evidence=json.dumps(snapshot(3), separators=(",", ":")))
    fields.update(changes)
    return status(**fields)


def client_result(**changes):
    abandoned = snapshot()
    abandoned.update(focused_display_token=0, tasks=[])
    for display in abandoned["displays"]: display["shell_generation"] = 1
    proof = dict(abandoned=abandoned, recovered=snapshot(3))
    fields = dict(native_broker_dispatch="passed", scope=dispatch.SCOPE, api=3, run=RUN,
        owner_uid=UID, owner_pid=1234, fingerprint="wonad/test", native_abi="x86_64",
        old_generation=2, new_generation=3, identity_epoch=44, dispatch_elapsed=2010,
        revocation_reason=5, timeout_message="Broker did not respond", callbacks_silent="true",
        proxy_restoration_observed="true", evidence=json.dumps(proof, separators=(",", ":")))
    fields.update(changes)
    return client_phase("client_ready") + client_phase("timeout_observed") + client_phase("recovered") + \
        "".join("INSTRUMENTATION_RESULT: " + key + "=" + str(value) + "\n" for key, value in fields.items()) + \
        "INSTRUMENTATION_CODE: -1\n"


def fault_phase(phase, **changes):
    fields = dict(run=RUN, phase=phase, api=3, owner_uid=UID, systemui_uid=1000, systemui_pid=2222)
    if phase == "dispatch_delayed": fields.update(started=10000, identity_epoch=44)
    elif phase == "cleanup_observed": fields.update(started=10000, finished=14500, elapsed=4500, identity_epoch=44)
    fields.update(changes)
    return status(**fields)


def fault_result(**changes):
    fields = dict(broker_dispatch_fault="passed", scope=dispatch.FAULT_SCOPE, api=3, run=RUN,
        owner_uid=UID, systemui_uid=1000, systemui_pid=2222, fingerprint="wonad/test", native_abi="x86_64",
        delay_started=10000, delay_finished=14500, delay_elapsed=4500, identity_epoch=44,
        delay_calls=1, session_cleaned="true", proxy_restored="true")
    fields.update(changes)
    return fault_phase("injector_ready") + fault_phase("dispatch_delayed") + fault_phase("cleanup_observed") + \
        "".join("INSTRUMENTATION_RESULT: " + key + "=" + str(value) + "\n" for key, value in fields.items()) + \
        "INSTRUMENTATION_CODE: -1\n"


class NativeBrokerDispatchSmokeTests(unittest.TestCase):
    def test_both_fault_modes_use_one_exact_typed_private_desktop_accessor(self):
        source = (ANDROID / "transition-fault/src/main/kotlin/org/wonad/desktop/transitionfault/NativeCompletionProofInstrumentation.kt").read_text()
        self.assertNotIn('it.name == "getNativeDesktop"', source)
        self.assertEqual(2, source.count("val native = nativeDesktop(parentClass, parent, loader)"))
        body = source.split("private fun nativeDesktop(", 1)[1].split("private fun call(", 1)[0]
        for invariant in ('parentClass.name == "org.wonad.desktop.broker.WonadController"',
                'parent.javaClass === parentClass',
                'Class.forName("org.wonad.desktop.broker.NativeDesktopController", false, loader)',
                'parentClass.declaredMethods.single', 'it.declaringClass === parentClass',
                'it.parameterCount == 0', 'it.returnType === nativeClass',
                '!java.lang.reflect.Modifier.isStatic(it.modifiers)', 'native.javaClass === nativeClass'):
            self.assertIn(invariant, body)

    baseline = dict(generation=1, identity_epoch=44, tasks={7: {}, 8: {}}, monitors={
        3: dict(display=3, token=90, workspace=1, density=160, identity_hint="50",
                area=[0, 0, 4000, 2000], shell_generation=1)})

    def test_complete_client_and_fault_receipts(self):
        client = dispatch.check_client(client_result(), "wonad/test", RUN, UID, self.baseline)
        fault = dispatch.check_fault(fault_result(), "wonad/test", RUN, UID, 1000, 2222)
        self.assertEqual("passed", client["native_broker_dispatch"])
        self.assertEqual("true", fault["session_cleaned"])

    def test_driver_help_is_self_contained_outside_repository_cwd(self):
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("PYTHONPATH", "PYTHONHOME")}
        result = subprocess.run([sys.executable, dispatch.__file__, "--help"], cwd="/tmp",
            env=environment, text=True, capture_output=True, timeout=30)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("usage:", result.stdout)

    def test_client_rejects_non_two_second_timeout_or_wrong_revocation(self):
        for output in (client_result().replace("elapsed=2010", "elapsed=1000"),
                       client_result().replace("revocation_reason=5", "revocation_reason=4"),
                       client_result(dispatch_elapsed=4001),
                       client_result(timeout_message="Broker operation failed")):
            with self.subTest(output=output), self.assertRaises(ValueError):
                dispatch.check_client(output, "wonad/test", RUN, UID, self.baseline)

    def test_client_requires_fresh_generation_and_exact_identity_continuity(self):
        for output in (client_result(new_generation=2),
                       client_result().replace('"identity_epoch":44', '"identity_epoch":45', 1),
                       client_result().replace('"token":7', '"token":9', 1),
                       client_result(callbacks_silent="false"),
                       client_result(proxy_restoration_observed="false")):
            with self.subTest(output=output), self.assertRaises(ValueError):
                dispatch.check_client(output, "wonad/test", RUN, UID, self.baseline)

    def test_pre_ui_admission_cannot_claim_tasks_shell_readiness_or_other_displays(self):
        admitted = snapshot()
        admitted.update(focused_display_token=0, tasks=[])
        for display in admitted["displays"]: display["shell_generation"] = 1
        self.assertEqual([], dispatch.admission_snapshot(admitted)["tasks"])
        for mutation in (
            lambda value: value.update(tasks=[snapshot()["tasks"][0]]),
            lambda value: value["displays"][0].update(shell_generation=value["generation"]),
            lambda value: value["displays"][0].update(token=91),
            lambda value: value.update(focused_display_token=90),
            lambda value: value.update(focused_display_token=False),
            lambda value: value.update(focused_token=False),
        ):
            changed = json.loads(json.dumps(admitted)); mutation(changed)
            with self.subTest(changed=changed):
                if changed["displays"][0]["token"] == 91:
                    output = client_result().replace('"token":90', '"token":91', 1)
                    with self.assertRaises(ValueError):
                        dispatch.check_client(output, "wonad/test", RUN, UID, self.baseline)
                else:
                    with self.assertRaises(ValueError): dispatch.admission_snapshot(changed)

    def test_baseline_requires_real_native_snapshot_hex_identity_hint(self):
        for hint in (80, "", "0", "50A", "not-hex", "8000000000000000"):
            baseline = dict(self.baseline, monitors={3: dict(self.baseline["monitors"][3],
                identity_hint=hint)})
            with self.subTest(hint=hint), self.assertRaises(ValueError):
                dispatch.check_client(client_result(), "wonad/test", RUN, UID, baseline)

    def test_fault_requires_single_long_delay_cleanup_and_exact_restoration(self):
        for output in (fault_result().replace("elapsed=4500", "elapsed=2000"),
                       fault_result(delay_calls=2), fault_result(session_cleaned="false"),
                       fault_result(proxy_restored="false"),
                       fault_result().replace("identity_epoch=44", "identity_epoch=45", 1)):
            with self.subTest(output=output), self.assertRaises(ValueError):
                dispatch.check_fault(output, "wonad/test", RUN, UID, 1000, 2222)

    def test_duplicate_phase_or_result_fields_cannot_pass(self):
        with self.assertRaises(ValueError):
            dispatch.client_phases(client_phase("client_ready") * 2, RUN, UID)
        with self.assertRaises(ValueError):
            dispatch.check_fault(fault_result() + "INSTRUMENTATION_RESULT: delay_calls=1\n",
                                 "wonad/test", RUN, UID, 1000, 2222)

    def test_runtime_fault_is_exact_real_iwm_call_and_restores_only_its_proxy(self):
        source = (ANDROID / "transition-fault/src/main/kotlin/org/wonad/desktop/transitionfault/NativeCompletionProofInstrumentation.kt").read_text()
        body = source.split("private fun runDispatchFault()", 1)[1].split("private fun field", 1)[0]
        self.assertIn('method.name != "getWonadNativeIdentityEpoch"', body)
        self.assertLess(body.index("method.invoke(delegate, *args)"), body.index("SystemClock.sleep(DISPATCH_DELAY_MILLIS)"))
        self.assertIn('field(native, "session") == null', body)
        self.assertIn('check(field(native, "session") == null) { "Unreceived native Session survived abandonment" }', body)
        cleanup = body.split("} finally {", 1)[1]
        self.assertIn("wmCache.get(null) === proxy", cleanup)
        self.assertIn("wmCache.set(null, original)", cleanup)
        self.assertIn('Build.TYPE == "userdebug"', body)

    def test_owner_uses_only_public_api_and_exact_timeout_result(self):
        source = (ANDROID / "session-security/src/main/kotlin/org/wonad/desktop/security/NativeBrokerDispatchInstrumentation.kt").read_text()
        self.assertIn("broker.openSession(DesktopProtocol.API_VERSION, events)", source)
        self.assertIn('failure?.message == "Broker did not respond"', source)
        self.assertIn("elapsed in 1800..4000", source)
        self.assertIn("events.revoked.poll(10, TimeUnit.SECONDS)", source)
        self.assertIn("abandoned.tasks.isEmpty()", source)
        self.assertIn("recovered.tasks.size == 2", source)
        self.assertIn("displayIdentity(recovered) == displayIdentity(abandoned)", source)
        for forbidden in ("adoptShellPermissionIdentity", "uiAutomation", "getDeclaredField", "openNativeSession("):
            self.assertNotIn(forbidden, source)

    def test_production_dispatch_deadline_and_serial_abandonment_are_bound(self):
        controller = (ANDROID / "os-integration/src/org/wonad/desktop/broker/NativeDesktopController.kt").read_text()
        body = controller.split("private fun <T> synchronous", 1)[1].split("private inner class Session", 1)[0]
        self.assertIn("awaitBrokerResult(dispatch.task, 2000)", body)
        self.assertIn("executor.execute { guarded", body)
        self.assertIn("dispatch.abandon()", body)
        dispatch_source = (ANDROID / "broker-core/src/main/kotlin/org/wonad/desktop/broker/BrokerDispatch.kt").read_text()
        self.assertIn("task.cancel(false)", dispatch_source)
        self.assertIn("onCancelled()", dispatch_source)
        self.assertIn("action().also { outcome = Outcome(it) }", dispatch_source)

    def test_standalone_producer_runs_the_same_fail_closed_semantic_auditor(self):
        source = Path(dispatch.__file__).read_text()
        self.assertIn('semantic_audit=lambda report, directory: audit_gate("broker_dispatch", report, directory)',
                      source)

    def test_manifest_keeps_owner_unprivileged_and_fault_userdebug_only(self):
        ns = "{http://schemas.android.com/apk/res/android}"
        manifest = ET.parse(ANDROID / "session-security/src/main/AndroidManifest.xml").getroot()
        entries = [node for node in manifest.findall("instrumentation") if
                   node.get(ns + "name", "").endswith(".NativeBrokerDispatchInstrumentation")]
        self.assertEqual(1, len(entries)); self.assertEqual("org.wonad.desktop", entries[0].get(ns + "targetPackage"))
        self.assertFalse(manifest.findall("uses-permission"))
        self.assertEqual("true", manifest.find("application").get(ns + "testOnly"))
        fault = ET.parse(ANDROID / "transition-fault/src/main/AndroidManifest.xml").getroot()
        proof = [node for node in fault.findall("instrumentation") if
                 node.get(ns + "name", "").endswith(".NativeCompletionProofInstrumentation")]
        self.assertEqual(1, len(proof)); self.assertEqual("com.android.systemui", proof[0].get(ns + "targetPackage"))
        self.assertFalse(list(fault.find("application")))


if __name__ == "__main__": unittest.main()
