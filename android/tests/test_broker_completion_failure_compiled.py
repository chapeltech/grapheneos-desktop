"""Execute the real API3 completion and guarded-failure methods.

The doubles provide only the Android/JNI objects surrounding those extracted
methods.  This proves serial model ordering and fail-closed dispatch; it is not
Binder, WindowManager, SurfaceFlinger, emulator, or physical-device evidence.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_native_ui_surface_migration_compiled import JDK, KOTLINC, method


ANDROID = Path(__file__).resolve().parents[1]
BROKER = ANDROID / "os-integration/src/org/wonad/desktop/broker"
DISPATCH = ANDROID / "broker-core/src/main/kotlin/org/wonad/desktop/broker/BrokerDispatch.kt"


NATIVE_HARNESS = r'''
package org.wonad.desktop.broker

var checks = 0
fun expect(value: Boolean, label: String) { check(value) { label }; checks++ }

object Log {
    val failures = mutableListOf<Throwable>()
    fun e(tag: String, text: String, error: Throwable) { failures.add(error) }
}
object DesktopProtocol {
    const val REVOKED_CLIENT_FAILED = 8
}
data class Identity(val uid: Int)
data class Pending(val request: Long, val topology: Long)
class Pick { var importing: Any? = null }
class Callback {
    var calls = 0
    var failure: Throwable? = null
    fun onResult(generation: Long, request: Long, result: Int, revision: Long) {
        events += "callback:$generation:$request:$result:$revision"
        calls++
        failure?.let { throw it }
    }
}
class Callbacks(private val callback: Callback, private val generation: Long) {
    fun result(request: Long, result: Int, revision: Long) =
        callback.onResult(generation, request, result, revision)
}
class Session(val owner: Identity, val generation: Long, var topology: Long) {
    var pending: Pending? = null
    val callback = Callback()
    val callbacks = Callbacks(callback, generation)
    fun callbackResult(request: Long, result: Int, revision: Long) =
        callbacks.result(request, result, revision)
    var revision = 4L
    var pick: Pick? = null
    var waitingForShell = false
    // This harness exercises unscoped completion errors only. Exact scoped
    // ownership is compiled separately in test_broker_retained_owner_compiled.
    fun currentOwner(): Boolean = error("Unexpected scoped guard in completion harness")
}
class StaleNativeObservation : IllegalStateException()
class Executor {
    fun executeDelayed(action: () -> Unit, delay: Long) { events += "delayed:$delay"; action() }
}
var events = mutableListOf<String>()
object BrokerNative {
    var answer = 1L
    var failure: Throwable? = null
    var frame = longArrayOf()
    fun nativeSession(operation: Int, value: LongArray): Long {
        events += "native:$operation"
        frame = value
        failure?.let { throw it }
        return answer
    }
}

class Controller {
    companion object { const val TAG = "test"; const val POLL_MILLIS = 50L }
    val executor = Executor()
    var session: Session? = null
    var authorizedFailure: Throwable? = null
    var reconcileFailure: Throwable? = null
    var revocations = 0

    fun identity(uid: Int) = Identity(uid)
    fun authorityFrame(identity: Identity, generation: Long, request: Long,
        topology: Long): LongArray = longArrayOf(identity.uid.toLong(), generation, request, topology)
    fun authorized(uid: Int) {
        events += "authorized:$uid"
        authorizedFailure?.let { throw it }
    }
    fun reconcile() {
        events += "reconcile"
        reconcileFailure?.let { throw it }
    }
    fun revoke(reason: Int) {
        events += "revoke:$reason"
        revocations++
        session?.pending = null
        session = null
    }
    fun changed() { events += "changed" }
    fun refresh(live: Session) { events += "refresh:${live.generation}" }
    fun poll(live: Session) { events += "poll:${live.generation}" }

    __GUARDED__
    __FINISH__

    fun complete(live: Session, request: Long, result: Int) = guarded { finish(live, request, result) }
}

fun reset() {
    events.clear(); Log.failures.clear(); BrokerNative.answer = 1L
    BrokerNative.failure = null; BrokerNative.frame = longArrayOf()
}
fun live(): Pair<Controller, Session> {
    val controller = Controller()
    val value = Session(Identity(10181), 17, 31).also { it.pending = Pending(77, 29) }
    controller.session = value
    return controller to value
}
fun main() {
    run {
        reset(); val (controller, value) = live()
        controller.complete(value, 77, 1)
        expect(events == listOf("native:5", "authorized:10181", "callback:17:77:1:4"),
            "native success acknowledges only after exact Rust completion and authorization")
        expect(value.pending == null && controller.session === value && value.callback.calls == 1,
            "native success retires the request without revoking its owner")
        expect(BrokerNative.frame.contentEquals(longArrayOf(10181, 17, 77, 29)),
            "native completion uses the pending request topology")
    }
    run {
        reset(); val (controller, value) = live(); BrokerNative.answer = 0
        controller.complete(value, 77, 2)
        expect(events == listOf("native:5", "revoke:8"),
            "native refusal revokes before authorization or callback")
        expect(controller.session == null && value.pending == null && value.callback.calls == 0,
            "native refusal cannot leave pending authority")
    }
    for (linkage in listOf(false, true)) run {
        reset(); val (controller, value) = live()
        val failure: Throwable = if (linkage) UnsatisfiedLinkError("JNI missing")
            else IllegalStateException("JNI failed")
        BrokerNative.failure = failure
        controller.complete(value, 77, 3)
        expect(events == if (linkage) listOf("native:5", "revoke:8")
            else listOf("native:5", "reconcile", "revoke:8"),
            "native completion failure follows the exact guarded failure class")
        expect(Log.failures.single() === failure && controller.session == null && value.callback.calls == 0,
            "native completion failure remains observable and cannot acknowledge")
    }
    run {
        reset(); val (controller, value) = live()
        val denied = SecurityException("signer changed")
        controller.authorizedFailure = denied
        controller.complete(value, 77, 4)
        expect(events == listOf("native:5", "authorized:10181", "reconcile", "revoke:8"),
            "authorization loss after Rust completion revokes before callback")
        expect(Log.failures.single() === denied && value.callback.calls == 0 && controller.session == null,
            "authorization loss is not reported as completion")
    }
    run {
        reset(); val (controller, value) = live()
        val callback = IllegalStateException("dead callback")
        value.callback.failure = callback
        controller.complete(value, 77, 5)
        expect(events == listOf("native:5", "authorized:10181", "callback:17:77:5:4", "reconcile", "revoke:8"),
            "callback failure occurs only after completion and then revokes")
        expect(Log.failures.single() === callback && value.callback.calls == 1 && controller.session == null,
            "failed callback cannot retain a live owner")
    }
    run {
        reset(); val (controller, value) = live()
        val primary = IllegalStateException("JNI failed")
        val secondary = IllegalStateException("reconcile failed")
        BrokerNative.failure = primary; controller.reconcileFailure = secondary
        controller.complete(value, 77, 6)
        expect(primary.suppressed.single() === secondary,
            "secondary reconciliation failure is retained on the original completion failure")
        expect(events == listOf("native:5", "reconcile", "revoke:8") && controller.session == null,
            "reconciliation failure still reaches revocation")
    }
    run {
        reset(); val (controller, stale) = live(); val replacement = Session(Identity(10181), 18, 32)
        controller.session = replacement
        controller.complete(stale, 77, 7)
        expect(events.isEmpty() && stale.pending != null && controller.session === replacement,
            "stale completion cannot mutate or revoke a replacement session")
    }
    println("native_completion_failure_checks=$checks")
}
'''


class BrokerCompletionFailure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not KOTLINC.is_file() or not (JDK / "bin/java").is_file():
            raise AssertionError("Pinned Kotlin/JDK toolchain is required")

    def compile_and_run(self, name, harness):
        env = {**os.environ, "JAVA_HOME": str(JDK)}
        with tempfile.TemporaryDirectory(prefix=f"wonad-{name}-completion-") as temporary:
            root = Path(temporary)
            scenario = root / "Scenario.kt"
            scenario.write_text(harness)
            jar = root / "scenario.jar"
            result = subprocess.run(
                [str(KOTLINC), str(DISPATCH), str(scenario), "-include-runtime", "-d", str(jar)],
                env=env, text=True, capture_output=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return subprocess.check_output([str(JDK / "bin/java"), "-jar", str(jar)], text=True, timeout=30)

    def test_actual_native_completion_failure_ordering(self):
        source = (BROKER / "NativeDesktopController.kt").read_text()
        guarded = method(source, "private fun guarded(")
        finish = method(source, "private fun finish(")
        harness = NATIVE_HARNESS.replace("__GUARDED__", guarded).replace("__FINISH__", finish)
        output = self.compile_and_run("native", harness)
        self.assertIn("native_completion_failure_checks=16", output)

if __name__ == "__main__":
    unittest.main()
