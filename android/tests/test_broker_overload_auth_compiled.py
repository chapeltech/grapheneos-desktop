"""Compile the real session overload/authentication methods against JVM doubles.

This is focused ordering/queue evidence. It does not replace real Binder,
PackageManager, WM, SurfaceFlinger, emulator, or physical-device qualification.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_native_ui_surface_migration_compiled import JDK, KOTLINC, method


ANDROID = Path(__file__).resolve().parents[1]
BROKER = ANDROID / "os-integration/src/org/wonad/desktop/broker"
CONTROLLER = BROKER / "NativeDesktopController.kt"


HARNESS = r'''
package org.wonad.desktop.broker

var checks = 0
fun expect(value: Boolean, label: String) { check(value) { label }; checks++ }

object Binder {
    @Volatile var uid = 101
    fun getCallingUid() = uid
}
object DesktopProtocol {
    const val RESULT_STALE = 1
    const val RESULT_BUSY = 5
}
data class Identity(val uid: Int)
class StaleNativeObservation : IllegalStateException()
data class Result(val generation: Long, val request: Long, val result: Int, val revision: Long)

class Callbacks(private val events: MutableList<String>) {
    val results = mutableListOf<Result>()
    fun result(request: Long, result: Int, revision: Long) {
        val generation = 7L
        events += "result:$generation:$request:$result:$revision"
        results += Result(generation, request, result, revision)
    }
    fun markTerminal() { events += "terminal" }
}
class Slots(private val events: MutableList<String>) {
    var available = false
    var releases = 0
    fun tryAcquire(): Boolean { events += "slot"; return available }
    fun release() { releases++; events += "release" }
}
class Executor(private val events: MutableList<String>) {
    var deferred = false
    val work = mutableListOf<() -> Unit>()
    fun execute(action: () -> Unit) {
        events += "execute"
        if (deferred) work += action else action()
    }
    fun drain() { work.toList().also { work.clear() }.forEach { it() } }
}

class Controller {
    val events = mutableListOf<String>()
    val queueSlots = Slots(events)
    val executor = Executor(events)
    var authenticatedUid = 101
    var stale = false
    var replaceDuringReconcile = false
    var session: Session? = null

    fun authorized(uid: Int) {
        events += "auth:$uid"
        if (uid != authenticatedUid) throw SecurityException("auth:$uid")
    }
    fun reconcile() {
        events += "reconcile"
        if (replaceDuringReconcile) session = Session(Identity(101), 8)
        if (stale) throw StaleNativeObservation()
    }
    fun guarded(expected: Session? = null, action: () -> Unit) {
        if (expected != null && !expected.currentOwner()) return
        try { action() } catch (_: StaleNativeObservation) { events += "guarded-stale" }
    }

    inner class Session(val owner: Identity, val generation: Long) {
        @Volatile private var closed = false
        @Volatile var revision = 12L
        private val requestOrder = Any()
        private var lastRequest = 0L
        val callbacks = Callbacks(events)

        __CURRENT_OWNER__
        __MARK_TERMINAL__

        __REGISTER_REQUEST__
        fun completeQueueOverflow(request: Long, base: Long) {
            events += "overflow:$request:$base"
        }
        __ENQUEUE__

        fun submit(gen: Long, request: Long, base: Long = 3) = enqueue(gen, request, base) { events += "action" }
    }
}

fun live(): Pair<Controller, Controller.Session> {
    val controller = Controller()
    val session = controller.Session(Identity(101), 7)
    controller.session = session
    return controller to session
}

fun main() {
    run {
        val (controller, session) = live()
        Binder.uid = 202
        try { session.submit(7, 1); error("Expected authentication denial") }
        catch (error: SecurityException) { expect(error.message == "auth:202", "authentication denial wins") }
        expect(controller.events == listOf("auth:202"), "no ownership, queue or argument state before auth")
    }
    run {
        val (controller, session) = live()
        Binder.uid = 202; controller.authenticatedUid = 202
        try { session.submit(7, 2); error("Expected owner denial") }
        catch (error: SecurityException) {
            expect(error.message == "Session belongs to another caller", "owner denial retained after auth")
        }
        expect(controller.events == listOf("auth:202"), "owner denial precedes queue observation")
    }
    run {
        val (controller, session) = live(); Binder.uid = 101
        session.submit(7, 55)
        expect(session.callbacks.results.isEmpty(), "overload does not bypass native admission")
        expect(controller.events == listOf("auth:101", "slot", "overflow:55:3"),
            "authenticated overload is deferred with its base revision")
    }
    run {
        val (controller, session) = live(); Binder.uid = 101
        session.submit(6, 56)
        expect(session.callbacks.results.single() == Result(7, 56, 1, 12), "wrong generation is STALE")
        expect(controller.events == listOf("auth:101", "result:7:56:1:12"),
            "wrong generation precedes queue observation")
        session.submit(6, 56); session.submit(7, 56); session.submit(7, 0)
        expect(session.callbacks.results.size == 1 && controller.events.takeLast(3) ==
            listOf("auth:101", "auth:101", "auth:101"),
            "replayed, cross-generation and nonpositive IDs are inert")
    }
    run {
        val (controller, session) = live(); Binder.uid = 101
        controller.session = controller.Session(Identity(101), 8)
        session.submit(7, 57)
        expect(session.callbacks.results.isEmpty(), "retained session binder is inert")
        expect(controller.events == listOf("auth:101"), "retained binder stops before request or queue state")
    }
    run {
        val (controller, session) = live(); Binder.uid = 101; controller.queueSlots.available = true
        session.submit(7, 58)
        expect(controller.events == listOf("auth:101", "slot", "execute", "auth:101", "reconcile",
            "action", "release"), "accepted work reauthenticates before session state")
        expect(controller.queueSlots.releases == 1, "accepted slot released once")
    }
    run {
        val (controller, session) = live(); Binder.uid = 101
        controller.queueSlots.available = true; controller.stale = true
        session.submit(7, 59)
        expect(controller.events == listOf("auth:101", "slot", "execute", "auth:101", "reconcile",
            "auth:101", "result:7:59:1:12", "guarded-stale", "release"),
            "stale observation reauthenticates before completion")
        expect(session.callbacks.results.single().result == DesktopProtocol.RESULT_STALE,
            "stale observation completes request")
        expect(controller.queueSlots.releases == 1, "stale slot released once")
    }
    run {
        val (controller, session) = live(); Binder.uid = 101
        controller.queueSlots.available = true; controller.executor.deferred = true
        session.submit(7, 60)
        controller.session = controller.Session(Identity(101), 8)
        controller.executor.drain()
        expect("reconcile" !in controller.events && "action" !in controller.events,
            "replacement is rejected before reconcile on worker")
        expect(controller.queueSlots.releases == 1, "replaced work releases its slot")
    }
    run {
        val (controller, session) = live(); Binder.uid = 101
        controller.queueSlots.available = true; controller.replaceDuringReconcile = true
        session.submit(7, 61)
        expect(controller.events == listOf("auth:101", "slot", "execute", "auth:101", "reconcile", "release"),
            "post-reconcile replacement is rechecked before action")
    }
    run {
        val (controller, session) = live(); Binder.uid = 101
        controller.queueSlots.available = true; controller.executor.deferred = true
        session.submit(7, 62)
        session.markCallbackTerminal()
        val replacement = controller.Session(Identity(202), 8)
        controller.session = replacement; controller.authenticatedUid = 202
        controller.events.clear(); controller.executor.drain()
        expect(controller.events == listOf("release"),
            "retired worker cannot authorize old UID or observe replacement")
        expect(controller.session === replacement && controller.queueSlots.releases == 1,
            "replacement survives and old permit releases exactly once")
    }
    run {
        val (controller, session) = live(); Binder.uid = 101
        controller.queueSlots.available = true; controller.executor.deferred = true
        session.submit(7, 63); session.markCallbackTerminal()
        controller.events.clear(); controller.executor.drain()
        expect(controller.events == listOf("release"), "closed same-pointer work is inert")
    }
    run {
        val (controller, session) = live(); Binder.uid = 101
        controller.queueSlots.available = true; controller.executor.deferred = true
        session.submit(7, 64); Binder.uid = 202
        controller.events.clear(); controller.executor.drain()
        expect(controller.events == listOf("auth:101", "reconcile", "action", "release"),
            "worker uses the original authenticated Binder UID, not executor identity")
    }
    println("broker_overload_auth_checks=$checks")
}
'''


class BrokerOverloadAuthorization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not KOTLINC.is_file() or not (JDK / "bin/java").is_file():
            raise AssertionError("Pinned Kotlin/JDK toolchain is required")

    def test_actual_queue_methods_authenticate_complete_and_order_terminal_callback(self):
        source = CONTROLLER.read_text()
        harness = HARNESS.replace("__REGISTER_REQUEST__", method(source, "private fun registerRequest("))
        harness = harness.replace("__ENQUEUE__", method(source, "private fun enqueue("))
        owners = [line.strip() for line in source.splitlines() if line.strip().startswith("fun currentOwner(")]
        self.assertEqual(1, len(owners))
        harness = harness.replace("__CURRENT_OWNER__", owners[0])
        harness = harness.replace("__MARK_TERMINAL__", method(source, "fun markCallbackTerminal("))
        env = {**os.environ, "JAVA_HOME": str(JDK)}
        with tempfile.TemporaryDirectory(prefix="wonad-broker-overload-") as temporary:
            scenario = Path(temporary) / "Scenario.kt"
            scenario.write_text(harness)
            jar = Path(temporary) / "scenario.jar"
            compiled = subprocess.run(
                [str(KOTLINC), str(scenario), "-include-runtime", "-d", str(jar)],
                env=env, text=True, capture_output=True, timeout=90)
            self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
            output = subprocess.check_output([str(JDK / "bin/java"), "-jar", str(jar)],
                                             text=True, timeout=30)
            self.assertIn("broker_overload_auth_checks=23", output)

    def test_binder_source_authentication_and_terminal_order_are_explicit(self):
        native = CONTROLLER.read_text()
        controller = (BROKER / "WonadController.kt").read_text()

        opening = controller.split("override fun openSession(", 1)[1].split("    }\n", 1)[0]
        self.assertLess(opening.index("checkAuthorized(uid)"), opening.index("desktop.open(uid"))

        enqueue = method(native, "private fun enqueue(")
        self.assertLess(enqueue.index("authorized(uid)"), enqueue.index("uid != owner.uid"))
        self.assertLess(enqueue.index("uid != owner.uid"), enqueue.index("queueSlots.tryAcquire()"))
        self.assertLess(enqueue.index("session !== this"), enqueue.index("queueSlots.tryAcquire()"))
        self.assertLess(enqueue.index("registerRequest(gen, request)"), enqueue.index("queueSlots.tryAcquire()"))
        self.assertIn("if (request != null) completeQueueOverflow(request, base)", enqueue)
        worker = enqueue.split("executor.execute", 1)[1]
        self.assertLess(worker.index("authorized(uid)"), worker.index("reconcile()"))
        checks = [index for index in range(len(worker)) if worker.startswith("session !== this", index)]
        self.assertGreaterEqual(len(checks), 2)
        self.assertLess(checks[0], worker.index("reconcile()"))
        self.assertLess(worker.index("reconcile()"), checks[1])

        overflow = method(native, "private fun completeQueueOverflow(")
        self.assertNotIn("callbacks.result", overflow)
        self.assertIn("if (overloadFailed) return", overflow)
        self.assertLess(overflow.index("overloadFailed = true"), overflow.index("executor.execute"))
        drain = method(native, "private fun drainQueueOverflow(")
        self.assertLess(drain.index("nativeSession(4"), drain.index("nativeSession(5"))
        self.assertLess(drain.index("nativeSession(5"), drain.index("callbacks.result"))

        launcher = native.split("override fun launcherPage(", 1)[1].split(
            "override fun showLauncher(", 1)[0]
        direct, dispatched = launcher.split("return synchronous", 1)
        self.assertLess(direct.index("authorized(uid)"), direct.index("uid != owner.uid"))
        self.assertLess(direct.index("uid != owner.uid"), direct.index("session !== this"))
        self.assertLess(dispatched.index("authorized(uid)"), dispatched.index("reconcile()"))
        dispatched_checks = [index for index in range(len(dispatched)) if dispatched.startswith("session !== this", index)]
        self.assertGreaterEqual(len(dispatched_checks), 2)
        self.assertLess(dispatched_checks[0], dispatched.index("reconcile()"))
        self.assertLess(dispatched.index("reconcile()"), dispatched_checks[1])

        revoke = method(native, "fun revoke(")
        self.assertLess(revoke.index("live.markCallbackTerminal()"), revoke.index("session = null"))
        self.assertLess(revoke.index("live.markCallbackTerminal()"), revoke.index("live.callbackRevoked"))
        session_fields = native.split("private inner class Session", 1)[1].split("val death", 1)[0]
        self.assertIn("@Volatile var revision", session_fields)
        self.assertIn("SerialCallbackDispatcher", session_fields)
        self.assertNotIn("callbackOrder", native)

        picker = method(native, "private fun selectPicker(")
        picker_checks = [index for index in range(len(picker)) if picker.startswith("session !== live", index)]
        self.assertGreaterEqual(len(picker_checks), 2)
        self.assertLess(picker_checks[0], picker.index("reconcile()"))
        self.assertLess(picker.index("reconcile()"), picker_checks[1])
        shortcut = native.split("override fun notifyShortcutKeyPressed(", 1)[1].split(
            "fun renewShortcuts", 1)[0]
        shortcut_checks = [index for index in range(len(shortcut))
                           if shortcut.startswith("session !== this@Session", index)]
        self.assertGreaterEqual(len(shortcut_checks), 2)
        self.assertLess(shortcut_checks[0], shortcut.index("reconcile()"))
        self.assertLess(shortcut.index("reconcile()"), shortcut_checks[1])
        poll = method(native, "private fun poll(")
        poll_checks = [index for index in range(len(poll)) if poll.startswith("session !== live", index)]
        self.assertGreaterEqual(len(poll_checks), 3)
        self.assertLess(poll_checks[1], poll.index("reconcile()"))
        self.assertLess(poll.index("reconcile()"), poll_checks[2])


if __name__ == "__main__":
    unittest.main()
