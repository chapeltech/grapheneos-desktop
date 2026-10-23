"""Compile the actual completion-poll/guard/finish bodies with JVM doubles.

Exercises delayed-owner ordering, not Binder, JNI, WMS or compositor runtime.
The native completion decision is an explicit test double, not a deadline proof.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_native_ui_surface_migration_compiled import JDK, KOTLINC, method

ANDROID = Path(__file__).resolve().parents[1]
CONTROLLER = ANDROID / "os-integration/src/org/wonad/desktop/broker/NativeDesktopController.kt"
CORE = ANDROID / "broker-core/src/main/kotlin/org/wonad/desktop/broker"

HARNESS = r'''
package org.wonad.desktop.broker

object BrokerNative {
    var completionResult = 0
    fun completion(finished: Boolean, aborted: Boolean, now: Long, deadline: Long, matches: Boolean) =
        if (completionResult == 1 && !matches) 0 else completionResult
    fun nativeFrameMatches(observed: LongArray, desired: LongArray) = true
    fun nativeSession(operation: Int, frame: LongArray) = 1L
}

object PollOwnerScenario {
    private const val TAG = "test"
    private const val POLL_MILLIS = 50L
    private var checks = 0
    private fun expect(value: Boolean, label: String) { check(value) { label }; checks++ }
    private object Log { fun e(tag: String, message: String, error: Throwable) {} }
    private object SystemClock { fun elapsedRealtime() = 1L }
    private object DesktopProtocol {
        const val RESULT_STALE = 1
        const val RESULT_APPLIED = 0
        const val RESULT_PLATFORM_CONSTRAINT = 3
        const val REVOKED_CLIENT_FAILED = 5
    }
    private class StaleNativeObservation : IllegalStateException()
    private data class Owner(val uid: Int = 101, val user: Int = 0)
    private data class Task(val token: Long, val displayToken: Long = 1)
    private data class Snapshot(val topologyRevision: Long = 1, val focusedToken: Long = 0,
        val tasks: List<Task> = emptyList())
    private class Token { fun asBinder(): Any = this }
    private class Running { val launchCookies = emptyList<Any>(); val token = Token() }
    private class Phone { fun matches(value: Running) = true }
    private data class Observation(val snapshot: Snapshot = Snapshot(), val running: Map<Long, Running> = emptyMap())
    private data class Pending(val request: Long = 1, val topology: Long = 1, val deadline: Long = 100,
        val closeToken: Long = 0, val focusToken: Long = 1, val desired: LongArray? = null,
        val taskBinders: Array<Any> = emptyArray(), val taskUids: IntArray = intArrayOf(),
        val capturedCurrent: LongArray = longArrayOf())
    private class Pick {
        var importing: Any? = null
        val cookie = false
        val phone: Phone? = null
        val displayToken = 1L
        val importDeadline = 100L
    }
    private data class Monitor(val shellGeneration: Long)
    private val monitors = mutableListOf<Monitor>()
    private var session: Session? = null
    private var reconciles = 0
    private var refreshes = 0
    private var authorizations = 0
    private var changes = 0
    private var revocations = 0
    private var observedFocusToken = 0L
    private var refreshFailure: Throwable? = null
    private var refreshHook: () -> Unit = {}
    private var reconcileHook: () -> Unit = {}
    private class Session(val owner: Owner = Owner()) {
        __CLOSED__
        val generation = 7L
        val revision = 3L
        val topology = 1L
        var pollQueued = false
        var pending: Pending? = null
        var pick: Pick? = null
        var waitingForShell = false
        var uiEnabled = false
        var results = 0
        private val callbacks = object { fun markTerminal() {} }
        __TERMINAL__
        __OWNER__
        fun asBinder(): Any = this
        fun callbackResult(request: Long, result: Int, revision: Long) { results++ }
    }
    private object executor {
        val queued = mutableListOf<() -> Unit>()
        fun executeDelayed(action: () -> Unit, delay: Long) { queued.add(action) }
        fun next() { queued.removeAt(0).invoke() }
    }
    private object wm {
        fun isWonadNativeFrameApplied(vararg value: Any?) = true
    }
    private fun wm() = wm
    private fun observedWire(value: Snapshot) = longArrayOf()
    private fun identity(uid: Int) = Owner(uid)
    private fun authorityFrame(owner: Owner, generation: Long, request: Long, topology: Long) = longArrayOf()
    private fun authorized(uid: Int) { authorizations++ }
    private fun reconcile() { reconciles++; reconcileHook() }
    private fun changed() { changes++ }
    private fun refresh(live: Session, force: Boolean = false): Observation {
        refreshes++; refreshHook(); refreshFailure?.let { throw it }
        return Observation(Snapshot(focusedToken = observedFocusToken))
    }
    private fun endPicker(live: Session) { live.pick = null }
    private fun revoke(reason: Int) { session?.markCallbackTerminal(); session = null; revocations++ }

    __GUARDED__
    __POLL__
    __FINISH__

    private fun reset(): Session {
        reconciles = 0; refreshes = 0; authorizations = 0; changes = 0; revocations = 0
        refreshFailure = null; refreshHook = {}; reconcileHook = {}; observedFocusToken = 0
        executor.queued.clear(); monitors.clear(); BrokerNative.completionResult = NativeFrameCompletion.WAITING
        return Session().also { session = it }
    }

    @JvmStatic fun main(args: Array<String>) {
        run {
            val old = reset(); poll(old)
            expect(old.pollQueued && executor.queued.size == 1, "actual poll schedules exactly once")
            old.markCallbackTerminal(); val fresh = Session(Owner(202)); session = fresh
            executor.next()
            expect(!old.pollQueued && session === fresh && fresh.results == 0, "old bookkeeping cannot transfer ownership")
            expect(reconciles == 0 && refreshes == 0 && authorizations == 0 && revocations == 0,
                "retired delayed poll is inert before OS observation")
        }
        run {
            val old = reset(); poll(old); refreshFailure = StaleNativeObservation(); executor.next()
            expect(executor.queued.size == 1 && revocations == 0, "actual stale poll coalesces recovery without revoke")
            old.markCallbackTerminal(); val fresh = Session(Owner(202)); session = fresh
            val prior = reconciles; executor.next()
            expect(session === fresh && reconciles == prior && refreshes == 1 && changes == 0,
                "stale poll recovery stays scoped to its original owner")
        }
        for (failure in listOf(IllegalStateException("old capture"), UnsatisfiedLinkError("old optional bridge"))) {
            val old = reset(); poll(old); val fresh = Session(Owner(202))
            refreshHook = { old.markCallbackTerminal(); session = fresh }; refreshFailure = failure
            executor.next()
            expect(session === fresh && revocations == 0 && fresh.results == 0,
                "old capture error cannot revoke replacement")
        }
        run {
            val old = reset(); poll(old); val fresh = Session(Owner(202))
            reconcileHook = { old.markCallbackTerminal(); session = fresh }
            executor.next()
            expect(session === fresh && refreshes == 0 && revocations == 0,
                "post-reconcile exact-owner fence precedes capture")
        }
        for (failure in listOf(IllegalStateException("current capture"), UnsatisfiedLinkError("current optional bridge"))) {
            val live = reset(); poll(live); refreshFailure = failure; executor.next()
            expect(session == null && revocations == 1 && live.results == 0,
                "current owner capture failure still fails closed")
        }
        run {
            val live = reset(); live.pending = Pending(); poll(live); executor.next()
            expect(session === live && live.pending != null && live.pollQueued && executor.queued.size == 1,
                "current pending poll still reschedules")
        }
        run {
            val live = reset(); live.pending = Pending(); BrokerNative.completionResult = NativeFrameCompletion.APPLIED
            observedFocusToken = 1
            poll(live); executor.next()
            expect(session === live && live.pending == null && live.results == 1 && authorizations == 1,
                "actual current completion reaches native finish and authorized callback")
        }
        run {
            val live = reset(); live.pending = Pending(); BrokerNative.completionResult = NativeFrameCompletion.TIMED_OUT
            poll(live); executor.next()
            expect(session == null && revocations == 1 && live.pending == null && live.results == 1,
                "native timeout result still acknowledges constraint then revokes")
        }
        println("broker_retained_poll_checks=$checks")
    }
}
'''


class RetainedPollCompiled(unittest.TestCase):
    def test_actual_delayed_poll_guard_and_finish_source(self):
        self.assertTrue(KOTLINC.is_file() and (JDK / "bin/java").is_file(), "Pinned Kotlin/JDK required")
        source = CONTROLLER.read_text()
        owner = [line.strip() for line in source.splitlines() if line.strip().startswith("fun currentOwner(")]
        closed = [line.strip() for line in source.splitlines() if line.strip() == "@Volatile private var closed = false"]
        self.assertEqual((1, 1), (len(owner), len(closed)))
        harness = HARNESS.replace("__CLOSED__", closed[0]).replace("__OWNER__", owner[0])
        for token, prefix in (("__TERMINAL__", "fun markCallbackTerminal("),
                              ("__GUARDED__", "private fun guarded("),
                              ("__POLL__", "private fun poll("),
                              ("__FINISH__", "private fun finish(")):
            harness = harness.replace(token, method(source, prefix))
        with tempfile.TemporaryDirectory(prefix="wonad-retained-poll-") as name:
            root = Path(name); scenario, jar = root / "Scenario.kt", root / "scenario.jar"
            scenario.write_text(harness)
            command = [str(KOTLINC), "-J-Xmx512m", "-J-XX:ActiveProcessorCount=2",
                       str(CORE / "BrokerDispatch.kt"), str(CORE / "NativeFrameCompletion.kt"),
                       str(scenario), "-include-runtime", "-d", str(jar)]
            compiled = subprocess.run(command, env={**os.environ, "JAVA_HOME": str(JDK)},
                                      text=True, capture_output=True, timeout=90)
            self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
            output = subprocess.check_output([str(JDK / "bin/java"), "-cp", str(jar),
                "org.wonad.desktop.broker.PollOwnerScenario"], text=True, timeout=30)
            self.assertIn("broker_retained_poll_checks=13", output)


if __name__ == "__main__": unittest.main()
