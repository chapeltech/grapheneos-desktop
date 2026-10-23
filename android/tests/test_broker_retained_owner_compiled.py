"""Compile exact OS owner/error/overflow methods against explicit JVM doubles.

These deterministic scheduling controls are not Android/Binder runtime proof.
The production methods are extracted at test time, without rewritten bodies.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_native_ui_surface_migration_compiled import JDK, KOTLINC, method


ANDROID = Path(__file__).resolve().parents[1]
SOURCE = ANDROID / "os-integration/src/org/wonad/desktop/broker/NativeDesktopController.kt"
DISPATCH = ANDROID / "broker-core/src/main/kotlin/org/wonad/desktop/broker/BrokerDispatch.kt"

HARNESS = r'''
package org.wonad.desktop.broker
import java.util.ArrayDeque

object RetainedOwnerScenario {
    private const val POLL_MILLIS = 50L
    private const val TAG = "test"
    private var checks = 0
    private fun expect(value: Boolean, label: String) { check(value) { label }; checks++ }
    private object Log { fun e(tag: String, message: String, error: Throwable) {} }
    private object DesktopProtocol {
        const val REVOKED_CLIENT_FAILED = 5
        const val RESULT_APPLIED = 0
        const val RESULT_BUSY = 5
        const val RESULT_REVOKED = 6
    }
    private class StaleNativeObservation : IllegalStateException()
    private class Owner(val uid: Int)
    private class Pick { var importing: Any? = null }
    private var session: Session? = null
    private var authorizedUid = 101
    private var authCalls = 0
    private var reconciles = 0
    private var changedCalls = 0
    private var polls = 0
    private var reconcileHook: () -> Unit = {}
    private val delayed = mutableListOf<() -> Unit>()
    private object executor {
        fun executeDelayed(action: () -> Unit, delay: Long) { delayed.add(action) }
    }
    private object BrokerNative {
        val calls = mutableListOf<Int>()
        fun nativeSession(op: Int, frame: LongArray): Long {
            calls.add(op)
            return if (op == 4) 0 else 1
        }
    }
    private fun authorized(uid: Int) {
        authCalls++
        if (uid != authorizedUid) throw SecurityException("Original UID no longer admitted")
    }
    private fun identity(uid: Int) = Owner(uid)
    private fun authorityFrame(owner: Owner, generation: Long, request: Long,
        base: Long = 0, revision: Long = 0, topology: Long = 0) = longArrayOf(generation, request)
    private fun reconcile() { reconciles++; reconcileHook() }
    private fun changed() { changedCalls++ }
    private fun poll(live: Session) { polls++ }
    private fun revoke(reason: Int) {
        session?.let { it.markCallbackTerminal(); it.revocations++ }
        session = null
    }

    __GUARDED__

    private class Session(val owner: Owner) {
        __CLOSED__
        val generation = 7L
        val revision = 3L
        val topology = 2L
        var pending: Any? = null
        var pick: Pick? = null
        var waitingForShell = false
        var revocations = 0
        private val overloadOrder = Any()
        private val overloads = ArrayDeque<Pair<Long, Long>>()
        private var overloadDrainQueued = false
        private val callbacks = object {
            val results = mutableListOf<Int>()
            fun markTerminal() {}
            fun result(request: Long, result: Int, revision: Long) { results.add(result) }
        }
        __TERMINAL__
        __OWNER__
        __OVERFLOW__
        fun submitOverflow() { overloads.add(1L to 3L); overloadDrainQueued = true }
        fun drain() = drainQueueOverflow()
        fun resultCount() = callbacks.results.size
    }

    private fun reset(): Session {
        authorizedUid = 101; authCalls = 0; reconciles = 0; changedCalls = 0; polls = 0
        reconcileHook = {}; delayed.clear(); BrokerNative.calls.clear()
        return Session(Owner(101)).also { session = it }
    }

    @JvmStatic fun main(args: Array<String>) {
        run {
            val old = reset(); old.submitOverflow()
            old.markCallbackTerminal()
            val replacement = Session(Owner(202)); session = replacement; authorizedUid = 202
            old.drain()
            expect(authCalls == 0 && reconciles == 0 && BrokerNative.calls.isEmpty(),
                "retired overflow is inert before auth/native/reconcile")
            expect(session === replacement && replacement.revocations == 0 && old.resultCount() == 0,
                "replacement and callback boundary survive old overflow")
        }
        run {
            val live = reset(); live.submitOverflow(); authorizedUid = 202; live.drain()
            expect(live.revocations == 1 && session == null && authCalls == 1,
                "current unauthorized owner still fails closed")
        }
        run {
            val live = reset(); live.submitOverflow(); live.drain()
            expect(authCalls == 1 && reconciles == 1 && BrokerNative.calls == listOf(4, 5),
                "current overload keeps native admission/completion order")
            expect(live.resultCount() == 1 && session === live, "current overload completes exactly once")
        }
        for (error in listOf(SecurityException("old auth"), UnsatisfiedLinkError("old bridge"))) {
            val old = reset(); val replacement = Session(Owner(202))
            guarded(old) { old.markCallbackTerminal(); session = replacement; throw error }
            expect(session === replacement && replacement.revocations == 0 && reconciles == 0,
                "old failure cannot reconcile or revoke replacement")
        }
        run {
            val old = reset(); val replacement = Session(Owner(202))
            reconcileHook = { old.markCallbackTerminal(); session = replacement }
            guarded(old) { throw SecurityException("owner changed during error reconciliation") }
            expect(session === replacement && replacement.revocations == 0 && reconciles == 1,
                "error reconciliation cannot transfer revoke to replacement")
        }
        run {
            val old = reset(); guarded(old) { throw StaleNativeObservation() }
            expect(delayed.size == 1, "stale observation retains one deferred recovery")
            old.markCallbackTerminal(); val replacement = Session(Owner(202)); session = replacement
            delayed.removeAt(0).invoke()
            expect(session === replacement && reconciles == 0 && changedCalls == 0 && polls == 0,
                "old deferred recovery cannot touch replacement")
        }
        run {
            val live = reset(); live.pending = Any()
            guarded(live) { throw StaleNativeObservation() }; delayed.removeAt(0).invoke()
            expect(session === live && reconciles == 1 && changedCalls == 1 && polls == 1,
                "current stale recovery remains functional")
        }
        run {
            val live = reset(); live.markCallbackTerminal()
            var ran = false; guarded(live) { ran = true }
            expect(!ran && !live.currentOwner(), "closed same-pointer guard is inert")
        }
        run {
            val live = reset()
            expect(live.currentOwner(101) && !live.currentOwner(202), "captured UID is exact")
            guarded(live) { throw UnsatisfiedLinkError("current bridge") }
            expect(live.revocations == 1 && session == null, "current bridge failure still revokes")
        }
        run {
            val live = reset(); guarded { throw SecurityException("global OS observer") }
            expect(live.revocations == 1 && reconciles == 1, "unscoped OS fail-closed policy remains")
        }
        for (fatal in listOf(AssertionError("assert"), OutOfMemoryError("VM"))) {
            val live = reset()
            try { guarded(live) { throw fatal }; error("fatal was swallowed") }
            catch (error: Error) { expect(error === fatal && session === live, "fatal error identity retained") }
        }
        println("broker_retained_owner_checks=$checks")
    }
}
'''


class RetainedOwnerCompiled(unittest.TestCase):
    def test_all_session_owned_guards_capture_the_exact_owner(self):
        source = SOURCE.read_text()
        session = source.split("private inner class Session", 1)[1]
        self.assertNotRegex(session, r"guarded\s*\{")
        self.assertIn("onFailure = { error -> executor.execute { guarded(this@Session)", session)
        self.assertIn("try { guarded(this@Session)", session)
        self.assertIn("guarded(this) { selectPicker(this, catalog, if (confirmed)", session)
        self.assertIn("guarded(this) { selectPicker(this, catalog, index)", session)
        polling = method(source, "private fun poll(")
        self.assertNotRegex(polling, r"guarded\s*\{")
        self.assertIn("guarded(live) {", polling)

    def test_actual_owner_error_and_overflow_bodies(self):
        self.assertTrue(KOTLINC.is_file() and (JDK / "bin/java").is_file(), "Pinned Kotlin/JDK required")
        source = SOURCE.read_text()
        owner = [line.strip() for line in source.splitlines() if line.strip().startswith("fun currentOwner(")]
        closed = [line.strip() for line in source.splitlines() if line.strip() == "@Volatile private var closed = false"]
        self.assertEqual((1, 1), (len(owner), len(closed)))
        harness = (HARNESS.replace("__GUARDED__", method(source, "private fun guarded("))
                   .replace("__CLOSED__", closed[0])
                   .replace("__OWNER__", owner[0])
                   .replace("__TERMINAL__", method(source, "fun markCallbackTerminal("))
                   .replace("__OVERFLOW__", method(source, "private fun drainQueueOverflow(")))
        with tempfile.TemporaryDirectory(prefix="wonad-retained-owner-") as name:
            root = Path(name)
            scenario, jar = root / "Scenario.kt", root / "scenario.jar"
            scenario.write_text(harness)
            compiled = subprocess.run([str(KOTLINC), str(DISPATCH), str(scenario), "-include-runtime", "-d", str(jar)],
                                      env={**os.environ, "JAVA_HOME": str(JDK)},
                                      text=True, capture_output=True, timeout=90)
            self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
            output = subprocess.check_output([str(JDK / "bin/java"), "-cp", str(jar),
                                              "org.wonad.desktop.broker.RetainedOwnerScenario"], text=True, timeout=30)
            self.assertIn("broker_retained_owner_checks=17", output)


if __name__ == "__main__":
    unittest.main()
