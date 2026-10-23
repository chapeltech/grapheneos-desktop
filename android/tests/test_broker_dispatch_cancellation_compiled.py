"""Execute real Kotlin dispatch code across a serial executor and Binder-like waiter.

This covers cancellation races, not live WM/SurfaceFlinger qualification.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_native_ui_surface_migration_compiled import JDK, KOTLINC

ANDROID = Path(__file__).resolve().parents[1]
SOURCE = ANDROID / 'broker-core/src/main/kotlin/org/wonad/desktop/broker/BrokerDispatch.kt'

HARNESS = r'''
package org.wonad.desktop.broker
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger

var checks = 0
fun expect(value: Boolean, label: String) { check(value) { label }; checks++ }
fun main() {
    var ran = false
    var disposed = 0
    var cancelled = 0
    val queued = BrokerDispatch<Int>(onAbandoned = { disposed++ }) { ran = true; 42 }
    try { awaitBrokerResult(queued.task, 1) { cancelled++ }; error("Expected timeout") }
    catch (e: IllegalStateException) { expect(e.message == "Broker did not respond", "bounded timeout") }
    queued.task.run(); queued.abandon()
    expect(!ran && disposed == 0 && cancelled == 1, "undispatched cancellation has no authority")

    val success = BrokerDispatch<Int>(onAbandoned = { error("Not abandoned") }) { 42 }
    success.task.run()
    expect(awaitBrokerResult(success.task, 100) { error("Not cancelled") } == 42, "success unchanged")
    val denied = SecurityException("Exact original denial")
    val failed = BrokerDispatch<Int> { throw denied }.also { it.task.run() }
    try { awaitBrokerResult(failed.task, 100) { error("No cleanup for completed denial") }; error("Expected denial") }
    catch (e: SecurityException) { expect(e === denied, "authorization exception identity preserved") }

    for (fatal in listOf(AssertionError("assertion"), OutOfMemoryError("virtual machine"))) {
        val failedFatal = BrokerDispatch<Int> { throw fatal }.also { it.task.run() }
        try { awaitBrokerResult(failedFatal.task, 100) { error("No cleanup for completed fatal") }; error("Expected fatal") }
        catch (error: Error) { expect(error === fatal, "fatal executor error identity preserved") }
    }
    val linkage = UnsatisfiedLinkError("optional bridge unavailable")
    val failedLinkage = BrokerDispatch<Int> { throw linkage }.also { it.task.run() }
    try { awaitBrokerResult(failedLinkage.task, 100) { error("No cleanup for completed linkage") }; error("Expected bridge failure") }
    catch (error: IllegalStateException) {
        expect(error.cause === linkage, "linkage failure remains a supported bridge failure")
    }

    for (supported in listOf(Exception("ordinary"), UnsatisfiedLinkError("linkage"))) {
        expect(attemptBrokerOperation { throw supported } === supported,
            "optional operation reports supported failure")
        expect(brokerValueOrNull<Int> { throw supported } == null,
            "optional value maps supported failure to null")
    }
    for (fatal in listOf(AssertionError("assertion"), OutOfMemoryError("virtual machine"))) {
        try { attemptBrokerOperation { throw fatal }; error("Expected fatal operation") }
        catch (error: Error) { expect(error === fatal, "optional operation rethrows fatal identity") }
        try { brokerValueOrNull<Int> { throw fatal }; error("Expected fatal value") }
        catch (error: Error) { expect(error === fatal, "optional value rethrows fatal identity") }
    }

    // Deterministically model get timing out just before cancel(false): the
    // FutureTask has completed, so cancellation fails despite an unreceived
    // session. Cleanup still runs and must not revoke a replacement session.
    for (replace in listOf(false, true)) {
        val old = Any(); val replacement = Any()
        var live: Any? = null
        var cleanup = 0
        val dispatch = BrokerDispatch<Any>(onAbandoned = { opened ->
            if (live === opened) { live = null; cleanup++ }
        }) { live = old; old }
        val completedBeforeCancel = object : FutureTask<Any>({
            dispatch.task.run(); old
        }) {
            override fun get(timeout: Long, unit: TimeUnit): Any {
                run()
                throw TimeoutException("completed in timeout/cancellation gap")
            }
        }
        try {
            awaitBrokerResult(completedBeforeCancel, 1) {
                if (replace) live = replacement
                dispatch.abandon(); dispatch.abandon()
            }
            error("Expected timeout even though task completed")
        } catch (e: IllegalStateException) {
            expect(e.cause is TimeoutException, "timeout gap is not reported as success")
        }
        expect(!completedBeforeCancel.isCancelled, "cancel(false) lost to completed result")
        expect(cleanup == if (replace) 0 else 1, "completed orphan cleanup is exact-owner and one-shot")
        expect(if (replace) live === replacement else live == null, "replacement survives completed-result cleanup")
    }

    var interruptedCleanup = 0
    val interrupted = object : FutureTask<Int>({ 42 }) {
        override fun get(timeout: Long, unit: TimeUnit): Int {
            throw InterruptedException("Binder waiter interrupted")
        }
    }
    try { awaitBrokerResult(interrupted, 1) { interruptedCleanup++ }; error("Expected interruption") }
    catch (e: IllegalStateException) { expect(e.cause is InterruptedException, "interrupted wait retains cause") }
    expect(Thread.interrupted(), "interrupted waiter flag restored")
    expect(interruptedCleanup == 1 && interrupted.isCancelled, "interrupted waiter cancels and queues cleanup")

    // Block the actual operation AFTER it starts, then let cancellation win.
    // Cleanup is queued on the same executor and sees the discarded result.
    for (replace in listOf(false, true)) repeat(32) {
        val executor = Executors.newSingleThreadExecutor()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val old = Any(); val replacement = Any()
        var live: Any? = null
        val cleanup = AtomicInteger()
        var cleanupThread = ""
        var operationThread = ""
        val dispatch = BrokerDispatch<Any>(onAbandoned = { opened ->
            cleanupThread = Thread.currentThread().name
            if (live === opened) { live = null; cleanup.incrementAndGet() }
        }) {
            operationThread = Thread.currentThread().name
            entered.countDown()
            check(release.await(5, TimeUnit.SECONDS))
            live = old
            old
        }
        try {
            executor.execute { dispatch.task.run() }
            check(entered.await(5, TimeUnit.SECONDS))
            try {
                awaitBrokerResult(dispatch.task, 1) {
                    if (replace) executor.execute { live = replacement }
                    executor.execute { dispatch.abandon(); dispatch.abandon() }
                }
                error("Expected running-operation timeout")
            } catch (e: IllegalStateException) {
                expect(e.message == "Broker did not respond", "running timeout is not success")
            }
            release.countDown()
            executor.submit {}.get(5, TimeUnit.SECONDS)
            expect(dispatch.task.isCancelled, "FutureTask loses result after cancellation")
            expect(operationThread == cleanupThread, "cleanup stays on serial executor")
            expect(cleanup.get() == if (replace) 0 else 1, "cleanup is exact-owner and one-shot")
            expect(if (replace) live === replacement else live == null, "new lease survives; old orphan revoked")
        } finally {
            release.countDown(); executor.shutdown()
            check(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }
    // Nullable results must not be confused with a cancelled-before-run task.
    var nullCleanup = 0
    val nullable = BrokerDispatch<String?>(onAbandoned = { expect(it == null, "nullable result"); nullCleanup++ }) { null }
    nullable.task.run(); nullable.abandon(); nullable.abandon()
    expect(nullCleanup == 1, "nullable outcome cleanup one-shot")
    println("broker_dispatch_cancellation_checks=$checks")
}
'''


class BrokerDispatchCancellation(unittest.TestCase):
    def test_actual_dispatch_code_handles_running_and_queued_cancellation(self):
        if not KOTLINC.is_file() or not (JDK / 'bin/java').is_file():
            self.fail('Pinned Kotlin/JDK toolchain is required')
        env = {**os.environ, 'JAVA_HOME': str(JDK)}
        with tempfile.TemporaryDirectory(prefix='wonad-broker-cancellation-') as name:
            root = Path(name)
            # Test artifacts only; production source is compiled unchanged.
            harness = root / 'Scenarios.kt'
            harness.write_text(HARNESS)
            jar = root / 'scenarios.jar'
            result = subprocess.run([str(KOTLINC), str(SOURCE), str(harness),
                                     '-include-runtime', '-d', str(jar)], env=env,
                                    capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            output = subprocess.check_output([str(JDK / 'bin/java'), '-jar', str(jar)],
                                             text=True, timeout=30)
            self.assertIn('broker_dispatch_cancellation_checks=348', output)

    def test_controller_optional_failures_do_not_use_result_run_catching(self):
        for filename in ['NativeDesktopController.kt', 'WonadController.kt']:
            source = (ANDROID / 'os-integration/src/org/wonad/desktop/broker' / filename).read_text()
            self.assertNotIn('runCatching', source)
        source = (ANDROID / 'os-integration/src/org/wonad/desktop/broker/NativeDesktopController.kt').read_text()
        self.assertIn('attemptBrokerOperation', source)

    def test_v3_session_open_discards_only_the_exact_abandoned_session(self):
        source = (ANDROID / 'os-integration/src/org/wonad/desktop/broker/NativeDesktopController.kt').read_text()
        self.assertIn('synchronous(onAbandoned = { opened ->', source)
        self.assertIn('if (session === opened) revoke(DesktopProtocol.REVOKED_CLIENT_FAILED)', source)
        self.assertIn('dispatch.abandon()', source)
        self.assertNotIn('FutureTask<T>', source)

    def test_v3_launcher_discards_only_exact_unreceived_initial_catalogue(self):
        source = (ANDROID / 'os-integration/src/org/wonad/desktop/broker/NativeDesktopController.kt').read_text()
        launcher = source.split('override fun launcherPage(', 1)[1].split('override fun showLauncher(', 1)[0]
        self.assertIn('synchronous(onAbandoned = { page ->', launcher)
        self.assertIn('catalogId == 0L && offset == 0 && page != null && session === this', launcher)
        self.assertIn('pick?.id == page.catalogId', launcher)
        self.assertIn('endPicker(this); refresh(this, true)', launcher)


if __name__ == '__main__':
    unittest.main()
