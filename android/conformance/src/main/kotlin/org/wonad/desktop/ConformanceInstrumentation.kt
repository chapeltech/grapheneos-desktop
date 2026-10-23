package org.wonad.desktop

import android.app.Activity
import android.app.Instrumentation
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.os.SystemClock
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Same-APK orchestration entry point. Unlike an exported Activity/receiver,
 * it does not turn the authenticated conformance client into a deputy for an
 * arbitrary ordinary app. The canonical evidence remains the service dump. */
class ConformanceInstrumentation : Instrumentation() {
    private lateinit var run: String
    private lateinit var mode: String
    private lateinit var nonce: String
    private lateinit var phase: String

    private fun bindRuntime(): ServiceConnection {
        val latch = CountDownLatch(1)
        val local = AtomicReference<ConformanceService.LocalBinder?>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                local.set(binder as ConformanceService.LocalBinder); latch.countDown()
            }
            override fun onServiceDisconnected(name: ComponentName) { local.set(null) }
            override fun onNullBinding(name: ComponentName) { latch.countDown() }
            override fun onBindingDied(name: ComponentName) { local.set(null); latch.countDown() }
        }
        check(targetContext.bindService(Intent(targetContext, ConformanceService::class.java),
            connection, Context.BIND_AUTO_CREATE)) { "runtime status service bind was rejected" }
        check(latch.await(10, TimeUnit.SECONDS)) { "runtime status service bind timed out" }
        checkNotNull(local.get()) { "runtime status service returned no local binder" }
            .start(run, mode, nonce)
        return connection
    }

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        run = arguments?.getString(ConformanceContract.EXTRA_RUN).orEmpty()
        mode = arguments?.getString(ConformanceContract.EXTRA_MODE).orEmpty()
        nonce = arguments?.getString(ConformanceContract.EXTRA_NONCE).orEmpty()
        phase = arguments?.getString(ConformanceContract.EXTRA_PHASE).orEmpty()
        require(ConformanceContract.validRun(run)) { "run must be 32 lowercase hexadecimal characters" }
        require(ConformanceContract.validMode(mode)) { "unsupported conformance mode" }
        require(mode != ConformanceContract.MODE_RUNTIME || ConformanceContract.validNonce(nonce)) {
            "runtime mode requires a host nonce"
        }
        require(mode != ConformanceContract.MODE_RUNTIME || phase == ConformanceContract.RUNTIME_START) {
            "runtime mode requires the explicit start phase"
        }
        start()
    }

    override fun onStart() {
        val result = Bundle().apply { putString("run", run); putString("mode", mode); putInt("api", 3) }
        var runtimeConnection: ServiceConnection? = null
        try {
            if (mode == ConformanceContract.MODE_RUNTIME) {
                runtimeConnection = bindRuntime()
            } else {
                targetContext.startActivity(Intent(ConformanceContract.ACTION_RUN)
                    .setComponent(ComponentName(targetContext, ConformanceControlActivity::class.java))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    .putExtra(ConformanceContract.EXTRA_RUN, run)
                    .putExtra(ConformanceContract.EXTRA_MODE, mode))
            }
            val readinessDeadline = SystemClock.elapsedRealtime() +
                if (mode == ConformanceContract.MODE_FULL) 10 * 60_000L else 60_000L
            var runtimeReady = false
            while (mode == ConformanceContract.MODE_RUNTIME ||
                    SystemClock.elapsedRealtime() < readinessDeadline) {
                val ledger = ConformanceRegistry.ledger
                val state = ledger?.terminalState()
                if (mode == ConformanceContract.MODE_FULL && state == "passed") {
                    result.putString("conformance", "passed"); result.putString("status", ledger.json())
                    // finish() force-stops the instrumented process, including
                    // its status Service. Retain the terminal dump for the host
                    // just as runtime stop/failure does; never substitute the
                    // instrumentation result for the actual service observation.
                    SystemClock.sleep(2_000)
                    finish(Activity.RESULT_OK, result); return
                }
                if (mode == ConformanceContract.MODE_RUNTIME &&
                    (ledger as? ConformanceRuntimeLedger)?.initialReady(nonce) == true) {
                    runtimeReady = true
                }
                if (mode == ConformanceContract.MODE_RUNTIME && runtimeReady && state == "stopped") {
                    result.putString("runtime", "stopped"); result.putString("status", ledger.json())
                    // Keep the bound service alive long enough for the host to
                    // observe the exact stop nonce acknowledgement in dumpsys.
                    SystemClock.sleep(2_000)
                    finish(Activity.RESULT_OK, result); return
                }
                if (state == "failed") {
                    result.putString(if (mode == ConformanceContract.MODE_FULL) "conformance" else "runtime", "failed")
                    result.putString("status", ledger.json())
                    SystemClock.sleep(2_000)
                    finish(Activity.RESULT_CANCELED, result); return
                }
                if (mode == ConformanceContract.MODE_RUNTIME && !runtimeReady &&
                    SystemClock.elapsedRealtime() >= readinessDeadline) break
                SystemClock.sleep(200)
            }
            result.putString(if (mode == ConformanceContract.MODE_FULL) "conformance" else "runtime", "failed")
            result.putString("failure", "instrumentation timeout")
        } catch (error: Throwable) {
            result.putString(if (mode == ConformanceContract.MODE_FULL) "conformance" else "runtime", "failed")
            result.putString("failure", error.stackTraceToString().take(16 * 1024))
        } finally {
            runtimeConnection?.let { try { targetContext.unbindService(it) } catch (_: Throwable) { } }
        }
        finish(Activity.RESULT_CANCELED, result)
    }
}
