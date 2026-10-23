package org.wonad.desktop

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.SystemClock
import java.io.FileDescriptor
import java.io.PrintWriter
import java.util.concurrent.Executors
import java.util.concurrent.Future

/** Unexported bound service. `dumpsys activity service` is the sole host status
 * channel; no broadcast, socket, storage or test-only platform permission is used. */
class ConformanceService : Service() {
    inner class LocalBinder : Binder() {
        fun start(run: String, mode: String, nonce: String) = startRun(run, mode, nonce)
        fun status(): String = ConformanceRegistry.ledger?.json() ?: idleStatus()
    }
    private val binder = LocalBinder()
    private val executor = Executors.newSingleThreadExecutor()
    private var active: Future<*>? = null
    private var runtime: ConformanceRuntimeRunner? = null

    @Synchronized private fun startRun(run: String, mode: String, nonce: String) {
        require(ConformanceContract.validRun(run)) { "run must be 32 lowercase hexadecimal characters" }
        require(ConformanceContract.validMode(mode)) { "unsupported conformance mode" }
        require(mode != ConformanceContract.MODE_RUNTIME || ConformanceContract.validNonce(nonce)) {
            "runtime mode requires a 32-character lowercase hexadecimal host nonce"
        }
        check(active?.isDone != false) { "a conformance run is already active" }
        if (mode == ConformanceContract.MODE_FULL) {
            val ledger = ConformanceLedger(run, mode) { SystemClock.elapsedRealtime() }
            ConformanceRegistry.begin(ledger)
            runtime = null
            active = executor.submit(ConformanceRunner(applicationContext, ledger))
        } else {
            val ledger = ConformanceRuntimeLedger(run, nonce) { SystemClock.elapsedRealtime() }
            ConformanceRegistry.begin(ledger)
            val runner = ConformanceRuntimeRunner(applicationContext, ledger, nonce)
            runtime = runner
            active = executor.submit(runner)
        }
    }
    @Synchronized private fun submitRuntime(instruction: RuntimeHostInstruction) {
        check(active?.isDone == false) { "no live policy-free runtime worker" }
        check(ConformanceRegistry.ledger?.terminalState() !in setOf("failed", "stopped")) {
            "policy-free runtime is terminal"
        }
        checkNotNull(runtime) { "no policy-free runtime is active" }.submit(instruction)
    }
    private fun idleStatus() = "{\"schema\":1,\"state\":\"idle\",\"phase\":\"idle\"}"
    override fun onBind(intent: Intent): IBinder = binder
    override fun onDestroy() {
        active?.cancel(true); executor.shutdownNow(); super.onDestroy()
    }
    override fun dump(fd: FileDescriptor, writer: PrintWriter, args: Array<out String>?) {
        val commandArgs = args ?: emptyArray()
        if (commandArgs.isNotEmpty()) {
            try {
                val instruction = RuntimeHostInstruction.parse(commandArgs)
                submitRuntime(instruction)
                writer.println("WONAD_CONFORMANCE_CONTROL accepted ${instruction.run} " +
                    "${instruction.nonce} ${instruction.phase}")
            } catch (_: Throwable) {
                writer.println("WONAD_CONFORMANCE_CONTROL rejected")
            }
        }
        writer.println("WONAD_CONFORMANCE_EXPECTATION " + (runtime?.expectedRevocationJson() ?: "null"))
        writer.println("WONAD_CONFORMANCE_BROKER_DEATH " + (runtime?.expectedBrokerDeathJson() ?: "null"))
        writer.println(ConformanceMalformedCalls.MARKER + (runtime?.malformedProofJson() ?: "null"))
        writer.println("WONAD_CONFORMANCE_STATUS " + (ConformanceRegistry.ledger?.json() ?: idleStatus()))
    }
}
