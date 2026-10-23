package org.wonad.desktop.security

import android.app.Instrumentation
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.json.JSONArray
import org.json.JSONObject
import org.wonad.desktop.api.*

/** Ordinary API3 owner. It has no completion-fault capability. A separately
 * platform-signed, no-restart isolated SystemUI test withholds one exact native
 * completion proof, NOT a Shell transition and NOT an actual application.
 * Native geometry/input and process liveness must be independently observed. */
class NativeCompletionTimeoutInstrumentation : Instrumentation() {
    companion object {
        private const val SUBMIT = "org.wonad.desktop.test.NATIVE_TIMEOUT_SUBMIT"
        private const val RESTORED = "org.wonad.desktop.test.NATIVE_TIMEOUT_PROXY_RESTORED"
    }
    private lateinit var run: String
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        run = checkNotNull(arguments?.getString("run")); check(run.matches(Regex("[0-9a-f]{32}")))
        start()
    }

    private fun status(phase: String, snapshot: DesktopSnapshot, elapsed: Long = 0,
        heartbeats: Long = 0, checks: Long = 0) = sendStatus(1, Bundle().apply {
        putString("run", run); putString("phase", phase); putInt("api", 3)
        putLong("generation", snapshot.generation); putLong("identity_epoch", snapshot.identityEpoch)
        putInt("owner_uid", Process.myUid()); putInt("owner_pid", Process.myPid())
        putLong("elapsed", elapsed); putLong("heartbeats", heartbeats); putLong("responsive_checks", checks)
        putString("evidence", NativeSecurityClient.proof(snapshot).toString())
    })

    override fun onStart() {
        val report = Bundle()
        val submit = CountDownLatch(1)
        val restored = CountDownLatch(1)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.getStringExtra("run") != run) return
                if (intent.action == SUBMIT) submit.countDown()
                if (intent.action == RESTORED) restored.countDown()
            }
        }
        var registered = false
        var outcome = 0
        try {
            NativeSecurityClient.requireOwner(targetContext, 0)
            check(DesktopProtocol.TRANSACTION_TIMEOUT_MILLIS == 15000L)
            targetContext.registerReceiver(receiver, IntentFilter().apply { addAction(SUBMIT); addAction(RESTORED) },
                null, Handler(Looper.getMainLooper()), Context.RECEIVER_EXPORTED)
            registered = true
            val evidence = JSONObject().put("api", 3)
            NativeSecurityClient.Bound(targetContext).use { binding ->
                val broker = binding.broker()
                lateinit var before: DesktopSnapshot
                NativeSecurityClient.open(targetContext, broker).use { old ->
                    before = old.stable()
                    check(before.displays.size == 1 && before.tasks.all { it.visible && it.inputEnabled })
                    old.armShortcuts(before)
                    evidence.put("before", NativeSecurityClient.proof(before))
                    report.putString("phase", "native_completion_owner_ready")
                    status("client_ready", before)
                    check(submit.await(45, TimeUnit.SECONDS)) { "Host did not install exact isolated native-proof injector" }
                    val current = old.stable()
                    check(current.identityEpoch == before.identityEpoch && current.tasks.map { it.token }.toSet() == before.tasks.map { it.token }.toSet())
                    val area = current.displays.single().bounds
                    val desired = DesktopFrame().apply {
                        topologyRevision = current.topologyRevision; focusedDisplayToken = 0; focusedToken = 0
                        placements = current.tasks.mapIndexed { index, task -> DesktopPlacement().apply {
                            token = task.token; destinationDisplayToken = task.displayToken
                            bounds = DesktopRect().apply {
                                left = area.left + 3; right = area.right - 3
                                top = area.top + index * (area.bottom - area.top) / 2 + 3
                                bottom = area.top + (index + 1) * (area.bottom - area.top) / 2 - 3
                            }
                            visible = true; inputEnabled = true; zOrder = task.zOrder
                        } }.toTypedArray()
                        shellRegions = emptyArray()
                    }
                    check(current.tasks.any { task -> desired.placements.single { it.token == task.token }.bounds.let {
                        it.left != task.bounds.left || it.top != task.bounds.top || it.right != task.bounds.right || it.bottom != task.bounds.bottom
                    } }) { "Native timeout probe must apply a real changed frame" }
                    val heartbeatStart = old.heartbeatsSent()
                    val submitted = SystemClock.elapsedRealtime()
                    old.session.applyFrame(current.generation, 1000, current.revision, desired)
                    status("frame_submitted", current)
                    report.putString("phase", "await_native_completion_observation_timeout")
                    var responsive = 0L
                    var revoked: Pair<Long, Int>? = null
                    while (revoked == null) {
                        check(SystemClock.elapsedRealtime() - submitted < 22000) { "Native completion deadline did not revoke" }
                        NativeSecurityClient.requireApi(broker); responsive++
                        revoked = old.events.revoked.poll(250, TimeUnit.MILLISECONDS)
                    }
                    val elapsed = SystemClock.elapsedRealtime() - submitted
                    val heartbeats = old.heartbeatsSent() - heartbeatStart
                    check(revoked == current.generation to DesktopProtocol.REVOKED_CLIENT_FAILED)
                    check(elapsed in 14900..22000 && heartbeats >= 20 && responsive >= 20) {
                        "No responsive owner/broker at the unchanged real native deadline"
                    }
                    val result = checkNotNull(old.events.results.poll(2, TimeUnit.SECONDS)) { "Native timeout lacked its request result" }
                    check(result.take(3) == listOf(current.generation, 1000L, DesktopProtocol.RESULT_PLATFORM_CONSTRAINT.toLong())) {
                        "Native timeout must never acknowledge a withheld proof as APPLIED: $result"
                    }
                    old.stopHeartbeat()
                    val terminal = old.events.terminal()
                    NativeSecurityClient.retainedCalls(old.session, current)
                    Thread.sleep(1000); old.events.requireSilent(terminal)
                    evidence.put("timeout_elapsed", elapsed).put("heartbeats", heartbeats).put("responsive_checks", responsive)
                        .put("result", DesktopProtocol.RESULT_PLATFORM_CONSTRAINT).put("revocation_reason", revoked.second)
                        .put("retained_methods", JSONArray(NativeSecurityClient.METHODS))
                    report.putLong("old_generation", current.generation); report.putLong("identity_epoch", current.identityEpoch)
                    report.putLong("elapsed", elapsed); report.putLong("heartbeats", heartbeats); report.putLong("responsive_checks", responsive)
                    report.putInt("retained_calls", NativeSecurityClient.METHODS.size); report.putInt("revocation_reason", revoked.second)
                    status("stale_calls_complete", current, elapsed, heartbeats, responsive)
                    report.putString("phase", "await_exact_proxy_restoration")
                    check(restored.await(45, TimeUnit.SECONDS)) { "Host did not verify exact native-proof proxy restoration" }
                }
                report.putString("phase", "native_completion_recovery")
                NativeSecurityClient.open(targetContext, broker).use { fresh ->
                    val ready = fresh.stable()
                    NativeSecurityClient.continuity(before).requireRecovery(ready.generation, ready.identityEpoch, ready.tasks.map { it.token })
                    fresh.apply(2000, restore = before)
                    val applied = fresh.apply(2001, restore = before, signed = true)
                    evidence.put("recovered", NativeSecurityClient.proof(applied)).put("owner_frame", "applied")
                        .put("owner_signed_frame", "applied")
                    report.putLong("new_generation", applied.generation); report.putString("owner_frame", "applied")
                    report.putString("owner_signed_frame", "applied")
                }
            }
            report.putString("native_completion_timeout", "passed")
            report.putString("scope", "v3_native_completion_observation_timeout_signed_rpc")
            report.putInt("api", 3); report.putString("run", run)
            report.putInt("owner_uid", Process.myUid()); report.putInt("owner_pid", Process.myPid())
            report.putString("fingerprint", Build.FINGERPRINT); report.putString("native_abi", Build.SUPPORTED_ABIS.first())
            report.putString("evidence", evidence.toString()); outcome = -1
        } catch (error: Throwable) {
            report.putString("native_completion_timeout", "not_passed"); report.putString("failure_details", error.stackTraceToString())
        } finally {
            try { if (registered) targetContext.unregisterReceiver(receiver) }
            catch (error: Throwable) {
                outcome = 0; report.putString("native_completion_timeout", "not_passed"); report.putString("cleanup_error", error.stackTraceToString())
            }
        }
        finish(outcome, report)
    }
}
