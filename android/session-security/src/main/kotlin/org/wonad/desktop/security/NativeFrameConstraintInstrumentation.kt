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

/** Genuine v3 app-constraint probe, ordinary owner UID, no fault injector.
 * Both validators reject an otherwise valid frame. Actual signed transaction13
 * then completes on the SAME live Binder/lease. Host raw WM/input/pixels and
 * exclusive app input delivery are mandatory independent evidence. */
class NativeFrameConstraintInstrumentation : Instrumentation() {
    companion object {
        const val SUBMIT = "org.wonad.desktop.test.NATIVE_CONSTRAINT_SUBMIT"
        const val RECOVER = "org.wonad.desktop.test.NATIVE_CONSTRAINT_RECOVER"
        const val COMPLETE = "org.wonad.desktop.test.NATIVE_CONSTRAINT_COMPLETE"
    }
    private lateinit var run: String
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        run = checkNotNull(arguments?.getString("run")); check(run.matches(Regex("[0-9a-f]{32}")))
        start()
    }

    private fun rect(value: DesktopRect) = listOf(value.left, value.top, value.right, value.bottom)
    private fun proof(snapshot: DesktopSnapshot): JSONObject = NativeSecurityClient.proof(snapshot).also { json ->
        json.put("tasks", JSONArray(snapshot.tasks.map { task -> JSONObject()
            .put("token", task.token).put("display_token", task.displayToken).put("package", task.packageName)
            .put("bounds", JSONArray(rect(task.bounds))).put("visible", task.visible).put("input", task.inputEnabled)
            .put("z", task.zOrder).put("minimum_width", task.minimumWidth).put("minimum_height", task.minimumHeight)
            .put("resizable", task.resizable) }))
    }
    private fun state(snapshot: DesktopSnapshot) = proof(snapshot).also { it.remove("revision") }.toString()
    private fun status(phase: String, snapshot: DesktopSnapshot, checks: Int = 0, heartbeats: Long = 0) {
        sendStatus(1, Bundle().apply {
            putString("phase", phase); putString("run", run); putInt("api", 3)
            putInt("owner_uid", Process.myUid()); putInt("owner_pid", Process.myPid())
            putLong("generation", snapshot.generation); putLong("identity_epoch", snapshot.identityEpoch)
            putInt("responsive_checks", checks); putLong("heartbeats", heartbeats)
            putString("evidence", proof(snapshot).toString())
        })
    }

    override fun onStart() {
        val report = Bundle(); var outcome = 0; var registered = false
        val submit = CountDownLatch(1); val recover = CountDownLatch(1); val complete = CountDownLatch(1)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.getStringExtra("run") != run) return
                when (intent.action) { SUBMIT -> submit.countDown(); RECOVER -> recover.countDown(); COMPLETE -> complete.countDown() }
            }
        }
        try {
            NativeSecurityClient.requireOwner(targetContext, 0)
            targetContext.registerReceiver(receiver, IntentFilter().apply {
                addAction(SUBMIT); addAction(RECOVER); addAction(COMPLETE)
            }, null, Handler(Looper.getMainLooper()), Context.RECEIVER_EXPORTED)
            registered = true
            val evidence = JSONObject().put("api", 3).put("revocations", 0)
            NativeSecurityClient.Bound(targetContext).use { binding ->
                val broker = binding.broker()
                NativeSecurityClient.open(targetContext, broker).use { lease ->
                    val before = lease.stable()
                    check(before.displays.size == 1 && before.tasks.all { it.visible && it.inputEnabled })
                    val selected = before.tasks.firstNotNullOfOrNull { task ->
                        val area = before.displays.single { it.token == task.displayToken }
                        NativeFrameConstraintSpec.impossible(rect(task.bounds), task.minimumWidth, task.minimumHeight,
                            task.resizable, rect(area.bounds))?.let { Triple(task.token, it.first, it.second) }
                    } ?: error("No genuine app minimum/nonresizable constraint in actual native snapshot")
                    evidence.put("before", proof(before)).put("constraint_token", selected.first)
                        .put("constraint_kind", selected.second).put("impossible_bounds", JSONArray(selected.third))
                    status("client_ready", before)
                    check(submit.await(45, TimeUnit.SECONDS)) { "Host did not seal pre-constraint observations" }
                    val calls = JSONArray()
                    fun apply(snapshot: DesktopSnapshot, request: Long, signed: Boolean, impossible: Boolean): DesktopSnapshot {
                        val frame = DesktopFrame().apply {
                            topologyRevision = snapshot.topologyRevision
                            focusedDisplayToken = snapshot.focusedDisplayToken; focusedToken = snapshot.focusedToken
                            placements = snapshot.tasks.map { task -> DesktopPlacement().apply {
                                token = task.token; destinationDisplayToken = task.displayToken
                                bounds = if (impossible && task.token == selected.first) DesktopRect().apply {
                                    left = selected.third[0]; top = selected.third[1]; right = selected.third[2]; bottom = selected.third[3]
                                } else task.bounds
                                visible = task.visible; inputEnabled = task.inputEnabled; zOrder = task.zOrder
                            } }.toTypedArray(); shellRegions = emptyArray()
                        }
                        val started = SystemClock.elapsedRealtime()
                        if (signed) lease.session.applySignedFrame(snapshot.generation, request, snapshot.revision, frame)
                        else lease.session.applyFrame(snapshot.generation, request, snapshot.revision, frame)
                        val callback = checkNotNull(lease.events.results.poll(5, TimeUnit.SECONDS)) { "No actual constraint/frame callback" }
                        check(callback.size == 4 && callback.take(3) == listOf(snapshot.generation, request,
                            if (impossible) 6L else 0L) && callback[3] > 0) { "False APPLIED or incorrect native callback: $callback" }
                        calls.put(JSONObject().put("method", if (signed) "applySignedFrame" else "applyFrame")
                            .put("transaction", if (signed) 13 else 1).put("request", request)
                            .put("base", proof(snapshot)).put("frame", JSONObject().put("topology_revision", frame.topologyRevision)
                                .put("focused_display_token", frame.focusedDisplayToken).put("focused_token", frame.focusedToken)
                                .put("shell_regions", JSONArray()).put("placements", JSONArray(frame.placements.map { placement ->
                                    JSONObject().put("token", placement.token).put("display_token", placement.destinationDisplayToken)
                                        .put("bounds", JSONArray(rect(placement.bounds))).put("visible", placement.visible)
                                        .put("input", placement.inputEnabled).put("z", placement.zOrder) })))
                            .put("callback", JSONArray(callback)).put("elapsed_ms", SystemClock.elapsedRealtime() - started))
                        return lease.stable().also { next ->
                            check(state(next) == state(snapshot)) { "Constraint/recovery changed exact native state" }
                            check(lease.events.results.isEmpty() && lease.events.revoked.isEmpty())
                        }
                    }
                    val bounded = apply(before, 1000, false, true)
                    val rejected = apply(bounded, 1001, true, true)
                    val heartbeatStart = lease.heartbeatsSent(); var responsive = 0
                    repeat(25) { NativeSecurityClient.requireApi(broker); responsive++; SystemClock.sleep(100) }
                    val heartbeats = lease.heartbeatsSent() - heartbeatStart
                    check(heartbeats >= 4 && lease.events.revoked.isEmpty() && lease.events.results.isEmpty())
                    check(state(lease.stable()) == state(before))
                    evidence.put("rejected", proof(rejected)).put("responsive_checks", responsive).put("heartbeats", heartbeats)
                    status("constraint_reported", rejected, responsive, heartbeats)
                    check(recover.await(45, TimeUnit.SECONDS)) { "Host did not prove unchanged constraint state/input" }
                    // An actual signed RPC, not a manufactured success flag. The
                    // host may have changed focus through ordinary app input.
                    val current = lease.stable()
                    val applied = apply(current, 2000, true, false)
                    check(applied.generation == before.generation && applied.identityEpoch == before.identityEpoch &&
                        applied.tasks.map { it.token }.toSet() == before.tasks.map { it.token }.toSet())
                    evidence.put("calls", calls).put("recovered", proof(applied))
                    status("same_lease_recovered", applied, responsive, heartbeats)
                    check(complete.await(45, TimeUnit.SECONDS)) { "Host did not seal responsive recovery" }
                    check(lease.events.results.isEmpty() && lease.events.revoked.isEmpty())
                }
            }
            report.putString("native_constraint", "passed"); report.putInt("api", 3)
            report.putString("scope", "v3_actual_app_constraint_same_lease_signed_rpc")
            report.putString("run", run); report.putInt("owner_uid", Process.myUid()); report.putInt("owner_pid", Process.myPid())
            report.putString("fingerprint", Build.FINGERPRINT); report.putString("native_abi", Build.SUPPORTED_ABIS.first())
            report.putString("evidence", evidence.toString()); outcome = -1
        } catch (error: Throwable) {
            report.putString("native_constraint", "not_passed"); report.putString("failure_details", error.stackTraceToString())
        } finally {
            try { if (registered) targetContext.unregisterReceiver(receiver) }
            catch (error: Throwable) { outcome = 0; report.putString("native_constraint", "not_passed"); report.putString("cleanup_error", error.stackTraceToString()) }
        }
        finish(outcome, report)
    }
}
