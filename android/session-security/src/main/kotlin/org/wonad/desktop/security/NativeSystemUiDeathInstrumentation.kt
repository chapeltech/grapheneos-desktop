package org.wonad.desktop.security

import android.app.Instrumentation
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.os.DeadObjectException
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONArray
import org.json.JSONObject
import org.wonad.desktop.api.*

/** API3 only. Old remote proxies die; no replacement lease is opened until
 * the host seals exact-black/input-consuming/no-SPY observations. Fresh
 * readiness uses NativeSecurityClient's real ordinary fixed planes, followed
 * by signed transaction13. This is a test-only owner-UID instrumented process,
 * not the normal policy process and never an adopted Shell/system identity. */
class NativeSystemUiDeathInstrumentation : Instrumentation() {
    companion object {
        const val ARM = "org.wonad.desktop.test.NATIVE_SYSTEMUI_DEATH_ARM"
        const val RECONNECT = "org.wonad.desktop.test.NATIVE_SYSTEMUI_DEATH_RECONNECT"
        const val COMPLETE = "org.wonad.desktop.test.NATIVE_SYSTEMUI_DEATH_COMPLETE"
        const val SCOPE = "v3_systemui_death_dead_binders_fail_closed_signed_reconnect"
    }
    private lateinit var run: String
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        run = checkNotNull(arguments?.getString("run")); check(run.matches(Regex("[0-9a-f]{32}")))
        start()
    }
    private fun counters(events: NativeSecurityClient.Events) = listOf(events.snapshots.get(), events.commands.get(),
        events.results.size.toLong(), events.revoked.size.toLong())
    private fun status(phase: String, snapshot: DesktopSnapshot) = sendStatus(1, Bundle().apply {
        putString("phase", phase); putString("run", run); putInt("api", 3)
        putInt("owner_uid", Process.myUid()); putInt("owner_pid", Process.myPid())
        putLong("generation", snapshot.generation); putLong("identity_epoch", snapshot.identityEpoch)
        putString("evidence", NativeSecurityClient.proof(snapshot).toString())
    })
    private fun signed(lease: NativeSecurityClient.Lease, request: Long): Pair<DesktopSnapshot, JSONObject> {
        val base = lease.stable()
        val frame = DesktopFrame().apply {
            topologyRevision = base.topologyRevision
            focusedDisplayToken = base.focusedDisplayToken; focusedToken = base.focusedToken
            placements = base.tasks.map { task -> DesktopPlacement().apply {
                token = task.token; destinationDisplayToken = task.displayToken; bounds = task.bounds
                visible = task.visible; inputEnabled = task.inputEnabled; zOrder = task.zOrder
            } }.toTypedArray(); shellRegions = emptyArray()
        }
        lease.session.applySignedFrame(base.generation, request, base.revision, frame)
        val callback = checkNotNull(lease.events.results.poll(5, TimeUnit.SECONDS))
        check(callback.size == 4 && callback.take(3) == listOf(base.generation, request, 0L) && callback[3] > 0)
        check(lease.events.revoked.isEmpty())
        val next = lease.stable()
        check(next.generation == base.generation && next.identityEpoch == base.identityEpoch &&
            next.tasks.size == base.tasks.size)
        val expected = NativeSecurityClient.proof(base).also { it.remove("revision") }.toString()
        check(NativeSecurityClient.proof(next).also { it.remove("revision") }.toString() == expected)
        return next to JSONObject().put("method", "applySignedFrame").put("transaction", 13).put("request", request)
            .put("base", NativeSecurityClient.proof(base)).put("callback", JSONArray(callback))
            .put("frame", JSONObject().put("topology_revision", frame.topologyRevision)
                .put("focused_display_token", frame.focusedDisplayToken).put("focused_token", frame.focusedToken)
                .put("shell_regions", JSONArray()).put("placements", JSONArray(base.tasks.map { task ->
                    JSONObject().put("token", task.token).put("display_token", task.displayToken)
                        .put("bounds", JSONArray(listOf(task.bounds.left, task.bounds.top, task.bounds.right, task.bounds.bottom)))
                        .put("visible", task.visible).put("input", task.inputEnabled).put("z", task.zOrder) })))
            .put("applied", NativeSecurityClient.proof(next))
    }
    override fun onStart() {
        val report = Bundle(); var outcome = 0; var registered = false
        val armed = CountDownLatch(1); val reconnect = CountDownLatch(1); val complete = CountDownLatch(1)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.getStringExtra("run") != run) return
                when (intent.action) { ARM -> armed.countDown(); RECONNECT -> reconnect.countDown(); COMPLETE -> complete.countDown() }
            }
        }
        var original: NativeSecurityClient.Lease? = null
        var deathHeartbeat: NativeSystemUiDeathHeartbeat? = null
        try {
            NativeSecurityClient.requireOwner(targetContext, 0)
            check(NativeSystemUiDeathSpec.sessionMethods == NativeSecurityClient.METHODS)
            targetContext.registerReceiver(receiver, IntentFilter().apply {
                addAction(ARM); addAction(RECONNECT); addAction(COMPLETE)
            }, null, Handler(Looper.getMainLooper()), Context.RECEIVER_EXPORTED)
            registered = true
            val proof = JSONObject().put("api", 3)
            NativeSecurityClient.Bound(targetContext).use { binding ->
                val broker = binding.broker()
                val brokerDeath = CountDownLatch(1); val sessionDeath = CountDownLatch(1)
                val brokerDeaths = AtomicInteger(); val sessionDeaths = AtomicInteger()
                broker.asBinder().linkToDeath({ brokerDeaths.incrementAndGet(); brokerDeath.countDown() }, 0)
                val old = NativeSecurityClient.open(targetContext, broker); original = old
                old.session.asBinder().linkToDeath({ sessionDeaths.incrementAndGet(); sessionDeath.countDown() }, 0)
                val (initial, initialSigned) = signed(old, 1000)
                proof.put("before", NativeSecurityClient.proof(initial))
                status("lease_ready", initial)
                check(armed.await(45, TimeUnit.SECONDS)) { "Host did not seal actual original lease/input" }
                val beforeDeath = old.stable()
                // Transfer the SAME increasing real heartbeat sequence to a
                // test-only loop which remains live throughout host captures.
                // Stopping here without a replacement would prove expiry, not
                // an active-lease SystemUI death, on a slow host.
                old.stopHeartbeat()
                val keepalive = NativeSystemUiDeathHeartbeat(old.heartbeatsSent(),
                    { sequence -> old.session.heartbeat(beforeDeath.generation, sequence) },
                    { brokerDeaths.get() == 1 && sessionDeaths.get() == 1 &&
                        !broker.asBinder().isBinderAlive && !old.session.asBinder().isBinderAlive },
                    { error -> error is DeadObjectException })
                deathHeartbeat = keepalive
                keepalive.requireAlive()
                proof.put("ready_for_crash", NativeSecurityClient.proof(beforeDeath))
                status("ready_for_crash", beforeDeath)
                check(brokerDeath.await(60, TimeUnit.SECONDS)) { "Original actual broker proxy did not die" }
                check(sessionDeath.await(10, TimeUnit.SECONDS)) { "Original actual native session proxy did not die" }
                check(!broker.asBinder().isBinderAlive && !old.session.asBinder().isBinderAlive)
                keepalive.stopAfterDeath()
                SystemClock.sleep(500) // Drain only callbacks posted before actual process death.
                check(old.events.revoked.isEmpty()) { "Original lease revoked before actual SystemUI death" }
                val terminal = counters(old.events)
                val session = old.session; val snapshot = beforeDeath; val gen = snapshot.generation
                val task = snapshot.tasks.first().token; val display = snapshot.displays.first().token
                val operations = listOf<() -> Unit>(
                    { session.applyFrame(gen, 1, snapshot.revision, null) },
                    { session.focusTask(gen, 2, snapshot.revision, task) },
                    { session.closeTask(gen, 3, snapshot.revision, task) },
                    { session.enableShortcuts(gen, true) }, { session.heartbeat(gen, 1000000) },
                    { session.release(gen) }, { session.enableExternalUi(gen) }, { session.showShell(gen, display) },
                    { session.launcherPage(gen, 0, display, 0); Unit }, { session.showLauncher(gen, 1) },
                    { session.selectLauncher(gen, 1, 0) }, { session.showTransferPicker(gen, display) },
                    { session.applySignedFrame(gen, 4, snapshot.revision, null) },
                    { broker.apiVersion; Unit }, { broker.capabilities; Unit },
                    { broker.openSession(3, NativeSecurityClient.Events()); Unit })
                val calls = operations.mapIndexed { index, operation ->
                    val exception = try { operation(); error("Dead native Binder operation returned") }
                        catch (dead: DeadObjectException) { dead.javaClass.name }
                    NativeSystemUiDeathSpec.DeadCall(if (index < 13) "session" else "broker",
                        if (index < 13) NativeSystemUiDeathSpec.sessionMethods[index] else NativeSystemUiDeathSpec.brokerMethods[index - 13],
                        if (index < 13) index + 1 else listOf(1, 2, 4)[index - 13], exception)
                }
                NativeSystemUiDeathSpec.requireCalls(calls)
                SystemClock.sleep(1000); NativeSystemUiDeathSpec.requireSilent(terminal, counters(old.events))
                proof.put("dead_calls", JSONArray(calls.map { call -> JSONObject().put("role", call.role)
                    .put("method", call.method).put("transaction", call.transaction).put("exception", call.exception) }))
                    .put("old_callback_counts", JSONArray(terminal)).put("callbacks_after_dead", JSONArray(counters(old.events)))
                    .put("broker_death_notifications", brokerDeaths.get()).put("session_death_notifications", sessionDeaths.get())
                    .put("old_broker_alive", false).put("old_session_alive", false)
                status("dead_calls_complete", beforeDeath)
                check(reconnect.await(45, TimeUnit.SECONDS)) { "Host did not seal fail-black/no-SPY/consuming input before fresh open" }
                NativeSystemUiDeathSpec.requireSilent(terminal, counters(old.events))
                NativeSecurityClient.Bound(targetContext).use { newBinding ->
                    val newBroker = newBinding.broker()
                    check(newBroker.asBinder() != broker.asBinder() && newBroker.asBinder().isBinderAlive)
                    NativeSecurityClient.open(targetContext, newBroker).use { fresh ->
                        val (recovered, recoverySigned) = signed(fresh, 2000)
                        NativeSystemUiDeathSpec.requireFresh(beforeDeath.generation, recovered.generation)
                        proof.put("recovered", NativeSecurityClient.proof(recovered))
                            .put("signed_calls", JSONArray(listOf(initialSigned, recoverySigned)))
                        status("fresh_lease_recovered", recovered)
                        check(complete.await(45, TimeUnit.SECONDS)) { "Host did not seal exact fresh-drawn/input recovery" }
                        NativeSystemUiDeathSpec.requireSilent(terminal, counters(old.events))
                        proof.put("callbacks_after_fresh", JSONArray(counters(old.events)))
                        check(brokerDeaths.get() == 1 && sessionDeaths.get() == 1)
                    }
                }
            }
            report.putString("native_dead_binders", "passed"); report.putInt("api", 3); report.putString("scope", SCOPE)
            report.putString("run", run); report.putInt("owner_uid", Process.myUid()); report.putInt("owner_pid", Process.myPid())
            report.putString("fingerprint", Build.FINGERPRINT); report.putString("native_abi", Build.SUPPORTED_ABIS.first())
            report.putInt("dead_session_calls", 13); report.putInt("dead_broker_calls", 3)
            report.putString("evidence", proof.toString()); outcome = -1
        } catch (error: Throwable) {
            report.putString("native_dead_binders", "not_passed"); report.putString("failure_details", error.stackTraceToString())
        } finally {
            try {
                try { deathHeartbeat?.close() } finally {
                    try {
                        original?.let { lease ->
                            lease.stopHeartbeat()
                            if (lease.session.asBinder().isBinderAlive) lease.close()
                        }
                    } finally {
                        if (registered) targetContext.unregisterReceiver(receiver)
                    }
                }
            } catch (error: Throwable) {
                outcome = 0; report.putString("native_dead_binders", "not_passed"); report.putString("cleanup_error", error.stackTraceToString())
            }
        }
        finish(outcome, report)
    }
}
