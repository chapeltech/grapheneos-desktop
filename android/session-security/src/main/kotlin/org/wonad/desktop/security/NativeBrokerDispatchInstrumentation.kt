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
import org.json.JSONObject
import org.wonad.desktop.api.DesktopProtocol

/** Ordinary, unprivileged API3 owner for the real BrokerDispatch deadline.
 * The separate userdebug-only SystemUI injector delays one unchanged IWM read;
 * this client uses only the public Binder API and receives no fault authority. */
class NativeBrokerDispatchInstrumentation : Instrumentation() {
    companion object {
        private const val START = "org.wonad.desktop.test.BROKER_DISPATCH_START"
        private const val RESTORED = "org.wonad.desktop.test.BROKER_DISPATCH_PROXY_RESTORED"
    }
    private lateinit var run: String

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        run = checkNotNull(arguments?.getString("run")); check(run.matches(Regex("[0-9a-f]{32}")))
        start()
    }

    private fun status(phase: String, extra: Bundle.() -> Unit = {}) = sendStatus(1, Bundle().apply {
        putString("run", run); putString("phase", phase); putInt("api", 3)
        putInt("owner_uid", Process.myUid()); putInt("owner_pid", Process.myPid()); extra()
    })

    override fun onStart() {
        val report = Bundle()
        val start = CountDownLatch(1)
        val restored = CountDownLatch(1)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.getStringExtra("run") != run) return
                when (intent.action) { START -> start.countDown(); RESTORED -> restored.countDown() }
            }
        }
        var registered = false
        var outcome = 0
        try {
            NativeSecurityClient.requireOwner(targetContext, 0)
            targetContext.registerReceiver(receiver, IntentFilter().apply { addAction(START); addAction(RESTORED) },
                null, Handler(Looper.getMainLooper()), Context.RECEIVER_EXPORTED)
            registered = true
            NativeSecurityClient.Bound(targetContext).use { binding ->
                val broker = binding.broker()
                status("client_ready")
                check(start.await(45, TimeUnit.SECONDS)) { "Host did not start the exact dispatch fault" }
                val events = NativeSecurityClient.Events()
                val began = SystemClock.elapsedRealtime()
                val failure = try {
                    broker.openSession(DesktopProtocol.API_VERSION, events)
                    null
                } catch (error: IllegalStateException) { error }
                val elapsed = SystemClock.elapsedRealtime() - began
                check(failure?.message == "Broker did not respond") { "Dispatch did not expose the bounded timeout: $failure" }
                check(elapsed in 1800..4000) { "Public Binder timeout did not retain its two-second bound: $elapsed" }
                val revoked = checkNotNull(events.revoked.poll(10, TimeUnit.SECONDS)) {
                    "Unreceived completed Session was not revoked"
                }
                check(revoked.second == DesktopProtocol.REVOKED_CLIENT_FAILED)
                val abandoned = checkNotNull(events.snapshot.get()) { "Delayed real open never created the abandoned Session" }
                check(abandoned.generation == revoked.first && abandoned.generation > 0 && abandoned.identityEpoch > 0 &&
                    abandoned.revision > 0 && abandoned.topologyRevision > 0 && abandoned.tasks.isEmpty() &&
                    abandoned.displays.isNotEmpty() && abandoned.focusedDisplayToken == 0L && abandoned.focusedToken == 0L &&
                    !abandoned.interactionBlocked && abandoned.displays.all { display ->
                        display.token > 0 && display.displayId > 0 && display.identityHint > 0 && display.secure &&
                            display.shellGeneration >= 0 && display.shellGeneration != abandoned.generation
                    })
                check(events.results.isEmpty() && events.commands.get() == 0L)
                val terminal = events.terminal(); Thread.sleep(250); events.requireSilent(terminal)
                status("timeout_observed") {
                    putLong("elapsed", elapsed); putLong("generation", abandoned.generation)
                    putLong("identity_epoch", abandoned.identityEpoch); putInt("revocation_reason", revoked.second)
                    putString("evidence", NativeSecurityClient.proof(abandoned).toString())
                }
                check(restored.await(45, TimeUnit.SECONDS)) { "Host did not verify exact fault-proxy restoration" }
                NativeSecurityClient.open(targetContext, broker).use { fresh ->
                    val recovered = fresh.stable()
                    check(recovered.generation > 0 && recovered.generation != abandoned.generation &&
                        recovered.identityEpoch == abandoned.identityEpoch && recovered.tasks.size == 2)
                    fun displayIdentity(snapshot: org.wonad.desktop.api.DesktopSnapshot) = snapshot.displays.map {
                        listOf(it.token, it.displayId.toLong(), it.identityHint, it.bounds.left.toLong(),
                            it.bounds.top.toLong(), it.bounds.right.toLong(), it.bounds.bottom.toLong(), if (it.secure) 1L else 0L)
                    }.sortedBy { it[1] }
                    check(displayIdentity(recovered) == displayIdentity(abandoned)) {
                        "Dispatch cleanup/recovery changed native display identities"
                    }
                    status("recovered") {
                        putLong("generation", recovered.generation); putLong("identity_epoch", recovered.identityEpoch)
                        putString("evidence", NativeSecurityClient.proof(recovered).toString())
                    }
                    report.putLong("old_generation", abandoned.generation)
                    report.putLong("new_generation", recovered.generation)
                    report.putLong("identity_epoch", recovered.identityEpoch)
                    report.putString("evidence", JSONObject().put("abandoned", NativeSecurityClient.proof(abandoned))
                        .put("recovered", NativeSecurityClient.proof(recovered)).toString())
                }
                report.putLong("dispatch_elapsed", elapsed); report.putInt("revocation_reason", revoked.second)
            }
            report.putString("native_broker_dispatch", "passed")
            report.putString("scope", "v3_actual_broker_dispatch_2s_timeout_abandonment")
            report.putString("timeout_message", "Broker did not respond")
            report.putString("callbacks_silent", "true"); report.putString("proxy_restoration_observed", "true")
            report.putInt("api", 3); report.putString("run", run)
            report.putInt("owner_uid", Process.myUid()); report.putInt("owner_pid", Process.myPid())
            report.putString("fingerprint", Build.FINGERPRINT); report.putString("native_abi", Build.SUPPORTED_ABIS.first())
            outcome = -1
        } catch (error: Throwable) {
            report.putString("native_broker_dispatch", "not_passed")
            report.putString("failure_details", error.stackTraceToString())
        } finally {
            try { if (registered) targetContext.unregisterReceiver(receiver) }
            catch (error: Throwable) {
                outcome = 0; report.putString("native_broker_dispatch", "not_passed")
                report.putString("cleanup_error", error.stackTraceToString())
            }
        }
        finish(outcome, report)
    }
}
