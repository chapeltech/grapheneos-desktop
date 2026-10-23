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
import java.util.concurrent.atomic.AtomicLong
import org.json.JSONObject
import org.wonad.desktop.api.DesktopProtocol
import org.wonad.desktop.api.DesktopSnapshot

/** Ordinary public-API owner. No hidden API or fault authority. Tests only
 * abandoned initial-page cleanup followed by recovery, NOT replacement races. */
class NativeLauncherPageTimeoutInstrumentation : Instrumentation() {
    companion object {
        private const val START = "org.wonad.desktop.test.LAUNCHER_TIMEOUT_START"
        private const val RESTORED = "org.wonad.desktop.test.LAUNCHER_TIMEOUT_PROXY_RESTORED"
    }
    private lateinit var run: String
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        run = checkNotNull(arguments?.getString("run"))
        check(run.matches(Regex("[0-9a-f]{32}")))
        start()
    }
    private fun status(phase: String, snapshot: DesktopSnapshot, extra: Bundle.() -> Unit = {}) =
        sendStatus(1, Bundle().apply {
            putString("run", run); putString("phase", phase); putInt("api", 3)
            putInt("owner_uid", Process.myUid()); putInt("owner_pid", Process.myPid())
            putLong("generation", snapshot.generation); putLong("identity_epoch", snapshot.identityEpoch)
            putLong("display_token", snapshot.displays.single().token)
            putString("evidence", NativeSecurityClient.proof(snapshot).toString()); extra()
        })
    override fun onStart() {
        val report = Bundle()
        val start = CountDownLatch(1)
        val restored = CountDownLatch(1)
        val abandonedCatalogue = AtomicLong()
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.getStringExtra("run") != run) return
                when (intent.action) {
                    START -> start.countDown()
                    RESTORED -> {
                        abandonedCatalogue.set(intent.getLongExtra("catalogue_id", 0))
                        restored.countDown()
                    }
                }
            }
        }
        var registered = false
        var outcome = 0
        try {
            NativeSecurityClient.requireOwner(targetContext, 0)
            targetContext.registerReceiver(receiver, IntentFilter().apply {
                addAction(START); addAction(RESTORED)
            }, null, Handler(Looper.getMainLooper()), Context.RECEIVER_EXPORTED)
            registered = true
            NativeSecurityClient.Bound(targetContext).use { binding ->
                NativeSecurityClient.open(targetContext, binding.broker()).use { lease ->
                    val before = lease.stable()
                    check(before.displays.size == 1)
                    lease.armShortcuts(before)
                    status("client_ready", before)
                    check(start.await(45, TimeUnit.SECONDS)) { "Host did not arm exact initial-page injector" }
                    val began = SystemClock.elapsedRealtime()
                    val failure = try {
                        lease.session.launcherPage(before.generation, 0, before.displays.single().token, 0)
                        null
                    } catch (error: IllegalStateException) { error }
                    val elapsed = SystemClock.elapsedRealtime() - began
                    check(failure?.message == "Broker did not respond" && elapsed in 1800..4000) {
                        "Initial page did not retain exact two-second Binder timeout: $failure / $elapsed"
                    }
                    status("timeout_observed", before) { putLong("elapsed", elapsed) }
                    check(restored.await(45, TimeUnit.SECONDS)) { "Host did not authenticate exact proxy restoration" }
                    check(abandonedCatalogue.get() > 0)
                    val cleaned = lease.stable()
                    check(cleaned.generation == before.generation && cleaned.identityEpoch == before.identityEpoch &&
                        cleaned.revision > before.revision && !cleaned.interactionBlocked &&
                        cleaned.topologyRevision == before.topologyRevision &&
                        cleaned.tasks.map { it.token }.toSet() == before.tasks.map { it.token }.toSet() &&
                        cleaned.displays.single().token == before.displays.single().token)
                    check(lease.events.revoked.isEmpty() && lease.events.results.isEmpty() && lease.events.commands.get() == 0L)
                    // Four-plus seconds already elapsed after admission: the
                    // shared one-second catalogue cadence must not be relaxed.
                    val fresh = checkNotNull(lease.session.launcherPage(before.generation, 0,
                        before.displays.single().token, 0)) { "Same session could not admit a fresh catalogue" }
                    check(fresh.generation == before.generation && fresh.catalogId > 0 &&
                        fresh.catalogId != abandonedCatalogue.get() && fresh.displayToken == before.displays.single().token &&
                        fresh.offset == 0 && fresh.totalEntries >= fresh.entries.size && fresh.expiresAt > SystemClock.elapsedRealtime())
                    lease.session.selectLauncher(before.generation, fresh.catalogId, -1)
                    val recovered = lease.stable()
                    check(recovered.generation == before.generation && recovered.identityEpoch == before.identityEpoch &&
                        recovered.revision > cleaned.revision && !recovered.interactionBlocked)
                    check(lease.events.revoked.isEmpty() && lease.events.results.isEmpty())
                    status("recovered", recovered) {
                        putLong("abandoned_catalogue", abandonedCatalogue.get()); putLong("fresh_catalogue", fresh.catalogId)
                    }
                    report.putString("evidence", JSONObject().put("before", NativeSecurityClient.proof(before))
                        .put("cleaned", NativeSecurityClient.proof(cleaned)).put("recovered", NativeSecurityClient.proof(recovered)).toString())
                    report.putLong("generation", before.generation); report.putLong("identity_epoch", before.identityEpoch)
                    report.putLong("display_token", before.displays.single().token); report.putLong("dispatch_elapsed", elapsed)
                    report.putLong("abandoned_catalogue", abandonedCatalogue.get()); report.putLong("fresh_catalogue", fresh.catalogId)
                }
            }
            report.putString("native_launcher_page_timeout", "passed")
            report.putString("scope", "v3_initial_launcher_page_after_picker_creation_2s_timeout_same_session_recovery")
            report.putString("replacement_before_cleanup", "not_tested")
            report.putString("proxy_restoration_observed", "true"); outcome = -1
        } catch (error: Throwable) {
            report.putString("native_launcher_page_timeout", "not_passed")
            report.putString("failure_details", error.stackTraceToString())
        } finally {
            try { if (registered) targetContext.unregisterReceiver(receiver) }
            catch (error: Throwable) {
                outcome = 0; report.putString("native_launcher_page_timeout", "not_passed")
                report.putString("cleanup_error", error.stackTraceToString())
            }
        }
        report.putInt("api", 3); report.putString("run", run)
        report.putInt("owner_uid", Process.myUid()); report.putInt("owner_pid", Process.myPid())
        report.putString("fingerprint", Build.FINGERPRINT); report.putString("native_abi", Build.SUPPORTED_ABIS.first())
        finish(outcome, report)
    }
}
