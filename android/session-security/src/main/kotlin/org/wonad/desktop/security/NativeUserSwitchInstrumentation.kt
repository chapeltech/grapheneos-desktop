package org.wonad.desktop.security

import android.app.Instrumentation
import android.app.KeyguardManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.os.UserManager
import java.util.concurrent.TimeUnit
import java.util.concurrent.CountDownLatch
import org.json.JSONArray
import org.json.JSONObject
import org.wonad.desktop.api.DesktopProtocol

/** API3 real-user probe. Only the isolated host creates/switches users and
 * gives ordinary per-user consent; this runner has no user-management power. */
class NativeUserSwitchInstrumentation : Instrumentation() {
    private lateinit var run: String
    private lateinit var mode: String
    private var expectedUser = -1
    private val frameObserved = CountDownLatch(1)
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        run = checkNotNull(arguments?.getString("run"))
        mode = checkNotNull(arguments.getString("mode"))
        expectedUser = checkNotNull(arguments.getString("user")).toInt()
        check(run.matches(Regex("[0-9a-f]{32}")) && mode in listOf("owner", "secondary", "disabled"))
        check(if (mode == "owner") expectedUser == 0 else expectedUser in 10..1000)
        start()
    }

    private fun status(phase: String, generation: Long, epoch: Long,
        snapshot: org.wonad.desktop.api.DesktopSnapshot? = null) = sendStatus(1, Bundle().apply {
        putString("run", run); putString("phase", phase); putInt("api", 3)
        putLong("generation", generation); putLong("identity_epoch", epoch)
        putInt("owner_uid", Process.myUid()); putInt("owner_pid", Process.myPid()); putInt("user", expectedUser)
        putString("mode", mode)
        snapshot?.let { putString("evidence", NativeSecurityClient.proof(it).toString()) }
    })

    override fun onStart() {
        val report = Bundle()
        var outcome = 0
        var registered = false
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (mode == "secondary" && intent.action == "org.wonad.desktop.test.NATIVE_USER_FRAME_OBSERVED" &&
                    intent.getStringExtra("run") == run) frameObserved.countDown()
            }
        }
        try {
            NativeSecurityClient.requireOwner(targetContext, expectedUser)
            val users = targetContext.getSystemService(UserManager::class.java)
            val keyguard = targetContext.getSystemService(KeyguardManager::class.java)
            check(users.isUserForeground && users.isUserUnlocked && !keyguard.isKeyguardLocked)
            if (mode == "secondary") {
                targetContext.registerReceiver(receiver,
                    IntentFilter("org.wonad.desktop.test.NATIVE_USER_FRAME_OBSERVED"), Context.RECEIVER_EXPORTED)
                registered = true
            }
            val evidence = JSONObject().put("api", 3).put("mode", mode).put("user", expectedUser)
            NativeSecurityClient.Bound(targetContext).use { binding ->
                val broker = binding.broker()
                if (mode == "disabled") {
                    report.putString("phase", "native_secondary_consent_disabled")
                    val denied = NativeSecurityClient.Events()
                    try {
                        broker.openSession(DesktopProtocol.API_VERSION, denied)
                        error("Inherited another Android user's external desktop consent")
                    } catch (error: IllegalStateException) {
                        check(error.message == NativeSecurityClient.ADMISSION_DENIED) { "Unexpected disabled admission: $error" }
                    }
                    Thread.sleep(750)
                    check(denied.empty() && users.isUserForeground && !keyguard.isKeyguardLocked)
                    report.putString("consent", "denied"); evidence.put("consent", "denied")
                } else if (mode == "secondary") {
                    report.putString("phase", "native_secondary_frame")
                    NativeSecurityClient.open(targetContext, broker).use { lease ->
                        val initial = lease.stable()
                        lease.apply(100, vertical = true)
                        val applied = lease.apply(101, signed = true)
                        check(users.isUserForeground)
                        report.putLong("generation", applied.generation); report.putLong("identity_epoch", applied.identityEpoch)
                        report.putString("owner_frame", "vertical_applied")
                        report.putString("owner_signed_frame", "applied")
                        evidence.put("before", NativeSecurityClient.proof(initial)).put("applied", NativeSecurityClient.proof(applied))
                            .put("owner_signed_frame", "applied")
                        // Hold this genuine lease while the host independently
                        // observes native bounds and injects ordinary mouse/key
                        // input into both actual secondary-user apps. A nonce
                        // acknowledgment cannot replace that host-side proof.
                        status("secondary_frame_applied", applied.generation, applied.identityEpoch, applied)
                        check(frameObserved.await(45, TimeUnit.SECONDS)) { "Host did not observe the live secondary native frame/input" }
                        check(users.isUserForeground && users.isUserUnlocked && !keyguard.isKeyguardLocked)
                        val observed = lease.stable()
                        check(observed.generation == applied.generation && observed.identityEpoch == applied.identityEpoch)
                        check(observed.tasks.map { it.token }.toSet() == applied.tasks.map { it.token }.toSet())
                        evidence.put("observed", NativeSecurityClient.proof(observed)).put("host_frame_observed", true)
                        report.putString("host_frame_observed", "true")
                    }
                } else {
                    report.putString("phase", "native_owner_hide")
                    lateinit var original: org.wonad.desktop.api.DesktopSnapshot
                    NativeSecurityClient.open(targetContext, broker).use { old ->
                        original = old.stable()
                        old.armShortcuts(original)
                        val hidden = old.apply(100, hidden = true)
                        report.putLong("old_generation", hidden.generation); report.putLong("identity_epoch", hidden.identityEpoch)
                        report.putString("hidden_frame", "applied")
                        evidence.put("before", NativeSecurityClient.proof(original)).put("hidden", NativeSecurityClient.proof(hidden))
                        status("ready_for_switch", hidden.generation, hidden.identityEpoch)
                        report.putString("phase", "native_await_secondary_user")
                        NativeSecurityClient.await(60000) { !users.isUserForeground }
                        val revoked = checkNotNull(old.events.revoked.poll(10, TimeUnit.SECONDS)) { "No native user-switch revocation" }
                        check(revoked == hidden.generation to DesktopProtocol.REVOKED_USER_CHANGED) { "Wrong native user revocation: $revoked" }
                        old.stopHeartbeat()
                        check(old.events.commands.get() == 0L && old.events.results.isEmpty())
                        val terminal = old.events.terminal()
                        report.putInt("revocation_reason", revoked.second); evidence.put("revocation_reason", revoked.second)
                        report.putString("phase", "native_inactive_owner_calls")
                        NativeSecurityClient.retainedCalls(old.session, hidden)
                        val denied = NativeSecurityClient.Events()
                        val methods = listOf("getApiVersion", "getCapabilities", "openSession")
                        val calls = listOf<() -> Unit>({ broker.apiVersion }, { broker.capabilities },
                            { broker.openSession(DesktopProtocol.API_VERSION, denied) })
                        calls.forEach { call ->
                            check(!users.isUserForeground)
                            try { call(); error("Inactive user retained native broker admission") }
                            catch (error: SecurityException) { check(error.message == "Caller is not the Wonad package") }
                        }
                        Thread.sleep(750)
                        check(!users.isUserForeground && denied.empty()); old.events.requireSilent(terminal)
                        report.putInt("retained_calls", NativeSecurityClient.METHODS.size); report.putInt("denied_methods", 3)
                        evidence.put("retained_methods", JSONArray(NativeSecurityClient.METHODS))
                            .put("denied_broker_methods", JSONArray(methods)).put("terminal_snapshots", terminal.first)
                            .put("shortcuts_armed", true)
                        status("inactive_calls_complete", hidden.generation, hidden.identityEpoch)
                        report.putString("phase", "native_await_owner_return")
                        NativeSecurityClient.await(180000) { users.isUserForeground && users.isUserUnlocked && !keyguard.isKeyguardLocked }
                        old.events.requireSilent(terminal)
                    }
                    report.putString("phase", "native_owner_reconnect")
                    NativeSecurityClient.open(targetContext, broker).use { lease ->
                        val ready = lease.stable()
                        NativeSecurityClient.continuity(original).requireRecovery(ready.generation, ready.identityEpoch, ready.tasks.map { it.token })
                        lease.apply(200, restore = original)
                        val applied = lease.apply(201, restore = original, signed = true)
                        check(users.isUserForeground)
                        NativeSecurityClient.continuity(original).requireRecovery(applied.generation, applied.identityEpoch, applied.tasks.map { it.token })
                        report.putLong("new_generation", applied.generation); report.putString("owner_frame", "applied")
                        report.putString("owner_signed_frame", "applied")
                        evidence.put("recovered", NativeSecurityClient.proof(applied)).put("owner_frame", "applied")
                            .put("owner_signed_frame", "applied")
                    }
                }
            }
            report.putString("native_user_switch", "passed"); report.putString("scope", "v3_active_user_consent_and_exact_task_isolation_signed_rpc")
            report.putInt("api", 3); report.putString("run", run); report.putString("mode", mode)
            report.putInt("owner_uid", Process.myUid()); report.putInt("owner_pid", Process.myPid()); report.putInt("user", expectedUser)
            report.putString("fingerprint", Build.FINGERPRINT); report.putString("native_abi", Build.SUPPORTED_ABIS.first())
            report.putString("evidence", evidence.toString()); outcome = -1
        } catch (error: Throwable) {
            report.putString("native_user_switch", "not_passed"); report.putString("failure_details", error.stackTraceToString())
        } finally {
            if (registered) try { targetContext.unregisterReceiver(receiver) }
            catch (error: Throwable) {
                outcome = 0; report.putString("native_user_switch", "not_passed")
                report.putString("cleanup_error", error.stackTraceToString())
            }
        }
        finish(outcome, report)
    }
}
