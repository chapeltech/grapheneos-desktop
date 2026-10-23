package org.wonad.desktop.security

import android.app.Instrumentation
import android.app.KeyguardManager
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.os.Process
import java.util.concurrent.TimeUnit
import org.json.JSONObject
import org.wonad.desktop.api.DesktopProtocol

/** API3 credential-lock probe. The host alone supplies actual phone lock/PIN
 * input on fresh isolated userdata. This APK never receives the credential,
 * configures lock state, dismisses Keyguard or adopts another identity. */
class NativeLockedSessionInstrumentation : Instrumentation() {
    private lateinit var run: String
    private lateinit var trigger: String
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        run = checkNotNull(arguments?.getString("run"))
        trigger = checkNotNull(arguments.getString("trigger"))
        check(run.matches(Regex("[0-9a-f]{32}")) && trigger in listOf("sleep", "lock-key"))
        start()
    }

    private fun status(phase: String, generation: Long, epoch: Long) = sendStatus(1, Bundle().apply {
        putString("run", run); putString("phase", phase); putInt("api", 3)
        putLong("generation", generation); putLong("identity_epoch", epoch)
        putInt("owner_uid", Process.myUid()); putInt("owner_pid", Process.myPid()); putInt("user", 0)
        putString("trigger", trigger)
    })

    override fun onStart() {
        val report = Bundle()
        var outcome = 0
        try {
            NativeSecurityClient.requireOwner(targetContext, 0)
            val keyguard = targetContext.getSystemService(KeyguardManager::class.java)
            val power = targetContext.getSystemService(PowerManager::class.java)
            check(keyguard.isDeviceSecure && !keyguard.isDeviceLocked && !keyguard.isKeyguardLocked)
            val evidence = JSONObject().put("api", 3).put("trigger", trigger)
            NativeSecurityClient.Bound(targetContext).use { binding ->
                val broker = binding.broker()
                report.putString("phase", "native_open_original")
                lateinit var before: org.wonad.desktop.api.DesktopSnapshot
                NativeSecurityClient.open(targetContext, broker).use { old ->
                    before = old.stable()
                    check(before.tasks.all { it.visible && it.inputEnabled }) { "Credential probe needs visible native fixtures" }
                    old.armShortcuts(before)
                    evidence.put("before", NativeSecurityClient.proof(before))
                    report.putLong("old_generation", before.generation); report.putLong("identity_epoch", before.identityEpoch)
                    status("ready_for_lock", before.generation, before.identityEpoch)
                    report.putString("phase", "await_real_credential_lock")
                    NativeSecurityClient.await(60000) { keyguard.isKeyguardLocked && keyguard.isDeviceLocked && power.isInteractive }
                    check(keyguard.isDeviceSecure)
                    val revoked = checkNotNull(old.events.revoked.poll(10, TimeUnit.SECONDS)) { "No native lock revocation" }
                    check(revoked.first == before.generation && revoked.second in listOf(
                        DesktopProtocol.REVOKED_UNDOCKED, DesktopProtocol.REVOKED_LOCKED)) { "Wrong native lock reason: $revoked" }
                    if (trigger == "lock-key") check(revoked.second == DesktopProtocol.REVOKED_LOCKED) {
                        "Lock-only probe cannot pass through display sleep"
                    }
                    old.stopHeartbeat()
                    check(old.events.commands.get() == 0L && old.events.results.isEmpty())
                    val terminal = old.events.terminal()
                    evidence.put("revocation_reason", revoked.second).put("terminal_snapshots", terminal.first)
                    report.putInt("revocation_reason", revoked.second)
                    report.putString("phase", "native_locked_retained_calls")
                    NativeSecurityClient.retainedCalls(old.session, before)
                    repeat(3) {
                        check(keyguard.isDeviceSecure && keyguard.isKeyguardLocked && keyguard.isDeviceLocked && power.isInteractive)
                        NativeSecurityClient.requireApi(broker)
                        val denied = NativeSecurityClient.Events()
                        try {
                            broker.openSession(DesktopProtocol.API_VERSION, denied)
                            error("Native session admitted while credential-locked")
                        } catch (error: IllegalStateException) {
                            check(error.message == NativeSecurityClient.ADMISSION_DENIED) { "Unexpected locked admission: $error" }
                        }
                        Thread.sleep(750)
                        check(denied.empty()); old.events.requireSilent(terminal)
                    }
                    report.putInt("retained_calls", NativeSecurityClient.METHODS.size); report.putInt("denied_opens", 3)
                    evidence.put("retained_methods", org.json.JSONArray(NativeSecurityClient.METHODS)).put("denied_opens", 3)
                        .put("shortcuts_armed", true)
                    status("locked_calls_complete", before.generation, before.identityEpoch)
                    report.putString("phase", "await_actual_pin_unlock")
                    NativeSecurityClient.await(60000) { !keyguard.isKeyguardLocked && !keyguard.isDeviceLocked }
                    check(keyguard.isDeviceSecure) { "Credential was removed instead of authenticated" }
                    old.events.requireSilent(terminal)
                }
                report.putString("phase", "native_reconnect_after_unlock")
                NativeSecurityClient.open(targetContext, broker).use { fresh ->
                    val ready = fresh.stable()
                    NativeSecurityClient.continuity(before).requireRecovery(ready.generation, ready.identityEpoch, ready.tasks.map { it.token })
                    fresh.apply(100, restore = before)
                    val applied = fresh.apply(101, restore = before, signed = true)
                    NativeSecurityClient.continuity(before).requireRecovery(applied.generation, applied.identityEpoch, applied.tasks.map { it.token })
                    report.putLong("new_generation", applied.generation); report.putString("owner_frame", "applied")
                    report.putString("owner_signed_frame", "applied")
                    evidence.put("recovered", NativeSecurityClient.proof(applied)).put("owner_frame", "applied")
                        .put("owner_signed_frame", "applied")
                }
            }
            report.putString("native_locked_session", "passed")
            report.putString("scope", "v3_credential_lock_retained_session_reject_reconnect_signed_rpc")
            report.putInt("api", 3); report.putString("run", run); report.putString("trigger", trigger)
            report.putInt("owner_uid", Process.myUid()); report.putInt("owner_pid", Process.myPid()); report.putInt("user", 0)
            report.putString("fingerprint", Build.FINGERPRINT); report.putString("native_abi", Build.SUPPORTED_ABIS.first())
            report.putString("evidence", evidence.toString()); outcome = -1
        } catch (error: Throwable) {
            report.putString("native_locked_session", "not_passed"); report.putString("failure_details", error.stackTraceToString())
        }
        finish(outcome, report)
    }
}
