package org.wonad.desktop.security

import android.app.Service
import android.content.ComponentName
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.Process
import org.wonad.desktop.api.*

/** Real foreign-UID v3 probes. This service lives only in the separately
 * installed test APK; no production permission or test endpoint is added.
 */
class NativeAttackService : Service() {
    private val endpoint = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code != FIRST_CALL_TRANSACTION) return super.onTransact(code, data, reply, flags)
            data.enforceInterface(PROBE)
            val session = checkNotNull(data.readStrongBinder())
            val broker = IDesktopBroker.Stub.asInterface(checkNotNull(data.readStrongBinder()))
            val snapshot = checkNotNull(data.readTypedObject(DesktopSnapshot.CREATOR))
            data.enforceNoDataAvail()
            val caller = getCallingUid()
            check(caller != Process.myUid() && Process.myUid() in 10000..19999)
            check(session.isBinderAlive && session.queryLocalInterface(SESSION) == null &&
                session.interfaceDescriptor == SESSION && snapshot.generation > 0 && snapshot.identityEpoch > 0 &&
                snapshot.displays.isNotEmpty() && snapshot.tasks.size == 2)
            val denied = mutableListOf<String>()
            for (name in METHODS) {
                val field = IDesktopSession.Stub::class.java.getDeclaredField("TRANSACTION_$name")
                field.isAccessible = true // Our generated AIDL, not an Android hidden API.
                val request = Parcel.obtain(); val response = Parcel.obtain()
                try {
                    request.writeInterfaceToken(SESSION); request.writeLong(snapshot.generation)
                    when (name) {
                        "applyFrame", "applySignedFrame" -> {
                            request.writeLong(1); request.writeLong(snapshot.revision)
                            request.writeTypedObject(null as DesktopFrame?, 0)
                        }
                        "focusTask", "closeTask" -> {
                            request.writeLong(1); request.writeLong(snapshot.revision); request.writeLong(snapshot.tasks.first().token)
                        }
                        "enableShortcuts" -> request.writeBoolean(true)
                        "heartbeat" -> request.writeLong(1)
                        "release", "enableExternalUi" -> Unit
                        "showShell", "showTransferPicker" -> request.writeLong(snapshot.displays.first().token)
                        "launcherPage" -> { request.writeLong(0); request.writeLong(snapshot.displays.first().token); request.writeInt(0) }
                        "showLauncher" -> request.writeLong(1)
                        "selectLauncher" -> { request.writeLong(1); request.writeInt(0) }
                        else -> error("Unpacked native method $name")
                    }
                    check(session.transact(field.getInt(null), request, response, 0)) { "Unknown native transaction $name" }
                    try {
                        response.readException(); error("Foreign native session call was accepted: $name")
                    } catch (denial: SecurityException) {
                        // Session calls authenticate the live package/signer
                        // before consulting ownership, generation or arguments.
                        check(denial.message == "Caller is not the Wonad package") { "Wrong native denial: $name $denial" }
                        denied.add(name)
                    }
                } finally { request.recycle(); response.recycle() }
            }
            val brokerDenied = mutableListOf<String>()
            val callback = object : IDesktopCallback.Stub() {
                override fun onSnapshot(snapshot: DesktopSnapshot) = Unit
                override fun onCommand(generation: Long, command: Int, argument: Int, taskToken: Long, displayToken: Long) = Unit
                override fun onResult(generation: Long, requestId: Long, result: Int, revision: Long) = Unit
                override fun onRevoked(generation: Long, reason: Int) = Unit
            }
            for ((name, action) in listOf<Pair<String, () -> Unit>>(
                "getApiVersion" to { broker.apiVersion; Unit },
                "getCapabilities" to { broker.capabilities; Unit },
                "openSession" to { broker.openSession(DesktopProtocol.API_VERSION, callback); Unit })) {
                try { action(); error("Foreign broker call was accepted: $name") }
                catch (denial: SecurityException) {
                    check(denial.message == "Caller is not the Wonad package") { "Wrong broker denial: $name $denial" }
                    brokerDenied.add(name)
                }
            }
            val uiDenied = mutableListOf<String>()
            val guardedUi = listOf(
                Triple("ExternalHomeActivity", "org.wonad.desktop",
                    "android.permission.STATUS_BAR_SERVICE"),
                Triple("ExternalShellActivity", "org.wonad.desktop",
                    "android.permission.STATUS_BAR_SERVICE"),
                Triple("LauncherActivity", "org.wonad.desktop",
                    "android.permission.STATUS_BAR_SERVICE"),
                Triple("WonadClientSettingsActivity", "com.android.systemui",
                    "org.wonad.desktop.permission.OPEN_OS_SETTINGS"),
                Triple("WonadSettingsActivity", "com.android.systemui", "android.permission.DUMP"))
            for ((name, pkg, permission) in guardedUi) {
                val className = if (pkg == "org.wonad.desktop") "org.wonad.desktop.$name"
                    else "org.wonad.desktop.broker.$name"
                try {
                    startActivity(Intent().setComponent(ComponentName(pkg, className))
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK).putExtra("org.wonad.desktop.shell.GENERATION", snapshot.generation)
                        .putExtra("org.wonad.desktop.shell.DISPLAY_TOKEN", snapshot.displays.first().token))
                    error("Foreign protected-UI Activity start was accepted: $name")
                } catch (denial: SecurityException) {
                    check(denial.message?.contains(permission) == true) {
                        "Wrong protected-UI denial: $name $denial" }
                    uiDenied.add(name)
                }
            }
            checkNotNull(reply).apply {
                writeNoException(); writeInt(Process.myUid()); writeInt(Process.myPid()); writeInt(caller)
                writeStringList(denied); writeStringList(brokerDenied); writeStringList(uiDenied)
            }
            return true
        }
    }
    override fun onBind(intent: Intent): IBinder = endpoint

    companion object {
        const val PROBE = "org.wonad.desktop.security.NativeSessionProbe"
        private const val SESSION = "org.wonad.desktop.api.IDesktopSession"
        val METHODS = listOf("applyFrame", "focusTask", "closeTask", "enableShortcuts", "heartbeat", "release",
            "enableExternalUi", "showShell", "launcherPage", "showLauncher", "selectLauncher", "showTransferPicker",
            "applySignedFrame")
    }
}
