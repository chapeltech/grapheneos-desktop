package org.wonad.desktop.security

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.Process
import android.util.Base64
import java.io.File
import java.util.concurrent.atomic.AtomicLong
import org.json.JSONArray
import org.json.JSONObject
import org.wonad.desktop.api.*

/** TEST APK's ordinary foreign UID; no product shell model or UI launch. */
class NeutralMalformedCallerService : Service() {
    private val endpoint = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code != FIRST_CALL_TRANSACTION) return super.onTransact(code, data, reply, flags)
            data.enforceInterface(PROBE)
            val session = checkNotNull(data.readStrongBinder())
            val broker = IDesktopBroker.Stub.asInterface(checkNotNull(data.readStrongBinder()))
            val snapshot = checkNotNull(data.readTypedObject(DesktopSnapshot.CREATOR))
            val challenge = JSONObject(checkNotNull(data.readString()))
            data.enforceNoDataAvail()
            val caller = getCallingUid()
            check(caller in 10000..19999 && Process.myUid() in 10000..19999 && caller != Process.myUid())
            check(packageManager.getPackagesForUid(caller)?.toList() == listOf("org.wonad.desktop")) {
                "Neutral TEST probe requires exact ordinary conformance owner"
            }
            check(session.isBinderAlive && session.queryLocalInterface(SESSION) == null &&
                session.interfaceDescriptor == SESSION && snapshot.generation > 0 && snapshot.identityEpoch > 0 &&
                snapshot.displays.size == 3 && snapshot.tasks.size == 3 &&
                snapshot.tasks.all { it.packageName == "org.wonad.fixture" })
            check(challenge.keys().asSequence().toSet() == setOf("run", "nonce", "generation", "identity_epoch", "revision"))
            for (key in listOf("run", "nonce")) check(challenge.get(key) is String && Regex("[0-9a-f]{32}").matches(challenge.getString(key)))
            for ((key, expected) in listOf("generation" to snapshot.generation,
                "identity_epoch" to snapshot.identityEpoch, "revision" to snapshot.revision)) {
                check(challenge.get(key) is Int || challenge.get(key) is Long)
                check(expected > 0 && challenge.getLong(key) == expected)
            }
            val statBefore = File("/proc/self/stat").readText()
            val denied = JSONArray()
            for (name in METHODS) {
                // Generated public SDK AIDL transaction IDs, not hidden APIs.
                val field = IDesktopSession.Stub::class.java.getDeclaredField("TRANSACTION_$name")
                field.isAccessible = true
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
                        else -> error("Unpacked neutral method $name")
                    }
                    check(session.transact(field.getInt(null), request, response, 0))
                    val error = try { response.readException(); null } catch (error: SecurityException) { error }
                    checkNotNull(error) { "Foreign session call accepted: $name" }
                    check(error.message == "Caller is not the Wonad package")
                    denied.put(JSONObject().put("method", name).put("exception", error.javaClass.name).put("message", error.message))
                } finally { request.recycle(); response.recycle() }
            }
            val snapshots = AtomicLong(); val commands = AtomicLong(); val results = AtomicLong(); val revoked = AtomicLong()
            val callbacks = object : IDesktopCallback.Stub() {
                override fun onSnapshot(snapshot: DesktopSnapshot) { snapshots.incrementAndGet() }
                override fun onCommand(generation: Long, command: Int, argument: Int, taskToken: Long, displayToken: Long) { commands.incrementAndGet() }
                override fun onResult(generation: Long, requestId: Long, result: Int, revision: Long) { results.incrementAndGet() }
                override fun onRevoked(generation: Long, reason: Int) { revoked.incrementAndGet() }
            }
            val brokerDenied = JSONArray()
            for ((name, call) in listOf<Pair<String, () -> Unit>>(
                "getApiVersion" to { broker.apiVersion; Unit }, "getCapabilities" to { broker.capabilities; Unit },
                "openSession" to { broker.openSession(DesktopProtocol.API_VERSION, callbacks); Unit })) {
                val error = try { call(); null } catch (error: SecurityException) { error }
                checkNotNull(error) { "Foreign broker call accepted: $name" }
                check(error.message == "Caller is not the Wonad package")
                brokerDenied.put(JSONObject().put("method", name).put("exception", error.javaClass.name).put("message", error.message))
            }
            android.os.SystemClock.sleep(250)
            check(snapshots.get() == 0L && commands.get() == 0L && results.get() == 0L && revoked.get() == 0L)
            val proof = JSONObject().put("schema", 1).put("caller_uid", caller)
                .put("challenge", JSONObject(challenge.toString()))
                .put("uid", Process.myUid()).put("pid", Process.myPid())
                .put("proc_stat_before_b64", Base64.encodeToString(statBefore.toByteArray(Charsets.UTF_8), Base64.NO_WRAP))
                .put("proc_stat_after_b64", Base64.encodeToString(File("/proc/self/stat").readBytes(), Base64.NO_WRAP))
                .put("denied_session", denied).put("denied_broker", brokerDenied)
                .put("callbacks", JSONObject().put("onSnapshot", snapshots.get()).put("onCommand", commands.get())
                    .put("onResult", results.get()).put("onRevoked", revoked.get()))
            checkNotNull(reply).apply { writeNoException(); writeString(proof.toString()) }
            return true
        }
    }
    override fun onBind(intent: Intent): IBinder = endpoint
    companion object {
        const val PROBE = "org.wonad.desktop.security.NeutralMalformedProbe"
        private const val SESSION = "org.wonad.desktop.api.IDesktopSession"
        val METHODS = listOf("applyFrame", "focusTask", "closeTask", "enableShortcuts", "heartbeat", "release",
            "enableExternalUi", "showShell", "launcherPage", "showLauncher", "selectLauncher", "showTransferPicker", "applySignedFrame")
    }
}
