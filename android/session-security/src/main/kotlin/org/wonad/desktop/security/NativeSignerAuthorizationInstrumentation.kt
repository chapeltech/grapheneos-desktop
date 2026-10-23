package org.wonad.desktop.security

import android.app.Instrumentation
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.os.Process
import android.os.SystemClock
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.wonad.desktop.api.DesktopProtocol
import org.wonad.desktop.api.IDesktopBroker
import org.wonad.desktop.api.IDesktopCallback
import org.wonad.desktop.api.DesktopSnapshot

/** Actual API3 Binder probes from the expected package with a wrong certificate.
 * The host must use fresh owned userdata, verify signature-only APK changes,
 * and independently inspect black/input isolation and trusted-client recovery.
 * This instrumentation does not adopt identities, grant permissions, change
 * the OS signer pin, or claim a complete wrong-signer gate by itself.
 */
class NativeSignerAuthorizationInstrumentation : Instrumentation() {
    private lateinit var arguments: Bundle

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        this.arguments = Bundle(checkNotNull(arguments))
        start()
    }

    override fun onStart() {
        val report = Bundle()
        val ready = CountDownLatch(1)
        val remote = AtomicReference<IBinder?>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                remote.set(service); ready.countDown()
            }
            override fun onServiceDisconnected(name: ComponentName) { remote.set(null) }
            override fun onNullBinding(name: ComponentName) { ready.countDown() }
            override fun onBindingDied(name: ComponentName) { remote.set(null); ready.countDown() }
        }
        var bound = false
        var result = 0
        try {
            val run = checkNotNull(arguments.getString("run"))
            val trusted = checkNotNull(arguments.getString("trusted_signer"))
            val expected = checkNotNull(arguments.getString("expected_signer"))
            val uid = Process.myUid()
            NativeSignerAuthorizationSpec.requireArguments(run, uid, trusted, expected)
            check(DesktopProtocol.API_VERSION == NativeSignerAuthorizationSpec.API)
            check(targetContext.packageName == NativeSignerAuthorizationSpec.PACKAGE &&
                targetContext.applicationInfo.uid == uid)
            check(targetContext.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0)
            val pm = targetContext.packageManager
            check(pm.getPackagesForUid(uid)?.toList() == listOf(NativeSignerAuthorizationSpec.PACKAGE))
            val info = pm.getPackageInfo(NativeSignerAuthorizationSpec.PACKAGE,
                PackageManager.GET_SIGNING_CERTIFICATES)
            val signing = checkNotNull(info.signingInfo)
            check(!signing.hasMultipleSigners() && signing.apkContentsSigners.size == 1)
            val actual = MessageDigest.getInstance("SHA-256")
                .digest(signing.apkContentsSigners.single().toByteArray())
                .joinToString("") { "%02x".format(it.toInt() and 255) }
            check(actual == expected && actual != trusted) {
                "Installed expected package does not have the exact untrusted certificate"
            }

            report.putString("phase", "bind_native_broker")
            bound = targetContext.bindService(Intent("org.wonad.desktop.BIND").setComponent(ComponentName(
                "com.android.systemui", "org.wonad.desktop.broker.WonadBrokerService")),
                connection, Context.BIND_AUTO_CREATE)
            check(bound && ready.await(5, TimeUnit.SECONDS)) { "Native broker binding failed or timed out" }
            val binder = checkNotNull(remote.get())
            check(binder.isBinderAlive && binder.queryLocalInterface("org.wonad.desktop.api.IDesktopBroker") == null)
            check(binder.interfaceDescriptor == "org.wonad.desktop.api.IDesktopBroker")
            val broker = IDesktopBroker.Stub.asInterface(binder)
            val callbacks = AtomicInteger()
            val callback = object : IDesktopCallback.Stub() {
                override fun onSnapshot(value: DesktopSnapshot) { callbacks.incrementAndGet() }
                override fun onCommand(generation: Long, command: Int, argument: Int,
                    taskToken: Long, displayToken: Long) { callbacks.incrementAndGet() }
                override fun onResult(generation: Long, requestId: Long, value: Int, revision: Long) {
                    callbacks.incrementAndGet()
                }
                override fun onRevoked(generation: Long, reason: Int) { callbacks.incrementAndGet() }
            }
            val probes: List<Pair<String, () -> Unit>> = listOf(
                "getApiVersion" to { broker.apiVersion; Unit },
                "getCapabilities" to { broker.capabilities; Unit },
                "openSession" to {
                    broker.openSession(DesktopProtocol.API_VERSION, callback); Unit
                },
            )
            check(probes.map { it.first } == NativeSignerAuthorizationSpec.METHODS)
            val denied = mutableListOf<String>()
            for ((method, probe) in probes) {
                report.putString("phase", method)
                try {
                    probe()
                    error("Untrusted signer was accepted by native API3: $method")
                } catch (denial: SecurityException) {
                    check(denial.message == NativeSignerAuthorizationSpec.DENIAL) {
                        "Wrong native signer denial for $method: $denial"
                    }
                    denied.add(method)
                }
            }
            repeat(10) {
                check(callbacks.get() == 0 && remote.get() === binder && binder.isBinderAlive) {
                    "Unauthorized API3 call produced a callback or replaced the actual broker"
                }
                SystemClock.sleep(200)
            }
            report.putString("native_wrong_signer", "passed")
            report.putInt("api", NativeSignerAuthorizationSpec.API)
            report.putString("scope", NativeSignerAuthorizationSpec.SCOPE)
            report.putString("run", run)
            report.putString("package", NativeSignerAuthorizationSpec.PACKAGE)
            report.putInt("owner_uid", uid)
            report.putInt("owner_pid", Process.myPid())
            report.putLong("version_code", info.longVersionCode)
            report.putString("signer", actual)
            report.putString("trusted_signer", trusted)
            report.putString("denied_methods", denied.joinToString(","))
            report.putString("denial", NativeSignerAuthorizationSpec.DENIAL)
            report.putInt("callbacks", callbacks.get())
            report.putString("fingerprint", Build.FINGERPRINT)
            report.putString("native_abi", Build.SUPPORTED_ABIS.first())
            result = -1
        } catch (error: Throwable) {
            report.putString("native_wrong_signer", "not_passed")
            report.putString("failure_details", error.stackTraceToString())
        } finally {
            try {
                if (bound) targetContext.unbindService(connection)
            } catch (error: Throwable) {
                result = 0
                report.putString("native_wrong_signer", "not_passed")
                report.putString("cleanup_error", error.stackTraceToString())
            }
        }
        finish(result, report)
    }
}
