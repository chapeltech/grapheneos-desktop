package org.wonad.desktop.broker

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.Process
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.wonad.desktop.api.*

/** Actual Binder calls from the test APK's own unprivileged UID. No Shell identity. */
internal object BrokerBoundaryChecks {
    fun run(context: Context): Int {
        val uid = Process.myUid()
        check(uid % 100000 in 10000..19999 && context.packageName != "org.wonad.desktop")
        check(uid != context.packageManager.getPackageUid("org.wonad.desktop", 0))
        check(uid != context.packageManager.getPackageUid("com.android.systemui", 0))
        val connected = CountDownLatch(1)
        val binder = AtomicReference<IBinder?>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                binder.set(service); connected.countDown()
            }
            override fun onServiceDisconnected(name: ComponentName) { binder.set(null) }
            override fun onNullBinding(name: ComponentName) { connected.countDown() }
            override fun onBindingDied(name: ComponentName) { binder.set(null); connected.countDown() }
        }
        val bound = context.bindService(Intent("org.wonad.desktop.BIND").setComponent(ComponentName(
            "com.android.systemui", "org.wonad.desktop.broker.WonadBrokerService")), connection, Context.BIND_AUTO_CREATE)
        check(bound) { "Could not bind the actual OS broker" }
        try {
            check(connected.await(5, TimeUnit.SECONDS)) { "Timed out binding the OS broker" }
            val service = checkNotNull(binder.get()) { "OS broker returned no live Binder" }
            check(service.isBinderAlive && service.interfaceDescriptor == "org.wonad.desktop.api.IDesktopBroker")
            val broker = IDesktopBroker.Stub.asInterface(service)
            val callback = object : IDesktopCallback.Stub() {
                override fun onSnapshot(snapshot: DesktopSnapshot) { }
                override fun onCommand(
                    generation: Long,
                    command: Int,
                    argument: Int,
                    taskToken: Long,
                    displayToken: Long,
                ) { }
                override fun onResult(generation: Long, request: Long, result: Int, revision: Long) { }
                override fun onRevoked(generation: Long, reason: Int) { }
            }
            var denied = 0
            fun expectDenial(name: String, action: () -> Unit) {
                try { action(); error("Unauthorized call succeeded: $name") }
                catch (error: SecurityException) {
                    check(error.message == "Caller is not the Wonad package") { "Unexpected denial for $name: $error" }
                    denied++
                }
            }
            expectDenial("getApiVersion") { broker.apiVersion }
            expectDenial("getCapabilities") { broker.capabilities }
            expectDenial("openSession") { broker.openSession(DesktopProtocol.API_VERSION, callback) }
            return denied
        } finally { context.unbindService(connection) }
    }
}
