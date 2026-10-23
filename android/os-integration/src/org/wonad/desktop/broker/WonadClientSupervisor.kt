package org.wonad.desktop.broker

import android.app.ActivityManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.ApplicationInfo
import android.os.IBinder
import android.os.SystemClock
import android.os.UserHandle
import android.os.UserManager
import android.util.Log
import com.android.wm.shell.common.ShellExecutor

/** Starts only the authenticated enabled user's ordinary APK. Native desktop
 * admission remains independently enforced by the unchanged API3 broker. */
internal class WonadClientSupervisor(
    private val context: Context,
    private val executor: ShellExecutor,
    private val eligible: (Int) -> Boolean,
    private val authorized: (Int, Int) -> Boolean,
) {
    companion object {
        private const val TAG = "WonadSupervisor"
        private const val ACTION = "org.wonad.desktop.SUPERVISE"
        private const val PERMISSION = "android.permission.STATUS_BAR_SERVICE"
        private val COMPONENT = ComponentName(WonadController.PACKAGE, "org.wonad.desktop.DesktopService")
    }
    private data class Target(val user: Int, val uid: Int, val version: Long, val updated: Long)
    private val retry = DesktopSupervisionPolicy()
    private var connection: ServiceConnection? = null
    private var target: Target? = null
    private var connected = false
    private var bindingDeadline = 0L
    private var lastStatus = ""

    private fun report(message: String) {
        if (message != lastStatus) { lastStatus = message; Log.i(TAG, message) }
    }

    private fun resolve(user: Int): Target? {
        val userContext = context.createContextAsUser(UserHandle.of(user), 0)
        if (!userContext.getSystemService(UserManager::class.java).isUserUnlocked) return null
        val pm = userContext.packageManager
        val app = pm.getApplicationInfo(WonadController.PACKAGE, 0)
        // Never defeat explicit Android Force stop, suspension, or disabling.
        if (!app.enabled || app.flags and (ApplicationInfo.FLAG_STOPPED or ApplicationInfo.FLAG_SUSPENDED) != 0 ||
            !authorized(app.uid, user)) return null
        val service = pm.getServiceInfo(COMPONENT, 0)
        if (!service.enabled || !service.exported || service.permission != PERMISSION ||
            service.applicationInfo.uid != app.uid) return null
        val pkg = pm.getPackageInfo(WonadController.PACKAGE, 0)
        return Target(user, app.uid, pkg.longVersionCode, pkg.lastUpdateTime)
    }

    private fun release(stop: Boolean) {
        val old = connection
        val owner = target
        connection = null; target = null; connected = false; bindingDeadline = 0
        if (old != null) runCatching { context.unbindService(old) }
        if (stop && owner != null) runCatching {
            // A delayed stop must not affect a replacement package/UID.
            if (resolve(owner.user) == owner)
                context.stopServiceAsUser(Intent(ACTION).setComponent(COMPONENT), UserHandle.of(owner.user))
        }
    }

    private fun failed(owner: ServiceConnection, message: String) {
        if (connection !== owner) return
        release(false)
        val delay = retry.failed(SystemClock.elapsedRealtime())
        report("$message; retry in ${delay}ms")
    }

    /** All calls and callbacks are serialized on Shell's executor. */
    fun reconcile() {
        val now = SystemClock.elapsedRealtime()
        val user = ActivityManager.getCurrentUser()
        val desired = try { if (eligible(user)) resolve(user) else null }
            catch (_: Exception) { null }
        if (desired == null) {
            release(true); retry.reset()
            report("Idle: disabled, locked, no eligible display, or client unavailable")
            return
        }
        if (target != null && target != desired) { release(false); retry.reset() }
        val current = connection
        if (current != null) {
            if (!connected && now >= bindingDeadline) failed(current, "Client binding timed out")
            else if (connected) retry.healthy(now)
            return
        }
        if (!retry.mayStart(now)) return
        val attempt = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                executor.execute {
                    if (connection !== this) return@execute
                    connected = true; retry.connected(SystemClock.elapsedRealtime())
                    report("Supervising user=${desired.user} uid=${desired.uid} version=${desired.version}")
                }
            }
            override fun onServiceDisconnected(name: ComponentName) = executor.execute {
                failed(this, "Client process disconnected")
            }
            override fun onBindingDied(name: ComponentName) = executor.execute {
                failed(this, "Client binding died")
            }
            override fun onNullBinding(name: ComponentName) = executor.execute {
                failed(this, "Client does not support OS supervision")
            }
        }
        target = desired; connection = attempt; bindingDeadline = now + 15_000
        try {
            if (!context.bindServiceAsUser(Intent(ACTION).setComponent(COMPONENT), attempt,
                    Context.BIND_AUTO_CREATE or Context.BIND_IMPORTANT, UserHandle.of(user)))
                failed(attempt, "Client binding declined")
        } catch (_: Exception) { failed(attempt, "Client binding unavailable") }
    }
}
