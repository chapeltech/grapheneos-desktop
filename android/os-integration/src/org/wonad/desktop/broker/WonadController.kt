package org.wonad.desktop.broker

import android.app.ActivityManager
import android.app.KeyguardManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.database.ContentObserver
import android.os.Binder
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.UserHandle
import android.provider.Settings
import android.util.Log
import android.view.SurfaceControl
import android.view.WindowManagerGlobal
import com.android.wm.shell.ShellTaskOrganizer
import com.android.wm.shell.common.DisplayController
import com.android.wm.shell.common.ShellExecutor
import com.android.wm.shell.dagger.WMSingleton
import com.android.wm.shell.shared.annotations.ShellMainThread
import com.android.wm.shell.sysui.KeyguardChangeListener
import com.android.wm.shell.sysui.ShellController
import com.android.wm.shell.sysui.UserChangeListener
import java.security.MessageDigest
import java.security.SecureRandom
import javax.inject.Inject
import org.wonad.desktop.api.DesktopProtocol
import org.wonad.desktop.api.IDesktopBroker
import org.wonad.desktop.api.IDesktopCallback
import org.wonad.desktop.api.IDesktopSession

/** Sole API3 broker entry point. Desktop policy and workspace semantics stay in
 * the independently updatable APK; this class authenticates the fixed client
 * and delegates only workspace-free observations and scalar frame requests. */
@WMSingleton
class WonadController @Inject constructor(
    private val context: Context,
    @ShellMainThread private val executor: ShellExecutor,
    private val organizer: ShellTaskOrganizer,
    private val displays: DisplayController,
    private val shell: ShellController,
) : ShellTaskOrganizer.TaskAppearedListener, ShellTaskOrganizer.TaskInfoChangedListener,
    ShellTaskOrganizer.TaskVanishedListener, DisplayController.OnDisplaysChangedListener,
    KeyguardChangeListener, UserChangeListener {
    companion object {
        const val PACKAGE = "org.wonad.desktop"
        const val ENABLED_SETTING = "wonad_external_desktop_enabled"
        const val BIND_ACTION = "org.wonad.desktop.BIND"
        private const val TAG = "WonadBroker"
        @Volatile var instance: WonadController? = null
            private set
    }

    private data class Identity(val uid: Int, val user: Int, val signer: ByteArray)
    private var ready = false
    private var shortcutAvailable = false
    private var apiAvailable = false
    private var signedPlacementAvailable = false
    private val keys = context.getSystemService(KeyguardManager::class.java)
    private val power = context.getSystemService(PowerManager::class.java)

    private val desktop by lazy {
        NativeDesktopController(context, executor, organizer, displays,
            identity = { uid -> identity(uid)?.let {
                NativeDesktopController.Identity(it.uid, it.user, it.signer) } },
            retainedIdentity = { uid, user -> identityForUser(uid, user)?.let {
                NativeDesktopController.Identity(it.uid, it.user, it.signer) } },
            enabled = { user -> enabled(user) },
            locked = { locked() },
            activeUser = { ActivityManager.getCurrentUser() },
            operational = { ready && apiAvailable &&
                shell.currentUserId == ActivityManager.getCurrentUser() },
            shortcutAvailable = { shortcutAvailable },
            signedPlacementAvailable = { signedPlacementAvailable },
            authorized = { uid -> checkAuthorized(uid) })
    }

    private val supervisor by lazy { WonadClientSupervisor(context, executor,
        eligible = { user -> ready && apiAvailable && shell.currentUserId == user &&
            enabled(user) && !locked() && desktop.hasEligibleDisplaysForLifecycle() },
        authorized = { uid, user -> identityForUser(uid, user)?.signer?.let {
            it.joinToString("") { byte -> "%02x".format(byte.toInt() and 255) }
                .equals(WonadSigning.SHA256, ignoreCase = true) } == true }) }

    private fun reconcileClient() {
        try { desktop.reconcile() } finally { supervisor.reconcile() }
    }

    private val observer = object : ContentObserver(Handler(Looper.getMainLooper())) {
        override fun onChange(selfChange: Boolean) { executor.execute { guarded { reconcileClient() } } }
    }

    private val watchdog = object : Runnable {
        override fun run() {
            guarded { reconcileClient() }
            executor.executeDelayed(this, 500)
        }
    }

    /** Called once by WMComponent after Shell initialization. */
    fun initialize() = executor.execute {
        if (instance != null) return@execute
        ready = try {
            val digest = WonadSigning.SHA256.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            BrokerNative.initialize(digest, (SecureRandom().nextLong() and 0x3fffffffffffffffL) + 1)
        } catch (error: Exception) {
            Log.e(TAG, "Broker remains disabled: native initialization failed", error); false
        } catch (error: LinkageError) {
            Log.e(TAG, "Broker remains disabled: native library unavailable", error); false
        }
        shortcutAvailable = try {
            WindowManagerGlobal.getWindowManagerService()
                ?.setWonadShortcutLease(-1, -1, 0, 0, null) == true
        } catch (error: Throwable) {
            if (error !is Exception && error !is LinkageError) throw error
            Log.e(TAG, "External shortcuts unavailable", error); false
        }
        apiAvailable = ready && try {
            check(checkNotNull(WindowManagerGlobal.getWindowManagerService())
                .getWonadNativeDisplayState(intArrayOf()).isEmpty())
            check(BrokerNative.nativeValidateFrame(longArrayOf(), longArrayOf()) ==
                DesktopProtocol.RESULT_INVALID)
            true
        } catch (error: Exception) {
            Log.e(TAG, "Desktop API unavailable", error); false
        } catch (error: LinkageError) {
            Log.e(TAG, "Desktop decision library unavailable", error); false
        }
        signedPlacementAvailable = apiAvailable && try {
            check(BrokerNative.nativeValidateSignedFrame(longArrayOf(), longArrayOf()) ==
                DesktopProtocol.RESULT_INVALID)
            check(!checkNotNull(WindowManagerGlobal.getWindowManagerService()).applyWonadNativeSignedFrame(
                -1, 0, null, emptyArray(), intArrayOf(), longArrayOf(), longArrayOf()))
            true
        } catch (error: Exception) {
            Log.e(TAG, "Signed placement capability unavailable", error); false
        } catch (error: LinkageError) {
            Log.e(TAG, "Signed placement decision library unavailable", error); false
        }
        instance = this
        organizer.addTaskAppearedListener(this)
        organizer.addTaskInfoChangedListener(this)
        organizer.addTaskVanishedListener(this)
        displays.addDisplayWindowListener(this)
        shell.addUserChangeListener(this)
        shell.addKeyguardChangeListener(this)
        context.contentResolver.registerContentObserver(Settings.Secure.getUriFor(ENABLED_SETTING),
            false, observer, UserHandle.USER_ALL)
        executor.executeDelayed(watchdog, 500)
    }

    private fun identity(uid: Int): Identity? {
        val user = UserHandle.getUserId(uid)
        return if (user != ActivityManager.getCurrentUser()) null else identityForUser(uid, user)
    }

    /** Resolve an already-authenticated callback owner in its original user.
     * Unlike ordinary admission this intentionally survives active-user change
     * so the timeout path can release the old Binder sender without ever
     * killing a UID whose sole package or signer has changed. */
    private fun identityForUser(uid: Int, user: Int): Identity? = try {
        if (UserHandle.getAppId(uid) !in 10000..19999 || UserHandle.getUserId(uid) != user) null
        else {
            val pm = context.createContextAsUser(UserHandle.of(user), 0).packageManager
            val names = pm.getPackagesForUid(uid)
            if (names == null || names.size != 1 || names[0] != PACKAGE) null
            else {
                val info = pm.getPackageInfo(PACKAGE, PackageManager.GET_SIGNING_CERTIFICATES)
                val signing = info.signingInfo
                val current = signing?.apkContentsSigners
                val history = signing?.signingCertificateHistory
                if (info.applicationInfo?.uid != uid || info.sharedUserId != null || signing == null ||
                    signing.hasMultipleSigners() || current == null || current.size != 1 ||
                    history == null || history.size != 1 || history.single() != current.single()) null
                else Identity(uid, user, MessageDigest.getInstance("SHA-256")
                    .digest(current.single().toByteArray()))
            }
        }
    } catch (_: PackageManager.NameNotFoundException) { null }

    private fun enabled(user: Int = ActivityManager.getCurrentUser()): Boolean =
        Settings.Secure.getIntForUser(context.contentResolver, ENABLED_SETTING, 0, user) == 1

    private fun locked(): Boolean = keys.isKeyguardLocked || keys.isDeviceLocked || !power.isInteractive

    private fun checkAuthorized(uid: Int) {
        val who = identity(uid) ?: throw SecurityException("Caller is not the Wonad package")
        val actual = who.signer.joinToString("") { "%02x".format(it.toInt() and 255) }
        if (!actual.equals(WonadSigning.SHA256, ignoreCase = true))
            throw SecurityException("Wonad signer not allowed")
    }

    /** Defense in depth for the known-signer consent alias: the permission pins
     * the certificate, while this also pins the active user's sole package/UID.
     */
    internal fun isAuthorizedClient(uid: Int): Boolean = try {
        checkAuthorized(uid)
        true
    } catch (_: SecurityException) { false }

    val binder: IDesktopBroker.Stub = object : IDesktopBroker.Stub() {
        override fun getApiVersion(): Int {
            checkAuthorized(Binder.getCallingUid())
            return DesktopProtocol.API_VERSION
        }

        override fun getCapabilities(): Long {
            checkAuthorized(Binder.getCallingUid())
            return if (apiAvailable) desktop.capabilities else 0L
        }

        override fun openSession(version: Int, callback: IDesktopCallback?): IDesktopSession {
            val uid = Binder.getCallingUid()
            // Authenticate at the Binder boundary before version/callback
            // validation or any broker/session state is observed. The serial
            // operation authenticates again immediately before acting.
            checkAuthorized(uid)
            return desktop.open(uid, version, callback)
        }
    }

    /** Launcher3 is authenticated independently at the trusted Recents Binder boundary. */
    fun trustedRecentsCaller(uid: Int): Boolean = try {
        val user = UserHandle.getUserId(uid)
        val pm = context.createContextAsUser(UserHandle.of(user), 0).packageManager
        val packages = pm.getPackagesForUid(uid)
        user == ActivityManager.getCurrentUser() && packages != null &&
            packages.size == 1 && packages[0] == "com.android.launcher3" &&
            pm.getApplicationInfo("com.android.launcher3", 0).uid == uid
    } catch (_: PackageManager.NameNotFoundException) { false }

    fun canTransferFromRecents(taskId: Int, user: Int, lastActive: Long,
        baseActivity: ComponentName?, taskToken: IBinder?): Boolean =
        desktop.canTransferFromRecents(taskId, user, lastActive, baseActivity, taskToken)

    fun transferFromRecents(taskId: Int, user: Int, lastActive: Long,
        baseActivity: ComponentName?, taskToken: IBinder?): Boolean =
        desktop.transferFromRecents(taskId, user, lastActive, baseActivity, taskToken)

    private fun changed() = executor.execute { guarded { reconcileClient(); desktop.changed() } }

    private fun guarded(action: () -> Unit) {
        try { action() } catch (error: Exception) {
            Log.e(TAG, "Desktop broker reconciliation failed closed", error)
            desktop.revoke(DesktopProtocol.REVOKED_CLIENT_FAILED)
        } catch (error: LinkageError) {
            Log.e(TAG, "Desktop bridge unavailable", error)
            desktop.revoke(DesktopProtocol.REVOKED_CLIENT_FAILED)
        }
    }

    override fun onTaskAppeared(taskInfo: ActivityManager.RunningTaskInfo, leash: SurfaceControl) = changed()
    override fun onTaskInfoChanged(taskInfo: ActivityManager.RunningTaskInfo) = changed()
    override fun onTaskVanished(taskInfo: ActivityManager.RunningTaskInfo) = changed()
    override fun onDisplayAdded(displayId: Int) = changed()
    override fun onDisplayRemoved(displayId: Int) = changed()
    override fun onDisplayConfigurationChanged(displayId: Int, config: android.content.res.Configuration) = changed()

    override fun onKeyguardVisibilityChanged(visible: Boolean, occluded: Boolean,
        animatingDismiss: Boolean) = executor.execute { guarded {
        if (visible) desktop.revoke(DesktopProtocol.REVOKED_LOCKED)
        reconcileClient()
    } }

    override fun onUserChanged(newUserId: Int, userContext: Context) = executor.execute {
        guarded { reconcileClient() }
    }
}
