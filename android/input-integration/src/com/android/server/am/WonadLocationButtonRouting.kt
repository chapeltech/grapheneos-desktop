package com.android.server.am

import android.app.ActivityManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManagerInternal
import android.os.Build
import android.os.Process
import android.os.RemoteCallback
import android.os.UserHandle
import android.permission.flags.Flags
import com.android.server.pm.KnownPackages.PACKAGE_PERMISSION_CONTROLLER

/** Native final-field PendingIntent provenance, not a Binder API or app-provided authority.
 * Kept in AM's package to inspect its private-to-package creator/key without exposing handles.
 * ActivityStarter must first check the exact live native source under WM's global lock.
 */
internal object WonadLocationButtonRouting {
    private const val ACTIVITY =
        "com.android.permissioncontroller.permission.ui.v37.RequestLocationButtonPermissionsActivity"
    private const val ACTION = "android.app.permissionui.action.REQUEST_LOCATION_BUTTON_PERMISSIONS"
    private const val REQUIRED_FLAGS = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_ONE_SHOT

    @JvmStatic fun shouldRouteToPhone(pending: PendingIntentRecord?, info: ActivityInfo?,
        launch: Intent?, sourceUid: Int, sourceUser: Int, sourcePackage: String?,
        realCallingUid: Int, launchedFromUid: Int, pm: PackageManagerInternal): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.CINNAMON_BUN || !Flags.locationButtonEnabled()
            || pending == null || info == null || launch == null || sourcePackage.isNullOrEmpty()
            || sourceUser < 0 || sourceUid < 0 || UserHandle.getUserId(sourceUid) != sourceUser
            || realCallingUid != sourceUid || launchedFromUid != pending.uid
            || info.name != ACTIVITY || info.targetActivity != null || launch.action != ACTION) return false
        val app = info.applicationInfo ?: return false
        if (app.flags and ApplicationInfo.FLAG_SYSTEM == 0 || UserHandle.getUserId(app.uid) != sourceUser) return false
        val controllers = pm.getKnownPackageNames(PACKAGE_PERMISSION_CONTROLLER, sourceUser)
        if (controllers.size != 1 || controllers[0] != info.packageName || launch.`package` != controllers[0]
            || pm.getPackageUid(controllers[0], 0, sourceUser) != app.uid) return false

        // The real producer is fixed SystemUI (system user), even for a context-as-user request.
        val systemUi = pm.systemUiServiceComponent?.packageName ?: return false
        val creatorUid = pm.getPackageUid(systemUi, 0, UserHandle.USER_SYSTEM)
        val creator = pm.getApplicationInfo(systemUi, 0, Process.SYSTEM_UID, UserHandle.USER_SYSTEM)
            ?: return false
        if (creatorUid < 0 || creatorUid != pending.uid || creator.uid != creatorUid
            || creator.flags and ApplicationInfo.FLAG_SYSTEM == 0) return false
        val key = pending.key
        if (key.packageName != systemUi || key.userId != sourceUser
            || key.type != ActivityManager.INTENT_SENDER_ACTIVITY
            || key.flags and REQUIRED_FLAGS != REQUIRED_FLAGS || key.allIntents?.size != 1
            || key.activity != null || key.who != null || key.requestCode != 0) return false
        // A one-shot PI is already marked canceled as it is sent. Do not reinterpret that
        // mutable flag as rejection or acquire AM's PI lock while holding the native WM lock.
        val original = key.requestIntent ?: return false
        if (original.action != ACTION || original.`package` != controllers[0]
            || original.component?.let { it.packageName != controllers[0] || it.className != ACTIVITY } == true
            || original.flags != 0
            || launch.flags and (Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NEW_DOCUMENT
                or Intent.FLAG_ACTIVITY_FORWARD_RESULT or Intent.FLAG_ACTIVITY_LAUNCH_ADJACENT
                or Intent.FLAG_ACTIVITY_CLEAR_TASK) != 0) return false
        return try {
            val target = original.getStringExtra(Intent.EXTRA_PACKAGE_NAME)
            if (target != sourcePackage || launch.getStringExtra(Intent.EXTRA_PACKAGE_NAME) != target
                || pm.getPackageUid(target, 0, sourceUser) != sourceUid) return false
            val originalCallback = original.getParcelableExtra(Intent.EXTRA_REMOTE_CALLBACK, RemoteCallback::class.java)
                ?: return false
            val actualCallback = launch.getParcelableExtra(Intent.EXTRA_REMOTE_CALLBACK, RemoteCallback::class.java)
                ?: return false
            originalCallback.getInterface().asBinder() == actualCallback.getInterface().asBinder()
        } catch (_: RuntimeException) {
            // Malformed lazy extras never establish trusted UI provenance.
            false
        }
    }
}
