package com.android.server.wm

import android.app.ActivityOptions
import android.content.ComponentName
import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.pm.PackageManager
import android.os.UserHandle

/** Private proposal only. WM lock held. Resolve real launch metadata without
 * restoring a Task, constructing an ActivityRecord, consuming a token, or
 * invoking ActivityStarter. This is a denial boundary, never launch authority.
 */
internal object WonadNativeWallpaperLaunches {
    private const val PACKAGE = "com.android.systemui"
    private val component = ComponentName(PACKAGE,
        "com.android.wm.shell.desktopmode.DesktopWallpaperActivity")

    @JvmStatic fun rejects(parent: WindowContainer<*>, info: ActivityInfo, user: Int): Boolean {
        if (!parent.isAttached) return false
        val dc = parent.displayContent ?: return false
        val wm = dc.mWmService
        val currentUser = wm.mCurrentUserId
        if (dc.displayId <= 0 || wm.mRoot.getDisplayContent(dc.displayId) !== dc ||
            !WonadUiBridge.nativeMode(dc) || user < 0 ||
            (user != currentUser && info.flags and ActivityInfo.FLAG_SHOW_FOR_ALL_USERS == 0) ||
            info.packageName != component.packageName || info.name != component.className ||
            info.applicationInfo.packageName != PACKAGE || !info.applicationInfo.isSystemApp ||
            !info.applicationInfo.isPrivilegedApp) return false
        val uid = try { wm.mContext.packageManager.getPackageUidAsUser(PACKAGE, user) }
            catch (_: PackageManager.NameNotFoundException) { return false }
        return uid >= 0 && UserHandle.getUserId(uid) == user && info.applicationInfo.uid == uid &&
            parent.isAttached && parent.displayContent === dc && wm.mCurrentUserId == currentUser &&
            wm.mRoot.getDisplayContent(dc.displayId) === dc && WonadUiBridge.nativeMode(dc) &&
            info.packageName == PACKAGE && info.name == component.className &&
            info.applicationInfo.packageName == PACKAGE && info.applicationInfo.isSystemApp &&
            info.applicationInfo.isPrivilegedApp &&
            (user == currentUser || info.flags and ActivityInfo.FLAG_SHOW_FOR_ALL_USERS != 0)
    }

    /** Read-only projection of RootWindowContainer.getOrCreateRootTask's
     * null-Activity recents routing. Root/TDA tokens are native objects, not
     * intent extras. Do not call the default anyTaskForId RESTORE overload.
     */
    private fun recentParent(supervisor: ActivityTaskSupervisor, task: Task,
            options: ActivityOptions?): WindowContainer<*> {
        val root = supervisor.mRootWindowContainer
        options?.launchRootTask?.let { token ->
            val target = WindowContainer.fromBinder(token.asBinder())?.asTask()
            val area = target?.taskDisplayArea
            if (target != null && target.isAttached && area != null &&
                !area.shouldKeepNoTask()) return target
        }
        if (options != null && options.launchTaskId != -1) {
            val candidate = root.anyTaskForId(options.launchTaskId,
                RootWindowContainer.MATCH_ATTACHED_TASK_OR_RECENT_TASKS)
            if (candidate != null) {
                // The stock routine temporarily removes this ID before its
                // recursive restore. Mutate ONLY a private options copy.
                val copy = requireNotNull(ActivityOptions.fromBundle(options.toBundle()))
                copy.launchTaskId = -1
                return recentParent(supervisor, candidate, copy)
            }
        }
        options?.launchTaskDisplayArea?.let { token ->
            val area = WindowContainer.fromBinder(token.asBinder())?.asTaskDisplayArea()
            if (area != null) return area
        }
        if (options != null) root.getDisplayContent(options.launchDisplayId)?.let {
            return it.defaultTaskDisplayArea
        }
        task.rootTask?.displayArea?.let { return it }
        // Actual restoreRecentTaskLocked passes no launchParams/source. An
        // unattached recent task without explicit routing goes to the phone.
        return root.defaultTaskDisplayArea
    }

    @JvmStatic fun addRecent(routes: WonadNativeWallpaperRoutes.Transaction,
            supervisor: ActivityTaskSupervisor, task: Task, options: ActivityOptions?,
            callerPid: Int, callerUid: Int) {
        val parent = recentParent(supervisor, task, options)
        routes.add(task, parent)
        addTaskMetadata(routes, supervisor, task, parent, callerPid, callerUid)
    }

    @JvmStatic fun addTaskMetadata(routes: WonadNativeWallpaperRoutes.Transaction,
            supervisor: ActivityTaskSupervisor, task: Task, parent: WindowContainer<*>,
            callerPid: Int, callerUid: Int) {
        val original = task.intent ?: return
        val user = task.mUserId
        val copy = Intent(original)
        val resolved = supervisor.resolveIntent(copy,
            copy.resolveTypeIfNeeded(supervisor.mService.mContext.contentResolver),
            user, 0, callerUid, callerPid)?.activityInfo ?: return
        if (task.intent !== original || task.mUserId != user || !copy.filterEquals(original))
            throw IllegalStateException("Recent launch metadata changed during preflight")
        routes.addLaunch(resolved, user, parent)
    }

    /** Direct attach/reparent of an empty saved Wallpaper task must not bypass
     * the Activity traversal. The saved component only narrows PM work; it is
     * never authority. PM still resolves/authenticates the actual Activity.
     */
    @JvmStatic fun addSavedTask(routes: WonadNativeWallpaperRoutes.Transaction,
            task: Task, parent: WindowContainer<*>) {
        if (task.realActivity != component && task.intent?.component != component) return
        addTaskMetadata(routes, task.mTaskSupervisor, task, parent, -1, task.mCallingUid)
    }

    @JvmStatic fun addFragment(routes: WonadNativeWallpaperRoutes.Transaction,
            supervisor: ActivityTaskSupervisor, parent: WindowContainer<*>, intent: Intent,
            options: ActivityOptions?, caller: ActivityRecord?, callerUid: Int, callerPid: Int) {
        val user = caller?.mUserId ?: supervisor.mService.currentUserId
        val copy = Intent(intent)
        val info = supervisor.resolveIntent(copy,
            copy.resolveTypeIfNeeded(supervisor.mService.mContext.contentResolver),
            user, 0, callerUid, callerPid)?.activityInfo ?: return
        routes.addLaunch(info, user, parent)
        // Same actual LaunchParamsUtil options/source/process/phone fallback;
        // no fake ActivityRecord and no layout/create/restore operation.
        val request = ActivityStarter.Request().also {
            it.activityInfo = info; it.callingUid = callerUid; it.callingPid = callerPid
            it.realCallingUid = callerUid; it.realCallingPid = callerPid
        }
        val area = LaunchParamsUtil.getPreferredLaunchTaskDisplayArea(supervisor,
            null, options, caller, null, null, request) { }
        routes.addLaunch(info, user, area)
    }

    @JvmStatic fun enforceRecent(supervisor: ActivityTaskSupervisor, task: Task,
            options: ActivityOptions?, callerPid: Int, callerUid: Int) {
        val routes = WonadNativeWallpaperRoutes.Transaction()
        addRecent(routes, supervisor, task, options, callerPid, callerUid)
        routes.enforce()
    }
}
