package com.android.server.wm

import android.content.ComponentName
import android.content.pm.ActivityInfo
import android.content.pm.PackageManager
import android.os.Process
import android.os.UserHandle
import android.view.Display
import android.view.WindowManager
import com.android.internal.util.ToBooleanFunction
import java.util.function.Consumer

/** WM-lock-only boundary for Shell's actual fullscreen wallpaper Activity.
 * This is not TYPE_WALLPAPER, an intent/attrs package-name filter, or general
 * application policy. The sticky native attachment also covers parked owners.
 */
internal object WonadNativeWallpapers {
    private const val PACKAGE = "com.android.systemui"
    private val component = ComponentName(PACKAGE,
        "com.android.wm.shell.desktopmode.DesktopWallpaperActivity")
    private data class Scope(val dc: DisplayContent, val user: Int)

    private fun scope(dc: DisplayContent): Scope? {
        val wm = dc.mWmService
        if (dc.displayId <= Display.DEFAULT_DISPLAY ||
            wm.mRoot.getDisplayContent(dc.displayId) !== dc ||
            !WonadUiBridge.nativeMode(dc)) return null
        val user = wm.mCurrentUserId
        // UserController advances before WMS.prepareUserStart updates this
        // cached user. Reject the handoff interval, as the other native leases do.
        if (wm.mAmInternal.currentUserId != user ||
            wm.mRoot.getDisplayContent(dc.displayId) !== dc ||
            !WonadUiBridge.nativeMode(dc)) return null
        return Scope(dc, user)
    }

    private fun current(expected: Scope): Boolean = scope(expected.dc) == expected

    private fun wallpaper(activity: ActivityRecord, expected: Scope): Boolean {
        val user = activity.mUserId
        // Shell declares this exact Activity showForAllUsers. Its primary-user
        // instance can therefore remain visible while a secondary user owns a
        // parked native attachment. No unrelated foreign-user record qualifies.
        if (user < 0 || (user != expected.user &&
                activity.info.flags and ActivityInfo.FLAG_SHOW_FOR_ALL_USERS == 0) ||
            activity.mActivityComponent != component || activity.packageName != PACKAGE ||
            activity.info.packageName != PACKAGE || activity.info.name != component.className ||
            activity.info.applicationInfo.packageName != PACKAGE ||
            !activity.info.applicationInfo.isSystemApp || !activity.info.applicationInfo.isPrivilegedApp)
            return false
        val uid = try {
            expected.dc.mWmService.mContext.packageManager.getPackageUidAsUser(PACKAGE, user)
        } catch (_: PackageManager.NameNotFoundException) { return false }
        // Re-resolve the real Activity user's UID, not the current user's UID
        // or a cached numeric appId; PM can race user/package/display changes.
        return uid >= 0 && UserHandle.getUserId(uid) == user && activity.mUserId == user &&
            activity.uid == uid && activity.info.applicationInfo.uid == uid && current(expected)
    }

    /** Runs after actual launch-params resolution and before task mutation.
     * The record's PM-resolved ActivityInfo is authority, never Intent extras.
     */
    @JvmStatic fun rejectsLaunch(area: TaskDisplayArea?, activity: ActivityRecord?): Boolean {
        if (area == null || activity == null || !area.isAttached) return false
        val dc = area.displayContent ?: return false
        val expected = scope(dc) ?: return false
        return wallpaper(activity, expected) && area.displayContent === dc &&
            area.isAttached && current(expected)
    }

    /** Cached Activity tokens must not recreate a window after takeover. The
     * WMS hook is inside its application-token branch, after token validation.
     */
    @JvmStatic fun rejectsWindow(dc: DisplayContent, activity: ActivityRecord?): Boolean {
        if (activity == null) return false
        val expected = scope(dc) ?: return false
        return wallpaper(activity, expected) && activity.isAttached &&
            activity.displayContent === dc && current(expected)
    }

    private fun retirement(task: Task, activity: ActivityRecord, expected: Scope): Boolean {
        if (!current(expected) || !wallpaper(activity, expected) || !task.isAttached ||
            !activity.isAttached || task.displayContent !== expected.dc ||
            activity.displayContent !== expected.dc || task.mUserId != activity.mUserId ||
            task.mCreatedByOrganizer || task.effectiveUid != activity.uid ||
            !task.isActivityTypeStandard || !task.isLeafTask || task.childCount != 1 ||
            task.getChildAt(0) !== activity || activity.parent !== task || activity.task !== task)
            return false
        // Do not destroy an IME/protected/foreign window even if a corrupted
        // task tree places one below the otherwise exact wallpaper record.
        val foreignWindow = activity.forAllWindows(ToBooleanFunction { window ->
            window.mActivityRecord !== activity || window.displayContent !== expected.dc ||
                window.baseType !in WindowManager.LayoutParams.FIRST_APPLICATION_WINDOW..
                    WindowManager.LayoutParams.LAST_APPLICATION_WINDOW ||
                (window.owningUid != activity.uid &&
                    !(window.baseType == WindowManager.LayoutParams.TYPE_APPLICATION_STARTING &&
                        window.owningUid == Process.SYSTEM_UID))
        }, true)
        return !foreignWindow && wallpaper(activity, expected) && current(expected)
    }

    /** DesktopWallpaperActivity is singleInstancePerTask. Retire only its
     * exact solitary leaf, using stock synchronous Task removal: the real
     * Activity, windows, input channels and task sink are destroyed, rather
     * than left hidden behind a cover or an asynchronous closing transition.
     */
    @JvmStatic fun retire(dc: DisplayContent) {
        val expected = scope(dc) ?: return
        val stock = mutableListOf<Pair<Task, ActivityRecord>>()
        dc.forAllActivities(Consumer { activity ->
            val task = activity.task
            if (task != null && retirement(task, activity, expected)) stock.add(task to activity)
        }, true)
        stock.forEach { (task, activity) ->
            // Removal callbacks may change subsequent records/attachments.
            if (retirement(task, activity, expected))
                task.removeImmediately("wonad-native-stock-wallpaper")
        }
    }
}
