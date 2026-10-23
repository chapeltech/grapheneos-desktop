package com.android.server.wm

import android.app.ActivityManager
import android.app.WindowConfiguration.WINDOWING_MODE_FREEFORM
import android.graphics.Rect
import android.os.Binder
import android.os.IBinder
import android.os.SystemClock
import android.os.UserHandle
import android.provider.Settings
import android.util.Log
import android.view.Display

/** Android object glue, under the WM global lock. No APK can register a lease.
 *
 * Stock task ordering remains authoritative for drawing and pointer targeting.
 * Only focus selection among the explicitly leased external leaf tasks differs:
 * raising a tile can focus it without raising it above an always-on-top float.
 * The same selection feeds Android's top-resumed lifecycle, not just TaskInfo.
 */
internal object WonadFocusBridge {
    private const val MAX_TASKS = 128
    private const val MAX_LEASE_MILLIS = 5000L
    private class Owner(val generation: Long, val user: Int, val display: Int,
        var expires: Long, val binder: IBinder, var tasks: Set<IBinder>) {
        val originalAlwaysOnTop = mutableMapOf<IBinder, Boolean>()
        lateinit var death: IBinder.DeathRecipient
        lateinit var timeout: Runnable
    }
    private val owners = mutableMapOf<Int, Owner>()
    // Binder death callbacks may arrive in either order. Keep at most the last
    // nine dead display leases until their native organizers are disposed.
    // This grants no input/focus authority and never resolves numeric task IDs.
    private val departed = mutableMapOf<Int, Owner>()

    /** Empty desktop clicks need not produce a Shell transition. Read the same
     * display selected by native input, not FocusTransitionObserver's cache.
     * This observes a scalar only; it neither changes focus nor grants a lease.
     */
    @JvmStatic fun focusedDisplay(wm: WindowManagerService): Int {
        val context = wm.mContext
        context.enforceCallingPermission("android.permission.STATUS_BAR_SERVICE", "Wonad focus observation")
        if (Binder.getCallingUid() != context.packageManager.getPackageUidAsUser("com.android.systemui", UserHandle.USER_SYSTEM)) {
            throw SecurityException("Focus observation is SystemUI-only")
        }
        val callingIdentity = Binder.clearCallingIdentity()
        return try {
            wm.withWonadGlobalLock { wm.mRoot.topFocusedDisplayContent.displayId }
        } finally { Binder.restoreCallingIdentity(callingIdentity) }
    }

    private fun displayEligible(wm: WindowManagerService, display: Int, user: Int): Boolean {
        val dc = wm.mRoot.getDisplayContent(display) ?: return false
        val info = dc.displayInfo
        return display > 0 && wm.mCurrentUserId == user && wm.mAtmService.mAmInternal.currentUserId == user &&
            !wm.mPolicy.isKeyguardLocked && !wm.mPolicy.isKeyguardShowing && !dc.isSleeping &&
            wm.mAtmService.lockTaskController.lockTaskModeState == ActivityManager.LOCK_TASK_MODE_NONE &&
            info.state == Display.STATE_ON && info.flags and Display.FLAG_TRUSTED != 0 &&
            info.flags and Display.FLAG_PRIVATE == 0 && info.flags and Display.FLAG_SECURE != 0 &&
            Settings.Secure.getIntForUser(wm.mContext.contentResolver,
                "wonad_external_desktop_enabled", 0, user) == 1 &&
            (info.type == Display.TYPE_EXTERNAL || info.type == Display.TYPE_VIRTUAL)
    }

    private fun live(wm: WindowManagerService, display: Int): Owner? = owners[display]?.takeIf {
        it.binder.isBinderAlive && SystemClock.elapsedRealtime() < it.expires &&
            displayEligible(wm, it.display, it.user)
    }

    private fun managed(task: Task, lease: Owner, visible: Boolean = true): Boolean {
        if (!task.isAttached || !task.isLeafTask || !task.isActivityTypeStandard ||
            !task.inFreeformWindowingMode() || task.mUserId != lease.user || task.displayId != lease.display ||
            task.mRemoteToken?.toWindowContainerToken()?.asBinder() !in lease.tasks) return false
        val activity = task.topRunningActivity() ?: return false
        return UserHandle.getUserId(activity.uid) == lease.user && UserHandle.getAppId(activity.uid) in 10000..19999 &&
            activity.packageName !in setOf("android", "com.android.systemui", "com.android.permissioncontroller") &&
            (!visible || (task.isVisible && !task.isForceHidden && task.isFocusable && activity.isVisibleRequested))
    }

    private fun clear(wm: WindowManagerService, expected: Owner) {
        if (owners[expected.display] !== expected) return
        if (!expected.binder.isBinderAlive) {
            if (expected.display !in departed && departed.size >= 9) departed.remove(departed.keys.first())
            departed[expected.display] = expected
        }
        owners.remove(expected.display)
        val failures = WonadCleanupFailures()
        failures.attempt { wm.mH.removeCallbacks(expected.timeout) }
        failures.attempt { expected.binder.unlinkToDeath(expected.death, 0) }
        failures.attempt {
            wm.updateFocusedWindowLocked(WindowManagerService.UPDATE_FOCUS_NORMAL, true)
        }
        failures.attempt {
            wm.mAtmService.mTaskSupervisor.updateTopResumedActivityIfNeeded("wonad-focus-release")
        }
        failures.supportedFailure?.let {
            Log.e("WonadFocus", "Focus lease cleanup completed with failures", it)
        }
        failures.rethrowFatal()
    }

    /** Original Binder identity must still be present. Task handles never reach the APK. */
    @JvmStatic fun setLease(wm: WindowManagerService, display: Int, user: Int, generation: Long,
        expires: Long, tasks: Array<IBinder>?, binder: IBinder?): Boolean {
        val context = wm.mContext
        context.enforceCallingPermission("android.permission.STATUS_BAR_SERVICE", "Wonad focus lease")
        if (Binder.getCallingUid() != context.packageManager.getPackageUidAsUser("com.android.systemui", UserHandle.USER_SYSTEM)) {
            throw SecurityException("Focus registration is SystemUI-only")
        }
        val enabled = binder == null || Settings.Secure.getIntForUser(context.contentResolver,
            "wonad_external_desktop_enabled", 0, user) == 1
        val callingIdentity = Binder.clearCallingIdentity()
        return try {
            // Android's locked-region priority injector understands javac monitor
            // regions, not Kotlin's. Keep acquisition in the tiny Java wrapper.
            wm.withWonadGlobalLock { setLeaseLocked(wm, display, user, generation, expires, tasks, binder, enabled) }
        } finally { Binder.restoreCallingIdentity(callingIdentity) }
    }

    private fun setLeaseLocked(wm: WindowManagerService, display: Int, user: Int, generation: Long,
        expires: Long, tasks: Array<IBinder>?, binder: IBinder?, enabled: Boolean): Boolean {
        if (binder == null) {
            owners[display]?.let { if (it.generation == generation) clear(wm, it) }
            return true // generation=0 is an availability probe, not a revocation.
        }
        val now = SystemClock.elapsedRealtime()
        if (!enabled || !binder.isBinderAlive || generation <= 0 || expires <= now ||
            expires - now > MAX_LEASE_MILLIS ||
            tasks == null || tasks.size > MAX_TASKS || tasks.toSet().size != tasks.size ||
            !displayEligible(wm, display, user)) return false
        // Death delivery is asynchronous and Handler posting can be delayed or
        // rejected. A dead owner has no authority and cannot block replacement.
        owners.values.toList().forEach { if (!it.binder.isBinderAlive || now >= it.expires) clear(wm, it) }
        if (display !in owners && owners.size >= 9) return false
        if (owners.values.any { it.generation != generation || it.user != user || it.binder != binder }) return false
        val owner = owners[display]
        owner?.let {
            if (it.generation != generation || it.user != user || it.display != display || it.binder != binder) return false
        }
        // A stale organizer callback can name a vanished task. Resolve actual Binder
        // objects under the lock; never adopt a recycled integer task ID instead.
        val proposed = Owner(generation, user, display, expires, binder, tasks.toSet())
        val accepted = proposed.tasks.filter { token ->
            val task = (token as? WindowContainer.RemoteToken)?.container?.asTask()
            task != null && managed(task, proposed, visible = false)
        }.toSet()
        val next = owner ?: proposed
        next.originalAlwaysOnTop.keys.retainAll(accepted)
        for (token in accepted) {
            val task = (token as WindowContainer.RemoteToken).container?.asTask() ?: continue
            next.originalAlwaysOnTop.putIfAbsent(token, task.configuration.windowConfiguration.isAlwaysOnTop)
        }
        next.tasks = accepted
        next.expires = expires
        if (owner == null) {
            next.death = IBinder.DeathRecipient { wm.mH.post { wm.withWonadGlobalLock { clear(wm, next) } } }
            next.timeout = Runnable { wm.withWonadGlobalLock {
                if (owners[display] === next && SystemClock.elapsedRealtime() >= next.expires) clear(wm, next)
            } }
            owners[display] = next
            departed.remove(display)
            try { binder.linkToDeath(next.death, 0) }
            catch (error: Throwable) {
                val cleanup = WonadCleanupFailures()
                cleanup.attempt { clear(wm, next) }
                cleanup.rethrowFatal(error)
                return false
            }
        }
        wm.mH.removeCallbacks(next.timeout)
        wm.mH.postDelayed(next.timeout, expires - now)
        return true
    }

    /** Called under WM's global lock, before a dead organizer destroys its roots.
     * Only exact app objects from its dead Wonad lease can escape those roots.
     * Phone, protected, foreign-user/display and organizer-created tasks are
     * never selected. Ordinary organizer unregistering keeps stock behavior.
     */
    @JvmStatic fun onOrganizerDisposing(wm: WindowManagerService, organizer: IBinder, uid: Int) {
        if (organizer.isBinderAlive || uid != wm.mContext.packageManager.getPackageUidAsUser(
                "com.android.systemui", UserHandle.USER_SYSTEM)) return
        val candidates = (owners.values + departed.values).distinct().filter { !it.binder.isBinderAlive }
        for (lease in candidates) {
            val tasks = lease.tasks.mapNotNull { token ->
                val task = (token as? WindowContainer.RemoteToken)?.container?.asTask() ?: return@mapNotNull null
                if (!managed(task, lease, visible = false) || task.mCreatedByOrganizer) return@mapNotNull null
                val root = task.rootTask ?: return@mapNotNull null
                if (!root.mCreatedByOrganizer || root.mTaskOrganizer?.asBinder() != organizer) return@mapNotNull null
                token to task
            }
            if (tasks.isEmpty()) continue // Another organizer's death cannot consume this recovery.
            // Invalidate special focus first, including when organizer death
            // wins the race against the focus Binder's queued death callback.
            clear(wm, lease)
            if (departed[lease.display] === lease) departed.remove(lease.display)
            var preserved = 0
            for ((token, task) in tasks) {
                val area = task.displayArea ?: continue
                val rectangle = Rect(task.configuration.windowConfiguration.bounds)
                task.setFocusable(true)
                task.setAlwaysOnTop(lease.originalAlwaysOnTop[token] ?: false)
                task.setWindowingMode(WINDOWING_MODE_FREEFORM)
                // Native root placement on the SAME display. Do not raise the
                // display above the phone or transfer tasks across users.
                task.reparent(area, true)
                task.setBounds(rectangle)
                preserved++
            }
            Log.i("WonadFocus", "Preserved $preserved native tasks after SystemUI organizer death")
        }
    }

    /** Preserve the original raise direction when AOT clamping gives index zero.
     * WindowContainer otherwise treats that adjusted child position as a request
     * to send the entire parent branch (including the display) to the bottom.
     * Only the already-requested ancestor raise is performed here; the caller
     * still uses Android's adjusted position for the leaf's drawing order.
     */
    @JvmStatic fun propagateTaskPosition(parent: Task, child: WindowContainer<*>, toTop: Boolean,
        includingParents: Boolean): Boolean {
        if (!toTop || !includingParents) return includingParents
        val lease = live(parent.mWmService, parent.displayId) ?: return includingParents
        val task = child.asTask() ?: return includingParents
        if (!managed(task, lease)) return includingParents
        // The actual parent owns this Task; its generic child type is erased by
        // Java's raw getParent() API, not supplied by a Binder caller.
        @Suppress("UNCHECKED_CAST")
        val ancestor = parent.parent as? WindowContainer<WindowContainer<*>>
        ancestor?.positionChildAt(WindowContainer.POSITION_TOP, parent, true)
        return false
    }

    /** Called after ordinary hierarchy movement selects a managed leaf. */
    @JvmStatic fun onTaskRaised(parent: Task, child: WindowContainer<*>, toTop: Boolean, includingParents: Boolean) {
        if (!toTop || !includingParents) return
        val wm = parent.mWmService
        val lease = live(wm, parent.displayId) ?: return
        val task = child.asTask() ?: return
        if (!managed(task, lease)) return
        val activity = task.topRunningActivity() ?: return
        if (!activity.windowsAreFocusable()) return
        task.displayContent.setFocusedApp(activity)
        wm.updateFocusedWindowLocked(WindowManagerService.UPDATE_FOCUS_NORMAL, true)
        wm.mAtmService.mTaskSupervisor.updateTopResumedActivityIfNeeded("wonad-task-focus")
    }

    /** Reconcile lifecycle only after InputDispatcher confirms actual focus.
     * A restored Activity can become focusedApp before its window is visible;
     * that early event is not sufficient to deliver top-resumed lifecycle.
     * This callback runs under the existing WM global lock, outside the task
     * resume pass. It neither chooses focus nor synthesizes app callbacks.
     */
    @JvmStatic fun onInputFocusChanged(wm: WindowManagerService, target: InputTarget?) {
        WonadNativeBridge.onFocusChanged(wm)
        val window = target as? WindowState ?: return // Embedded/system input keeps stock handling.
        val display = window.displayContent ?: return
        val lease = live(wm, display.displayId) ?: return
        val activity = window.mActivityRecord ?: return
        val task = activity.task ?: return
        // Input reports may lag a newer WM focus change. Never apply an old
        // selection or act on a protected, sleeping, hidden or unleased task.
        if (wm.mRoot.topFocusedDisplayContent === display && display.mCurrentFocus === window &&
            display.mFocusedApp === activity && managed(task, lease) &&
            activity == task.topRunningActivity() && activity.isState(ActivityRecord.State.RESUMED) &&
            activity.windowsAreFocusable()) {
            wm.mAtmService.mTaskSupervisor.updateTopResumedActivityIfNeeded("wonad-input-focus")
        }
    }

    /** Multi-resume must not equate higher drawing order with keyboard selection.
     * Only protect focus between two live managed app tasks. System activities,
     * disappeared/hidden tasks and ordinary Android desktops use stock behavior.
     */
    @JvmStatic fun keepResumedFocus(focused: ActivityRecord?, next: ActivityRecord): Boolean {
        val selected = focused?.task ?: return false
        val candidate = next.task ?: return false
        val lease = live(selected.mWmService, selected.displayId) ?: return false
        return selected !== candidate && managed(selected, lease) && managed(candidate, lease) &&
            focused == selected.topRunningActivity() && focused.windowsAreFocusable()
    }

    /** Preserve focus through Android's multi-resume lifecycle selection. */
    @JvmStatic fun focusedResumedActivity(root: Task): ActivityRecord? {
        if (root.isLeafTask) return null
        val lease = live(root.mWmService, root.displayId) ?: return null
        val activity = root.displayContent?.mFocusedApp ?: return null
        val task = activity.task ?: return null
        return activity.takeIf { task.isDescendantOf(root) && managed(task, lease) &&
            activity == task.topRunningActivity() && activity.isState(ActivityRecord.State.RESUMED) }
    }

    /** Skip only other leased app tasks. System/IME windows retain stock priority. */
    @JvmStatic fun skipUnfocusedTask(display: DisplayContent, window: WindowState): Boolean {
        if (WonadNativeBridge.skipAppForDesktopFocus(display, window)) return true
        val lease = live(display.mWmService, display.displayId) ?: return false
        val focused = display.mFocusedApp ?: return false
        val selected = focused.task ?: return false
        val candidate = window.mActivityRecord?.task ?: return false
        return selected !== candidate && managed(selected, lease) && managed(candidate, lease) &&
            focused == selected.topRunningActivity() && focused.isState(ActivityRecord.State.RESUMED)
    }
}
