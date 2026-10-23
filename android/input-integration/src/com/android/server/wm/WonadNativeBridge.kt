package com.android.server.wm

import android.app.WindowConfiguration.WINDOWING_MODE_FREEFORM
import android.app.WindowConfiguration.WINDOWING_MODE_UNDEFINED
import android.app.WindowConfiguration.ACTIVITY_TYPE_UNDEFINED
import android.content.ComponentName
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Rect
import android.graphics.Region
import android.os.Binder
import android.os.IBinder
import android.os.InputConfig
import android.os.SystemClock
import android.os.UserHandle
import android.util.Log
import android.view.Display
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.SurfaceControl
import android.view.WindowManager
import android.view.WindowManagerPolicyConstants.PointerEventListener
import com.android.server.pm.KnownPackages.PACKAGE_PERMISSION_CONTROLLER
import java.lang.ref.WeakReference
import java.security.SecureRandom
import java.util.WeakHashMap
import java.util.concurrent.Executor
import java.util.function.Consumer

/** Exact native-object adapter for protocol v3. There is deliberately no desk,
 * workspace, layout, reserved area, or floating policy here. SystemUI supplies
 * copied frames already validated by Rust, then this layer rechecks the native
 * objects under WM's lock before changing anything. No handle reaches the APK.
 */
internal object WonadNativeBridge {
    private const val PACKAGE = "org.wonad.desktop"
    private const val GEN = "$PACKAGE.shell.GENERATION"
    private const val DISPLAY_TOKEN = "$PACKAGE.shell.DISPLAY_TOKEN"
    private val component = ComponentName(PACKAGE, "$PACKAGE.ExternalShellActivity")
    private val launcher = ComponentName(PACKAGE, "$PACKAGE.LauncherActivity")
    private val clientPrompt = ComponentName(PACKAGE, "$PACKAGE.DesktopPromptActivity")
    private val home = ComponentName(PACKAGE, "$PACKAGE.ExternalHomeActivity")
    private const val OBSERVER_TITLE = "Wonad pointer observer"
    private const val COMPONENT_PERMISSION = "android.permission.STATUS_BAR_SERVICE"
    private const val MAX_TASKS = 128
    private const val MAX_REGIONS = 768
    private const val MAX_CURRENT = 1622
    private const val MAX_DESIRED = 5767
    private const val MAX_IDENTITIES = 512
    private const val POINTER_FRESH_MILLIS = 250L
    private data class RetiredShellInput(val display: WeakReference<DisplayContent>,
        val uid: Int, val user: Int, val generation: Long, val incarnation: Long)
    // A retirement is only a non-touchable input-sink exemption, never a live
    // plane or input grant. Neither keys nor values retain a destroyed Activity
    // or Display; native task/Activity identities cannot be replaced by numbers.
    private val retiredShellInputs = WeakHashMap<ActivityRecord, RetiredShellInput>()
    private class Plane(val lease: WonadUiBridge.NativeLease, val window: WindowState,
        val observer: WindowState) {
        // Capture only here: every Plane is constructed after findPlane's full
        // native-object/UID/user/component/permission/generation checks.
        val inputActivity = checkNotNull(window.mActivityRecord)
        val inputRetirement = RetiredShellInput(WeakReference(lease.dc),
            window.owningUid, lease.user, lease.generation, lease.incarnation)
        val regions = Region()
        var meta = false
        var desktopFocus = false
        var pointerTask: Task? = null
        var pointerTime = 0L
        var pointerListener: PointerEventListener? = null
        var interactionBlocked = false
    }
    private data class Route(val wm: WindowManagerService, val dc: DisplayContent,
        val generation: Long, val incarnation: Long, val owner: IBinder)
    private data class DisplayRow(val token: Long, val dc: DisplayContent,
        val lease: WonadUiBridge.NativeLease, val bounds: Rect, val shell: Long)
    private data class TaskRow(val opaque: Long, val task: Task, val uid: Int,
        val displayToken: Long, val bounds: Rect, val minimumWidth: Int,
        val minimumHeight: Int, val resizable: Boolean, val visible: Boolean,
        val input: Boolean, val z: Int)
    private data class Placement(val observed: TaskRow, val display: DisplayRow,
        val bounds: Rect, val visible: Boolean, val input: Boolean, val z: Int)
    private data class LogicalOrder(val generation: Long, val owner: IBinder, val z: Int)
    private data class LayerTask(val task: Task, val activity: ActivityRecord, val uid: Int,
        val opaque: Long, val surface: SurfaceControl, val bounds: Rect,
        val visible: Boolean, val input: Boolean, val z: Int)
    private data class LayerWindow(val window: WindowState, val surface: SurfaceControl)
    private class LayerDisplay(val lease: WonadUiBridge.NativeLease, val plane: Plane,
        val shellSurface: SurfaceControl, val observerSurface: SurfaceControl,
        val tasks: List<LayerTask>) {
        var serial = 0L
        var submitted = false
        var committed = false
        var inputReported = false
        var windows = emptyList<LayerWindow>()
    }
    private class LayerFrame(val user: Int, val generation: Long, val owner: IBinder,
        val current: LongArray, val desired: LongArray, val displays: List<LayerDisplay>) {
        var ready = false
    }
    private val planes = linkedMapOf<Int, Plane>()
    /** InputMonitor repopulates this wrapper under WM's global lock. Remember
     * only a DROP_INPUT transition made by Wonad: Android's stock input-config
     * mask does not own that bit, and an existing stock DROP_INPUT must survive
     * lease recovery, phone migration and display removal. Weak keys cannot
     * retain a destroyed WindowState/input handle. */
    private val ownedAppInputDrops = WeakHashMap<InputWindowHandleWrapper, Boolean>()
    private val logicalOrder = linkedMapOf<Task, LogicalOrder>()
    // A private completion receipt, not APK policy. These bounded exact native
    // objects and copied scalars never cross the public Binder API.
    private var layerFrame: LayerFrame? = null
    private data class NativeIdentity(val uid: Int, val token: Long)
    // This namespace belongs to system_server, not the restartable SystemUI
    // broker. A private APK checkpoint can safely rebind surviving exact tasks
    // after either APK or broker death, without teaching the OS workspaces.
    private val identityEpoch = (SecureRandom().nextLong() and Long.MAX_VALUE).coerceAtLeast(1)
    private var nextIdentity = 1L
    private val identities = linkedMapOf<Task, NativeIdentity>()
    @Volatile private var routes: Map<Int, Route> = emptyMap()

    @JvmStatic fun identityEpoch(wm: WindowManagerService): Long {
        WonadUiBridge.enforceSystemUi(wm)
        return identityEpoch
    }

    private fun taskIdentity(task: Task): NativeIdentity {
        val uid = checkNotNull(task.topRunningActivity()).uid
        identities[task]?.takeIf { it.uid == uid }?.let { return it }
        identities.keys.removeAll { !it.isAttached }
        check(identities.size < MAX_IDENTITIES || task in identities) { "Native task identity capacity" }
        val id = nextIdentity
        nextIdentity = Math.addExact(nextIdentity, 1L)
        return NativeIdentity(uid, id).also { identities[task] = it }
    }

    private fun publishRoutes() {
        routes = planes.mapValues { (_, plane) ->
            val lease = plane.lease
            Route(lease.dc.mWmService, lease.dc, lease.generation, lease.incarnation, lease.owner)
        }
    }

    /** Package removal/update can race native visibility and Binder queries.
     * Resolve the current user-specific owner each time; a cached UID must not
     * authorize a stale plane or exempt Home after the package disappears.
     * Other PM failures remain visible rather than becoming an exemption.
     */
    private fun currentOwnerUid(wm: WindowManagerService, user: Int): Int? {
        return try { wm.mContext.packageManager.getPackageUidAsUser(PACKAGE, user) }
        catch (_: PackageManager.NameNotFoundException) { null }
    }

    private fun launcherWindow(plane: Plane): WindowState? {
        val lease = plane.lease
        val uid = plane.window.owningUid
        return lease.dc.getWindow(java.util.function.Predicate { window ->
            val activity = window.mActivityRecord
            // A finishing catalogue can retain a drawn Window/input sink
            // during its stock close transition. It no longer owns launcher
            // interaction; do not let it suppress a fresh background click
            // after the trusted phone confirmation has been dismissed.
            activity != null && !activity.finishing &&
                ((activity.mActivityComponent == launcher && activity.intent.getLongExtra("catalog", 0) > 0) ||
                 (activity.mActivityComponent == clientPrompt && activity.intent.getLongExtra("request", 0) > 0)) &&
                activity.info.permission == COMPONENT_PERMISSION &&
                activity.mUserId == lease.user && activity.uid == uid && window.owningUid == uid &&
                activity.intent.getLongExtra("generation", 0) == lease.generation &&
                window.isVisible &&
                window.isDrawn && window.mAttrs.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
        })
    }

    private fun homeWindow(plane: Plane): WindowState? =
        plane.lease.dc.getWindow(java.util.function.Predicate { window ->
            val activity = window.mActivityRecord
            activity != null && activity.mActivityComponent == home &&
                activity.info.permission == COMPONENT_PERMISSION &&
                activity.mUserId == plane.lease.user && activity.uid == plane.window.owningUid &&
                window.owningUid == plane.window.owningUid && window.isDrawn &&
                window.mAttrs.type == WindowManager.LayoutParams.TYPE_BASE_APPLICATION &&
                window.mAttrs.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
        })

    /** Home is the background, not an occluding desktop application. Resolve
     * both sides from actual native objects under WM's lock; this cannot make
     * a hidden task visible or bypass ancestor, lock-task, or keyguard checks.
     * Registration may run behind the black readiness barrier, before drawing.
     */
    @JvmStatic fun ignoreNativeHomeOcclusion(current: TaskFragment,
        other: WindowContainer<*>): Boolean {
        val task = current.asTask() ?: return false
        val dc = task.displayContent ?: return false
        val wm = dc.mWmService
        val lease = WonadUiBridge.nativeLease(wm, dc, requireReady = false) ?: return false
        val area = dc.defaultTaskDisplayArea
        val background = other.asTask() ?: return false
        if (dc.displayId == Display.DEFAULT_DISPLAY || lease.user != wm.mCurrentUserId ||
            lease.incarnation != WonadUiBridge.attachment(dc) || task.parent !== area ||
            background.parent !== area || background.displayContent !== dc ||
            !background.isActivityTypeHome || task === background) return false
        val uid = currentOwnerUid(wm, lease.user) ?: return false
        val homeActivity = background.topRunningActivity() ?: return false
        if (!homeActivity.isAttached || homeActivity.finishing ||
            homeActivity.mActivityComponent != home || homeActivity.uid != uid ||
            homeActivity.mUserId != lease.user || homeActivity.displayContent !== dc ||
            homeActivity.info.permission != COMPONENT_PERMISSION) return false
        if (app(task, lease.user)) return true
        val shellActivity = task.topRunningActivity() ?: return false
        return shellActivity.isAttached && !shellActivity.finishing &&
            shellActivity.mActivityComponent == component && shellActivity.uid == uid &&
            shellActivity.mUserId == lease.user && shellActivity.displayContent === dc &&
            shellActivity.info.permission == COMPONENT_PERMISSION &&
            shellActivity.intent.getLongExtra(GEN, 0) == lease.generation &&
            shellActivity.intent.getLongExtra(DISPLAY_TOKEN, 0) == lease.incarnation
    }

    /** Stock TDA caches a preferred root without rechecking focusability.
     * Invalidate only the exact direct root whose native focus was withdrawn;
     * ordinary stock roots, other displays and unrelated preferred roots stay.
     */
    private fun clearWithdrawnPreferredFocus(task: Task) {
        val area = task.displayContent?.defaultTaskDisplayArea ?: return
        if (task.parent === area && (!task.isFocusable || task.isForceHidden) &&
            area.mPreferredTopFocusableRootTask === task) {
            area.mPreferredTopFocusableRootTask = null
        }
    }

    /** Retire stock Shell's unused prewarmed containers at native takeover.
     * These are actual empty organizer-created roots, never client task IDs.
     * Occupied, foreign-organizer, phone, Home, and ordinary roots are retained.
     * Both collection and the final emptiness check run under the same WM lock.
     */
    internal fun retireEmptyDesktopRoots(dc: DisplayContent) {
        val wm = dc.mWmService
        val lease = WonadUiBridge.nativeLease(wm, dc, requireReady = false) ?: return
        if (dc.displayId == Display.DEFAULT_DISPLAY || lease.dc !== dc ||
            lease.user != wm.mCurrentUserId ||
            lease.incarnation != WonadUiBridge.attachment(dc)) return
        val area = dc.defaultTaskDisplayArea
        val uid = wm.mContext.packageManager.getPackageUidAsUser(
            "com.android.systemui", UserHandle.USER_SYSTEM)
        fun eligibleRoot(task: Task): Boolean {
            val organizer = task.mTaskOrganizer ?: return false
            return task.isAttached && task.displayContent === dc && task.parent === area &&
                task.isRootTask && task.mCreatedByOrganizer && task.childCount == 0 &&
                task.topRunningActivity() == null && task.activityType == ACTIVITY_TYPE_UNDEFINED &&
                task.windowingMode == WINDOWING_MODE_FREEFORM &&
                (task.mName == "Desk" || task.mName?.matches(Regex("MinimizedDesk_[1-9][0-9]*")) == true) &&
                wm.mAtmService.mTaskOrganizerController.getWonadOrganizerUid(organizer) == uid
        }
        val unused = mutableListOf<Task>()
        dc.forAllTasks(Consumer { task -> if (eligibleRoot(task)) unused.add(task) })
        unused.forEach { task ->
            val current = WonadUiBridge.nativeLease(wm, dc, requireReady = false) ?: return
            if (current.dc !== dc || current.owner !== lease.owner ||
                current.user != lease.user || current.user != wm.mCurrentUserId ||
                current.generation != lease.generation || current.incarnation != lease.incarnation ||
                current.incarnation != WonadUiBridge.attachment(dc)) return
            if (eligibleRoot(task)) task.removeImmediately("wonad-native-empty-stock-root")
        }
    }

    private fun protectedPhoneFocus(wm: WindowManagerService): Boolean {
        val focused = wm.mRoot.topFocusedDisplayContent
        if (focused.displayId != Display.DEFAULT_DISPLAY) return false
        val window = focused.mCurrentFocus ?: return true
        // Normal phone Home and ordinary app windows can yield to a fresh
        // external mouse observation. Permission/system/Recents dialogs cannot.
        if (window.mActivityRecord?.isActivityTypeHome == true) return false
        return UserHandle.getAppId(window.owningUid) !in 10000..19999 ||
            window.mActivityRecord?.packageName in setOf("android", "com.android.systemui") ||
            permissionController(wm, window.mActivityRecord?.packageName, wm.mCurrentUserId)
    }

    private fun permissionController(wm: WindowManagerService, packageName: String?, user: Int): Boolean =
        packageName != null && wm.mPmInternal.getKnownPackageNames(
            PACKAGE_PERMISSION_CONTROLLER, user).contains(packageName)

    private fun ownPhonePrompt(wm: WindowManagerService, window: WindowState, user: Int): Boolean =
        window.displayId == Display.DEFAULT_DISPLAY &&
            UserHandle.getUserId(window.owningUid) == UserHandle.USER_SYSTEM &&
            window.owningUid == wm.mContext.packageManager.getPackageUidAsUser(
                "com.android.systemui", UserHandle.USER_SYSTEM) &&
            window.mAttrs.type == WindowManager.LayoutParams.TYPE_SYSTEM_DIALOG &&
            window.mAttrs.flags and WindowManager.LayoutParams.FLAG_SECURE != 0 &&
            wm.mCurrentUserId == user && window.mAttrs.title.toString() in setOf(
                "Wonad: Move from phone", "Move this phone window?", "Wonad: Open an app",
                "Open on external desktop?")

    private fun protectedWindow(wm: WindowManagerService, window: WindowState, user: Int): Boolean {
        if (!window.isVisible || !window.isDrawn) return false
        val activity = window.mActivityRecord
        if (activity != null && activity.mUserId != user) return false
        if (permissionController(wm, activity?.packageName, user) ||
            activity?.isActivityTypeRecents == true) return true
        return UserHandle.getAppId(window.owningUid) !in 10000..19999 &&
            window.mAttrs.type in setOf(WindowManager.LayoutParams.TYPE_SYSTEM_DIALOG,
                WindowManager.LayoutParams.TYPE_SYSTEM_ERROR)
    }

    /** The source's key DOWN can start a phone permission Activity before it
     * has any Window. Its still-external key UP must not raise the desktop in
     * that gap. Observe only the actual top phone root and its authenticated
     * native result chain; no package name, cached token or APK modal flag can
     * manufacture this protection. Finishing/removal ends it naturally. */
    private fun pendingNativePhonePermission(wm: WindowManagerService, user: Int): Boolean {
        if (user != wm.mCurrentUserId) return false
        val phone = wm.mRoot.getDisplayContent(Display.DEFAULT_DISPLAY) ?: return false
        val area = phone.defaultTaskDisplayArea ?: return false
        val root = area.topRootTask ?: return false
        val activity = root.topRunningActivity() ?: return false
        val intent = activity.intent ?: return false
        val applicationInfo = activity.info.applicationInfo ?: return false
        val task = activity.task ?: return false
        val source = activity.resultTo ?: return false
        val sourceTask = source.task ?: return false
        val dc = source.displayContent ?: return false
        if (phone.mWmService !== wm || phone.parent !== wm.mRoot || area.displayContent !== phone ||
            phone.topRootTask !== root ||
            !root.isAttached || root.parent !== area || root.displayContent !== phone || root.isForceHidden ||
            !task.isAttached || !task.isLeafTask || !task.isActivityTypeStandard || task.rootTask !== root ||
            task.displayContent !== phone || task.isForceHidden || task.topRunningActivity() !== activity ||
            !activity.isAttached || activity.finishing || activity.displayContent !== phone ||
            activity.mUserId != user || activity.requestCode < 0 || activity.info.targetActivity != null ||
            activity.info.name != "com.android.permissioncontroller.permission.ui.GrantPermissionsActivity" ||
            intent.action != PackageManager.ACTION_REQUEST_PERMISSIONS ||
            intent.flags and (Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NEW_DOCUMENT or
                Intent.FLAG_ACTIVITY_FORWARD_RESULT) != 0 ||
            applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM == 0 ||
            source.finishing || !source.isAttached || source.mUserId != user ||
            sourceTask.topRunningActivity() !== source || sourceTask.displayContent !== dc || sourceTask.isForceHidden ||
            activity.launchedFromUid != source.uid || dc.mWmService !== wm || dc.parent !== wm.mRoot ||
            wm.mRoot.getDisplayContent(dc.displayId) !== dc || !isManagedPermissionSource(source)) return false
        val controllers = wm.mPmInternal.getKnownPackageNames(PACKAGE_PERMISSION_CONTROLLER, user)
        if (controllers.size != 1 || controllers[0] != activity.packageName ||
            activity.info.packageName != activity.packageName) return false
        val uid = wm.mPmInternal.getPackageUid(controllers[0], 0, user)
        if (uid < 0 || uid != activity.uid || UserHandle.getUserId(uid) != user) return false
        val lease = WonadUiBridge.nativeLease(wm, dc, requireReady = false) ?: return false
        return lease.dc === dc && lease.user == user && lease.generation > 0 && lease.incarnation > 0 &&
            lease.incarnation == WonadUiBridge.attachment(dc)
    }

    /** Observed protected UI, not an APK modal flag. Keeping a healthy lease
     * alive never permits a native mutation or an input spy during a prompt. */
    private fun interactionBlockedLocked(wm: WindowManagerService, user: Int): Boolean {
        if (wm.mCurrentUserId != user || wm.mPolicy.isKeyguardLocked || wm.mPolicy.isKeyguardShowing)
            return true
        if (pendingNativePhonePermission(wm, user)) return true
        val focused = wm.mRoot.topFocusedDisplayContent.mCurrentFocus
        if (protectedPhoneFocus(wm) &&
            (focused == null || !ownPhonePrompt(wm, focused, user))) return true
        var blocked = false
        wm.mRoot.forAllDisplays(Consumer { dc ->
            if (dc.getWindow(java.util.function.Predicate { window ->
                    protectedWindow(wm, window, user) && !ownPhonePrompt(wm, window, user)
                }) != null) blocked = true
        })
        return blocked
    }

    @JvmStatic fun interactionBlocked(wm: WindowManagerService, user: Int): Boolean {
        WonadUiBridge.enforceSystemUi(wm)
        val identity = Binder.clearCallingIdentity()
        return try { wm.withWonadGlobalLock { interactionBlockedLocked(wm, user) } }
        finally { Binder.restoreCallingIdentity(identity) }
    }

    /** Native input containment includes our own phone confirmations too.
     * The transparent consumer keeps their keyboard focus without hiding the
     * external desktop or changing any app's policy visibility/workspace. */
    internal fun protectedInput(wm: WindowManagerService, user: Int): Boolean =
        interactionBlockedLocked(wm, user) || protectedPhoneFocus(wm)

    /** WMS-global-lock stock display-raise boundary. Only the same live native
     * physical display is affected; phone and ordinary external displays keep
     * Android's normal targeted-key behavior. This chooses no replacement
     * focus and never alters a lease, Task or surface. */
    @JvmStatic fun preventNativeDisplayRaise(wm: WindowManagerService, dc: DisplayContent): Boolean {
        if (dc.displayId <= Display.DEFAULT_DISPLAY || dc.mWmService !== wm || dc.parent !== wm.mRoot ||
            wm.mRoot.getDisplayContent(dc.displayId) !== dc) return false
        val lease = WonadUiBridge.nativeLease(wm, dc, requireReady = false) ?: return false
        if (lease.dc !== dc || lease.user != wm.mCurrentUserId || lease.generation <= 0 ||
            lease.incarnation <= 0 || lease.incarnation != WonadUiBridge.attachment(dc)) return false
        return protectedInput(wm, lease.user)
    }

    /** ActivityStarter-only, under the native WM lock. No caller-supplied
     * component/display/task IDs can qualify an external permission source. */
    @JvmStatic fun isManagedPermissionSource(source: ActivityRecord): Boolean {
        val task = source.task ?: return false
        val dc = source.displayContent ?: return false
        val wm = dc.mWmService
        if (!source.isAttached || task.displayContent !== dc || source.mUserId != wm.mCurrentUserId ||
            wm.mRoot.getDisplayContent(dc.displayId) !== dc || !app(task, source.mUserId)) return false
        val lease = WonadUiBridge.nativeLease(wm, dc, requireReady = false) ?: return false
        return lease.user == source.mUserId && lease.incarnation == WonadUiBridge.attachment(dc)
    }

    private fun registerPointer(plane: Plane) {
        val dc = plane.lease.dc
        val wm = dc.mWmService
        val listener = PointerEventListener { event ->
            // Never retain the pooled MotionEvent or lock WM on the dispatcher
            // thread. This observation grants no policy; it only proves that a
            // later bounded focus request follows actual input on this lease.
            val action = event.actionMasked
            if (action !in setOf(MotionEvent.ACTION_HOVER_ENTER, MotionEvent.ACTION_HOVER_MOVE,
                    MotionEvent.ACTION_DOWN, MotionEvent.ACTION_BUTTON_PRESS)) return@PointerEventListener
            val x = event.x
            val y = event.y
            val time = event.eventTime
            val noModifiers = event.metaState == 0 && event.buttonState == 0
            if (action in setOf(MotionEvent.ACTION_HOVER_ENTER, MotionEvent.ACTION_HOVER_MOVE) &&
                !noModifiers) return@PointerEventListener
            wm.mH.post { wm.withWonadGlobalLock {
                if (planes[dc.displayId] !== plane || WonadUiBridge.nativeLease(wm, dc) != plane.lease ||
                    SystemClock.uptimeMillis() - time !in 0..POINTER_FRESH_MILLIS ||
                    launcherWindow(plane) != null || protectedPhoneFocus(wm) ||
                    interactionBlockedLocked(wm, plane.lease.user)) return@withWonadGlobalLock
                if (!x.isFinite() || !y.isFinite() || plane.regions.contains(x.toInt(), y.toInt())) {
                    // Border drags remain ordinary base-window streams, not a
                    // proof authorizing an unrelated app focus request.
                    plane.pointerTask = null
                    plane.pointerTime = 0
                    return@withWonadGlobalLock
                }
                val candidate = dc.getWindow(java.util.function.Predicate { window ->
                    val task = window.mActivityRecord?.task
                    window !== plane.window && window !== plane.observer && window.isVisible &&
                        window.isDrawn && window.frame.contains(x.toInt(), y.toInt()) &&
                        task != null && app(task, plane.lease.user) && !task.isForceHidden && task.isFocusable
                })?.mActivityRecord?.task
                plane.pointerTask = candidate
                plane.pointerTime = if (candidate != null) time else 0
                if (candidate == null && action == MotionEvent.ACTION_DOWN) {
                    val background = homeWindow(plane)
                    if (background?.isVisible == true && background.frame.contains(x.toInt(), y.toInt())) {
                        // Stock native background selection, scoped to an
                        // actual pointer DOWN on our exact fixed home. No APK
                        // message can manufacture this empty-desktop focus.
                        plane.desktopFocus = true
                        dc.setFocusedApp(background.mActivityRecord)
                        wm.mRoot.positionChildAt(WindowContainer.POSITION_TOP, dc, false)
                        wm.mRoot.resumeFocusedTasksTopActivities()
                        wm.updateFocusedWindowLocked(WindowManagerService.UPDATE_FOCUS_NORMAL, true)
                        wm.mAtmService.mTaskSupervisor.updateTopResumedActivityIfNeeded("wonad-native-background-click")
                    }
                }
            } }
        }
        plane.pointerListener = listener
        dc.registerPointerEventListener(listener)
    }

    private fun unregisterPointer(plane: Plane) {
        plane.pointerListener?.let { plane.lease.dc.unregisterPointerEventListener(it) }
        plane.pointerListener = null
        plane.pointerTask = null
        plane.pointerTime = 0
    }

    private fun focusAllowed(wm: WindowManagerService, target: DisplayRow, selected: Task?): Boolean {
        if (protectedPhoneFocus(wm) || interactionBlockedLocked(wm, target.lease.user)) return false
        val focusedLease = WonadUiBridge.nativeLease(wm, wm.mRoot.topFocusedDisplayContent)
        if (focusedLease?.let { it.user == target.lease.user && it.owner == target.lease.owner &&
                it.generation == target.lease.generation } == true) return true
        val plane = planes[target.dc.displayId] ?: return false
        return selected != null && plane.lease == target.lease && plane.pointerTask === selected &&
            SystemClock.uptimeMillis() - plane.pointerTime in 0..POINTER_FRESH_MILLIS
    }

    /** Keyboard desktop focus is explicit, but neither changes the app's z
     * order nor selects a layout. Protected/system/IME windows keep priority. */
    @JvmStatic fun skipAppForDesktopFocus(dc: DisplayContent, window: WindowState): Boolean {
        val plane = planes[dc.displayId] ?: return false
        if (!plane.desktopFocus || WonadUiBridge.nativeLease(dc.mWmService, dc) != plane.lease ||
            dc.mFocusedApp?.mActivityComponent != home) return false
        val task = window.mActivityRecord?.task ?: return false
        return app(task, plane.lease.user)
    }

    private fun setTaskTransform(task: Task, bounds: Rect,
        transaction: SurfaceControl.Transaction = task.pendingTransaction) {
        // Organized roots are not positioned by stock WM. Use only the same
        // finite rectangle already accepted by the exact-object preflight.
        // The DisplayContent hierarchy clips pixels to its physical viewport.
        val surface = task.surfaceControl ?: error("Native task surface disappeared")
        transaction.setPosition(surface, bounds.left.toFloat(), bounds.top.toFloat())
            .setWindowCrop(surface, bounds.width(), bounds.height())
            .setShadowRadius(surface, 0f).setCornerRadius(surface, 0f)
    }

    /** Physical undock, not a client frame. Park exact ordinary survivors on
     * another live same-user native attachment before Android clears this
     * DisplayContent. The APK decides their workspace/geometry after observing
     * the new topology. Never merge them into visible apps or focus the phone.
     * With no suitable external attachment stock final-undock behavior wins.
     */
    @JvmStatic fun undockApps(dc: DisplayContent, user: Int) {
        val wm = dc.mWmService
        val targets = WonadUiBridge.nativeLeases(wm).filter {
            it.dc !== dc && it.user == user && !it.dc.isRemoving
        }.sortedWith(compareByDescending<WonadUiBridge.NativeLease> {
            it.dc === wm.mRoot.topFocusedDisplayContent
        }.thenBy { it.incarnation })
        val tasks = taskOrder(dc, user)
        if (tasks.size > MAX_TASKS) return
        val focused = wm.mRoot.topFocusedDisplayContent
        val phone = wm.mRoot.getDisplayContent(Display.DEFAULT_DISPLAY)
        val phoneApp = phone?.mFocusedApp
        wm.mAtmService.deferWindowLayout()
        try {
            for (task in tasks) {
                val previous = Rect(task.bounds)
                val destination = targets.firstOrNull { lease ->
                    val info = lease.dc.displayInfo
                    task.canBeLaunchedOnDisplay(lease.dc.displayId) &&
                        task.minWidth <= info.logicalWidth && task.minHeight <= info.logicalHeight &&
                        (task.isResizeable || (previous.width() <= info.logicalWidth &&
                            previous.height() <= info.logicalHeight))
                }
                if (destination == null) {
                    // Last-monitor undock must restore ordinary phone task
                    // eligibility, not bring a formerly hidden desktop above
                    // the user's existing phone Activity. No workspace is
                    // assigned here; normal GrapheneOS Recents can resume it.
                    if (phone != null && task.shouldReparentOnDisplayRemoval() &&
                        task.canBeLaunchedOnDisplay(Display.DEFAULT_DISPLAY)) {
                        try {
                            task.setForceHidden(TaskFragment.FLAG_FORCE_HIDDEN_FOR_WONAD_POLICY, true)
                            task.setFocusable(false)
                            task.setAlwaysOnTop(false)
                            val area = phone.defaultTaskDisplayArea
                            task.reparent(area, false)
                            check(task.parent === area && task.displayContent === phone) { "Native phone undock declined" }
                            task.setWindowingMode(WINDOWING_MODE_UNDEFINED)
                            task.setBounds(null)
                            task.surfaceControl?.let { surface ->
                                task.pendingTransaction.setPosition(surface, 0f, 0f)
                                    .setWindowCrop(surface, null).setShadowRadius(surface, 0f).setCornerRadius(surface, 0f)
                            }
                        } catch (error: Exception) {
                            // A physical-undock constraint cannot crash WM or
                            // strand a partially reparented phone task hidden.
                            Log.e("WonadNative", "Could not return exact undocked task to phone", error)
                        } finally {
                            if (task.isAttached && task.mUserId == user) {
                                task.setForceHidden(TaskFragment.FLAG_FORCE_HIDDEN_FOR_WONAD, false)
                                task.setForceHidden(TaskFragment.FLAG_FORCE_HIDDEN_FOR_WONAD_POLICY, false)
                                task.setFocusable(true)
                            }
                        }
                    }
                    continue
                }
                val info = destination.dc.displayInfo
                val width = previous.width().coerceIn(task.minWidth.coerceAtLeast(1), info.logicalWidth)
                val height = previous.height().coerceIn(task.minHeight.coerceAtLeast(1), info.logicalHeight)
                val left = previous.left.coerceIn(0, info.logicalWidth - width)
                val top = previous.top.coerceIn(0, info.logicalHeight - height)
                val rectangle = Rect(left, top, left + width, top + height)
                try {
                    // Hide before native reparent: no intermediate frame can
                    // flash the departed workspace on the surviving desktop.
                    task.setForceHidden(TaskFragment.FLAG_FORCE_HIDDEN_FOR_WONAD_POLICY, true)
                    task.setFocusable(false)
                    task.setForceHidden(TaskFragment.FLAG_FORCE_HIDDEN_FOR_WONAD, false)
                    task.setAlwaysOnTop(false)
                    task.setWindowingMode(WINDOWING_MODE_FREEFORM)
                    val area = destination.dc.defaultTaskDisplayArea
                    task.reparent(area, false)
                    check(task.parent === area) { "Native undock reparent declined" }
                    task.setBounds(rectangle)
                    setTaskTransform(task, rectangle)
                } catch (error: Exception) {
                    Log.e("WonadNative", "Could not park exact undocked task", error)
                    WonadUiBridge.parkNative(wm, destination.user, destination.generation, destination.owner)
                }
            }
            if (focused === phone && phone != null) {
                phone.setFocusedApp(phoneApp)
                wm.mRoot.positionChildAt(WindowContainer.POSITION_TOP, phone, false)
            }
            wm.mRoot.ensureActivitiesVisible()
            wm.mRoot.resumeFocusedTasksTopActivities()
            wm.updateFocusedWindowLocked(WindowManagerService.UPDATE_FOCUS_NORMAL, true)
        } finally { wm.mAtmService.continueWindowLayout() }
    }

    /** Only a fixed own ordinary application window can become the plane.
     * Native extras bind it to this session AND this physical attachment.
     * This is an OS observation, never a client-selected WindowToken. */
    private fun findPlane(wm: WindowManagerService, dc: DisplayContent): Plane? {
        val lease = WonadUiBridge.nativeLease(wm, dc, requireReady = false) ?: return null
        val uid = currentOwnerUid(wm, lease.user) ?: return null
        val candidates = mutableListOf<WindowState>()
        dc.forAllWindows(Consumer { window ->
            val activity = window.mActivityRecord ?: return@Consumer
            val attrs = window.mAttrs
            if (activity.mActivityComponent == component && activity.mUserId == lease.user &&
                activity.info.permission == COMPONENT_PERMISSION &&
                activity.uid == uid && window.owningUid == uid &&
                attrs.type == WindowManager.LayoutParams.TYPE_BASE_APPLICATION &&
                attrs.flags and WindowManager.LayoutParams.FLAG_SECURE != 0 &&
                attrs.flags and WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE != 0 &&
                attrs.flags and WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL != 0 &&
                activity.intent.getLongExtra(GEN, 0) == lease.generation &&
                activity.intent.getLongExtra(DISPLAY_TOKEN, 0) == lease.incarnation &&
                window.isDrawn && window.mHasSurface) candidates.add(window)
        }, true)
        val window = candidates.singleOrNull() ?: return null
        val observers = mutableListOf<WindowState>()
        dc.forAllWindows(Consumer { child ->
            if (child.mActivityRecord === window.mActivityRecord && child.parentWindow === window &&
                child.owningUid == uid && child.mAttrs.type == WindowManager.LayoutParams.TYPE_APPLICATION_PANEL &&
                child.mAttrs.title.toString() == OBSERVER_TITLE &&
                child.mAttrs.flags and WindowManager.LayoutParams.FLAG_SECURE != 0 &&
                child.mAttrs.flags and WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE != 0 &&
                child.mAttrs.flags and WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL != 0 &&
                child.isDrawn && child.mHasSurface) observers.add(child)
        }, true)
        val observer = observers.singleOrNull() ?: return null
        // A non-focusable overlay Activity still has a focusable Task by
        // default. Its top-task position must not displace the actual home/app
        // focused Activity and leave an otherwise empty desktop keyless.
        val shellActivity = window.mActivityRecord ?: return null
        val shellTask = shellActivity.task ?: return null
        shellTask.setFocusable(false)
        clearWithdrawnPreferredFocus(shellTask)
        if (dc.mFocusedApp === shellActivity) {
            dc.setFocusedApp(dc.defaultTaskDisplayArea.focusedActivity)
        }
        val previous = planes[dc.displayId]
        if (previous != null && previous.window === window && previous.observer === observer &&
            previous.lease == lease) return previous
        previous?.let { retirePlaneInput(it) }
        // Retirement calls framework/surface code. A reentrant callback can
        // replace or revoke the exact lease; never install the stale candidate
        // captured before that boundary or overwrite a replacement plane.
        if (planes[dc.displayId] !== previous || wm.mRoot.getDisplayContent(dc.displayId) !== dc ||
            WonadUiBridge.nativeLease(wm, dc, requireReady = false) != lease ||
            currentOwnerUid(wm, lease.user) != uid || window.displayContent !== dc ||
            observer.displayContent !== dc || window.mActivityRecord !== shellActivity ||
            observer.mActivityRecord !== shellActivity || shellActivity.uid != uid ||
            shellActivity.mUserId != lease.user || shellActivity.mActivityComponent != component ||
            shellActivity.info.permission != COMPONENT_PERMISSION ||
            shellActivity.intent.getLongExtra(GEN, 0) != lease.generation ||
            shellActivity.intent.getLongExtra(DISPLAY_TOKEN, 0) != lease.incarnation ||
            window.owningUid != uid || observer.owningUid != uid ||
            window.mAttrs.type != WindowManager.LayoutParams.TYPE_BASE_APPLICATION ||
            observer.mAttrs.type != WindowManager.LayoutParams.TYPE_APPLICATION_PANEL ||
            observer.parentWindow !== window || observer.mAttrs.title.toString() != OBSERVER_TITLE ||
            !window.isDrawn || !window.mHasSurface || !observer.isDrawn || !observer.mHasSurface) return null
        val requiredFlags = WindowManager.LayoutParams.FLAG_SECURE or
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL
        if (window.mAttrs.flags and requiredFlags != requiredFlags ||
            observer.mAttrs.flags and requiredFlags != requiredFlags) return null
        return Plane(lease, window, observer).also {
            planes[dc.displayId] = it
            registerPointer(it)
            publishRoutes()
        }
    }

    @JvmStatic fun shellGeneration(wm: WindowManagerService, dc: DisplayContent): Long =
        findPlane(wm, dc)?.lease?.generation ?: 0L

    /** Only our exact authenticated live plane or its recorded retired Activity
     * can opt the shell's stock input sink out. Retirement grants no window,
     * pointer, key or live-plane authority. Ordinary app/phone/system sinks keep
     * Android's touch-opaque/tapjacking protection. */
    @JvmStatic fun transparentShellInput(activity: ActivityRecord): Boolean {
        val dc = activity.displayContent ?: return false
        retiredShellInputs[activity]?.let { retired ->
            if (retiredShellInputMatches(activity, dc, retired)) return true
        }
        val plane = planes[dc.displayId] ?: return false
        return plane.window.mActivityRecord === activity && plane.lease.dc === dc &&
            activity.mActivityComponent == component && activity.info.permission == COMPONENT_PERMISSION &&
            activity.uid == plane.window.owningUid && activity.mUserId == plane.lease.user &&
            WonadUiBridge.nativeLease(dc.mWmService, dc) == plane.lease &&
            activity.intent.getLongExtra(GEN, 0) == plane.lease.generation &&
            activity.intent.getLongExtra(DISPLAY_TOKEN, 0) == plane.lease.incarnation
    }

    private fun retiredShellInputMatches(activity: ActivityRecord, dc: DisplayContent,
        retired: RetiredShellInput): Boolean {
        return dc.displayId > Display.DEFAULT_DISPLAY &&
            retired.display.get() === dc && dc.mWmService.mRoot.getDisplayContent(dc.displayId) === dc &&
            WonadUiBridge.nativeMode(dc) && activity.displayContent === dc &&
            activity.mActivityComponent == component && activity.info.permission == COMPONENT_PERMISSION &&
            activity.uid == retired.uid && activity.mUserId == retired.user &&
            activity.intent.getLongExtra(GEN, 0) == retired.generation &&
            activity.intent.getLongExtra(DISPLAY_TOKEN, 0) == retired.incarnation
    }

    /** Retire every exact resource even if an independent native update fails.
     * Apply the stock Activity sink immediately: a hidden Activity skips its
     * ordinary prepareSurfaces pass and may otherwise strand a touchable sink.
     */
    private fun retirePlaneInput(plane: Plane) {
        val dc = plane.lease.dc
        val failures = WonadCleanupFailures()
        failures.attempt {
            if (retiredShellInputMatches(plane.inputActivity, dc, plane.inputRetirement)) {
                retiredShellInputs[plane.inputActivity] = plane.inputRetirement
                plane.inputActivity.mActivityRecordInputSink.applyChangesToSurfaceIfChanged(dc.pendingTransaction)
            }
        }
        for (window in listOf(plane.window, plane.observer)) {
            failures.attempt {
                if (retiredWindowUnclaimed(plane, window)) dropInput(window.mInputWindowHandle)
            }
            failures.attempt {
                if (retiredWindowUnclaimed(plane, window)) window.mWinAnimator.mSurfaceControl?.let { surface ->
                    window.mInputWindowHandle.applyChangesToSurface(dc.pendingTransaction, surface)
                }
            }
        }
        failures.attempt { unregisterPointer(plane) }
        failures.rethrowFatal()
        failures.supportedFailure?.let { throw it }
    }

    private fun retiredWindowUnclaimed(plane: Plane, window: WindowState): Boolean {
        if (window.displayContent !== plane.lease.dc || window.mActivityRecord !== plane.inputActivity) return false
        val replacement = planes[plane.lease.dc.displayId]
        return replacement == null || replacement === plane ||
            (replacement.window !== window && replacement.observer !== window)
    }

    @JvmStatic fun nativeMode(wm: WindowManagerService, displayId: Int): Boolean {
        WonadUiBridge.enforceSystemUi(wm)
        val identity = Binder.clearCallingIdentity()
        return try { wm.withWonadGlobalLock {
            wm.mRoot.getDisplayContent(displayId)?.let { WonadUiBridge.nativeMode(it) } == true
        } } finally { Binder.restoreCallingIdentity(identity) }
    }

    private fun exactTask(token: IBinder): Task? =
        (token as? WindowContainer.RemoteToken)?.container?.asTask()

    /** Same ordinary-app identity checks as native enumeration, but only for
     * stock migration that has already reached the phone. No lease is opened. */
    internal fun returningPhoneApp(task: Task, user: Int): Boolean =
        task.displayId == Display.DEFAULT_DISPLAY && app(task, user, allowPhone = true)

    private fun app(task: Task, user: Int, expectedUid: Int? = null,
        allowPhone: Boolean = false): Boolean {
        if (!task.isAttached || !task.isLeafTask || !task.isActivityTypeStandard ||
            task.mCreatedByOrganizer || task.mUserId != user ||
            (task.displayId <= 0 && !(allowPhone && task.displayId == Display.DEFAULT_DISPLAY))) return false
        val activity = task.topRunningActivity() ?: return false
        return UserHandle.getUserId(activity.uid) == user &&
            UserHandle.getAppId(activity.uid) in 10000..19999 &&
            (expectedUid == null || activity.uid == expectedUid) &&
            activity.packageName !in setOf(PACKAGE, "android", "com.android.systemui",
                "com.android.permissioncontroller") &&
            !permissionController(task.mWmService, activity.packageName, user)
    }

    /** Generic native-bounds ownership, not a layout/minimum-size policy.
     * Explicit application minima still apply. Stock caption-based fallback
     * dimensions and placement adjustment must not alter an APK-owned frame.
     * Sticky ownership includes the parked state until physical removal.
     */
    @JvmStatic fun usesClientBounds(task: Task): Boolean =
        task.displayContent?.let { dc -> WonadUiBridge.nativeMode(dc) &&
            app(task, task.mWmService.mCurrentUserId) } == true

    /** Only leaves still on the departed display will fall through to stock
     * final-undock. Migrated hidden survivors on another monitor stay hidden. */
    @JvmStatic fun restoreUndockedFocus(task: Task, user: Int) {
        if (app(task, user)) task.setFocusable(true)
    }

    private fun leaseFor(wm: WindowManagerService, task: Task, user: Int,
        generation: Long, owner: IBinder, requireReady: Boolean = true): WonadUiBridge.NativeLease? {
        val dc = task.displayContent ?: return null
        return WonadUiBridge.nativeLease(wm, dc, requireReady)?.takeIf {
            it.user == user && it.generation == generation && it.owner == owner
        }
    }

    private fun taskOrder(dc: DisplayContent, user: Int): List<Task> {
        val tasks = mutableListOf<Task>()
        // Native enumeration is top-to-bottom. Exclude fixed UI and system
        // activities, then reverse for the public bottom-to-top rank.
        dc.forAllTasks(Consumer { task -> if (app(task, user)) tasks.add(task) })
        return tasks.asReversed()
    }

    @JvmStatic fun taskState(wm: WindowManagerService, user: Int, generation: Long,
        owner: IBinder?, tokens: Array<IBinder>?): LongArray {
        WonadUiBridge.enforceSystemUi(wm)
        require(owner != null && tokens != null && tokens.size <= MAX_TASKS &&
            tokens.toSet().size == tokens.size)
        val identity = Binder.clearCallingIdentity()
        return try { wm.withWonadGlobalLock {
            val tasks = tokens.map { token ->
                exactTask(token)?.takeIf { app(it, user) &&
                    leaseFor(wm, it, user, generation, owner, requireReady = false) != null }
                    ?: return@withWonadGlobalLock longArrayOf()
            }
            val orders = tasks.map { it.displayContent }.distinct().associateWith { taskOrder(it, user) }
            val remembered = tasks.map { logicalOrder[it] }
            val labelsValid = remembered.all { it != null && it.generation == generation && it.owner == owner } &&
                remembered.map { it!!.z }.toSet() == tasks.indices.toSet() &&
                orders.all { (dc, native) -> tasks.filter { it.displayContent === dc }
                    .sortedBy { logicalOrder.getValue(it).z } == native }
            val canonical = orders.keys.sortedBy { WonadUiBridge.attachment(it) }
                .flatMap { orders.getValue(it) }
            LongArray(tasks.size * 13).also { result -> tasks.forEachIndexed { index, task ->
                val rect = task.bounds
                val visible = !task.isForceHidden
                val nativeIdentity = taskIdentity(task)
                val row = longArrayOf(rect.left.toLong(), rect.top.toLong(), rect.right.toLong(),
                    rect.bottom.toLong(), task.minWidth.coerceAtLeast(0).toLong(),
                    task.minHeight.coerceAtLeast(0).toLong(), if (task.isResizeable) 1 else 0,
                    if (visible) 1 else 0, if (visible && task.isFocusable) 1 else 0,
                    (if (labelsValid) logicalOrder.getValue(task).z else canonical.indexOf(task)).toLong(),
                    WonadUiBridge.attachment(task.displayContent), nativeIdentity.token,
                    nativeIdentity.uid.toLong())
                row.copyInto(result, index * 13)
            } }
        } } finally { Binder.restoreCallingIdentity(identity) }
    }

    private fun scalar(value: Long): Int? = value.takeIf { it in Int.MIN_VALUE..Int.MAX_VALUE }?.toInt()
    private fun bool(value: Long): Boolean? = when (value) { 0L -> false; 1L -> true; else -> null }
    private fun rect(values: LongArray, offset: Int): Rect? {
        val coordinates = (offset until offset + 4).map { scalar(values[it]) ?: return null }
        val result = Rect(coordinates[0], coordinates[1], coordinates[2], coordinates[3])
        return result.takeIf { coordinates.all { value -> value in -32768..32768 } &&
            coordinates[2].toLong() - coordinates[0].toLong() in 1L..32768L &&
            coordinates[3].toLong() - coordinates[1].toLong() in 1L..32768L }
    }

    @JvmStatic fun applyFrame(wm: WindowManagerService, user: Int, generation: Long,
        owner: IBinder?, tokens: Array<IBinder>?, uids: IntArray?, current: LongArray?,
        desired: LongArray?): Boolean =
        applyFrameInternal(wm, user, generation, owner, tokens, uids, current, desired, false)

    /** Additive signed native geometry. Authentication, exact objects and all
     * shell/input bounds are unchanged; only ordinary app rectangles may lie
     * outside their selected external viewport. No raw surface reaches APKs. */
    @JvmStatic fun applySignedFrame(wm: WindowManagerService, user: Int, generation: Long,
        owner: IBinder?, tokens: Array<IBinder>?, uids: IntArray?, current: LongArray?,
        desired: LongArray?): Boolean =
        applyFrameInternal(wm, user, generation, owner, tokens, uids, current, desired, true)

    private fun applyFrameInternal(wm: WindowManagerService, user: Int, generation: Long,
        owner: IBinder?, tokens: Array<IBinder>?, uids: IntArray?, current: LongArray?,
        desired: LongArray?, signed: Boolean): Boolean {
        WonadUiBridge.enforceSystemUi(wm)
        if (owner == null || tokens == null || uids == null || current == null || desired == null ||
            tokens.size > MAX_TASKS || uids.size != tokens.size || tokens.toSet().size != tokens.size ||
            current.size !in 5..MAX_CURRENT || desired.size !in 7..MAX_DESIRED) return false
        val identity = Binder.clearCallingIdentity()
        return try { wm.withWonadGlobalLock {
            try { applyLocked(wm, user, generation, owner, tokens, uids, current, desired, signed) }
            catch (error: Exception) {
                // Fail closed even if a native constraint appeared during the
                // commit. The existing lease watchdog provides black/input
                // containment; no partial frame may be reported as applied.
                Log.e("WonadNative", "Native frame failed", error)
                WonadUiBridge.parkNative(wm, user, generation, owner)
                false
            }
        } } finally { Binder.restoreCallingIdentity(identity) }
    }

    private fun applyLocked(wm: WindowManagerService, user: Int, generation: Long,
        owner: IBinder, tokens: Array<IBinder>, uids: IntArray, current: LongArray,
        desired: LongArray, signed: Boolean): Boolean {
        if (interactionBlockedLocked(wm, user) || generation <= 0 ||
            current[0] != generation || desired[0] != generation ||
            current[1] != desired[1] || current[2] != desired[2]) return false
        val displayCount = scalar(current[3])?.takeIf { it in 1..9 } ?: return false
        val taskCount = scalar(current[4])?.takeIf { it in 0..MAX_TASKS } ?: return false
        val regionCount = scalar(desired[6])?.takeIf { it in 0..MAX_REGIONS } ?: return false
        if (taskCount != tokens.size || desired[5] != taskCount.toLong() ||
            current.size != 5 + displayCount * 9 + taskCount * 12 ||
            desired.size != 7 + taskCount * 9 + regionCount * 6) return false
        val displays = (0 until displayCount).map { index ->
            val offset = 5 + index * 9
            val token = current[offset]
            val id = scalar(current[offset + 1]) ?: return false
            val dc = wm.mRoot.getDisplayContent(id) ?: return false
            val lease = WonadUiBridge.nativeLease(wm, dc) ?: return false
            val bounds = rect(current, offset + 2) ?: return false
            val info = dc.displayInfo
            val secure = bool(current[offset + 7]) ?: return false
            if (token <= 0 || lease.incarnation != token || lease.user != user ||
                lease.generation != generation || lease.owner != owner ||
                bounds != Rect(0, 0, info.logicalWidth, info.logicalHeight) ||
                current[offset + 6] != info.logicalDensityDpi.toLong() ||
                secure != (info.flags and Display.FLAG_SECURE != 0) ||
                current[offset + 8] != shellGeneration(wm, dc)) return false
            DisplayRow(token, dc, lease, bounds, current[offset + 8])
        }
        if (displays.map { it.token }.toSet().size != displayCount ||
            displays.map { it.dc }.toSet().size != displayCount) return false
        val tasks = (0 until taskCount).map { index ->
            val offset = 5 + displayCount * 9 + index * 12
            val task = exactTask(tokens[index]) ?: return false
            val display = displays.singleOrNull { it.token == current[offset + 1] } ?: return false
            val bounds = rect(current, offset + 2) ?: return false
            val visible = bool(current[offset + 9]) ?: return false
            val input = bool(current[offset + 10]) ?: return false
            val resizeable = bool(current[offset + 8]) ?: return false
            val minWidth = scalar(current[offset + 6]) ?: return false
            val minHeight = scalar(current[offset + 7]) ?: return false
            val z = scalar(current[offset + 11]) ?: return false
            val nativeIdentity = taskIdentity(task)
            if (current[offset] != nativeIdentity.token || nativeIdentity.uid != uids[index] ||
                !app(task, user, uids[index]) ||
                task.displayContent !== display.dc || task.bounds != bounds ||
                resizeable != task.isResizeable || minWidth != task.minWidth.coerceAtLeast(0) ||
                minHeight != task.minHeight.coerceAtLeast(0) ||
                visible != !task.isForceHidden || input != (visible && task.isFocusable) ||
                input != visible || z !in 0 until taskCount) return false
            TaskRow(current[offset], task, uids[index], display.token, bounds,
                minWidth, minHeight, resizeable, visible, input, z)
        }
        if (tasks.map { it.opaque }.toSet().size != taskCount ||
            tasks.map { it.z }.toSet().size != taskCount) return false
        for (display in displays) {
            val native = taskOrder(display.dc, user)
            val supplied = tasks.filter { it.displayToken == display.token }.sortedBy { it.z }.map { it.task }
            if (native != supplied) return false // Complete exact leaves; no stale/truncated admission.
        }
        val placements = (0 until taskCount).map { index ->
            val offset = 7 + index * 9
            val observed = tasks.singleOrNull { it.opaque == desired[offset] } ?: return false
            val display = displays.singleOrNull { it.token == desired[offset + 1] } ?: return false
            val bounds = rect(desired, offset + 2) ?: return false
            val visible = bool(desired[offset + 6]) ?: return false
            val input = bool(desired[offset + 7]) ?: return false
            val z = scalar(desired[offset + 8]) ?: return false
            if ((!signed && !display.bounds.contains(bounds)) ||
                bounds.width().toLong() !in 1L..32768L || bounds.height().toLong() !in 1L..32768L ||
                visible != input || z !in 0 until taskCount ||
                bounds.width() < observed.minimumWidth || bounds.height() < observed.minimumHeight ||
                (!observed.resizable && (bounds.width() != observed.bounds.width() ||
                    bounds.height() != observed.bounds.height())) ||
                !observed.task.canBeLaunchedOnDisplay(display.dc.displayId)) return false
            Placement(observed, display, bounds, visible, input, z)
        }
        if (placements.map { it.observed.opaque }.toSet().size != taskCount ||
            placements.map { it.z }.toSet().size != taskCount) return false
        val regions = displays.associate { it.token to Region() }
        repeat(regionCount) { index ->
            val offset = 7 + taskCount * 9 + index * 6
            val display = displays.singleOrNull { it.token == desired[offset + 1] } ?: return false
            val bounds = rect(desired, offset + 2) ?: return false
            if (desired[offset] != generation || display.shell != generation ||
                display.dc.displayInfo.flags and Display.FLAG_SECURE == 0 ||
                !display.bounds.contains(bounds)) return false
            regions.getValue(display.token).op(bounds, Region.Op.UNION)
        }
        val focusDisplay = desired[3]
        val focusToken = desired[4]
        if (focusDisplay < 0 || focusToken < 0 || (focusDisplay == 0L && focusToken != 0L)) return false
        val target = if (focusDisplay == 0L) null else
            (displays.singleOrNull { it.token == focusDisplay } ?: return false)
        val selected = if (focusToken == 0L) null else (placements.singleOrNull {
            it.observed.opaque == focusToken && it.visible && it.input && it.display === target
        } ?: return false)
        // Keyboard selection cannot steal the phone's focus. A fresh actual
        // external mouse observation may authorize the APK's hover selection,
        // except while a trusted phone window owns input.
        if (target != null && !focusAllowed(wm, target, selected?.observed?.task)) return false
        val desktop = if (target != null && selected == null) {
            val plane = findPlane(wm, target.dc) ?: return false
            val activity = homeWindow(plane)?.mActivityRecord ?: return false
            if (desktopFrameRoot(target, activity) == null) return false
            activity
        } else null

        // A passive frame normalizes native z order, but does not request a
        // focus change. positionChildAt changes Android's preferred-root cache;
        // retain each actual app focus before sorting so it cannot resume the
        // last tile instead of the app just clicked by the user. A moved/hidden
        // or replaced app is never retained. Global/phone display order is not
        // changed by this local preservation.
        val retainedFocus = displays.filter { it !== target }.mapNotNull { display ->
            retainedFrameFocus(display, placements)?.let { display to it }
        }
        val retainedDesktopFocus = displays.filter { it !== target }.mapNotNull { display ->
            retainedDesktopFrameFocus(display)?.let { display to it }
        }

        wm.mAtmService.deferWindowLayout()
        try {
            for (placement in placements.sortedBy { it.z }) {
                val task = placement.observed.task
                val area = placement.display.dc.defaultTaskDisplayArea
                task.setAlwaysOnTop(false)
                task.setWindowingMode(WINDOWING_MODE_FREEFORM)
                if (task.parent !== area) task.reparent(area, true)
                check(task.parent === area) { "Native reparent was declined" }
                task.setBounds(placement.bounds)
                // SystemUI organizes root tasks, so stock WM deliberately
                // skips their surface positioning. This native adapter owns
                // that bounded transform on the direct default-TDA root; no
                // SurfaceControl or transform primitive is given to the APK.
                setTaskTransform(task, placement.bounds)
                task.setFocusable(placement.input)
                task.setForceHidden(TaskFragment.FLAG_FORCE_HIDDEN_FOR_WONAD_POLICY, !placement.visible)
                clearWithdrawnPreferredFocus(task)
                area.positionChildAt(WindowContainer.POSITION_TOP, task, false)
            }
            for ((display, activity) in retainedFocus) installFrameFocus(display, activity)
            for ((display, activity) in retainedDesktopFocus) installDesktopFrameFocus(display, activity)
            if (target != null) {
                if (selected != null) {
                    installFrameFocus(target, selected.observed.task.topRunningActivity()
                        ?: error("Native frame focus Activity disappeared"))
                } else {
                    installDesktopFrameFocus(target, desktop ?: error("Native desktop Activity disappeared"))
                }
            }
            logicalOrder.keys.retainAll(tasks.map { it.task }.toSet())
            placements.forEach { logicalOrder[it.observed.task] = LogicalOrder(generation, owner, it.z) }
            val layers = LayerFrame(user, generation, owner, current.copyOf(), desired.copyOf(),
                displays.map { display ->
                    val plane = findPlane(wm, display.dc) ?: error("Native layer plane disappeared")
                    LayerDisplay(display.lease, plane,
                        plane.window.mWinAnimator.mSurfaceControl ?: error("Native shell surface disappeared"),
                        plane.observer.mWinAnimator.mSurfaceControl ?: error("Native observer surface disappeared"),
                        placements.filter { it.display === display }.sortedBy { it.z }.map { placement ->
                            val task = placement.observed.task
                            LayerTask(task, task.topRunningActivity() ?: error("Native layer Activity disappeared"),
                                placement.observed.uid, placement.observed.opaque,
                                task.surfaceControl ?: error("Native app surface disappeared"),
                                Rect(placement.bounds), placement.visible, placement.input, placement.z)
                        })
                })
            layerFrame = layers
            for (display in displays) {
                val plane = findPlane(wm, display.dc) ?: error("Native shell disappeared")
                plane.regions.set(regions.getValue(display.token))
                display.dc.inputMonitor.setUpdateInputWindowsNeededLw()
                display.dc.inputMonitor.updateInputWindowsLw(true)
                display.dc.assignWindowLayers(false)
                display.dc.scheduleAnimation()
            }
            wm.mRoot.ensureActivitiesVisible()
            wm.mRoot.resumeFocusedTasksTopActivities()
            if (target != null) {
                // An explicit focus-monitor request can change the selected
                // external display, but never takes the phone's global focus.
                wm.mRoot.positionChildAt(WindowContainer.POSITION_TOP, target.dc, false)
                val plane = findPlane(wm, target.dc) ?: error("Native focus plane disappeared")
                plane.desktopFocus = selected == null
                plane.pointerTask = null
                plane.pointerTime = 0
                target.dc.setFocusedApp(selected?.observed?.task?.topRunningActivity() ?: desktop)
            }
            wm.updateFocusedWindowLocked(WindowManagerService.UPDATE_FOCUS_NORMAL, true)
            wm.mAtmService.mTaskSupervisor.updateTopResumedActivityIfNeeded("wonad-native-frame")
            // Final focus must be reflected in the SAME submitted input/layer
            // transaction. The earlier async update alone cannot prove this.
            layers.ready = true
            displays.forEach { it.dc.assignWindowLayers(false) }
        } finally { wm.mAtmService.continueWindowLayout() }
        return true
    }

    private fun invalidateLayers(display: LayerDisplay) {
        display.serial = Math.addExact(display.serial, 1L)
        display.submitted = false
        display.committed = false
        display.inputReported = false
        display.windows = emptyList()
    }

    /** No cache/label alone is native layer authority. In particular a reused
     * numeric display/task ID, replaced surface, sync transaction or animation
     * leash cannot inherit the last frame's completion proof. */
    private fun layerScopeValid(frame: LayerFrame, display: LayerDisplay): Boolean {
        val lease = display.lease
        val dc = lease.dc
        val wm = dc.mWmService
        val area = dc.defaultTaskDisplayArea
        val shellActivity = display.plane.window.mActivityRecord ?: return false
        if (layerFrame !== frame || display !in frame.displays || dc.displayId <= 0 ||
            wm.mCurrentUserId != frame.user || lease.user != frame.user ||
            lease.generation != frame.generation || lease.owner !== frame.owner ||
            wm.mRoot.getDisplayContent(dc.displayId) !== dc ||
            WonadUiBridge.nativeLease(wm, dc) != lease ||
            WonadUiBridge.attachment(dc) != lease.incarnation || planes[dc.displayId] !== display.plane ||
            display.plane.lease != lease || !transparentShellInput(shellActivity) ||
            shellActivity.task?.parent !== area || display.plane.window.displayContent !== dc ||
            display.plane.observer.displayContent !== dc || display.plane.observer.parentWindow !== display.plane.window ||
            display.plane.observer.mActivityRecord !== shellActivity ||
            display.plane.observer.owningUid != display.plane.window.owningUid ||
            interactionBlockedLocked(wm, frame.user) ||
            dc.mSyncState != WindowContainer.SYNC_STATE_NONE || dc.syncTransactionCommitCallbackDepth != 0 ||
            dc.mSurfaceAnimator.hasLeash() || !dc.mTransitionController.canAssignLayers(dc) ||
            display.plane.window.mWinAnimator.mSurfaceControl !== display.shellSurface ||
            display.plane.observer.mWinAnimator.mSurfaceControl !== display.observerSurface ||
            !display.shellSurface.isValid || !display.observerSurface.isValid ||
            !display.plane.window.mHasSurface || !display.plane.observer.mHasSurface ||
            !display.plane.window.isDrawn || !display.plane.observer.isDrawn ||
            !display.plane.window.mWinAnimator.shown || !display.plane.observer.mWinAnimator.shown ||
            display.tasks.size > MAX_TASKS || display.tasks.map { it.task }.toSet().size != display.tasks.size ||
            display.tasks.map { it.z }.toSet().size != display.tasks.size ||
            taskOrder(dc, frame.user) != display.tasks.map { it.task }) return false
        return display.tasks.all { entry ->
            val task = entry.task
            val native = identities[task]
            task.isRootTask && task.parent === area && task.displayContent === dc &&
                app(task, frame.user, entry.uid) && task.topRunningActivity() === entry.activity &&
                entry.activity.isAttached && !entry.activity.finishing && entry.activity.task === task &&
                entry.activity.displayContent === dc && entry.activity.mUserId == frame.user &&
                native != null && native.uid == entry.uid && native.token == entry.opaque &&
                task.surfaceControl === entry.surface && entry.surface.isValid &&
                task.bounds == entry.bounds && !task.isForceHidden == entry.visible &&
                task.isFocusable == entry.input &&
                entry.z in 0 until MAX_TASKS &&
                logicalOrder[task] == LogicalOrder(frame.generation, frame.owner, entry.z) &&
                task.mSyncState == WindowContainer.SYNC_STATE_NONE && task.syncTransactionCommitCallbackDepth == 0 &&
                !task.mSurfaceAnimator.hasLeash() && !task.inTransition() &&
                task.mTransitionController.canAssignLayers(task)
        }
    }

    private fun layerWindows(display: LayerDisplay): List<LayerWindow>? {
        val windows = mutableListOf<LayerWindow>()
        for (entry in display.tasks) {
            val window = entry.activity.findMainWindow()
            if (!entry.visible) {
                // A force-hidden label alone is not a native hide/input proof.
                // Wait for Android's visibility pass to withdraw the actual
                // app window; a stopped app may legitimately have no window.
                if (window != null && (window.isVisible || window.mWinAnimator.shown ||
                        window.canReceiveTouchInput())) return null
                continue
            }
            if (window == null) return null
            val surface = window.mWinAnimator.mSurfaceControl ?: return null
            if (window.mActivityRecord !== entry.activity || window.displayContent !== display.lease.dc ||
                window.owningUid != entry.uid || window.mAttrs.type != WindowManager.LayoutParams.TYPE_BASE_APPLICATION ||
                !window.mHasSurface || !window.isVisible || !window.isDrawn || !window.mWinAnimator.shown || !surface.isValid ||
                window.mInputChannelToken == null) return null
            windows.add(LayerWindow(window, surface))
        }
        return windows
    }

    private fun copiedLayerWindows(display: LayerDisplay): Boolean {
        return layerWindows(display) == display.windows && display.windows.all {
            !it.window.mInputWindowHandle.isChanged && !it.window.mInputWindowHandle.isPaused &&
                it.window.mInputWindowHandle.displayId == display.lease.dc.displayId
        }
    }

    private fun completeLayers(frame: LayerFrame, display: LayerDisplay, serial: Long, input: Boolean) {
        val wm = display.lease.dc.mWmService
        wm.withWonadGlobalLock {
            // Late callbacks from superseded/parked/surface-replaced frames are
            // ignored. Invalidation increments the serial before any resubmit.
            if (layerFrame !== frame || display.serial != serial || !display.submitted) return@withWonadGlobalLock
            if (!layerScopeValid(frame, display) || !copiedLayerWindows(display)) {
                invalidateLayers(display)
                return@withWonadGlobalLock
            }
            if (input) display.inputReported = true else display.committed = true
        }
    }

    private fun assignAppLayers(area: TaskDisplayArea, transaction: SurfaceControl.Transaction) {
        val frame = layerFrame ?: return
        val display = frame.displays.singleOrNull { it.lease.dc.defaultTaskDisplayArea === area } ?: return
        if (!layerScopeValid(frame, display)) {
            invalidateLayers(display)
            return
        }
        // Shell transitions intentionally skip ordinary root ordering. Only
        // these exact native-owned direct roots may bypass that stock skip.
        // A stock organizer/transition can overwrite a root's position/crop
        // after the initial bounds mutation. Maintain the SAME validated
        // finite transform as well as Z, after stock child traversal and in
        // the transaction covered by both native completion fences. This is
        // not a new placement: no bounds, visibility, focus, parent, workspace
        // or window flags change here. Never touch a replaced or leased root.
        display.tasks.forEach {
            setTaskTransform(it.task, it.bounds, transaction)
            transaction.setLayer(it.surface, it.z)
            // Stock package-update closing animations can leave the SAME
            // surviving ordinary root at alpha 0 after their finish fence.
            // Only this fully authenticated, transition-free visible frame
            // may normalize that root; hidden tasks and app/window alpha or
            // input flags remain untouched. Use the existing fenced layer
            // transaction, never an unfenced pending transaction or APK data.
            if (it.visible) transaction.setAlpha(it.surface, 1f)
        }
        if (!frame.ready || display.submitted) return
        val windows = layerWindows(display) ?: return
        display.lease.dc.inputMonitor.updateInputWindowsImmediately(transaction)
        display.windows = windows
        if (!copiedLayerWindows(display)) { invalidateLayers(display); return }
        display.serial = Math.addExact(display.serial, 1L)
        val serial = display.serial
        display.submitted = true
        val wm = display.lease.dc.mWmService
        transaction.addTransactionCommittedListener(Executor { wm.mH.post(it) }) {
            completeLayers(frame, display, serial, false)
        }
        transaction.addWindowInfosReportedListener {
            wm.mH.post { completeLayers(frame, display, serial, true) }
        }
    }

    private fun layersApplied(user: Int, generation: Long, owner: IBinder,
        current: LongArray, desired: LongArray): Boolean {
        val frame = layerFrame ?: return false
        if (frame.user != user || frame.generation != generation || frame.owner !== owner || !frame.ready ||
            !frame.current.contentEquals(current) || !frame.desired.contentEquals(desired)) return false
        for (display in frame.displays) {
            if (!layerScopeValid(frame, display)) {
                invalidateLayers(display)
                return false
            }
        }
        for (display in frame.displays) {
            if (!display.submitted) {
                // The accepted exact frame may have arrived before drawing or
                // while stock transitions held the layer transaction. Realize
                // only those SAME still-valid objects after they settle; never
                // reapply placements, visibility, focus, policy or authority.
                if (layerWindows(display) != null) display.lease.dc.assignWindowLayers(false)
                return false // Neither queueing nor cached order is completion.
            }
            if (!copiedLayerWindows(display)) {
                invalidateLayers(display)
                return false
            }
            if (!display.committed || !display.inputReported) return false
        }
        return true
    }

    private fun retainedFrameFocus(display: DisplayRow, placements: List<Placement>): ActivityRecord? {
        // A launch can select an Activity before its Window is created. The
        // last input Window may still be the launcher-close fallback; keeping
        // it while sorting would overwrite that newer native app selection.
        // A non-null but withdrawn selection must not resurrect the old Window.
        // This caller holds the WM lock and has authenticated the exact lease.
        val activity = display.dc.mFocusedApp
            ?: display.dc.mCurrentFocus?.mActivityRecord ?: return null
        val task = activity.task ?: return null
        return activity.takeIf { activity.isAttached && !activity.finishing &&
            app(task, display.lease.user) && task.topRunningActivity() === activity &&
            !task.isForceHidden && task.isFocusable && task.displayContent === display.dc &&
            placements.any { it.observed.task === task && it.display === display && it.visible && it.input } }
    }

    private fun installFrameFocus(display: DisplayRow, activity: ActivityRecord) {
        val task = activity.task ?: error("Native frame focus lost its exact Task")
        val area = display.dc.defaultTaskDisplayArea
        check(activity.isAttached && !activity.finishing && task.isAttached && task.isRootTask &&
            task.parent === area && task.displayContent === display.dc && activity.mUserId == display.lease.user &&
            !task.isForceHidden && task.isFocusable && task.topRunningActivity() === activity) {
            "Native frame focus no longer belongs to its selected exact display"
        }
        area.mPreferredTopFocusableRootTask = task
        display.dc.setFocusedApp(activity)
    }

    // Android's fixed HOME Activity lives in an ordinary leaf under a HOME
    // root, unlike the native application's direct default-TDA root. Resolve
    // that exact private ancestry without relaxing ordinary app admission.
    private fun desktopFrameRoot(display: DisplayRow, activity: ActivityRecord): Task? {
        val dc = display.dc
        val wm = dc.mWmService
        val lease = WonadUiBridge.nativeLease(wm, dc) ?: return null
        if (dc.displayId == Display.DEFAULT_DISPLAY || lease != display.lease) return null
        val plane = findPlane(wm, dc) ?: return null
        if (plane.lease != lease) return null
        val background = homeWindow(plane) ?: return null
        if (background.mActivityRecord !== activity || !background.isVisible ||
            !background.mWinAnimator.getShown()) return null
        val task = activity.task ?: return null
        val root = task.rootTask ?: return null
        return root.takeIf {
            activity.isAttached && !activity.finishing && activity.isActivityTypeHome &&
                activity.mUserId == lease.user && task.mUserId == lease.user && root.mUserId == lease.user &&
                task.isAttached && task.isLeafTask && task.isActivityTypeHome && !task.isForceHidden && task.isFocusable &&
                task.displayContent === dc && task.topRunningActivity() === activity &&
                root.isAttached && root.isRootTask && root.isActivityTypeHome && !root.isForceHidden && root.isFocusable &&
                root.parent === dc.defaultTaskDisplayArea && root.displayContent === dc &&
                root.topRunningActivity() === activity
        }
    }

    private fun installDesktopFrameFocus(display: DisplayRow, activity: ActivityRecord) {
        val root = desktopFrameRoot(display, activity)
            ?: error("Native desktop focus lost its exact ready HOME ancestry")
        display.dc.defaultTaskDisplayArea.mPreferredTopFocusableRootTask = root
        display.dc.setFocusedApp(activity)
    }

    /** A passive frame must preserve a previously explicit desktop focus as
     * well as app focus. Sorting hidden app roots can otherwise replace HOME's
     * preferred root and strand keyboard input on an invisible app. This only
     * retains the exact ready HOME already selected on this leased display;
     * it cannot select a workspace or take global focus from the phone.
     */
    private fun retainedDesktopFrameFocus(display: DisplayRow): ActivityRecord? {
        val plane = findPlane(display.dc.mWmService, display.dc) ?: return null
        if (plane.lease != display.lease || !plane.desktopFocus) return null
        val activity = display.dc.mFocusedApp ?: return null
        if (homeWindow(plane)?.mActivityRecord !== activity || desktopFrameRoot(display, activity) == null) return null
        return activity
    }

    /** Keep a focused external display key-addressable while its selected Task
     * is closed. ActivityTaskSupervisor starts the close transition inside
     * removeTask(); waiting until afterwards can expose a five-second interval
     * with no focused input Window, so a physical chord's remaining key-up
     * events can be blamed on the finishing application and trigger an ANR.
     *
     * Use the authenticated, drawn fixed HOME as a neutral input sink. Choosing
     * an application successor here would duplicate client workspace/focus
     * policy and could leak the chord's trailing modifier events to that app;
     * the client's next frame chooses the lasting focus. Closing a background
     * Task changes no focus.
     */
    private fun installCloseFallbackFocus(wm: WindowManagerService, task: Task?,
        lease: WonadUiBridge.NativeLease): Boolean {
        // null is private OS reconciliation of an authenticated finishing
        // launcher whose Task may already have detached, never an APK target.
        val dc = if (task == null) lease.dc else task.displayContent ?: return false
        if (task != null && dc.mFocusedApp?.task !== task &&
            dc.mCurrentFocus?.mActivityRecord?.task !== task) return true
        val plane = findPlane(wm, dc)?.takeIf { it.lease == lease } ?: return false
        val info = dc.displayInfo
        val row = DisplayRow(lease.incarnation, dc, lease,
            Rect(0, 0, info.logicalWidth, info.logicalHeight), lease.generation)
        val activity = homeWindow(plane)?.mActivityRecord ?: return false
        if (desktopFrameRoot(row, activity) == null) return false
        plane.desktopFocus = true
        plane.pointerTask = null
        plane.pointerTime = 0
        installDesktopFrameFocus(row, activity)
        wm.mRoot.resumeFocusedTasksTopActivities()
        wm.updateFocusedWindowLocked(WindowManagerService.UPDATE_FOCUS_NORMAL, true)
        wm.mAtmService.mTaskSupervisor.updateTopResumedActivityIfNeeded("wonad-native-close-fallback")
        return true
    }

    /** The ordinary launcher finishes through Activity.finish(), not our
     * operateTask close path. Stock can retain that finishing focusedApp after
     * its input window disappears, blocking the next chord until a focus ANR.
     * Reconcile only this exact fixed role to drawn, authenticated neutral HOME;
     * the APK still chooses any lasting application focus in its next frame.
     * Called by the existing WM-locked UI watchdog, whose failure path contains
     * and retires the exact claim. No new Binder/API or phone focus request.
     */
    internal fun reconcileClosingLauncherFocus(wm: WindowManagerService, dc: DisplayContent) {
        if (dc.displayId <= Display.DEFAULT_DISPLAY || dc.mWmService !== wm ||
            wm.mRoot.topFocusedDisplayContent !== dc) return
        val plane = findPlane(wm, dc) ?: return
        val lease = WonadUiBridge.nativeLease(wm, dc) ?: return
        if (plane.lease != lease || interactionBlockedLocked(wm, lease.user) ||
            protectedPhoneFocus(wm)) return
        val closing = dc.mFocusedApp ?: return
        val task = closing.task
        if (!closing.finishing || closing.mActivityComponent !in setOf(launcher, clientPrompt) ||
            closing.mUserId != lease.user || closing.uid != plane.window.owningUid ||
            closing.info.permission != COMPONENT_PERMISSION ||
            closing.intent.getLongExtra("generation", 0) != lease.generation ||
            (if (closing.mActivityComponent == launcher) closing.intent.getLongExtra("catalog", 0)
                else closing.intent.getLongExtra("request", 0)) <= 0 ||
            (task != null && task.displayContent !== dc) ||
            dc.mCurrentFocus != null) return
        // An undrawn HOME is not authority. Leave it for the next watchdog
        // pass, rather than manufacturing focus or a replacement Task.
        installCloseFallbackFocus(wm, null, lease)
    }

    /** Native confirmation is consumed by SystemUI/Rust before this private
     * call. Re-resolve the exact source Task; no APK-supplied numeric task ID or
     * component can be converted into import authority. */
    @JvmStatic fun transferTask(wm: WindowManagerService, user: Int, generation: Long,
        owner: IBinder?, token: IBinder?, expectedUid: Int, destination: Long): Boolean {
        WonadUiBridge.enforceSystemUi(wm)
        if (owner == null || token == null || destination <= 0) return false
        val identity = Binder.clearCallingIdentity()
        return try { wm.withWonadGlobalLock {
            if (interactionBlockedLocked(wm, user)) return@withWonadGlobalLock false
            val task = exactTask(token) ?: return@withWonadGlobalLock false
            val activity = task.topRunningActivity() ?: return@withWonadGlobalLock false
            val lease = WonadUiBridge.nativeLeases(wm).singleOrNull { it.user == user &&
                it.generation == generation && it.owner == owner && it.incarnation == destination }
                ?: return@withWonadGlobalLock false
            if (!task.isAttached || !task.isLeafTask || !task.isActivityTypeStandard ||
                task.mCreatedByOrganizer || task.mUserId != user || task.displayId != Display.DEFAULT_DISPLAY ||
                task.isForceHidden || activity.uid != expectedUid || UserHandle.getUserId(expectedUid) != user ||
                UserHandle.getAppId(expectedUid) !in 10000..19999 ||
                activity.packageName in setOf(PACKAGE, "android", "com.android.systemui",
                    "com.android.permissioncontroller") || !task.isResizeable ||
                !task.canBeLaunchedOnDisplay(lease.dc.displayId)) return@withWonadGlobalLock false
            val info = lease.dc.displayInfo
            val bounds = Rect(0, 0, info.logicalWidth, info.logicalHeight)
            if (task.minWidth > bounds.width() || task.minHeight > bounds.height())
                return@withWonadGlobalLock false
            val phone = wm.mRoot.getDisplayContent(Display.DEFAULT_DISPLAY) ?: return@withWonadGlobalLock false
            val phoneFocus = phone.mFocusedApp?.takeIf { it.task !== task }
            try {
                wm.mAtmService.deferWindowLayout()
                try {
                task.setAlwaysOnTop(false)
                task.setWindowingMode(WINDOWING_MODE_FREEFORM)
                val area = lease.dc.defaultTaskDisplayArea
                task.reparent(area, true)
                check(task.parent === area && task.displayContent === lease.dc) { "Native transfer was declined" }
                task.setBounds(bounds)
                setTaskTransform(task, bounds)
                task.setFocusable(true)
                task.setForceHidden(TaskFragment.FLAG_FORCE_HIDDEN_FOR_WONAD_POLICY, false)
                phone.setFocusedApp(phoneFocus)
                wm.mRoot.ensureActivitiesVisible()
                wm.mRoot.resumeFocusedTasksTopActivities()
                wm.updateFocusedWindowLocked(WindowManagerService.UPDATE_FOCUS_NORMAL, true)
                wm.mAtmService.mTaskSupervisor.updateTopResumedActivityIfNeeded("wonad-native-transfer")
                } finally { wm.mAtmService.continueWindowLayout() }
                true
            } catch (error: Exception) {
                Log.e("WonadNative", "Native transfer failed", error)
                WonadUiBridge.parkNative(wm, user, generation, owner)
                false
            }
        } } finally { Binder.restoreCallingIdentity(identity) }
    }

    /** Completion observation, separate from mutation ACK. Check exact current
     * native objects/order/bounds and registered WindowHandle regions after
     * they have been copied into the surface's input transaction. Runtime
     * gates additionally test real InputDispatcher delivery and viewer pixels.
     */
    @JvmStatic fun frameApplied(wm: WindowManagerService, user: Int, generation: Long,
        owner: IBinder?, tokens: Array<IBinder>?, uids: IntArray?, current: LongArray?,
        desired: LongArray?): Boolean {
        WonadUiBridge.enforceSystemUi(wm)
        if (owner == null || tokens == null || uids == null || current == null || desired == null ||
            tokens.size > MAX_TASKS || uids.size != tokens.size || current.size !in 5..MAX_CURRENT ||
            desired.size !in 7..MAX_DESIRED || current[0] != generation || desired[0] != generation ||
            current[1] != desired[1] || current[2] != desired[2] ||
            desired[5] != tokens.size.toLong()) return false
        val identity = Binder.clearCallingIdentity()
        return try { wm.withWonadGlobalLock {
            if (interactionBlockedLocked(wm, user)) return@withWonadGlobalLock false
            val count = scalar(current[3])?.takeIf { it in 1..9 } ?: return@withWonadGlobalLock false
            val regionsCount = scalar(desired[6])?.takeIf { it in 0..MAX_REGIONS }
                ?: return@withWonadGlobalLock false
            if (current[4] != tokens.size.toLong() || current.size != 5 + count * 9 + tokens.size * 12 ||
                desired.size != 7 + tokens.size * 9 + regionsCount * 6) return@withWonadGlobalLock false
            val leases = WonadUiBridge.nativeLeases(wm).filter {
                it.user == user && it.generation == generation && it.owner == owner }
            val byToken = leases.associateBy { it.incarnation }
            if (byToken.size != count) return@withWonadGlobalLock false
            repeat(count) { index ->
                val offset = 5 + index * 9
                val lease = byToken[current[offset]] ?: return@withWonadGlobalLock false
                val info = lease.dc.displayInfo
                if (current[offset + 1] != lease.dc.displayId.toLong() ||
                    rect(current, offset + 2) != Rect(0, 0, info.logicalWidth, info.logicalHeight) ||
                    current[offset + 6] != info.logicalDensityDpi.toLong() ||
                    current[offset + 8] != shellGeneration(wm, lease.dc)) return@withWonadGlobalLock false
            }
            val nativeTasks = tokens.mapIndexed { index, token ->
                exactTask(token)?.takeIf { app(it, user, uids[index]) }
                    ?: return@withWonadGlobalLock false
            }
            if (nativeTasks.indices.any { index ->
                val nativeIdentity = taskIdentity(nativeTasks[index])
                nativeIdentity.uid != uids[index] ||
                    nativeIdentity.token != current[5 + count * 9 + index * 12]
            }) return@withWonadGlobalLock false
            if (!layersApplied(user, generation, owner, current, desired)) return@withWonadGlobalLock false
            val desiredOrder = linkedMapOf<Task, Int>()
            repeat(tokens.size) { index ->
                val offset = 7 + index * 9
                val opaque = desired[offset]
                val currentIndex = (tokens.indices).singleOrNull {
                    current[5 + count * 9 + it * 12] == opaque } ?: return@withWonadGlobalLock false
                val task = nativeTasks[currentIndex]
                val lease = byToken[desired[offset + 1]] ?: return@withWonadGlobalLock false
                val visible = bool(desired[offset + 6]) ?: return@withWonadGlobalLock false
                val input = bool(desired[offset + 7]) ?: return@withWonadGlobalLock false
                val z = scalar(desired[offset + 8]) ?: return@withWonadGlobalLock false
                if (task.displayContent !== lease.dc || task.bounds != rect(desired, offset + 2) ||
                    !task.isForceHidden != visible || (visible && task.isFocusable) != input ||
                    logicalOrder[task] != LogicalOrder(generation, owner, z) ||
                    desiredOrder.put(task, z) != null) return@withWonadGlobalLock false
            }
            val expectedRegions = byToken.mapValues { Region() }
            repeat(regionsCount) { index ->
                val offset = 7 + tokens.size * 9 + index * 6
                if (desired[offset] != generation) return@withWonadGlobalLock false
                val union = expectedRegions[desired[offset + 1]] ?: return@withWonadGlobalLock false
                val rectangle = rect(desired, offset + 2) ?: return@withWonadGlobalLock false
                union.op(rectangle, Region.Op.UNION)
            }
            for (lease in leases) {
                val plane = findPlane(wm, lease.dc) ?: return@withWonadGlobalLock false
                if (launcherWindow(plane) != null) return@withWonadGlobalLock false
                val fullRegion = Region(0, 0, lease.dc.displayInfo.logicalWidth,
                    lease.dc.displayInfo.logicalHeight)
                val inputRegion = if (plane.meta) fullRegion else plane.regions
                if (!plane.regions.equals(expectedRegions.getValue(lease.incarnation)) ||
                    !plane.window.mInputWindowHandle.hasWonadRegion(inputRegion) ||
                    !plane.observer.mInputWindowHandle.hasWonadObserver(fullRegion) ||
                    taskOrder(lease.dc, user) != desiredOrder.keys.filter { it.displayContent === lease.dc }
                        .sortedBy { desiredOrder.getValue(it) }) return@withWonadGlobalLock false
            }
            if (desired[3] != 0L) {
                val focused = byToken[desired[3]] ?: return@withWonadGlobalLock false
                if (wm.mRoot.topFocusedDisplayContent !== focused.dc) return@withWonadGlobalLock false
                if (desired[4] != 0L) {
                    val index = tokens.indices.singleOrNull {
                        current[5 + count * 9 + it * 12] == desired[4] } ?: return@withWonadGlobalLock false
                    if (focused.dc.mCurrentFocus?.mActivityRecord?.task !== nativeTasks[index])
                        return@withWonadGlobalLock false
                } else {
                    val plane = planes[focused.dc.displayId] ?: return@withWonadGlobalLock false
                    if (!plane.desktopFocus || focused.dc.mCurrentFocus?.mActivityRecord !==
                        homeWindow(plane)?.mActivityRecord || focused.dc.mCurrentFocus == null)
                        return@withWonadGlobalLock false
                }
            }
            true
        } } finally { Binder.restoreCallingIdentity(identity) }
    }

    /** Exact ordinary app focus/close, never a phone/native-ID import. */
    @JvmStatic fun operateTask(wm: WindowManagerService, user: Int, generation: Long,
        owner: IBinder?, token: IBinder?, expectedUid: Int, close: Boolean): Boolean {
        WonadUiBridge.enforceSystemUi(wm)
        if (owner == null || token == null) return false
        val identity = Binder.clearCallingIdentity()
        return try { wm.withWonadGlobalLock {
            if (interactionBlockedLocked(wm, user)) return@withWonadGlobalLock false
            val task = exactTask(token) ?: return@withWonadGlobalLock false
            val lease = leaseFor(wm, task, user, generation, owner)
            if (!app(task, user, expectedUid) || lease == null)
                return@withWonadGlobalLock false
            if (close) {
                // removeTask requests the close transition synchronously.
                // Publish a validated replacement focus first so there is
                // never an externally observable null-focus interval.
                if (!installCloseFallbackFocus(wm, task, lease)) return@withWonadGlobalLock false
                wm.mAtmService.mTaskSupervisor.removeTask(task, false, true, "wonad-native-close")
                wm.mRoot.ensureActivitiesVisible()
                wm.mRoot.resumeFocusedTasksTopActivities()
                wm.updateFocusedWindowLocked(WindowManagerService.UPDATE_FOCUS_NORMAL, true)
                wm.mAtmService.mTaskSupervisor.updateTopResumedActivityIfNeeded("wonad-native-close")
            } else {
                val info = lease.dc.displayInfo
                val display = DisplayRow(lease.incarnation, lease.dc, lease,
                    Rect(0, 0, info.logicalWidth, info.logicalHeight), generation)
                if (task.isForceHidden || !task.isFocusable || !focusAllowed(wm, display, task))
                    return@withWonadGlobalLock false
                planes[task.displayId]?.let { it.desktopFocus = false; it.pointerTask = null; it.pointerTime = 0 }
                wm.mRoot.positionChildAt(WindowContainer.POSITION_TOP, task.displayContent, false)
                task.displayContent.setFocusedApp(task.topRunningActivity())
                wm.updateFocusedWindowLocked(WindowManagerService.UPDATE_FOCUS_NORMAL, true)
                wm.mAtmService.mTaskSupervisor.updateTopResumedActivityIfNeeded("wonad-native-focus")
            }
            true
        } } finally { Binder.restoreCallingIdentity(identity) }
    }

    /** Remove only a DROP_INPUT bit that this adapter added on the preceding
     * population. This runs before every exit, so moving the same wrapper to an
     * unclaimed/phone/null display or renewing its lease cannot strand input. */
    private fun restoreOwnedAppInput(handle: InputWindowHandleWrapper) {
        if (ownedAppInputDrops.remove(handle) == true)
            handle.setInputConfigMasked(0, InputConfig.DROP_INPUT)
    }

    /** After stock population, a sticky native display without a valid lease
     * must not publish a fresh app input handle. Preserve every stock flag and
     * remember ownership only if this call changed DROP_INPUT from false. */
    private fun blockUnleasedAppInput(handle: InputWindowHandleWrapper) {
        if (handle.setInputConfigMasked(InputConfig.DROP_INPUT, InputConfig.DROP_INPUT))
            ownedAppInputDrops[handle] = true
    }

    /** Always applied after Android's default window-input computation. */
    @JvmStatic fun configureInput(wm: WindowManagerService, window: WindowState,
        handle: InputWindowHandleWrapper) {
        restoreOwnedAppInput(handle)
        val dc = window.displayContent ?: return
        if (!WonadUiBridge.nativeMode(dc)) return
        if (window.mActivityRecord?.mActivityComponent != component) {
            clipNativeAppInput(wm, window, handle)
            return
        }
        val plane = planes[dc.displayId]
        val live = WonadUiBridge.nativeLease(wm, dc)
        if (plane == null || plane.lease.dc !== dc || plane.lease != live ||
            (window !== plane.window && window !== plane.observer) || launcherWindow(plane) != null ||
            interactionBlockedLocked(wm, plane.lease.user) || protectedPhoneFocus(wm)) {
            dropInput(handle)
            return
        }
        val observing = window === plane.observer
        val region = if (observing || plane.meta) Region(0, 0, dc.displayInfo.logicalWidth,
            dc.displayInfo.logicalHeight) else plane.regions
        handle.setFocusable(false)
        handle.setReplaceTouchableRegionWithCrop(false)
        handle.setTouchableRegionCrop(null)
        handle.setTouchableRegion(region)
        val config = (if (region.isEmpty) InputConfig.NOT_TOUCHABLE else 0) or
            (if (observing) InputConfig.SPY else 0)
        handle.setInputConfigMasked(config, InputConfig.NOT_TOUCHABLE or InputConfig.SPY or InputConfig.DROP_INPUT)
        // This narrowly registered external WM plane is transparent over app
        // content. Without trust Android blocks underlying input as obscured.
        // Trust is never granted on display0, outside a live authenticated UI
        // lease, to another APK component, or through a client-supplied flag.
        handle.setTrustedOverlay(true)
    }

    /** Task coordinates may be signed; pointer authority may not leave the
     * actual viewport. With a live lease, preserve Android's app-provided region,
     * modal behavior, global-scale mapping and root crop, then intersect in
     * surface coordinates without changing focus/trust/drop flags. The
     * no-lease branch above this clipping operation adds only Wonad-owned
     * DROP_INPUT, and this method never touches the phone. */
    private fun clipNativeAppInput(wm: WindowManagerService, window: WindowState,
        handle: InputWindowHandleWrapper) {
        val dc = window.displayContent ?: return
        val lease = WonadUiBridge.nativeLease(wm, dc) ?: run {
            blockUnleasedAppInput(handle)
            return
        }
        val task = window.task ?: return
        if (dc.displayId <= 0 || !app(task, lease.user) || task.displayContent !== dc) return
        val root = task.rootTask ?: return
        if (!root.isAttached || root.displayContent !== dc) return
        val frame = window.frame
        // The window's layout basis may carry an existing fixed-rotation
        // transform during import. Android's own region uses this same basis.
        val info = window.displayInfo
        val viewport = Region(-frame.left, -frame.top,
            info.logicalWidth - frame.left, info.logicalHeight - frame.top)
        if (window.mInvGlobalScale != 1f) viewport.scale(window.mInvGlobalScale)
        val region = Region()
        window.getSurfaceTouchableRegion(region, window.mAttrs)
        region.op(viewport, Region.Op.INTERSECT)
        handle.setReplaceTouchableRegionWithCrop(false)
        handle.setTouchableRegionCrop(root.surfaceControl)
        handle.setTouchableRegion(region)
    }

    /** No Binder callback/WM lock on InputDispatcher's thread. A modifier
     * transition posts a generation/object-scoped region update to WM's handler.
     * Gesture ownership remains InputDispatcher's ordinary down-to-up stream. */
    @JvmStatic fun observeMeta(event: KeyEvent, display: Int, requiredModifiers: Int = KeyEvent.META_META_ON,
        strictModifiers: Boolean = false) {
        val route = routes[display] ?: return
        val held = org.wonad.server.input.ShortcutModifiers.held(event.keyCode,
            event.action, event.metaState, event.isCanceled, requiredModifiers, strictModifiers)
        route.wm.mH.post { route.wm.withWonadGlobalLock {
            val plane = planes[display] ?: return@withWonadGlobalLock
            val lease = WonadUiBridge.nativeLease(route.wm, route.dc) ?: return@withWonadGlobalLock
            if (plane.lease.dc !== route.dc || lease.generation != route.generation ||
                lease.incarnation != route.incarnation || lease.owner != route.owner ||
                route.wm.mRoot.topFocusedDisplayContent !== route.dc ||
                interactionBlockedLocked(route.wm, lease.user) || protectedPhoneFocus(route.wm) ||
                launcherWindow(plane) != null) return@withWonadGlobalLock
            if (plane.meta != held) {
                plane.meta = held
                route.dc.inputMonitor.setUpdateInputWindowsNeededLw()
                route.dc.inputMonitor.updateInputWindowsLw(true)
                route.dc.scheduleAnimation()
            }
        } }
    }

    @JvmStatic fun onFocusChanged(wm: WindowManagerService) {
        val focused = wm.mRoot.topFocusedDisplayContent
        for (plane in planes.values) {
            val blocked = interactionBlockedLocked(wm, plane.lease.user) || protectedPhoneFocus(wm)
            if (plane.desktopFocus && plane.lease.dc.mFocusedApp?.mActivityComponent != home)
                plane.desktopFocus = false
            // A launcher on the SAME display must release a latched Meta
            // full-plane capture even when its picker disabled shortcut input
            // before the Meta-up event arrived.
            val launcherActive = launcherWindow(plane) != null
            if ((plane.meta && plane.lease.dc !== focused) || launcherActive ||
                blocked != plane.interactionBlocked) {
                plane.meta = false
                plane.pointerTask = null
                plane.pointerTime = 0
                plane.interactionBlocked = blocked
                plane.lease.dc.inputMonitor.setUpdateInputWindowsNeededLw()
                plane.lease.dc.inputMonitor.updateInputWindowsLw(true)
            }
        }
        WonadUiBridge.reconcileProtectedInput(wm)
    }

    /** Native application roots plus fixed UI layers, all resolved privately
     * from the exact current lease. No client-selected surface is accepted. */
    @JvmStatic fun assignShellLayers(area: TaskDisplayArea, transaction: SurfaceControl.Transaction) {
        assignAppLayers(area, transaction)
        val dc = area.displayContent ?: return
        val plane = findPlane(dc.mWmService, dc) ?: return
        val task = plane.window.mActivityRecord?.task ?: return
        if (task.parent === area) task.assignLayer(transaction, Int.MAX_VALUE - 3)
        // Empty-background focus can raise HOME in the logical hierarchy.
        // Keep only our authenticated Home behind native applications; the
        // corresponding visibility helper also prevents it stopping them.
        homeWindow(plane)?.mActivityRecord?.let { activity ->
            val root = activity.task?.rootTask
            if (root != null && root.parent === area && root.topRunningActivity() === activity &&
                ignoreNativeHomeOcclusion(task, root)) root.assignLayer(transaction, -1)
        }
        // Raise only the fixed authenticated ordinary launcher, never an app
        // or system window chosen by client data. It must be above shell rings
        // and below the OS-owned black/input containment layer.
        launcherWindow(plane)?.mActivityRecord?.task?.takeIf { it.parent === area }
            ?.assignLayer(transaction, Int.MAX_VALUE - 2)
    }

    @JvmStatic fun onParked(dc: DisplayContent) {
        val failures = WonadCleanupFailures()
        val parked = planes[dc.displayId]?.takeIf { it.lease.dc === dc }
        if (layerFrame?.displays?.any { it.lease.dc === dc } == true) layerFrame = null
        parked?.let { plane ->
            // SPY windows can observe input even behind an input consumer.
            // Withdraw them in the SAME WM surface transaction as blanking,
            // rather than relying on a later focus/input-population pass.
            failures.attempt { retirePlaneInput(plane) }
            // A reentrant native callback must not remove a replacement plane.
            if (planes[dc.displayId] === plane) planes.remove(dc.displayId)
        }
        failures.attempt { publishRoutes() }
        failures.attempt { logicalOrder.entries.removeAll { (task, order) ->
            !task.isAttached || (task.displayContent === dc &&
                (parked == null || (order.generation == parked.lease.generation && order.owner === parked.lease.owner)))
        } }
        failures.rethrowFatal()
        failures.supportedFailure?.let { throw it }
    }

    private fun dropInput(handle: InputWindowHandleWrapper) {
        handle.setFocusable(false)
        handle.clearTouchableRegion()
        handle.setInputConfigMasked(InputConfig.DROP_INPUT or InputConfig.NOT_TOUCHABLE,
            InputConfig.SPY or InputConfig.DROP_INPUT or InputConfig.NOT_TOUCHABLE)
        handle.setTrustedOverlay(false)
    }

    @JvmStatic fun onRemoved(dc: DisplayContent) = onParked(dc)
}
