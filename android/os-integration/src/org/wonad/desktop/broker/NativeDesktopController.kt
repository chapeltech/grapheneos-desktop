package org.wonad.desktop.broker

import android.app.ActivityManager
import android.app.ActivityManager.RunningTaskInfo
import android.app.ActivityOptions
import android.app.ActivityTaskManager
import android.app.WindowConfiguration.ACTIVITY_TYPE_STANDARD
import android.app.WindowConfiguration.WINDOWING_MODE_FREEFORM
import android.app.WindowConfiguration.WINDOWING_MODE_FULLSCREEN
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.LauncherApps
import android.graphics.Rect
import android.hardware.display.DisplayManager
import android.net.Uri
import android.os.Binder
import android.os.IBinder
import android.os.PowerManager
import android.os.Process
import android.os.SystemClock
import android.os.UserHandle
import android.util.Log
import android.view.Display
import android.view.WindowManagerGlobal
import com.android.internal.policy.IShortcutService
import com.android.wm.shell.ShellTaskOrganizer
import com.android.wm.shell.common.DisplayController
import com.android.wm.shell.common.ShellExecutor
import java.util.ArrayDeque
import java.util.IdentityHashMap
import java.util.concurrent.Semaphore
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.wonad.desktop.api.*

/** Workspace-free OS adapter. The APK owns all workspace/layout/floating/panel
 * policy. Rust admits authority and bounded scalar frames; this adapter only
 * resolves fresh native objects and observes their actual application.
 *
 * There are deliberately no DesktopTasksController, DesksOrganizer, desk IDs,
 * client Intent/taskId, native surface handles or input channels here. Parent
 * WonadController supplies the authorization predicate and serial executor.
 */
internal class NativeDesktopController(
    private val context: Context,
    private val executor: ShellExecutor,
    @Suppress("unused") private val organizer: ShellTaskOrganizer,
    private val displayController: DisplayController,
    private val identity: (Int) -> Identity?,
    private val retainedIdentity: (Int, Int) -> Identity?,
    private val enabled: (Int) -> Boolean,
    private val locked: () -> Boolean,
    private val activeUser: () -> Int,
    private val operational: () -> Boolean,
    private val shortcutAvailable: () -> Boolean,
    private val signedPlacementAvailable: () -> Boolean,
    private val authorized: (Int) -> Unit,
) {
    data class Identity(val uid: Int, val user: Int, val signer: ByteArray)
    private data class Monitor(val token: Long, val id: Int, val bounds: Rect,
        val density: Int, val secure: Boolean, val shellGeneration: Long, val identityHint: Long)
    private data class Binding(val token: Long, val taskId: Int, val binder: IBinder, val uid: Int)
    private data class Observation(val snapshot: DesktopSnapshot, val running: Map<Long, RunningTaskInfo>)
    private class StaleNativeObservation : IllegalStateException("Native task/display observation changed")
    private data class Pending(val request: Long, val topology: Long, val deadline: Long,
        val desired: LongArray? = null, val focusToken: Long = 0, val closeToken: Long = 0,
        val capturedCurrent: LongArray? = null, val taskBinders: Array<IBinder>? = null,
        val taskUids: IntArray? = null)
    private data class PhoneBinding(val id: Int, val binder: IBinder, val uid: Int,
        val user: Int, val component: ComponentName) {
        fun matches(task: RunningTaskInfo): Boolean = task.taskId == id && task.token.asBinder() == binder &&
            task.userId == user && task.topActivity == component && task.topActivityInfo?.applicationInfo?.uid == uid
    }
    private data class Choice(val item: WonadPickerUi.Item, val component: ComponentName,
        val uid: Int, val phone: PhoneBinding? = null)
    private class Pick(val id: Long, val displayToken: Long, val kind: Int, val choices: List<Choice>, val expires: Long) {
        val ui = WonadPickerUi.Handle()
        var shown = false
        var confirming = false
        var phone: PhoneBinding? = null
        var importing: IBinder? = null
        var cookie = false
        var importDeadline = 0L
    }
    private class ClientPrompt(val request: Long, val display: Long, val deadline: Long) {
        var seen = false
    }

    companion object {
        private const val TAG = "WonadNativeBroker"
        private const val PACKAGE = "org.wonad.desktop"
        private const val FIXED_UI_PERMISSION = "android.permission.STATUS_BAR_SERVICE"
        private const val NATIVE_TASK_LIMIT = DesktopProtocol.MAX_TASKS * 2
        private const val POLL_MILLIS = 50L
        private const val BROKER_QUEUE_LIMIT = 32
        private const val CALLBACK_QUEUE_LIMIT = 64
        private const val CALLBACK_WORKER_LIMIT = 4
        private const val CALLBACK_TIMEOUT_MILLIS = DesktopProtocol.CLIENT_TIMEOUT_MILLIS
        private const val SHELL_GENERATION = "org.wonad.desktop.shell.GENERATION"
        private const val SHELL_DISPLAY_TOKEN = "org.wonad.desktop.shell.DISPLAY_TOKEN"
    }

    private val displayManager = context.getSystemService(DisplayManager::class.java)
    private val power = context.getSystemService(PowerManager::class.java)
    private val launcher = context.getSystemService(LauncherApps::class.java)
    private val pickerUi = WonadPickerUi(context)
    private val queueSlots = Semaphore(BROKER_QUEUE_LIMIT)
    private val callbackThread = AtomicInteger()
    /** A wedged remote callback can consume one worker, never Shell's serial
     * executor. The pool and every per-session queue are independently bounded. */
    private val callbackExecutor = ThreadPoolExecutor(0, CALLBACK_WORKER_LIMIT, 60L, TimeUnit.SECONDS,
        SynchronousQueue<Runnable>()) { task ->
        Thread(task, "WonadNativeCallback-${callbackThread.incrementAndGet()}").apply { isDaemon = true }
    }
    private val callbackFlightLock = Any()
    private val callbackFlights = IdentityHashMap<Session, Long>()
    private val callbackWorkers = IdentityHashMap<Session, Int>()
    private var monitors = emptyList<Monitor>()
    private var topologyRevision = 0L
    @Volatile private var session: Session? = null // Written by Shell; checked at Binder entry too.
    private var refreshQueued = false

    private fun shellLaunchOptions(display: Int): ActivityOptions {
        require(display > 0)
        return ActivityOptions.makeBasic().apply {
            setLaunchDisplayId(display)
            setLaunchWindowingMode(WINDOWING_MODE_FULLSCREEN)
            // Installing the nonfocusable fixed plane is not an external
            // app launch or monitor-selection request. Keep existing phone
            // or monitor keyboard focus while the plane draws behind apps.
            setAvoidMoveToFront()
        }
    }

    /** A configuration change can briefly invalidate the existing plane's
     * draw barrier. A second showShell must address that SAME fixed document,
     * not create a competing Activity that makes WM's single-plane check fail.
     * The key comes only from the authenticated generation/physical attachment;
     * Android's ordinary document-task matching preserves separate monitors.
     */
    private fun shellLaunchIntent(component: ComponentName, generation: Long, displayToken: Long): Intent {
        require(component == ComponentName(PACKAGE, "$PACKAGE${DesktopProtocol.SHELL_ACTIVITY}") &&
            generation > 0 && displayToken > 0)
        return Intent().setComponent(component).setData(Uri.parse("wonad-shell://$generation/$displayToken"))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NEW_DOCUMENT)
            .putExtra(SHELL_GENERATION, generation).putExtra(SHELL_DISPLAY_TOKEN, displayToken)
    }

    val capabilities: Long get() = DesktopProtocol.CAP_FRAME or DesktopProtocol.CAP_SHELL or
        DesktopProtocol.CAP_EXTERNAL_UI or DesktopProtocol.CAP_APK_LAUNCHER or
        DesktopProtocol.CAP_TRANSFER_PICKER or (if (shortcutAvailable()) DesktopProtocol.CAP_SHORTCUTS else 0L) or
        (if (signedPlacementAvailable()) DesktopProtocol.CAP_SIGNED_PLACEMENT else 0L) or
        DesktopProtocol.CAP_CLIENT_PROMPT or
        (if (shortcutAvailable()) DesktopProtocol.CAP_SHORTCUT_KEYS else 0L)

    fun isActive(): Boolean = session != null

    /** Track the exact session whose one-way Binder transaction is executing.
     * A timeout first parks/revokes its desktop, then kills only the dedicated,
     * still-authenticated Wonad UID. Binder death releases the bounded worker;
     * replacement admission is barred until that delivery actually exits. */
    private fun callbackStarted(live: Session, delivery: Long) {
        synchronized(callbackFlightLock) { callbackFlights[live] = delivery }
        executor.execute { live.armCallbackWatchdog(delivery) }
    }

    private fun callbackFinished(live: Session, delivery: Long) {
        synchronized(callbackFlightLock) {
            if (callbackFlights[live] == delivery) callbackFlights.remove(live)
        }
        executor.execute { live.disarmCallbackWatchdog(delivery) }
    }

    private fun callbackActive(live: Session) = synchronized(callbackFlightLock) {
        callbackWorkers[live] = (callbackWorkers[live] ?: 0) + 1
    }

    private fun callbackIdle(live: Session) = synchronized(callbackFlightLock) {
        val remaining = (callbackWorkers[live] ?: 1) - 1
        if (remaining <= 0) callbackWorkers.remove(live) else callbackWorkers[live] = remaining
    }

    private fun callbackRecoveryBusy(): Boolean = synchronized(callbackFlightLock) {
        callbackWorkers.isNotEmpty() || callbackFlights.isNotEmpty()
    }

    private fun callbackTimedOut(live: Session, delivery: Long) {
        if (!live.callbackInFlight(delivery)) return
        val failure = IllegalStateException("Wonad callback delivery timed out")
        if (session === live)
            revoke(DesktopProtocol.REVOKED_CLIENT_FAILED, initiatingFailure = failure)
        // isInFlight proves that the original recipient transaction has not
        // returned. The owner was admitted only as the sole package on a
        // non-shared application UID, so kill exactly that stored UID;
        // active-user transition must not strand an old callback worker.
        val actual = try { retainedIdentity(live.owner.uid, live.owner.user) }
            catch (error: Exception) {
                failure.addSuppressed(error)
                Log.e(TAG, "Could not revalidate hung callback owner", error)
                null
            } catch (error: LinkageError) {
                failure.addSuppressed(error)
                Log.e(TAG, "Callback-owner identity API unavailable", error)
                null
            }
        if (actual == null || actual.uid != live.owner.uid || actual.user != live.owner.user ||
            !actual.signer.contentEquals(live.owner.signer)) {
            Log.e(TAG, "Refusing to kill a changed callback owner", failure)
            return
        }
        try {
            ActivityManager.getService().killUid(UserHandle.getAppId(live.owner.uid), live.owner.user,
                "hung Wonad desktop callback")
        } catch (error: Exception) {
            failure.addSuppressed(error)
            Log.e(TAG, "Could not kill hung native desktop callback owner", error)
        } catch (error: LinkageError) {
            failure.addSuppressed(error)
            Log.e(TAG, "Could not reach callback-owner recovery API", error)
        }
    }

    /** Parent native task/display listeners call this on the same executor. */
    fun changed() {
        if (session == null || refreshQueued) return
        refreshQueued = true
        executor.executeDelayed({
            refreshQueued = false
            guarded { reconcile(); session?.let { refresh(it) } }
        }, 0)
    }

    /** Called by the parent's watchdog and protected-state listeners. */
    fun reconcile() {
        val live = session ?: return
        observeMonitors()
        val reason = BrokerNative.nativeSession(2, authorityFrame(identity(live.owner.uid)))
        if (reason != 0L) {
            // Rust reconcile has already cleared the exact authority when it
            // returns a positive revocation reason. A malformed/error frame
            // has not established that fact and must still attempt retirement.
            revoke(if (reason > 0) reason.toInt() else DesktopProtocol.REVOKED_CLIENT_FAILED,
                authorityAlreadyRetired = reason > 0)
            return
        }
        authorized(live.owner.uid)
        if (live.topology != topologyRevision) {
            val pending = live.pending
            live.pending = null // Rust invalidates a request on exact topology change.
            val next = monitors.map { it.id }.toSet()
            if (!retireDepartedDisplays(live, next)) return
            live.leasedDisplays = next
            live.topology = topologyRevision
            live.showingShells.keys.retainAll(monitors.map { it.token }.toSet())
            if (live.pick?.let { pick -> monitors.none { it.token == pick.displayToken } } == true) endPicker(live)
            if (live.uiEnabled) live.renewUi()
            if (live.shortcuts) live.renewShortcuts()
            if (pending != null) live.callbackResult(pending.request,
                DesktopProtocol.RESULT_STALE, live.revision)
            live.lastKey = null
        }
        val pick = live.pick
        if (pick != null && pick.importing == null && pickerCall(live, pick, 2) != 1L) endPicker(live)
        val now = SystemClock.elapsedRealtime()
        live.clientPrompt?.let { prompt ->
            val monitor = monitors.singleOrNull { it.token == prompt.display }
            val component = ComponentName(PACKAGE, "$PACKAGE${DesktopProtocol.PROMPT_ACTIVITY}")
            // The normal task query strips Intent extras. This fixed-role
            // observation needs its generation/request correlation fields.
            val present = monitor != null && nativeTasks(monitor.id, keepIntentExtras = true).any { task ->
                task.userId == live.owner.user && task.topActivity == component &&
                    task.topActivityInfo?.applicationInfo?.uid == live.owner.uid &&
                    task.baseIntent.getLongExtra("generation", 0) == live.generation &&
                    task.baseIntent.getLongExtra("request", 0) == prompt.request
            }
            if (present) prompt.seen = true
            if (monitor == null || prompt.seen && !present) live.clientPrompt = null
            else if (now >= prompt.deadline) {
                revoke(DesktopProtocol.REVOKED_CLIENT_FAILED,
                    initiatingFailure = IllegalStateException("Client prompt did not close by its deadline"))
                return
            }
        }
        live.showingShells.entries.removeAll { (token, _) -> monitors.any {
            it.token == token && it.shellGeneration == live.generation } }
        if (live.showingShells.values.any { now >= it }) revoke(DesktopProtocol.REVOKED_CLIENT_FAILED)
    }

    /** A display can cease to be an admissible native monitor while its
     * DisplayContent is still attached (power, trust or Shell layout readiness
     * changed). Park the exact OS-owned UI claim immediately; waiting for the
     * heartbeat deadline would leave the old owner visible after this topology
     * has already rejected it. Every independently owned lease is attempted. */
    private fun retireDepartedDisplays(live: Session, next: Set<Int>): Boolean {
        var failure: Throwable? = null
        (live.leasedDisplays - next).forEach { id ->
            retireDepartedDisplay(live, id)?.let { error ->
                val previous = failure
                if (previous == null) failure = error
                else if (previous !== error) previous.addSuppressed(error)
            }
        }
        failure?.let { error ->
            // Do not publish a topology which has stopped renewing an old
            // display while its privileged owner may still be live. Revoking
            // retries every old lease and leaves WMS's sticky claim black.
            if (session === live)
                revoke(DesktopProtocol.REVOKED_CLIENT_FAILED, initiatingFailure = error)
            return false
        }
        return true
    }

    private fun retireDepartedDisplay(live: Session, id: Int): Throwable? {
        var failure: Throwable? = null
        fun retire(message: String, action: () -> Boolean) {
            val error = attemptBrokerOperation { check(action()) { message } } ?: return
            Log.w(TAG, message, error)
            val previous = failure
            if (previous == null) failure = error
            else if (previous !== error) previous.addSuppressed(error)
        }
        if (live.uiEnabled) retire("Could not retire departed native UI lease") {
            wm().setWonadNativeUiLease(id, live.owner.user, live.generation, 0, null)
        }
        retire("Could not retire departed shortcut lease") {
            wm().setWonadShortcutLease(id, live.owner.user, live.generation, 0, null)
        }
        retire("Could not retire departed focus lease") {
            wm().setWonadFocusLease(id, live.owner.user, live.generation, 0, emptyArray(), null)
        }
        return failure
    }

    /** Sticky external claims are parked black, never restored through desks. */
    fun revoke(reason: Int, initiatingFailure: Throwable? = null, authorityAlreadyRetired: Boolean = false) {
        val live = session ?: return
        // onRevoked is terminal. Stop direct overload completions before
        // retiring the serially-owned session so no Binder thread can enqueue
        // an onResult after the terminal callback.
        live.markCallbackTerminal()
        session = null
        live.pending = null
        val cleanup = mutableListOf<() -> Unit>(
            { endPicker(live) },
            {
                check(authorityAlreadyRetired ||
                    BrokerNative.nativeSession(7, authorityFrame(live.owner, live.generation)) == 1L) {
                    "Native session retirement declined"
                }
            },
        )
        live.leasedDisplays.forEach { id ->
            if (live.uiEnabled) cleanup.add {
                check(wm().setWonadNativeUiLease(id, live.owner.user, live.generation, 0, null)) {
                    "Native UI lease retirement declined"
                }
            }
            cleanup.add {
                check(wm().setWonadShortcutLease(id, live.owner.user, live.generation, 0, null)) {
                    "Native shortcut lease retirement declined"
                }
            }
            cleanup.add {
                check(wm().setWonadFocusLease(id, live.owner.user, live.generation, 0, emptyArray(), null)) {
                    "Native focus lease retirement declined"
                }
            }
        }
        cleanup.add { live.callback.asBinder().unlinkToDeath(live.death, 0) }
        cleanup.add { live.callbackRevoked(reason) }
        try { runBrokerCleanup(*cleanup.toTypedArray()) } catch (error: Throwable) {
            if (error !is Exception && error !is LinkageError) throw error
            if (initiatingFailure != null && initiatingFailure !== error) initiatingFailure.addSuppressed(error)
            Log.w(TAG, "Native resource cleanup failed during revoke", error)
        }
        Log.i(TAG, "Revoked native generation=${live.generation} reason=$reason")
    }

    /** Binder caller must be captured by parent before dispatch. */
    fun open(uid: Int, version: Int, callback: IDesktopCallback?): IDesktopSession {
        require(version == DesktopProtocol.API_VERSION) {
            "Unsupported desktop API version $version"
        }
        require(callback != null)
        return synchronous(onAbandoned = { opened ->
            if (session === opened) revoke(DesktopProtocol.REVOKED_CLIENT_FAILED)
        }) {
            authorized(uid)
            reconcile()
            check(session == null) { "Native desktop session is already open" }
            if (callbackRecoveryBusy() || callbackExecutor.activeCount >= CALLBACK_WORKER_LIMIT)
                throw BrokerAdmissionException("Previous native callback delivery is still retiring")
            if (!operational() || !enabled(activeUser()) || locked())
                throw BrokerAdmissionException("Enable Wonad external desktop and unlock the phone")
            observeMonitors()
            if (monitors.isEmpty()) throw BrokerAdmissionException("No trusted, secure, public native external display")
            val owner = identity(uid) ?: throw SecurityException("Caller identity changed")
            if (owner.user != activeUser()) throw BrokerAdmissionException("Native user transition still in progress")
            // Opaque identities belong to system_server's exact Task/UID
            // registry, not SystemUI. They survive both APK and broker death.
            val epoch = wm().wonadNativeIdentityEpoch
            check(epoch > 0) { "Native task identity namespace unavailable" }
            val generation = BrokerNative.nativeSession(1, authorityFrame(owner, version = version))
            if (generation <= 0) throw BrokerAdmissionException("OS rejected native desktop session ($generation)")
            val opened = Session(owner, generation, epoch, callback, SystemClock.elapsedRealtime())
            session = opened
            try {
                callback.asBinder().linkToDeath(opened.death, 0)
                refresh(opened, true)
                opened
            } catch (error: Throwable) {
                if (error !is Exception && error !is LinkageError) throw error
                preserveBrokerFailure(error) {
                    if (session === opened) revoke(DesktopProtocol.REVOKED_CLIENT_FAILED, initiatingFailure = error)
                }
                throw error
            }
        }
    }

    private fun wm() = WindowManagerGlobal.getWindowManagerService() ?: error("Native WM unavailable")

    /** A physical attachment can disappear between observation and a private
     * WM renewal. Only a fresh native attachment-token mismatch is stale, not
     * a declined lease on the same attachment or a transport/authentication
     * failure. No rejected call grants authority on a replacement display. */
    private fun requireLeaseRenewal(accepted: Boolean, monitor: Monitor, uid: Int, message: String) {
        if (accepted) return
        authorized(uid)
        val row = wm().getWonadNativeDisplayState(intArrayOf(monitor.id))
        check(row.size == 4 && row[0] == monitor.id.toLong() && row[1] >= 0 && row[2] >= 0 &&
            (if (row[1] == 0L) row[2] == 0L && row[3] == 0L else row[3] > 0L)) {
            "Invalid native display renewal observation"
        }
        if (row[1] != monitor.token) throw StaleNativeObservation()
        error(message)
    }

    /** Renew every independent sibling even during hotplug. A stale attachment
     * must never mask a real later failure in the cleanup aggregator: only
     * after all genuine failures have been ruled out do we coalesce a fresh
     * topology read through the existing guarded stale-observation path. */
    private fun renewNativeLeases(renewals: List<() -> Unit>) {
        var stale = false
        runBrokerCleanup(*renewals.map { renewal -> {
            try { renewal() } catch (_: StaleNativeObservation) { stale = true }
        } }.toTypedArray())
        if (stale) throw StaleNativeObservation()
    }

    /** Read-only startup eligibility; does not create or grant a session. */
    internal fun hasEligibleDisplaysForLifecycle(): Boolean {
        observeMonitors()
        return monitors.isNotEmpty()
    }

    private fun observeMonitors() {
        val displays = displayManager.displays.filter { display -> display.isValid && display.displayId > 0 &&
            (display.type == Display.TYPE_EXTERNAL || display.type == Display.TYPE_VIRTUAL) &&
            display.flags and Display.FLAG_TRUSTED != 0 && display.flags and Display.FLAG_PRIVATE == 0 &&
            display.flags and Display.FLAG_SECURE != 0 &&
            display.state == Display.STATE_ON && power.isInteractive(display.displayId) }
        check(displays.size <= DesktopProtocol.MAX_DISPLAYS) { "Native display capacity exceeded" }
        val rows = wm().getWonadNativeDisplayState(displays.map { it.displayId }.toIntArray())
        check(rows.size == displays.size * 4) { "Invalid native display observation" }
        val next = displays.mapIndexedNotNull { index, display ->
            check(rows[index * 4] == display.displayId.toLong())
            val token = rows[index * 4 + 1]
            if (token <= 0) return@mapIndexedNotNull null
            val identityHint = rows[index * 4 + 3]
            check(identityHint > 0) { "Native monitor identity hint unavailable" }
            val layout = displayController.getDisplayLayout(display.displayId) ?: return@mapIndexedNotNull null
            Monitor(token, display.displayId, Rect(0, 0, layout.width(), layout.height()),
                layout.densityDpi(), display.flags and Display.FLAG_SECURE != 0, rows[index * 4 + 2], identityHint)
        }.sortedBy { it.token }
        check(next.map { it.token }.distinct().size == next.size)
        if (next != monitors) { monitors = next; topologyRevision = Math.addExact(topologyRevision, 1L) }
    }

    /** Scalar header mirrors existing multiSession identity/environment indices,
     * but uses version3 and exact native display rows9; never APK observations.
     */
    private fun authorityFrame(who: Identity?, generation: Long = 0, sequence: Long = 0,
        base: Long = 0, actual: Long = 0, version: Int = DesktopProtocol.API_VERSION,
        topology: Long = topologyRevision): LongArray {
        val user = activeUser()
        val digest = who?.signer ?: ByteArray(32)
        check(digest.size == 32)
        val words = LongArray(4) { i ->
            var word = 0L
            for (offset in 0..7) word = (word shl 8) or (digest[i * 8 + offset].toLong() and 255)
            word
        }
        return longArrayOf(SystemClock.elapsedRealtime(), generation, sequence, base, actual,
            version.toLong(), who?.uid?.toLong() ?: -1, who?.user?.toLong() ?: -1,
            if (who == null) 0 else 1, 0, *words, user.toLong(), topology,
            if (enabled(user)) 1 else 0, if (locked()) 1 else 0, monitors.size.toLong(),
            *monitors.flatMap { monitor -> listOf(monitor.token, monitor.id.toLong(), monitor.bounds.left.toLong(),
                monitor.bounds.top.toLong(), monitor.bounds.right.toLong(), monitor.bounds.bottom.toLong(),
                monitor.density.toLong(), if (monitor.secure) 1L else 0L, monitor.shellGeneration) }.toLongArray())
    }

    private fun selectable(uid: Int, user: Int, packageName: String): Boolean =
        UserHandle.getUserId(uid) == user && UserHandle.getAppId(uid) in 10000..19999 &&
            packageName !in setOf(PACKAGE, "android", "com.android.systemui", "com.android.permissioncontroller")

    private fun eligible(task: RunningTaskInfo, user: Int): Boolean {
        val app = task.topActivityInfo ?: return false
        return task.userId == user && task.activityType == ACTIVITY_TYPE_STANDARD && task.isRunning &&
            task.numActivities > 0 && !task.isSleeping && task.topActivity != null &&
            selectable(app.applicationInfo.uid, user, app.packageName)
    }

    private fun nativeTasks(displayId: Int, keepIntentExtras: Boolean = false): List<RunningTaskInfo> =
        ActivityTaskManager.getInstance().getTasks(NATIVE_TASK_LIMIT + 1, false, keepIntentExtras, displayId).also {
            check(it.size <= NATIVE_TASK_LIMIT) { "Native task enumeration would be truncated" }
        }

    private fun phoneTasks(user: Int): List<RunningTaskInfo> = nativeTasks(Display.DEFAULT_DISPLAY).filter {
        eligible(it, user) && it.displayId == Display.DEFAULT_DISPLAY && it.windowingMode == WINDOWING_MODE_FULLSCREEN
    }
    private fun phoneBinding(task: RunningTaskInfo) = PhoneBinding(task.taskId, task.token.asBinder(),
        task.topActivityInfo!!.applicationInfo.uid, task.userId, checkNotNull(task.topActivity))
    private fun label(value: CharSequence): String = value.toString().replace(Regex("[\\p{Cc}\\p{Cf}]"), " ").trim().take(160)
    private fun rect(value: Rect) = DesktopRect().apply { left = value.left; top = value.top; right = value.right; bottom = value.bottom }
    private fun bounds(value: DesktopRect) = listOf(value.left.toLong(), value.top.toLong(), value.right.toLong(), value.bottom.toLong())

    private fun capture(live: Session): Observation {
        authorized(live.owner.uid)
        check(wm().wonadNativeIdentityEpoch == live.identityEpoch) { "Native task identity namespace changed" }
        // Read-only native observations are permitted behind the readiness
        // barrier; mutation remains blocked until all fixed shells have drawn.
        // Never erase surviving task identities merely because one new monitor
        // is still drawing its shell.
        val collectTasks = live.uiEnabled
        val running = if (collectTasks) monitors.flatMap { monitor ->
            nativeTasks(monitor.id).filter { eligible(it, live.owner.user) && it.displayId == monitor.id }
        } else emptyList()
        check(running.size <= DesktopProtocol.MAX_TASKS) { "Native external task capacity exceeded" }
        // Both observations must complete before touching identity continuity.
        // A task can reparent between the individual per-display reads; a
        // duplicate Binder/task ID is an observation race, not a new identity.
        if (running.map { it.token.asBinder() }.distinct().size != running.size ||
            running.map { it.taskId }.distinct().size != running.size) throw StaleNativeObservation()
        val states = if (running.isEmpty()) LongArray(0) else wm().getWonadNativeTaskState(live.owner.user,
            live.generation, live.asBinder(), running.map { it.token.asBinder() }.toTypedArray())
        // Cold launches may briefly have no native content geometry. Never
        // publish an invalid rectangle or discard the previous registry on
        // that intermediate observation, UID change or reparent race.
        if (!NativeDesktopWire.nativeTaskStateValid(states,
            running.map { it.topActivityInfo!!.applicationInfo.uid }.toIntArray(), monitors.map { it.token }.toSet()))
            throw StaleNativeObservation()
        val actualDisplayTokens = running.indices.map { index -> states[index * 13 + 10] }
        val nativeTokens = running.indices.map { index -> states[index * 13 + 11] }
        if (collectTasks) {
            val present = nativeTokens.toSet()
            // Display removal migrates real leaves atomically in native WM,
            // but the per-display ATM read can straddle that transaction. A
            // missing enumerated token is not disappearance while its exact
            // native Task/UID remains attached to a claimed external display.
            // Withhold the whole partial snapshot and coalesce a fresh read;
            // never publish a removed display as an actionable destination.
            live.bindings.values.filter { it.token !in present }.forEach { saved ->
                val native = wm().getWonadNativeTaskState(live.owner.user, live.generation,
                    live.asBinder(), arrayOf(saved.binder))
                if (NativeDesktopWire.nativeTaskIdentityMatches(native, saved.token, saved.uid))
                    throw StaleNativeObservation()
            }
        }
        val actual = running.mapIndexed { index, task ->
            val binder = task.token.asBinder()
            val uid = task.topActivityInfo!!.applicationInfo.uid
            val token = nativeTokens[index]
            // The namespace guarantees no opaque-ID reuse. Never silently
            // bind an existing native ID to a replacement Binder or UID.
            live.bindings[token]?.let { previous -> check(previous.binder == binder && previous.uid == uid) }
            live.bindings[token] = Binding(token, task.taskId, binder, uid)
            token to task
        }.toMap()
        if (collectTasks) live.bindings.keys.retainAll(actual.keys)
        val ordered = actual.entries.toList()
        val nativeRanks = ordered.indices.map { Math.toIntExact(states[it * 13 + 9]) }
        val exactGlobalOrder = nativeRanks.toSet() == ordered.indices.toSet()
        val canonical = ordered.indices.sortedWith(compareBy<Int> {
            actualDisplayTokens[it]
        }.thenBy { nativeRanks[it] }.thenBy { ordered[it].key }).withIndex().associate { it.value to it.index }
        val tasks = ordered.mapIndexed { index, (token, task) ->
            val at = index * 13
            DesktopTask().apply {
                this.token = token
                displayToken = actualDisplayTokens[index]
                bounds = DesktopRect().apply {
                    left = Math.toIntExact(states[at]); top = Math.toIntExact(states[at + 1])
                    right = Math.toIntExact(states[at + 2]); bottom = Math.toIntExact(states[at + 3])
                }
                minimumWidth = Math.toIntExact(states[at + 4]); minimumHeight = Math.toIntExact(states[at + 5])
                check(states[at + 6] in 0L..1L && states[at + 7] in 0L..1L && states[at + 8] in 0L..1L)
                resizable = states[at + 6] == 1L; visible = states[at + 7] == 1L; inputEnabled = states[at + 8] == 1L
                zOrder = if (exactGlobalOrder) nativeRanks[index] else canonical.getValue(index)
                packageName = checkNotNull(task.topActivity).packageName
                title = label(task.taskDescription?.label ?: packageName)
            }
        }.sortedBy { it.token }
        if (collectTasks) renewNativeLeases(monitors.map { monitor -> {
            requireLeaseRenewal(wm().setWonadFocusLease(monitor.id, live.owner.user, live.generation,
                live.heartbeat + DesktopProtocol.CLIENT_TIMEOUT_MILLIS,
                tasks.filter { it.displayToken == monitor.token }.map { actual.getValue(it.token).token.asBinder() }.toTypedArray(),
                live.asBinder()), monitor, live.owner.uid, "Native focus lease declined")
        } })
        val focusId = wm().wonadFocusedDisplayId
        val focusMonitor = monitors.singleOrNull { it.id == focusId }
        if (focusMonitor != null) live.lastFocusedDisplayToken = focusMonitor.token
        // RunningTaskInfo focus may lag the native force-hidden/input state
        // after parking. Never publish a focused opaque token for a task that
        // the exact native observation cannot currently display or deliver to.
        val focused = actual.entries.singleOrNull { (token, info) ->
            val task = tasks.single { it.token == token }
            info.isFocused && task.visible && task.inputEnabled &&
                task.displayToken == focusMonitor?.token && focusMonitor?.shellGeneration == live.generation
        }?.key ?: 0L
        return Observation(DesktopSnapshot().apply {
            generation = live.generation; revision = live.revision; topologyRevision = live.topology
            identityEpoch = live.identityEpoch
            interactionBlocked = live.pick != null || wm().isWonadNativeInteractionBlocked(live.owner.user)
            capabilities = this@NativeDesktopController.capabilities
            focusedDisplayToken = if (live.pick == null) focusMonitor?.token ?: 0L else 0L
            focusedToken = if (live.pick == null) focused else 0L
            displays = monitors.map { monitor -> DesktopDisplay().apply {
                token = monitor.token; displayId = monitor.id; bounds = rect(monitor.bounds)
                densityDpi = monitor.density; secure = monitor.secure; shellGeneration = monitor.shellGeneration
                identityHint = monitor.identityHint
            } }.toTypedArray()
            this.tasks = tasks.toTypedArray()
        }, actual)
    }

    private fun stateKey(snapshot: DesktopSnapshot): List<Any> = listOf(snapshot.topologyRevision,
        snapshot.identityEpoch, snapshot.interactionBlocked,
        snapshot.focusedDisplayToken, snapshot.focusedToken,
        snapshot.displays.map { listOf(it.token, it.displayId, bounds(it.bounds), it.densityDpi, it.secure, it.shellGeneration, it.identityHint) },
        snapshot.tasks.map { listOf(it.token, it.displayToken, bounds(it.bounds), it.minimumWidth, it.minimumHeight,
            it.resizable, it.visible, it.inputEnabled, it.zOrder, it.title, it.packageName) })

    private fun refresh(live: Session, force: Boolean = false): Observation {
        check(session === live)
        val observed = capture(live)
        val key = stateKey(observed.snapshot)
        if (key != live.lastKey) { live.revision = Math.addExact(live.revision, 1L); live.lastKey = key }
        observed.snapshot.revision = live.revision
        live.observation = observed
        if (observed.snapshot.interactionBlocked) live.pending?.let {
            // A trusted phone prompt may remain open indefinitely. End only
            // the admitted mutation, not its still-heartbeating UI/session.
            // New requests remain barred until the native observation clears.
            finish(live, it.request, DesktopProtocol.RESULT_STALE)
        }
        if (force || live.publishedRevision != live.revision) {
            authorized(live.owner.uid)
            check(live.callbackSnapshot(observed.snapshot)) { "Native callback delivery unavailable" }
            live.publishedRevision = live.revision
        }
        return observed
    }

    private fun observedWire(snapshot: DesktopSnapshot) = NativeDesktopWire.snapshot(snapshot)
    private fun desiredWire(live: Session, base: Long, frame: DesktopFrame) =
        NativeDesktopWire.frame(live.generation, base, frame)

    private fun poll(live: Session) {
        if (session !== live || live.pollQueued) return
        live.pollQueued = true
        executor.executeDelayed({
            live.pollQueued = false
            guarded(live) {
                if (session !== live) return@guarded
                reconcile()
                if (session !== live) return@guarded
                val observed = refresh(live)
                val pending = live.pending
                if (pending != null) {
                    val sameTopology = pending.topology == observed.snapshot.topologyRevision
                    val done = when {
                        !sameTopology -> false
                        pending.closeToken > 0 -> observed.snapshot.tasks.none { it.token == pending.closeToken }
                        pending.focusToken > 0 -> observed.snapshot.focusedToken == pending.focusToken
                        pending.desired != null -> BrokerNative.nativeFrameMatches(observedWire(observed.snapshot), pending.desired) &&
                            wm().isWonadNativeFrameApplied(live.owner.user, live.generation, live.asBinder(),
                                pending.taskBinders, pending.taskUids, pending.capturedCurrent, pending.desired)
                        else -> false
                    }
                    if (!sameTopology) finish(live, pending.request, DesktopProtocol.RESULT_STALE)
                    else when (NativeFrameCompletion.observe(done, SystemClock.elapsedRealtime(), pending.deadline)) {
                        NativeFrameCompletion.APPLIED -> finish(live, pending.request, DesktopProtocol.RESULT_APPLIED)
                        NativeFrameCompletion.PLATFORM_CONSTRAINT, NativeFrameCompletion.TIMED_OUT -> {
                            finish(live, pending.request, DesktopProtocol.RESULT_PLATFORM_CONSTRAINT)
                            revoke(DesktopProtocol.REVOKED_CLIENT_FAILED)
                        }
                        NativeFrameCompletion.WAITING -> Unit
                        else -> error("Invalid native completion result")
                    }
                }
                live.pick?.let { pick ->
                    val marker = pick.importing
                    if (marker != null) {
                        val imported = observed.running.entries.singleOrNull {
                            if (pick.cookie) marker in it.value.launchCookies
                            else pick.phone?.matches(it.value) == true && it.value.token.asBinder() == marker
                        }
                        if (imported != null && observed.snapshot.tasks.single { it.token == imported.key }.displayToken == pick.displayToken) {
                            endPicker(live); refresh(live, true)
                        } else if (SystemClock.elapsedRealtime() >= pick.importDeadline) {
                            endPicker(live); refresh(live, true)
                        }
                    }
                }
                if (live.pending != null || live.pick?.importing != null || live.waitingForShell) poll(live)
                live.waitingForShell = live.uiEnabled && monitors.any { it.shellGeneration != live.generation }
            }
        }, POLL_MILLIS)
    }

    private fun finish(live: Session, request: Long, result: Int) {
        if (session !== live) return
        val pending = live.pending
        live.pending = null
        val finished = BrokerNative.nativeSession(5, authorityFrame(identity(live.owner.uid), live.generation,
            request, topology = pending?.topology ?: live.topology))
        if (finished != 1L) { revoke(DesktopProtocol.REVOKED_CLIENT_FAILED); return }
        authorized(live.owner.uid)
        live.callbackResult(request, result, live.revision)
    }

    private fun pickerCall(live: Session, pick: Pick, operation: Int, value: Int = 0): Long =
        BrokerNative.nativePicker(operation, longArrayOf(SystemClock.elapsedRealtime(), pick.id, live.generation,
            live.owner.user.toLong(), pick.displayToken, pick.kind.toLong(), value.toLong()))

    private fun endPicker(live: Session) {
        val pick = live.pick ?: return
        live.pick = null
        runBrokerCleanup(
            {
                check(pickerCall(live, pick, 4) == 1L) {
                    "Native picker cancellation declined"
                }
            },
            { pickerUi.dismiss(pick.ui) },
            { if (session === live && live.shortcuts) live.renewShortcuts() },
        )
    }

    private fun beginPicker(live: Session, displayToken: Long, kind: Int): Pick? {
        if (!live.uiEnabled || live.pending != null || live.pick != null || live.bindings.size >= DesktopProtocol.MAX_TASKS ||
            wm().isWonadNativeInteractionBlocked(live.owner.user)) return null
        val monitor = monitors.singleOrNull { it.token == displayToken && it.secure && it.shellGeneration == live.generation }
            ?: return null
        val choices = if (kind == 1) launcher.getActivityList(null, UserHandle.of(live.owner.user)).filter {
            selectable(it.applicationInfo.uid, live.owner.user, it.componentName.packageName)
        }.map { item ->
            val name = label(item.label) + "\n" + item.componentName.flattenToShortString()
            Choice(WonadPickerUi.Item(name, "$name\n\nThis may reuse an existing phone window."), item.componentName,
                item.applicationInfo.uid)
        } else phoneTasks(live.owner.user).map { task ->
            val name = label(task.taskDescription?.label ?: task.topActivity!!.shortClassName) +
                "\n" + task.topActivity!!.flattenToShortString() + " — task ${task.taskId}"
            Choice(WonadPickerUi.Item(name, "$name\n\nMove this exact phone window to external display ${monitor.id}?"),
                task.topActivity!!, task.topActivityInfo!!.applicationInfo.uid, phoneBinding(task))
        }.sortedBy { it.item.label.lowercase() }
        if (choices.size > DesktopProtocol.MAX_LAUNCH_ENTRIES) return null
        val now = SystemClock.elapsedRealtime()
        val id = BrokerNative.nativePicker(1, longArrayOf(now, 0, live.generation, live.owner.user.toLong(),
            displayToken, kind.toLong(), choices.size.toLong()))
        if (id <= 0) return null
        val pick = Pick(id, displayToken, kind, choices, now + DesktopProtocol.LAUNCHER_TIMEOUT_MILLIS)
        live.pick = pick
        try {
            if (live.shortcuts) live.renewShortcuts()
            refresh(live, true)
            return pick
        } catch (error: Throwable) {
            if (error !is Exception && error !is LinkageError) throw error
            // A failed initial observation must not leave a Rust one-shot
            // ticket open while the caller received no catalogue to cancel.
            preserveBrokerFailure(error) {
                if (session === live && live.pick === pick) endPicker(live)
            }
            throw error
        }
    }

    private fun selectPicker(live: Session, pick: Pick, index: Int?) {
        if (session !== live) return
        reconcile()
        if (session !== live || live.pick !== pick) return
        if (wm().isWonadNativeInteractionBlocked(live.owner.user)) {
            // No deferred launch may fire after an unrelated phone prompt is
            // dismissed. Catalogue operations have no admitted request ID;
            // cancel their one-shot ticket instead of inventing onResult IDs.
            Log.i(TAG, "Native catalogue selection stale: protected phone interaction (${DesktopProtocol.RESULT_STALE})")
            endPicker(live); refresh(live, true); return
        }
        if (index == null || index !in pick.choices.indices || pickerCall(live, pick, 3, index) != 1L) {
            endPicker(live); refresh(live, true); return
        }
        authorized(live.owner.uid)
        val target = monitors.singleOrNull { it.token == pick.displayToken && it.shellGeneration == live.generation }
        if (target == null) { endPicker(live); return }
        val choice = pick.choices[index]
        try {
            val binding = pick.phone ?: choice.phone
            if (binding != null) {
                val phone = phoneTasks(live.owner.user).singleOrNull { binding.matches(it) }
                check(phone != null) { "Consented phone window changed" }
                check(wm().transferWonadNativeTask(live.owner.user, live.generation, live.asBinder(),
                    binding.binder, binding.uid, pick.displayToken)) { "Native phone transfer declined" }
                pick.phone = binding; pick.importing = binding.binder; pick.cookie = false
            } else {
                val app = launcher.getActivityList(choice.component.packageName, UserHandle.of(live.owner.user))
                    .singleOrNull { it.componentName == choice.component && it.applicationInfo.uid == choice.uid }
                check(app != null) { "Chosen application changed" }
                check(phoneTasks(live.owner.user).none { it.topActivityInfo!!.applicationInfo.uid == choice.uid &&
                    it.topActivity?.packageName == choice.component.packageName }) { "Phone window appeared after selection" }
                val cookie = Binder()
                launcher.startMainActivity(choice.component, UserHandle.of(live.owner.user), null,
                    ActivityOptions.makeBasic().apply {
                        setLaunchDisplayId(target.id); setLaunchWindowingMode(WINDOWING_MODE_FREEFORM); setLaunchCookie(cookie)
                    }.toBundle())
                pick.importing = cookie; pick.cookie = true
            }
            pick.importDeadline = SystemClock.elapsedRealtime() + DesktopProtocol.TRANSACTION_TIMEOUT_MILLIS
            poll(live)
        } catch (error: Exception) {
            Log.w(TAG, "Native picker operation declined", error)
            endPicker(live); refresh(live, true)
        }
    }

    /** Phone Recents supplies observations only; parent validates Launcher3 UID
     * at its trusted Binder boundary. Recheck the exact native leaf here.
     */
    fun canTransferFromRecents(taskId: Int, user: Int, lastActive: Long,
        baseActivity: ComponentName?, taskToken: IBinder?): Boolean = recentsResult { expected ->
        recentsCandidate(expected, taskId, user, lastActive, baseActivity, taskToken)?.first === expected
    }

    fun transferFromRecents(taskId: Int, user: Int, lastActive: Long,
        baseActivity: ComponentName?, taskToken: IBinder?): Boolean = recentsResult { expected ->
        val (live, task) = recentsCandidate(expected, taskId, user, lastActive, baseActivity, taskToken)
            ?: return@recentsResult false
        if (live !== expected || wm().wonadFocusedDisplayId != Display.DEFAULT_DISPLAY)
            return@recentsResult false
        val target = recentsDestination(live) ?: return@recentsResult false
        authorized(live.owner.uid)
        val applied = wm().transferWonadNativeTask(user, live.generation, live.asBinder(), task.token.asBinder(),
            task.topActivityInfo!!.applicationInfo.uid, target.token)
        if (applied) changed()
        applied
    }

    /** Recents is a trusted platform caller, but it is not the session's
     * asynchronous guarded queue. Never let an optional JNI/WM/authentication
     * failure escape that Binder call or leave its old authority live. Capture
     * the exact session so reentrant cleanup cannot revoke a replacement. */
    private inline fun recentsResult(action: (Session) -> Boolean): Boolean {
        val expected = session ?: return false
        return try { action(expected) }
        catch (error: Exception) { recentsFailure(expected, error) }
        catch (error: LinkageError) { recentsFailure(expected, error) }
    }

    private fun recentsFailure(expected: Session, error: Throwable): Boolean {
        Log.e(TAG, "Native Recents operation failed closed", error)
        if (session === expected)
            revoke(DesktopProtocol.REVOKED_CLIENT_FAILED, initiatingFailure = error)
        return false
    }

    private fun recentsDestination(live: Session): Monitor? = monitors.singleOrNull {
        it.token == live.lastFocusedDisplayToken && it.shellGeneration == live.generation
    }

    private fun recentsCandidate(expected: Session, taskId: Int, user: Int, lastActive: Long,
        baseActivity: ComponentName?, taskToken: IBinder?): Pair<Session, RunningTaskInfo>? {
        if (session !== expected) return null
        reconcile()
        val live = session?.takeIf { it === expected } ?: return null
        if (live.owner.user != user || !live.uiEnabled || live.pick != null || live.pending != null ||
            live.bindings.size >= DesktopProtocol.MAX_TASKS || recentsDestination(live) == null ||
            taskToken == null || baseActivity == null || lastActive <= 0) return null
        val task = phoneTasks(user).singleOrNull { it.taskId == taskId && it.token.asBinder() == taskToken &&
            it.baseActivity == baseActivity && it.lastActiveTime >= lastActive } ?: return null
        return live to task
    }

    private fun guarded(expected: Session? = null, action: () -> Unit) {
        if (expected != null && !expected.currentOwner()) return
        try { action() } catch (_: StaleNativeObservation) {
            // A native reparent/vanish can race the two read-only observers.
            // Publish neither fabricated placement nor a stale UID/token pair.
            // Coalesce a new authoritative read instead of revoking a healthy
            // session merely because a display changed during observation.
            executor.executeDelayed({ guarded(expected) {
                reconcile(); changed()
                session?.let { live -> if (live.pending != null || live.pick?.importing != null || live.waitingForShell) poll(live) }
            } }, POLL_MILLIS)
        } catch (error: Exception) {
            if (expected != null && !expected.currentOwner()) return
            Log.e(TAG, "Native desktop operation failed closed", error)
            attemptBrokerOperation { reconcile() }?.let {
                if (it !== error) error.addSuppressed(it)
            }
            if (expected == null || expected.currentOwner())
                revoke(DesktopProtocol.REVOKED_CLIENT_FAILED)
        } catch (error: LinkageError) {
            if (expected != null && !expected.currentOwner()) return
            Log.e(TAG, "Native desktop bridge unavailable", error)
            revoke(DesktopProtocol.REVOKED_CLIENT_FAILED)
        }
    }

    private fun <T> synchronous(onAbandoned: (T) -> Unit = {}, action: () -> T): T {
        check(queueSlots.tryAcquire()) { "Broker queue full" }
        val dispatch = BrokerDispatch(onAbandoned, action)
        executor.execute { try { dispatch.task.run() } finally { queueSlots.release() } }
        return awaitBrokerResult(dispatch.task, 2000) { executor.execute { guarded {
            dispatch.abandon()
            reconcile()
        } } }
    }

    private inner class Session(val owner: Identity, val generation: Long, val identityEpoch: Long,
        val callback: IDesktopCallback, var heartbeat: Long) : IDesktopSession.Stub() {
        val bindings = linkedMapOf<Long, Binding>()
        var topology = topologyRevision
        @Volatile var revision = 0L
        var publishedRevision = -1L
        var lastKey: List<Any>? = null
        var observation: Observation? = null
        var leasedDisplays = monitors.map { it.id }.toSet()
        var lastFocusedDisplayToken = monitors.first().token
        var pending: Pending? = null
        var pick: Pick? = null
        var clientPrompt: ClientPrompt? = null
        var shortcuts = false
        var shortcutKeys = false
        var uiEnabled = false
        var pollQueued = false
        var waitingForShell = false
        val showingShells = mutableMapOf<Long, Long>()
        private val receivers = mutableMapOf<Int, IShortcutService>()
        private val requestOrder = Any()
        @Volatile private var closed = false
        private var lastRequest = 0L
        private val overloadOrder = Any()
        private val overloads = ArrayDeque<Pair<Long, Long>>()
        private var overloadDrainQueued = false
        private var overloadFailed = false
        private val callbacks = object {
            private val dispatcher = SerialCallbackDispatcher(callbackExecutor, CALLBACK_QUEUE_LIMIT,
                onFailure = { error -> executor.execute { guarded(this@Session) {
                    if (session === this@Session)
                        revoke(DesktopProtocol.REVOKED_CLIENT_FAILED, initiatingFailure = error)
                } } },
                onStarted = { delivery -> callbackStarted(this@Session, delivery) },
                onFinished = { delivery -> callbackFinished(this@Session, delivery) },
                onActive = { callbackActive(this@Session) },
                onIdle = { callbackIdle(this@Session) })

            fun snapshot(value: DesktopSnapshot) = dispatcher.offer { callback.onSnapshot(value) }
            fun command(command: Int, argument: Int, task: Long, display: Long) = dispatcher.offer {
                callback.onCommand(generation, command, argument, task, display)
            }
            fun result(request: Long, result: Int, revision: Long) = dispatcher.offer {
                callback.onResult(generation, request, result, revision)
            }
            fun isInFlight(delivery: Long) = dispatcher.isInFlight(delivery)
            fun markTerminal() = dispatcher.markTerminal()
            fun revoked(reason: Int) = dispatcher.offerTerminal { callback.onRevoked(generation, reason) }
        }
        private var callbackWatchdogDelivery = 0L
        private val callbackWatchdog = Runnable {
            val delivery = callbackWatchdogDelivery
            if (delivery > 0) callbackTimedOut(this, delivery)
        }

        fun armCallbackWatchdog(delivery: Long) {
            if (!callbacks.isInFlight(delivery)) return
            executor.removeCallbacks(callbackWatchdog)
            callbackWatchdogDelivery = delivery
            executor.executeDelayed(callbackWatchdog, CALLBACK_TIMEOUT_MILLIS)
        }

        fun disarmCallbackWatchdog(delivery: Long) {
            if (callbackWatchdogDelivery != delivery) return
            executor.removeCallbacks(callbackWatchdog)
            callbackWatchdogDelivery = 0
        }
        val death = IBinder.DeathRecipient { executor.execute {
            if (session === this@Session) revoke(DesktopProtocol.REVOKED_CLIENT_FAILED)
        } }

        fun markCallbackTerminal() { closed = true; callbacks.markTerminal() }

        fun currentOwner(uid: Int = owner.uid): Boolean = !closed && session === this && uid == owner.uid

        // Kotlin does not grant an enclosing class access to a nested class's
        // private members. Keep the anonymous dispatcher private (making it
        // non-private would erase its inferred type to Any), and expose only
        // the bounded operations the outer controller owns.
        fun callbackInFlight(delivery: Long) = callbacks.isInFlight(delivery)
        fun callbackSnapshot(value: DesktopSnapshot) = callbacks.snapshot(value)
        fun callbackResult(request: Long, result: Int, revision: Long) =
            callbacks.result(request, result, revision)
        fun callbackRevoked(reason: Int) = callbacks.revoked(reason)

        /** Request IDs are lease-scoped even when the caller supplies a wrong
         * generation. A positive, strictly newer wrong-generation request gets
         * exactly one STALE result under the live generation; nonpositive and
         * replayed IDs are inert. This entry fence complements (and never
         * replaces) Rust admission, preventing duplicate terminal results when
         * Binder threads race a saturated Shell queue. */
        private fun registerRequest(gen: Long, request: Long): Int = synchronized(requestOrder) {
            if (request <= 0 || request <= lastRequest) return@synchronized 0
            lastRequest = request
            if (gen == generation) 1 else 2
        }

        /** Queue exhaustion is processed in arrival order on Shell's executor.
         * Every distinct request still passes through Rust admission; an
         * accepted overload request is immediately retired there before BUSY
         * is emitted. Thus overload cannot skip the native replay/sequence,
         * revision, topology, ownership or pending-request state machine. */
        private fun completeQueueOverflow(request: Long, base: Long) {
            var schedule = false
            var saturated = false
            synchronized(overloadOrder) {
                if (overloadFailed) return
                if (overloads.size >= BROKER_QUEUE_LIMIT) {
                    overloadFailed = true
                    saturated = true
                }
                else {
                    overloads.addLast(request to base)
                    if (!overloadDrainQueued) { overloadDrainQueued = true; schedule = true }
                }
            }
            if (saturated) {
                executor.execute { guarded(this) {
                    if (session === this) revoke(DesktopProtocol.REVOKED_CLIENT_FAILED,
                        initiatingFailure = IllegalStateException("Native overload queue full"))
                } }
            } else if (schedule) executor.execute { drainQueueOverflow() }
        }

        private fun drainQueueOverflow() {
            while (true) {
                val item = synchronized(overloadOrder) {
                    if (overloads.isEmpty()) { overloadDrainQueued = false; return }
                    overloads.removeFirst()
                }
                // Retained work is inert before authorization or error policy
                // can observe/revoke a replacement owner.
                if (!currentOwner()) return
                guarded(this) {
                    authorized(owner.uid)
                    if (session !== this) return@guarded
                    reconcile()
                    if (session !== this) return@guarded
                    val (request, base) = item
                    val admitted = BrokerNative.nativeSession(4, authorityFrame(identity(owner.uid), generation,
                        request, base, revision, topology = topology))
                    val result = if (admitted == DesktopProtocol.RESULT_APPLIED.toLong()) {
                        val finished = BrokerNative.nativeSession(5, authorityFrame(identity(owner.uid), generation,
                            request, topology = topology))
                        if (finished != 1L) {
                            revoke(DesktopProtocol.REVOKED_CLIENT_FAILED)
                            return@guarded
                        }
                        DesktopProtocol.RESULT_BUSY
                    } else if (admitted >= 0) admitted.toInt() else DesktopProtocol.RESULT_REVOKED
                    callbacks.result(request, result, revision)
                    if (admitted < 0) revoke(DesktopProtocol.REVOKED_CLIENT_FAILED)
                }
            }
        }

        private fun enqueue(gen: Long, request: Long? = null, base: Long = 0, action: () -> Unit) {
            val uid = Binder.getCallingUid()
            authorized(uid)
            if (uid != owner.uid) throw SecurityException("Session belongs to another caller")
            // Retained Binders are completely inert. A current Binder's wrong
            // generation is handled before queue state or reconciliation.
            if (session !== this) return
            if (request != null) when (registerRequest(gen, request)) {
                0 -> return
                2 -> { callbacks.result(request, DesktopProtocol.RESULT_STALE, revision); return }
            } else if (gen != generation) return
            if (!queueSlots.tryAcquire()) {
                if (request != null) completeQueueOverflow(request, base)
                return
            }
            executor.execute {
                try {
                    if (!currentOwner(uid) || gen != generation) return@execute
                    guarded(this) {
                        try {
                            authorized(uid)
                            if (session !== this || gen != generation) return@guarded
                            reconcile()
                            if (session !== this || gen != generation) return@guarded
                            action()
                        } catch (error: StaleNativeObservation) {
                            if (request != null && session === this && gen == generation) {
                                authorized(uid)
                                callbacks.result(request, DesktopProtocol.RESULT_STALE, revision)
                            }
                            throw error
                        }
                    }
                } finally { queueSlots.release() }
            }
        }

        private fun admit(gen: Long, request: Long, base: Long, action: (Observation) -> Unit) = enqueue(gen, request, base) {
            val observed = refresh(this)
            val result = BrokerNative.nativeSession(4, authorityFrame(identity(owner.uid), generation,
                request, base, revision, topology = topology))
            if (result != DesktopProtocol.RESULT_APPLIED.toLong()) {
                callbacks.result(request, if (result >= 0) result.toInt() else DesktopProtocol.RESULT_REVOKED, revision)
                if (result < 0) revoke(DesktopProtocol.REVOKED_CLIENT_FAILED)
            } else if (observed.snapshot.interactionBlocked) finish(this, request, DesktopProtocol.RESULT_STALE)
            else if (pick != null || !uiEnabled || monitors.any { it.shellGeneration != generation })
                finish(this, request, DesktopProtocol.RESULT_PLATFORM_CONSTRAINT)
            else action(observed)
        }

        fun renewUi() {
            renewNativeLeases(monitors.map { monitor -> {
                requireLeaseRenewal(wm().setWonadNativeUiLease(monitor.id, owner.user, generation,
                    heartbeat + DesktopProtocol.CLIENT_TIMEOUT_MILLIS, asBinder()),
                    monitor, owner.uid, "Native shell lease declined")
            } })
        }

        private fun shortcutReceiver(displayId: Int): IShortcutService = receivers.getOrPut(displayId) {
            object : IShortcutService.Stub() {
                override fun notifyShortcutKeyPressed(code: Long) {
                    if (Binder.getCallingUid() != Process.SYSTEM_UID) throw SecurityException("OS input callback only")
                    val command = (code ushr 32).toInt(); val argument = code.toInt()
                    if (code <= 0 || command !in 1..17 || (command == 17) != shortcutKeys || when (command) {
                            17 -> !shortcutKeys || !DesktopShortcutKeys.valid(argument)
                            8, 9 -> argument !in 1..9 // Registered key argument, not native workspace policy.
                            15, 16 -> argument !in 0..2
                            else -> argument != 0
                        }) return
                    if (!queueSlots.tryAcquire()) return
                    executor.execute {
                        try { guarded(this@Session) {
                            if (session !== this@Session) return@guarded
                            reconcile()
                            if (session !== this@Session) return@guarded
                            val monitor = monitors.singleOrNull { it.id == displayId }
                            if (session === this@Session && shortcuts && (command == 17) == shortcutKeys && pick == null && monitor != null &&
                                monitor.shellGeneration == generation && wm().wonadFocusedDisplayId == displayId &&
                                !wm().isWonadNativeInteractionBlocked(owner.user)) {
                                val observed = refresh(this@Session)
                                callbacks.command(command, argument, observed.snapshot.focusedToken, monitor.token)
                            }
                        } } finally { queueSlots.release() }
                    }
                }
            }
        }

        fun renewShortcuts() {
            receivers.keys.retainAll(leasedDisplays)
            // enableShortcuts may negotiate support before external UI is
            // enabled.  That state is only an APK preference: it must not
            // preclaim an input lease or turn an expected pre-enable call into
            // session revocation.
            if (!uiEnabled) return
            val renewals = monitors.map<Monitor, () -> Unit> { monitor ->
                {
                    // A display becomes input-authoritative only after its
                    // exact fixed shell generation has crossed the native UI
                    // draw barrier.  Release every other display independently
                    // while still renewing ready siblings if one call fails.
                    val active = shortcuts && pick == null &&
                        monitor.shellGeneration == generation
                    val expiry = if (active) heartbeat + DesktopProtocol.CLIENT_TIMEOUT_MILLIS else 0
                    val receiver = if (active) shortcutReceiver(monitor.id) else null
                    requireLeaseRenewal(if (shortcutKeys)
                        wm().setWonadShortcutKeyLease(monitor.id, owner.user, generation, expiry, receiver)
                        else wm().setWonadShortcutLease(monitor.id, owner.user, generation, expiry, receiver),
                        monitor, owner.uid, "Native shortcuts declined")
                }
            }
            renewNativeLeases(renewals)
        }

        override fun heartbeat(gen: Long, sequence: Long) = enqueue(gen) {
            if (BrokerNative.nativeSession(3, authorityFrame(identity(owner.uid), generation, sequence)) == 1L) {
                heartbeat = SystemClock.elapsedRealtime()
                if (uiEnabled) renewUi()
                if (shortcuts) renewShortcuts()
                reconcile()
                if (session === this) refresh(this)
            }
        }
        override fun release(gen: Long) = enqueue(gen) { revoke(DesktopProtocol.REVOKED_DISABLED) }
        override fun enableShortcuts(gen: Long, enable: Boolean) = enqueue(gen) {
            check(!enable || shortcutAvailable()) { "Native shortcut integration unavailable" }
            shortcuts = enable; shortcutKeys = false; renewShortcuts()
        }
        override fun enableShortcutKeys(gen: Long, enable: Boolean) = enqueue(gen) {
            check(!enable || shortcutAvailable()) { "Native shortcut-key integration unavailable" }
            shortcuts = enable; shortcutKeys = enable; renewShortcuts()
        }
        override fun getShortcutProfile(gen: Long): DesktopShortcutProfile? {
            val uid = Binder.getCallingUid()
            authorized(uid)
            if (uid != owner.uid) throw SecurityException("Session belongs to another caller")
            if (session !== this || gen != generation) return null
            return synchronous {
                authorized(uid)
                if (session !== this || gen != generation || !shortcutAvailable()) null
                else {
                    reconcile()
                    if (session !== this) null else {
                        val prefix = wm().wonadShortcutPrefix
                        check(prefix in setOf(0x10000, 0x11000)) { "Unsupported product shortcut prefix" }
                        DesktopShortcutProfile().apply {
                            keysetVersion = DesktopProtocol.SHORTCUT_KEYSET_VERSION; requiredModifiers = prefix
                        }
                    }
                }
            }
        }
        override fun showClientPrompt(gen: Long, requestId: Long, displayToken: Long) = enqueue(gen) {
            if (requestId <= 0 || !uiEnabled || pending != null || pick != null || clientPrompt != null ||
                wm().isWonadNativeInteractionBlocked(owner.user)) return@enqueue
            val target = monitors.singleOrNull { it.token == displayToken && it.secure &&
                it.shellGeneration == generation } ?: return@enqueue
            val component = ComponentName(PACKAGE, "$PACKAGE${DesktopProtocol.PROMPT_ACTIVITY}")
            val info = context.createContextAsUser(UserHandle.of(owner.user), 0).packageManager.getActivityInfo(component, 0)
            check(info.enabled && info.exported && info.applicationInfo.uid == owner.uid && info.permission == FIXED_UI_PERMISSION)
            clientPrompt = ClientPrompt(requestId, displayToken, SystemClock.elapsedRealtime() + 31000)
            context.startActivityAsUser(Intent().setComponent(component)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_MULTIPLE_TASK)
                .putExtra("generation", generation).putExtra("request", requestId),
                ActivityOptions.makeBasic().apply { setLaunchDisplayId(target.id)
                    setLaunchWindowingMode(WINDOWING_MODE_FULLSCREEN) }.toBundle(), UserHandle.of(owner.user))
        }
        override fun enableExternalUi(gen: Long) = enqueue(gen) {
            val component = ComponentName(PACKAGE, "$PACKAGE.ExternalHomeActivity")
            val info = context.createContextAsUser(UserHandle.of(owner.user), 0).packageManager.getActivityInfo(component, 0)
            check(info.enabled && info.exported && info.applicationInfo.uid == owner.uid && info.permission == FIXED_UI_PERMISSION)
            uiEnabled = true; renewUi()
            reconcile()
            if (session === this) { refresh(this, true); waitingForShell = true; poll(this) }
        }
        override fun showShell(gen: Long, displayToken: Long) = enqueue(gen) {
            if (!uiEnabled) return@enqueue
            val target = monitors.singleOrNull { it.token == displayToken && it.secure } ?: return@enqueue
            val component = ComponentName(PACKAGE, "$PACKAGE${DesktopProtocol.SHELL_ACTIVITY}")
            val info = context.createContextAsUser(UserHandle.of(owner.user), 0).packageManager.getActivityInfo(component, 0)
            check(info.enabled && info.exported && info.applicationInfo.uid == owner.uid && info.permission == FIXED_UI_PERMISSION)
            if (target.shellGeneration == generation) return@enqueue
            if (displayToken in showingShells) return@enqueue // One bounded pending Activity per attachment.
            showingShells[displayToken] = SystemClock.elapsedRealtime() + DesktopProtocol.TRANSACTION_TIMEOUT_MILLIS
            context.startActivityAsUser(shellLaunchIntent(component, generation, displayToken),
                shellLaunchOptions(target.id).toBundle(), UserHandle.of(owner.user))
            waitingForShell = true; poll(this)
        }

        override fun applyFrame(gen: Long, request: Long, base: Long, frame: DesktopFrame?) =
            applyNativeFrame(gen, request, base, frame, signed = false)

        override fun applySignedFrame(gen: Long, request: Long, base: Long, frame: DesktopFrame?) =
            applyNativeFrame(gen, request, base, frame, signed = true)

        /** Mode is selected only by the authenticated method, never an APK
         * field. Both share exact admission, native identity, modal/readiness
         * barriers and unchanged actual completion/deadline observations.
         */
        private fun applyNativeFrame(gen: Long, request: Long, base: Long, frame: DesktopFrame?,
            signed: Boolean) = admit(gen, request, base) { observed ->
            if (signed && !signedPlacementAvailable()) {
                finish(this, request, DesktopProtocol.RESULT_UNSUPPORTED); return@admit
            }
            val desired = try { frame?.let { desiredWire(this, base, it) } } catch (_: Exception) { null }
            val current = observedWire(observed.snapshot)
            val result = when {
                desired == null -> DesktopProtocol.RESULT_INVALID
                signed -> BrokerNative.nativeValidateSignedFrame(current, desired)
                else -> BrokerNative.nativeValidateFrame(current, desired)
            }
            if (result != DesktopProtocol.RESULT_APPLIED || desired == null) { finish(this, request, result); return@admit }
            val actual = observed.snapshot.tasks.map { bindings.getValue(it.token) }
            val taskBinders = actual.map { it.binder }.toTypedArray()
            val taskUids = actual.map { it.uid }.toIntArray()
            val applied = if (signed) wm().applyWonadNativeSignedFrame(owner.user, generation, asBinder(),
                taskBinders, taskUids, current, desired) else wm().applyWonadNativeFrame(owner.user, generation,
                asBinder(), taskBinders, taskUids, current, desired)
            if (!applied) { finish(this, request, DesktopProtocol.RESULT_PLATFORM_CONSTRAINT); return@admit }
            pending = Pending(request, topology, SystemClock.elapsedRealtime() + DesktopProtocol.TRANSACTION_TIMEOUT_MILLIS,
                desired, capturedCurrent = current, taskBinders = taskBinders, taskUids = taskUids)
            poll(this)
        }
        override fun focusTask(gen: Long, request: Long, base: Long, token: Long) = admit(gen, request, base) { observed ->
            val binding = bindings[token]
            if (binding == null || !BrokerNative.nativeTaskAllowed(observedWire(observed.snapshot), token, true)) {
                finish(this, request, DesktopProtocol.RESULT_INVALID); return@admit
            }
            if (!wm().operateWonadNativeTask(owner.user, generation, asBinder(), binding.binder, binding.uid, false)) {
                finish(this, request, DesktopProtocol.RESULT_PLATFORM_CONSTRAINT); return@admit
            }
            pending = Pending(request, topology, SystemClock.elapsedRealtime() + DesktopProtocol.TRANSACTION_TIMEOUT_MILLIS,
                focusToken = token); poll(this)
        }
        override fun closeTask(gen: Long, request: Long, base: Long, token: Long) = admit(gen, request, base) { observed ->
            val binding = bindings[token]
            if (binding == null || !BrokerNative.nativeTaskAllowed(observedWire(observed.snapshot), token, false)) {
                finish(this, request, DesktopProtocol.RESULT_INVALID); return@admit
            }
            if (!wm().operateWonadNativeTask(owner.user, generation, asBinder(), binding.binder, binding.uid, true)) {
                finish(this, request, DesktopProtocol.RESULT_PLATFORM_CONSTRAINT); return@admit
            }
            pending = Pending(request, topology, SystemClock.elapsedRealtime() + DesktopProtocol.TRANSACTION_TIMEOUT_MILLIS,
                closeToken = token); poll(this)
        }
        override fun launcherPage(gen: Long, catalogId: Long, displayToken: Long, offset: Int): DesktopLaunchPage? {
            val uid = Binder.getCallingUid()
            authorized(uid)
            if (uid != owner.uid) throw SecurityException("Session belongs to another caller")
            // A retained/replaced session or wrong generation is rejected
            // before observing queue capacity or native environment state.
            if (session !== this || gen != generation) return null
            return synchronous(onAbandoned = { page ->
                // Only the initial page creates a picker. An unreceived page
                // must not leave shortcuts suspended or cancel a newer picker.
                if (catalogId == 0L && offset == 0 && page != null && session === this &&
                    pick?.id == page.catalogId) {
                    endPicker(this); refresh(this, true)
                }
            }) {
                authorized(uid)
                if (session !== this || gen != generation) return@synchronous null
                reconcile()
                if (session !== this || gen != generation) return@synchronous null
                if (catalogId < 0 || offset < 0) return@synchronous null
                val catalog = if (catalogId == 0L && offset == 0) beginPicker(this, displayToken, 1)
                    else pick?.takeIf { it.id == catalogId }
                if (catalog == null || catalog.kind != 1 || catalog.displayToken != displayToken || catalog.confirming ||
                    catalog.importing != null || pickerCall(this, catalog, 2) != 1L || offset > catalog.choices.size ||
                    offset == catalog.choices.size && offset != 0) return@synchronous null
                DesktopLaunchPage().apply {
                    generation = this@Session.generation; this.catalogId = catalog.id; this.displayToken = catalog.displayToken
                    this.offset = offset; totalEntries = catalog.choices.size; expiresAt = catalog.expires
                    entries = catalog.choices.drop(offset).take(DesktopProtocol.MAX_LAUNCH_PAGE).mapIndexed { index, choice ->
                        DesktopLaunchEntry().apply { this.index = offset + index; label = choice.item.label.substringBefore('\n')
                            component = choice.component.flattenToShortString().take(512) }
                    }.toTypedArray()
                }
            }
        }
        override fun showLauncher(gen: Long, catalogId: Long) = enqueue(gen) {
            val catalog = pick?.takeIf { it.id == catalogId && it.kind == 1 && !it.shown && !it.confirming &&
                it.importing == null && pickerCall(this, it, 2) == 1L } ?: return@enqueue
            if (wm().isWonadNativeInteractionBlocked(owner.user)) {
                endPicker(this); refresh(this, true); return@enqueue
            }
            val target = monitors.singleOrNull { it.token == catalog.displayToken && it.shellGeneration == generation }
                ?: return@enqueue
            val component = ComponentName(PACKAGE, "$PACKAGE.LauncherActivity")
            val info = context.createContextAsUser(UserHandle.of(owner.user), 0).packageManager.getActivityInfo(component, 0)
            check(info.enabled && info.exported && info.applicationInfo.uid == owner.uid && info.permission == FIXED_UI_PERMISSION)
            catalog.shown = true
            context.startActivityAsUser(Intent().setComponent(component).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or
                Intent.FLAG_ACTIVITY_MULTIPLE_TASK).putExtra("catalog", catalog.id).putExtra("generation", generation),
                ActivityOptions.makeBasic().apply { setLaunchDisplayId(target.id); setLaunchWindowingMode(WINDOWING_MODE_FULLSCREEN) }
                    .toBundle(), UserHandle.of(owner.user))
        }
        override fun selectLauncher(gen: Long, catalogId: Long, index: Int) = enqueue(gen) {
            val catalog = pick?.takeIf { it.id == catalogId && it.kind == 1 && !it.confirming && it.importing == null }
                ?: return@enqueue
            if (index !in catalog.choices.indices) { selectPicker(this, catalog, null); return@enqueue }
            val choice = catalog.choices[index]
            val phones = phoneTasks(owner.user).filter { it.topActivityInfo!!.applicationInfo.uid == choice.uid &&
                it.topActivity?.packageName == choice.component.packageName }
            if (phones.size > 1) { endPicker(this); refresh(this, true); return@enqueue }
            val phone = phones.singleOrNull()
            if (phone == null) selectPicker(this, catalog, index) else {
                catalog.phone = phoneBinding(phone); catalog.confirming = true
                val target = monitors.single { it.token == catalog.displayToken }
                pickerUi.confirm(catalog.ui, owner.user, "Open on external desktop?", choice.item.confirmation +
                    "\n\nMove this existing phone window without restarting it?\n" +
                    phone.topActivity!!.flattenToShortString() + " — task ${phone.taskId}.\nExternal display ${target.id}.") { confirmed ->
                    executor.execute { guarded(this) { selectPicker(this, catalog, if (confirmed) index else null) } }
                }
            }
        }
        override fun showTransferPicker(gen: Long, displayToken: Long) = enqueue(gen) {
            val catalog = beginPicker(this, displayToken, 2) ?: return@enqueue
            val target = monitors.single { it.token == displayToken }
            pickerUi.showNativeTransfer(catalog.ui, owner.user, target.id, catalog.choices.map { it.item }) { index ->
                executor.execute { guarded(this) { selectPicker(this, catalog, index) } }
            }
        }
    }
}
