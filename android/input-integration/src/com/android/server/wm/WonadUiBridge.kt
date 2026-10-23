package com.android.server.wm

import android.app.ActivityManager
import android.app.WindowConfiguration
import android.content.ComponentName
import android.content.pm.ActivityInfo
import android.content.pm.PackageManager
import android.os.Binder
import android.os.IBinder
import android.os.InputConfig
import android.os.Process
import android.os.SystemClock
import android.os.UserHandle
import android.provider.Settings
import android.util.Log
import android.view.Display
import android.view.InputChannel
import android.view.InputEvent
import android.view.InputEventReceiver
import android.view.InputWindowHandle
import android.view.SurfaceControl
import android.view.WindowManager
import org.wonad.server.input.InputNative
import org.wonad.server.input.WonadInputBridge

/** OS-owned display objects; called under WM's global lock except setLease.
 * Ownership is independent of Android's desktop/content-mode eligibility.
 * The Rust state machine keeps a screen claimed through death, timeout and
 * protected transitions. Exact native display removal is the only release.
 */
internal object WonadUiBridge {
    private const val PACKAGE = "org.wonad.desktop"
    private val home = ComponentName(PACKAGE, "$PACKAGE.ExternalHomeActivity")
    private val launcher = ComponentName(PACKAGE, "$PACKAGE.LauncherActivity")
    private val clientPrompt = ComponentName(PACKAGE, "$PACKAGE.DesktopPromptActivity")
    private val shell = ComponentName(PACKAGE, "$PACKAGE.ExternalShellActivity")
    internal data class NativeLease(val dc: DisplayContent, val incarnation: Long,
        val user: Int, val generation: Long, val owner: IBinder)
    private class NativeHomeLaunch(val wm: WindowManagerService, val lease: NativeLease,
        val area: TaskDisplayArea, val uid: Int)
    // This is synchronous framework execution authority, not a permission
    // conveyed in an Intent, ActivityOptions, public API, or cached HOME task.
    private val nativeHomeLaunch = ThreadLocal<NativeHomeLaunch?>()
    private class Claim(val dc: DisplayContent, val incarnation: Long) {
        var user = -1
        var generation = 0L
        var expires = 0L
        var owner: IBinder? = null
        var death: IBinder.DeathRecipient? = null
        var blank = true
        // Startup readiness is tied to a client generation, not current home
        // visibility. Android may destroy a stopped home's surface while an
        // ordinary app is in front; that is not a failed desktop session.
        var homeDrawn = false
        // Only our own changed focusability bit, bound to the actual Task and
        // Activity objects. Only a fresh admitted lease may draw HOME behind
        // containment; a parked owner must not retain a surfaced HOME window.
        val parkedHomes = linkedMapOf<Task, ActivityRecord>()
        // Once a physical attachment has hosted the native shell, stock
        // decorations must not reappear during owner death or recovery.
        var nativeMode = false
        var surface: SurfaceControl? = null
        var protectedInputSurface: SurfaceControl? = null
        var protectedInput = false
        var channel: InputChannel? = null
        var receiver: InputEventReceiver? = null
        var handle: InputWindowHandle? = null
        var pollScheduled = false
        lateinit var poll: Runnable
    }
    private var nextIncarnation = 1L
    private var nextIdentityHint = 1L
    private data class HintKey(val user: Int, val uniqueId: String?, val freshAttachment: Long)
    private val hintHistory = java.util.LinkedHashMap<HintKey, Long>(137, 0.75f, true)
    private val attachmentHints = linkedMapOf<Pair<DisplayContent, Int>, Pair<HintKey, Long>>()
    private val attachments = linkedMapOf<Int, Pair<DisplayContent, Long>>()
    private val claims = linkedMapOf<Int, Claim>()
    @Volatile private var blankDisplays: Set<Int> = emptySet()
    @Volatile private var protectedInputDisplays: Set<Int> = emptySet()
    // Display ids can be reused while the old DisplayContent is still running
    // its detach callbacks. Keep a counted, WM-lock-only departure barrier so
    // every lock-free input reader remains fail-closed until each exact removal
    // finishes. The published set is always rebuilt from current claims plus
    // these temporary barriers, so an old cleanup cannot erase a reentrant
    // replacement's blank/protected state.
    private val departingInputBarriers = linkedMapOf<Int, Int>()
    /** Lock-free input authority for one exact WMS-owned native claim. Object
     * identity is intentional: a replacement owner/generation on the same
     * numeric display must never inherit an old shortcut lease. */
    internal class ShortcutClaim internal constructor(val display: Int, val user: Int,
        val generation: Long, val incarnation: Long, internal val owner: IBinder)
    /** The identity token remains stable across same-owner heartbeats while
     * this immutable state publishes only a successfully renewed deadline. */
    internal class ShortcutClaimState internal constructor(internal val claim: ShortcutClaim,
        internal val expires: Long)
    @Volatile private var shortcutClaimStates: Map<Int, ShortcutClaimState> = emptyMap()

    @JvmStatic fun consumeInput(display: Int): Boolean =
        display in blankDisplays || display in protectedInputDisplays

    private fun publishInputContainment() {
        blankDisplays = claims.values.filter { it.blank }.map { it.dc.displayId }.toSet() +
            departingInputBarriers.keys
        protectedInputDisplays = claims.values.filter { it.protectedInput }
            .map { it.dc.displayId }.toSet()
    }

    private fun beginDepartingInputBarrier(display: Int) {
        departingInputBarriers[display] = Math.addExact(departingInputBarriers[display] ?: 0, 1)
        publishInputContainment()
    }

    private fun endDepartingInputBarrier(display: Int) {
        val count = checkNotNull(departingInputBarriers[display])
        if (count == 1) departingInputBarriers.remove(display)
        else departingInputBarriers[display] = count - 1
        publishInputContainment()
    }

    /** Called without WM's lock by the input-dispatch path. The immutable
     * snapshot is published only for a real native UI owner; generic external
     * display eligibility is deliberately insufficient. Read-only containment
     * state deliberately retains an expired/dead
     * exact claim. Authority admission below additionally requires it live. */
    internal fun currentShortcutClaimState(display: Int): ShortcutClaimState? =
        shortcutClaimStates[display]?.takeIf { it.claim.display == display &&
            it.claim.incarnation > 0 && it.expires > 0 }

    internal fun shortcutClaim(display: Int, user: Int, generation: Long): ShortcutClaim? =
        currentShortcutClaimState(display)?.takeIf { state ->
            state.claim.user == user && state.claim.generation == generation &&
                state.claim.owner.isBinderAlive && SystemClock.elapsedRealtime() < state.expires
        }?.claim

    internal fun shortcutClaimCurrent(expected: ShortcutClaim): Boolean =
        shortcutClaimStates[expected.display]?.claim === expected

    /** Publish removal before touching the old input owner. A new token is not
     * visible until exact old-owner cleanup has completed, so releaseDisplay
     * can never revoke a replacement shortcut slot with the same display id. */
    private fun retireShortcutClaim(claim: Claim) {
        val previous = shortcutClaimStates[claim.dc.displayId]?.claim?.takeIf {
            it.incarnation == claim.incarnation
        } ?: return
        shortcutClaimStates = shortcutClaimStates - claim.dc.displayId
        WonadInputBridge.onUiClaimRetired(previous)
    }

    private fun publishShortcutClaim(claim: Claim) {
        val owner = claim.owner
        if (!claim.nativeMode || claim.dc.displayId <= Display.DEFAULT_DISPLAY || claim.user < 0 ||
            claim.generation <= 0 || claim.incarnation <= 0 || claim.expires <= 0 || owner == null) {
            retireShortcutClaim(claim)
            return
        }
        val previous = shortcutClaimStates[claim.dc.displayId]?.claim
        if (previous != null && previous.user == claim.user &&
            previous.generation == claim.generation && previous.incarnation == claim.incarnation &&
            previous.owner === owner) {
            shortcutClaimStates = shortcutClaimStates + (claim.dc.displayId to
                ShortcutClaimState(previous, claim.expires))
            return
        }
        if (previous != null) {
            shortcutClaimStates = shortcutClaimStates - claim.dc.displayId
            // If exact old-owner cleanup raises a fatal error, this method
            // stops here and cannot publish replacement authority.
            WonadInputBridge.onUiClaimRetired(previous)
        }
        val token = ShortcutClaim(claim.dc.displayId, claim.user, claim.generation,
            claim.incarnation, owner)
        shortcutClaimStates = shortcutClaimStates + (claim.dc.displayId to
            ShortcutClaimState(token, claim.expires))
    }

    @JvmStatic fun owns(dc: DisplayContent): Boolean = claims[dc.displayId]?.dc === dc
    @JvmStatic fun secondaryHome(dc: DisplayContent): ComponentName? =
        if (owns(dc)) home else null

    internal fun enforceSystemUi(wm: WindowManagerService) {
        val context = wm.mContext
        context.enforceCallingPermission("android.permission.STATUS_BAR_SERVICE", "Wonad native desktop")
        if (Binder.getCallingUid() != context.packageManager.getPackageUidAsUser(
                "com.android.systemui", UserHandle.USER_SYSTEM))
            throw SecurityException("Native desktop registration is SystemUI-only")
    }

    /** Package replacement/removal can occur while a claimed display still
     * needs its black/input containment. A missing APK is never shell draw
     * authority, and an old cached UID must not authenticate a replacement. */
    private fun currentOwnerUid(wm: WindowManagerService, user: Int): Int? = try {
        wm.mContext.packageManager.getPackageUidAsUser(PACKAGE, user)
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }

    /** WM-lock-only identities, tied to the actual native DisplayContent, not
     * DMS uniqueId, numeric displayId, or a cached physical-monitor history. */
    internal fun attachment(dc: DisplayContent): Long {
        attachments[dc.displayId]?.takeIf { it.first === dc }?.let { return it.second }
        check(attachments.size < 9 || dc.displayId in attachments)
        val token = nextIncarnation
        nextIncarnation = Math.addExact(nextIncarnation, 1L)
        attachments[dc.displayId] = dc to token
        return token
    }

    /** Read-only continuity hint, not a display destination or lease token.
     * Never publish the raw physical identifier. Workspace/history decisions
     * remain APK-owned; identities are user-scoped and bounded to nine current
     * attachments plus 128 recent native connection identities.
     */
    private fun identityHint(dc: DisplayContent, user: Int): Long {
        val attachmentKey = dc to user
        attachmentHints[attachmentKey]?.let { return it.second }
        val unique = dc.displayInfo.uniqueId?.takeIf { it.isNotEmpty() && it.length <= 1024 }
        val key = HintKey(user, unique, if (unique == null) attachment(dc) else 0L)
        val hint = hintHistory[key] ?: nextIdentityHint.also {
            nextIdentityHint = Math.addExact(nextIdentityHint, 1L)
            hintHistory[key] = it
        }
        attachmentHints[attachmentKey] = key to hint
        // Display/user changes cannot grow an unbounded active-hint cache.
        attachmentHints.keys.removeAll { (display, account) ->
            attachments[display.displayId]?.first !== display || account != user
        }
        val active = attachmentHints.values.map { it.first }.toSet()
        val inactive = hintHistory.keys.filter { it !in active }
        inactive.take((inactive.size - 128).coerceAtLeast(0)).forEach { hintHistory.remove(it) }
        return hint
    }

    internal fun nativeMode(dc: DisplayContent): Boolean =
        claims[dc.displayId]?.let { it.dc === dc && it.nativeMode } == true

    /** Pending shell registration is permitted while the black readiness
     * barrier is up. Mutation additionally requires the barrier to be down. */
    internal fun nativeLease(wm: WindowManagerService, dc: DisplayContent,
        requireReady: Boolean = true): NativeLease? {
        val claim = claims[dc.displayId]?.takeIf { it.dc === dc && it.nativeMode } ?: return null
        val owner = claim.owner?.takeIf { it.isBinderAlive } ?: return null
        if ((requireReady && claim.blank) || !eligible(wm, dc, claim.user) ||
            InputNative.uiMode(dc.displayId, claim.incarnation, SystemClock.elapsedRealtime(),
                true, wm.mCurrentUserId) != 1) return null
        return NativeLease(dc, claim.incarnation, claim.user, claim.generation, owner)
    }

    internal fun nativeLeases(wm: WindowManagerService): List<NativeLease> =
        claims.values.mapNotNull { nativeLease(wm, it.dc) }

    /** Internal fail-closed recovery after the public Binder identity has been
     * cleared. Do not re-enter a SystemUI-only Binder facade as system_server. */
    internal fun parkNative(wm: WindowManagerService, user: Int, generation: Long, owner: IBinder) {
        claims.values.filter { it.nativeMode && it.user == user &&
            it.generation == generation && it.owner == owner }.toList().forEach { park(wm, it) }
    }

    @JvmStatic fun nativeDisplayState(wm: WindowManagerService, ids: IntArray?): LongArray {
        enforceSystemUi(wm)
        require(ids != null && ids.size <= 9 && ids.all { it > 0 } && ids.toSet().size == ids.size)
        val identity = Binder.clearCallingIdentity()
        return try { wm.withWonadGlobalLock {
            LongArray(ids.size * 4).also { values -> ids.forEachIndexed { index, id ->
                values[index * 4] = id.toLong()
                val dc = wm.mRoot.getDisplayContent(id)
                if (dc != null && eligible(wm, dc, wm.mCurrentUserId)) {
                    values[index * 4 + 1] = attachment(dc)
                    // Public readiness means the WHOLE claim barrier is down,
                    // not merely a drawn shell waiting for its home/poll pass.
                    values[index * 4 + 2] = nativeLease(wm, dc)?.generation?.takeIf {
                        WonadNativeBridge.shellGeneration(wm, dc) == it } ?: 0L
                    values[index * 4 + 3] = identityHint(dc, wm.mCurrentUserId)
                }
            } }
        } } finally { Binder.restoreCallingIdentity(identity) }
    }

    private fun eligible(wm: WindowManagerService, dc: DisplayContent, user: Int): Boolean {
        val info = dc.displayInfo
        return dc.displayId > 0 && wm.mRoot.getDisplayContent(dc.displayId) === dc &&
            wm.mCurrentUserId == user && wm.mAtmService.mAmInternal.currentUserId == user &&
            !wm.mPolicy.isKeyguardLocked && !wm.mPolicy.isKeyguardShowing && !dc.isSleeping &&
            wm.mAtmService.lockTaskController.lockTaskModeState == ActivityManager.LOCK_TASK_MODE_NONE &&
            info.state == Display.STATE_ON && info.flags and Display.FLAG_TRUSTED != 0 &&
            info.flags and Display.FLAG_PRIVATE == 0 && info.flags and Display.FLAG_SECURE != 0 &&
            (info.type == Display.TYPE_EXTERNAL || info.type == Display.TYPE_VIRTUAL) &&
            Settings.Secure.getIntForUser(wm.mContext.contentResolver,
                "wonad_external_desktop_enabled", 0, user) == 1
    }

    /** Original Binder caller must be platform SystemUI. The APK never sees
     * this entry point, native task tokens, an input channel, or a surface.
     */
    @JvmStatic fun setNativeLease(wm: WindowManagerService, display: Int, user: Int,
        generation: Long, expires: Long, owner: IBinder?): Boolean =
        setLease(wm, display, user, generation, expires, owner, true)

    private fun setLease(wm: WindowManagerService, display: Int, user: Int,
        generation: Long, expires: Long, owner: IBinder?, native: Boolean): Boolean {
        enforceSystemUi(wm)
        val identity = Binder.clearCallingIdentity()
        return try { wm.withWonadGlobalLock {
            val dc = wm.mRoot.getDisplayContent(display) ?: return@withWonadGlobalLock owner == null
            val old = claims[display]
            if (owner == null) {
                if (old?.dc === dc && old.generation == generation) park(wm, old)
                return@withWonadGlobalLock true
            }
            if (old != null && old.dc !== dc) return@withWonadGlobalLock false
            var affected = old
            try {
                if (old != null && old.owner != null &&
                    (old.owner != owner || old.generation != generation || old.user != user)) {
                    reconcile(wm, old)
                    if (!old.blank) return@withWonadGlobalLock false
                }
                if (old == null && claims.size >= 9) return@withWonadGlobalLock false
                val claim = old ?: Claim(dc, attachment(dc))
                affected = claim
                val now = SystemClock.elapsedRealtime()
                if (!InputNative.uiRenew(display, claim.incarnation, user, generation, expires,
                        now, eligible(wm, dc, user))) return@withWonadGlobalLock false
                val nativeTakeover = native && !claim.nativeMode
                val newOwner = claim.generation != generation || claim.user != user || claim.owner != owner
                if (newOwner) claim.homeDrawn = false
                if (newOwner) retireShortcutClaim(claim)
                unlink(claim)
                claim.user = user; claim.generation = generation; claim.expires = expires
                claim.owner = owner
                claim.nativeMode = claim.nativeMode || native
                val death = IBinder.DeathRecipient {
                    val action = Runnable { wm.withWonadGlobalLock {
                        if (claims[display] === claim && claim.owner == owner &&
                            claim.generation == generation) park(wm, claim)
                    } }
                    val dispatchFailure = try {
                        if (wm.mH.post(action)) null
                        else IllegalStateException("Could not dispatch external UI owner death")
                    } catch (error: Throwable) { error }
                    if (dispatchFailure != null) wm.withWonadGlobalLock {
                        if (claims[display] === claim && claim.owner == owner &&
                            claim.generation == generation) containAndRelease(wm, claim,
                                dispatchFailure, "External UI owner death dispatch failed")
                    }
                }
                claim.death = death
                if (old == null) {
                    claim.poll = Runnable { wm.withWonadGlobalLock {
                        claim.pollScheduled = false
                        if (claims[display] === claim) {
                            try { reconcile(wm, claim) }
                            catch (error: Throwable) {
                                if (error !is Exception && error !is LinkageError) throw error
                                // Establish the real OS-owned black/input/app-hidden
                                // state before releasing the failed native owner.
                                // Every independently owned step is attempted.
                                containAndRelease(wm, claim, error,
                                    "Could not reconcile external UI; parked with containment")
                            }
                            if (claims[display] === claim) try {
                                check(schedulePoll(wm, claim, 250)) {
                                    "Could not reschedule external UI watchdog"
                                }
                            } catch (error: Throwable) {
                                containAndRelease(wm, claim, error,
                                    "External UI watchdog reschedule failed")
                            }
                        }
                    } }
                    claims[display] = claim
                    // InputDispatcher does not take WM's lock. Publish the
                    // default-blank claim before any fallible surface/callback
                    // setup so takeover has no input-admission window.
                    publishInputContainment()
                    // A new sticky claim is synchronously black and input-safe
                    // before callbacks, home launch, death registration or the
                    // asynchronous watchdog can fail.
                    show(wm, claim, blank = true)
                    // Notify consumers without changing canHostTasks, freeform
                    // eligibility, topology, or persistent display settings.
                    dc.displayPolicy.notifyDisplayRemoveSystemDecorations()
                }
                check(schedulePoll(wm, claim, 0)) { "Could not schedule external UI watchdog" }
                if (nativeTakeover) {
                    // Existing stock windows must disappear before the readiness
                    // barrier can open. Late/cached clients are denied atomically
                    // by WM's root-type admission guard; normal client teardown
                    // still follows the decoration-removal notification.
                    WonadNativeDecorations.retire(dc)
                    if (old != null) dc.displayPolicy.notifyDisplayRemoveSystemDecorations()
                }
                owner.linkToDeath(death, 0)
                publishShortcutClaim(claim)
                // A force-stopped client loses its home Activity too. Recreate it
                // for a fresh session, not only for a newly attached display.
                if (newOwner && !homeReady(claim)) {
                    if (claim.nativeMode) startNativeHome(wm, claim)
                    else wm.mRoot.startHomeOnDisplay(user, "wonad-external-ui", display)
                }
                show(wm, claim, blank = !ready(wm, claim))
                true
            } catch (error: Throwable) {
                val claim = affected?.takeIf { claims[display] === it && it.dc === dc }
                if (claim != null) {
                    containAndRelease(wm, claim, error,
                        "External UI lease setup failed; parked with containment")
                    if (!claim.pollScheduled) {
                        val scheduling = WonadCleanupFailures()
                        scheduling.attempt {
                            check(schedulePoll(wm, claim, 0)) {
                                "Could not schedule parked external UI watchdog"
                            }
                        }
                        scheduling.supportedFailure?.let {
                            if (it !== error) error.addSuppressed(it)
                            Log.e("WonadUi", "Could not schedule parked external UI watchdog", it)
                        }
                        scheduling.rethrowFatal(error)
                    }
                }
                if (error !is Exception && error !is LinkageError) throw error
                Log.e("WonadUi", "External UI lease request failed closed", error)
                false
            }
        } } finally { Binder.restoreCallingIdentity(identity) }
    }

    /** Exact per-claim scheduling state; a failed post is never confused with
     * an existing watchdog, and any later renewal retries it. */
    private fun schedulePoll(wm: WindowManagerService, claim: Claim, delay: Long): Boolean {
        if (claim.pollScheduled) return true
        val posted = if (delay > 0) wm.mH.postDelayed(claim.poll, delay)
            else wm.mH.post(claim.poll)
        claim.pollScheduled = posted
        return posted
    }

    private fun unlink(claim: Claim) {
        val owner = claim.owner
        val death = claim.death
        try {
            if (owner != null && death != null) owner.unlinkToDeath(death, 0)
        } catch (error: Throwable) {
            if (error !is Exception && error !is LinkageError) throw error
        } finally {
            claim.owner = null
            claim.death = null
        }
    }

    private fun park(wm: WindowManagerService, claim: Claim) {
        containAndRelease(wm, claim, null, "External UI park completed with failures")
    }

    private fun reconcile(wm: WindowManagerService, claim: Claim) {
        if (wm.mRoot.getDisplayContent(claim.dc.displayId) !== claim.dc) {
            onRemoved(claim.dc)
            return
        }
        val mode = InputNative.uiMode(claim.dc.displayId, claim.incarnation,
            SystemClock.elapsedRealtime(), eligible(wm, claim.dc, claim.user), wm.mCurrentUserId)
        if (mode != 1 || claim.owner?.isBinderAlive != true) {
            containAndRelease(wm, claim, null, "External UI reconciliation park failed")
        } else {
            revealNativeBackground(wm, claim)
            if (claim.blank != !ready(wm, claim)) show(wm, claim, blank = !ready(wm, claim))
        }
        // Protected-window visibility can change independently of global
        // display focus. Reconcile the fixed plane's input eligibility too.
        if (claim.nativeMode) {
            WonadNativeBridge.reconcileClosingLauncherFocus(wm, claim.dc)
            WonadNativeBridge.onFocusChanged(wm)
        }
        else if (claim.surface != null) protectInput(wm, claim)
    }

    private fun ready(wm: WindowManagerService, claim: Claim): Boolean =
        claim.owner?.isBinderAlive == true && homeReady(claim) &&
        (!claim.nativeMode || WonadNativeBridge.shellGeneration(wm, claim.dc) == claim.generation)

    /** Creating the fixed background is passive attachment/recovery, not a
     * keyboard focus request. Stock startHomeOnDisplay always raises the new
     * display's HOME branch and can steal the phone's focus during redock.
     * Start the SAME private HOME on the exact native TDA without raising its
     * ancestors. Later real mouse/keyboard selections use the normal guarded
     * native focus path; no cached phone Activity is restored here.
     * The authenticated owner's private background must also start when that
     * ordinary owner is instrumented. This is not the phone/default HOME path;
     * all native claim checks below still apply and no ancestor is raised.
     */
    private fun startNativeHome(wm: WindowManagerService, claim: Claim): Boolean {
        val dc = claim.dc
        if (!claim.nativeMode || dc.displayId <= Display.DEFAULT_DISPLAY ||
            claims[dc.displayId] !== claim || wm.mRoot.getDisplayContent(dc.displayId) !== dc ||
            claim.user != wm.mCurrentUserId || claim.generation <= 0 ||
            claim.owner?.isBinderAlive != true) return false
        val lease = nativeLease(wm, dc, requireReady = false) ?: return false
        if (lease.user != claim.user || lease.generation != claim.generation ||
            lease.incarnation != claim.incarnation || lease.owner != claim.owner) return false
        val uid = currentOwnerUid(wm, claim.user) ?: return false
        val area = dc.defaultTaskDisplayArea
        val previous = nativeHomeLaunch.get()
        nativeHomeLaunch.set(NativeHomeLaunch(wm, lease, area, uid))
        return try {
            wm.mRoot.startHomeOnTaskDisplayArea(claim.user, "wonad-external-ui",
                area, true, false, false)
        } finally {
            if (previous == null) nativeHomeLaunch.remove() else nativeHomeLaunch.set(previous)
        }
    }

    /** Android checks instrumented HOME eligibility again during launch-param
     * calculation, after the resolver already selected the exact external TDA.
     * Preserve the private admitted launch there without granting instrumented
     * phone/foreign HOME or turning an Intent reason into execution authority.
     * Called synchronously under WM's global lock while startNativeHome runs.
     */
    @JvmStatic fun allowInstrumentedNativeHome(info: ActivityInfo?, area: TaskDisplayArea?): Boolean {
        val pending = nativeHomeLaunch.get() ?: return false
        val wm = pending.wm
        val lease = pending.lease
        val dc = lease.dc
        if (info == null || area == null || area !== pending.area || area !== dc.defaultTaskDisplayArea ||
            dc.displayId <= Display.DEFAULT_DISPLAY || area.displayContent !== dc ||
            wm.mRoot.getDisplayContent(dc.displayId) !== dc || dc.mWmService !== wm ||
            Binder.getCallingUid() != Process.SYSTEM_UID || Binder.getCallingPid() != Process.myPid()) return false
        val live = nativeLease(wm, dc, requireReady = false) ?: return false
        if (live.dc !== dc || live.incarnation != lease.incarnation || live.user != lease.user ||
            live.generation != lease.generation || live.owner != lease.owner ||
            live.user != wm.mCurrentUserId || live.generation <= 0 || !live.owner.isBinderAlive) return false
        val uid = currentOwnerUid(wm, live.user) ?: return false
        val application = info.applicationInfo ?: return false
        return uid == pending.uid && application.uid == uid &&
            UserHandle.getUserId(uid) == live.user && info.enabled && info.exported &&
            info.packageName == PACKAGE && application.packageName == PACKAGE &&
            info.name == home.className && info.permission == "android.permission.STATUS_BAR_SERVICE"
    }

    private fun claimObjectsCurrent(wm: WindowManagerService, claim: Claim,
        user: Int, generation: Long, owner: IBinder?): Boolean {
        val dc = claim.dc
        return claims[dc.displayId] === claim && claim.user == user &&
            claim.generation == generation && claim.owner === owner &&
            claim.incarnation > 0 && dc.displayId > Display.DEFAULT_DISPLAY &&
            dc.mWmService === wm && dc.parent === wm.mRoot &&
            wm.mRoot.getDisplayContent(dc.displayId) === dc &&
            attachments[dc.displayId]?.let { it.first === dc && it.second == claim.incarnation } == true
    }

    /** Exact fixed external HOME object scope, not generic HOME ownership.
     * Historical claim-user authentication is sufficient only to hide this
     * already claimed background. Revealing additionally requires a fresh
     * admissible native lease, independently established below.
     */
    private fun claimedNativeHome(wm: WindowManagerService, claim: Claim,
        task: Task): ActivityRecord? {
        val dc = claim.dc
        if (!claim.nativeMode || claim.user < 0 ||
            !claimObjectsCurrent(wm, claim, claim.user, claim.generation, claim.owner))
            return null
        val area = dc.defaultTaskDisplayArea ?: return null
        if (area.displayContent !== dc) return null
        val uid = currentOwnerUid(wm, claim.user) ?: return null
        if (UserHandle.getUserId(uid) != claim.user) return null
        // A former user's background may still own a surface while stock
        // topRunningActivity excludes it via showToCurrentUser(). Hiding is
        // permitted for the exact old claim, not just currently runnable HOME.
        val activity = task.getTopNonFinishingActivity() ?: return null
        val root = task.rootTask ?: return null
        return activity.takeIf {
            task.isLeafTask && task.isAttached && task.isActivityTypeHome &&
            task.mUserId == claim.user && task.displayContent === dc &&
            root.isAttached && root.parent === area && root.isActivityTypeHome &&
            root.displayContent === dc &&
            !it.finishing && it.mUserId == claim.user && it.uid == uid && it.displayContent === dc &&
            it.mActivityComponent == home && it.info.permission == "android.permission.STATUS_BAR_SERVICE"
        }
    }

    private fun nativeHomeDrawLease(wm: WindowManagerService, claim: Claim): NativeLease? {
        val user = claim.user; val generation = claim.generation; val owner = claim.owner
        if (!claimObjectsCurrent(wm, claim, user, generation, owner)) return null
        val lease = nativeLease(wm, claim.dc, requireReady = false) ?: return null
        return lease.takeIf { claimObjectsCurrent(wm, claim, user, generation, owner) &&
            it.dc === claim.dc && it.user == user && it.generation == generation &&
            it.incarnation == claim.incarnation && it.owner === owner && it.owner.isBinderAlive &&
            it.generation > 0 && it.user == wm.mCurrentUserId }
    }

    /** Avoid-front creates cold activities behind the existing opaque HOME;
     * they have no process/window yet and will never draw on their own. Admit
     * ONLY the two authenticated fixed roles into their local visible order.
     * Do not raise DisplayContent/ancestors, select a monitor, revive an app,
     * or reorder either fixed role after its generation has drawn.
     */
    private fun revealNativeBackground(wm: WindowManagerService, claim: Claim) {
        val dc = claim.dc
        val user = claim.user; val generation = claim.generation; val owner = claim.owner
        fun current() = claimObjectsCurrent(wm, claim, user, generation, owner)
        val admittedLease = nativeHomeDrawLease(wm, claim) ?: return
        // Binder liveness and elapsed expiry are not protected by WM's lock.
        // Never recapture another lease after blocking PM/framework calls.
        fun active() = current() && nativeHomeDrawLease(wm, claim) == admittedLease && current()
        val uid = currentOwnerUid(wm, claim.user) ?: return
        if (!active()) return
        val area = dc.defaultTaskDisplayArea
        val homes = mutableListOf<Task>()
        val shells = mutableListOf<Task>()
        dc.forAllTasks(java.util.function.Consumer { task ->
            if (!active()) return@Consumer
            val activity = task.topRunningActivity()
            if (task.isLeafTask && task.isAttached && activity != null && !activity.finishing &&
                activity.mUserId == claim.user && activity.uid == uid && activity.displayContent === dc &&
                activity.info.permission == "android.permission.STATUS_BAR_SERVICE") {
                if (!claim.homeDrawn && claimedNativeHome(wm, claim, task) === activity && active())
                    homes.add(task)
                if (task.isActivityTypeStandard && task.parent === area &&
                    activity.mActivityComponent == shell &&
                    activity.intent.getLongExtra("$PACKAGE.shell.GENERATION", 0) == claim.generation &&
                    activity.intent.getLongExtra("$PACKAGE.shell.DISPLAY_TOKEN", 0) == claim.incarnation &&
                    !activity.firstWindowDrawn) shells.add(task)
            }
        })
        var changed = false
        homes.singleOrNull()?.let { task ->
            if (!active()) return@let
            // Restore only this OS-owned visibility bit under the exact fresh
            // lease, while the existing black/input readiness barrier is up.
            // Do not restore focusability here or raise any ancestor.
            changed = task.setForceHidden(TaskFragment.FLAG_FORCE_HIDDEN_FOR_WONAD, false) || changed
            if (!active()) return@let
            val parent = task.parent?.asTask()
            // Select this HOME within the existing HOME root, not above apps.
            if (parent != null && parent.isActivityTypeHome && parent.displayContent === dc &&
                parent.topMostTask !== task) {
                if (!active()) return@let
                parent.positionChildAt(WindowContainer.POSITION_TOP, task, false)
                changed = true
                if (!active()) return@let
            }
        }
        shells.singleOrNull()?.let { task ->
            if (!active()) return@let
            // Set native task focusability BEFORE exposing its Activity. The
            // APK's NOT_FOCUSABLE window flag does not exist before onCreate.
            if (task.isFocusable) {
                if (!active()) return@let
                task.setFocusable(false); changed = true
                if (!active()) return@let
            }
            if (area.mPreferredTopFocusableRootTask === task) {
                if (!active()) return@let
                area.mPreferredTopFocusableRootTask = null
            }
            if (!active()) return@let
            changed = task.setForceHidden(TaskFragment.FLAG_FORCE_HIDDEN_FOR_WONAD, false) || changed
            if (!active()) return@let
            if (area.topChild !== task) {
                if (!active()) return@let
                area.positionChildAt(WindowContainer.POSITION_TOP, task, false)
                changed = true
                if (!active()) return@let
            }
        }
        if (changed && active()) {
            wm.mRoot.ensureActivitiesVisible()
            if (!active()) return
            dc.scheduleAnimation()
        }
    }

    private fun homeReady(claim: Claim): Boolean {
        if (!claim.homeDrawn) claim.homeDrawn = claim.dc.getWindow(
            java.util.function.Predicate { window ->
                val activity = window.mActivityRecord
                activity != null && activity.mUserId == claim.user &&
                    activity.mActivityComponent == home && window.isDrawn
            }) != null
        return claim.homeDrawn
    }

    /** A blank external display is not a keyboard-focus destination. Android's
     * global focus scan deliberately accepts mFocusedApp even without a window,
     * so hiding ordinary apps alone leaves the fixed HOME ahead of the phone.
     * Withdraw only the authenticated HOME and this exact claimed display's
     * global order. Recovery restores our own bit, never raises an ancestor or
     * chooses a phone/app Activity. Historical claim-user authentication is
     * permitted only while blank, to contain a previous user's fixed HOME.
     */
    private fun reconcileNativeHomeFocus(wm: WindowManagerService, claim: Claim,
        blank: Boolean): Boolean {
        val dc = claim.dc
        val user = claim.user; val generation = claim.generation; val owner = claim.owner
        fun current() = claimObjectsCurrent(wm, claim, user, generation, owner)
        if (!claim.nativeMode || user < 0 || !current()) return false
        val area = dc.defaultTaskDisplayArea ?: return false
        if (area.displayContent !== dc) return false
        val admittedLease = if (blank) null else nativeHomeDrawLease(wm, claim) ?: return false
        fun permitted() = current() && dc.defaultTaskDisplayArea === area && area.displayContent === dc &&
            (blank || (ready(wm, claim) && current() &&
                nativeHomeDrawLease(wm, claim) == admittedLease && current()))
        if (!permitted()) return false
        // Claim ownership survives removal of the APK. Withdraw only this
        // inactive display's global order even if no HOME can authenticate;
        // never use that absence as Task/cache/restore-bit authority.
        var changed = false
        if (blank && wm.mRoot.bottomChild !== dc) {
            wm.mRoot.positionChildAt(WindowContainer.POSITION_BOTTOM, dc, false)
            changed = true
        }
        if (!permitted()) return changed
        val uid = currentOwnerUid(wm, user) ?: return changed
        if (!permitted() || UserHandle.getUserId(uid) != user) return changed
        fun authenticated(task: Task): ActivityRecord? {
            if (!permitted()) return null
            val activity = task.topRunningActivity() ?: return null
            val root = task.rootTask ?: return null
            return activity.takeIf {
                permitted() &&
                task.isLeafTask && task.isAttached && task.isActivityTypeHome &&
                task.mUserId == user && task.displayContent === dc &&
                root.isAttached && root.parent === area && root.isActivityTypeHome && root.displayContent === dc &&
                !it.finishing && it.mUserId == user && it.uid == uid && it.displayContent === dc &&
                it.mActivityComponent == home && it.info.permission == "android.permission.STATUS_BAR_SERVICE"
            }
        }
        // A replaced Activity must never inherit the old object's restore bit.
        claim.parkedHomes.entries.removeAll { (task, activity) ->
            val valid = authenticated(task) === activity
            permitted() && !valid
        }
        if (!permitted()) return changed
        if (blank) {
            dc.forAllTasks(java.util.function.Consumer { task ->
                val activity = authenticated(task) ?: return@Consumer
                if (!permitted()) return@Consumer
                val focusChanged = task.setFocusable(false)
                if (!permitted()) return@Consumer
                if (focusChanged) {
                    claim.parkedHomes[task] = activity
                    changed = true
                }
                val root = task.rootTask ?: return@Consumer
                if (!permitted()) return@Consumer
                if (area.mPreferredTopFocusableRootTask === root && root.topRunningActivity() === activity) {
                    if (!permitted()) return@Consumer
                    area.mPreferredTopFocusableRootTask = null
                    changed = true
                }
                if (!permitted()) return@Consumer
                if (dc.mFocusedApp === activity) changed = dc.setFocusedApp(null) || changed
            })
        } else {
            for ((task, activity) in claim.parkedHomes.entries.toList()) {
                if (!permitted()) return changed
                changed = task.setFocusable(true) || changed
                if (!permitted()) return changed
                // A reentrant replacement must not consume its new cache.
                claim.parkedHomes.remove(task, activity)
            }
        }
        return changed
    }

    private fun show(wm: WindowManagerService, claim: Claim, blank: Boolean) {
        val dc = claim.dc
        val user = claim.user; val generation = claim.generation; val owner = claim.owner
        fun current() = claimObjectsCurrent(wm, claim, user, generation, owner)
        if (!current()) return
        val liveNative = !blank && claim.nativeMode
        // A healthy lease renewal is not a blank-to-live transition. Publishing
        // a temporary blank here makes the lock-free input policy discard keys
        // even though this exact desktop remains admitted throughout renewal.
        val openingNative = liveNative && claim.blank
        val admittedLease = if (liveNative) nativeHomeDrawLease(wm, claim) else null
        fun permitted() = current() && (!liveNative ||
            (admittedLease != null && ready(wm, claim) && current() &&
                nativeHomeDrawLease(wm, claim) == admittedLease && current()))
        fun proceed(): Boolean {
            if (permitted()) return true
            // Restore the real barrier on lost admission, but never touch a
            // replacement Claim/owner/generation captured by the old call.
            if (liveNative && current()) show(wm, claim, true)
            else publishInputContainment()
            return false
        }
        if (!proceed()) return
        val changed = claim.blank != blank
        if (blank || openingNative) {
            // Input interception is lock-free. Publish fail-closed state before
            // any JNI/framework/surface operation that may throw or re-enter.
            claim.blank = true
            publishInputContainment()
        }
        // Includes timeout/lock/user-change reconciliation, not just explicit
        // owner release. A spy must not observe input behind the black layer.
        if (blank) WonadNativeBridge.onParked(dc)
        if (!proceed()) return
        if (changed) Log.i("WonadUi", "Display ${dc.displayId} generation ${claim.generation}: " +
            if (blank) "blank" else "live")
        ensureContainmentChannel(wm, claim)
        if (!proceed()) return
        ensureContainmentHandle(claim)
        if (!proceed()) return
        ensureContainmentReceiver(wm, claim)
        if (!proceed()) return
        ensureContainmentSurface(wm, claim)
        if (!proceed()) return
        // Keep black/input containment across PM and task eligibility work.
        configureContainment(claim, blank || openingNative)
        if (!proceed()) return
        protectInput(wm, claim, blank || openingNative)
        if (!proceed()) return
        if (claim.nativeMode) WonadNativeBridge.retireEmptyDesktopRoots(dc)
        if (!proceed()) return
        var visibilityChanged = false
        val shellUid = if (claim.nativeMode) currentOwnerUid(wm, claim.user) else null
        if (!proceed()) return
        dc.forAllTasks(java.util.function.Consumer { task ->
            if (!permitted()) return@Consumer
            val activity = task.topRunningActivity()
            // The black native layer/input consumer remains above this window.
            // Let ONLY the authenticated fixed shell draw behind it; hiding it
            // would deadlock the draw-readiness barrier on every cold/restart.
            val drawingShell = claim.nativeMode && shellUid != null && activity != null && activity.mActivityComponent == shell &&
                activity.mUserId == claim.user && activity.uid == shellUid &&
                activity.intent.getLongExtra("$PACKAGE.shell.GENERATION", 0) == claim.generation &&
                activity.intent.getLongExtra("$PACKAGE.shell.DISPLAY_TOKEN", 0) == claim.incarnation
            // Failure containment may have hidden the fixed shell too. Give
            // the exact authenticated shell its draw-readiness exemption by
            // explicitly clearing our bit behind the black layer; every task
            // is cleared when reopening.
            if (task.isLeafTask && task.isActivityTypeStandard && permitted())
                visibilityChanged = task.setForceHidden(TaskFragment.FLAG_FORCE_HIDDEN_FOR_WONAD,
                    blank && !drawingShell) || visibilityChanged
            else if (claimedNativeHome(wm, claim, task) != null && current() &&
                    nativeHomeDrawLease(wm, claim) == null && current()) {
                claim.homeDrawn = false
                visibilityChanged = task.setForceHidden(TaskFragment.FLAG_FORCE_HIDDEN_FOR_WONAD,
                    true) || visibilityChanged
            }
        })
        if (!proceed()) return
        if (openingNative) {
            configureContainment(claim, false)
            if (!proceed()) return
            protectInput(wm, claim, false)
            if (!proceed()) return
        }
        claim.blank = blank
        publishInputContainment()
        if (!proceed()) return
        visibilityChanged = reconcileNativeHomeFocus(wm, claim, blank) || visibilityChanged
        if (!proceed()) return
        if (visibilityChanged) {
            // setForceHidden changes native eligibility/order, but does not
            // itself restore an Activity's visibleRequested/resumed lifecycle.
            wm.mRoot.ensureActivitiesVisible()
            if (!proceed()) return
            wm.mRoot.resumeFocusedTasksTopActivities()
            if (!proceed()) return
        }
        wm.updateFocusedWindowLocked(WindowManagerService.UPDATE_FOCUS_NORMAL, true)
        if (!proceed()) return
        wm.mAtmService.mTaskSupervisor.updateTopResumedActivityIfNeeded("wonad-external-ui")
        if (!proceed()) return
        dc.scheduleAnimation()
        if (!proceed()) return
    }

    private fun ensureContainmentChannel(wm: WindowManagerService, claim: Claim) {
        if (claim.channel == null) claim.channel =
            wm.mInputManager.createInputChannel("Wonad inactive ${claim.dc.displayId}")
    }

    private fun ensureContainmentHandle(claim: Claim) {
        if (claim.handle != null) return
        val channel = checkNotNull(claim.channel)
        claim.handle = InputWindowHandle(null, claim.dc.displayId).also {
            it.name = "Wonad inactive ${claim.dc.displayId}"; it.token = channel.token
            it.ownerPid = Process.myPid(); it.ownerUid = Process.SYSTEM_UID
            it.inputConfig = InputConfig.NOT_FOCUSABLE
            it.layoutParamsType = WindowManager.LayoutParams.TYPE_INPUT_CONSUMER
            it.scaleFactor = 1f; it.dispatchingTimeoutMillis = 5000
        }
    }

    private fun ensureContainmentReceiver(wm: WindowManagerService, claim: Claim) {
        if (claim.receiver != null) return
        val channel = checkNotNull(claim.channel)
        // Native InputEventReceiver takes ownership of the channel; obtain the
        // token for the handle before constructing this receiver.
        claim.receiver = object : InputEventReceiver(channel, wm.mH.looper) {
            override fun onInputEvent(event: InputEvent) { finishInputEvent(event, true) }
        }
    }

    private fun ensureContainmentSurface(wm: WindowManagerService, claim: Claim) {
        val dc = claim.dc
        if (claim.surface == null) claim.surface = containmentSurfaceBuilder(wm, dc)
            .setColorLayer().setName("Wonad inactive ${dc.displayId}")
            .setCallsite("WonadUiBridge").build()
    }

    private fun configureContainment(claim: Claim, blank: Boolean) {
        val dc = claim.dc
        val surface = checkNotNull(claim.surface)
        val handle = checkNotNull(claim.handle)
        val info = dc.displayInfo
        handle.touchableRegion.set(0, 0, info.logicalWidth, info.logicalHeight)
        val transaction = dc.pendingTransaction
        handle.setTrustedOverlay(transaction, surface, true)
        transaction.setLayer(surface, Int.MAX_VALUE - 1).setColor(surface, floatArrayOf(0f, 0f, 0f))
            .setWindowCrop(surface, info.logicalWidth, info.logicalHeight)
            .setInputWindowInfo(surface, handle)
        if (blank) transaction.show(surface) else transaction.hide(surface)
    }

    /** Poll failures are recoverable extension failures, but only after actual
     * system-server containment is queued. Do not replace that with volatile
     * bookkeeping: create/show the black input surface and hide every app by
     * native object before dropping the owner or asking JNI to park its lease.
     */
    private fun containAndRelease(wm: WindowManagerService, claim: Claim,
        primary: Throwable?, message: String) {
        val expectedGeneration = claim.generation
        val expectedOwner = claim.owner
        val expectedUser = claim.user
        fun current(): Boolean = claimObjectsCurrent(wm, claim, expectedUser,
            expectedGeneration, expectedOwner)
        if (!current()) {
            if (primary != null) Log.e("WonadUi", message, primary)
            if (primary != null && primary !is Exception && primary !is LinkageError) throw primary
            return
        }
        // This volatile gate is consumed off the WM thread. Close it before
        // every fallible containment/release step; later replacement checks
        // prevent this old claim from overwriting a new claim's snapshot.
        claim.homeDrawn = false
        claim.blank = true
        publishInputContainment()
        // Retire exact keyboard authority before any fallible parking step.
        // blankDisplays remains the independent fail-closed dispatch barrier.
        val failures = WonadCleanupFailures()
        failures.attempt { retireShortcutClaim(claim) }
        failures.attempt { WonadNativeBridge.onParked(claim.dc) }
        if (!current()) {
            publishInputContainment()
            failures.supportedFailure?.let {
                if (primary != null && it !== primary &&
                    (primary is Exception || primary is LinkageError)) primary.addSuppressed(it)
            }
            failures.rethrowFatal(primary)
            return
        }
        failures.attempt { if (current()) ensureContainmentChannel(wm, claim) }
        failures.attempt { if (current()) ensureContainmentHandle(claim) }
        failures.attempt { if (current()) ensureContainmentReceiver(wm, claim) }
        failures.attempt { if (current()) ensureContainmentSurface(wm, claim) }
        failures.attempt { if (current()) configureContainment(claim, true) }
        failures.attempt { if (current()) protectInput(wm, claim, true) }

        val tasks = mutableListOf<Task>()
        failures.attempt { if (current()) claim.dc.forAllTasks(java.util.function.Consumer { task ->
            if (current() && task.isLeafTask && (task.isActivityTypeStandard ||
                    claimedNativeHome(wm, claim, task) != null)) tasks.add(task)
        }) }
        var visibilityChanged = false
        tasks.forEach { task -> failures.attempt {
            if (current()) visibilityChanged = task.setForceHidden(
                TaskFragment.FLAG_FORCE_HIDDEN_FOR_WONAD, true) || visibilityChanged
        } }

        if (current()) {
            claim.protectedInput = false
            publishInputContainment()
            failures.attempt {
                visibilityChanged = reconcileNativeHomeFocus(wm, claim, true) || visibilityChanged
            }
            if (visibilityChanged) {
                failures.attempt { wm.mRoot.ensureActivitiesVisible() }
                failures.attempt { wm.mRoot.resumeFocusedTasksTopActivities() }
            }
            failures.attempt {
                wm.updateFocusedWindowLocked(WindowManagerService.UPDATE_FOCUS_NORMAL, true)
            }
            failures.attempt {
                wm.mAtmService.mTaskSupervisor.updateTopResumedActivityIfNeeded("wonad-external-ui-failure")
            }
            failures.attempt { claim.dc.scheduleAnimation() }
        }

        // Release comes last: even a broken/missing JNI bridge cannot bypass
        // the independently established framework containment above.
        if (current()) failures.attempt {
            InputNative.uiPark(claim.dc.displayId, claim.incarnation, expectedGeneration)
        }
        if (current()) failures.attempt { unlink(claim) }
        if (!current()) {
            publishInputContainment()
        }
        failures.supportedFailure?.let { failure ->
            if (primary != null && failure !== primary &&
                (primary is Exception || primary is LinkageError)) primary.addSuppressed(failure)
        }
        val reported = primary ?: failures.supportedFailure
        if (reported != null) Log.e("WonadUi", message, reported)
        failures.rethrowFatal(primary)
    }

    private fun containmentSurfaceBuilder(wm: WindowManagerService, dc: DisplayContent): SurfaceControl.Builder =
        // DisplayContent migrates this exact OS overlay, in the same surface
        // transaction, when an organizer dies and its root is replaced. Direct
        // untracked root children would lose their black/input containment.
        wm.makeSurfaceBuilder().setParent(dc.inputOverlayLayer)

    private fun protectInput(wm: WindowManagerService, claim: Claim, blank: Boolean = claim.blank) {
        val dc = claim.dc
        val blocked = claim.nativeMode && !blank && WonadNativeBridge.protectedInput(wm, claim.user)
        if (claim.protectedInputSurface == null && blocked) {
            // As in stock InputConsumerImpl, a container layer has no pixels
            // but supplies a native input window. No APK gets this channel.
            claim.protectedInputSurface = containmentSurfaceBuilder(wm, dc).setContainerLayer()
                .setName("Wonad protected input ${dc.displayId}")
                .setCallsite("WonadUiBridge.protectInput").build()
        }
        claim.protectedInputSurface?.let { surface ->
            val handle = checkNotNull(claim.handle)
            val info = dc.displayInfo
            handle.touchableRegion.set(0, 0, info.logicalWidth, info.logicalHeight)
            handle.setTrustedOverlay(dc.pendingTransaction, surface, true)
            dc.pendingTransaction.setLayer(surface, Int.MAX_VALUE - 1)
                .setPosition(surface, 0f, 0f).setWindowCrop(surface, info.logicalWidth, info.logicalHeight)
                .setInputWindowInfo(surface, handle)
            if (blocked) dc.pendingTransaction.show(surface) else dc.pendingTransaction.hide(surface)
        }
        if (claim.protectedInput != blocked) {
            claim.protectedInput = blocked
            dc.scheduleAnimation()
        }
        publishInputContainment()
    }

    /** Focus-change transaction, not just the 250ms reconciliation watchdog.
     * External app windows must not get a tap between a trusted phone prompt
     * taking focus and the next poll installing its native input consumer. */
    internal fun reconcileProtectedInput(wm: WindowManagerService) {
        claims.values.filter { it.nativeMode && it.surface != null }.forEach { protectInput(wm, it) }
    }

    /** Stock launches/Recents may move a parked task to the phone without
     * unplugging its old monitor. Retire only this extension's task state;
     * the phone's stock hierarchy, focus, keyguard and other hiding bits win.
     * Called by Task.onDisplayChanged under WM's lock, after native reparent.
     */
    @JvmStatic fun onTaskDisplayChanged(task: Task, previous: DisplayContent?) {
        val old = previous ?: return
        val dc = task.displayContent ?: return
        if (old === dc || old.displayId <= Display.DEFAULT_DISPLAY || dc.displayId != Display.DEFAULT_DISPLAY ||
            old.mWmService !== dc.mWmService || !task.isAttached || !task.isLeafTask ||
            !task.isActivityTypeStandard || task.mCreatedByOrganizer) return
        val claim = claims[old.displayId] ?: return
        if (claim.dc !== old || !claim.nativeMode || task.mUserId != claim.user ||
            task.mUserId != dc.mWmService.mCurrentUserId) return
        // Reuse native enumeration's ordinary-app/UID/system-role checks.
        // A visible app has no hiding bit, but its native desktop geometry
        // still belongs to the departing claimed monitor and must be retired.
        if (!WonadNativeBridge.returningPhoneApp(task, claim.user)) return
        task.setForceHidden(TaskFragment.FLAG_FORCE_HIDDEN_FOR_WONAD, false)
        task.setForceHidden(TaskFragment.FLAG_FORCE_HIDDEN_FOR_WONAD_POLICY, false)
        task.setFocusable(true)
        task.setWindowingMode(WindowConfiguration.WINDOWING_MODE_UNDEFINED)
        task.setBounds(null)
        task.surfaceControl?.let { surface ->
            task.pendingTransaction.setPosition(surface, 0f, 0f).setWindowCrop(surface, null)
                .setShadowRadius(surface, 0f).setCornerRadius(surface, 0f)
        }
        // No display/root raise, session reopening, consent change or explicit
        // resume: continue the ordinary framework transaction that moved it.
    }

    @JvmStatic fun onRemoved(dc: DisplayContent) {
        val claim = claims[dc.displayId]?.takeIf { it.dc === dc }
        // InputDispatcher may already hold an event stamped with this numeric
        // display id. Publish the temporary barrier before removing the exact
        // claim/token/Owner and retain it through every detach attempt.
        if (claim != null) beginDepartingInputBarrier(dc.displayId)
        attachments[dc.displayId]?.takeIf { it.first === dc }?.let { attachments.remove(dc.displayId) }
        attachmentHints.keys.removeAll { it.first === dc }
        val failures = WonadCleanupFailures()
        if (claim != null && claims[dc.displayId] === claim) claims.remove(dc.displayId)
        publishInputContainment()
        // Exact claim authority disappears before every fallible detach step.
        if (claim != null) failures.attempt { retireShortcutClaim(claim) }
        failures.attempt { WonadNativeBridge.onRemoved(dc) }
        if (claim != null) {
            val wm = dc.mWmService
            // The exact departing claim was captured and removed before any
            // fallible/reentrant cleanup. A replacement reusing the numeric id
            // is independent and remains in the map and volatile snapshots.

            failures.attempt { InputNative.uiDetach(dc.displayId, claim.incarnation) }
            failures.attempt { unlink(claim) }
            claim.pollScheduled = false
            failures.attempt { wm.mH.removeCallbacks(claim.poll) }

            // Transient APK shell UI must never be reparented onto the phone
            // when its physical display disappears. Resolve exact native leaf
            // objects, not recycled task IDs, and attempt each removal even if
            // a sibling has already failed.
            val transient = mutableListOf<Task>()
            failures.attempt { dc.forAllTasks(java.util.function.Consumer { task ->
                if (task.isLeafTask && task.mUserId == claim.user &&
                    task.topRunningActivity()?.mActivityComponent in setOf(launcher, shell, clientPrompt)) transient.add(task)
            }) }
            transient.forEach { task -> failures.attempt {
                task.removeImmediately("wonad-external-launcher-detach")
            } }

            if (claim.nativeMode) failures.attempt { WonadNativeBridge.undockApps(dc, claim.user) }

            // Display removal moves survivors to the phone or another monitor.
            // Clear only our two hiding bits and restore each exact survivor
            // independently; another task's failure must not strand this one.
            val survivors = mutableListOf<Task>()
            failures.attempt { dc.forAllTasks(java.util.function.Consumer { survivors.add(it) }) }
            survivors.forEach { task ->
                failures.attempt {
                    task.setForceHidden(TaskFragment.FLAG_FORCE_HIDDEN_FOR_WONAD, false)
                }
                failures.attempt {
                    task.setForceHidden(TaskFragment.FLAG_FORCE_HIDDEN_FOR_WONAD_POLICY, false)
                }
                if (claim.nativeMode) failures.attempt {
                    WonadNativeBridge.restoreUndockedFocus(task, claim.user)
                }
            }

            failures.attempt {
                claim.handle?.token?.let { wm.mInputManager.removeInputChannel(it) }
            }
            val dispose = Runnable { disposeClaimInput(claim) }
            var posted = false
            failures.attempt { posted = wm.mH.post(dispose) }
            if (!posted) failures.attempt { dispose.run() }
            claim.surface?.let { surface ->
                failures.attempt { dc.pendingTransaction.remove(surface) }
            }
            claim.protectedInputSurface?.let { surface ->
                failures.attempt { dc.pendingTransaction.remove(surface) }
            }

            // Release only this removal's temporary barrier after every detach
            // attempt. Recompute from current exact claims so a reentrant same-id
            // replacement and unrelated departure barriers retain their state.
            endDepartingInputBarrier(dc.displayId)
        }
        failures.supportedFailure?.let {
            Log.e("WonadUi", "External display cleanup completed with failures", it)
        }
        failures.rethrowFatal()
    }

    private fun disposeClaimInput(claim: Claim) {
        val failures = WonadCleanupFailures()
        failures.attempt { claim.receiver?.dispose() }
        failures.attempt { claim.channel?.dispose() }
        failures.supportedFailure?.let {
            Log.e("WonadUi", "External display input cleanup completed with failures", it)
        }
        failures.rethrowFatal()
    }
}
