package org.wonad.server.input

import android.app.ActivityManager
import android.app.ActivityManagerInternal
import android.content.Context
import android.hardware.display.DisplayManager
import android.os.Binder
import android.os.IBinder
import android.os.SystemClock
import android.os.UserHandle
import android.provider.Settings
import android.util.Log
import android.view.Display
import android.view.KeyEvent
import android.view.WindowManagerPolicyConstants.FLAG_TRUSTED
import com.android.internal.os.BackgroundThread
import com.android.internal.policy.IShortcutService
import com.android.server.LocalServices
import com.android.server.wm.ActivityTaskManagerInternal
import com.android.server.wm.WindowManagerInternal
import com.android.server.wm.WonadCleanupFailures
import com.android.server.wm.WonadUiBridge
import com.android.server.wm.WonadNativeBridge
import java.util.concurrent.Semaphore

/** system_server glue. The only registration caller is the platform SystemUI.
 * Native Rust sees copied scalars; SystemUI receives only fixed command IDs.
 * No remote command callback is made on the input dispatch thread or under this lock.
 */
object WonadInputBridge {
    private const val TAG = "WonadInput"
    private val lock = Any()
    private val queue = Semaphore(32)
    @Volatile private var available: Boolean? = null
    private val owners = mutableMapOf<Int, Owner>()
    private class Owner(val generation: Long, val user: Int, val display: Int,
        var expires: Long, val receiver: IShortcutService,
        val claim: WonadUiBridge.ShortcutClaim) {
        lateinit var death: IBinder.DeathRecipient
        var shortcutKeys = false
    }

    private fun nativeReady(): Boolean {
        available?.let { return it }
        return try {
            InputNative.release(0)
            available = true; true
        } catch (error: Throwable) {
            if (error !is Exception && error !is LinkageError) throw error
            Log.e(TAG, "Desktop shortcuts remain disabled: native bridge unavailable", error)
            available = false; false
        }
    }

    private fun clear(expected: Owner) = synchronized(lock) {
        if (owners[expected.display] === expected) {
            owners.remove(expected.display)
            val failures = WonadCleanupFailures()
            failures.attempt { expected.receiver.asBinder().unlinkToDeath(expected.death, 0) }
            failures.attempt { InputNative.releaseDisplay(expected.generation, expected.display) }
            failures.supportedFailure?.let {
                Log.e(TAG, "Shortcut lease cleanup completed with failures", it)
            }
            failures.rethrowFatal()
        }
    }

    private fun activeUser() = LocalServices.getService(ActivityManagerInternal::class.java).currentUserId
    private fun unlocked(wm: WindowManagerInternal) = !wm.isKeyguardLocked && !wm.isKeyguardShowing &&
        LocalServices.getService(ActivityTaskManagerInternal::class.java).lockTaskModeState == ActivityManager.LOCK_TASK_MODE_NONE

    private fun eligible(context: Context, displayId: Int): Boolean {
        val d = context.getSystemService(DisplayManager::class.java).getDisplay(displayId) ?: return false
        return displayId > 0 && d.state == Display.STATE_ON && d.flags and Display.FLAG_TRUSTED != 0 &&
            d.flags and Display.FLAG_PRIVATE == 0 && d.flags and Display.FLAG_SECURE != 0 &&
            (d.type == Display.TYPE_EXTERNAL || d.type == Display.TYPE_VIRTUAL)
    }

    private fun exactOwner(display: Int): Owner? = synchronized(lock) { owners[display] }
        ?.takeIf { WonadUiBridge.shortcutClaimCurrent(it.claim) }

    private fun claimActive(context: Context, wm: WindowManagerInternal,
        state: WonadUiBridge.ShortcutClaimState, now: Long): Boolean =
        WonadUiBridge.shortcutClaimCurrent(state.claim) && state.claim.owner.isBinderAlive &&
        now < state.expires && state.claim.user == activeUser() && unlocked(wm) &&
        eligible(context, state.claim.display) && Settings.Secure.getIntForUser(
            context.contentResolver, "wonad_external_desktop_enabled", 0, state.claim.user) == 1

    private fun ownerActive(context: Context, wm: WindowManagerInternal, owner: Owner,
        state: WonadUiBridge.ShortcutClaimState?, now: Long): Boolean = state != null &&
        state.claim === owner.claim && owner.display == state.claim.display &&
        owner.user == state.claim.user && owner.generation == state.claim.generation &&
        now < owner.expires && claimActive(context, wm, state, now)

    /** Once a live lease has seen a supported bridge failure, keep its keys out
     * of stock policy until SystemUI retires that exact Java owner. The next
     * renewal fails and drives the display through the independent native-UI
     * fail-black path; allowing keys through during that interval could invoke
     * an Android Meta shortcut on a still-visible claimed desktop. */
    private fun failedBridgeConsumes(display: Int): Boolean =
        available == false && exactOwner(display) != null

    /** WMS publishes claim removal before calling here and does not publish a
     * replacement token until this exact cleanup completes. A delayed old
     * callback therefore cannot release replacement Rust state. */
    @JvmStatic internal fun onUiClaimRetired(expected: WonadUiBridge.ShortcutClaim) {
        val owner = synchronized(lock) { owners[expected.display] }
        if (owner?.claim === expected) clear(owner)
    }

    /** Called from IWindowManager with the original Binder caller identity. */
    @JvmStatic fun setLease(context: Context, display: Int, user: Int, generation: Long,
        expires: Long, receiver: IShortcutService?): Boolean =
        setLeaseMode(context, display, user, generation, expires, receiver, false)

    @JvmStatic fun setKeyLease(context: Context, display: Int, user: Int, generation: Long,
        expires: Long, receiver: IShortcutService?): Boolean =
        setLeaseMode(context, display, user, generation, expires, receiver, true)

    @JvmStatic fun shortcutPrefix(context: Context): Int {
        context.enforceCallingPermission("android.permission.STATUS_BAR_SERVICE", "Wonad shortcut profile")
        val uid = context.packageManager.getPackageUidAsUser("com.android.systemui", UserHandle.USER_SYSTEM)
        if (Binder.getCallingUid() != uid) throw SecurityException("Shortcut profile is SystemUI-only")
        return if (nativeReady()) InputNative.shortcutPrefix() else 0
    }

    private fun setLeaseMode(context: Context, display: Int, user: Int, generation: Long,
        expires: Long, receiver: IShortcutService?, shortcutKeys: Boolean): Boolean {
        context.enforceCallingPermission("android.permission.STATUS_BAR_SERVICE", "Wonad shortcut lease")
        val uid = Binder.getCallingUid()
        val systemUiUid = context.packageManager.getPackageUidAsUser("com.android.systemui", UserHandle.USER_SYSTEM)
        if (uid != systemUiUid) throw SecurityException("Shortcut registration is SystemUI-only")

        // Cleanup must remain available after the optional JNI bridge has
        // failed. Removing Java callback authority first is safe, and clear()
        // independently attempts native release while retaining diagnostics.
        // Negative display IDs are availability probes and still exercise JNI.
        if (receiver == null && display > 0) {
            synchronized(lock) {
                owners[display]?.let { if (it.generation == generation) clear(it) }
            }
            return true
        }
        if (!nativeReady()) return false
        val wm = LocalServices.getService(WindowManagerInternal::class.java)
        val claim = if (receiver != null)
            WonadUiBridge.shortcutClaim(display, user, generation) ?: return false
        else null
        if (receiver != null && (user != activeUser() || !unlocked(wm) || !eligible(context, display) ||
            Settings.Secure.getIntForUser(context.contentResolver, "wonad_external_desktop_enabled", 0, user) != 1)) return false
        synchronized(lock) {
            if (receiver == null) {
                owners[display]?.let { if (it.generation == generation) clear(it) }
                return true // generation=0 probes availability, never revokes a live owner.
            }
            val now = SystemClock.elapsedRealtime()
            owners.values.toList().forEach { if (now >= it.expires) clear(it) }
            if (display !in owners && owners.size >= 9) return false
            if (owners.values.any { it.generation != generation || it.user != user }) return false
            val owner = owners[display]
            val exactClaim = checkNotNull(claim)
            if (!WonadUiBridge.shortcutClaimCurrent(exactClaim)) return false
            owner?.let {
                if (it.generation != generation || it.user != user || it.display != display ||
                    it.receiver.asBinder() != receiver.asBinder() || it.claim !== exactClaim) return false
            }
            if (!(if (shortcutKeys) InputNative.renewKeys(generation, user, display, expires, now)
                else InputNative.renew(generation, user, display, expires, now))) return false
            if (!WonadUiBridge.shortcutClaimCurrent(exactClaim)) {
                // The replacement token is deliberately unpublished until its
                // predecessor has been retired, so this release is exact.
                try { InputNative.releaseDisplay(generation, display) }
                catch (error: Throwable) {
                    if (error !is Exception && error !is LinkageError) throw error
                    Log.e(TAG, "Could not retire an unpublished shortcut lease", error)
                    available = false
                }
                return false
            }
            if (owner == null) {
                val next = Owner(generation, user, display, expires, receiver, exactClaim)
                next.shortcutKeys = shortcutKeys
                next.death = IBinder.DeathRecipient { clear(next) }
                owners[display] = next
                try { receiver.asBinder().linkToDeath(next.death, 0) }
                catch (error: Throwable) {
                    val cleanup = WonadCleanupFailures()
                    cleanup.attempt { clear(next) }
                    cleanup.rethrowFatal(error)
                    return false
                }
            } else { owner.expires = expires; owner.shortcutKeys = shortcutKeys }
            return true
        }
    }

    /** Pure Rust alphabet, not a grant. Only fixed desktop keys are examined
     * before stock Meta gestures; all other system keys keep their old order.
     * The dispatch hook calls intercept exactly once for each physical event,
     * including captured UPs with no remaining modifiers after focus changes.
     */
    @JvmStatic fun shortcutKey(keyCode: Int): Boolean {
        // After a bridge failure, returning true only asks the priority hook to
        // consult intercept(). That second step checks the event's exact display
        // and retained owner; phone and unrelated-display shortcuts still pass.
        if (available != true) return available == false &&
            synchronized(lock) { owners.values.toList() }.any {
                WonadUiBridge.shortcutClaimCurrent(it.claim)
            }
        return try { InputNative.commandKey(keyCode) }
        catch (error: Throwable) {
            if (error !is Exception && error !is LinkageError) throw error
            Log.e(TAG, "Desktop shortcut priority unavailable after bridge failure", error)
            available = false
            synchronized(lock) { owners.values.toList() }.any {
                WonadUiBridge.shortcutClaimCurrent(it.claim)
            }
        }
    }

    private fun modifiers(event: KeyEvent): Int =
        KeyEvent.normalizeMetaState(event.metaState) and (KeyEvent.META_CTRL_ON or
            KeyEvent.META_META_ON or KeyEvent.META_SHIFT_ON or KeyEvent.META_ALT_ON or
            KeyEvent.META_SYM_ON or KeyEvent.META_FUNCTION_ON)

    /** Observe only an exact prior captured pair. eligible_display=0 and
     * unlocked=0 make command creation impossible in the Rust state machine;
     * trusted policy provenance is still required before draining a pair. */
    private fun drainContained(wm: WindowManagerInternal, event: KeyEvent, policyFlags: Int,
        owner: Owner?) {
        if (available != true || policyFlags and FLAG_TRUSTED == 0) return
        try {
            val code = InputNative.event(longArrayOf(SystemClock.elapsedRealtime(),
                (owner?.user ?: activeUser()).toLong(), event.displayId.toLong(),
                wm.topFocusedDisplayId.toLong(), 0, 0, 1, event.keyCode.toLong(),
                modifiers(event).toLong(), event.action.toLong(), event.repeatCount.toLong(),
                event.deviceId.toLong(), event.downTime, if (event.isCanceled) 1 else 0))
            if (code > 0) {
                // No callback is made, even if incompatible native code ever
                // violates the command-disabled frame contract.
                available = false
                Log.e(TAG, "Command-disabled containment observation returned a command",
                    IllegalStateException("Unexpected contained command $code"))
            }
        } catch (error: Throwable) {
            if (error !is Exception && error !is LinkageError) throw error
            Log.e(TAG, "Contained key-pair observation disabled after native failure", error)
            available = false
        }
    }

    /** Read-only final dispatch decision. It neither enters Rust nor delivers
     * a command, so intercept() can safely repeat it after a stale-owner guard,
     * JNI pass result or JNI failure without observing one physical key twice. */
    private fun claimedInputBlocked(context: Context, wm: WindowManagerInternal,
        display: Int): Boolean {
        if (display <= Display.DEFAULT_DISPLAY) return false
        // The already-published containment barriers do not depend on any
        // further framework state read. Recheck them below as well, closing a
        // race with WMS publishing containment while this method validates.
        if (WonadUiBridge.consumeInput(display) || failedBridgeConsumes(display)) return true
        val state = WonadUiBridge.currentShortcutClaimState(display)
        val owner = exactOwner(display)
        val invalid = state != null && try {
            val now = SystemClock.elapsedRealtime()
            !claimActive(context, wm, state, now) ||
                (owner != null && !ownerActive(context, wm, owner, state, now))
        } catch (error: Throwable) {
            if (error !is Exception && error !is LinkageError) throw error
            Log.e(TAG, "Claimed input state check failed closed", error)
            true
        }
        return WonadUiBridge.consumeInput(display) || failedBridgeConsumes(display) || invalid
    }

    /** Early policy seam for paste/action/app-capture branches which return
     * before ordinary shortcut interception. InputDispatcher has already
     * resolved KeyEvent.displayId; never substitute a mutable focused display
     * or grant authority from a generic numeric external id. */
    @JvmStatic fun consumeClaimedInput(context: Context, wm: WindowManagerInternal,
        event: KeyEvent, policyFlags: Int): Boolean {
        val display = event.displayId
        if (!claimedInputBlocked(context, wm, display)) return false
        drainContained(wm, event, policyFlags, exactOwner(display))
        return true
    }

    /** Acquiring the bounded delivery slot and posting are one operation. A
     * rejected or throwing Handler must return the slot before stock key
     * dispatch continues; fatal failures retain their original identity. */
    private fun postCommand(action: () -> Unit): Boolean {
        var posted = false
        try {
            posted = BackgroundThread.getHandler().post { action() }
            return posted
        } finally {
            if (!posted) queue.release()
        }
    }

    /** Fixed desktop keys run before stock Meta gestures, all other keys after
     * non-capturable system keys. Every command still needs the exact live,
     * unlocked, trusted, focused external-display lease below.
     */
    @JvmStatic fun intercept(context: Context, wm: WindowManagerInternal, event: KeyEvent, policyFlags: Int): Boolean {
        val target = event.displayId
        if (consumeClaimedInput(context, wm, event, policyFlags)) return true
        if (available != true || policyFlags and FLAG_TRUSTED == 0)
            return claimedInputBlocked(context, wm, target)
        return try {
            val focused = wm.topFocusedDisplayId
            val display = event.displayId
            val current = synchronized(lock) { owners[display] }
            val user = activeUser()
            val exact = current?.takeIf { WonadUiBridge.shortcutClaimCurrent(it.claim) }
            val state = WonadUiBridge.currentShortcutClaimState(display)
            val now = SystemClock.elapsedRealtime()
            val allowed = exact != null && ownerActive(context, wm, exact, state, now)
            if (exact != null && !allowed) {
                drainContained(wm, event, policyFlags, exact)
                return true
            }
            val displayEligible = allowed
            if (allowed && displayEligible && current != null && display == focused &&
                now < current.expires)
                WonadNativeBridge.observeMeta(event, display,
                    if (current.shortcutKeys) InputNative.shortcutPrefix() else KeyEvent.META_META_ON, current.shortcutKeys)
            val code: Long? = synchronized(lock) {
                if (owners[display] !== current ||
                    (exact != null && !WonadUiBridge.shortcutClaimCurrent(exact.claim))) null
                else InputNative.event(longArrayOf(SystemClock.elapsedRealtime(), user.toLong(), display.toLong(), focused.toLong(),
                    if (allowed) 1 else 0, if (displayEligible) 1 else 0, 1,
                    event.keyCode.toLong(), modifiers(event).toLong(), event.action.toLong(), event.repeatCount.toLong(),
                    event.deviceId.toLong(), event.downTime, if (event.isCanceled) 1 else 0))
            }
            if (code == null) return claimedInputBlocked(context, wm, target)
            if (code > 0 && current != null && queue.tryAcquire()) {
                postCommand {
                    try {
                        val now = SystemClock.elapsedRealtime()
                        val state = WonadUiBridge.currentShortcutClaimState(display)
                        val live = synchronized(lock) { owners[display] === current } &&
                            ownerActive(context, wm, current, state, now)
                        if (live && wm.topFocusedDisplayId == current.display) {
                            current.receiver.notifyShortcutKeyPressed(code)
                        }
                    } catch (error: Throwable) {
                        val cleanup = WonadCleanupFailures()
                        cleanup.attempt { clear(current) }
                        cleanup.rethrowFatal(error)
                    }
                    finally { queue.release() }
                }
            }
            code != 0L || claimedInputBlocked(context, wm, target)
        } catch (error: Exception) {
            Log.e(TAG, "Desktop input hook disabled after failure", error)
            available = false; claimedInputBlocked(context, wm, target)
        } catch (error: LinkageError) {
            Log.e(TAG, "Desktop input hook disabled after native failure", error)
            available = false; claimedInputBlocked(context, wm, target)
        }
    }
}
