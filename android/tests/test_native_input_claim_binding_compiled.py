"""Compile exact claim-binding and synchronous input-containment helpers.

These fixtures execute the workspace Kotlin method bodies with small typed
framework doubles.  They do not qualify an OS image or replace device tests.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_native_ui_surface_migration_compiled import JDK, KOTLINC, method


ANDROID = Path(__file__).resolve().parents[1]
INPUT = ANDROID / "input-integration/src/org/wonad/server/input/WonadInputBridge.kt"
UI = ANDROID / "input-integration/src/com/android/server/wm/WonadUiBridge.kt"


UI_PREFIX = r'''
package com.android.server.wm

object Display { const val DEFAULT_DISPLAY = 0 }
object SystemClock { var now = 100L; fun elapsedRealtime() = now }
class Binder(var isBinderAlive: Boolean = true)
class DisplayContent(val displayId: Int)

object WonadInputBridge {
    data class Retirement(val claim: Probe.ShortcutClaim, val snapshotAbsent: Boolean)
    val owners = mutableMapOf<Int, Probe.ShortcutClaim>()
    val retirements = mutableListOf<Retirement>()
    var retirementFailure: Throwable? = null
    fun onUiClaimRetired(expected: Probe.ShortcutClaim) {
        retirements += Retirement(expected, Probe.rawClaim(expected.display) == null)
        if (owners[expected.display] === expected) owners.remove(expected.display)
        retirementFailure?.let { throw it }
    }
}

object Probe {
    private class Claim(val dc: DisplayContent, val incarnation: Long) {
        var user = -1
        var generation = 0L
        var expires = 0L
        var owner: Binder? = null
        var nativeMode = false
    }
    class ShortcutClaim(val display: Int, val user: Int,
        val generation: Long, val incarnation: Long, val owner: Binder)
    class ShortcutClaimState(val claim: ShortcutClaim, val expires: Long)
    @Volatile private var shortcutClaimStates: Map<Int, ShortcutClaimState> = emptyMap()
    private val claims = mutableMapOf<Int, Claim>()
'''


UI_SUFFIX = r'''
    fun configure(display: Int, incarnation: Long, user: Int, generation: Long,
        owner: Binder?, nativeMode: Boolean, expires: Long = 200) {
        val claim = claims.getOrPut(display) { Claim(DisplayContent(display), incarnation) }
        check(claim.incarnation == incarnation)
        claim.user = user
        claim.generation = generation
        claim.expires = expires
        claim.owner = owner
        claim.nativeMode = nativeMode
    }
    fun replaceClaim(display: Int, incarnation: Long, user: Int, generation: Long,
        owner: Binder, expires: Long) {
        claims[display] = Claim(DisplayContent(display), incarnation).also {
            it.user = user; it.generation = generation; it.expires = expires
            it.owner = owner; it.nativeMode = true
        }
    }
    fun publishForTest(display: Int) = publishShortcutClaim(checkNotNull(claims[display]))
    fun retireForTest(display: Int) = retireShortcutClaim(checkNotNull(claims[display]))
    fun rawClaim(display: Int): ShortcutClaim? = shortcutClaimStates[display]?.claim
    fun rawState(display: Int): ShortcutClaimState? = shortcutClaimStates[display]
    fun lookup(display: Int, user: Int, generation: Long) =
        shortcutClaim(display, user, generation)
}

var checks = 0
fun expect(value: Boolean, label: String) { check(value) { label }; checks++ }

fun main() {
    val firstBinder = Binder()
    Probe.configure(2, 11, 0, 7, firstBinder, false)
    Probe.publishForTest(2)
    expect(Probe.rawClaim(2) == null, "non-native UI cannot publish shortcut authority")

    Probe.configure(2, 11, 0, 7, firstBinder, true)
    Probe.publishForTest(2)
    val first = checkNotNull(Probe.rawClaim(2))
    expect(first.display == 2 && first.user == 0 && first.generation == 7L &&
        first.incarnation == 11L && first.owner === firstBinder,
        "published token binds exact display user generation incarnation and owner")
    expect(Probe.lookup(2, 0, 7) === first, "exact lookup returns the published object")
    expect(Probe.lookup(2, 1, 7) == null && Probe.lookup(2, 0, 8) == null,
        "numeric display alone never grants shortcut authority")
    val firstState = checkNotNull(Probe.rawState(2))
    Probe.configure(2, 11, 0, 7, firstBinder, true, expires = 250)
    Probe.publishForTest(2)
    expect(Probe.rawClaim(2) === first && Probe.rawState(2) !== firstState &&
        Probe.rawState(2)?.expires == 250L && WonadInputBridge.retirements.isEmpty(),
        "heartbeat atomically updates deadline while retaining exact token")

    WonadInputBridge.owners[2] = first
    val replacementBinder = Binder()
    Probe.configure(2, 11, 0, 8, replacementBinder, true, expires = 300)
    Probe.publishForTest(2)
    val replacement = checkNotNull(Probe.rawClaim(2))
    expect(replacement !== first && replacement.generation == 8L &&
        replacement.owner === replacementBinder, "replacement receives a distinct exact token")
    expect(WonadInputBridge.retirements.single().claim === first &&
        WonadInputBridge.retirements.single().snapshotAbsent,
        "old token is unpublished before exact input-owner cleanup")
    expect(2 !in WonadInputBridge.owners,
        "old input owner is cleared before replacement publication returns")

    WonadInputBridge.owners[2] = replacement
    Probe.retireForTest(2)
    expect(Probe.rawClaim(2) == null && 2 !in WonadInputBridge.owners,
        "retirement removes matching UI and input authority")

    val dead = Binder(false)
    Probe.configure(2, 11, 0, 9, dead, true)
    Probe.publishForTest(2)
    expect(Probe.rawClaim(2)?.owner === dead && Probe.lookup(2, 0, 9) == null,
        "dead exact claim remains visible for containment but grants no authority")

    Probe.configure(3, 12, 0, 0, Binder(), true)
    Probe.publishForTest(3)
    expect(Probe.rawClaim(3) == null, "non-positive generation cannot publish authority")

    val incarnationOneBinder = Binder()
    Probe.configure(5, 31, 0, 10, incarnationOneBinder, true)
    Probe.publishForTest(5)
    val incarnationOne = checkNotNull(Probe.rawClaim(5))
    WonadInputBridge.owners[5] = incarnationOne
    Probe.replaceClaim(5, 32, 0, 10, Binder(), 300)
    Probe.publishForTest(5)
    expect(Probe.rawClaim(5)?.incarnation == 32L && 5 !in WonadInputBridge.owners,
        "recycled display replaces exact incarnation only after old cleanup")

    Probe.configure(6, 41, 0, 10, Binder(), true)
    Probe.publishForTest(6)
    val fatalOld = checkNotNull(Probe.rawClaim(6))
    WonadInputBridge.owners[6] = fatalOld
    Probe.replaceClaim(6, 42, 0, 11, Binder(), 300)
    val fatal = AssertionError("retirement fatal")
    WonadInputBridge.retirementFailure = fatal
    try { Probe.publishForTest(6); error("fatal replacement cleanup expected") }
    catch (error: Error) { expect(error === fatal, "retirement fatal identity preserved") }
    expect(Probe.rawClaim(6) == null && 6 !in WonadInputBridge.owners,
        "fatal old-owner cleanup leaves replacement authority unpublished")
    println("wonad_ui_claim_binding_checks=$checks")
}
'''


INPUT_PREFIX = r'''
package org.wonad.server.input

import java.util.concurrent.Semaphore

const val FLAG_TRUSTED = 1
object Display { const val DEFAULT_DISPLAY = 0 }
object SystemClock { var now = 100L; fun elapsedRealtime() = now }
object Log { fun e(tag: String, message: String, error: Throwable) {} }
class Context { val contentResolver = Any() }
class WindowManagerInternal(var topFocusedDisplayId: Int = 2)
class Binder(var isBinderAlive: Boolean = true)
class KeyEvent(val displayId: Int, val keyCode: Int = 38, val metaState: Int = 0x11000,
    val action: Int = 0, val repeatCount: Int = 0, val deviceId: Int = 3,
    val downTime: Long = 50, val isCanceled: Boolean = false) {
    companion object {
        const val META_CTRL_ON = 0x1000
        const val META_META_ON = 0x10000
        const val META_SHIFT_ON = 1
        const val META_ALT_ON = 2
        const val META_SYM_ON = 4
        const val META_FUNCTION_ON = 8
        fun normalizeMetaState(value: Int) = value
    }
}
object Settings {
    object Secure {
        var enabled = 1
        var failure: Throwable? = null
        fun getIntForUser(resolver: Any, key: String, default: Int, user: Int): Int {
            failure?.let { throw it }
            return enabled
        }
    }
}
object WonadUiBridge {
    class ShortcutClaim(val display: Int, val user: Int, val generation: Long,
        val owner: Binder)
    class ShortcutClaimState(val claim: ShortcutClaim, val expires: Long)
    val current = mutableMapOf<Int, ShortcutClaimState>()
    val blocked = mutableSetOf<Int>()
    fun currentShortcutClaimState(display: Int) = current[display]
    fun shortcutClaimCurrent(expected: ShortcutClaim) = current[expected.display]?.claim === expected
    fun consumeInput(display: Int) = display in blocked
}
object InputNative {
    val frames = mutableListOf<LongArray>()
    var result = 0L
    var failure: Throwable? = null
    var beforeReturn: (() -> Unit)? = null
    fun event(values: LongArray): Long {
        frames += values
        beforeReturn?.also { beforeReturn = null; it() }
        failure?.let { throw it }
        return result
    }
}
object WonadNativeBridge { var observations = 0; fun observeMeta(event: KeyEvent, display: Int) { observations++ } }
class WonadCleanupFailures {
    fun attempt(action: () -> Unit) { action() }
    fun rethrowFatal(error: Throwable? = null) { if (error != null) throw error }
}
class Receiver {
    companion object { var totalCallbacks = 0 }
    fun notifyShortcutKeyPressed(code: Long) { totalCallbacks++ }
}

object Probe {
    const val TAG = "WonadInput"
    private val lock = Any()
    private val queue = Semaphore(32)
    @Volatile private var available: Boolean? = true
    private class Owner(val generation: Long, val user: Int, val display: Int, var expires: Long,
        val claim: WonadUiBridge.ShortcutClaim, val receiver: Receiver = Receiver())
    private val owners = mutableMapOf<Int, Owner>()
    var activeUserId = 0
    var unlockedState = true
    var eligibleState = true
    var activeUserCalls = 0
    var activeUserHookAt = -1
    private fun activeUser(): Int {
        activeUserCalls++
        if (activeUserCalls == activeUserHookAt) blockAndRetire(2)
        return activeUserId
    }
    private fun unlocked(wm: WindowManagerInternal) = unlockedState
    private fun eligible(context: Context, displayId: Int) = eligibleState
    private fun postCommand(action: () -> Unit): Boolean { action(); return true }
    private fun clear(expected: Owner) { if (owners[expected.display] === expected) owners.remove(expected.display) }
'''


INPUT_SUFFIX = r'''
    fun reset() {
        owners.clear()
        WonadUiBridge.current.clear()
        WonadUiBridge.blocked.clear()
        InputNative.frames.clear()
        InputNative.result = 0
        InputNative.failure = null
        InputNative.beforeReturn = null
        available = true
        activeUserId = 0
        activeUserCalls = 0
        activeUserHookAt = -1
        unlockedState = true
        eligibleState = true
        Settings.Secure.enabled = 1
        Settings.Secure.failure = null
        SystemClock.now = 100
        Receiver.totalCallbacks = 0
    }
    fun install(display: Int = 2, user: Int = 0, generation: Long = 7,
        expires: Long = 200, uiExpires: Long = expires, alive: Boolean = true,
        withOwner: Boolean = true): WonadUiBridge.ShortcutClaim {
        val claim = WonadUiBridge.ShortcutClaim(display, user, generation, Binder(alive))
        WonadUiBridge.current[display] = WonadUiBridge.ShortcutClaimState(claim, uiExpires)
        if (withOwner) owners[display] = Owner(generation, user, display, expires, claim)
        return claim
    }
    fun replaceUiClaim(display: Int) {
        val old = checkNotNull(WonadUiBridge.current[display]).claim
        val claim = WonadUiBridge.ShortcutClaim(display, old.user, old.generation, Binder())
        WonadUiBridge.current[display] = WonadUiBridge.ShortcutClaimState(claim, 200)
    }
    fun block(display: Int) { WonadUiBridge.blocked += display }
    fun blockAndRetire(display: Int) {
        WonadUiBridge.blocked += display
        WonadUiBridge.current.remove(display)
        owners.remove(display)
    }
    fun setAvailable(value: Boolean?) { available = value }
    fun isAvailable() = available
    fun callbackCount() = Receiver.totalCallbacks
    fun consume(context: Context, wm: WindowManagerInternal, event: KeyEvent, flags: Int) =
        consumeClaimedInput(context, wm, event, flags)
    fun interceptForTest(context: Context, wm: WindowManagerInternal, event: KeyEvent, flags: Int) =
        intercept(context, wm, event, flags)
}

var checks = 0
fun expect(value: Boolean, label: String) { check(value) { label }; checks++ }
fun main() {
    val context = Context()
    val wm = WindowManagerInternal(2)

    Probe.reset()
    expect(!Probe.consume(context, wm, KeyEvent(0), FLAG_TRUSTED),
        "phone input is never claimed")
    expect(InputNative.frames.isEmpty(), "phone input never reaches native drainage")

    Probe.reset()
    expect(!Probe.consume(context, wm, KeyEvent(2), FLAG_TRUSTED),
        "generic numeric external display grants no authority")

    Probe.reset(); Probe.install()
    expect(!Probe.consume(context, wm, KeyEvent(2), FLAG_TRUSTED),
        "healthy exact live owner is left for ordinary shortcut interception")

    Probe.reset(); Probe.install(withOwner = false)
    expect(!Probe.consume(context, wm, KeyEvent(2), FLAG_TRUSTED),
        "healthy exact UI claim without shortcuts leaves ordinary input alone")

    Probe.block(2)
    val captured = KeyEvent(2, keyCode = 51, metaState = 0x11001, action = 1,
        deviceId = 9, downTime = 44, isCanceled = true)
    expect(Probe.consume(context, wm, captured, FLAG_TRUSTED),
        "blank or protected claimed display consumes synchronously")
    val frame = InputNative.frames.single()
    expect(frame.size == 14 && frame[1] == 0L && frame[2] == 2L && frame[3] == 2L &&
        frame[4] == 0L && frame[5] == 0L && frame[6] == 1L && frame[7] == 51L &&
        frame[9] == 1L && frame[11] == 9L && frame[12] == 44L && frame[13] == 1L,
        "contained frame copies physical pair but disables unlock and eligibility")

    val count = InputNative.frames.size
    expect(Probe.consume(context, wm, captured, 0), "untrusted contained input still stays contained")
    expect(InputNative.frames.size == count, "untrusted input cannot drain or create native state")

    Probe.reset(); Probe.install(); Probe.block(2); InputNative.result = 9
    expect(Probe.consume(context, wm, KeyEvent(2), FLAG_TRUSTED),
        "contained input remains consumed on incompatible positive native result")
    expect(Probe.isAvailable() == false,
        "unexpected command result disables bridge without dispatching a callback")

    Probe.reset(); Probe.install(); Probe.setAvailable(false)
    expect(Probe.consume(context, wm, KeyEvent(2), FLAG_TRUSTED),
        "failed bridge consumes only its exact retained owner")
    expect(InputNative.frames.isEmpty(), "failed bridge is never re-entered for drainage")

    fun invalidWithoutShortcutOwner(label: String, mutate: () -> Unit) {
        Probe.reset(); Probe.install(withOwner = false); mutate()
        expect(Probe.consume(context, wm, KeyEvent(2), FLAG_TRUSTED),
            "$label UI invalidation is synchronously contained without a shortcut owner")
    }
    invalidWithoutShortcutOwner("dead owner") {
        WonadUiBridge.current[2]!!.claim.owner.isBinderAlive = false
    }
    invalidWithoutShortcutOwner("expired lease") { SystemClock.now = 200 }
    invalidWithoutShortcutOwner("wrong active user") { Probe.activeUserId = 10 }
    invalidWithoutShortcutOwner("locked device") { Probe.unlockedState = false }
    invalidWithoutShortcutOwner("ineligible display") { Probe.eligibleState = false }
    invalidWithoutShortcutOwner("revoked consent") { Settings.Secure.enabled = 0 }
    invalidWithoutShortcutOwner("state-read failure") {
        Settings.Secure.failure = IllegalStateException("read")
    }

    Probe.reset(); Probe.install(expires = 150, uiExpires = 250); SystemClock.now = 150
    expect(Probe.consume(context, wm, KeyEvent(2), FLAG_TRUSTED),
        "expired shortcut owner is contained even while exact UI claim remains live")

    Probe.reset(); Probe.install(); Probe.replaceUiClaim(2)
    expect(!Probe.consume(context, wm, KeyEvent(2), FLAG_TRUSTED),
        "stale shortcut owner cannot capture a replacement UI claim")

    Probe.reset(); Probe.install(); Probe.activeUserHookAt = 3
    expect(Probe.interceptForTest(context, wm, KeyEvent(2), FLAG_TRUSTED),
        "retirement before guarded JNI is caught outside the input lock")
    expect(InputNative.frames.isEmpty() && Probe.callbackCount() == 0,
        "stale-owner guard neither re-observes input nor delivers a command")

    Probe.reset(); Probe.install()
    InputNative.beforeReturn = { Probe.blockAndRetire(2) }
    expect(Probe.interceptForTest(context, wm, KeyEvent(2), FLAG_TRUSTED),
        "retirement after native pass result is caught by final predicate")
    expect(InputNative.frames.size == 1 && Probe.callbackCount() == 0,
        "native pass race has one observation and no callback")

    Probe.reset(); Probe.install()
    InputNative.beforeReturn = { Probe.blockAndRetire(2) }
    InputNative.failure = IllegalStateException("JNI")
    expect(Probe.interceptForTest(context, wm, KeyEvent(2), FLAG_TRUSTED),
        "retirement before JNI exception catch remains contained")
    expect(InputNative.frames.size == 1 && Probe.callbackCount() == 0,
        "JNI failure race has one observation and no callback")

    Probe.reset()
    expect(!Probe.interceptForTest(context, wm, KeyEvent(0), FLAG_TRUSTED),
        "phone input remains outside claimed-monitor containment")
    expect(InputNative.frames.size == 1 && Probe.callbackCount() == 0,
        "phone pass creates no command or callback")

    Probe.reset()
    expect(!Probe.interceptForTest(context, wm, KeyEvent(8), FLAG_TRUSTED),
        "unclaimed external input remains outside containment")
    expect(InputNative.frames.size == 1 && Probe.callbackCount() == 0,
        "unclaimed external pass creates no command or callback")

    println("wonad_input_containment_checks=$checks")
}
'''


class NativeInputClaimBindingCompiledTests(unittest.TestCase):
    def _compile_run(self, source: str, expected: str):
        if not KOTLINC.is_file() or not (JDK / "bin/java").is_file():
            self.fail("Pinned Kotlin/JDK toolchain is required")
        with tempfile.TemporaryDirectory(prefix="wonad-claim-binding-") as directory:
            root = Path(directory)
            fixture = root / "Fixture.kt"
            fixture.write_text(source)
            archive = root / "fixture.jar"
            compiled = subprocess.run(
                [str(KOTLINC), str(fixture), "-include-runtime", "-d", str(archive)],
                env={**os.environ, "JAVA_HOME": str(JDK)}, capture_output=True, text=True,
                timeout=90)
            self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
            executed = subprocess.run([str(JDK / "bin/java"), "-jar", str(archive)],
                capture_output=True, text=True, timeout=20)
            self.assertEqual(0, executed.returncode, executed.stdout + executed.stderr)
            self.assertIn(expected, executed.stdout)

    def test_actual_ui_token_publication_and_retirement_are_exact(self):
        source = UI.read_text()
        start = source.index("internal fun currentShortcutClaimState(")
        state_lookup = source[start:source.index("\n\n    internal fun shortcutClaim(", start)]
        start = source.index("internal fun shortcutClaim(")
        lookup = source[start:source.index("\n\n    internal fun shortcutClaimCurrent(", start)]
        start = source.index("internal fun shortcutClaimCurrent(")
        current = source[start:source.index("\n\n    /** Publish removal", start)]
        retire = method(source, "private fun retireShortcutClaim(")
        publish = method(source, "private fun publishShortcutClaim(")
        self._compile_run(UI_PREFIX + state_lookup + "\n" + lookup + "\n" + current + "\n" +
            retire + "\n" + publish + UI_SUFFIX, "wonad_ui_claim_binding_checks=14")

    def test_actual_containment_helper_fails_closed_without_command_authority(self):
        source = INPUT.read_text()
        start = source.index("private fun exactOwner(")
        exact = source[start:source.index("\n\n    private fun claimActive(", start)]
        start = source.index("private fun claimActive(")
        claim_active = source[start:source.index("\n\n    private fun ownerActive(", start)]
        start = source.index("private fun ownerActive(")
        owner_active = source[start:source.index("\n\n    /** Once a live lease", start)]
        start = source.index("private fun failedBridgeConsumes(")
        failed = source[start:source.index("\n\n    /** WMS publishes claim removal", start)]
        start = source.index("private fun modifiers(")
        modifiers = source[start:source.index("\n\n    /** Observe only", start)]
        drain = method(source, "private fun drainContained(")
        claimed = method(source, "private fun claimedInputBlocked(")
        consume = method(source, "@JvmStatic fun consumeClaimedInput(")
        intercept = method(source, "@JvmStatic fun intercept(")
        self._compile_run(INPUT_PREFIX + exact + "\n" + claim_active + "\n" + owner_active +
            "\n" + failed + "\n" + modifiers + "\n" + drain + "\n" + claimed + "\n" +
            consume + "\n" + intercept + INPUT_SUFFIX, "wonad_input_containment_checks=32")

    def test_registration_and_invalidation_order_is_source_bound(self):
        input_source = INPUT.read_text()
        ui_source = UI.read_text()
        lease = method(input_source, "@JvmStatic fun setLease(")
        self.assertIn("WonadUiBridge.shortcutClaim(display, user, generation) ?: return false", lease)
        self.assertGreaterEqual(lease.count("WonadUiBridge.shortcutClaimCurrent(exactClaim)"), 2)
        self.assertIn("it.claim !== exactClaim", lease)
        owner = input_source[input_source.index("private class Owner("):
            input_source.index("\n    private fun nativeReady(")]
        self.assertIn("val claim: WonadUiBridge.ShortcutClaim", owner)

        ui_lease = method(ui_source, "private fun setLease(")
        renewed = ui_lease.index("if (!InputNative.uiRenew(")
        retained = ui_lease.index("return@withWonadGlobalLock false", renewed)
        mutated = ui_lease.index("claim.user = user", renewed)
        published = ui_lease.index("publishShortcutClaim(claim)", mutated)
        self.assertLess(renewed, retained)
        self.assertLess(retained, mutated)
        self.assertLess(mutated, published)
        self.assertIn("claim.expires = expires", ui_lease[mutated:published])
        self.assertNotIn("shortcutClaimStates =", ui_lease[renewed:retained])

        claimed = method(input_source, "private fun claimedInputBlocked(")
        self.assertLess(claimed.index("WonadUiBridge.consumeInput(display)"),
            claimed.index("val state = WonadUiBridge.currentShortcutClaimState(display)"))
        self.assertGreaterEqual(claimed.count("WonadUiBridge.consumeInput(display)"), 2)
        self.assertNotIn("InputNative", claimed)
        self.assertNotIn("drainContained", claimed)
        self.assertNotIn("notifyShortcutKeyPressed", claimed)
        consume = method(input_source, "@JvmStatic fun consumeClaimedInput(")
        self.assertIn("if (!claimedInputBlocked(context, wm, display)) return false", consume)
        self.assertEqual(1, consume.count("drainContained("))

        intercept = method(input_source, "@JvmStatic fun intercept(")
        self.assertIn("val code: Long? = synchronized(lock)", intercept)
        self.assertIn("if (code == null) return claimedInputBlocked(context, wm, target)", intercept)
        self.assertIn("code != 0L || claimedInputBlocked(context, wm, target)", intercept)
        self.assertEqual(5, intercept.count("claimedInputBlocked(context, wm, target)"))
        self.assertEqual(1, intercept.count("InputNative.event("))

        contain = method(ui_source, "private fun containAndRelease(")
        self.assertLess(contain.index("publishInputContainment()"),
            contain.index("retireShortcutClaim(claim)"))
        self.assertIn("failures.attempt { retireShortcutClaim(claim) }", contain)
        self.assertLess(contain.index("retireShortcutClaim(claim)"),
            contain.index("WonadNativeBridge.onParked(claim.dc)"))
        removed = method(ui_source, "@JvmStatic fun onRemoved(")
        self.assertLess(removed.index("claims.remove(dc.displayId)"),
            removed.index("retireShortcutClaim(claim)"))
        self.assertLess(removed.index("retireShortcutClaim(claim)"),
            removed.index("WonadNativeBridge.onRemoved(dc)"))
        self.assertIn("failures.attempt { retireShortcutClaim(claim) }", removed)

    def test_rust_drain_contract_is_bound_to_existing_regressions(self):
        rust = (ANDROID / "input-jni/src/lib.rs").read_text()
        core = (ANDROID / "broker-rust/src/shortcuts.rs").read_text()
        for name in ("rollback_revokes_every_monitor_but_still_drains_captured_key_up",
                     "reused_slot_retains_old_captured_release_without_authorizing_old_display",
                     "unrelated_untrusted_keys_never_drain_captured_pairs_or_invoke_commands"):
            self.assertIn("fn " + name + "()", rust)
        self.assertIn("eligible_display: false", rust)
        self.assertIn("if !env.trusted_event", core)
        self.assertIn("if key.action == 1 || key.cancelled", core)
        self.assertLess(core.index("if let Some(index) = self.pressed.iter().position"),
            core.index("if key.action != 0"))


if __name__ == "__main__":
    unittest.main()
