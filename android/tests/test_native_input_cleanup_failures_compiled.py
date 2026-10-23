"""Compile the real shortcut/focus cleanup boundaries with injected failures."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_native_ui_surface_migration_compiled import JDK, KOTLINC, method

ANDROID = Path(__file__).resolve().parents[1]
CLEANUP = ANDROID / 'input-integration/src/com/android/server/wm/WonadCleanupFailures.kt'
INPUT = ANDROID / 'input-integration/src/org/wonad/server/input/WonadInputBridge.kt'
FOCUS = ANDROID / 'input-integration/src/com/android/server/wm/WonadFocusBridge.kt'


INPUT_PREFIX = r'''
package org.wonad.server.input
import com.android.server.wm.WonadCleanupFailures
import java.util.concurrent.Semaphore

object Log { fun e(tag: String, message: String, error: Throwable) {} }
class Binder {
    var unlinkFailure: Throwable? = null
    var unlinkCalls = 0
    fun unlinkToDeath(death: Any, flags: Int): Boolean {
        unlinkCalls++
        unlinkFailure?.let { throw it }
        return true
    }
}
class Receiver(val binder: Binder) { fun asBinder() = binder }
object WonadUiBridge {
    class ShortcutClaim(val display: Int)
    val current = mutableMapOf<Int, ShortcutClaim>()
    fun shortcutClaimCurrent(expected: ShortcutClaim) = current[expected.display] === expected
}
class Owner(val generation: Long, val display: Int, val receiver: Receiver,
    val claim: WonadUiBridge.ShortcutClaim) { val death = Any() }
object InputNative {
    var releaseFailure: Throwable? = null
    var commandFailure: Throwable? = null
    var releaseCalls = 0
    var commandCalls = 0
    fun releaseDisplay(generation: Long, display: Int) {
        releaseCalls++
        releaseFailure?.let { throw it }
    }
    fun commandKey(keyCode: Int): Boolean {
        commandCalls++
        commandFailure?.let { throw it }
        return keyCode == 42
    }
    fun reset() { releaseFailure = null; commandFailure = null; releaseCalls = 0; commandCalls = 0 }
}
class FakeHandler {
    var result = true
    var failure: Throwable? = null
    var pending: (() -> Unit)? = null
    fun post(action: () -> Unit): Boolean {
        failure?.let { throw it }
        if (result) pending = action
        return result
    }
}
object BackgroundThread {
    val instance = FakeHandler()
    fun getHandler() = instance
}
object Probe {
    const val TAG = "WonadInput"
    val lock = Any()
    val queue = Semaphore(32)
    val owners = mutableMapOf<Int, Owner>()
    var available: Boolean? = true
'''


INPUT_SUFFIX = r'''
    fun clearForTest(owner: Owner) = clear(owner)
    fun retiredForTest(claim: WonadUiBridge.ShortcutClaim) = onUiClaimRetired(claim)
    fun postForTest(action: () -> Unit) = postCommand(action)
    fun failedBridgeConsumesForTest(display: Int) = failedBridgeConsumes(display)
}
var checks = 0
fun expect(value: Boolean, label: String) { check(value) { label }; checks++ }
fun owner(display: Int = 2): Owner {
    val claim = WonadUiBridge.ShortcutClaim(display)
    WonadUiBridge.current[display] = claim
    return Owner(7, display, Receiver(Binder()), claim)
}
fun main() {
    for ((name, failure, unlink) in listOf(
        Triple("unlink exception", IllegalStateException("unlink"), true),
        Triple("unlink linkage", UnsatisfiedLinkError("unlink"), true),
        Triple("release exception", IllegalArgumentException("release"), false),
        Triple("release linkage", NoClassDefFoundError("release"), false),
    )) {
        InputNative.reset()
        val value = owner()
        Probe.owners[2] = value
        if (unlink) value.receiver.binder.unlinkFailure = failure else InputNative.releaseFailure = failure
        Probe.clearForTest(value)
        expect(2 !in Probe.owners, "$name removes authority first")
        expect(value.receiver.binder.unlinkCalls == 1, "$name attempts unlink")
        expect(InputNative.releaseCalls == 1, "$name attempts native release")
    }

    for ((name, failure, unlink) in listOf(
        Triple("unlink fatal", AssertionError("unlink fatal"), true),
        Triple("release fatal", OutOfMemoryError("release fatal"), false),
    )) {
        InputNative.reset()
        val value = owner()
        Probe.owners[2] = value
        if (unlink) value.receiver.binder.unlinkFailure = failure else InputNative.releaseFailure = failure
        try { Probe.clearForTest(value); error("$name expected") }
        catch (error: Error) { expect(error === failure, "$name identity preserved") }
        expect(value.receiver.binder.unlinkCalls == 1 && InputNative.releaseCalls == 1,
            "$name delayed until both cleanup operations")
    }

    InputNative.reset()
    val old = owner()
    val replacement = owner()
    Probe.owners[2] = replacement
    Probe.clearForTest(old)
    expect(Probe.owners[2] === replacement, "stale clear preserves replacement")
    expect(InputNative.releaseCalls == 0 && old.receiver.binder.unlinkCalls == 0,
        "stale clear touches no old resources")
    Probe.owners.remove(2)

    InputNative.reset()
    val retired = owner(4)
    Probe.owners[4] = retired
    Probe.retiredForTest(retired.claim)
    expect(4 !in Probe.owners, "exact UI retirement clears matching shortcut owner")
    expect(InputNative.releaseCalls == 1,
        "exact UI retirement releases matching Rust display state")

    InputNative.reset()
    val staleRetirement = owner(5)
    val currentReplacement = owner(5)
    Probe.owners[5] = currentReplacement
    Probe.retiredForTest(staleRetirement.claim)
    expect(Probe.owners[5] === currentReplacement,
        "stale UI retirement preserves replacement shortcut owner")
    expect(InputNative.releaseCalls == 0 && currentReplacement.receiver.binder.unlinkCalls == 0,
        "stale UI retirement touches no replacement resources")
    Probe.owners.remove(5)

    for (supported in listOf(IllegalStateException("command"), UnsatisfiedLinkError("command"))) {
        InputNative.reset(); Probe.available = true; InputNative.commandFailure = supported
        expect(!Probe.shortcutKey(42), "supported command failure falls through to stock key policy")
        expect(Probe.available == false, "supported command failure disables extension")
    }
    run {
        InputNative.reset()
        val leased = owner(6)
        Probe.owners[6] = leased
        Probe.available = true
        InputNative.commandFailure = UnsatisfiedLinkError("command")
        expect(Probe.shortcutKey(42),
            "bridge failure with a lease reaches exact-display priority interception")
        val calls = InputNative.commandCalls
        expect(Probe.shortcutKey(42),
            "disabled bridge retains priority interception while a Java owner remains")
        expect(InputNative.commandCalls == calls,
            "disabled bridge does not re-enter the failed native alphabet")
        Probe.owners.remove(6)
        expect(!Probe.shortcutKey(42),
            "disabled bridge releases priority once no Java owner remains")
    }
    InputNative.reset(); Probe.available = true
    val fatal = AssertionError("command fatal")
    InputNative.commandFailure = fatal
    try { Probe.shortcutKey(42); error("fatal command expected") }
    catch (error: Error) { expect(error === fatal, "shortcut fatal identity preserved") }

    run {
        val leased = owner(7)
        Probe.owners[7] = leased
        Probe.available = false
        expect(Probe.failedBridgeConsumesForTest(7),
            "failed native bridge consumes keys for the exact retained owner")
        expect(!Probe.failedBridgeConsumesForTest(8),
            "failed native bridge does not capture an unrelated display")
        Probe.available = true
        expect(!Probe.failedBridgeConsumesForTest(7),
            "healthy bridge does not activate the failure barrier")
        Probe.owners.remove(7)
    }

    run {
        val permits = Probe.queue.availablePermits()
        check(Probe.queue.tryAcquire())
        BackgroundThread.instance.result = false
        expect(!Probe.postForTest {}, "rejected Handler post reported")
        expect(Probe.queue.availablePermits() == permits, "rejected post returns queue slot")
    }
    for (failure in listOf(IllegalStateException("post"), UnsatisfiedLinkError("post"),
            AssertionError("fatal post"))) {
        val permits = Probe.queue.availablePermits()
        check(Probe.queue.tryAcquire())
        BackgroundThread.instance.result = true
        BackgroundThread.instance.failure = failure
        try { Probe.postForTest {}; error("throwing post expected") }
        catch (error: Throwable) { expect(error === failure, "throwing post identity preserved") }
        expect(Probe.queue.availablePermits() == permits, "throwing post returns queue slot")
        BackgroundThread.instance.failure = null
    }
    println("wonad_input_cleanup_checks=$checks")
}
'''


FOCUS_PREFIX = r'''
package com.android.server.wm

object Log { fun e(tag: String, message: String, error: Throwable) {} }
class Binder(var isBinderAlive: Boolean = true) {
    var unlinkFailure: Throwable? = null
    var unlinkCalls = 0
    fun unlinkToDeath(death: Any, flags: Int): Boolean {
        unlinkCalls++
        unlinkFailure?.let { throw it }
        return true
    }
}
class Owner(val display: Int, val binder: Binder) { val death = Any(); val timeout = Runnable {} }
class Handler {
    var failure: Throwable? = null
    var calls = 0
    fun removeCallbacks(runnable: Runnable) { calls++; failure?.let { throw it } }
}
class Supervisor {
    var failure: Throwable? = null
    var calls = 0
    fun updateTopResumedActivityIfNeeded(reason: String) { calls++; failure?.let { throw it } }
}
class Atm { val mTaskSupervisor = Supervisor() }
class WindowManagerService {
    companion object { const val UPDATE_FOCUS_NORMAL = 0 }
    val mH = Handler()
    val mAtmService = Atm()
    var focusFailure: Throwable? = null
    var focusCalls = 0
    fun updateFocusedWindowLocked(reason: Int, updateInput: Boolean) {
        focusCalls++
        focusFailure?.let { throw it }
    }
}
object Probe {
    val owners = mutableMapOf<Int, Owner>()
    val departed = mutableMapOf<Int, Owner>()
'''


FOCUS_SUFFIX = r'''
    fun clearForTest(wm: WindowManagerService, owner: Owner) = clear(wm, owner)
}
var checks = 0
fun expect(value: Boolean, label: String) { check(value) { label }; checks++ }
fun main() {
    for (site in listOf("handler", "unlink", "focus", "resume")) {
        val wm = WindowManagerService()
        val binder = Binder()
        val owner = Owner(2, binder)
        Probe.owners[2] = owner
        val failure = if (site == "unlink") UnsatisfiedLinkError(site) else IllegalStateException(site)
        when (site) {
            "handler" -> wm.mH.failure = failure
            "unlink" -> binder.unlinkFailure = failure
            "focus" -> wm.focusFailure = failure
            "resume" -> wm.mAtmService.mTaskSupervisor.failure = failure
        }
        Probe.clearForTest(wm, owner)
        expect(2 !in Probe.owners, "$site removes focus authority")
        expect(wm.mH.calls == 1 && binder.unlinkCalls == 1 && wm.focusCalls == 1 &&
            wm.mAtmService.mTaskSupervisor.calls == 1, "$site attempts all cleanup")
    }

    val wm = WindowManagerService()
    val binder = Binder()
    val owner = Owner(3, binder)
    Probe.owners[3] = owner
    val fatal = AssertionError("focus fatal")
    wm.focusFailure = fatal
    try { Probe.clearForTest(wm, owner); error("fatal expected") }
    catch (error: Error) { expect(error === fatal, "focus fatal identity preserved") }
    expect(wm.mAtmService.mTaskSupervisor.calls == 1, "fatal delayed until final cleanup")
    println("wonad_focus_cleanup_checks=$checks")
}
'''


class NativeInputCleanupFailuresCompiled(unittest.TestCase):
    def _compile_run(self, text: str, expected: str):
        if not KOTLINC.is_file() or not (JDK / 'bin/java').is_file():
            self.fail('Pinned Kotlin/JDK toolchain is required')
        with tempfile.TemporaryDirectory(prefix='wonad-input-cleanup-') as directory:
            root = Path(directory)
            fixture = root / 'Cleanup.kt'
            fixture.write_text(text)
            archive = root / 'cleanup.jar'
            compiled = subprocess.run(
                [str(KOTLINC), str(CLEANUP), str(fixture), '-include-runtime', '-d', str(archive)],
                env={**os.environ, 'JAVA_HOME': str(JDK)}, capture_output=True, text=True,
                timeout=90)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            executed = subprocess.run([str(JDK / 'bin/java'), '-jar', str(archive)],
                capture_output=True, text=True, timeout=20)
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            self.assertIn(expected, executed.stdout)

    def test_actual_shortcut_cleanup_and_stock_hook_failure_boundary(self):
        source = INPUT.read_text()
        clear = method(source, 'private fun clear(')
        start = source.index('private fun exactOwner(')
        exact = source[start:source.index('\n\n    private fun claimActive(', start)]
        retired = method(source, '@JvmStatic internal fun onUiClaimRetired(')
        shortcut = method(source, '@JvmStatic fun shortcutKey(')
        post = method(source, 'private fun postCommand(')
        start = source.index('private fun failedBridgeConsumes(')
        failed = source[start:source.index('\n\n    /** WMS publishes claim removal', start)]
        self._compile_run(INPUT_PREFIX + clear + '\n' + exact + '\n' + retired + '\n' + shortcut +
                          '\n' + post + '\n' + failed + INPUT_SUFFIX,
                          'wonad_input_cleanup_checks=42')

    def test_actual_focus_cleanup_attempts_all_and_preserves_fatal_identity(self):
        clear = method(FOCUS.read_text(), 'private fun clear(')
        self._compile_run(FOCUS_PREFIX + clear + FOCUS_SUFFIX, 'wonad_focus_cleanup_checks=10')

    def test_link_registration_cleanup_uses_same_fatal_preserving_boundary(self):
        for path in (INPUT, FOCUS):
            source = path.read_text()
            self.assertIn('catch (error: Throwable)', source)
            self.assertIn('cleanup.attempt { clear(', source)
            self.assertIn('cleanup.rethrowFatal(error)', source)
        shortcut = method(INPUT.read_text(), '@JvmStatic fun shortcutKey(')
        self.assertIn('error !is Exception && error !is LinkageError', shortcut)

    def test_cleanup_bypasses_a_failed_optional_native_bridge(self):
        source = INPUT.read_text()
        lease = method(source, '@JvmStatic fun setLease(')
        cleanup = lease.index('if (receiver == null && display > 0)')
        native = lease.index('if (!nativeReady()) return false')
        self.assertLess(cleanup, native)
        self.assertIn('owners[display]?.let { if (it.generation == generation) clear(it) }',
                      lease[cleanup:native])
        intercept = method(source, '@JvmStatic fun intercept(')
        self.assertLess(intercept.index('if (consumeClaimedInput(context, wm, event, policyFlags)) return true'),
                        intercept.index('if (available != true'))
        self.assertEqual(intercept.count('available = false; claimedInputBlocked(context, wm, target)'), 2)
        self.assertIn('if (code == null) return claimedInputBlocked(context, wm, target)', intercept)
        self.assertIn('code != 0L || claimedInputBlocked(context, wm, target)', intercept)


if __name__ == '__main__':
    unittest.main()
