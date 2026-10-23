"""Compile the actual native app-input population boundary.

This is a source regression for one deterministic WMS population path.  It
does not model an event which InputDispatcher had already routed, nor does it
qualify SurfaceFlinger/InputDispatcher transaction timing on a guest.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_native_ui_surface_migration_compiled import JDK, KOTLINC, method


ANDROID = Path(__file__).resolve().parents[1]
BRIDGE = ANDROID / "input-integration/src/com/android/server/wm/WonadNativeBridge.kt"


HARNESS = r'''
package com.android.server.wm

object InputConfig {
    const val NOT_TOUCHABLE = 1
    const val SPY = 2
    const val DROP_INPUT = 4
    const val STOCK_FLAG = 8
}

data class ComponentName(val name: String)

class Rect(var left: Int, var top: Int, var right: Int, var bottom: Int)

class Region() {
    var left = 0
    var top = 0
    var right = 0
    var bottom = 0

    constructor(l: Int, t: Int, r: Int, b: Int) : this() {
        set(l, t, r, b)
    }

    val isEmpty: Boolean get() = left >= right || top >= bottom

    fun set(l: Int, t: Int, r: Int, b: Int) {
        left = l; top = t; right = r; bottom = b
    }

    fun set(other: Region) = set(other.left, other.top, other.right, other.bottom)

    fun scale(scale: Float) {
        left = (left * scale).toInt(); top = (top * scale).toInt()
        right = (right * scale).toInt(); bottom = (bottom * scale).toInt()
    }

    fun op(other: Region, operation: Op): Boolean {
        check(operation == Op.INTERSECT)
        left = maxOf(left, other.left); top = maxOf(top, other.top)
        right = minOf(right, other.right); bottom = minOf(bottom, other.bottom)
        if (isEmpty) set(0, 0, 0, 0)
        return !isEmpty
    }

    enum class Op { INTERSECT }
}

class SurfaceControl(val name: String)
class DisplayInfo(var logicalWidth: Int = 400, var logicalHeight: Int = 200)
class DisplayContent(val displayId: Int, var claimed: Boolean) {
    val displayInfo = DisplayInfo()
}

class RootTask(val displayContent: DisplayContent) {
    var isAttached = true
    val surfaceControl = SurfaceControl("root")
}

class Task(val displayContent: DisplayContent, val user: Int) {
    var validApp = true
    val rootTask = RootTask(displayContent)
}

class ActivityRecord(val mActivityComponent: ComponentName)
class LayoutParams

class WindowState(val displayContent: DisplayContent?) {
    var mActivityRecord: ActivityRecord? = null
    var task: Task? = null
    var frame = Rect(0, 0, 100, 100)
    var mInvGlobalScale = 1f
    val displayInfo: DisplayInfo get() = checkNotNull(displayContent).displayInfo
    val mAttrs = LayoutParams()
    val stockRegion = Region(0, 0, 100, 100)

    fun getSurfaceTouchableRegion(out: Region, attrs: LayoutParams) {
        check(attrs === mAttrs)
        out.set(stockRegion)
    }
}

class InputWindowHandleWrapper {
    var focusableState = true
    var replaceWithCrop = true
    var crop: SurfaceControl? = null
    var region = Region(0, 0, 100, 100)
    var inputConfig = InputConfig.STOCK_FLAG
    var trustedState = true

    fun setFocusable(value: Boolean) { focusableState = value }
    fun setReplaceTouchableRegionWithCrop(value: Boolean) {
        replaceWithCrop = value
    }
    fun setTouchableRegionCrop(value: SurfaceControl?) { crop = value }
    fun setTouchableRegion(value: Region) { region = Region(value.left, value.top, value.right, value.bottom) }
    fun clearTouchableRegion() { region = Region() }
    fun setInputConfigMasked(value: Int, mask: Int) {
        inputConfig = (inputConfig and mask.inv()) or (value and mask)
    }
    fun setTrustedOverlay(value: Boolean) { trustedState = value }
}

class WindowManagerService

data class NativeLease(val dc: DisplayContent, val user: Int)

object WonadUiBridge {
    var lease: NativeLease? = null
    fun nativeMode(dc: DisplayContent) = dc.claimed
    fun nativeLease(wm: WindowManagerService, dc: DisplayContent): NativeLease? {
        check(wm === Probe.wm)
        return lease?.takeIf { it.dc === dc }
    }
}

object Probe {
    val wm = WindowManagerService()
    private val component = ComponentName("org.wonad.desktop.ExternalShellActivity")
    private data class Plane(val lease: NativeLease, val window: WindowState,
        val observer: WindowState, val regions: Region = Region(), var meta: Boolean = false)
    private val planes = mutableMapOf<Int, Plane>()

    private fun launcherWindow(plane: Plane): WindowState? = null
    private fun interactionBlockedLocked(wm: WindowManagerService, user: Int): Boolean = false
    private fun protectedPhoneFocus(wm: WindowManagerService): Boolean = false
    private fun app(task: Task, user: Int): Boolean =
        task.validApp && task.user == user && task.displayContent.displayId > 0

__METHODS__

    fun populate(window: WindowState, handle: InputWindowHandleWrapper) =
        configureInput(wm, window, handle)
}

var checks = 0
fun expect(value: Boolean, message: String) {
    check(value) { message }
    checks++
}

fun ordinary(display: DisplayContent): WindowState = WindowState(display).also {
    it.mActivityRecord = ActivityRecord(ComponentName("example.App"))
    it.task = Task(display, 0)
}

fun unchanged(handle: InputWindowHandleWrapper): Boolean =
    handle.focusableState && handle.replaceWithCrop && handle.crop == null &&
        handle.region.left == 0 && handle.region.top == 0 && handle.region.right == 100 &&
        handle.region.bottom == 100 && handle.inputConfig == InputConfig.STOCK_FLAG &&
        handle.trustedState

fun main() {
    val phone = DisplayContent(0, false)
    val phoneHandle = InputWindowHandleWrapper()
    Probe.populate(ordinary(phone), phoneHandle)
    expect(unchanged(phoneHandle), "phone input population must remain stock")

    val unclaimed = DisplayContent(4, false)
    val unclaimedHandle = InputWindowHandleWrapper()
    Probe.populate(ordinary(unclaimed), unclaimedHandle)
    expect(unchanged(unclaimedHandle), "unclaimed external input population must remain stock")

    val live = DisplayContent(2, true)
    WonadUiBridge.lease = NativeLease(live, 0)
    val liveWindow = ordinary(live).also {
        it.frame = Rect(-20, -10, 180, 130)
        it.stockRegion.set(0, 0, 500, 500)
    }
    val liveHandle = InputWindowHandleWrapper()
    Probe.populate(liveWindow, liveHandle)
    expect(liveHandle.inputConfig == InputConfig.STOCK_FLAG && liveHandle.focusableState &&
        liveHandle.trustedState, "live ordinary app clipping must preserve stock flags")
    expect(!liveHandle.replaceWithCrop &&
        liveHandle.crop === liveWindow.task!!.rootTask.surfaceControl,
        "live ordinary app must use its exact root crop")
    expect(liveHandle.region.left == 20 && liveHandle.region.top == 10 &&
        liveHandle.region.right == 420 && liveHandle.region.bottom == 210,
        "live ordinary app region must be clipped to the display viewport")

    // Expiry, owner death, ineligibility and not-ready all make nativeLease()
    // null while nativeMode() deliberately remains sticky until physical removal.
    // This is a newly populated handle, not an already-routed input event.
    WonadUiBridge.lease = null
    val unavailableHandle = InputWindowHandleWrapper()
    Probe.populate(ordinary(live), unavailableHandle)
    expect(unavailableHandle.inputConfig and InputConfig.DROP_INPUT != 0 &&
        unavailableHandle.inputConfig and InputConfig.NOT_TOUCHABLE != 0 &&
        !unavailableHandle.focusableState && unavailableHandle.region.isEmpty &&
        !unavailableHandle.trustedState,
        "sticky native display without a valid lease must drop newly populated app input")

    println("wonad_native_app_input_lease_loss_checks=$checks")
}
'''


class NativeAppInputLeaseLossCompiledTests(unittest.TestCase):
    def test_actual_population_drops_claimed_app_input_without_live_lease(self):
        if not KOTLINC.exists() or not JDK.exists():
            raise unittest.SkipTest("Pinned Kotlin/JDK toolchain unavailable")
        source = BRIDGE.read_text()
        methods = "\n\n".join(
            method(source, prefix)
            for prefix in (
                "@JvmStatic fun configureInput(",
                "private fun clipNativeAppInput(",
                "private fun dropInput(",
            )
        )
        harness = HARNESS.replace("__METHODS__", methods)
        with tempfile.TemporaryDirectory(prefix="wonad-app-input-lease-loss-") as directory:
            root = Path(directory)
            source_file = root / "Fixture.kt"
            jar = root / "fixture.jar"
            source_file.write_text(harness)
            environment = dict(os.environ)
            environment["JAVA_HOME"] = str(JDK)
            compiled = subprocess.run(
                [str(KOTLINC), str(source_file), "-include-runtime", "-d", str(jar)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=environment,
                timeout=120,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout)
            executed = subprocess.run(
                [str(JDK / "bin/java"), "-jar", str(jar)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            self.assertEqual(executed.returncode, 0, executed.stdout)
            self.assertIn("wonad_native_app_input_lease_loss_checks=6", executed.stdout)


if __name__ == "__main__":
    unittest.main()
