#!/usr/bin/env python3
"""Bounded host replay for the external containment candidate.

This compiles only small Kotlin/JVM and extracted-Java fixtures.  It does not
invoke Gradle, Soong, Docker, an emulator, or any Android build.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
STAGE = Path("/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7")
KOTLIN = STAGE / "external/kotlinc/bin/kotlinc"
KOTLIN_ROOT = KOTLIN.parent.parent
JAVA_HOME = STAGE / "prebuilts/jdk/jdk21/linux-x86"
JAVA = JAVA_HOME / "bin/java"
JAVAC = JAVA_HOME / "bin/javac"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run(argv: list[str], *, expected: str | None = None) -> str:
    env = os.environ.copy()
    env.update({
        "JAVA_HOME": str(JAVA_HOME),
        "PATH": f"{JAVA_HOME / 'bin'}:{env.get('PATH', '')}",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    result = subprocess.run(argv, env=env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=60, check=False)
    if result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {argv!r}\n{result.stdout}")
    if expected is not None:
        require(expected in result.stdout,
            f"missing result {expected!r}:\n{result.stdout}")
    return result.stdout


def index(text: str, needle: str) -> int:
    require(text.count(needle) == 1,
        f"expected one generated source anchor {needle!r}, got {text.count(needle)}")
    return text.index(needle)


def source_guards(generated: Path) -> None:
    ims = (generated / "InputManagerService.java").read_text()
    kgc = (generated / "KeyGestureController.java").read_text()
    pwm = (generated / "PhoneWindowManager.java").read_text()
    bridge = (generated / "WonadInputBridge.kt").read_text()
    ui = (generated / "WonadUiBridge.kt").read_text()
    helper = (generated / "WonadPolicyKeyContainment.kt").read_text()
    adapter = (generated / "WonadPolicyKeyAdapter.kt").read_text()

    # Actual branch order: passive bookkeeping; multi-key safety; paste policy;
    # fixed Wonad alphabet; generic guard; every stock/capture bypass.
    intercept_start = index(kgc,
        "public long interceptKeyBeforeDispatching(IBinder focus, KeyEvent event, int policyFlags)")
    passive = kgc.index("passiveBeforeSafety(", intercept_start)
    safety = kgc.index("interceptMultiKeyCombination(event)", passive)
    paste = kgc.index("SecurePasteKeyEventHandler.isPasteKeyEvent(event)", safety)
    fixed = kgc.index("final boolean wonadShortcut", paste)
    generic = kgc.index("final org.wonad.server.input.WonadPolicyKeyAdapter.Decision wonadDecision", fixed)
    bypass = kgc.index("shouldInterceptShortcuts(focus)", generic)
    before_stage = kgc.index("INTERCEPT_STAGE_SHORTCUTS_BEFORE_KEY_CAPTURE", bypass)
    capture = kgc.index("canFocusedWindowCaptureKeys(focus)", before_stage)
    after_stage = kgc.index("INTERCEPT_STAGE_SHORTCUTS_AFTER_KEY_CAPTURE", capture)
    require(passive < safety < paste < fixed < generic < bypass < before_stage < capture < after_stage,
        "generated dispatch order changed")

    for required in (
        "KEYCODE_RECENT_APPS", "KEYCODE_APP_SWITCH", "KEYCODE_BRIGHTNESS_UP",
        "KEYCODE_KEYBOARD_BACKLIGHT_DOWN", "KEYCODE_ALL_APPS", "KEYCODE_SCREENSHOT",
        "KEYCODE_LOCK", "KEYCODE_FULLSCREEN", "KEYCODE_ESCAPE",
        "KEYCODE_DO_NOT_DISTURB", "KEYCODE_ACCESSIBILITY",
    ):
        require(required in kgc[generic:], f"stock action absent after generic guard: {required}")

    require("SparseArray<Map<Integer, Long>>" in kgc and
        "oldDownTime.longValue() != downTime" in kgc and
        "retainedDownTime.longValue() == downTime" in kgc,
        "stock stage is not exact-downTime aware")
    require("registerInputDeviceListener(mWonadInputDeviceListener, mHandler)" in kgc and
        "stage.removeDevice(deviceId)" in kgc and "removeDevice(deviceId)" in kgc and
        "if (decision.saturated) reconcileWonadPolicyDevices();" in kgc,
        "trusted device retirement/reconciliation is not wired")
    require("mInputDataStore, mNative);" in ims and
        "@Nullable private final NativeInputManagerService mWonadNativeInput" in kgc and
        "keyCode <= KeyEvent.getMaxKeyCode()" in kgc and
        "nativeInput.getKeyCodeState(" in kgc and
        "InputDevice.SOURCE_ANY" in kgc and
        "InputManagerService.KEY_STATE_DOWN" in kgc and
        "InputManagerService.KEY_STATE_VIRTUAL" in kgc and
        "input.getInputDeviceIds(), allKeysReleased" in kgc,
        "complete native key/device census is not injected and used")
    require("dispatchEscape(" in kgc and "completeEscape(msg.obj)" not in kgc and
        "removeMessages(MSG_EXIT_FOCUSED_APP, owner.completion)" in kgc,
        "Escape completion is not atomically exact-message owned")
    require("installMeta(" in kgc and "installCaps(" in kgc and
        "installAltTab(" in kgc and "installRecent(" in kgc and
        "installEscape(" in kgc and "completeCaps(" in kgc and
        "completeAltTab(" in kgc and "applyWonadPolicyCleanup(install.cleanup)" in kgc,
        "transactional stateful owners are not wired")
    for stale in ("markMeta(", "markCaps(", "markAltTab(", "markRecent(", "markEscape("):
        require(stale not in kgc,
            f"generated Java retains non-transactional owner publication: {stale}")
    require("if (mWonadPendingAltTabOwner.get() == null)" not in kgc and
        "install -> {\n                                        applyWonadPolicyCleanup(install.cleanup);" in kgc and
        kgc.count("applyWonadPolicyCleanup(install.cleanup);") == 6 and
        kgc.count("this::rollbackWonadOwnerInstall") == 5 and
        kgc.count("this::rollbackWonadEscapeInstall") == 1 and
        "applyWonadPolicyCleanup(install.rollback);" in kgc and
        "mWonadPendingMetaOwner.set(install.owner);" in kgc and
        "mWonadPendingCapsOwner.set(install.owner);" in kgc and
        "mWonadPendingAltTabOwner.set(install.owner);" in kgc,
        "owner mirror/action publication is outside the lifecycle transaction")
    require("AtomicReference<Object> mWonadPendingMetaOwner" in kgc and
        "AtomicReference<Object> mWonadPendingCapsOwner" in kgc and
        "AtomicReference<Object> mWonadPendingAltTabOwner" in kgc and
        "compareAndSet(expected, null)" in kgc and
        "if (decision.clearMeta != null) mPendingMetaAction = false" not in kgc and
        "if (decision.clearCaps != null) mPendingCapsLockToggle = false" not in kgc,
        "delayed cleanup is not exact-owner conditional")
    require("mWonadPreloadedRecentAppsOwner" in pwm and
        "owner == mWonadPreloadedRecentAppsOwner" in pwm and
        "owner != null && owner == mWonadPreloadedRecentAppsOwner" in pwm,
        "PWM preload lacks exact owner checks")
    require("event.isCancelled()" in pwm and "complete && keyguardOn" in pwm,
        "PWM canceled/keyguard exact unwind missing")

    require("it.claim === retained" in bridge and
        "drainContained(wm, event, policyFlags, owner)" in bridge,
        "bridge does not retain exact old claim metadata")
    require("WonadPolicyKeyAdapter.onClaimRetiring(expected)" in bridge and
        "WonadPolicyKeyAdapter.claimBlocked(state.claim)" in bridge and
        "WonadPolicyKeyAdapter.onClaimRetired(expected)" in bridge,
        "bridge does not bind synchronous exact-claim lifecycle state")
    retire_method = index(ui, "private fun retireShortcutClaim(claim: Claim)")
    retiring = ui.index("WonadInputBridge.onUiClaimRetiring(previous)", retire_method)
    removal = ui.index("shortcutClaimStates = shortcutClaimStates - claim.dc.displayId",
        retiring)
    retired = ui.index("WonadInputBridge.onUiClaimRetired(previous)", removal)
    require(retiring < removal < retired,
        "UiBridge unpublishes claim before exact policy retirement")
    containment_method = index(ui, "private fun publishInputContainment()")
    barrier_block = ui.index(
        "WonadInputBridge.onUiClaimContainmentChanged(it, true)", containment_method)
    barrier_publish = ui.index("blankDisplays = nextBlank", barrier_block)
    barrier_open = ui.index(
        "WonadInputBridge.onUiClaimContainmentChanged(it, false)", barrier_publish)
    require(barrier_block < barrier_publish < barrier_open,
        "claim policy barrier does not bracket volatile display barrier")
    require("value.displayId" in adapter and "decision.matches(value)" in adapter,
        "adapter does not validate original physical event")
    original_kgc = (STAGE /
        "frameworks/base/services/core/java/com/android/server/input/KeyGestureController.java"
        ).read_text()
    for forbidden in ("setDisplayId", "KeyEvent.obtain", "changeDisplayId"):
        require(forbidden not in adapter + bridge and
            kgc.count(forbidden) == original_kgc.count(forbidden),
            f"candidate added KeyEvent relabel/clone path via {forbidden}")
    require("claim === other.claim" in helper and "owner === other.owner" in helper,
        "claim lineage degraded to scalar/value equality")
    require(helper.count(
            "preserveOriginalFailure(error) { rollback(registration) }") == 5 and
        "rollbackDecision(owner, replaced)" in helper and
        "original.addSuppressed(rollbackFailure)" in helper,
        "callback failure does not remove/cancel the exact new owner while preserving cause")
    require(adapter.count("rollback: OwnerInstallAction") == 4 and
        adapter.count("rollback = { rollback.run(OwnerInstall(it)) }") == 4 and
        "rollback: EscapeInstallAction" in adapter and
        "rollback = { rollback.run(EscapeInstall(it)) }" in adapter and
        "@JvmField val rollback: Decision" in adapter,
        "private adapter does not require compensating rollback on every install callback")
    require("maximumPairs" in helper and "saturated = true" in helper and
        "removeDevice(device: Int)" in helper,
        "bounded/device-retirement state absent")
    require("tracked(role) || currentOrigin != null" in helper and
        "passiveBeforeSafety(\n        event: Event" in helper and
        "ThreadLocal<ArrayDeque<RecentDispatch>>()" in helper and
        "active.values.toList().forEach { retire(it, effects, retainDrain = false) }" in helper and
        "mutationEpoch != expectedEpoch" in helper and
        "internal fun updateClaimStatus(" in helper and
        "private fun pairUsable(pair: PairToken, resolver: OriginResolver)" in helper and
        "private fun mayReplace(" in helper and
        "if (incomingOrigin == null) return true" in helper and
        "if (existing.any { it.origin == null }) return false" in helper,
        "ordinary claimed parity/passive lineage/thread confinement missing")
    epoch = index(kgc, "WonadPolicyKeyAdapter.mutationEpoch()")
    scan = kgc.index("nativeInput.getKeyCodeState(", epoch)
    reconcile = kgc.index("allKeysReleased, expectedEpoch", scan)
    require(epoch < scan < reconcile,
        "device census lacks a mutation-epoch bracket")
    listener = index(kgc, "WonadPolicyKeyAdapter.registerCleanupListener")
    device_listener = kgc.index("registerInputDeviceListener", listener)
    require(listener < device_listener,
        "claim cleanup listener is not installed before device/key callbacks")


def main() -> int:
    require(KOTLIN.is_file() and JAVA.is_file() and JAVAC.is_file(),
        "pinned small compiler toolchain is unavailable")
    with tempfile.TemporaryDirectory(prefix="wonad-containment-host-") as raw:
        tmp = Path(raw)
        generated = tmp / "generated"
        run([sys.executable, "-B", str(HERE / "apply_candidate.py"),
            "--output", str(generated)])
        for name in ("WonadPolicyKeyContainment.kt", "WonadPolicyKeyAdapter.kt"):
            require((generated / name).read_bytes() == (HERE / "candidate" / name).read_bytes(),
                f"generator did not copy exact candidate {name}")
        source_guards(generated)

        state_jar = tmp / "state.jar"
        run([str(KOTLIN), "-J-Xmx256m",
            str(generated / "WonadPolicyKeyContainment.kt"),
            str(HERE / "tests/ContainmentStateTest.kt"),
            "-include-runtime", "-d", str(state_jar)])
        run([str(JAVA), "-Xmx128m", "-jar", str(state_jar)],
            expected="RESULT 36 cases passed")

        compose = tmp / "compose"
        compose.mkdir()
        run([str(KOTLIN), "-J-Xmx256m",
            str(generated / "WonadPolicyKeyContainment.kt"),
            str(HERE / "tests/PolicyFixtureFacade.kt"), "-d", str(compose)])
        run([str(JAVAC), "-J-Xmx128m",
            "-cp", f"{compose}:{KOTLIN_ROOT / 'lib/kotlin-stdlib.jar'}",
            "-d", str(compose), str(HERE / "tests/PolicyCompositionTest.java"),
            str(HERE / "tests/StatefulOwnerCompositionTest.java"),
            str(HERE / "tests/AsyncCleanupReplacementTest.java"),
            str(HERE / "tests/InstallCallbackFailureTest.java")])
        classpath = f"{compose}:{KOTLIN_ROOT / 'lib/kotlin-stdlib.jar'}"
        run([str(JAVA), "-Xmx128m", "-cp", classpath,
            "org.wonad.server.input.PolicyCompositionTest"],
            expected="RESULT 10 Java composition cases passed")
        run([str(JAVA), "-Xmx128m", "-cp", classpath,
            "org.wonad.server.input.StatefulOwnerCompositionTest"],
            expected="RESULT 5 stateful owner cases passed")
        run([str(JAVA), "-Xmx128m", "-cp", classpath,
            "org.wonad.server.input.AsyncCleanupReplacementTest"],
            expected="RESULT 5 async replacement cases passed")
        run([str(JAVA), "-Xmx128m", "-cp", classpath,
            "org.wonad.server.input.InstallCallbackFailureTest"],
            expected="RESULT 5 callback failure cases passed")

        ledger = tmp / "ledger"
        ledger.mkdir()
        run([str(JAVAC), "-J-Xmx128m", "-d", str(ledger),
            str(HERE / "tests/ExactStageLedgerTest.java")])
        run([str(JAVA), "-Xmx128m", "-cp", str(ledger),
            "org.wonad.server.input.ExactStageLedgerTest"],
            expected="RESULT 4 exact stage-ledger cases passed")

        adapter_jar = tmp / "adapter.jar"
        stubs = sorted((HERE / "tests/stubs").rglob("*.kt"))
        run([str(KOTLIN), "-J-Xmx256m",
            str(generated / "WonadPolicyKeyContainment.kt"),
            str(generated / "WonadPolicyKeyAdapter.kt"),
            *map(str, stubs), str(HERE / "tests/AdapterIdentityTest.kt"),
            "-include-runtime", "-d", str(adapter_jar)])
        run([str(JAVA), "-Xmx128m", "-jar", str(adapter_jar)],
            expected="RESULT 11 adapter identity cases passed")

    print("RESULT 76 bounded candidate checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
