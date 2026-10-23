#!/usr/bin/env python3
"""Bounded host replay for the post-target total-control candidate.

This authenticates exact inputs, materializes a fresh six-file candidate,
executes source-order/removed-surface controls, and compiles two small JVM
fixtures. It does not invoke Gradle, Soong, Docker, an emulator or a platform
build. The separately documented pre-target PWM gap remains open.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
STAGE = Path("/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7")
KOTLIN = STAGE / "external/kotlinc/bin/kotlinc"
JAVA_HOME = STAGE / "prebuilts/jdk/jdk21/linux-x86"
JAVA = JAVA_HOME / "bin/java"
BASE_KGC = STAGE / "frameworks/base/services/core/java/com/android/server/input/KeyGestureController.java"
BASE_PWM = STAGE / "frameworks/base/services/core/java/com/android/server/policy/PhoneWindowManager.java"
KEYBOARD_MAPPER = STAGE / "frameworks/native/services/inputflinger/reader/mapper/KeyboardInputMapper.cpp"
INPUT_DISPATCHER = STAGE / "frameworks/native/services/inputflinger/dispatcher/InputDispatcher.cpp"
EXPECTED_FILES = {
    "InputManagerService.java",
    "KeyGestureController.java",
    "WonadInputBridge.kt",
    "WonadPolicyKeyAdapter.kt",
    "WonadPolicyKeyContainment.kt",
    "WonadUiBridge.kt",
}

checks = 0


def require(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


def run(argv: list[str], *, expected: str | None = None) -> str:
    env = os.environ.copy()
    env.update({
        "JAVA_HOME": str(JAVA_HOME),
        "PATH": f"{JAVA_HOME / 'bin'}:{env.get('PATH', '')}",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    result = subprocess.run(
        argv, env=env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=90, check=False)
    if result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {argv!r}\n{result.stdout}")
    if expected is not None:
        require(expected in result.stdout,
            f"missing result {expected!r}:\n{result.stdout}")
    return result.stdout


def one_index(text: str, needle: str, *, start: int = 0) -> int:
    count = text.count(needle, start)
    require(count == 1, f"expected one source anchor {needle!r}, observed {count}")
    return text.index(needle, start)


def java_method(text: str, signature: str) -> str:
    start = one_index(text, signature)
    brace = text.index("{", start)
    depth = 0
    index = brace
    state = "code"
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "/" and next_char == "/":
                state = "line"
                index += 1
            elif char == "/" and next_char == "*":
                state = "block"
                index += 1
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return text[start:index + 1]
        elif state == "string":
            if char == "\\":
                index += 1
            elif char == '"':
                state = "code"
        elif state == "char":
            if char == "\\":
                index += 1
            elif char == "'":
                state = "code"
        elif state == "line":
            if char == "\n":
                state = "code"
        elif state == "block" and char == "*" and next_char == "/":
            state = "code"
            index += 1
        index += 1
    raise AssertionError(f"unterminated Java method {signature!r}")


def source_guards(generated: Path) -> None:
    names = {path.name for path in generated.iterdir() if path.is_file()}
    require(names == EXPECTED_FILES,
        f"candidate file surface changed: {sorted(names)}")

    base_kgc = BASE_KGC.read_text()
    kgc = (generated / "KeyGestureController.java").read_text()
    ims = (generated / "InputManagerService.java").read_text()
    bridge = (generated / "WonadInputBridge.kt").read_text()
    ui = (generated / "WonadUiBridge.kt").read_text()
    adapter = (generated / "WonadPolicyKeyAdapter.kt").read_text()
    helper = (generated / "WonadPolicyKeyContainment.kt").read_text()
    pwm = BASE_PWM.read_text()
    mapper = KEYBOARD_MAPPER.read_text()
    dispatcher = INPUT_DISPATCHER.read_text()

    dispatch = one_index(kgc,
        "public long interceptKeyBeforeDispatching(IBinder focus, KeyEvent event, int policyFlags)")
    bookkeeping = kgc.index("WonadPolicyKeyAdapter.allowStockBookkeeping(", dispatch)
    safety = kgc.index("interceptMultiKeyCombination(event)", bookkeeping)
    paste = kgc.index("SecurePasteKeyEventHandler.isPasteKeyEvent(event)", safety)
    fixed = kgc.index("final boolean wonadShortcut", paste)
    seam = kgc.index("// Total-control seam.", fixed)
    app_return = kgc.index("if (wonadDecision.application)", seam)
    stock_meta = kgc.index("shouldInterceptShortcuts(focus)", app_return)
    before_stage = kgc.index("INTERCEPT_STAGE_SHORTCUTS_BEFORE_KEY_CAPTURE", stock_meta)
    capture = kgc.index("canFocusedWindowCaptureKeys(focus)", before_stage)
    after_stage = kgc.index("INTERCEPT_STAGE_SHORTCUTS_AFTER_KEY_CAPTURE", capture)
    fallback = kgc.index("KEY_INTERCEPT_RESULT_NOT_CONSUMED_GO_FALLBACK", after_stage)
    require(bookkeeping < safety < paste < fixed < seam < app_return < stock_meta <
        before_stage < capture < after_stage < fallback,
        "post-target routing order changed")
    bookkeeping_method = adapter[adapter.index("fun allowStockBookkeeping("):
        adapter.index("/** Final route", adapter.index("fun allowStockBookkeeping("))]
    require("policyClaimBlocked" not in bookkeeping_method and
        "WonadUiBridge.consumeInput" in bookkeeping_method,
        "pre-safety bookkeeping performs a fallible framework read")
    require("mWindowManagerCallbacks.interceptKeyBeforeDispatching(focus, event)" in
        kgc[paste:fixed],
        "SecurePaste exception is no longer explicit before the total-control seam")

    role_method = java_method(kgc, "private static int wonadPolicyRole(int keyCode)")
    for key in (
        "KEYCODE_APP_SWITCH", "KEYCODE_RECENT_APPS", "KEYCODE_ALL_APPS",
        "KEYCODE_HOME", "KEYCODE_SCREENSHOT", "KEYCODE_SYSRQ", "KEYCODE_LOCK",
        "KEYCODE_FULLSCREEN", "KEYCODE_ASSIST", "KEYCODE_VOICE_ASSIST",
        "KEYCODE_CONTEXTUAL_SEARCH", "KEYCODE_DO_NOT_DISTURB",
        "KEYCODE_ACCESSIBILITY", "KEYCODE_NOTIFICATION", "KEYCODE_SEARCH",
        "KEYCODE_SETTINGS", "KEYCODE_LANGUAGE_SWITCH",
    ):
        require(key in role_method, f"dedicated Android UI key is not reserved: {key}")
    require("case KeyEvent.KEYCODE_META_LEFT" in role_method and
        "ROLE_META" in role_method and "case KeyEvent.KEYCODE_ALT_LEFT" in role_method and
        "ROLE_ALT" in role_method and "case KeyEvent.KEYCODE_ESCAPE" in role_method and
        "ROLE_ESCAPE" in role_method,
        "ordinary Meta/Alt/Escape roles are not explicit")

    for signature in (
        "private boolean interceptShortcutsBeforeKeyCapture(",
        "private boolean interceptShortcutsAfterKeyCapture(",
        "private boolean interceptCapturableShortcuts(",
        "private boolean interceptUnhandledShortcuts(",
    ):
        require(java_method(kgc, signature) == java_method(base_kgc, signature),
            f"stock phone method changed rather than being bypassed: {signature}")

    private_unhandled = java_method(ims,
        "private boolean interceptUnhandledKey(KeyEvent event, IBinder focus)")
    require(private_unhandled.index("bypassUnhandledStock") <
        private_unhandled.index("mKeyGestureController.interceptUnhandledKey"),
        "claimed unhandled event reaches KGC stock shortcuts")
    fallback_method = java_method(ims,
        "private boolean interceptFallback(IBinder focusedToken, KeyEvent fallbackEvent,")
    require(fallback_method.index("bypassFallbackQueueing") <
        fallback_method.index("interceptKeyBeforeQueueing"),
        "claimed fallback can re-enter PWM queue policy")
    require("DisplayAuthority" in adapter and
        "MAX_CLAIMED_DISPLAYS_PER_WINDOW" in adapter and
        "WeakHashMap<IBinder, DeliveryLedger>" in adapter and
        "bypassUnhandledStock" in adapter and "bypassFallbackQueueing" in adapter,
        "bounded focus/display suppression authority is not retained")
    require("val delivered" not in adapter and "val fallbacks" not in adapter and
        "MAX_DELIVERIES_PER_WINDOW" not in adapter,
        "normal handled/no-fallback traffic still accumulates per-event history")
    require("ThreadLocal<FallbackScope?>" in adapter and
        "fun beginFallback" in adapter and "fun endFallback" in adapter and
        "matchingFallback" in adapter,
        "known fallback derivation is not exact and synchronous")

    dispatch_unhandled = java_method(ims,
        "private KeyEvent dispatchUnhandledKey(IBinder focus, KeyEvent event, int policyFlags)")
    no_fallback = dispatch_unhandled.index("if (fallbackAction == null)")
    scope_begin = dispatch_unhandled.index("WonadPolicyKeyAdapter.beginFallback", no_fallback)
    scope_finally = dispatch_unhandled.index("WonadPolicyKeyAdapter.endFallback", scope_begin)
    require(no_fallback < scope_begin < scope_finally,
        "fallback authority is retained before KCM proves a fallback or lacks finally cleanup")

    prepare = adapter.index("val request = state.prepareObservation(observed, current)")
    observations = adapter.index("val claims = request.origins.map", prepare)
    blocked = adapter.index("val blocked = focus == null", observations)
    commit = adapter.index("state.beforeStock(", observations)
    require(prepare < observations < blocked < commit,
        "fallible claim observations are not outside the pure helper commit")
    require("if (raw.application && focus == null)" not in adapter,
        "focus-null fail-close remains a post-commit wrapper rewrite")
    require("OriginResolver" not in helper and "Context" not in helper and
        "WindowManagerInternal" not in helper and "Settings" not in helper,
        "pure synchronized helper retains a framework callback/read")
    require("observation.request.lifecycleEpoch != lifecycleEpoch" in helper and
        helper.count("lifecycleEpoch = Math.addExact") == 3,
        "lifecycle mutation cannot invalidate an in-flight observation")

    whole = "\n".join((kgc, ims, bridge, ui, adapter, helper))
    for forbidden in (
        "installRecent", "installAltTab", "installMeta", "installCaps",
        "installEscape", "commitQueuedStart", "queuedStartSucceeded",
        "mWonadPolicyActionLock", "mWonadRecentsEndpointLock",
        "mWonadPreloadedRecentAppsOwner", "mWonadVisibleAltTabOwner",
        "captureWonadClaimedEscapeTarget", "closeWonadClaimedEscapeTarget",
    ):
        require(forbidden not in whole,
            f"rejected stock-endpoint architecture remains: {forbidden}")

    require("WonadPolicyKeyAdapter.onClaimRetiring(expected)" in bridge and
        "WonadPolicyKeyAdapter.onClaimRetired(expected)" in bridge and
        "WonadPolicyKeyAdapter.claimBlocked(state.claim)" in bridge,
        "exact claim lifecycle is not mirrored synchronously")
    retire = one_index(ui, "private fun retireShortcutClaim(claim: Claim)")
    retiring = ui.index("WonadInputBridge.onUiClaimRetiring(previous)", retire)
    unpublish = ui.index("shortcutClaimStates = shortcutClaimStates - claim.dc.displayId",
        retiring)
    retired = ui.index("WonadInputBridge.onUiClaimRetired(previous)", unpublish)
    require(retiring < unpublish < retired,
        "claim retirement is not ordered around authority unpublication")
    require("KeyEvent.obtain" not in bridge and "setDisplayId" not in bridge,
        "candidate relabels an input event to manufacture authority")

    require("registerInputDeviceListener(mWonadInputDeviceListener, mHandler)" in kgc and
        "nativeInput.getKeyCodeState(" in kgc and
        "final long expectedEpoch" in kgc and
        "input.getInputDeviceIds(), allKeysReleased, expectedEpoch" in kgc,
        "trusted complete census recovery is missing")
    require("saturatedDevices" in helper and
        "event.physical.device in saturatedDevices" in helper,
        "exceptional exhaustion is not physical-device scoped")
    require("statefulStock" not in helper and
        "if (event.action == Action.DOWN)" in helper and
        "route = route" in helper,
        "all no-claim initial DOWN routes are not retained through terminal")
    replacement = helper.index("retire(record, retainDrain = true)")
    refreshed_saturation = helper.index(
        "deviceSaturated = event.physical.device in saturatedDevices", replacement)
    require(replacement < refreshed_saturation,
        "drain overflow cannot fail the current replacement closed")

    init_rules = java_method(base_kgc, "private void initKeyCombinationRules()")
    for chord in (
        "KEYCODE_VOLUME_DOWN,\n                            KeyEvent.KEYCODE_POWER",
        "KEYCODE_POWER,\n                                KeyEvent.KEYCODE_STEM_PRIMARY",
        "KEYCODE_VOLUME_DOWN,\n                        KeyEvent.KEYCODE_VOLUME_UP",
        "KEYCODE_VOLUME_UP,\n                        KeyEvent.KEYCODE_POWER",
        "KEYCODE_BACK,\n                            KeyEvent.KEYCODE_DPAD_DOWN",
        "KEYCODE_BACK,\n                            KeyEvent.KEYCODE_DPAD_CENTER",
    ):
        require(chord in init_rules, f"retained safety chord missing: {chord}")
    multi = java_method(base_kgc, "private void handleMultiKeyGesture(int[] keycodes,")
    require("KeyCharacterMap.VIRTUAL_KEYBOARD" in multi and "DEFAULT_DISPLAY" in multi,
        "cross-device/default-display safety exception changed")

    require("return ui::LogicalDisplayId::INVALID;" in mapper and
        "getEventSource(), getDisplayId(), policyFlags" in mapper,
        "raw keyboard reader display behavior changed")
    notify = dispatcher[one_index(dispatcher, "void InputDispatcher::notifyKey("):
        one_index(dispatcher, "void InputDispatcher::notifyMotion(")]
    resolved = notify.index("calculateIntendedDisplayIdLocked(args)")
    initialized = notify.index("event.initialize(", resolved)
    queued = notify.index("mPolicy.interceptKeyBeforeQueueing(event", initialized)
    require(resolved < initialized < queued,
        "hardware key display is no longer resolved before queue policy")
    injected = dispatcher[one_index(dispatcher, "InputDispatcher::injectInputEvent("):
        one_index(dispatcher, "InputDispatcher::verifyInputEvent(")]
    require("incomingKey.getDisplayId()" in injected and
        "mPolicy.interceptKeyBeforeQueueing(keyEvent" in injected,
        "injected-key queue semantics changed")
    queue = java_method(pwm,
        "public int interceptKeyBeforeQueueing(KeyEvent event, int policyFlags)")
    require("case KeyEvent.KEYCODE_ASSIST" in queue and
        "case KeyEvent.KEYCODE_VOICE_ASSIST" in queue and
        "mGlobalKeyManager.shouldHandleGlobalKey" in queue and
        "WonadPolicyKey" not in queue,
        "OPEN pre-target PWM effect surface was silently changed or hidden")


def compile_and_run(generated: Path, temp: Path) -> None:
    routing_jar = temp / "routing.jar"
    run([
        str(KOTLIN), "-J-Xmx256m", "-include-runtime",
        str(generated / "WonadPolicyKeyContainment.kt"),
        str(HERE / "tests/TotalControlRoutingTest.kt"),
        "-d", str(routing_jar),
    ])
    run([str(JAVA), "-Xmx128m", "-cp", str(routing_jar),
        "org.wonad.server.input.TotalControlRoutingTestKt"],
        expected="TOTAL_CONTROL_ROUTING_PASS")

    adapter_jar = temp / "adapter.jar"
    stubs = sorted(str(path) for path in (HERE / "tests/stubs").rglob("*.kt"))
    run([
        str(KOTLIN), "-J-Xmx256m", "-include-runtime",
        str(generated / "WonadPolicyKeyContainment.kt"),
        str(generated / "WonadPolicyKeyAdapter.kt"),
        *stubs,
        str(HERE / "tests/AdapterFallbackTest.kt"),
        "-d", str(adapter_jar),
    ])
    run([str(JAVA), "-Xmx128m", "-cp", str(adapter_jar),
        "org.wonad.server.input.AdapterFallbackTestKt"],
        expected="ADAPTER_FALLBACK_PASS")


def main() -> int:
    require(KOTLIN.is_file() and JAVA.is_file(), "pinned Kotlin/JDK tools are absent")
    with tempfile.TemporaryDirectory(prefix="wonad-key-total-control-") as raw:
        temp = Path(raw)
        generated = temp / "generated"
        run([sys.executable, "-B", str(HERE / "apply_candidate.py"),
            "--output", str(generated)])
        source_guards(generated)
        compile_and_run(generated, temp)
    print(f"POST_TARGET_TOTAL_CONTROL_PASS checks={checks}")
    print("OPEN: pre-target PWM policy lacks exact device/incarnation/initial-origin proof")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
