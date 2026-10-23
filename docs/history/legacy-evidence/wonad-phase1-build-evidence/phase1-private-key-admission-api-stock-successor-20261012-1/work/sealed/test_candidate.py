#!/usr/bin/env python3
"""Bounded host replay for the post-target total-control candidate.

This authenticates exact inputs, materializes a fresh twelve-file candidate,
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
import hashlib
import argparse
import contextlib


HERE = Path(__file__).resolve().parent
STAGE = Path("/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7")
KOTLIN = STAGE / "external/kotlinc/bin/kotlinc"
JAVA_HOME = STAGE / "prebuilts/jdk/jdk21/linux-x86"
JAVA = JAVA_HOME / "bin/java"
BASE_KGC = STAGE / "frameworks/base/services/core/java/com/android/server/input/KeyGestureController.java"
BASE_PWM = STAGE / "frameworks/base/services/core/java/com/android/server/policy/PhoneWindowManager.java"
KEYBOARD_MAPPER = STAGE / "frameworks/native/services/inputflinger/reader/mapper/KeyboardInputMapper.cpp"
INPUT_DISPATCHER = STAGE / "frameworks/native/services/inputflinger/dispatcher/InputDispatcher.cpp"
KEY_EVENT_JNI = STAGE / "frameworks/base/core/jni/android_view_KeyEvent.cpp"
EXPECTED_FILES = {
    "Entry.h",
    "FakeInputDispatcherPolicy.cpp",
    "FakeInputDispatcherPolicy.h",
    "InputDispatcher.cpp",
    "InputDispatcherPolicyInterface.h",
    "InputManagerService.java",
    "KeyGestureController.java",
    "WonadInputBridge.kt",
    "WonadPolicyKeyAdapter.kt",
    "WonadPolicyKeyContainment.kt",
    "WonadUiBridge.kt",
    "com_android_server_input_InputManagerService.cpp",
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


def arities(text: str, name: str) -> list[int]:
    """Top-level parameter/call arity (nested parentheses are not commas)."""
    import re
    observed = []
    for matched in re.finditer(r"\b" + re.escape(name) + r"\s*\(", text):
        index = matched.end()
        depth, commas = 1, 0
        while depth:
            char = text[index]
            if char == "(": depth += 1
            elif char == ")": depth -= 1
            elif char == "," and depth == 1: commas += 1
            index += 1
        observed.append(commas + 1)
    return observed


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
    entry = (generated / "Entry.h").read_text()
    dispatcher = (generated / "InputDispatcher.cpp").read_text()
    policy = (generated / "InputDispatcherPolicyInterface.h").read_text()
    fake_h = (generated / "FakeInputDispatcherPolicy.h").read_text()
    fake_cpp = (generated / "FakeInputDispatcherPolicy.cpp").read_text()
    jni = (generated / "com_android_server_input_InputManagerService.cpp").read_text()
    pwm = BASE_PWM.read_text()
    mapper = KEYBOARD_MAPPER.read_text()
    base_dispatcher = INPUT_DISPATCHER.read_text()
    key_event_jni = KEY_EVENT_JNI.read_text()

    dispatch = one_index(kgc,
        "public long interceptKeyBeforeDispatching(IBinder focus, KeyEvent event, int policyFlags,")
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
    require("KEY_INTERCEPT_RESULT_WONAD_CLAIMED_APPLICATION = -3" in kgc and
        "wonadDecision.nativeCompletion" in kgc and
        "decision.nativeCompletion" in kgc[paste:fixed],
        "healthy source events do not retain exact native completion authority")
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
    require("MAX_PENDING_EVENTS = 256" in adapter and
        "LinkedHashMap<Long, DeliveredAuthority>" in adapter and
        "deliveries[admissionToken]" in adapter and "takeAuthority(" in adapter and
        "bypassUnhandledStock" in adapter and "bypassFallbackQueueing" in adapter and
        "fun finishHandled(admissionToken: Long" in adapter,
        "bounded private-nonce completion authority is missing")
    require("WeakHashMap" not in adapter and "DisplayAuthority" not in adapter and
        "MAX_CLAIMED_DISPLAYS_PER_WINDOW" not in adapter,
        "historical focus/display authority remains in the adapter")
    require("admissionToken <= 0L || admissionToken in deliveries" in adapter and
        "deliveries[call.token] === own" in adapter and "call.registered = record" in adapter,
        "duplicate token or non-owning rollback can alias prior claim authority")
    require("nativeCompletion = fallback == null && raw.application" in adapter,
        "synchronously derived fallbacks manufacture a second native marker")
    require("ThreadLocal<FallbackScope?>" in adapter and
        "ThreadLocal<UnhandledScope?>" in adapter and
        "fun beginUnhandled" in adapter and "fun endUnhandled" in adapter and
        "fun beginFallback" in adapter and "fun endFallback" in adapter and
        "matchingFallback" in adapter,
        "unhandled/fallback derivation is not exact and synchronous")

    dispatch_unhandled = java_method(ims,
        "private KeyEvent dispatchUnhandledKey(IBinder focus, KeyEvent event, int policyFlags,")
    no_fallback = dispatch_unhandled.index("if (fallbackAction == null)")
    scope_begin = dispatch_unhandled.index("WonadPolicyKeyAdapter.beginFallback", no_fallback)
    scope_finally = dispatch_unhandled.index("WonadPolicyKeyAdapter.endFallback", scope_begin)
    require(no_fallback < scope_begin < scope_finally,
        "fallback authority is retained before KCM proves a fallback or lacks finally cleanup")
    unhandled_scope = dispatch_unhandled.index("Object wonadUnhandledScope = null")
    unhandled_try = dispatch_unhandled.index("try", unhandled_scope)
    unhandled_begin = dispatch_unhandled.index("beginUnhandled", unhandled_try)
    cleanup_missing = dispatch_unhandled.index(
        "if (wonadClaimed && wonadUnhandledScope == null)", unhandled_begin)
    unhandled_end = dispatch_unhandled.index("endUnhandled", cleanup_missing)
    require(unhandled_scope < unhandled_try < unhandled_begin < cleanup_missing < unhandled_end,
        "native marker cleanup is not protected across begin/unhandled failures")

    require("CONTINUE_WONAD_CLAIMED" in entry and
        "WonadCompletionOwner { NONE, PENDING, FOREGROUND, TAKEN }" in entry and
        "mutable bool wonadInboundReleased = false" in entry,
        "KeyEntry does not retain exact claimed completion lifetime")
    require("bool wonadClaimed" in policy and
        "int64_t wonadAdmissionToken" in policy and
        "notifyWonadKeyHandled(const KeyEvent&, int64_t, ui::LogicalDisplayId, bool) override" in fake_h and
        "FakeInputDispatcherPolicy::notifyWonadKeyHandled" in fake_cpp,
        "private dispatcher policy/fake completion surface is incomplete")
    require("if (delayMillis == -3)" in jni and
        "InterceptKeyResult::CONTINUE_WONAD_CLAIMED" in jni and
        "bool wonadClaimed" in jni and
        '"(Landroid/os/IBinder;Landroid/view/KeyEvent;IZJI)Landroid/view/KeyEvent;"' in jni and
        '"(JIIIJIZ)V"' in jni,
        "JNI does not bind the exact private completion marker")
    require("gKeyEventClassInfo.obtain, event.getId()" in key_event_jni and
        "jint id = env->GetIntField(eventObj, gKeyEventClassInfo.mId)" in key_event_jni,
        "native/Java KeyEvent copies do not preserve the exact event id")
    for native_surface, label in ((policy, "policy"), (fake_h, "fake declaration"),
            (fake_cpp, "fake implementation"), (jni, "JNI declaration/definition")):
        require(all(value == 4 for value in arities(native_surface,
            "interceptKeyBeforeDispatching")), f"{label} admission signature drift")
        require(all(value == 6 for value in arities(native_surface,
            "dispatchUnhandledKey")), f"{label} unhandled signature drift")
        require(all(value == 4 for value in arities(native_surface,
            "notifyWonadKeyHandled")), f"{label} cleanup signature drift")
    require(all(value == 6 for value in arities(dispatcher, "dispatchUnhandledKey")) and
        all(value == 4 for value in arities(dispatcher, "notifyWonadKeyHandled")),
        "native dispatcher call arity drift")
    require("nanoseconds_to_milliseconds(keyEvent.getDownTime())" in jni,
        "primitive cleanup time must match Java KeyEvent.getDownTime milliseconds")
    require(jni.index("if (delayMillis == -3)") < jni.index("if (delayMillis < 0)") <
        jni.index("if (delayMillis > 60000)") < jni.index("milliseconds_to_nanoseconds(delayMillis)"),
        "malformed negative/overflow delay can reach duration conversion")
    obtain_failure = jni.index('ALOGE("Failed to obtain key event object for dispatchUnhandledKey.")')
    require(jni.index("checkAndClearExceptionFromCallback", obtain_failure) <
        jni.index("notifyWonadKeyHandled", obtain_failure),
        "obtain failure leaves pending exception during exact primitive cleanup")
    require("if (!callbackFailed && delayMillis == -3)" in jni and
        jni.index("const bool callbackFailed") < jni.index('"recycle intercepted KeyEvent"'),
        "postcommit recycling can leak authority or clean duplicate invocation")
    require("call.provisional?.let { state.failApplicationPair(it, it.physical) }" in adapter and
        "admissionCall.get()?.provisional = raw.pair" in adapter,
        "precommit SecurePaste exception can deliver unmatched terminal UP")

    after_key = dispatcher.index("InputDispatcher::afterKeyEventLockedInterruptable(")
    foreground_marker = dispatcher.index(
        "const bool wonadClaimed = hasForegroundTarget", after_key)
    final_target = dispatcher.index(
        "mPolicy.dispatchUnhandledKey(connection->getToken(), event,", foreground_marker)
    exact_bool = dispatcher.index("keyEntry.policyFlags, wonadClaimed", final_target)
    require(after_key < foreground_marker < final_target < exact_bool,
        "actual final connection does not receive the exact KeyEntry marker")
    require("dispatchEntry->wonadClaimedCompletionOwner = true" in dispatcher and
        "keyEntry.wonadCompletionOwner ==" in dispatcher and
        dispatcher.count("mPolicy.notifyWonadKeyHandled(event, admissionToken, admittedDisplay,") == 3,
        "handled/dropped/broken KeyEntry cleanup surface is incomplete")
    release_inbound = dispatcher.index("void InputDispatcher::releaseInboundEventLocked(")
    release_dispatch = dispatcher.index("void InputDispatcher::releaseDispatchEntry(")
    finish_callback = dispatcher.index("auto finishWonadHandled", after_key)
    require(dispatcher.index("scoped_unlock unlock(mLock)", release_inbound) <
        dispatcher.index("mPolicy.notifyWonadKeyHandled(event, admissionToken", release_inbound) and
        dispatcher.index("scoped_unlock unlock(mLock)", release_dispatch) <
        dispatcher.index("mPolicy.notifyWonadKeyHandled(event, admissionToken", release_dispatch) and
        dispatcher.index("scoped_unlock unlock(mLock)", finish_callback) <
        dispatcher.index("mPolicy.notifyWonadKeyHandled(event, admissionToken", finish_callback),
        "completion callback can execute while InputDispatcher lock is held")
    require("WonadCompletionOwner::TAKEN" in dispatcher and
        "if (wonadClaimed) {" in dispatcher,
        "trusted unhandled policy completion does not retire the native marker")
    require("Object wonadUnhandledScope = null" in ims and
        "private void notifyWonadKeyHandled(long wonadAdmissionToken" in ims and
        "beginAdmissionCall(wonadAdmissionToken)" in ims and "finishAdmissionCall(" in ims,
        "IMS does not replay exact handled/unhandled cleanup")

    prepare = adapter.index("val request = state.prepareObservation(observed, current)")
    observations = adapter.index("val claims = request.origins.map", prepare)
    blocked = adapter.index("val blocked = (focus == null && request.origins.isNotEmpty())", observations)
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
    notify = base_dispatcher[one_index(base_dispatcher, "void InputDispatcher::notifyKey("):
        one_index(base_dispatcher, "void InputDispatcher::notifyMotion(")]
    resolved = notify.index("calculateIntendedDisplayIdLocked(args)")
    initialized = notify.index("event.initialize(", resolved)
    queued = notify.index("mPolicy.interceptKeyBeforeQueueing(event", initialized)
    require(resolved < initialized < queued,
        "hardware key display is no longer resolved before queue policy")
    require("args.deviceId, args.source, args.displayId, policyFlags" in notify,
        "OPEN raw native display re-resolution gap was silently changed")
    injected = base_dispatcher[one_index(base_dispatcher, "InputDispatcher::injectInputEvent("):
        one_index(base_dispatcher, "InputDispatcher::verifyInputEvent(")]
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
    print(run([str(JAVA), "-Xmx128m", "-cp", str(routing_jar),
        "org.wonad.server.input.TotalControlRoutingTestKt"],
        expected="TOTAL_CONTROL_ROUTING_PASS").strip())

    adapter_jar = temp / "adapter.jar"
    stubs = sorted(str(path) for path in (HERE / "tests/stubs").rglob("*.kt"))
    run([
        str(KOTLIN), "-J-Xmx256m", "-include-runtime",
        str(generated / "WonadPolicyKeyContainment.kt"),
        str(generated / "WonadPolicyKeyAdapter.kt"),
        *stubs,
        str(HERE / "tests/NativeNonceAdapterTest.kt"),
        "-d", str(adapter_jar),
    ])
    print(run([str(JAVA), "-Xmx128m", "-cp", str(adapter_jar),
        "org.wonad.server.input.NativeNonceAdapterTestKt"],
        expected="NATIVE_NONCE_ADAPTER_PASS").strip())
    compile_native_projection(generated, temp)
    compile_stock_caller_projection(generated, temp)


def compile_stock_caller_projection(generated: Path, temp: Path) -> None:
    import re
    callers_path = STAGE / "frameworks/base/tests/Input/src/com/android/server/input/KeyGestureControllerTests.kt"
    require(hashlib.sha256(callers_path.read_bytes()).hexdigest() ==
        "f14238927f72d9b8939fcf1f707d7f7c869490146d8b3125b86d9f82932b7077",
        "pinned existing private caller test changed")
    callers = callers_path.read_text()
    calls = []
    for match in re.finditer(r"keyGestureController\.interceptKeyBeforeDispatching\(", callers):
        depth, end = 1, match.end()
        while depth:
            if callers[end] == "(": depth += 1
            elif callers[end] == ")": depth -= 1
            end += 1
        call = callers[match.start():end]
        require(arities(re.sub(r",\s*\)$", ")", call), "interceptKeyBeforeDispatching") == [3],
            "existing platform private caller shape changed")
        calls.append(call)
    require(len(calls) == 15, "existing private caller inventory incomplete")
    kgc = (generated / "KeyGestureController.java").read_text()
    compatibility = java_method(kgc,
        "public long interceptKeyBeforeDispatching(IBinder focus, KeyEvent event, int policyFlags)")
    require("return interceptKeyBeforeDispatching(focus, event, policyFlags, 0L);" in compatibility,
        "stock compatibility can manufacture claimed nonce authority")
    projection = temp / "stock-caller"
    projection.mkdir()
    (projection / "IBinder.java").write_text("public interface IBinder {}\n")
    (projection / "KeyEvent.java").write_text("public class KeyEvent { public static final int ACTION_DOWN = 0; }\n")
    (projection / "KeyGestureController.java").write_text(
        "public class KeyGestureController { public long lastNonce = -1;\n" + compatibility +
        "\npublic long interceptKeyBeforeDispatching(IBinder f, KeyEvent e, int p, long n) {\n"
        "lastNonce = n; return 0L; } }\n")
    (projection / "CallerProjection.kt").write_text(
        "private const val FLAG_TRUSTED = 1\n"
        "private fun createPasteKeyEvent(action: Int) = KeyEvent()\n"
        "fun main() { val keyGestureController = KeyGestureController(); val focus: IBinder? = null;\n"
        "val event = KeyEvent(); val initialDown = event; val repeatDown = event; val up = event; val canceledDown = event;\n" +
        "\n".join(call + "; check(keyGestureController.lastNonce == 0L)" for call in calls) +
        '\nprintln("STOCK_PRIVATE_CALLER_SIGNATURE_PASS calls=' + str(len(calls)) + '") }\n')
    run([str(JAVA_HOME / "bin/javac"), "-d", str(projection),
        str(projection / "IBinder.java"), str(projection / "KeyEvent.java"),
        str(projection / "KeyGestureController.java")])
    run([str(KOTLIN), "-J-Xmx256m", "-include-runtime", "-classpath", str(projection),
        str(projection / "CallerProjection.kt"), "-d", str(projection / "callers.jar")])
    print(run([str(JAVA), "-Xmx128m", "-cp", str(projection) + ":" + str(projection / "callers.jar"),
        "CallerProjectionKt"], expected="STOCK_PRIVATE_CALLER_SIGNATURE_PASS").strip())


def compile_native_projection(generated: Path, temp: Path) -> None:
    source = (generated / "InputDispatcher.cpp").read_text()
    entry = (generated / "Entry.h").read_text()
    input_state_path = STAGE / "frameworks/native/services/inputflinger/dispatcher/InputState.cpp"
    require(hashlib.sha256(input_state_path.read_bytes()).hexdigest() ==
        "ba322dd34e39f4421147a3187382bded3721b9a0f747a0c12e1b2462209115b8",
        "stock InputState cancellation input changed")
    state = input_state_path.read_text()
    fields_start = entry.index("    enum class WonadCompletionOwner")
    fields_end = entry.index("    mutable nsecs_t interceptKeyWakeupTime", fields_start)
    fields_end = entry.index("\n", fields_end)
    enqueue_start = source.index("void InputDispatcher::enqueueDispatchEntryLocked(")
    track_start = source.index("        case EventEntry::Type::KEY: {", enqueue_start)
    track_end = source.index("        case EventEntry::Type::MOTION:", track_start)
    transfer_start = source.index("    // Remember that we are waiting", track_end)
    transfer_end = source.index("    // Enqueue the dispatch entry.", transfer_start)
    cancel_start = state.index("    for (KeyMemento& memento : mKeyMementos)")
    cancel_end = state.index("    for (const MotionMemento&", cancel_start)
    allocator = java_method(source, "int64_t nextWonadAdmissionToken()")
    # The source callback must use the unchanged production allocator {1}.
    # Exhaustion tests call a second extraction with only initial storage changed.
    exhaustion = allocator.replace("nextWonadAdmissionToken()", "exhaustWonadAdmissionToken()")
    exhaustion = exhaustion.replace("next{1}", "next{INT64_MAX - 1}")
    substitutions = {
        "ENTRY_FIELDS": entry[fields_start:fields_end],
        "ALLOCATOR": allocator + "\n" + exhaustion,
        "BEFORE_CALLBACK": java_method(source,
            "void InputDispatcher::doInterceptKeyBeforeDispatchingCommand("),
        "RELEASE_INBOUND": java_method(source,
            "void InputDispatcher::releaseInboundEventLocked("),
        "RELEASE_DISPATCH": java_method(source,
            "void InputDispatcher::releaseDispatchEntry("),
        "AFTER_CALLBACK": java_method(source,
            "std::unique_ptr<const KeyEntry> InputDispatcher::afterKeyEventLockedInterruptable("),
        "SHOULD_CANCEL": java_method(state, "bool InputState::shouldCancelKey("),
        "TRACK_KEY": source[track_start:track_end],
        "TRANSFER": source[transfer_start:transfer_end],
        "CANCEL_KEYS": state[cancel_start:cancel_end],
        "JNI_DECODE": java_method((generated /
            "com_android_server_input_InputManagerService.cpp").read_text(),
            "NativeInputManager::interceptKeyBeforeDispatching(").split(
                "    // Negative delay represent states", 1)[1].split("\n", 1)[1].rsplit("}", 1)[0],
    }
    projection = (HERE / "tests/NativeLifetimeTest.cpp.in").read_text()
    for marker, value in substitutions.items():
        projection = projection.replace("@@" + marker + "@@", value)
    # Replace only three test calls, not native production allocator calls.
    projection = projection.replace("verify(nextWonadAdmissionToken()", "verify(exhaustWonadAdmissionToken()")
    projection = projection.replace("&& nextWonadAdmissionToken() == 0", "&& exhaustWonadAdmissionToken() == 0")
    cpp = temp / "native-lifetime.cpp"
    cpp.write_text(projection)
    binary = temp / "native-lifetime"
    run(["/usr/bin/g++", "-std=c++20", "-O0", "-pthread", str(cpp), "-o", str(binary)])
    print(run([str(binary)], expected="NATIVE_LIFETIME_PROJECTION_PASS").strip())


def main() -> int:
    require(KOTLIN.is_file() and JAVA.is_file(), "pinned Kotlin/JDK tools are absent")
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    if args.evidence is not None:
        require(args.evidence.resolve().is_relative_to(HERE),
            "persistent host outputs must stay inside this external successor")
        args.evidence.mkdir(parents=True, exist_ok=False)
    work = contextlib.nullcontext(str(args.evidence)) if args.evidence else \
        tempfile.TemporaryDirectory(prefix="wonad-key-admission-host-")
    with work as raw:
        temp = Path(raw)
        generated = temp / "generated"
        run([sys.executable, "-B", str(HERE / "apply_candidate.py"),
            "--output", str(generated)])
        source_guards(generated)
        compile_and_run(generated, temp)
    print(f"POST_TARGET_NATIVE_TOKEN_PASS checks={checks}")
    print("OPEN: pre-target PWM policy lacks exact device/incarnation/initial-origin proof")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
