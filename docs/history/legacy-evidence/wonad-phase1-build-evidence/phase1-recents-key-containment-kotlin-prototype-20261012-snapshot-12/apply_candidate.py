#!/usr/bin/env python3
"""Materialize the external Kotlin containment candidate from exact custom7 inputs.

This tool refuses unreviewed input bytes and writes only a new caller-selected
directory.  It never edits the repository or GrapheneOS source tree.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import shutil


ROOT = Path("/u/elric/tree/wonad")
STAGE = Path("/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7")
HERE = Path(__file__).resolve().parent

INPUTS = {
    "ims": (
        STAGE / "frameworks/base/services/core/java/com/android/server/input/InputManagerService.java",
        "df0e4cc78508383cd60fd2cd534ba450a0df2071b211ee21115fa71f35470dc1",
    ),
    "kgc": (
        STAGE / "frameworks/base/services/core/java/com/android/server/input/KeyGestureController.java",
        "3acaa08d5a39200bbcd521f760339c4d531936656899c195b9b9fa9b28aa66c5",
    ),
    "pwm": (
        STAGE / "frameworks/base/services/core/java/com/android/server/policy/PhoneWindowManager.java",
        "25be0cd9384ef463af854067e4904701041ece23ef0e9b9f8cc348503e6e1898",
    ),
    "bridge": (
        ROOT / "android/input-integration/src/org/wonad/server/input/WonadInputBridge.kt",
        "b512112fe58157e8e1a18baa3dbf0c0c338f073ea4d901c63d9949aaa11e60ff",
    ),
    "ui": (
        ROOT / "android/input-integration/src/com/android/server/wm/WonadUiBridge.kt",
        "8d227e84eef912d1016698e018ca37642cff8ec0150a380eb25dbf7e8dc21da4",
    ),
    "wmi": (
        STAGE / "frameworks/base/services/core/java/com/android/server/wm/WindowManagerInternal.java",
        "f940e0a8cb19b0e5902c23642043b8d24679fe914fe3d7f28db633c9d47da582",
    ),
    "wms": (
        STAGE / "frameworks/base/services/core/java/com/android/server/wm/WindowManagerService.java",
        "c2eb228520a585d86aa4097230f5c88700d32c08cbc8f2cf4da93b3787d6342c",
    ),
}

# Exact supporting sources for the lock-order review.  They are not rewritten,
# but refusing changed bytes prevents this candidate from silently projecting
# a lock conclusion onto a different platform implementation.
SUPPORT_INPUTS = {
    "Toast.java": (
        STAGE / "frameworks/base/core/java/android/widget/Toast.java",
        "f1da26d7d901315973e0364817576dbec6c1679eb6dbb11c7341fe27b0fd0120",
    ),
    "NotificationManagerService.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/notification/NotificationManagerService.java",
        "7176bdfb9aac98688a5710569fd2af6384259b111c71b304f5caaa0faf2e5c86",
    ),
    "WindowState.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/wm/WindowState.java",
        "a89225e7f263c769935f11179675887edb2f42fca3d548180ad6cc5ef74db02b",
    ),
    "ActivityRecord.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/wm/ActivityRecord.java",
        "ce91950667a1506172376737fc7520a48cb8a9a9ffeb549b7c5776d933dd0adc",
    ),
    "Task.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/wm/Task.java",
        "b58a4e7a8b9dba792c81e60a82e799aac81cd5f22175d6eb633f3c404153f6f8",
    ),
    "IStatusBar.aidl": (
        STAGE / "frameworks/base/core/java/com/android/internal/statusbar/IStatusBar.aidl",
        "4a9e4910bfbdf05e22c5fe28dd59af5146daa102afd327a199b8b1b57baf3fa2",
    ),
    "StatusBarManagerService.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/statusbar/StatusBarManagerService.java",
        "e7aef6f1795385937f1ad774740495ec3d8b0566fd328beb763d6a2f1b4c389a",
    ),
    "UserController.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/am/UserController.java",
        "b30cdcac2ca4976ab0f1427f468ad0d4e4e1de324a7fa76edcab81047dcaad41",
    ),
    "ActivityManagerService.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java",
        "3851765b11595887e6b044af93646b3b859363195ce4a5ec19d50b7dc55a8dee",
    ),
    "ActivityTaskManagerService.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/wm/ActivityTaskManagerService.java",
        "28d200431fd4a7289e3bf8f27d60f0c9472a8912da0211cf3bd5773eee170330",
    ),
    "LockTaskController.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/wm/LockTaskController.java",
        "929fb43d3bba2487a1ab9498be18b3fcea86bed8a1808d4034188dbce379d903",
    ),
    "DisplayManagerService.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/display/DisplayManagerService.java",
        "4bcd0a935e70b9dfb692c892e749fc0fa295fb38660ea6c1310b0f6790422a5f",
    ),
    "KeyguardServiceDelegate.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/policy/keyguard/KeyguardServiceDelegate.java",
        "522361e7cb37ffc9410a6879fd151260b7495504c4d8b8804a8bcfc2e722b74f",
    ),
    "IKeyGestureHandler.aidl": (
        STAGE / "frameworks/base/core/java/android/hardware/input/IKeyGestureHandler.aidl",
        "0f0d5d606d91fe981c50564af000a18cf51fad41c6c6c07a7cc6d8d08cd14945",
    ),
    "InputManagerGlobal.java": (
        STAGE / "frameworks/base/core/java/android/hardware/input/InputManagerGlobal.java",
        "8ae9a17705009ff4a65d9a64ca690733e290937288b061436430fad82807f774",
    ),
    "QuitFocusedAppKeyGestureHandler.kt": (
        STAGE / "frameworks/base/libs/WindowManager/Shell/src/com/android/wm/shell/common/QuitFocusedAppKeyGestureHandler.kt",
        "7e8461a7c5a71bbea3dfa4c365d4e09885feee9320453abe40704e6c4d4041c2",
    ),
    "InputGestureData.java": (
        STAGE / "frameworks/base/core/java/android/hardware/input/InputGestureData.java",
        "af518215e1cb74dd73daba35380402722890aa15540d86e54d53a699c735f650",
    ),
    "InputGestureManager.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/input/InputGestureManager.java",
        "bd99d2ed7e12ace76b72e93d5ec28d90dde25b966b95f98569344a5cadf18faa",
    ),
    "InputManagerService-jni.cpp": (
        STAGE / "frameworks/base/services/core/jni/com_android_server_input_InputManagerService.cpp",
        "0a71ebf0fb6697a1f21a6abe0e14e53d4b961e40a4baace0b8dedb0d5b8c08c5",
    ),
    "InputReader.cpp": (
        STAGE / "frameworks/native/services/inputflinger/reader/InputReader.cpp",
        "3a5acd8dbbd4d880a27eb84d9de68cbcceb81a91593749340a1800be7856eb5d",
    ),
    "TouchpadInputMapper.cpp": (
        STAGE / "frameworks/native/services/inputflinger/reader/mapper/TouchpadInputMapper.cpp",
        "d3cae87aca13c3aacdb130c030b96940bc6e307fa1814ea5aa95f630ed3f5471",
    ),
    "UncapturedGestureConverter.cpp": (
        STAGE / "frameworks/native/services/inputflinger/reader/mapper/gestures/UncapturedGestureConverter.cpp",
        "1136345136a27b5e1662f6b7c936ba8a5689a56d30da0acf826bd9811ee892f3",
    ),
    "ContextImpl.java": (
        STAGE / "frameworks/base/core/java/android/app/ContextImpl.java",
        "0a0a08280c32dbd6ab2995a9d832ed77e3ab17c1ff08f3d0fc246e0bd462a95b",
    ),
    "ActivityStarter.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/wm/ActivityStarter.java",
        "2e486da0ce092e7c64474db91b341422e9d5257b0102713b5649c4b55434fdf1",
    ),
    "Settings.java": (
        STAGE / "frameworks/base/core/java/android/provider/Settings.java",
        "2e120f6e778bf117629b7a95427fa28ab29829d35dc2295a3f05a2a174d1b0d9",
    ),
    "SettingsProvider.java": (
        STAGE / "frameworks/base/packages/SettingsProvider/src/com/android/providers/settings/SettingsProvider.java",
        "493f8ae79ea36b7f1c0e35b363f56ff544ed2e9f16345ca43e4147276e5322cb",
    ),
    "SettingsState.java": (
        STAGE / "frameworks/base/packages/SettingsProvider/src/com/android/providers/settings/SettingsState.java",
        "e2a5c43515382bc521be74d0147d7b014552c47e967f31b898d512c10e86ba61",
    ),
    "SettingsProvider-AndroidManifest.xml": (
        STAGE / "frameworks/base/packages/SettingsProvider/AndroidManifest.xml",
        "24d5770a4eb36916950325a5d6ea0ecee6c7254f338f5925d8ff524a9e699b71",
    ),
    "ActivityThread.java": (
        STAGE / "frameworks/base/core/java/android/app/ActivityThread.java",
        "836465993d13d4af15951a9b3870bef5018bc5bc67b442939dc28fc025253c35",
    ),
    "ActivityManager.java": (
        STAGE / "frameworks/base/core/java/android/app/ActivityManager.java",
        "428ea4bb8d50f0f67b494e777c3b94c1843d53bbe62b427c018848aeed6c8f62",
    ),
    "UserManager.java": (
        STAGE / "frameworks/base/core/java/android/os/UserManager.java",
        "040cca0a3f4711c64fd84e6c3fbb3da5574833e0864427477c3a091a01e54a88",
    ),
    "UserManagerService.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/pm/UserManagerService.java",
        "8da8432c10548c811c29e6a5b6b314cf3ab39acecf0b2b64799136ac6c1f30d5",
    ),
    "DisplayManager.java": (
        STAGE / "frameworks/base/core/java/android/hardware/display/DisplayManager.java",
        "08651f53fb377952d206017150db46e6599c5fad40a2c89f624bf2d2d023b7e8",
    ),
    "DisplayManagerGlobal.java": (
        STAGE / "frameworks/base/core/java/android/hardware/display/DisplayManagerGlobal.java",
        "da0a459c1dc040f893d4f43611fa06a4ab728d2a681f86fb14a62619c4e93804",
    ),
    "Display.java": (
        STAGE / "frameworks/base/core/java/android/view/Display.java",
        "266257a7e246a8db480c176520900c38f08bd62d9f480490c90b894b9936aca4",
    ),
    "UserVisibilityMediator.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/pm/UserVisibilityMediator.java",
        "b02ef309d808b135c68a3342775b76cdd7e19edbe7ca9cda52f45f58da2bb41e",
    ),
    "UserManagerInternal.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/pm/UserManagerInternal.java",
        "cd6b676b2bf56be8ca376cd6e4cc0c1a1b2f6b95afea3ec79d65489a53bc3b20",
    ),
    "Handler.java": (
        STAGE / "frameworks/base/core/java/android/os/Handler.java",
        "002ea23610c36245b39d97d377e1abcd2c440708b0b2af9e6a1f16b3fdfcc22a",
    ),
    "Looper.java": (
        STAGE / "frameworks/base/core/java/android/os/Looper.java",
        "89f15ad65f57e53c36ee91b51ce0761cdb0fa949c4f5c4bd60b7604748acfe33",
    ),
    "CombinedMessageQueue.java": (
        STAGE / "frameworks/base/core/java/android/os/CombinedMessageQueue/MessageQueue.java",
        "723297b2b18572bbc0433d53923c4ce869d5ea71703ee2c500f7906d8e7058df",
    ),
    "LegacyMessageQueue.java": (
        STAGE / "frameworks/base/core/java/android/os/LegacyMessageQueue/MessageQueue.java",
        "043ecf5c85fdb164c5df3da683831a66e823b5b93b8afb546943afed218cb537",
    ),
    "core-java-Android.bp": (
        STAGE / "frameworks/base/core/java/Android.bp",
        "10531a97d48d3841c88b9208215a4297dca17b0451536921bd39bbdcfd333e97",
    ),
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one source anchor, observed {count}")
    return text.replace(old, new)


def replace_count(text: str, old: str, new: str, count: int, label: str) -> str:
    observed = text.count(old)
    if observed != count:
        raise SystemExit(f"{label}: expected {count} source anchors, observed {observed}")
    return text.replace(old, new)


def key_gesture_controller(source: str) -> str:
    source = replace_once(source, "import java.util.HashSet;",
        "import java.util.HashMap;", "exact stage-map import")
    source = replace_once(source, "import java.util.Map;",
        "import java.util.Map;\nimport java.util.concurrent.atomic.AtomicReference;\n"
        "import java.util.function.BooleanSupplier;",
        "exact owner atomic import")
    source = replace_once(source, '''    private boolean mPendingMetaAction;
    private boolean mPendingCapsLockToggle;
    private boolean mPendingHideRecentSwitcher;
''', '''    private boolean mPendingMetaAction;
    private boolean mPendingCapsLockToggle;
    private boolean mPendingHideRecentSwitcher;
    // Java booleans mirror the exact Kotlin owner through atomic identity.
    // Delayed cleanup for a retired claim can never clear a replacement.
    private final AtomicReference<Object> mWonadPendingMetaOwner =
            new AtomicReference<>();
    private final AtomicReference<Object> mWonadPendingCapsOwner =
            new AtomicReference<>();
    private final AtomicReference<Object> mWonadPendingAltTabOwner =
            new AtomicReference<>();
''', "exact pending-owner mirrors")
    source = replace_once(source, '''    private final AtomicReference<Object> mWonadPendingAltTabOwner =
            new AtomicReference<>();

    // Platform behaviors
''', '''    private final AtomicReference<Object> mWonadPendingAltTabOwner =
            new AtomicReference<>();

    // Serializes Wonad-owned stock endpoint effects after the pure helper
    // monitor is released. Claimed and phone input work cannot overtake one
    // another between commit, START and terminal cleanup. Independent stock
    // PWM operations retain their ordinary endpoint-call order.
    private final Object mWonadPolicyActionLock = new Object();

    // The native reader is used only for exceptional saturation recovery: a
    // complete all-device/all-keycode UP census.  Tests without it fail closed.
    @Nullable private final NativeInputManagerService mWonadNativeInput;
    @Nullable private InputManager mWonadInputManager;

    // Device retirement discards that device's missing-UP pair state, then a
    // full physical census may release exceptional global saturation.
    private final InputManager.InputDeviceListener mWonadInputDeviceListener =
            new InputManager.InputDeviceListener() {
                @Override public void onInputDeviceAdded(int deviceId) {}
                @Override public void onInputDeviceChanged(int deviceId) {}
                @Override public void onInputDeviceRemoved(int deviceId) {
                    final org.wonad.server.input.WonadPolicyKeyAdapter.Decision decision =
                            org.wonad.server.input.WonadPolicyKeyAdapter.removeDevice(deviceId);
                    applyWonadPolicyCleanup(decision);
                    for (InterceptKeyStage stage : mInterceptStages.values()) {
                        stage.removeDevice(deviceId);
                    }
                    if (decision.saturated) reconcileWonadPolicyDevices();
                }
            };

    // Platform behaviors
''', "input-device retirement listener")
    source = replace_once(source, '''    public KeyGestureController(Context context, Looper looper, Looper ioLooper,
            InputDataStore inputDataStore) {
        this(context, looper, ioLooper, inputDataStore, new Injector());
    }

    @VisibleForTesting
    KeyGestureController(Context context, Looper looper, Looper ioLooper,
            InputDataStore inputDataStore, Injector injector) {
        mContext = context;
''', '''    public KeyGestureController(Context context, Looper looper, Looper ioLooper,
            InputDataStore inputDataStore) {
        this(context, looper, ioLooper, inputDataStore, new Injector(), null);
    }

    KeyGestureController(Context context, Looper looper, Looper ioLooper,
            InputDataStore inputDataStore, NativeInputManagerService nativeInput) {
        this(context, looper, ioLooper, inputDataStore, new Injector(), nativeInput);
    }

    @VisibleForTesting
    KeyGestureController(Context context, Looper looper, Looper ioLooper,
            InputDataStore inputDataStore, Injector injector) {
        this(context, looper, ioLooper, inputDataStore, injector, null);
    }

    private KeyGestureController(Context context, Looper looper, Looper ioLooper,
            InputDataStore inputDataStore, Injector injector,
            @Nullable NativeInputManagerService nativeInput) {
        mWonadNativeInput = nativeInput;
        mContext = context;
''', "native census constructor wiring")
    source = replace_once(source, '''        InputManager im = Objects.requireNonNull(mContext.getSystemService(InputManager.class));
        im.registerKeyGestureEventHandler(
''', '''        InputManager im = Objects.requireNonNull(mContext.getSystemService(InputManager.class));
        mWonadInputManager = im;
        org.wonad.server.input.WonadPolicyKeyAdapter.registerCleanupListener(decision -> {
            applyWonadPolicyMirrorCleanup(decision);
            // This callback may run while WMS global is held. Never call KGC,
            // PWM, or the private WMS endpoint inline. If the sole Handler
            // rejects the lifecycle cleanup, preserve the exact helper ticket
            // and fail closed instead of terminalizing an undispatched cancel.
            requireWonadHandlerPost(
                    () -> applyWonadPolicyActionCleanup(decision, false));
        });
        im.registerInputDeviceListener(mWonadInputDeviceListener, mHandler);
        im.registerKeyGestureEventHandler(
''', "input-device retirement registration")
    source = replace_once(source, '''        // Cancel any pending meta actions if we see any other keys being pressed between the
        // down of the meta key and its corresponding up.
        if (mPendingMetaAction && !KeyEvent.isMetaKey(keyCode)) {
            mPendingMetaAction = false;
        }
        // Any key that is not Alt or Meta cancels Caps Lock combo tracking.
        if (mPendingCapsLockToggle && !KeyEvent.isMetaKey(keyCode) && !KeyEvent.isAltKey(keyCode)) {
            mPendingCapsLockToggle = false;
        }

        // Multi-key shortcuts should never be blocked by any focused window configuration
''', '''        // Preserve stock's passive pending-state bookkeeping before safety, but bind any
        // blocked-event cleanup to its exact original Wonad claim owner.
        final int wonadPolicyRole = wonadPolicyRole(keyCode);
        final org.wonad.server.input.WonadPolicyKeyAdapter.Passive passive =
                org.wonad.server.input.WonadPolicyKeyAdapter.passiveBeforeSafety(
                        mContext, mWindowManagerInternal, event, wonadPolicyRole);
        clearWonadMetaOwner(passive.clearMeta);
        clearWonadCapsOwner(passive.clearCaps);

        // Multi-key shortcuts should never be blocked by any focused window configuration
''', "owner-aware passive bookkeeping")

    source = replace_once(source, '''            if (org.wonad.server.input.WonadInputBridge.consumeClaimedInput(
                    mContext, mWindowManagerInternal, event, policyFlags)) {
                return KEY_INTERCEPT_RESULT_CONSUMED;
            }
            SecurePasteKeyEventHandler.maybeGrantAccess(mWindowManagerInternal, focus, event);
''', '''            final org.wonad.server.input.WonadPolicyKeyAdapter.Decision decision =
                    org.wonad.server.input.WonadPolicyKeyAdapter.beforeStock(
                            mContext, mWindowManagerInternal, event, wonadPolicyRole);
            if (applyWonadPolicyDecision(focus, event, policyFlags, decision)) {
                return KEY_INTERCEPT_RESULT_CONSUMED;
            }
            SecurePasteKeyEventHandler.maybeGrantAccess(mWindowManagerInternal, focus, event);
''', "secure paste final guard")

    source = replace_once(source, '''        if (wonadShortcut && org.wonad.server.input.WonadInputBridge.intercept(
                mContext, mWindowManagerInternal, event, policyFlags)) {
            return KEY_INTERCEPT_RESULT_CONSUMED;
        }

        // TODO(b/358569822) Remove below once we have nicer API for listening to shortcuts
''', '''        if (wonadShortcut && org.wonad.server.input.WonadInputBridge.intercept(
                mContext, mWindowManagerInternal, event, policyFlags)) {
            return KEY_INTERCEPT_RESULT_CONSUMED;
        }

        // Generic fail-black containment is deliberately after platform safety,
        // SecurePaste policy and the fixed Wonad alphabet, but before every stock
        // system action or focused-window capture bypass.
        final org.wonad.server.input.WonadPolicyKeyAdapter.Decision wonadDecision =
                org.wonad.server.input.WonadPolicyKeyAdapter.beforeStock(
                        mContext, mWindowManagerInternal, event, wonadPolicyRole);
        if (applyWonadPolicyDecision(focus, event, policyFlags, wonadDecision)) {
            return KEY_INTERCEPT_RESULT_CONSUMED;
        }

        // TODO(b/358569822) Remove below once we have nicer API for listening to shortcuts
''', "generic guard placement")

    source = replace_once(source, '''        if (mInterceptStages.get(INTERCEPT_STAGE_SHORTCUTS_BEFORE_KEY_CAPTURE).interceptKey(focus,
                event)) {
            return KEY_INTERCEPT_RESULT_CONSUMED;
        }

        if (org.wonad.server.input.WonadInputBridge.consumeClaimedInput(
                mContext, mWindowManagerInternal, event, policyFlags)) {
            return KEY_INTERCEPT_RESULT_CONSUMED;
        }
''', '''        if (mInterceptStages.get(INTERCEPT_STAGE_SHORTCUTS_BEFORE_KEY_CAPTURE).interceptKey(
                focus, event, wonadDecision)) {
            return KEY_INTERCEPT_RESULT_CONSUMED;
        }
''', "before-stage decision wiring")

    source = replace_once(source, '''        if (mInterceptStages.get(INTERCEPT_STAGE_SHORTCUTS_AFTER_KEY_CAPTURE).interceptKey(focus,
                event)) {
''', '''        if (mInterceptStages.get(INTERCEPT_STAGE_SHORTCUTS_AFTER_KEY_CAPTURE).interceptKey(
                focus, event, wonadDecision)) {
''', "after-stage decision wiring")

    marker = '''    private long interceptMultiKeyCombination(@NonNull KeyEvent event) {
'''
    helpers = '''    private static int wonadPolicyRole(int keyCode) {
        return switch (keyCode) {
            case KeyEvent.KEYCODE_APP_SWITCH ->
                    org.wonad.server.input.WonadPolicyKeyAdapter.ROLE_APP_SWITCH;
            case KeyEvent.KEYCODE_META_LEFT, KeyEvent.KEYCODE_META_RIGHT ->
                    org.wonad.server.input.WonadPolicyKeyAdapter.ROLE_META;
            case KeyEvent.KEYCODE_ALT_LEFT, KeyEvent.KEYCODE_ALT_RIGHT ->
                    org.wonad.server.input.WonadPolicyKeyAdapter.ROLE_ALT;
            case KeyEvent.KEYCODE_TAB ->
                    org.wonad.server.input.WonadPolicyKeyAdapter.ROLE_TAB;
            case KeyEvent.KEYCODE_ESCAPE ->
                    org.wonad.server.input.WonadPolicyKeyAdapter.ROLE_ESCAPE;
            default -> org.wonad.server.input.WonadPolicyKeyAdapter.ROLE_ORDINARY;
        };
    }

    private static Throwable appendWonadPolicyFailure(@Nullable Throwable first,
            @NonNull Throwable next) {
        if (first == null) return next;
        if (first != next) first.addSuppressed(next);
        return first;
    }

    private static void rethrowWonadPolicyFailure(@Nullable Throwable failure) {
        if (failure instanceof RuntimeException runtime) throw runtime;
        if (failure instanceof Error fatal) throw fatal;
        if (failure != null) {
            throw new IllegalStateException("Wonad policy cleanup failed", failure);
        }
    }

    /** Exact mirror/Boolean bookkeeping only. This method has no Binder, KGC,
     * Handler or framework-state call and is the sole work permitted from an
     * owner-install callback while the Kotlin lifecycle monitor is held. */
    private void applyWonadPolicyMirrorCleanup(
            @NonNull org.wonad.server.input.WonadPolicyKeyAdapter.Decision decision) {
        clearWonadMetaOwner(decision.clearMeta);
        clearWonadCapsOwner(decision.clearCaps);
        clearWonadAltTabOwner(decision.finishAltTab);
    }

    /** Restore mirrors after a monitored owner-install callback failed. The
     * pure helper has already restored displaced owners before invoking this
     * callback; no stock action was delivered. */
    private void rollbackWonadLocalInstall(
            @NonNull org.wonad.server.input.WonadPolicyKeyAdapter.Decision cleanup,
            @NonNull org.wonad.server.input.WonadPolicyKeyAdapter.Decision rollback) {
        applyWonadPolicyMirrorCleanup(rollback);
        if (cleanup.clearMeta != null
                && mWonadPendingMetaOwner.compareAndSet(null, cleanup.clearMeta)) {
            mPendingMetaAction = true;
        }
        if (cleanup.clearCaps != null
                && mWonadPendingCapsOwner.compareAndSet(null, cleanup.clearCaps)) {
            mPendingCapsLockToggle = true;
        }
        if (cleanup.finishAltTab != null
                && mWonadPendingAltTabOwner.compareAndSet(null, cleanup.finishAltTab)) {
            mPendingHideRecentSwitcher = true;
        }
    }

    private void rollbackWonadOwnerInstall(
            @NonNull org.wonad.server.input.WonadPolicyKeyAdapter.OwnerInstall install) {
        rollbackWonadLocalInstall(install.cleanup, install.rollback);
    }

    private void rollbackWonadEscapeInstall(
            @NonNull org.wonad.server.input.WonadPolicyKeyAdapter.EscapeInstall install) {
        // Escape publishes neither a Java mirror nor a stock action before a
        // successful enqueue, so helper restoration is sufficient.
    }

    private boolean clearWonadMetaOwner(@Nullable Object expected) {
        if (expected == null || !mWonadPendingMetaOwner.compareAndSet(expected, null)) {
            return false;
        }
        mPendingMetaAction = false;
        return true;
    }

    private boolean clearWonadCapsOwner(@Nullable Object expected) {
        if (expected == null || !mWonadPendingCapsOwner.compareAndSet(expected, null)) {
            return false;
        }
        mPendingCapsLockToggle = false;
        return true;
    }

    private boolean clearWonadAltTabOwner(@Nullable Object expected) {
        if (expected == null || !mWonadPendingAltTabOwner.compareAndSet(expected, null)) {
            return false;
        }
        mPendingHideRecentSwitcher = false;
        return true;
    }

    private void cancelWonadEscape(@NonNull Object pending) {
        final org.wonad.server.input.WonadPolicyKeyAdapter.OwnerEvent owner =
                org.wonad.server.input.WonadPolicyKeyAdapter.ownerEvent(pending);
        mHandler.removeMessages(MSG_EXIT_FOCUSED_APP, owner.completion);
        if (!owner.claimed) {
            handleKeyGesture(owner.device, new int[]{KeyEvent.KEYCODE_ESCAPE},
                    /* modifierState = */ 0,
                    KeyGestureEvent.KEY_GESTURE_TYPE_QUIT_FOCUSED_TASK,
                    KeyGestureEvent.ACTION_GESTURE_COMPLETE, owner.display,
                    (IBinder) owner.focus, KeyGestureEvent.FLAG_CANCELLED,
                    /* appLaunchData = */ null);
        }
    }

    private void dispatchWonadEscapeCancel(@NonNull Object owner) {
        synchronized (mWonadPolicyActionLock) {
            if (org.wonad.server.input.WonadPolicyKeyAdapter
                    .takeQueuedTerminal(owner, true) == 2) {
                cancelWonadEscape(owner);
            }
        }
    }

    /** Run action-side cleanup after helper release under the action lock.
     * WMS lifecycle uses the sole KGC Handler to reach this method; input-side
     * displacement and failure compensation call it synchronously. Normal
     * cleanup cancels only after START succeeded. force=true compensates a
     * throwing callback whose partial START may already have escaped. */
    private void applyWonadPolicyActionCleanup(
            @NonNull org.wonad.server.input.WonadPolicyKeyAdapter.Decision decision,
            boolean force) {
        synchronized (mWonadPolicyActionLock) {
        Throwable failure = null;
        try {
            if (decision.finishAltTab != null && (force || org.wonad.server.input
                    .WonadPolicyKeyAdapter.takeQueuedTerminal(
                            decision.finishAltTab, true) == 2)) {
                dispatchWonadAltTabGesture(decision.finishAltTab,
                        KeyGestureEvent.ACTION_GESTURE_COMPLETE,
                        KeyGestureEvent.FLAG_CANCELLED);
            }
        } catch (Throwable error) {
            failure = appendWonadPolicyFailure(failure, error);
        }
        try {
            if (decision.cancelRecent != null && (force || org.wonad.server.input
                    .WonadPolicyKeyAdapter.takeQueuedTerminal(
                            decision.cancelRecent, true) == 2)) {
                final org.wonad.server.input.WonadPolicyKeyAdapter.OwnerEvent owner =
                        org.wonad.server.input.WonadPolicyKeyAdapter.ownerEvent(
                                decision.cancelRecent);
                final Object dispatch =
                        org.wonad.server.input.WonadPolicyKeyAdapter.beginRecentDispatch(
                                decision.cancelRecent,
                                org.wonad.server.input.WonadPolicyKeyAdapter.DISPATCH_CANCEL);
                try {
                    handleKeyGesture(owner.device, new int[]{KeyEvent.KEYCODE_APP_SWITCH},
                            /* modifierState = */ 0,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH,
                            KeyGestureEvent.ACTION_GESTURE_COMPLETE, owner.display,
                            (IBinder) owner.focus, KeyGestureEvent.FLAG_CANCELLED,
                            /* appLaunchData = */ null);
                } finally {
                    org.wonad.server.input.WonadPolicyKeyAdapter.endRecentDispatch(dispatch);
                }
            }
        } catch (Throwable error) {
            failure = appendWonadPolicyFailure(failure, error);
        }
        for (Object pending : decision.cancelEscapes) {
            try {
                if (force || org.wonad.server.input.WonadPolicyKeyAdapter
                        .takeQueuedTerminal(pending, true) == 2) {
                    cancelWonadEscape(pending);
                }
            } catch (Throwable error) {
                failure = appendWonadPolicyFailure(failure, error);
            }
        }
        rethrowWonadPolicyFailure(failure);
        }
    }

    private void applyWonadPolicyCleanup(
            @NonNull org.wonad.server.input.WonadPolicyKeyAdapter.Decision decision) {
        applyWonadPolicyMirrorCleanup(decision);
        applyWonadPolicyActionCleanup(decision, false);
    }

    private void requireWonadHandlerPost(@NonNull Runnable action) {
        if (!mHandler.post(action)) {
            throw new IllegalStateException("KGC handler rejected Wonad owner operation");
        }
    }

    /** Execute a stock START synchronously after monitored install returns.
     * Exact admission briefly re-enters the lifecycle monitor under the Java
     * action lock, then releases it before stock endpoint work. */
    private void runWonadQueuedStart(@NonNull Object owner,
            @NonNull org.wonad.server.input.WonadPolicyKeyAdapter.Decision displaced,
            @NonNull BooleanSupplier action) {
        synchronized (mWonadPolicyActionLock) {
        Throwable failure = null;
        boolean admitted = false;
        try {
            applyWonadPolicyActionCleanup(displaced, false);
        } catch (Throwable error) {
            failure = error;
        }
        if (failure == null) {
            admitted = org.wonad.server.input.WonadPolicyKeyAdapter
                    .commitQueuedStart(mContext, mWindowManagerInternal, owner);
            if (!admitted) {
                final org.wonad.server.input.WonadPolicyKeyAdapter.Decision rollback =
                        org.wonad.server.input.WonadPolicyKeyAdapter.queuedStartFailed(owner);
                applyWonadPolicyMirrorCleanup(rollback);
                return;
            }
        }
        if (failure == null) {
            try {
                if (!action.getAsBoolean()) {
                    final org.wonad.server.input.WonadPolicyKeyAdapter.Decision rollback =
                            org.wonad.server.input.WonadPolicyKeyAdapter
                                    .queuedStartFailed(owner);
                    applyWonadPolicyMirrorCleanup(rollback);
                    applyWonadPolicyActionCleanup(rollback, false);
                    return;
                }
                org.wonad.server.input.WonadPolicyKeyAdapter.queuedStartSucceeded(owner);
                return;
            } catch (Throwable error) {
                failure = error;
            }
        }
        final org.wonad.server.input.WonadPolicyKeyAdapter.Decision rollback =
                org.wonad.server.input.WonadPolicyKeyAdapter.queuedStartFailed(owner);
        try {
            applyWonadPolicyMirrorCleanup(rollback);
            applyWonadPolicyActionCleanup(rollback, admitted);
        } catch (Throwable cleanupFailure) {
            failure = appendWonadPolicyFailure(failure, cleanupFailure);
        }
        rethrowWonadPolicyFailure(failure);
        }
    }

    private void dispatchWonadRecentTerminal(@NonNull Object owner,
            boolean requestedCancel) {
        synchronized (mWonadPolicyActionLock) {
        final int terminal = org.wonad.server.input.WonadPolicyKeyAdapter
                .takeQueuedTerminal(owner, requestedCancel);
        if (terminal == 0) return;
        final boolean cancel = terminal == 2;
        final org.wonad.server.input.WonadPolicyKeyAdapter.OwnerEvent original =
                org.wonad.server.input.WonadPolicyKeyAdapter.ownerEvent(owner);
        final Object dispatch = org.wonad.server.input.WonadPolicyKeyAdapter
                .beginRecentDispatch(owner, cancel
                        ? org.wonad.server.input.WonadPolicyKeyAdapter.DISPATCH_CANCEL
                        : org.wonad.server.input.WonadPolicyKeyAdapter.DISPATCH_COMPLETE);
        try {
            handleKeyGesture(original.device,
                    new int[]{KeyEvent.KEYCODE_APP_SWITCH}, /* modifierState = */0,
                    KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH,
                    KeyGestureEvent.ACTION_GESTURE_COMPLETE, original.display,
                    (IBinder) original.focus,
                    cancel ? KeyGestureEvent.FLAG_CANCELLED : 0,
                    /* appLaunchData = */null);
        } finally {
            org.wonad.server.input.WonadPolicyKeyAdapter.endRecentDispatch(dispatch);
        }
        }
    }

    private void dispatchWonadAltTabTerminal(@NonNull Object owner,
            boolean requestedCancel) {
        synchronized (mWonadPolicyActionLock) {
        final int terminal = org.wonad.server.input.WonadPolicyKeyAdapter
                .takeQueuedTerminal(owner, requestedCancel);
        if (terminal == 0) return;
        dispatchWonadAltTabGesture(owner, KeyGestureEvent.ACTION_GESTURE_COMPLETE,
                terminal == 2 ? KeyGestureEvent.FLAG_CANCELLED : 0);
        }
    }

    /** Bind each synchronous PWM Alt-Tab endpoint mutation to its exact
     * physical-pair owner. A late cleanup can therefore never hide a newer
     * replacement or an unrelated stock/phone switcher. */
    private void dispatchWonadAltTabGesture(@NonNull Object owner, int action,
            int flags) {
        final org.wonad.server.input.WonadPolicyKeyAdapter.OwnerEvent original =
                org.wonad.server.input.WonadPolicyKeyAdapter.ownerEvent(owner);
        final int mode = action == KeyGestureEvent.ACTION_GESTURE_START
                ? org.wonad.server.input.WonadPolicyKeyAdapter.DISPATCH_START
                : flags != 0
                        ? org.wonad.server.input.WonadPolicyKeyAdapter.DISPATCH_CANCEL
                        : org.wonad.server.input.WonadPolicyKeyAdapter.DISPATCH_COMPLETE;
        final Object dispatch = org.wonad.server.input.WonadPolicyKeyAdapter
                .beginRecentDispatch(owner, mode);
        try {
            handleKeyGesture(original.device, new int[]{KeyEvent.KEYCODE_TAB},
                    KeyEvent.META_ALT_ON,
                    KeyGestureEvent.KEY_GESTURE_TYPE_RECENT_APPS_SWITCHER,
                    action, original.display, (IBinder) original.focus, flags,
                    /* appLaunchData = */null);
        } finally {
            org.wonad.server.input.WonadPolicyKeyAdapter.endRecentDispatch(dispatch);
        }
    }

    private boolean applyWonadPolicyDecision(@Nullable IBinder focusedToken,
            @NonNull KeyEvent event, int policyFlags,
            @NonNull org.wonad.server.input.WonadPolicyKeyAdapter.Decision decision) {
        applyWonadPolicyCleanup(decision);
        final boolean consumed = org.wonad.server.input.WonadPolicyKeyAdapter.consume(
                mWindowManagerInternal, event, policyFlags, decision);
        if (decision.saturated
                && (event.getAction() == KeyEvent.ACTION_UP || event.isCanceled())) {
            reconcileWonadPolicyDevices();
        }
        return consumed;
    }

    /** Release fail-black saturation only after an exact native physical census. */
    private void reconcileWonadPolicyDevices() {
        final InputManager input = mWonadInputManager;
        final NativeInputManagerService nativeInput = mWonadNativeInput;
        if (input == null || nativeInput == null) return;
        final long expectedEpoch =
                org.wonad.server.input.WonadPolicyKeyAdapter.mutationEpoch();
        boolean allKeysReleased = true;
        for (int keyCode = KeyEvent.KEYCODE_UNKNOWN;
                keyCode <= KeyEvent.getMaxKeyCode(); keyCode++) {
            final int state = nativeInput.getKeyCodeState(
                    /* deviceId = */ -1, InputDevice.SOURCE_ANY, keyCode);
            if (state == InputManagerService.KEY_STATE_DOWN
                    || state == InputManagerService.KEY_STATE_VIRTUAL
                    || (state != InputManagerService.KEY_STATE_UP
                            && state != InputManagerService.KEY_STATE_UNKNOWN)) {
                allKeysReleased = false;
                break;
            }
        }
        final org.wonad.server.input.WonadPolicyKeyAdapter.Decision decision =
                org.wonad.server.input.WonadPolicyKeyAdapter.reconcileDevices(
                        input.getInputDeviceIds(), allKeysReleased, expectedEpoch);
        applyWonadPolicyCleanup(decision);
    }

'''
    source = replace_once(source, marker, helpers + marker, "policy helper insertion")

    source = replace_count(source,
        '''protected boolean onKeyEvent(@Nullable IBinder focus, @NonNull KeyEvent event) {''',
        '''protected boolean onKeyEvent(@Nullable IBinder focus, @NonNull KeyEvent event,
                        @Nullable org.wonad.server.input.WonadPolicyKeyAdapter.Decision decision) {''',
        3, "stage override signatures")
    source = source.replace("interceptShortcutsBeforeKeyCapture(focus, event);",
        "interceptShortcutsBeforeKeyCapture(focus, event, decision);")
    source = source.replace("interceptShortcutsAfterKeyCapture(focus, event);",
        "interceptShortcutsAfterKeyCapture(focus, event, decision);")
    source = source.replace("interceptUnhandledShortcuts(focus, event);",
        "interceptUnhandledShortcuts(focus, event, decision);")

    source = replace_once(source, '''    private boolean interceptShortcutsBeforeKeyCapture(@Nullable IBinder focusedToken,
            @NonNull KeyEvent event) {
''', '''    private boolean interceptShortcutsBeforeKeyCapture(@Nullable IBinder focusedToken,
            @NonNull KeyEvent event,
            @Nullable org.wonad.server.input.WonadPolicyKeyAdapter.Decision wonadDecision) {
''', "before-stage signature")
    source = replace_once(source, '''    private boolean interceptShortcutsAfterKeyCapture(@Nullable IBinder focusedToken,
            @NonNull KeyEvent event) {
''', '''    private boolean interceptShortcutsAfterKeyCapture(@Nullable IBinder focusedToken,
            @NonNull KeyEvent event,
            @Nullable org.wonad.server.input.WonadPolicyKeyAdapter.Decision wonadDecision) {
''', "after-stage signature")
    source = replace_once(source,
        '''    private boolean interceptUnhandledShortcuts(IBinder focusedToken, KeyEvent event) {''',
        '''    private boolean interceptUnhandledShortcuts(IBinder focusedToken, KeyEvent event,
            @Nullable org.wonad.server.input.WonadPolicyKeyAdapter.Decision wonadDecision) {''',
        "unhandled signature")

    source = replace_once(source, '''            case KeyEvent.KEYCODE_APP_SWITCH:
                if (firstDown && !hasModifiers) {
                    handleKeyGesture(deviceId, new int[]{keyCode}, /* modifierState = */0,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH,
                            KeyGestureEvent.ACTION_GESTURE_START, displayId,
                            focusedToken, /* flags = */0, /* appLaunchData = */null);
                    return true;
                } else if (!down && !hasModifiers) {
                    handleKeyGesture(deviceId, new int[]{keyCode}, /* modifierState = */0,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH,
                            KeyGestureEvent.ACTION_GESTURE_COMPLETE, displayId,
                            focusedToken, canceled ? KeyGestureEvent.FLAG_CANCELLED : 0,
                            /* appLaunchData = */null);
                    return true;
                }
                break;
''', '''            case KeyEvent.KEYCODE_APP_SWITCH:
                if (firstDown && !hasModifiers && wonadDecision != null
                        && wonadDecision.pair != null) {
                    final org.wonad.server.input.WonadPolicyKeyAdapter.OwnerInstall install =
                            org.wonad.server.input.WonadPolicyKeyAdapter.installRecent(
                            mContext, mWindowManagerInternal, wonadDecision.pair, focusedToken,
                            candidate -> applyWonadPolicyMirrorCleanup(candidate.cleanup),
                            this::rollbackWonadOwnerInstall);
                    if (install != null && install.install) {
                        runWonadQueuedStart(install.owner, install.cleanup, () -> {
                            final Object dispatch = org.wonad.server.input
                                    .WonadPolicyKeyAdapter.beginRecentDispatch(
                                            install.owner,
                                            org.wonad.server.input.WonadPolicyKeyAdapter
                                                    .DISPATCH_START);
                            try {
                                handleKeyGesture(deviceId, new int[]{keyCode},
                                        /* modifierState = */0,
                                        KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH,
                                        KeyGestureEvent.ACTION_GESTURE_START,
                                        displayId, focusedToken, /* flags = */0,
                                        /* appLaunchData = */null);
                                return org.wonad.server.input.WonadPolicyKeyAdapter
                                        .recentEndpointApplied(dispatch);
                            } finally {
                                org.wonad.server.input.WonadPolicyKeyAdapter
                                        .endRecentDispatch(dispatch);
                            }
                        });
                    }
                    // A lifecycle transition which wins installation is still
                    // fail-closed; no stock START is sent.
                    return true;
                } else if (!down && !hasModifiers && wonadDecision != null
                        && wonadDecision.pair != null) {
                    final Object owner =
                            org.wonad.server.input.WonadPolicyKeyAdapter.completeRecent(
                                    wonadDecision.pair);
                    if (owner == null) break;
                    final Runnable terminal = () -> dispatchWonadRecentTerminal(owner, canceled);
                    terminal.run();
                    return true;
                }
                break;
''', "exact APP_SWITCH owner wiring")

    source = replace_once(source, '''            case KeyEvent.KEYCODE_ESCAPE:
                // TODO(b/358569822): Currently implemented long press using handler and delayed
                //  message here, instead of using SingleKeyGestureDetector because that detection
                //  logic doesn't have access to focused token. Refactor this so that we don't
                //  have this custom logic to detect long press.
                if (firstDown && canFocusedWindowCaptureKeys(focusedToken)) {
                    // Toast to quit application is shown on key down for ESCAPE key, when the
                    // focused window is capturing keys.
                    Toast.makeText(mContext, UiThread.get().getLooper(),
                            mContext.getString(R.string.exit_toast_on_long_press_escape),
                            Toast.LENGTH_SHORT).show();
                    handleKeyGesture(event.getDeviceId(), new int[]{KeyEvent.KEYCODE_ESCAPE},
                            metaState, KeyGestureEvent.KEY_GESTURE_TYPE_QUIT_FOCUSED_TASK,
                            KeyGestureEvent.ACTION_GESTURE_START,
                            displayId, focusedToken, /* flags= */0, /* appLaunchData= */ null);
                    AidlKeyGestureEvent eventToSend = createKeyGestureEvent(event.getDeviceId(),
                            new int[]{KeyEvent.KEYCODE_ESCAPE},
                            metaState, KeyGestureEvent.KEY_GESTURE_TYPE_QUIT_FOCUSED_TASK,
                            KeyGestureEvent.ACTION_GESTURE_COMPLETE,
                            displayId, /* flags= */0, /* appLaunchData= */ null);
                    Message msg = Message.obtain(mHandler, MSG_EXIT_FOCUSED_APP, eventToSend);
                    mHandler.sendMessageDelayed(msg, LONG_PRESS_DURATION_FOR_EXIT_APP_MS);
                } else if (!down) {
                    if (mHandler.hasMessages(MSG_EXIT_FOCUSED_APP)) {
                        mHandler.removeMessages(MSG_EXIT_FOCUSED_APP);
                        handleKeyGesture(event.getDeviceId(), new int[]{KeyEvent.KEYCODE_ESCAPE},
                                metaState, KeyGestureEvent.KEY_GESTURE_TYPE_QUIT_FOCUSED_TASK,
                                KeyGestureEvent.ACTION_GESTURE_COMPLETE, displayId, focusedToken,
                                KeyGestureEvent.FLAG_CANCELLED, /* appLaunchData= */ null);
                    }
                }
                break;
''', '''            case KeyEvent.KEYCODE_ESCAPE:
                // Claimed-display Escape never reaches Shell's global-focus
                // QUIT endpoint. Its original input token resolves to an
                // opaque exact WMS target before owner publication.
                if (firstDown && canFocusedWindowCaptureKeys(focusedToken)
                        && wonadDecision != null && wonadDecision.pair != null) {
                    final AidlKeyGestureEvent eventToSend = createKeyGestureEvent(
                            event.getDeviceId(), new int[]{KeyEvent.KEYCODE_ESCAPE}, metaState,
                            KeyGestureEvent.KEY_GESTURE_TYPE_QUIT_FOCUSED_TASK,
                            KeyGestureEvent.ACTION_GESTURE_COMPLETE, displayId,
                            /* flags= */0, /* appLaunchData= */ null);
                    final Object retainedClaim = org.wonad.server.input
                            .WonadPolicyKeyAdapter.retainedClaim(wonadDecision.pair);
                    final Object exactTarget = retainedClaim == null ? null :
                            mWindowManagerInternal.captureWonadClaimedEscapeTarget(
                                    focusedToken, displayId, retainedClaim);
                    if (retainedClaim != null && exactTarget == null) break;
                    final org.wonad.server.input.WonadPolicyKeyAdapter.EscapeInstall install =
                            org.wonad.server.input.WonadPolicyKeyAdapter.installEscape(
                            mContext, mWindowManagerInternal, wonadDecision.pair, focusedToken,
                            eventToSend, exactTarget, candidate -> {},
                            this::rollbackWonadEscapeInstall);
                    if (install != null && install.install) {
                        runWonadQueuedStart(install.owner, install.cleanup, () -> {
                            if (!org.wonad.server.input.WonadPolicyKeyAdapter
                                    .ownerIsClaimed(install.owner)) {
                                handleKeyGesture(event.getDeviceId(),
                                        new int[]{KeyEvent.KEYCODE_ESCAPE}, metaState,
                                        KeyGestureEvent.KEY_GESTURE_TYPE_QUIT_FOCUSED_TASK,
                                        KeyGestureEvent.ACTION_GESTURE_START, displayId,
                                        focusedToken, /* flags= */0,
                                        /* appLaunchData= */ null);
                            }
                            final Message msg = Message.obtain(
                                    mHandler, MSG_EXIT_FOCUSED_APP, eventToSend);
                            if (!mHandler.sendMessageDelayed(msg,
                                    LONG_PRESS_DURATION_FOR_EXIT_APP_MS)) {
                                throw new IllegalStateException(
                                        "KGC handler rejected Escape timer");
                            }
                            return true;
                        });
                        if (org.wonad.server.input.WonadPolicyKeyAdapter
                                .queuedStartWasDelivered(install.owner)
                                && org.wonad.server.input.WonadPolicyKeyAdapter
                                        .commitEscapeDeferredEffect(mContext,
                                                mWindowManagerInternal, install.owner)) {
                            Toast.makeText(mContext, UiThread.get().getLooper(),
                                    mContext.getString(
                                            R.string.exit_toast_on_long_press_escape),
                                    Toast.LENGTH_SHORT).show();
                        }
                    }
                    break;
                } else if (!down && wonadDecision != null && wonadDecision.pair != null) {
                    final Object owner =
                            org.wonad.server.input.WonadPolicyKeyAdapter.completeEscapePair(
                                    wonadDecision.pair);
                    if (owner != null) {
                        final Runnable terminal = () -> dispatchWonadEscapeCancel(owner);
                        terminal.run();
                        break;
                    }
                }
                break;
''', "exact Escape message owner")

    # The Java booleans remain diagnostic mirrors, but every state start/end is
    # tied to the pair object supplied by the Kotlin decision.
    source = replace_once(source, '''        final boolean firstDown = down && repeatCount == 0;

        // Handle stateful shortcuts (only if key capture is not enabled)
''', '''        final boolean firstDown = down && repeatCount == 0;
        final Object wonadPair = wonadDecision != null ? wonadDecision.pair : null;

        // Handle stateful shortcuts (only if key capture is not enabled)
''', "stateful exact pair local")
    source = replace_once(source, '''                    } else {
                        mPendingCapsLockToggle = false;
                        mPendingMetaAction = true;
                    }
''', '''                    } else {
                        if (wonadPair != null) {
                            if (!org.wonad.server.input.WonadPolicyKeyAdapter.installMeta(
                                    mContext, mWindowManagerInternal, wonadPair, focusedToken,
                                    install -> {
                                        applyWonadPolicyMirrorCleanup(install.cleanup);
                                        mWonadPendingMetaOwner.set(install.owner);
                                        mPendingMetaAction = true;
                                    }, this::rollbackWonadOwnerInstall)) {
                                return true;
                            }
                        }
                    }
''', "Meta owner start")
    source = replace_once(source, '''                    if (event.isAltPressed()) {
                        mPendingCapsLockToggle = true;
                        mPendingMetaAction = false;
''', '''                    if (event.isAltPressed()) {
                        final Object altPair =
                                org.wonad.server.input.WonadPolicyKeyAdapter.activePair(
                                        deviceId,
                                        org.wonad.server.input.WonadPolicyKeyAdapter.ROLE_ALT);
                        if (wonadPair != null && altPair != null) {
                            if (!org.wonad.server.input.WonadPolicyKeyAdapter.installCaps(
                                    mContext, mWindowManagerInternal, wonadPair, altPair,
                                    focusedToken, install -> {
                                        applyWonadPolicyMirrorCleanup(install.cleanup);
                                        mWonadPendingCapsOwner.set(install.owner);
                                        mPendingCapsLockToggle = true;
                                    }, this::rollbackWonadOwnerInstall)) {
                                return true;
                            }
                        }
''', "Meta-Alt exact Caps owner start")
    source = replace_once(source, '''                    // Toggle Caps Lock on META-ALT.
                    if (mPendingCapsLockToggle) {
                        mPendingCapsLockToggle = false;
                        handleKeyGesture(deviceId, new int[]{KeyEvent.KEYCODE_META_LEFT,
                                        KeyEvent.KEYCODE_ALT_LEFT}, /* modifierState = */0,
                                KeyGestureEvent.KEY_GESTURE_TYPE_TOGGLE_CAPS_LOCK,
                                KeyGestureEvent.ACTION_GESTURE_COMPLETE, displayId,
                                focusedToken, /* flags = */0, /* appLaunchData = */null);

                    } else if (mPendingMetaAction) {
                        mPendingMetaAction = false;
                        if (!canceled) {
                            handleKeyGesture(deviceId, new int[]{keyCode},
                                    /* modifierState = */0,
                                    KeyGestureEvent.KEY_GESTURE_TYPE_ALL_APPS,
                                    KeyGestureEvent.ACTION_GESTURE_COMPLETE, displayId,
                                    focusedToken, /* flags = */0, /* appLaunchData = */null);
                        }
                    }
''', '''                    final Object capsOwner = wonadPair == null ? null :
                            org.wonad.server.input.WonadPolicyKeyAdapter.completeCaps(wonadPair);
                    if (capsOwner != null && clearWonadCapsOwner(capsOwner)) {
                        final org.wonad.server.input.WonadPolicyKeyAdapter.OwnerEvent owner =
                                org.wonad.server.input.WonadPolicyKeyAdapter.ownerEvent(capsOwner);
                        handleKeyGesture(owner.device,
                                new int[]{KeyEvent.KEYCODE_META_LEFT, KeyEvent.KEYCODE_ALT_LEFT},
                                /* modifierState = */0,
                                KeyGestureEvent.KEY_GESTURE_TYPE_TOGGLE_CAPS_LOCK,
                                KeyGestureEvent.ACTION_GESTURE_COMPLETE, owner.display,
                                (IBinder) owner.focus, /* flags = */0,
                                /* appLaunchData = */null);
                    } else {
                        final Object metaOwner = wonadPair == null ? null :
                                org.wonad.server.input.WonadPolicyKeyAdapter.completeMeta(
                                        wonadPair);
                        if (metaOwner != null && clearWonadMetaOwner(metaOwner)) {
                            if (!canceled) {
                                final org.wonad.server.input.WonadPolicyKeyAdapter.OwnerEvent owner =
                                        org.wonad.server.input.WonadPolicyKeyAdapter.ownerEvent(
                                                metaOwner);
                                handleKeyGesture(owner.device, new int[]{owner.keyCode},
                                        /* modifierState = */0,
                                        KeyGestureEvent.KEY_GESTURE_TYPE_ALL_APPS,
                                        KeyGestureEvent.ACTION_GESTURE_COMPLETE, owner.display,
                                        (IBinder) owner.focus, /* flags = */0,
                                        /* appLaunchData = */null);
                            }
                        }
                    }
''', "Meta and Caps exact completion")
    source = replace_once(source, '''                    if (mPendingHideRecentSwitcher) {
                        mPendingHideRecentSwitcher = false;
                        handleKeyGesture(deviceId, new int[]{KeyEvent.KEYCODE_TAB},
                                KeyEvent.META_ALT_ON,
                                KeyGestureEvent.KEY_GESTURE_TYPE_RECENT_APPS_SWITCHER,
                                KeyGestureEvent.ACTION_GESTURE_COMPLETE, displayId,
                                focusedToken, /* flags = */0, /* appLaunchData = */null);
                        return true;
                    }
''', '''                    final Object altTabOwner = wonadPair == null ? null :
                            org.wonad.server.input.WonadPolicyKeyAdapter.completeAltTab(wonadPair);
                    if (altTabOwner != null && clearWonadAltTabOwner(altTabOwner)) {
                        final Runnable terminal =
                                () -> dispatchWonadAltTabTerminal(altTabOwner, false);
                        terminal.run();
                        return true;
                    }
''', "Alt-Tab exact completion")
    source = replace_once(source, '''                            mPendingHideRecentSwitcher = true;
                            handleKeyGesture(deviceId, new int[]{keyCode},
                                    KeyEvent.META_ALT_ON,
                                    KeyGestureEvent.KEY_GESTURE_TYPE_RECENT_APPS_SWITCHER,
                                    KeyGestureEvent.ACTION_GESTURE_START, displayId,
                                    focusedToken, /* flags = */0, /* appLaunchData = */null);
                            return true;
''', '''                            if (wonadPair != null) {
                                final org.wonad.server.input.WonadPolicyKeyAdapter.OwnerInstall
                                        install = org.wonad.server.input.WonadPolicyKeyAdapter
                                                .installAltTab(
                                        mContext, mWindowManagerInternal, wonadPair, focusedToken,
                                        candidate -> {
                                            applyWonadPolicyMirrorCleanup(candidate.cleanup);
                                            mWonadPendingAltTabOwner.set(candidate.owner);
                                            mPendingHideRecentSwitcher = true;
                                        }, this::rollbackWonadOwnerInstall);
                                if (install != null && install.install) {
                                    runWonadQueuedStart(install.owner, install.cleanup,
                                            () -> {
                                                final Object dispatch = org.wonad.server.input
                                                        .WonadPolicyKeyAdapter
                                                        .beginRecentDispatch(install.owner,
                                                                org.wonad.server.input
                                                                        .WonadPolicyKeyAdapter
                                                                        .DISPATCH_START);
                                                try {
                                                    dispatchWonadAltTabGesture(install.owner,
                                                            KeyGestureEvent
                                                                    .ACTION_GESTURE_START,
                                                            /* flags = */0);
                                                    return org.wonad.server.input
                                                            .WonadPolicyKeyAdapter
                                                            .recentEndpointApplied(dispatch);
                                                } finally {
                                                    org.wonad.server.input
                                                            .WonadPolicyKeyAdapter
                                                            .endRecentDispatch(dispatch);
                                                }
                                            });
                                }
                                return true;
                            }
''', "Alt-Tab exact start")
    source = replace_once(source, '''                    if (!mPendingHideRecentSwitcher) {''',
        '''                    if (wonadPair != null) {''',
        "Alt-Tab transactional owner admission")
    source = replace_once(source, '''                    if (event.isMetaPressed()) {
                        mPendingCapsLockToggle = true;
                        mPendingMetaAction = false;
                    } else {
                        mPendingCapsLockToggle = false;
                    }
''', '''                    if (event.isMetaPressed()) {
                        final Object metaPair =
                                org.wonad.server.input.WonadPolicyKeyAdapter.activePair(
                                        deviceId,
                                        org.wonad.server.input.WonadPolicyKeyAdapter.ROLE_META);
                        if (wonadPair != null && metaPair != null) {
                            if (!org.wonad.server.input.WonadPolicyKeyAdapter.installCaps(
                                    mContext, mWindowManagerInternal, metaPair, wonadPair,
                                    focusedToken, install -> {
                                        applyWonadPolicyMirrorCleanup(install.cleanup);
                                        mWonadPendingCapsOwner.set(install.owner);
                                        mPendingCapsLockToggle = true;
                                    }, this::rollbackWonadOwnerInstall)) {
                                return true;
                            }
                        }
                    } else {
                        if (wonadPair != null) {
                            clearWonadCapsOwner(org.wonad.server.input.WonadPolicyKeyAdapter
                                    .clearCapsForAllowedPair(mContext, mWindowManagerInternal,
                                            wonadPair));
                        }
                    }
''', "Alt-Meta exact Caps owner start")
    source = replace_once(source, '''                    // Toggle Caps Lock on META-ALT.
                    if (mPendingCapsLockToggle) {
                        mPendingCapsLockToggle = false;
                        handleKeyGesture(deviceId, new int[]{KeyEvent.KEYCODE_META_LEFT,
                                        KeyEvent.KEYCODE_ALT_LEFT}, /* modifierState = */0,
                                KeyGestureEvent.KEY_GESTURE_TYPE_TOGGLE_CAPS_LOCK,
                                KeyGestureEvent.ACTION_GESTURE_COMPLETE, displayId,
                                focusedToken, /* flags = */0, /* appLaunchData = */null);
                        return true;
                    }
''', '''                    final Object capsOwner = wonadPair == null ? null :
                            org.wonad.server.input.WonadPolicyKeyAdapter.completeCaps(wonadPair);
                    if (capsOwner != null && clearWonadCapsOwner(capsOwner)) {
                        final org.wonad.server.input.WonadPolicyKeyAdapter.OwnerEvent owner =
                                org.wonad.server.input.WonadPolicyKeyAdapter.ownerEvent(capsOwner);
                        handleKeyGesture(owner.device,
                                new int[]{KeyEvent.KEYCODE_META_LEFT, KeyEvent.KEYCODE_ALT_LEFT},
                                /* modifierState = */0,
                                KeyGestureEvent.KEY_GESTURE_TYPE_TOGGLE_CAPS_LOCK,
                                KeyGestureEvent.ACTION_GESTURE_COMPLETE, owner.display,
                                (IBinder) owner.focus, /* flags = */0,
                                /* appLaunchData = */null);
                        return true;
                    }
''', "Alt exact Caps completion")

    source = replace_once(source, '''    private abstract static class InterceptKeyStage {
''', '''    private abstract static class InterceptKeyStage {
''', "stage class anchor")

    source = replace_once(source, '''            case MSG_EXIT_FOCUSED_APP:
                handleKeyGesture((AidlKeyGestureEvent) msg.obj, /* focusedToken= */null);
                break;
''', '''            case MSG_EXIT_FOCUSED_APP:
                synchronized (mWonadPolicyActionLock) {
                final org.wonad.server.input.WonadPolicyKeyAdapter.OwnerEvent pending =
                        org.wonad.server.input.WonadPolicyKeyAdapter.takeEscapeForDispatch(
                                mContext, mWindowManagerInternal, msg.obj);
                if (pending != null) {
                    if (pending.claimed) {
                        mWindowManagerInternal.closeWonadClaimedEscapeTarget(
                                pending.exactTarget);
                    } else {
                        handleKeyGesture((AidlKeyGestureEvent) msg.obj,
                                (IBinder) pending.focus);
                    }
                }
                }
                break;
''', "exact Escape handler completion")
    source = replace_once(source, '''        private boolean interceptKey(@Nullable IBinder focusedToken, @NonNull KeyEvent event) {
''', '''        private boolean interceptKey(@Nullable IBinder focusedToken, @NonNull KeyEvent event,
                @Nullable org.wonad.server.input.WonadPolicyKeyAdapter.Decision decision) {
''', "stage intercept signature")
    source = replace_once(source,
        '''            if (onKeyEvent(focusedToken, event) && event.getAction() == KeyEvent.ACTION_DOWN''',
        '''            if (onKeyEvent(focusedToken, event, decision)
                    && event.getAction() == KeyEvent.ACTION_DOWN''',
        "stage invocation")
    source = replace_once(source, '''        protected abstract boolean onKeyEvent(@Nullable IBinder focusedToken,
                @NonNull KeyEvent event);
''', '''        protected abstract boolean onKeyEvent(@Nullable IBinder focusedToken,
                @NonNull KeyEvent event,
                @Nullable org.wonad.server.input.WonadPolicyKeyAdapter.Decision decision);
''', "stage abstract signature")

    source = replace_once(source, '''        /** Currently fully consumed key codes per device */
        private final SparseArray<Set<Integer>> mConsumedKeysForDevice = new SparseArray<>();

        private boolean interceptKey(@Nullable IBinder focusedToken, @NonNull KeyEvent event,
                @Nullable org.wonad.server.input.WonadPolicyKeyAdapter.Decision decision) {
            final int deviceId = event.getDeviceId();
            final int keyCode = event.getKeyCode();
            Set<Integer> consumedKeys = mConsumedKeysForDevice.get(deviceId);
            if (consumedKeys == null) {
                consumedKeys = new HashSet<>();
                mConsumedKeysForDevice.put(deviceId, consumedKeys);
            }

            if (onKeyEvent(focusedToken, event, decision)
                    && event.getAction() == KeyEvent.ACTION_DOWN
                    && event.getRepeatCount() == 0) {
                consumedKeys.add(keyCode);
                return true;
            }

            boolean needToConsumeKey = consumedKeys.contains(keyCode);
            if (event.getAction() == KeyEvent.ACTION_UP || event.isCanceled()) {
                consumedKeys.remove(keyCode);
                if (consumedKeys.isEmpty()) {
                    mConsumedKeysForDevice.remove(deviceId);
                }
            }
            return needToConsumeKey;
        }
''', '''        /** Exact fully-consumed physical key pairs per device. */
        private final SparseArray<Map<Integer, Long>> mConsumedKeysForDevice =
                new SparseArray<>();

        private boolean interceptKey(@Nullable IBinder focusedToken, @NonNull KeyEvent event,
                @Nullable org.wonad.server.input.WonadPolicyKeyAdapter.Decision decision) {
            final int deviceId = event.getDeviceId();
            final int keyCode = event.getKeyCode();
            final long downTime = event.getDownTime();
            Map<Integer, Long> consumedKeys = mConsumedKeysForDevice.get(deviceId);
            if (consumedKeys == null) {
                consumedKeys = new HashMap<>();
                mConsumedKeysForDevice.put(deviceId, consumedKeys);
            }

            // A fresh repeat-zero DOWN retires a lost-UP stage record.  A late
            // old UP can neither consume nor remove the replacement record.
            final Long oldDownTime = consumedKeys.get(keyCode);
            if (event.getAction() == KeyEvent.ACTION_DOWN && event.getRepeatCount() == 0
                    && oldDownTime != null && oldDownTime.longValue() != downTime) {
                consumedKeys.remove(keyCode);
            }
            if (onKeyEvent(focusedToken, event, decision)
                    && event.getAction() == KeyEvent.ACTION_DOWN
                    && event.getRepeatCount() == 0) {
                consumedKeys.put(keyCode, downTime);
                return true;
            }

            final Long retainedDownTime = consumedKeys.get(keyCode);
            final boolean needToConsumeKey = retainedDownTime != null
                    && retainedDownTime.longValue() == downTime;
            if ((event.getAction() == KeyEvent.ACTION_UP || event.isCanceled())
                    && needToConsumeKey) {
                consumedKeys.remove(keyCode);
            }
            if (consumedKeys.isEmpty()) {
                mConsumedKeysForDevice.remove(deviceId);
            }
            return needToConsumeKey;
        }

        private void removeDevice(int deviceId) {
            mConsumedKeysForDevice.remove(deviceId);
        }
''', "downTime-aware stage ledger")

    # The unhandled path has its own complete observation; it does not reuse a
    # stale main-dispatch decision.
    source = replace_once(source, '''    boolean interceptUnhandledKey(@NonNull KeyEvent event, @Nullable IBinder focus) {
        // A paste chord must not become a global or custom shortcut after the app declines it.
''', '''    boolean interceptUnhandledKey(@NonNull KeyEvent event, @Nullable IBinder focus) {
        final org.wonad.server.input.WonadPolicyKeyAdapter.Decision wonadDecision =
                org.wonad.server.input.WonadPolicyKeyAdapter.beforeStock(
                        mContext, mWindowManagerInternal, event,
                        wonadPolicyRole(event.getKeyCode()));
        if (applyWonadPolicyDecision(focus, event, /* policyFlags = */ 0, wonadDecision)) {
            return true;
        }
        // A paste chord must not become a global or custom shortcut after the app declines it.
''', "unhandled fresh decision")
    source = source.replace(
        ''').interceptKey(focus, event);\n        return intercepted''',
        ''').interceptKey(focus, event, wonadDecision);\n        return intercepted''')
    return source


def phone_window_manager(source: str) -> str:
    source = replace_once(source, '''    boolean mPreloadedRecentApps;
''', '''    boolean mPreloadedRecentApps;
    // Exact Kotlin physical-pair owner, or null for stock HOME/touch/other preload.
    Object mWonadPreloadedRecentAppsOwner;
    // Exact Alt-Tab owner currently exposed by PWM. A stale completion from a
    // retired claim must not hide a replacement or ordinary phone switcher.
    Object mWonadVisibleAltTabOwner;
    // Serializes state plus one-way SystemUI delivery for every Recents
    // endpoint mutation. It never calls back into KGC/actionLock/helper.
    final Object mWonadRecentsEndpointLock = new Object();
''', "PWM owner field")
    source = replace_once(source, '''            case KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH:
                if (!keyguardOn) {
                    if (start) {
                        preloadRecentApps();
                    } else if (complete) {
                        toggleRecentApps();
                    }
                }
                break;
''', '''            case KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH:
                if (event.isCancelled()) {
                    cancelPreloadRecentApps();
                } else if (complete && keyguardOn) {
                    cancelPreloadRecentApps();
                } else if (!keyguardOn) {
                    if (start) {
                        preloadRecentApps();
                    } else if (complete) {
                        toggleRecentApps();
                    }
                }
                break;
''', "PWM exact APP_SWITCH owner")
    source = replace_once(source, '''            case KeyGestureEvent.KEY_GESTURE_TYPE_RECENT_APPS_SWITCHER:
                if (start) {
                    showRecentApps(true);
                } else {
                    hideRecentApps(true, false);
                }
                break;
''', '''            case KeyGestureEvent.KEY_GESTURE_TYPE_RECENT_APPS_SWITCHER:
                if (start) {
                    showRecentApps(true);
                } else {
                    hideRecentApps(true, false);
                }
                break;
''', "PWM exact Alt-Tab endpoint owner")
    source = replace_once(source, '''    private void preloadRecentApps() {
        mPreloadedRecentApps = true;
        StatusBarManagerInternal statusbar = getStatusBarManagerInternal();
        if (statusbar != null) {
            statusbar.preloadRecentApps();
        }
    }
''', '''    private void preloadRecentApps() {
        synchronized (mWonadRecentsEndpointLock) {
            final Object dispatch = org.wonad.server.input.WonadPolicyKeyAdapter
                    .currentRecentDispatchTicket();
            if (dispatch != null && org.wonad.server.input.WonadPolicyKeyAdapter
                    .recentDispatchClaimed(dispatch)) {
                if (!org.wonad.server.input.WonadPolicyKeyAdapter
                        .commitRecentEndpointStart(dispatch)) return;
            } else {
                org.wonad.server.input.WonadPolicyKeyAdapter
                        .supersedeRecentEndpointStart();
            }
            mWonadPreloadedRecentAppsOwner = dispatch == null ? null :
                    org.wonad.server.input.WonadPolicyKeyAdapter
                            .recentDispatchOwner(dispatch);
            mPreloadedRecentApps = true;
            StatusBarManagerInternal statusbar = getStatusBarManagerInternal();
            if (statusbar != null) {
                statusbar.preloadRecentApps();
            }
            if (dispatch != null) {
                org.wonad.server.input.WonadPolicyKeyAdapter
                        .markRecentEndpointApplied(dispatch);
            }
        }
    }
''', "PWM reserved preload")
    source = replace_once(source, '''    private void cancelPreloadRecentApps() {
        if (mPreloadedRecentApps) {
            mPreloadedRecentApps = false;
            StatusBarManagerInternal statusbar = getStatusBarManagerInternal();
            if (statusbar != null) {
                statusbar.cancelPreloadRecentApps();
            }
        }
    }
''', '''    private void cancelPreloadRecentApps() {
        synchronized (mWonadRecentsEndpointLock) {
            final Object dispatch = org.wonad.server.input.WonadPolicyKeyAdapter
                    .currentRecentDispatchTicket();
            if (dispatch != null && org.wonad.server.input.WonadPolicyKeyAdapter
                    .recentDispatchOwner(dispatch) != mWonadPreloadedRecentAppsOwner) return;
            org.wonad.server.input.WonadPolicyKeyAdapter.supersedeRecentEndpointStart();
            mWonadPreloadedRecentAppsOwner = null;
            if (mPreloadedRecentApps) {
                mPreloadedRecentApps = false;
                StatusBarManagerInternal statusbar = getStatusBarManagerInternal();
                if (statusbar != null) {
                    statusbar.cancelPreloadRecentApps();
                }
            }
        }
    }
''', "PWM reserved cancel")
    source = replace_once(source, '''    private void toggleRecentApps() {
        mPreloadedRecentApps = false; // preloading no longer needs to be canceled
        StatusBarManagerInternal statusbar = getStatusBarManagerInternal();
        if (statusbar != null) {
            statusbar.toggleRecentApps();
        }
    }
''', '''    private void toggleRecentApps() {
        synchronized (mWonadRecentsEndpointLock) {
            final Object dispatch = org.wonad.server.input.WonadPolicyKeyAdapter
                    .currentRecentDispatchTicket();
            if (dispatch != null && org.wonad.server.input.WonadPolicyKeyAdapter
                    .recentDispatchOwner(dispatch) != mWonadPreloadedRecentAppsOwner) return;
            org.wonad.server.input.WonadPolicyKeyAdapter.supersedeRecentEndpointStart();
            mPreloadedRecentApps = false; // preloading no longer needs to be canceled
            mWonadPreloadedRecentAppsOwner = null;
            StatusBarManagerInternal statusbar = getStatusBarManagerInternal();
            if (statusbar != null) {
                statusbar.toggleRecentApps();
            }
        }
    }
''', "PWM reserved toggle")
    source = replace_once(source, '''    private void showRecentApps(boolean triggeredFromAltTab) {
        mPreloadedRecentApps = false; // preloading no longer needs to be canceled
        StatusBarManagerInternal statusbar = getStatusBarManagerInternal();
        if (statusbar != null) {
            statusbar.showRecentApps(triggeredFromAltTab);
        }
        dismissKeyboardShortcutsMenu();
    }
''', '''    private void showRecentApps(boolean triggeredFromAltTab) {
        synchronized (mWonadRecentsEndpointLock) {
            final Object dispatch = org.wonad.server.input.WonadPolicyKeyAdapter
                    .currentRecentDispatchTicket();
            if (triggeredFromAltTab && dispatch != null &&
                    org.wonad.server.input.WonadPolicyKeyAdapter
                            .recentDispatchClaimed(dispatch)) {
                if (!org.wonad.server.input.WonadPolicyKeyAdapter
                        .commitRecentEndpointStart(dispatch)) return;
            } else {
                org.wonad.server.input.WonadPolicyKeyAdapter
                        .supersedeRecentEndpointStart();
            }
            mPreloadedRecentApps = false; // preloading no longer needs to be canceled
            mWonadPreloadedRecentAppsOwner = null;
            mWonadVisibleAltTabOwner = triggeredFromAltTab && dispatch != null
                    ? org.wonad.server.input.WonadPolicyKeyAdapter
                            .recentDispatchOwner(dispatch) : null;
            StatusBarManagerInternal statusbar = getStatusBarManagerInternal();
            if (statusbar != null) {
                statusbar.showRecentApps(triggeredFromAltTab);
            }
            dismissKeyboardShortcutsMenu();
            if (dispatch != null) {
                org.wonad.server.input.WonadPolicyKeyAdapter
                        .markRecentEndpointApplied(dispatch);
            }
        }
    }
''', "PWM reserved show")
    source = replace_once(source, '''    private void hideRecentApps(boolean triggeredFromAltTab, boolean triggeredFromHome) {
        mPreloadedRecentApps = false; // preloading no longer needs to be canceled
        StatusBarManagerInternal statusbar = getStatusBarManagerInternal();
        if (statusbar != null) {
            statusbar.hideRecentApps(triggeredFromAltTab, triggeredFromHome);
        }
    }
''', '''    private void hideRecentApps(boolean triggeredFromAltTab, boolean triggeredFromHome) {
        synchronized (mWonadRecentsEndpointLock) {
            final Object dispatch = org.wonad.server.input.WonadPolicyKeyAdapter
                    .currentRecentDispatchTicket();
            if (dispatch != null && org.wonad.server.input.WonadPolicyKeyAdapter
                    .recentDispatchOwner(dispatch) != mWonadVisibleAltTabOwner) return;
            org.wonad.server.input.WonadPolicyKeyAdapter.supersedeRecentEndpointStart();
            mPreloadedRecentApps = false; // preloading no longer needs to be canceled
            mWonadPreloadedRecentAppsOwner = null;
            mWonadVisibleAltTabOwner = null;
            StatusBarManagerInternal statusbar = getStatusBarManagerInternal();
            if (statusbar != null) {
                statusbar.hideRecentApps(triggeredFromAltTab, triggeredFromHome);
            }
        }
    }
''', "PWM reserved hide")
    return source


def ui_bridge(source: str) -> str:
    source = replace_once(source, '''    @Volatile private var shortcutClaimStates: Map<Int, ShortcutClaimState> = emptyMap()
''', '''    @Volatile private var shortcutClaimStates: Map<Int, ShortcutClaimState> = emptyMap()

    /** Opaque system_server-only target captured from the original input token.
     * Every object identity is revalidated under the WMS global lock before
     * the exact Task is removed. */
    private class EscapeTarget(
        val inputToken: IBinder,
        val window: WindowState,
        val activity: ActivityRecord,
        val task: Task,
        val uid: Int,
        val display: Int,
        val claim: ShortcutClaim,
    )

    @JvmStatic fun captureClaimedEscapeTarget(wm: WindowManagerService,
        inputToken: IBinder?, display: Int, expectedClaim: Any?): Any? =
        wm.withWonadGlobalLock {
            val claim = expectedClaim as? ShortcutClaim ?: return@withWonadGlobalLock null
            if (inputToken == null || claim.display != display ||
                !shortcutClaimCurrent(claim) || !claim.owner.isBinderAlive) {
                return@withWonadGlobalLock null
            }
            val window = wm.getInputTargetFromToken(inputToken) as? WindowState
                ?: return@withWonadGlobalLock null
            val dc = window.displayContent ?: return@withWonadGlobalLock null
            val activity = window.mActivityRecord ?: return@withWonadGlobalLock null
            val task = activity.task ?: return@withWonadGlobalLock null
            if (window.displayId != display || dc.displayId != display ||
                window.uid != activity.uid || dc.mCurrentFocus !== window ||
                wm.mRoot.topFocusedDisplayContent !== dc ||
                wm.getFocusedWindowLocked() !== window ||
                task.topRunningActivity() !== activity ||
                !eligible(wm, dc, claim.user)) {
                return@withWonadGlobalLock null
            }
            EscapeTarget(inputToken, window, activity, task, window.uid, display, claim)
        }

    /** Exact claimed-display Escape endpoint. A numeric task/display id alone
     * never authorizes removal, and focus drift makes this a no-op. */
    @JvmStatic fun closeClaimedEscapeTarget(wm: WindowManagerService,
        opaque: Any?): Boolean = wm.withWonadGlobalLock {
        val target = opaque as? EscapeTarget ?: return@withWonadGlobalLock false
        val claim = target.claim
        if (!shortcutClaimCurrent(claim) || !claim.owner.isBinderAlive ||
            claim.display != target.display) return@withWonadGlobalLock false
        val window = wm.getInputTargetFromToken(target.inputToken) as? WindowState
            ?: return@withWonadGlobalLock false
        val dc = window.displayContent ?: return@withWonadGlobalLock false
        if (window !== target.window || window.mActivityRecord !== target.activity ||
            target.activity.task !== target.task || window.uid != target.uid ||
            window.displayId != target.display || dc.displayId != target.display ||
            dc.mCurrentFocus !== window || wm.mRoot.topFocusedDisplayContent !== dc ||
            wm.getFocusedWindowLocked() !== window ||
            target.task.topRunningActivity() !== target.activity ||
            !eligible(wm, dc, claim.user)) return@withWonadGlobalLock false
        wm.mAtmService.removeTask(target.task, "wonad-claimed-escape")
        true
    }
''', "exact claimed Escape target")
    source = replace_once(source, '''    private fun publishInputContainment() {
        blankDisplays = claims.values.filter { it.blank }.map { it.dc.displayId }.toSet() +
            departingInputBarriers.keys
        protectedInputDisplays = claims.values.filter { it.protectedInput }
            .map { it.dc.displayId }.toSet()
    }
''', '''    private fun publishInputContainment() {
        val nextBlank = claims.values.filter { it.blank }.map { it.dc.displayId }.toSet() +
            departingInputBarriers.keys
        val nextProtected = claims.values.filter { it.protectedInput }
            .map { it.dc.displayId }.toSet()
        val before = blankDisplays + protectedInputDisplays
        val after = nextBlank + nextProtected
        // Publish exact-claim policy containment before the lock-free UI
        // barrier changes. Delayed stock actions then cannot race through the
        // interval between a claim becoming unsafe and the display set write.
        (after - before).forEach { display ->
            shortcutClaimStates[display]?.claim?.let {
                WonadInputBridge.onUiClaimContainmentChanged(it, true)
            }
        }
        blankDisplays = nextBlank
        protectedInputDisplays = nextProtected
        // Opening is ordered after both volatile barriers. Old draining pairs
        // remain draining; only future pairs for this exact claim may pass.
        (before - after).forEach { display ->
            shortcutClaimStates[display]?.claim?.let {
                WonadInputBridge.onUiClaimContainmentChanged(it, false)
            }
        }
    }
''', "exact claim containment publication")
    source = replace_once(source, '''    /** Publish removal before touching the old input owner. A new token is not
     * visible until exact old-owner cleanup has completed, so releaseDisplay
     * can never revoke a replacement shortcut slot with the same display id. */
    private fun retireShortcutClaim(claim: Claim) {
        val previous = shortcutClaimStates[claim.dc.displayId]?.claim?.takeIf {
            it.incarnation == claim.incarnation
        } ?: return
        shortcutClaimStates = shortcutClaimStates - claim.dc.displayId
        WonadInputBridge.onUiClaimRetired(previous)
    }
''', '''    /** Mark exact policy state retired before unpublishing the old input
     * authority. A delayed stock action and this callback linearize on the
     * Kotlin helper; a replacement token remains unpublished until cleanup. */
    private fun retireShortcutClaim(claim: Claim) {
        val previous = shortcutClaimStates[claim.dc.displayId]?.claim?.takeIf {
            it.incarnation == claim.incarnation
        } ?: return
        WonadInputBridge.onUiClaimRetiring(previous)
        shortcutClaimStates = shortcutClaimStates - claim.dc.displayId
        WonadInputBridge.onUiClaimRetired(previous)
    }
''', "exact claim retirement ordering")
    source = replace_once(source, '''        if (previous != null) {
            shortcutClaimStates = shortcutClaimStates - claim.dc.displayId
            // If exact old-owner cleanup raises a fatal error, this method
            // stops here and cannot publish replacement authority.
            WonadInputBridge.onUiClaimRetired(previous)
        }
''', '''        if (previous != null) {
            WonadInputBridge.onUiClaimRetiring(previous)
            shortcutClaimStates = shortcutClaimStates - claim.dc.displayId
            // If exact old-owner cleanup raises a fatal error, this method
            // stops here and cannot publish replacement authority.
            WonadInputBridge.onUiClaimRetired(previous)
        }
''', "replacement exact claim retirement ordering")
    source = replace_once(source, '''        shortcutClaimStates = shortcutClaimStates + (claim.dc.displayId to
            ShortcutClaimState(token, claim.expires))
    }
''', '''        shortcutClaimStates = shortcutClaimStates + (claim.dc.displayId to
            ShortcutClaimState(token, claim.expires))
        if (consumeInput(token.display)) {
            WonadInputBridge.onUiClaimContainmentChanged(token, true)
        }
    }
''', "new token inherits published containment")
    return source


def input_bridge(source: str) -> str:
    anchor = '''    /** Early policy seam for paste/action/app-capture branches which return
     * before ordinary shortcut interception. InputDispatcher has already
'''
    addition = '''    /** Lifecycle callbacks are private system_server wiring. Exact claim
     * identity is preserved; no public Binder or SDK surface is added. */
    @JvmStatic internal fun onUiClaimContainmentChanged(
        expected: WonadUiBridge.ShortcutClaim, blocked: Boolean) {
        WonadPolicyKeyAdapter.onClaimContainmentChanged(expected, blocked)
    }

    @JvmStatic internal fun onUiClaimRetiring(expected: WonadUiBridge.ShortcutClaim) {
        WonadPolicyKeyAdapter.onClaimRetiring(expected)
    }

    /** Private read-only primitive for the exact Kotlin policy-pair adapter. */
    internal fun policyClaimBlocked(context: Context, wm: WindowManagerInternal,
        display: Int): Boolean = claimedInputBlocked(context, wm, display)

    /** Observe the original KeyEvent only; never substitute its display id.
     * The optional retained claim selects only the old private input owner/user
     * metadata; it cannot make the event eligible or create a command. */
    internal fun policyDrainContained(wm: WindowManagerInternal, event: KeyEvent,
        policyFlags: Int, claim: WonadUiBridge.ShortcutClaim?) {
        val owner = claim?.let { retained -> synchronized(lock) {
            owners[retained.display]?.takeIf { it.claim === retained }
        } }
        drainContained(wm, event, policyFlags, owner)
    }

'''
    source = replace_once(source, anchor, addition + anchor,
        "bridge private adapter primitives")
    source = replace_once(source, '''    @JvmStatic internal fun onUiClaimRetired(expected: WonadUiBridge.ShortcutClaim) {
        val owner = synchronized(lock) { owners[expected.display] }
        if (owner?.claim === expected) clear(owner)
    }
''', '''    @JvmStatic internal fun onUiClaimRetired(expected: WonadUiBridge.ShortcutClaim) {
        // UiBridge has already unpublished this exact identity; the helper can
        // now discard its temporary lifecycle override. Retained pairs remain
        // independently draining by exact physical identity.
        WonadPolicyKeyAdapter.onClaimRetired(expected)
        val owner = synchronized(lock) { owners[expected.display] }
        if (owner?.claim === expected) clear(owner)
    }
''', "bridge exact retirement completion")
    source = replace_once(source, '''        val invalid = state != null && try {
            val now = SystemClock.elapsedRealtime()
            !claimActive(context, wm, state, now) ||
''', '''        val invalid = state != null && try {
            val now = SystemClock.elapsedRealtime()
            WonadPolicyKeyAdapter.claimBlocked(state.claim) ||
                !claimActive(context, wm, state, now) ||
''', "bridge synchronous claim lifecycle guard")
    return source


def input_manager_service(source: str) -> str:
    return replace_once(source, '''        mKeyGestureController = new KeyGestureController(mContext, injector.getLooper(),
                injector.getIoLooper(), mInputDataStore);
''', '''        mKeyGestureController = new KeyGestureController(mContext, injector.getLooper(),
                injector.getIoLooper(), mInputDataStore, mNative);
''', "native census dependency injection")


def window_manager_internal(source: str) -> str:
    return replace_once(source, '''    public abstract IBinder getFocusedWindowTokenFromWindowStates();
''', '''    public abstract IBinder getFocusedWindowTokenFromWindowStates();

    /** Private system_server-only exact target for a claimed external Escape. */
    public abstract Object captureWonadClaimedEscapeTarget(IBinder inputToken,
            int displayId, Object exactClaim);

    /** Atomically revalidates and closes only the originally captured Task. */
    public abstract boolean closeWonadClaimedEscapeTarget(Object exactTarget);
''', "private exact Escape WMI declarations")


def window_manager_service(source: str) -> str:
    return replace_once(source, '''        public IBinder getFocusedWindowTokenFromWindowStates() {
            synchronized (mGlobalLock) {
                final WindowState windowState = getFocusedWindowLocked();
                if (windowState != null) {
                    return windowState.mClient.asBinder();
                }
                return null;
            }
        }
''', '''        public IBinder getFocusedWindowTokenFromWindowStates() {
            synchronized (mGlobalLock) {
                final WindowState windowState = getFocusedWindowLocked();
                if (windowState != null) {
                    return windowState.mClient.asBinder();
                }
                return null;
            }
        }

        @Override
        public Object captureWonadClaimedEscapeTarget(IBinder inputToken,
                int displayId, Object exactClaim) {
            return WonadUiBridge.captureClaimedEscapeTarget(
                    WindowManagerService.this, inputToken, displayId, exactClaim);
        }

        @Override
        public boolean closeWonadClaimedEscapeTarget(Object exactTarget) {
            return WonadUiBridge.closeClaimedEscapeTarget(
                    WindowManagerService.this, exactTarget);
        }
''', "private exact Escape WMS delegate")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit(f"output exists: {args.output}")
    for label, (path, expected) in INPUTS.items():
        observed = digest(path)
        if observed != expected:
            raise SystemExit(f"{label} input changed: {observed} != {expected}")
    for label, (path, expected) in SUPPORT_INPUTS.items():
        observed = digest(path)
        if observed != expected:
            raise SystemExit(f"{label} support input changed: {observed} != {expected}")

    outputs = {
        "InputManagerService.java": input_manager_service(INPUTS["ims"][0].read_text()),
        "KeyGestureController.java": key_gesture_controller(INPUTS["kgc"][0].read_text()),
        "PhoneWindowManager.java": phone_window_manager(INPUTS["pwm"][0].read_text()),
        "WonadInputBridge.kt": input_bridge(INPUTS["bridge"][0].read_text()),
        "WonadUiBridge.kt": ui_bridge(INPUTS["ui"][0].read_text()),
        "WindowManagerInternal.java": window_manager_internal(INPUTS["wmi"][0].read_text()),
        "WindowManagerService.java": window_manager_service(INPUTS["wms"][0].read_text()),
    }
    args.output.mkdir(parents=True)
    for name, content in outputs.items():
        (args.output / name).write_text(content)
    shutil.copyfile(HERE / "candidate/WonadPolicyKeyContainment.kt",
        args.output / "WonadPolicyKeyContainment.kt")
    shutil.copyfile(HERE / "candidate/WonadPolicyKeyAdapter.kt",
        args.output / "WonadPolicyKeyAdapter.kt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
