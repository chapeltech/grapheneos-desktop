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
        "import java.util.Map;\nimport java.util.concurrent.atomic.AtomicReference;",
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
            if (!mHandler.post(() -> applyWonadPolicyCleanup(decision))) {
                Slog.e(TAG, "Could not dispatch Wonad policy-owner cleanup");
            }
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

    /** Apply only cleanup objects owned by this exact physical pair/claim. */
    private void applyWonadPolicyCleanup(
            @NonNull org.wonad.server.input.WonadPolicyKeyAdapter.Decision decision) {
        clearWonadMetaOwner(decision.clearMeta);
        clearWonadCapsOwner(decision.clearCaps);
        if (clearWonadAltTabOwner(decision.finishAltTab)) {
            final org.wonad.server.input.WonadPolicyKeyAdapter.OwnerEvent owner =
                    org.wonad.server.input.WonadPolicyKeyAdapter.ownerEvent(
                            decision.finishAltTab);
            handleKeyGesture(owner.device, new int[]{KeyEvent.KEYCODE_TAB},
                    KeyEvent.META_ALT_ON,
                    KeyGestureEvent.KEY_GESTURE_TYPE_RECENT_APPS_SWITCHER,
                    KeyGestureEvent.ACTION_GESTURE_COMPLETE, owner.display,
                    (IBinder) owner.focus, KeyGestureEvent.FLAG_CANCELLED,
                    /* appLaunchData = */ null);
        }
        if (decision.cancelRecent != null) {
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
        for (Object pending : decision.cancelEscapes) {
            cancelWonadEscape(pending);
        }
    }

    /** Compensate a failed owner-install callback without hiding its original
     * exception. Both the displaced-owner cleanup and the newly published
     * owner rollback are exact-identity operations and must be attempted. */
    private void rollbackWonadOwnerInstall(
            @NonNull org.wonad.server.input.WonadPolicyKeyAdapter.OwnerInstall install) {
        Throwable failure = null;
        try {
            applyWonadPolicyCleanup(install.cleanup);
        } catch (Throwable error) {
            failure = error;
        }
        try {
            applyWonadPolicyCleanup(install.rollback);
        } catch (Throwable error) {
            if (failure == null) {
                failure = error;
            } else if (failure != error) {
                failure.addSuppressed(error);
            }
        }
        if (failure instanceof RuntimeException runtime) throw runtime;
        if (failure instanceof Error fatal) throw fatal;
        if (failure != null) {
            throw new IllegalStateException("Wonad policy owner rollback failed", failure);
        }
    }

    /** Escape has no Java owner mirror, but a START or delayed completion may
     * already have escaped before the callback failed. Cancel every exact
     * owner carried by the pure helper's rollback decision. */
    private void rollbackWonadEscapeInstall(
            @NonNull org.wonad.server.input.WonadPolicyKeyAdapter.EscapeInstall install) {
        applyWonadPolicyCleanup(install.rollback);
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
        handleKeyGesture(owner.device, new int[]{KeyEvent.KEYCODE_ESCAPE},
                /* modifierState = */ 0,
                KeyGestureEvent.KEY_GESTURE_TYPE_QUIT_FOCUSED_TASK,
                KeyGestureEvent.ACTION_GESTURE_COMPLETE, owner.display,
                (IBinder) owner.focus, KeyGestureEvent.FLAG_CANCELLED,
                /* appLaunchData = */ null);
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
                    org.wonad.server.input.WonadPolicyKeyAdapter.installRecent(
                            mContext, mWindowManagerInternal, wonadDecision.pair, focusedToken,
                            install -> {
                                applyWonadPolicyCleanup(install.cleanup);
                                final Object dispatch = org.wonad.server.input
                                        .WonadPolicyKeyAdapter.beginRecentDispatch(
                                                install.owner,
                                                org.wonad.server.input.WonadPolicyKeyAdapter
                                                        .DISPATCH_START);
                                try {
                                    handleKeyGesture(deviceId, new int[]{keyCode},
                                            /* modifierState = */0,
                                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH,
                                            KeyGestureEvent.ACTION_GESTURE_START, displayId,
                                            focusedToken, /* flags = */0,
                                            /* appLaunchData = */null);
                                } finally {
                                    org.wonad.server.input.WonadPolicyKeyAdapter
                                            .endRecentDispatch(dispatch);
                                }
                            }, this::rollbackWonadOwnerInstall);
                    // A lifecycle transition which wins installation is still
                    // fail-closed; no stock START is sent.
                    return true;
                } else if (!down && !hasModifiers && wonadDecision != null
                        && wonadDecision.pair != null) {
                    final Object owner =
                            org.wonad.server.input.WonadPolicyKeyAdapter.completeRecent(
                                    wonadDecision.pair);
                    if (owner == null) break;
                    final org.wonad.server.input.WonadPolicyKeyAdapter.OwnerEvent original =
                            org.wonad.server.input.WonadPolicyKeyAdapter.ownerEvent(owner);
                    final Object dispatch =
                            org.wonad.server.input.WonadPolicyKeyAdapter.beginRecentDispatch(
                                    owner,
                                    canceled
                                            ? org.wonad.server.input.WonadPolicyKeyAdapter
                                                    .DISPATCH_CANCEL
                                            : org.wonad.server.input.WonadPolicyKeyAdapter
                                                    .DISPATCH_COMPLETE);
                    try {
                        handleKeyGesture(original.device,
                                new int[]{KeyEvent.KEYCODE_APP_SWITCH}, /* modifierState = */0,
                                KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH,
                                KeyGestureEvent.ACTION_GESTURE_COMPLETE, original.display,
                                (IBinder) original.focus,
                                canceled ? KeyGestureEvent.FLAG_CANCELLED : 0,
                                /* appLaunchData = */null);
                    } finally {
                        org.wonad.server.input.WonadPolicyKeyAdapter.endRecentDispatch(dispatch);
                    }
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
                // The delayed completion is owned by this exact physical pair,
                // original claim attachment and original focus token.
                if (firstDown && canFocusedWindowCaptureKeys(focusedToken)
                        && wonadDecision != null && wonadDecision.pair != null) {
                    final AidlKeyGestureEvent eventToSend = createKeyGestureEvent(
                            event.getDeviceId(), new int[]{KeyEvent.KEYCODE_ESCAPE}, metaState,
                            KeyGestureEvent.KEY_GESTURE_TYPE_QUIT_FOCUSED_TASK,
                            KeyGestureEvent.ACTION_GESTURE_COMPLETE, displayId,
                            /* flags= */0, /* appLaunchData= */ null);
                    org.wonad.server.input.WonadPolicyKeyAdapter.installEscape(
                            mContext, mWindowManagerInternal, wonadDecision.pair, focusedToken,
                            eventToSend, install -> {
                                if (install.replaced != null) {
                                    cancelWonadEscape(install.replaced);
                                }
                                Toast.makeText(mContext, UiThread.get().getLooper(),
                                        mContext.getString(
                                                R.string.exit_toast_on_long_press_escape),
                                        Toast.LENGTH_SHORT).show();
                                handleKeyGesture(event.getDeviceId(),
                                        new int[]{KeyEvent.KEYCODE_ESCAPE}, metaState,
                                        KeyGestureEvent.KEY_GESTURE_TYPE_QUIT_FOCUSED_TASK,
                                        KeyGestureEvent.ACTION_GESTURE_START, displayId,
                                        focusedToken, /* flags= */0,
                                        /* appLaunchData= */ null);
                                final Message msg = Message.obtain(
                                        mHandler, MSG_EXIT_FOCUSED_APP, eventToSend);
                                mHandler.sendMessageDelayed(
                                        msg, LONG_PRESS_DURATION_FOR_EXIT_APP_MS);
                            }, this::rollbackWonadEscapeInstall);
                    return true;
                } else if (!down && wonadDecision != null && wonadDecision.pair != null) {
                    final Object owner =
                            org.wonad.server.input.WonadPolicyKeyAdapter.completeEscapePair(
                                    wonadDecision.pair);
                    if (owner != null) {
                        cancelWonadEscape(owner);
                        return true;
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
                                        applyWonadPolicyCleanup(install.cleanup);
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
                                        applyWonadPolicyCleanup(install.cleanup);
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
                        final org.wonad.server.input.WonadPolicyKeyAdapter.OwnerEvent owner =
                                org.wonad.server.input.WonadPolicyKeyAdapter.ownerEvent(
                                        altTabOwner);
                        handleKeyGesture(owner.device, new int[]{KeyEvent.KEYCODE_TAB},
                                KeyEvent.META_ALT_ON,
                                KeyGestureEvent.KEY_GESTURE_TYPE_RECENT_APPS_SWITCHER,
                                KeyGestureEvent.ACTION_GESTURE_COMPLETE, owner.display,
                                (IBinder) owner.focus, /* flags = */0,
                                /* appLaunchData = */null);
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
                                org.wonad.server.input.WonadPolicyKeyAdapter.installAltTab(
                                        mContext, mWindowManagerInternal, wonadPair, focusedToken,
                                        install -> {
                                            applyWonadPolicyCleanup(install.cleanup);
                                            mWonadPendingAltTabOwner.set(install.owner);
                                            mPendingHideRecentSwitcher = true;
                                            handleKeyGesture(deviceId, new int[]{keyCode},
                                                    KeyEvent.META_ALT_ON,
                                                    KeyGestureEvent
                                                            .KEY_GESTURE_TYPE_RECENT_APPS_SWITCHER,
                                                    KeyGestureEvent.ACTION_GESTURE_START,
                                                    displayId, focusedToken, /* flags = */0,
                                                    /* appLaunchData = */null);
                                        }, this::rollbackWonadOwnerInstall);
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
                                        applyWonadPolicyCleanup(install.cleanup);
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
                org.wonad.server.input.WonadPolicyKeyAdapter.dispatchEscape(
                        mContext, mWindowManagerInternal, msg.obj,
                        pending -> handleKeyGesture((AidlKeyGestureEvent) msg.obj,
                                (IBinder) pending.focus));
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
                    final Object owner =
                            org.wonad.server.input.WonadPolicyKeyAdapter
                                    .currentRecentDispatch(
                                            org.wonad.server.input
                                                    .WonadPolicyKeyAdapter.DISPATCH_CANCEL);
                    if (owner != null && owner == mWonadPreloadedRecentAppsOwner) {
                        cancelPreloadRecentApps();
                    }
                } else if (complete && keyguardOn) {
                    final Object owner =
                            org.wonad.server.input.WonadPolicyKeyAdapter
                                    .currentRecentDispatch(
                                            org.wonad.server.input
                                                    .WonadPolicyKeyAdapter.DISPATCH_COMPLETE);
                    if (owner != null && owner == mWonadPreloadedRecentAppsOwner) {
                        cancelPreloadRecentApps();
                    }
                } else if (!keyguardOn) {
                    if (start) {
                        preloadRecentApps();
                    } else if (complete) {
                        final Object owner =
                                org.wonad.server.input.WonadPolicyKeyAdapter
                                        .currentRecentDispatch(
                                                org.wonad.server.input
                                                        .WonadPolicyKeyAdapter.DISPATCH_COMPLETE);
                        if (owner != null && owner == mWonadPreloadedRecentAppsOwner) {
                            toggleRecentApps();
                        }
                    }
                }
                break;
''', "PWM exact APP_SWITCH owner")
    source = replace_once(source, '''    private void preloadRecentApps() {
        mPreloadedRecentApps = true;
''', '''    private void preloadRecentApps() {
        mWonadPreloadedRecentAppsOwner =
                org.wonad.server.input.WonadPolicyKeyAdapter.currentRecentDispatch(
                        org.wonad.server.input.WonadPolicyKeyAdapter.DISPATCH_START);
        mPreloadedRecentApps = true;
''', "PWM preload owner")
    source = replace_once(source, '''    private void cancelPreloadRecentApps() {
        if (mPreloadedRecentApps) {
            mPreloadedRecentApps = false;
''', '''    private void cancelPreloadRecentApps() {
        mWonadPreloadedRecentAppsOwner = null;
        if (mPreloadedRecentApps) {
            mPreloadedRecentApps = false;
''', "PWM cancel clears owner")
    source = replace_once(source, '''    private void toggleRecentApps() {
        mPreloadedRecentApps = false; // preloading no longer needs to be canceled
''', '''    private void toggleRecentApps() {
        mPreloadedRecentApps = false; // preloading no longer needs to be canceled
        mWonadPreloadedRecentAppsOwner = null;
''', "PWM toggle clears owner")
    source = replace_once(source, '''    private void showRecentApps(boolean triggeredFromAltTab) {
        mPreloadedRecentApps = false; // preloading no longer needs to be canceled
''', '''    private void showRecentApps(boolean triggeredFromAltTab) {
        mPreloadedRecentApps = false; // preloading no longer needs to be canceled
        mWonadPreloadedRecentAppsOwner = null;
''', "PWM show clears owner")
    source = replace_once(source, '''    private void hideRecentApps(boolean triggeredFromAltTab, boolean triggeredFromHome) {
        mPreloadedRecentApps = false; // preloading no longer needs to be canceled
''', '''    private void hideRecentApps(boolean triggeredFromAltTab, boolean triggeredFromHome) {
        mPreloadedRecentApps = false; // preloading no longer needs to be canceled
        mWonadPreloadedRecentAppsOwner = null;
''', "PWM hide clears owner")
    return source


def ui_bridge(source: str) -> str:
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

    outputs = {
        "InputManagerService.java": input_manager_service(INPUTS["ims"][0].read_text()),
        "KeyGestureController.java": key_gesture_controller(INPUTS["kgc"][0].read_text()),
        "PhoneWindowManager.java": phone_window_manager(INPUTS["pwm"][0].read_text()),
        "WonadInputBridge.kt": input_bridge(INPUTS["bridge"][0].read_text()),
        "WonadUiBridge.kt": ui_bridge(INPUTS["ui"][0].read_text()),
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
