#!/usr/bin/env python3
"""Materialize the external total-control key-routing candidate.

The tool authenticates exact custom7/repository inputs, writes only a fresh
caller-selected external directory, and never edits the source checkout.
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
    "bridge": (
        ROOT / "android/input-integration/src/org/wonad/server/input/WonadInputBridge.kt",
        "b512112fe58157e8e1a18baa3dbf0c0c338f073ea4d901c63d9949aaa11e60ff",
    ),
    "ui": (
        ROOT / "android/input-integration/src/com/android/server/wm/WonadUiBridge.kt",
        "8d227e84eef912d1016698e018ca37642cff8ec0150a380eb25dbf7e8dc21da4",
    ),
    "entry": (
        STAGE / "frameworks/native/services/inputflinger/dispatcher/Entry.h",
        "57aa994e65bfeebdceec811dd2bd380c6918508df93ce4799b3e682c433442b0",
    ),
    "dispatcher": (
        STAGE / "frameworks/native/services/inputflinger/dispatcher/InputDispatcher.cpp",
        "4598e3a96e0196a5965be2a4232736ba7e14616c8435b201ab6d394e44b762c9",
    ),
    "dispatcher_h": (
        STAGE / "frameworks/native/services/inputflinger/dispatcher/InputDispatcher.h",
        "713ca2351b28ebde8829edada02bea18c4923614f353bd7ca277eff69f4994d6",
    ),
    "dispatcher_policy": (
        STAGE / "frameworks/native/services/inputflinger/dispatcher/include/InputDispatcherPolicyInterface.h",
        "2aec8d0310d120f962ffd7da16a5c3e848f8e583ab4cc1025fe421142278e343",
    ),
    "fake_policy_h": (
        STAGE / "frameworks/native/services/inputflinger/tests/FakeInputDispatcherPolicy.h",
        "e77f7689438f6519579bb68916b6ccf63a10de0803b412c9e7618d1c72eb2373",
    ),
    "fake_policy_cpp": (
        STAGE / "frameworks/native/services/inputflinger/tests/FakeInputDispatcherPolicy.cpp",
        "54961406679d6aae58fd05c89f425fee697dda52c748613cfd81be37ea85df00",
    ),
    "ims_jni": (
        STAGE / "frameworks/base/services/core/jni/com_android_server_input_InputManagerService.cpp",
        "0a71ebf0fb6697a1f21a6abe0e14e53d4b961e40a4baace0b8dedb0d5b8c08c5",
    ),
}

# Source evidence for the deliberately retained pre-seam global-safety and
# resolver behavior. These files are not rewritten.
SUPPORT_INPUTS = {
    "KeyGestureControllerTests.kt": (
        STAGE / "frameworks/base/tests/Input/src/com/android/server/input/KeyGestureControllerTests.kt",
        "f14238927f72d9b8939fcf1f707d7f7c869490146d8b3125b86d9f82932b7077",
    ),
    "android_view_KeyEvent.cpp": (
        STAGE / "frameworks/base/core/jni/android_view_KeyEvent.cpp",
        "39115d46e379cc96bcf212ce2c789f17f3316b27de92f08bcc4790b025b3f7eb",
    ),
    "PhoneWindowManager.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/policy/PhoneWindowManager.java",
        "25be0cd9384ef463af854067e4904701041ece23ef0e9b9f8cc348503e6e1898",
    ),
    "KeyboardInputMapper.cpp": (
        STAGE / "frameworks/native/services/inputflinger/reader/mapper/KeyboardInputMapper.cpp",
        "0a8bc5d7d66b02d4faac11f9c8252e6bb059f7ad2f4cbbae80865d32a810f303",
    ),
    "KeyCombinationManager.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/input/KeyCombinationManager.java",
        "c0fc0486e537637ab9e1006eba597b1840692e7f6eb24c8c5ab9f466b4d46044",
    ),
    "KeyEvent.java": (
        STAGE / "frameworks/base/core/java/android/view/KeyEvent.java",
        "1f4ac4a6b669e19046e1c925e71d77938edf8575f87900d84d411403956e914b",
    ),
    "InputManager.java": (
        STAGE / "frameworks/base/core/java/android/hardware/input/InputManager.java",
        "fc66ed3ed586756cfd5b635a7b9658ec363b132e752f1d79b50cbb4839b8dc72",
    ),
    "ActivityManagerService.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java",
        "3851765b11595887e6b044af93646b3b859363195ce4a5ec19d50b7dc55a8dee",
    ),
    "UserController.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/am/UserController.java",
        "b30cdcac2ca4976ab0f1427f468ad0d4e4e1de324a7fa76edcab81047dcaad41",
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
    "Settings.java": (
        STAGE / "frameworks/base/core/java/android/provider/Settings.java",
        "2e120f6e778bf117629b7a95427fa28ab29829d35dc2295a3f05a2a174d1b0d9",
    ),
    "SettingsProvider.java": (
        STAGE / "frameworks/base/packages/SettingsProvider/src/com/android/providers/settings/SettingsProvider.java",
        "493f8ae79ea36b7f1c0e35b363f56ff544ed2e9f16345ca43e4147276e5322cb",
    ),
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one source anchor, observed {count}")
    return text.replace(old, new)


def key_gesture_controller(source: str) -> str:
    source = replace_once(source, '''    public long interceptKeyBeforeDispatching(IBinder focus, KeyEvent event, int policyFlags) {
''', '''    public long interceptKeyBeforeDispatching(IBinder focus, KeyEvent event, int policyFlags,
            long wonadAdmissionToken) {
''', "private native admission candidate")
    source = replace_once(source, '''    public long interceptKeyBeforeDispatching(IBinder focus, KeyEvent event, int policyFlags,
            long wonadAdmissionToken) {
''', '''    // Internal compatibility for stock policy/tests. Zero cannot authorize
    // claimed native completion; only IMS's private four-argument invocation can.
    public long interceptKeyBeforeDispatching(IBinder focus, KeyEvent event, int policyFlags) {
        return interceptKeyBeforeDispatching(focus, event, policyFlags, 0L);
    }

    public long interceptKeyBeforeDispatching(IBinder focus, KeyEvent event, int policyFlags,
            long wonadAdmissionToken) {
''', "stock private seam compatibility overload")
    source = replace_once(source, '''            KEY_INTERCEPT_RESULT_NOT_CONSUMED_GO_FALLBACK,
            KEY_INTERCEPT_RESULT_CONSUMED,
            KEY_INTERCEPT_RESULT_NOT_CONSUMED
''', '''            KEY_INTERCEPT_RESULT_NOT_CONSUMED_GO_FALLBACK,
            KEY_INTERCEPT_RESULT_CONSUMED,
            KEY_INTERCEPT_RESULT_NOT_CONSUMED,
            KEY_INTERCEPT_RESULT_WONAD_CLAIMED_APPLICATION
''', "claimed application intercept annotation")
    source = replace_once(source, '''    private static final long KEY_INTERCEPT_RESULT_NOT_CONSUMED_GO_FALLBACK = -2;
    static final long KEY_INTERCEPT_RESULT_CONSUMED = -1;
    static final long KEY_INTERCEPT_RESULT_NOT_CONSUMED = 0;
''', '''    private static final long KEY_INTERCEPT_RESULT_WONAD_CLAIMED_APPLICATION = -3;
    private static final long KEY_INTERCEPT_RESULT_NOT_CONSUMED_GO_FALLBACK = -2;
    static final long KEY_INTERCEPT_RESULT_CONSUMED = -1;
    static final long KEY_INTERCEPT_RESULT_NOT_CONSUMED = 0;
''', "claimed application intercept value")
    source = replace_once(source, '''    // Platform behaviors
''', '''    // Exceptional pair-ledger recovery uses only a trusted complete native
    // all-key-UP census. Ordinary routing never consults or modifies this.
    @Nullable private final NativeInputManagerService mWonadNativeInput;
    @Nullable private InputManager mWonadInputManager;
    private final InputManager.InputDeviceListener mWonadInputDeviceListener =
            new InputManager.InputDeviceListener() {
                @Override public void onInputDeviceAdded(int deviceId) {}
                @Override public void onInputDeviceChanged(int deviceId) {}
                @Override public void onInputDeviceRemoved(int deviceId) {
                    if (org.wonad.server.input.WonadPolicyKeyAdapter.removeDevice(deviceId)) {
                        reconcileWonadPolicyDevices();
                    }
                }
            };

    // Platform behaviors
''', "device retirement fields")

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
''', "native census constructor")

    source = replace_once(source, '''        InputManager im = Objects.requireNonNull(mContext.getSystemService(InputManager.class));
        im.registerKeyGestureEventHandler(
''', '''        InputManager im = Objects.requireNonNull(mContext.getSystemService(InputManager.class));
        mWonadInputManager = im;
        im.registerInputDeviceListener(mWonadInputDeviceListener, mHandler);
        im.registerKeyGestureEventHandler(
''', "device retirement registration")

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
''', '''        // Claimed external input must not mutate process-global phone Meta/Caps
        // bookkeeping. The read-only check also recognizes a retained claimed
        // pair whose terminal was stamped with a different current display.
        if (org.wonad.server.input.WonadPolicyKeyAdapter.allowStockBookkeeping(event)) {
            // Cancel any pending meta actions if we see any other keys being pressed between the
            // down of the meta key and its corresponding up.
            if (mPendingMetaAction && !KeyEvent.isMetaKey(keyCode)) {
                mPendingMetaAction = false;
            }
            // Any key that is not Alt or Meta cancels Caps Lock combo tracking.
            if (mPendingCapsLockToggle && !KeyEvent.isMetaKey(keyCode)
                    && !KeyEvent.isAltKey(keyCode)) {
                mPendingCapsLockToggle = false;
            }
        }

        // Multi-key shortcuts should never be blocked by any focused window configuration
''', "claimed input preserves phone bookkeeping")

    source = replace_once(source, '''            if (org.wonad.server.input.WonadInputBridge.consumeClaimedInput(
                    mContext, mWindowManagerInternal, event, policyFlags)) {
                return KEY_INTERCEPT_RESULT_CONSUMED;
            }
            SecurePasteKeyEventHandler.maybeGrantAccess(mWindowManagerInternal, focus, event);
''', '''            final org.wonad.server.input.WonadPolicyKeyAdapter.Decision decision =
                    org.wonad.server.input.WonadPolicyKeyAdapter.beforeStock(
                            mContext, mWindowManagerInternal, focus, event,
                            wonadPolicyRole(event.getKeyCode()));
            if (consumeWonadPolicyEvent(event, policyFlags, decision)) {
                return KEY_INTERCEPT_RESULT_CONSUMED;
            }
            SecurePasteKeyEventHandler.maybeGrantAccess(mWindowManagerInternal, focus, event);
            if (decision.nativeCompletion) {
                return org.wonad.server.input.WonadPolicyKeyAdapter.commitNativeCompletion(
                        mWindowManagerInternal, event, policyFlags,
                        wonadAdmissionToken, decision)
                        ? KEY_INTERCEPT_RESULT_WONAD_CLAIMED_APPLICATION
                        : KEY_INTERCEPT_RESULT_CONSUMED;
            }
''', "SecurePaste final containment")

    source = replace_once(source, '''        if (wonadShortcut && org.wonad.server.input.WonadInputBridge.intercept(
                mContext, mWindowManagerInternal, event, policyFlags)) {
            return KEY_INTERCEPT_RESULT_CONSUMED;
        }

        // TODO(b/358569822) Remove below once we have nicer API for listening to shortcuts
''', '''        if (wonadShortcut && org.wonad.server.input.WonadInputBridge.intercept(
                mContext, mWindowManagerInternal, event, policyFlags)) {
            return KEY_INTERCEPT_RESULT_CONSUMED;
        }

        // Total-control seam. A healthy exact claim either returns ordinary
        // input to its app or consumes a dedicated Android-desktop UI pair.
        // It never enters stock before/after-capture shortcut stages.
        final org.wonad.server.input.WonadPolicyKeyAdapter.Decision wonadDecision =
                org.wonad.server.input.WonadPolicyKeyAdapter.beforeStock(
                        mContext, mWindowManagerInternal, focus, event,
                        wonadPolicyRole(event.getKeyCode()));
        if (consumeWonadPolicyEvent(event, policyFlags, wonadDecision)) {
            return KEY_INTERCEPT_RESULT_CONSUMED;
        }
        if (wonadDecision.application) {
            if (!wonadDecision.nativeCompletion) {
                return KEY_INTERCEPT_RESULT_NOT_CONSUMED;
            }
            return org.wonad.server.input.WonadPolicyKeyAdapter.commitNativeCompletion(
                    mWindowManagerInternal, event, policyFlags,
                    wonadAdmissionToken, wonadDecision)
                    ? KEY_INTERCEPT_RESULT_WONAD_CLAIMED_APPLICATION
                    : KEY_INTERCEPT_RESULT_CONSUMED;
        }

        // TODO(b/358569822) Remove below once we have nicer API for listening to shortcuts
''', "total-control seam")

    source = replace_once(source, '''        if (org.wonad.server.input.WonadInputBridge.consumeClaimedInput(
                mContext, mWindowManagerInternal, event, policyFlags)) {
            return KEY_INTERCEPT_RESULT_CONSUMED;
        }

        // Allow focused window to capture key events
''', '''        // Allow focused window to capture key events
''', "obsolete post-stock containment")

    marker = '''    private long interceptMultiKeyCombination(@NonNull KeyEvent event) {
'''
    helpers = '''    private static int wonadPolicyRole(int keyCode) {
        return switch (keyCode) {
            case KeyEvent.KEYCODE_APP_SWITCH ->
                    org.wonad.server.input.WonadPolicyKeyAdapter.ROLE_APP_SWITCH;
            case KeyEvent.KEYCODE_RECENT_APPS ->
                    org.wonad.server.input.WonadPolicyKeyAdapter.ROLE_RECENT_APPS;
            case KeyEvent.KEYCODE_ALL_APPS ->
                    org.wonad.server.input.WonadPolicyKeyAdapter.ROLE_ALL_APPS;
            case KeyEvent.KEYCODE_BRIGHTNESS_UP, KeyEvent.KEYCODE_BRIGHTNESS_DOWN,
                    KeyEvent.KEYCODE_KEYBOARD_BACKLIGHT_DOWN,
                    KeyEvent.KEYCODE_KEYBOARD_BACKLIGHT_UP,
                    KeyEvent.KEYCODE_KEYBOARD_BACKLIGHT_TOGGLE,
                    KeyEvent.KEYCODE_SCREENSHOT, KeyEvent.KEYCODE_SYSRQ,
                    KeyEvent.KEYCODE_HOME, KeyEvent.KEYCODE_LOCK,
                    KeyEvent.KEYCODE_FULLSCREEN, KeyEvent.KEYCODE_ASSIST,
                    KeyEvent.KEYCODE_VOICE_ASSIST, KeyEvent.KEYCODE_CONTEXTUAL_SEARCH,
                    KeyEvent.KEYCODE_STYLUS_BUTTON_PRIMARY,
                    KeyEvent.KEYCODE_STYLUS_BUTTON_SECONDARY,
                    KeyEvent.KEYCODE_STYLUS_BUTTON_TERTIARY,
                    KeyEvent.KEYCODE_STYLUS_BUTTON_TAIL,
                    KeyEvent.KEYCODE_DO_NOT_DISTURB, KeyEvent.KEYCODE_ACCESSIBILITY,
                    KeyEvent.KEYCODE_NOTIFICATION, KeyEvent.KEYCODE_SEARCH,
                    KeyEvent.KEYCODE_SETTINGS, KeyEvent.KEYCODE_LANGUAGE_SWITCH ->
                    org.wonad.server.input.WonadPolicyKeyAdapter.ROLE_SYSTEM_ACTION;
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

    private boolean consumeWonadPolicyEvent(@NonNull KeyEvent event, int policyFlags,
            @NonNull org.wonad.server.input.WonadPolicyKeyAdapter.Decision decision) {
        final boolean consumed = org.wonad.server.input.WonadPolicyKeyAdapter.consume(
                mWindowManagerInternal, event, policyFlags, decision);
        if (decision.saturated
                && (event.getAction() == KeyEvent.ACTION_UP || event.isCanceled())) {
            reconcileWonadPolicyDevices();
        }
        return consumed;
    }

    /** Release exceptional fail-black saturation only after an unchanged,
     * complete native all-device/all-keycode UP census. */
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
        org.wonad.server.input.WonadPolicyKeyAdapter.reconcileDevices(
                input.getInputDeviceIds(), allKeysReleased, expectedEpoch);
    }

'''
    source = replace_once(source, marker, helpers + marker, "routing helpers")

    return source


def input_bridge(source: str) -> str:
    anchor = '''    /** Early policy seam for paste/action/app-capture branches which return
     * before ordinary shortcut interception. InputDispatcher has already
'''
    addition = '''    /** Private exact-claim lifecycle wiring; no public API is added. */
    @JvmStatic internal fun onUiClaimContainmentChanged(
        expected: WonadUiBridge.ShortcutClaim, blocked: Boolean) {
        WonadPolicyKeyAdapter.onClaimContainmentChanged(expected, blocked)
    }

    @JvmStatic internal fun onUiClaimRetiring(expected: WonadUiBridge.ShortcutClaim) {
        WonadPolicyKeyAdapter.onClaimRetiring(expected)
    }

    internal fun policyClaimBlocked(context: Context, wm: WindowManagerInternal,
        display: Int): Boolean = claimedInputBlocked(context, wm, display)

    /** Observe only the original event. A retained claim selects old private
     * owner metadata; it cannot grant eligibility or manufacture a command. */
    internal fun policyDrainContained(wm: WindowManagerInternal, event: KeyEvent,
        policyFlags: Int, claim: WonadUiBridge.ShortcutClaim?) {
        val owner = claim?.let { retained -> synchronized(lock) {
            owners[retained.display]?.takeIf { it.claim === retained }
        } }
        drainContained(wm, event, policyFlags, owner)
    }

'''
    source = replace_once(source, anchor, addition + anchor, "private routing primitives")
    source = replace_once(source, '''    @JvmStatic internal fun onUiClaimRetired(expected: WonadUiBridge.ShortcutClaim) {
        val owner = synchronized(lock) { owners[expected.display] }
        if (owner?.claim === expected) clear(owner)
    }
''', '''    @JvmStatic internal fun onUiClaimRetired(expected: WonadUiBridge.ShortcutClaim) {
        WonadPolicyKeyAdapter.onClaimRetired(expected)
        val owner = synchronized(lock) { owners[expected.display] }
        if (owner?.claim === expected) clear(owner)
    }
''', "retirement completion")
    source = replace_once(source, '''        val invalid = state != null && try {
            val now = SystemClock.elapsedRealtime()
            !claimActive(context, wm, state, now) ||
''', '''        val invalid = state != null && try {
            val now = SystemClock.elapsedRealtime()
            WonadPolicyKeyAdapter.claimBlocked(state.claim) ||
                !claimActive(context, wm, state, now) ||
''', "synchronous lifecycle block")
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
        (after - before).forEach { display ->
            shortcutClaimStates[display]?.claim?.let {
                WonadInputBridge.onUiClaimContainmentChanged(it, true)
            }
        }
        blankDisplays = nextBlank
        protectedInputDisplays = nextProtected
        (before - after).forEach { display ->
            shortcutClaimStates[display]?.claim?.let {
                WonadInputBridge.onUiClaimContainmentChanged(it, false)
            }
        }
    }
''', "containment publication")
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
''', '''    /** Mark exact pair state retired before unpublishing old authority. */
    private fun retireShortcutClaim(claim: Claim) {
        val previous = shortcutClaimStates[claim.dc.displayId]?.claim?.takeIf {
            it.incarnation == claim.incarnation
        } ?: return
        WonadInputBridge.onUiClaimRetiring(previous)
        shortcutClaimStates = shortcutClaimStates - claim.dc.displayId
        WonadInputBridge.onUiClaimRetired(previous)
    }
''', "retirement ordering")
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
''', "replacement retirement ordering")
    source = replace_once(source, '''        shortcutClaimStates = shortcutClaimStates + (claim.dc.displayId to
            ShortcutClaimState(token, claim.expires))
    }
''', '''        shortcutClaimStates = shortcutClaimStates + (claim.dc.displayId to
            ShortcutClaimState(token, claim.expires))
        if (consumeInput(token.display)) {
            WonadInputBridge.onUiClaimContainmentChanged(token, true)
        }
    }
''', "new token containment inheritance")
    return source


def dispatcher_entry(source: str) -> str:
    source = replace_once(source, '''        // The event should be sent to the application.
        CONTINUE,
        // The event should eventually be sent to the application, after a delay.
''', '''        // The event should be sent to the application.
        CONTINUE,
        // The exact event was admitted as healthy claimed Wonad application
        // input. InputDispatcher retains this marker through the app's
        // handled/unhandled completion and never infers it from later focus.
        CONTINUE_WONAD_CLAIMED,
        // The event should eventually be sent to the application, after a delay.
''', "native claimed application result")
    source = replace_once(source, '''    mutable InterceptKeyResult interceptKeyResult; // set based on the interception result
    mutable nsecs_t interceptKeyWakeupTime;        // used with INTERCEPT_KEY_RESULT_TRY_AGAIN_LATER
''', '''    mutable InterceptKeyResult interceptKeyResult; // set based on the interception result
    // Admission is immutable once policy returns the private -3 result. The
    // separate completion-owner state moves exactly once from the inbound
    // KeyEntry to one successfully enqueued foreground DispatchEntry, then to
    // either its handled/unhandled policy callback or its release cleanup.
    enum class WonadCompletionOwner { NONE, PENDING, FOREGROUND, TAKEN };
    mutable bool wonadClaimedAdmission = false;
    // Fresh signed-63-bit process nonce allocated under InputDispatcher's
    // lock before policy. Candidate persists across delay retries; token is
    // published only after Java returns the private claimed result.
    mutable int64_t wonadAdmissionCandidate = 0;
    mutable int64_t wonadAdmissionToken = 0;
    mutable ui::LogicalDisplayId wonadClaimedDisplayId =
            ui::LogicalDisplayId::INVALID;
    mutable WonadCompletionOwner wonadCompletionOwner = WonadCompletionOwner::NONE;
    // True only on real inbound release, not a move back into mInboundQueue.
    // Covers reset/filter/disable during the unlocked admission callback.
    mutable bool wonadInboundReleased = false;
    mutable nsecs_t interceptKeyWakeupTime;        // used with INTERCEPT_KEY_RESULT_TRY_AGAIN_LATER
''', "native claimed foreground lifetime")
    return replace_once(source, '''    std::optional<int32_t> windowId;

    DispatchEntry(std::shared_ptr<const EventEntry> eventEntry,
''', '''    std::optional<int32_t> windowId;

    // True only for the single foreground DispatchEntry which atomically took
    // a claimed KeyEntry's PENDING completion obligation at enqueue time.
    bool wonadClaimedCompletionOwner = false;

    DispatchEntry(std::shared_ptr<const EventEntry> eventEntry,
''', "foreground dispatch completion owner")


def dispatcher_policy(source: str) -> str:
    source = replace_once(source, '''    interceptKeyBeforeDispatching(const sp<IBinder>& token, const KeyEvent& keyEvent,
                                  uint32_t policyFlags) = 0;
''', '''    interceptKeyBeforeDispatching(const sp<IBinder>& token, const KeyEvent& keyEvent,
                                  uint32_t policyFlags,
                                  int64_t wonadAdmissionToken) = 0;
''', "policy admission nonce")
    source = replace_once(source, '''    virtual std::optional<KeyEvent> dispatchUnhandledKey(const sp<IBinder>& token,
                                                         const KeyEvent& keyEvent,
                                                         uint32_t policyFlags) = 0;
''', '''    virtual std::optional<KeyEvent> dispatchUnhandledKey(const sp<IBinder>& token,
                                                         const KeyEvent& keyEvent,
                                                         uint32_t policyFlags,
                                                         bool wonadClaimed,
                                                         int64_t wonadAdmissionToken,
                                                         ui::LogicalDisplayId wonadDisplayId) = 0;

    /* Releases one exact handled or undispatched Wonad event authority. */
    virtual void notifyWonadKeyHandled(const KeyEvent& keyEvent,
                                       int64_t wonadAdmissionToken,
                                       ui::LogicalDisplayId wonadDisplayId,
                                       bool abandoned) = 0;
''', "policy completion interface")
    return source


def fake_policy_header(source: str) -> str:
    source = replace_once(source, '''    interceptKeyBeforeDispatching(const sp<IBinder>&, const KeyEvent&, uint32_t) override;
''', '''    interceptKeyBeforeDispatching(const sp<IBinder>&, const KeyEvent&, uint32_t,
                                  int64_t) override;
''', "fake policy admission nonce")
    return replace_once(source, '''    std::optional<KeyEvent> dispatchUnhandledKey(const sp<IBinder>&, const KeyEvent& event,
                                                 uint32_t) override;
''', '''    std::optional<KeyEvent> dispatchUnhandledKey(const sp<IBinder>&, const KeyEvent& event,
                                                 uint32_t, bool, int64_t,
                                                 ui::LogicalDisplayId) override;
    void notifyWonadKeyHandled(const KeyEvent&, int64_t, ui::LogicalDisplayId, bool) override;
''', "fake policy completion declaration")


def fake_policy_cpp(source: str) -> str:
    source = replace_once(source, '''FakeInputDispatcherPolicy::interceptKeyBeforeDispatching(const sp<IBinder>&, const KeyEvent& event,
                                                         uint32_t) {
''', '''FakeInputDispatcherPolicy::interceptKeyBeforeDispatching(const sp<IBinder>&, const KeyEvent& event,
                                                         uint32_t, int64_t) {
''', "fake policy admission nonce implementation")
    source = replace_once(source, '''std::optional<KeyEvent> FakeInputDispatcherPolicy::dispatchUnhandledKey(const sp<IBinder>&,
                                                                        const KeyEvent& event,
                                                                        uint32_t) {
''', '''std::optional<KeyEvent> FakeInputDispatcherPolicy::dispatchUnhandledKey(const sp<IBinder>&,
                                                                        const KeyEvent& event,
                                                                        uint32_t, bool, int64_t,
                                                                        ui::LogicalDisplayId) {
''', "fake policy unhandled signature")
    marker = '''void FakeInputDispatcherPolicy::notifySwitch(nsecs_t when, uint32_t switchValues,
'''
    return replace_once(source, marker, '''void FakeInputDispatcherPolicy::notifyWonadKeyHandled(
        const KeyEvent&, int64_t, ui::LogicalDisplayId, bool) {}

''' + marker, "fake policy completion implementation")


def input_dispatcher(source: str) -> str:
    source = replace_once(source, '#include <cerrno>\n',
        '#include <atomic>\n#include <cerrno>\n', "nonce atomic include")
    source = replace_once(source, 'namespace {\n', '''namespace {

// Process-wide private signed63 nonce. INT64_MAX is issued once; zero is
// permanent exhaustion. No wrap and no dispatcher-recreation reuse.
int64_t nextWonadAdmissionToken() {
    static std::atomic<int64_t> next{1};
    int64_t candidate = next.load(std::memory_order_relaxed);
    while (candidate != 0) {
        const int64_t successor = candidate == INT64_MAX ? 0 : candidate + 1;
        if (next.compare_exchange_weak(candidate, successor, std::memory_order_relaxed)) {
            return candidate;
        }
    }
    return 0;
}
''', "process nonce allocator")
    source = replace_once(source, '''    KeyEvent event = createKeyEvent(entry);
    event.setDisplayId(displayId);
    std::variant<nsecs_t, KeyEntry::InterceptKeyResult> interceptResult;
''', '''    KeyEvent event = createKeyEvent(entry);
    event.setDisplayId(displayId);
    if (entry.wonadAdmissionCandidate == 0 && !entry.wonadInboundReleased) {
        entry.wonadAdmissionCandidate = nextWonadAdmissionToken();
    }
    const int64_t wonadAdmissionToken = entry.wonadAdmissionCandidate;
    std::variant<nsecs_t, KeyEntry::InterceptKeyResult> interceptResult;
''', "native admission nonce allocation")
    source = replace_once(source, '''                mPolicy.interceptKeyBeforeDispatching(focusedWindowToken, event, entry.policyFlags);
''', '''                mPolicy.interceptKeyBeforeDispatching(
                        focusedWindowToken, event, entry.policyFlags, wonadAdmissionToken);
''', "native admission nonce policy call")
    source = replace_once(source, '''    const KeyEntry& keyEntry = static_cast<const KeyEntry&>(*(eventEntry));
    // To prevent misuse, ensure dispatchEntry is no longer valid.
''', '''    const KeyEntry& keyEntry = static_cast<const KeyEntry&>(*(eventEntry));
    const bool wonadClaimed = hasForegroundTarget &&
            dispatchEntry->wonadClaimedCompletionOwner &&
            keyEntry.wonadClaimedAdmission &&
            keyEntry.wonadCompletionOwner == KeyEntry::WonadCompletionOwner::FOREGROUND;
    // Transfer the sole cleanup obligation before any interruptible policy
    // call. A concurrent queue drain now sees TAKEN and cannot post a second
    // cleanup for this Java record.
    if (wonadClaimed) {
        keyEntry.wonadCompletionOwner = KeyEntry::WonadCompletionOwner::TAKEN;
    }
    auto finishWonadHandled = [&]() REQUIRES(mLock) {
        if (!wonadClaimed) return;
        KeyEvent event = createKeyEvent(keyEntry);
        const int64_t admissionToken = keyEntry.wonadAdmissionToken;
        const ui::LogicalDisplayId admittedDisplay = keyEntry.wonadClaimedDisplayId;
        scoped_unlock unlock(mLock);
        mPolicy.notifyWonadKeyHandled(event, admissionToken, admittedDisplay, false);
    };
    // To prevent misuse, ensure dispatchEntry is no longer valid.
''', "native completion marker")
    source = replace_once(source, '''            mReporter->reportUnhandledKey(keyEntry.id);
        }
        return {};
    }

    // Get the fallback key state.
''', '''            mReporter->reportUnhandledKey(keyEntry.id);
        }
        if (wonadClaimed) finishWonadHandled();
        return {};
    }

    // Get the fallback key state.
''', "claimed injected fallback-flag early cleanup")
    source = replace_once(source, '''        return {};
    }

    // Get the fallback key state.
''', '''        return {};
    }
    // The immutable admission applies to every target of the KeyEntry. A
    // monitor must not run stock after-app policy or consume the foreground
    // target's exact Java completion authority.
    if (keyEntry.wonadClaimedAdmission && !wonadClaimed) return {};

    // Get the fallback key state.
''', "nonforeground claimed policy bypass")
    source = replace_once(source, '''                        mPolicy.dispatchUnhandledKey(connection->getToken(), event,
                                                     keyEntry.policyFlags);
''', '''                        mPolicy.dispatchUnhandledKey(connection->getToken(), event,
                                                     keyEntry.policyFlags, wonadClaimed,
                                                     keyEntry.wonadAdmissionToken,
                                                     keyEntry.wonadClaimedDisplayId);
''', "handled fallback exact marker")
    source = replace_once(source, '''            connection->inputState.removeFallbackKey(originalKeyCode);
        }
    } else {
''', '''            connection->inputState.removeFallbackKey(originalKeyCode);
        } else if (wonadClaimed) {
            finishWonadHandled();
        }
    } else {
''', "handled exact completion")
    source = replace_once(source, '''                       "not an initial down.  keyCode="
                    << originalKeyCode << ", action=" << keyEntry.action
                    << ", repeatCount=" << keyEntry.repeatCount << ", policyFlags=0x" << std::hex
                    << keyEntry.policyFlags;
            return {};
''', '''                       "not an initial down.  keyCode="
                    << originalKeyCode << ", action=" << keyEntry.action
                    << ", repeatCount=" << keyEntry.repeatCount << ", policyFlags=0x" << std::hex
                    << keyEntry.policyFlags;
            if (wonadClaimed) finishWonadHandled();
            return {};
''', "unhandled no-policy completion")
    source = replace_once(source, '''        if (auto fb = mPolicy.dispatchUnhandledKey(connection->getToken(), event,
                                                   keyEntry.policyFlags);
''', '''        if (auto fb = mPolicy.dispatchUnhandledKey(connection->getToken(), event,
                                                   keyEntry.policyFlags, wonadClaimed,
                                                   keyEntry.wonadAdmissionToken,
                                                   keyEntry.wonadClaimedDisplayId);
''', "unhandled exact marker")
    source = replace_once(source, '''        mLock.lock();

        if (connection->status != Connection::Status::NORMAL) {
''', '''        mLock.lock();

        if (connection->status != Connection::Status::NORMAL) {
''', "unhandled exact completion")
    source = replace_once(source, '''    // Remember that we are waiting for this dispatch to complete.
    if (dispatchEntry->hasForegroundTarget()) {
        incrementPendingForegroundDispatches(*eventEntry);
    }
''', '''    // Remember that we are waiting for this dispatch to complete.
    if (dispatchEntry->hasForegroundTarget()) {
        if (eventEntry->type == EventEntry::Type::KEY) {
            const KeyEntry& keyEntry = static_cast<const KeyEntry&>(*eventEntry);
            if (keyEntry.wonadClaimedAdmission &&
                keyEntry.wonadCompletionOwner ==
                        KeyEntry::WonadCompletionOwner::PENDING) {
                keyEntry.wonadCompletionOwner =
                        KeyEntry::WonadCompletionOwner::FOREGROUND;
                dispatchEntry->wonadClaimedCompletionOwner = true;
            }
        }
        incrementPendingForegroundDispatches(*eventEntry);
    }
''', "native foreground dispatch marker")
    source = replace_once(source, '''void InputDispatcher::releaseInboundEventLocked(std::shared_ptr<const EventEntry> entry) {
    const std::shared_ptr<InjectionState>& injectionState = entry->injectionState;
''', '''void InputDispatcher::releaseInboundEventLocked(std::shared_ptr<const EventEntry> entry) {
    if (entry->type == EventEntry::Type::KEY) {
        const KeyEntry& keyEntry = static_cast<const KeyEntry&>(*entry);
        keyEntry.wonadInboundReleased = true;
        if (keyEntry.wonadCompletionOwner ==
                KeyEntry::WonadCompletionOwner::PENDING) {
            KeyEvent event = createKeyEvent(keyEntry);
            const int64_t admissionToken = keyEntry.wonadAdmissionToken;
            const ui::LogicalDisplayId admittedDisplay = keyEntry.wonadClaimedDisplayId;
            keyEntry.wonadCompletionOwner = KeyEntry::WonadCompletionOwner::TAKEN;
            auto command = [this, event = std::move(event), admissionToken,
                            admittedDisplay]() REQUIRES(mLock) {
                scoped_unlock unlock(mLock);
                mPolicy.notifyWonadKeyHandled(event, admissionToken, admittedDisplay, true);
            };
            postCommandLocked(std::move(command));
        }
    }
    const std::shared_ptr<InjectionState>& injectionState = entry->injectionState;
''', "native undispatched cleanup")
    source = replace_once(source, '''void InputDispatcher::releaseDispatchEntry(std::unique_ptr<DispatchEntry> dispatchEntry) {
    if (dispatchEntry->hasForegroundTarget()) {
        decrementPendingForegroundDispatches(*(dispatchEntry->eventEntry));
    }
}
''', '''void InputDispatcher::releaseDispatchEntry(std::unique_ptr<DispatchEntry> dispatchEntry) {
    if (dispatchEntry->hasForegroundTarget()) {
        const std::shared_ptr<const EventEntry>& eventEntry = dispatchEntry->eventEntry;
        if (eventEntry->type == EventEntry::Type::KEY) {
            const KeyEntry& keyEntry = static_cast<const KeyEntry&>(*eventEntry);
            if (dispatchEntry->wonadClaimedCompletionOwner &&
                keyEntry.wonadCompletionOwner ==
                        KeyEntry::WonadCompletionOwner::FOREGROUND) {
                KeyEvent event = createKeyEvent(keyEntry);
                const int64_t admissionToken = keyEntry.wonadAdmissionToken;
                const ui::LogicalDisplayId admittedDisplay = keyEntry.wonadClaimedDisplayId;
                keyEntry.wonadCompletionOwner = KeyEntry::WonadCompletionOwner::TAKEN;
                auto command = [this, event = std::move(event), admissionToken,
                                admittedDisplay]() REQUIRES(mLock) {
                    scoped_unlock unlock(mLock);
                    mPolicy.notifyWonadKeyHandled(event, admissionToken, admittedDisplay, true);
                };
                postCommandLocked(std::move(command));
            }
        }
        decrementPendingForegroundDispatches(*eventEntry);
    }
}
''', "native broken-connection cleanup")
    source = replace_once(source, '''    if (std::holds_alternative<KeyEntry::InterceptKeyResult>(interceptResult)) {
        entry.interceptKeyResult = std::get<KeyEntry::InterceptKeyResult>(interceptResult);
        return;
    }
''', '''    if (std::holds_alternative<KeyEntry::InterceptKeyResult>(interceptResult)) {
        entry.interceptKeyResult = std::get<KeyEntry::InterceptKeyResult>(interceptResult);
        if (entry.interceptKeyResult ==
                KeyEntry::InterceptKeyResult::CONTINUE_WONAD_CLAIMED) {
            if (wonadAdmissionToken <= 0 || entry.wonadInboundReleased) {
                entry.interceptKeyResult = KeyEntry::InterceptKeyResult::SKIP;
                entry.wonadCompletionOwner = KeyEntry::WonadCompletionOwner::TAKEN;
                // A real release during policy unlock cannot acquire a new
                // pending obligation. Clean the exact orphan registration.
                scoped_unlock unlock(mLock);
                mPolicy.notifyWonadKeyHandled(event, wonadAdmissionToken, displayId, true);
            } else {
                entry.wonadClaimedAdmission = true;
                entry.wonadAdmissionToken = wonadAdmissionToken;
                entry.wonadClaimedDisplayId = displayId;
                entry.wonadCompletionOwner = KeyEntry::WonadCompletionOwner::PENDING;
            }
        }
        return;
    }
''', "native exact admission publication")
    return source


def input_manager_jni(source: str) -> str:
    source = replace_once(source, '''    interceptKeyBeforeDispatching(const sp<IBinder>& token, const KeyEvent& keyEvent,
                                  uint32_t policyFlags) override;
''', '''    interceptKeyBeforeDispatching(const sp<IBinder>& token, const KeyEvent& keyEvent,
                                  uint32_t policyFlags, int64_t wonadAdmissionToken) override;
''', "JNI admission declaration")
    source = replace_once(source, '''                                                  const KeyEvent& keyEvent, uint32_t policyFlags) {
''', '''                                                  const KeyEvent& keyEvent, uint32_t policyFlags,
                                                  int64_t wonadAdmissionToken) {
''', "JNI admission implementation")
    source = replace_once(source, '''                                tokenObj.get(), keyEventObj.get(), policyFlags);
''', '''                                tokenObj.get(), keyEventObj.get(), policyFlags,
                                static_cast<jlong>(wonadAdmissionToken));
''', "JNI admission argument")
    source = replace_once(source, '''            "(Landroid/os/IBinder;Landroid/view/KeyEvent;I)J");
''', '''            "(Landroid/os/IBinder;Landroid/view/KeyEvent;IJ)J");
''', "JNI admission binding")
    source = replace_once(source, '''    jmethodID dispatchUnhandledKey;
    jmethodID onPointerDownOutsideFocus;
''', '''    jmethodID dispatchUnhandledKey;
    jmethodID notifyWonadKeyHandled;
    jmethodID onPointerDownOutsideFocus;
''', "JNI completion method id")
    source = replace_once(source, '''    std::optional<KeyEvent> dispatchUnhandledKey(const sp<IBinder>& token, const KeyEvent& keyEvent,
                                                 uint32_t policyFlags) override;
    void pokeUserActivity(nsecs_t eventTime, int32_t eventType,
''', '''    std::optional<KeyEvent> dispatchUnhandledKey(const sp<IBinder>& token, const KeyEvent& keyEvent,
                                                 uint32_t policyFlags,
                                                 bool wonadClaimed,
                                                 int64_t wonadAdmissionToken,
                                                 ui::LogicalDisplayId wonadDisplayId) override;
    void notifyWonadKeyHandled(const KeyEvent& keyEvent,
                               int64_t wonadAdmissionToken,
                               ui::LogicalDisplayId wonadDisplayId, bool abandoned) override;
    void pokeUserActivity(nsecs_t eventTime, int32_t eventType,
''', "JNI completion declaration")
    source = replace_once(source, '''    // -2 : Skip sending even to application and go directly to post processing e.g. fallbacks.
    if (delayMillis == -2) {
        return inputdispatcher::KeyEntry::InterceptKeyResult::FALLBACK;
    }

    return milliseconds_to_nanoseconds(delayMillis);
''', '''    // -2 : Skip sending even to application and go directly to post processing e.g. fallbacks.
    if (delayMillis == -2) {
        return inputdispatcher::KeyEntry::InterceptKeyResult::FALLBACK;
    }

    // -3 : Deliver while retaining exact native completion authority.
    if (delayMillis == -3) {
        return inputdispatcher::KeyEntry::InterceptKeyResult::CONTINUE_WONAD_CLAIMED;
    }

    if (delayMillis < 0) {
        ALOGE("Malformed negative key interception result: %" PRId64, delayMillis);
        return inputdispatcher::KeyEntry::InterceptKeyResult::SKIP;
    }

    // Prevent duration/wakeup overflow for malformed positive policy.
    if (delayMillis > 60000) {
        ALOGE("Excessive key interception delay: %" PRId64, delayMillis);
        return inputdispatcher::KeyEntry::InterceptKeyResult::SKIP;
    }
    return milliseconds_to_nanoseconds(delayMillis);
''', "JNI claimed result decode")
    source = replace_once(source, '''    if (checkAndClearExceptionFromCallback(env, "interceptKeyBeforeDispatching")) {
        return 0;
    }
''', '''    if (checkAndClearExceptionFromCallback(env, "interceptKeyBeforeDispatching")) {
        return inputdispatcher::KeyEntry::InterceptKeyResult::SKIP;
    }
''', "JNI interception exception cleanup")
    source = replace_once(source, '''    android_view_KeyEvent_recycle(env, keyEventObj.get());
    if (checkAndClearExceptionFromCallback(env, "interceptKeyBeforeDispatching")) {
        return inputdispatcher::KeyEntry::InterceptKeyResult::SKIP;
    }
''', '''    // Clear a callback exception before any further JNI call. Java finally
    // already rolled back this invocation's exact record on callback failure.
    const bool callbackFailed =
            checkAndClearExceptionFromCallback(env, "interceptKeyBeforeDispatching");
    android_view_KeyEvent_recycle(env, keyEventObj.get());
    const bool recycleFailed =
            checkAndClearExceptionFromCallback(env, "recycle intercepted KeyEvent");
    if (callbackFailed || recycleFailed) {
        // Only an accepted -3 from this very invocation can own a record.
        // A duplicate/non--3 return must never erase an older registration.
        if (!callbackFailed && delayMillis == -3) {
            notifyWonadKeyHandled(keyEvent, wonadAdmissionToken, keyEvent.getDisplayId(), true);
        }
        return inputdispatcher::KeyEntry::InterceptKeyResult::SKIP;
    }
''', "JNI post-commit recycle failure rollback")
    source = replace_once(source, '''std::optional<KeyEvent> NativeInputManager::dispatchUnhandledKey(const sp<IBinder>& token,
                                                                 const KeyEvent& keyEvent,
                                                                 uint32_t policyFlags) {
''', '''std::optional<KeyEvent> NativeInputManager::dispatchUnhandledKey(const sp<IBinder>& token,
                                                                 const KeyEvent& keyEvent,
                                                                 uint32_t policyFlags,
                                                                 bool wonadClaimed,
                                                                 int64_t wonadAdmissionToken,
                                                                 ui::LogicalDisplayId wonadDisplayId) {
''', "JNI unhandled signature")
    source = replace_once(source, '''    if ((policyFlags & POLICY_FLAG_TRUSTED) == 0) {
        return {};
    }

    JNIEnv* env = jniEnv();
''', '''    if ((policyFlags & POLICY_FLAG_TRUSTED) == 0) {
        if (wonadClaimed) {
            notifyWonadKeyHandled(keyEvent, wonadAdmissionToken, wonadDisplayId, true);
        }
        return {};
    }

    JNIEnv* env = jniEnv();
''', "untrusted completion cleanup")
    source = replace_once(source, '''    if (!keyEventObj.get()) {
        ALOGE("Failed to obtain key event object for dispatchUnhandledKey.");
        return {};
    }
''', '''    if (!keyEventObj.get()) {
        ALOGE("Failed to obtain key event object for dispatchUnhandledKey.");
        checkAndClearExceptionFromCallback(env, "obtain unhandled KeyEvent");
        if (wonadClaimed) {
            notifyWonadKeyHandled(keyEvent, wonadAdmissionToken, wonadDisplayId, true);
        }
        return {};
    }
''', "unhandled copy failure cleanup")
    source = replace_once(source, '''                                                      tokenObj.get(), keyEventObj.get(),
                                                      policyFlags));
''', '''                                                      tokenObj.get(), keyEventObj.get(),
                                                      policyFlags,
                                                      wonadClaimed ? JNI_TRUE : JNI_FALSE,
                                                      static_cast<jlong>(wonadAdmissionToken),
                                                      wonadDisplayId.val()));
''', "JNI unhandled exact marker")
    source = replace_once(source, '''    if (checkAndClearExceptionFromCallback(env, "dispatchUnhandledKey") ||
        !fallbackKeyEventObj.get()) {
        return {};
    }
''', '''    if (checkAndClearExceptionFromCallback(env, "dispatchUnhandledKey")) {
        if (wonadClaimed) {
            notifyWonadKeyHandled(keyEvent, wonadAdmissionToken, wonadDisplayId, true);
        }
        return {};
    }
    if (!fallbackKeyEventObj.get()) {
        return {};
    }
''', "unhandled callback exception cleanup")
    source = replace_once(source, '''    android_view_KeyEvent_recycle(env, keyEventObj.get());
    if (checkAndClearExceptionFromCallback(env, "dispatchUnhandledKey")) {
''', '''    const bool unhandledFailed =
            checkAndClearExceptionFromCallback(env, "dispatchUnhandledKey");
    android_view_KeyEvent_recycle(env, keyEventObj.get());
    const bool unhandledRecycleFailed =
            checkAndClearExceptionFromCallback(env, "recycle unhandled KeyEvent");
    if (unhandledFailed || unhandledRecycleFailed) {
''', "JNI unhandled exception clear before recycle")
    marker = '''void NativeInputManager::pokeUserActivity(nsecs_t eventTime, int32_t eventType,
'''
    completion = '''void NativeInputManager::notifyWonadKeyHandled(
        const KeyEvent& keyEvent, int64_t wonadAdmissionToken,
        ui::LogicalDisplayId wonadDisplayId, bool abandoned) {
    JNIEnv* env = jniEnv();
    ScopedLocalFrame localFrame(env);
    env->CallVoidMethod(mServiceObj, gServiceClassInfo.notifyWonadKeyHandled,
                        static_cast<jlong>(wonadAdmissionToken),
                        keyEvent.getId(), keyEvent.getDeviceId(), keyEvent.getKeyCode(),
                        nanoseconds_to_milliseconds(keyEvent.getDownTime()), wonadDisplayId.val(),
                        abandoned ? JNI_TRUE : JNI_FALSE);
    checkAndClearExceptionFromCallback(env, "notifyWonadKeyHandled");
}

'''
    source = replace_once(source, marker, completion + marker,
        "JNI completion implementation")
    source = replace_once(source, '''    GET_METHOD_ID(gServiceClassInfo.dispatchUnhandledKey, clazz,
            "dispatchUnhandledKey",
            "(Landroid/os/IBinder;Landroid/view/KeyEvent;I)Landroid/view/KeyEvent;");

    GET_METHOD_ID(gServiceClassInfo.notifyStickyModifierStateChanged, clazz,
''', '''    GET_METHOD_ID(gServiceClassInfo.dispatchUnhandledKey, clazz,
            "dispatchUnhandledKey",
            "(Landroid/os/IBinder;Landroid/view/KeyEvent;IZJI)Landroid/view/KeyEvent;");

    GET_METHOD_ID(gServiceClassInfo.notifyWonadKeyHandled, clazz,
            "notifyWonadKeyHandled", "(JIIIJIZ)V");

    GET_METHOD_ID(gServiceClassInfo.notifyStickyModifierStateChanged, clazz,
''', "JNI completion method binding")
    return source


def input_manager_service(source: str) -> str:
    source = replace_once(source, '''    long interceptKeyBeforeDispatching(IBinder focus, KeyEvent event, int policyFlags) {
        return mKeyGestureController.interceptKeyBeforeDispatching(focus, event, policyFlags);
    }
''', '''    long interceptKeyBeforeDispatching(IBinder focus, KeyEvent event, int policyFlags,
            long wonadAdmissionToken) {
        final Object wonadCall = org.wonad.server.input.WonadPolicyKeyAdapter
                .beginAdmissionCall(wonadAdmissionToken);
        long result = -1;
        try {
            result = mKeyGestureController.interceptKeyBeforeDispatching(
                    focus, event, policyFlags, wonadAdmissionToken);
        } finally {
            result = org.wonad.server.input.WonadPolicyKeyAdapter.finishAdmissionCall(
                    wonadCall, result);
        }
        return result;
    }
''', "native admission candidate delegation")
    source = replace_once(source, '''        mKeyGestureController = new KeyGestureController(mContext, injector.getLooper(),
                injector.getIoLooper(), mInputDataStore);
''', '''        mKeyGestureController = new KeyGestureController(mContext, injector.getLooper(),
                injector.getIoLooper(), mInputDataStore, mNative);
''', "native census injection")
    source = replace_once(source, '''    private KeyEvent dispatchUnhandledKey(IBinder focus, KeyEvent event, int policyFlags) {
        if (interceptUnhandledKey(event, focus)) {
''', '''    private KeyEvent dispatchUnhandledKey(IBinder focus, KeyEvent event, int policyFlags,
            boolean wonadClaimed, long wonadAdmissionToken, int wonadDisplayId) {
        Object wonadUnhandledScope = null;
        try {
        wonadUnhandledScope = org.wonad.server.input.WonadPolicyKeyAdapter.beginUnhandled(
                mWindowManagerInternal, focus, event, wonadClaimed,
                wonadAdmissionToken, wonadDisplayId);
        if (wonadClaimed && (focus == null || wonadUnhandledScope == null)) return null;
        if (interceptUnhandledKey(event, focus)) {
''', "exact unhandled completion scope")
    source = replace_once(source, '''        return fallbackEvent;
    }

    private boolean interceptFallback(IBinder focusedToken, KeyEvent fallbackEvent,
''', '''        return fallbackEvent;
        } finally {
            if (wonadClaimed && wonadUnhandledScope == null) {
                org.wonad.server.input.WonadPolicyKeyAdapter.finishHandled(
                        wonadAdmissionToken, event.getId(), event.getDeviceId(), event.getKeyCode(),
                        event.getDownTime(), wonadDisplayId, true);
            }
            org.wonad.server.input.WonadPolicyKeyAdapter.endUnhandled(
                    wonadUnhandledScope);
        }
    }

    private void notifyWonadKeyHandled(long wonadAdmissionToken,
            int eventId, int deviceId, int keyCode,
            long downTime, int wonadDisplayId, boolean abandoned) {
        org.wonad.server.input.WonadPolicyKeyAdapter.finishHandled(
                wonadAdmissionToken, eventId, deviceId, keyCode, downTime, wonadDisplayId, abandoned);
    }

    private boolean interceptFallback(IBinder focusedToken, KeyEvent fallbackEvent,
''', "exact handled completion callback")
    source = replace_once(source, '''        if (!interceptFallback(focus, fallbackEvent, policyFlags)) {
            fallbackEvent.recycle();
            fallbackEvent = null;
        }
''', '''        final Object wonadFallbackScope =
                org.wonad.server.input.WonadPolicyKeyAdapter.beginFallback(
                        focus, event, fallbackEvent);
        try {
            if (!interceptFallback(focus, fallbackEvent, policyFlags)) {
                fallbackEvent.recycle();
                fallbackEvent = null;
            }
        } finally {
            org.wonad.server.input.WonadPolicyKeyAdapter.endFallback(wonadFallbackScope);
        }
''', "exact fallback scope")
    source = replace_once(source, '''    private boolean interceptUnhandledKey(KeyEvent event, IBinder focus) {
        if (mKeyGestureController.interceptUnhandledKey(event, focus)) {
''', '''    private boolean interceptUnhandledKey(KeyEvent event, IBinder focus) {
        // Skip KGC/PWM stock shortcut stages for the exact event which was
        // delivered from a claimed external origin. Returning false still
        // permits ordinary KeyCharacterMap fallback generation.
        if (org.wonad.server.input.WonadPolicyKeyAdapter.bypassUnhandledStock(
                focus, event)) {
            return false;
        }
        if (mKeyGestureController.interceptUnhandledKey(event, focus)) {
''', "unhandled stock bypass")
    source = replace_once(source, '''        long delayMillis = interceptKeyBeforeDispatching(focusedToken, fallbackEvent, policyFlags);
''', '''        long delayMillis = interceptKeyBeforeDispatching(
                focusedToken, fallbackEvent, policyFlags, 0L);
''', "fallback cannot acquire native admission authority")
    return replace_once(source, '''    private boolean interceptFallback(IBinder focusedToken, KeyEvent fallbackEvent,
            int policyFlags) {
        int actions = interceptKeyBeforeQueueing(fallbackEvent, policyFlags);
''', '''    private boolean interceptFallback(IBinder focusedToken, KeyEvent fallbackEvent,
            int policyFlags) {
        // A fallback derived from a claimed app event must not first execute
        // PhoneWindowManager/global queue-time policy. KGC below will either
        // deliver an ordinary fallback to the same claimed app lineage or
        // consume a fallback which maps to an Android UI/system-action key.
        int actions = org.wonad.server.input.WonadPolicyKeyAdapter.bypassFallbackQueueing(
                focusedToken, fallbackEvent)
                ? ACTION_PASS_TO_USER
                : interceptKeyBeforeQueueing(fallbackEvent, policyFlags);
''', "fallback queue-stage bypass")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit(f"output exists: {args.output}")
    for label, (path, expected) in {**INPUTS, **SUPPORT_INPUTS}.items():
        observed = digest(path)
        if observed != expected:
            raise SystemExit(f"{label} input changed: {observed} != {expected}")

    outputs = {
        "InputManagerService.java": input_manager_service(INPUTS["ims"][0].read_text()),
        "KeyGestureController.java": key_gesture_controller(INPUTS["kgc"][0].read_text()),
        "WonadInputBridge.kt": input_bridge(INPUTS["bridge"][0].read_text()),
        "WonadUiBridge.kt": ui_bridge(INPUTS["ui"][0].read_text()),
        "Entry.h": dispatcher_entry(INPUTS["entry"][0].read_text()),
        "InputDispatcher.cpp": input_dispatcher(INPUTS["dispatcher"][0].read_text()),
        "InputDispatcherPolicyInterface.h": dispatcher_policy(
            INPUTS["dispatcher_policy"][0].read_text()),
        "FakeInputDispatcherPolicy.h": fake_policy_header(
            INPUTS["fake_policy_h"][0].read_text()),
        "FakeInputDispatcherPolicy.cpp": fake_policy_cpp(
            INPUTS["fake_policy_cpp"][0].read_text()),
        "com_android_server_input_InputManagerService.cpp": input_manager_jni(
            INPUTS["ims_jni"][0].read_text()),
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
