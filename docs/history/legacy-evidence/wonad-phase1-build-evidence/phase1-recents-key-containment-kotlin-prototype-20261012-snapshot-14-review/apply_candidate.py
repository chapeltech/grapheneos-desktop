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
}

# Source evidence for the deliberately retained pre-seam global-safety and
# resolver behavior. These files are not rewritten.
SUPPORT_INPUTS = {
    "PhoneWindowManager.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/policy/PhoneWindowManager.java",
        "25be0cd9384ef463af854067e4904701041ece23ef0e9b9f8cc348503e6e1898",
    ),
    "KeyboardInputMapper.cpp": (
        STAGE / "frameworks/native/services/inputflinger/reader/mapper/KeyboardInputMapper.cpp",
        "0a8bc5d7d66b02d4faac11f9c8252e6bb059f7ad2f4cbbae80865d32a810f303",
    ),
    "InputDispatcher.cpp": (
        STAGE / "frameworks/native/services/inputflinger/dispatcher/InputDispatcher.cpp",
        "4598e3a96e0196a5965be2a4232736ba7e14616c8435b201ab6d394e44b762c9",
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
            return KEY_INTERCEPT_RESULT_NOT_CONSUMED;
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


def input_manager_service(source: str) -> str:
    source = replace_once(source, '''        mKeyGestureController = new KeyGestureController(mContext, injector.getLooper(),
                injector.getIoLooper(), mInputDataStore);
''', '''        mKeyGestureController = new KeyGestureController(mContext, injector.getLooper(),
                injector.getIoLooper(), mInputDataStore, mNative);
''', "native census injection")
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
