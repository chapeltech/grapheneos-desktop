#!/usr/bin/env python3
"""External-only compiled checks for the proposed Recents-key containment patch.

The checked Java is extracted from the candidate copies in this directory.  These
tests do not qualify or modify a GrapheneOS build.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
JDK = pathlib.Path(
    "/u/elric/tree/wonad/android/out/phase1-client-tools-image-20261011-3/"
    "rootfs/usr/lib/jvm/java-21-openjdk-amd64/bin"
)
JDK_ROOTFS = pathlib.Path(
    "/u/elric/tree/wonad/android/out/phase1-client-tools-image-20261011-3/rootfs"
)
JAVAC = JDK / "javac"
JAVA = JDK / "java"
INPUT_KGC = ROOT / "inputs/KeyGestureController.java"
INPUT_PWM = ROOT / "inputs/PhoneWindowManager.java"
CANDIDATE_KGC = ROOT / "candidate/KeyGestureController.java"
CANDIDATE_PWM = ROOT / "candidate/PhoneWindowManager.java"

INPUT_KGC_SHA256 = "3acaa08d5a39200bbcd521f760339c4d531936656899c195b9b9fa9b28aa66c5"
INPUT_PWM_SHA256 = "25be0cd9384ef463af854067e4904701041ece23ef0e9b9f8cc348503e6e1898"


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def java_block(source: str, marker: str) -> str:
    start = source.index(marker)
    brace = source.index("{", start)
    depth = 0
    for offset in range(brace, len(source)):
        char = source[offset]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : offset + 1]
    raise AssertionError(f"unterminated Java block for {marker!r}")


def compile_and_run(files: dict[str, str], main_class: str) -> str:
    with tempfile.TemporaryDirectory(prefix="wonad-recents-containment-") as raw:
        root = pathlib.Path(raw)
        # The retained tools rootfs uses absolute /etc symlinks. Build a private
        # java.home view so javac reads the authenticated rootfs configuration
        # without modifying that immutable input or the host.
        java_home = root / "java-home"
        java_home.mkdir()
        (java_home / "bin").symlink_to(JDK)
        (java_home / "lib").symlink_to(JDK.parent / "lib")
        (java_home / "jmods").symlink_to(JDK.parent / "jmods")
        shutil.copytree(JDK_ROOTFS / "etc/java-21-openjdk", java_home / "conf")
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        sources = sorted(str(path) for path in root.rglob("*.java"))
        compiled = subprocess.run(
            [str(JAVAC), f"-J-Djava.home={java_home}", "-Werror", "-Xlint:all",
             "-d", str(root / "classes"), *sources],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if compiled.returncode:
            raise AssertionError(f"javac failed:\n{compiled.stdout}\n{compiled.stderr}")
        ran = subprocess.run(
            [str(JAVA), f"-Djava.home={java_home}", "-cp", str(root / "classes"), main_class],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if ran.returncode:
            raise AssertionError(f"java failed:\n{ran.stdout}\n{ran.stderr}")
        return ran.stdout


ANDROID_STUBS = {
    "android/annotation/NonNull.java": """
        package android.annotation;
        import java.lang.annotation.*;
        @Retention(RetentionPolicy.SOURCE) public @interface NonNull {}
    """,
    "android/annotation/Nullable.java": """
        package android.annotation;
        import java.lang.annotation.*;
        @Retention(RetentionPolicy.SOURCE) public @interface Nullable {}
    """,
    "android/os/IBinder.java": "package android.os; public interface IBinder {}",
    "android/os/Handler.java": """
        package android.os;
        public class Handler {
            public int removes;
            public Object lastRemoved;
            public void removeMessages(int what, Object object) {
                removes++; lastRemoved = object;
            }
        }
    """,
    "android/util/SparseArray.java": """
        package android.util;
        import java.util.LinkedHashMap;
        import java.util.ArrayList;
        public final class SparseArray<E> {
            private final LinkedHashMap<Integer, E> values = new LinkedHashMap<>();
            public E get(int key) { return values.get(key); }
            public void put(int key, E value) { values.put(key, value); }
            public void remove(int key) { values.remove(key); }
            public int size() { return values.size(); }
            public E valueAt(int index) { return new ArrayList<>(values.values()).get(index); }
            public int keyAt(int index) { return new ArrayList<>(values.keySet()).get(index); }
            public void removeAt(int index) { values.remove(keyAt(index)); }
        }
    """,
    "android/util/SparseIntArray.java": """
        package android.util;
        import java.util.HashMap;
        public final class SparseIntArray {
            private final HashMap<Integer, Integer> values = new HashMap<>();
            public int get(int key, int fallback) { return values.getOrDefault(key, fallback); }
            public void put(int key, int value) { values.put(key, value); }
            public void delete(int key) { values.remove(key); }
            public int size() { return values.size(); }
        }
    """,
    "android/view/KeyEvent.java": """
        package android.view;
        public final class KeyEvent {
            public static final int ACTION_DOWN = 0;
            public static final int ACTION_UP = 1;
            public static final int KEYCODE_APP_SWITCH = 187;
            public static final int KEYCODE_RECENT_APPS = 312;
            public static final int KEYCODE_ALL_APPS = 284;
            public static final int KEYCODE_SCREENSHOT = 120;
            public static final int KEYCODE_FULLSCREEN = 325;
            public static final int KEYCODE_ESCAPE = 111;
            public static final int KEYCODE_LOCK = 324;
            public static final int KEYCODE_BRIGHTNESS_UP = 221;
            public static final int KEYCODE_KEYBOARD_BACKLIGHT_TOGGLE = 307;
            public static final int KEYCODE_DO_NOT_DISTURB = 326;
            public static final int KEYCODE_F1 = 131;
            private final int action, keyCode, deviceId, displayId, repeatCount, metaState;
            private final long downTime;
            private final boolean canceled, blocked;
            public KeyEvent(int action, int keyCode, int deviceId, int displayId,
                    int repeatCount, int metaState, long downTime,
                    boolean canceled, boolean blocked) {
                this.action = action; this.keyCode = keyCode; this.deviceId = deviceId;
                this.displayId = displayId; this.repeatCount = repeatCount;
                this.metaState = metaState; this.downTime = downTime;
                this.canceled = canceled; this.blocked = blocked;
            }
            public int getAction() { return action; }
            public int getKeyCode() { return keyCode; }
            public int getDeviceId() { return deviceId; }
            public int getDisplayId() { return displayId; }
            public int getRepeatCount() { return repeatCount; }
            public int getMetaState() { return metaState; }
            public long getDownTime() { return downTime; }
            public boolean isCanceled() { return canceled; }
            public boolean blocked() { return blocked; }
        }
    """,
    "android/hardware/input/KeyGestureEvent.java": """
        package android.hardware.input;
        public final class KeyGestureEvent {
            public static final int KEY_GESTURE_TYPE_APP_SWITCH = 1;
            public static final int KEY_GESTURE_TYPE_LAUNCH_ASSISTANT = 2;
            public static final int KEY_GESTURE_TYPE_QUIT_FOCUSED_TASK = 5;
            public static final int ACTION_GESTURE_START = 3;
            public static final int ACTION_GESTURE_COMPLETE = 4;
            public static final int FLAG_CANCELLED = 8;
            private final int action, type, deviceId, displayId;
            private final boolean cancelled;
            public KeyGestureEvent(int action, int type, boolean cancelled) {
                this(action, type, cancelled, 1, 3);
            }
            public KeyGestureEvent(int action, int type, boolean cancelled,
                    int deviceId, int displayId) {
                this.action = action; this.type = type; this.cancelled = cancelled;
                this.deviceId = deviceId; this.displayId = displayId;
            }
            public int getAction() { return action; }
            public int getKeyGestureType() { return type; }
            public boolean isCancelled() { return cancelled; }
            public int getDeviceId() { return deviceId; }
            public int getDisplayId() { return displayId; }
        }
    """,
    "android/hardware/input/AidlKeyGestureEvent.java": """
        package android.hardware.input;
        public final class AidlKeyGestureEvent { public int marker; }
    """,
}


class CandidateTests(unittest.TestCase):
    maxDiff = None

    def test_authenticated_preimages_and_original_defect(self) -> None:
        self.assertEqual(sha256(INPUT_KGC), INPUT_KGC_SHA256)
        self.assertEqual(sha256(INPUT_PWM), INPUT_PWM_SHA256)
        original = INPUT_KGC.read_text(encoding="utf-8")
        dispatch = java_block(original, "public long interceptKeyBeforeDispatching(")
        self.assertNotIn("interceptWonadContainedBeforeKeyCapture", dispatch)
        stock = dispatch.index("INTERCEPT_STAGE_SHORTCUTS_BEFORE_KEY_CAPTURE).interceptKey")
        self.assertGreater(dispatch.index("WonadInputBridge.consumeClaimedInput", stock), stock)
        original_pwm = INPUT_PWM.read_text(encoding="utf-8")
        app_switch = original_pwm[
            original_pwm.index("case KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH:") :
            original_pwm.index("case KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_ASSISTANT:")
        ]
        self.assertNotIn("cancelPreloadRecentApps", app_switch)

    def test_candidate_order_is_generic_after_explicit_priorities(self) -> None:
        source = CANDIDATE_KGC.read_text(encoding="utf-8")
        dispatch = java_block(source, "public long interceptKeyBeforeDispatching(")
        target = dispatch.index("interceptWonadContainedBeforeKeyCapture")
        self.assertGreater(target, dispatch.index("WonadInputBridge.intercept("))
        self.assertGreater(target, dispatch.index("SecurePasteKeyEventHandler.isPasteKeyEvent"))
        self.assertLess(target, dispatch.index("shouldInterceptShortcuts(focus)"))
        self.assertLess(
            target,
            dispatch.index("INTERCEPT_STAGE_SHORTCUTS_BEFORE_KEY_CAPTURE).interceptKey"),
        )
        self.assertEqual(dispatch.count("interceptWonadContainedBeforeKeyCapture"), 1)
        guard = java_block(source, "private boolean interceptWonadContainedBeforeKeyCapture(")
        self.assertLess(guard.index("WonadInputBridge.consumeClaimedInput"),
                        guard.index("keyCode != KeyEvent.KEYCODE_APP_SWITCH"))
        self.assertIn("KEYCODE_RECENT_APPS", guard)
        self.assertIn("decision.cancelStockAppSwitch", guard)
        self.assertIn("KEYCODE_ESCAPE", guard)
        self.assertIn("forgetConsumedKey(event.getDeviceId(), keyCode)", guard)

    def test_exact_state_helper_compiles_and_drains_pairs(self) -> None:
        source = CANDIDATE_KGC.read_text(encoding="utf-8")
        helper = java_block(source, "private static final class WonadRecentsKeyContainment")
        harness = f"""
            package com.android.server.input;
            import android.annotation.NonNull;
            import android.util.SparseArray;
            import android.util.SparseIntArray;
            import android.view.KeyEvent;
            import java.util.ArrayList;
            import java.util.List;
            import java.util.function.IntPredicate;
            public final class StateHarness {{
                {helper}
                private static KeyEvent e(int action, int key, int device, int display,
                        int repeat, long downTime, boolean canceled) {{
                    return new KeyEvent(action, key, device, display, repeat, 0, downTime,
                            canceled, false);
                }}
                private static void check(boolean value, String message) {{
                    if (!value) throw new AssertionError(message);
                }}
                public static void main(String[] ignored) {{
                    final int down = KeyEvent.ACTION_DOWN, up = KeyEvent.ACTION_UP;
                    final int app = KeyEvent.KEYCODE_APP_SWITCH;
                    final int recent = KeyEvent.KEYCODE_RECENT_APPS;
                    WonadRecentsKeyContainment m = new WonadRecentsKeyContainment();
                    WonadRecentsKeyContainment.Decision d = m.onKeyEvent(
                            e(down, 99, 1, 3, 0, 1, false), true, false, true);
                    check(!d.consume && !d.forgetStockPair && !d.cancelStockAppSwitch,
                            "unrelated key");

                    d = m.onKeyEvent(e(down, app, 1, 0, 0, 10, false), false, false, true);
                    check(!d.consume, "healthy phone down unchanged");
                    d = m.onKeyEvent(e(up, app, 1, 0, 0, 10, false), false, true, false);
                    check(!d.consume, "healthy phone up unchanged");
                    d = m.onKeyEvent(e(up, app, 1, 0, 0, 10, false), false, false, false);
                    check(d.consume, "unowned duplicate up cannot toggle Recents");

                    m = new WonadRecentsKeyContainment();
                    d = m.onKeyEvent(e(down, app, 2, 3, 0, 20, false), true, false, true);
                    check(d.consume, "blocked initial external down");
                    d = m.onKeyEvent(e(down, app, 2, 0, 1, 20, false), false, false, false);
                    check(d.consume, "same pair drains across focus/display migration");
                    d = m.onKeyEvent(e(up, app, 2, 0, 0, 20, false), false, false, false);
                    check(d.consume && m.mPairsForDevice.size() == 0,
                            "recovered up drains and clears pair");

                    // Lost external UP must not poison a fresh phone pair reusing device/key.
                    m = new WonadRecentsKeyContainment();
                    check(m.onKeyEvent(e(down, app, 7, 3, 0, 100, false), true, false, true).consume,
                            "old blocked external down");
                    d = m.onKeyEvent(e(down, app, 7, 0, 0, 200, false), false, false, true);
                    check(!d.consume && !d.forgetStockPair && !d.cancelStockAppSwitch,
                            "fresh phone down retires stale drain");
                    check(m.onKeyEvent(e(up, app, 7, 3, 0, 100, false), false, true, false).consume,
                            "late old up cannot complete replacement");
                    check(!m.onKeyEvent(e(up, app, 7, 0, 0, 200, false), false, true, false).consume,
                            "fresh phone up reaches stock");
                    check(m.mPairsForDevice.size() == 0, "replacement pair leaves no state");

                    // A new first DOWN also retires an in-flight stock pair, asks the caller to
                    // cancel only the old display owner, and lets the replacement reach stock.
                    m = new WonadRecentsKeyContainment();
                    check(!m.onKeyEvent(e(down, app, 8, 3, 0, 300, false),
                            false, false, true).consume, "old healthy stock down");
                    d = m.onKeyEvent(e(down, app, 8, 0, 0, 400, false),
                            false, true, true);
                    check(!d.consume && d.forgetStockPair && d.cancelStockAppSwitch
                            && d.cancelDisplayId == 3, "replacement cancels exact old owner");
                    check(m.onKeyEvent(e(up, app, 8, 3, 0, 300, false),
                            false, true, false).consume, "stale old up isolated");
                    check(!m.onKeyEvent(e(up, app, 8, 0, 0, 400, false),
                            false, true, false).consume, "replacement up remains healthy");

                    // Containment appearing after stock DOWN cancels immediately and drains until
                    // the exact downTime terminates, even if the claim recovers before UP.
                    m = new WonadRecentsKeyContainment();
                    check(!m.onKeyEvent(e(down, app, 9, 3, 0, 500, false),
                            false, false, true).consume, "stock pair starts healthy");
                    d = m.onKeyEvent(e(down, app, 9, 3, 1, 500, false),
                            true, true, false);
                    check(d.consume && d.forgetStockPair && d.cancelStockAppSwitch
                            && d.cancelDisplayId == 3, "blocked repeat cancels exact stock pair");
                    d = m.onKeyEvent(e(up, app, 9, 0, 0, 500, false),
                            false, false, false);
                    check(d.consume && !d.cancelStockAppSwitch,
                            "post-cancel up drains without duplicate cancellation");

                    m = new WonadRecentsKeyContainment();
                    check(!m.onKeyEvent(e(down, recent, 10, 3, 0, 600, false),
                            false, false, true).consume, "one-shot begins healthy");
                    d = m.onKeyEvent(e(up, recent, 10, 3, 0, 600, false),
                            true, true, false);
                    check(d.consume && d.forgetStockPair && !d.cancelStockAppSwitch,
                            "one-shot bookkeeping drains without fake cancellation");

                    // Distinct devices remain independent and every terminal/replacement path is
                    // bounded to at most the two tracked Recents keys per active device.
                    m = new WonadRecentsKeyContainment();
                    check(m.onKeyEvent(e(down, app, 11, 3, 0, 700, false),
                            true, false, true).consume, "device eleven blocked");
                    check(!m.onKeyEvent(e(down, app, 12, 0, 0, 800, false),
                            false, false, true).consume, "device twelve phone isolated");
                    check(m.mPairsForDevice.size() == 2, "two bounded active devices");
                    check(m.onKeyEvent(e(down, app, 11, 3, 1, 700, true),
                            false, false, false).consume, "canceled old device clears");
                    check(!m.onKeyEvent(e(up, app, 12, 0, 0, 800, false),
                            false, true, false).consume, "healthy other device completes");
                    check(m.mPairsForDevice.size() == 0, "all state released");

                    m = new WonadRecentsKeyContainment();
                    check(!m.onKeyEvent(e(down, app, 21, 3, 0, 900, false),
                            false, false, true).consume, "missing device stock pair starts");
                    check(m.onKeyEvent(e(down, app, 22, 4, 0, 910, false),
                            true, false, true).consume, "missing device draining pair starts");
                    java.util.List<WonadRecentsKeyContainment.RetiredPair> retired =
                            m.retireMissingDevices(device -> false);
                    check(retired.size() == 2 && m.mPairsForDevice.size() == 0,
                            "missing devices release all pair state");
                    int cancellations = 0;
                    for (WonadRecentsKeyContainment.RetiredPair pair : retired) {{
                        if (pair.cancelStockAppSwitch && pair.deviceId == 21
                                && pair.displayId == 3) cancellations++;
                    }}
                    check(cancellations == 1,
                            "only retired stock APP_SWITCH requests exact cancellation");
                    System.out.println("state-machine-controls=41");
                }}
            }}
        """
        files = dict(ANDROID_STUBS)
        files["com/android/server/input/StateHarness.java"] = textwrap.dedent(harness)
        self.assertEqual(compile_and_run(files, "com.android.server.input.StateHarness").strip(),
                         "state-machine-controls=41")

    def test_exact_interceptor_method_compiles_and_preserves_isolation(self) -> None:
        source = CANDIDATE_KGC.read_text(encoding="utf-8")
        helper = java_block(source, "private static final class WonadRecentsKeyContainment")
        method = java_block(source, "private boolean interceptWonadContainedBeforeKeyCapture(")
        bridge = """
            package org.wonad.server.input;
            import android.view.KeyEvent;
            public final class WonadInputBridge {
                public static int calls;
                public static boolean consumeClaimedInput(Object context, Object wm,
                        KeyEvent event, int flags) {
                    calls++;
                    return event.getDisplayId() > 0 && event.blocked();
                }
            }
        """
        harness = f"""
            package com.android.server.input;
            import android.annotation.NonNull;
            import android.annotation.Nullable;
            import android.hardware.input.KeyGestureEvent;
            import android.os.IBinder;
            import android.util.SparseArray;
            import android.util.SparseIntArray;
            import android.view.KeyEvent;
            import java.util.HashMap;
            import java.util.ArrayList;
            import java.util.List;
            import java.util.Map;
            import java.util.function.IntPredicate;
            public final class InterceptorHarness {{
                private static final int INTERCEPT_STAGE_SHORTCUTS_BEFORE_KEY_CAPTURE = 0;
                private static final int SHORTCUT_META_MASK = 0xf0000;
                private final Object mContext = new Object();
                private final Object mWindowManagerInternal = new Object();
                private final Map<Integer, InterceptKeyStage> mInterceptStages = new HashMap<>();
                private final WonadRecentsKeyContainment mWonadRecentsKeyContainment =
                        new WonadRecentsKeyContainment();
                private int cancellations;
                private int escapeCancellations;
                private int lastFlags;
                private int lastCancelDisplay = -99;
                InterceptorHarness() {{ mInterceptStages.put(0, new InterceptKeyStage()); }}
                private Object getInputDevice(int deviceId) {{ return new Object(); }}
                private void handleKeyGesture(int device, int[] keys, int modifiers, int type,
                        int action, int display, IBinder token, int flags, Object launchData) {{
                    cancellations++;
                    lastFlags = flags;
                    lastCancelDisplay = display;
                }}
                private static final class InterceptKeyStage {{
                    private long consumedDownTime = -1;
                    private boolean isKeyConsumed(KeyEvent event) {{
                        return consumedDownTime == event.getDownTime();
                    }}
                    private void forgetConsumedKey(KeyEvent event) {{
                        if (isKeyConsumed(event)) consumedDownTime = -1;
                    }}
                    private void forgetConsumedKey(int device, int key) {{
                        consumedDownTime = -1;
                    }}
                }}
                private boolean cancelPendingExitFocusedApp(KeyEvent event,
                        boolean replacement) {{
                    escapeCancellations++;
                    return true;
                }}
                {method}
                {helper}
                private static KeyEvent e(int action, int key, int device, int display,
                        int repeat, long downTime, boolean canceled, boolean blocked) {{
                    return new KeyEvent(action, key, device, display, repeat, 0, downTime,
                            canceled, blocked);
                }}
                private static void check(boolean value, String message) {{
                    if (!value) throw new AssertionError(message);
                }}
                public static void main(String[] ignored) {{
                    final int down = KeyEvent.ACTION_DOWN, up = KeyEvent.ACTION_UP;
                    final int app = KeyEvent.KEYCODE_APP_SWITCH;
                    InterceptorHarness h = new InterceptorHarness();
                    check(h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, KeyEvent.KEYCODE_ALL_APPS, 1, 3, 0, 1,
                                    false, true), 1), "blocked ALL_APPS contained");
                    check(h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, KeyEvent.KEYCODE_SCREENSHOT, 1, 3, 0, 2,
                                    false, true), 1), "blocked screenshot contained");
                    check(h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, KeyEvent.KEYCODE_FULLSCREEN, 1, 3, 0, 3,
                                    false, true), 1), "blocked fullscreen contained");
                    check(h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, KeyEvent.KEYCODE_LOCK, 1, 3, 0, 4,
                                    false, true), 1), "blocked lock contained");
                    check(h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, KeyEvent.KEYCODE_BRIGHTNESS_UP, 1, 3, 0, 5,
                                    false, true), 1), "blocked brightness contained");
                    check(h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, KeyEvent.KEYCODE_KEYBOARD_BACKLIGHT_TOGGLE, 1, 3, 0, 6,
                                    false, true), 1), "blocked backlight contained");
                    check(h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, KeyEvent.KEYCODE_DO_NOT_DISTURB, 1, 3, 0, 7,
                                    false, true), 1), "blocked DND contained");
                    check(h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, KeyEvent.KEYCODE_F1, 1, 3, 0, 8,
                                    false, true), 1), "blocked configured system shortcut contained");
                    check(org.wonad.server.input.WonadInputBridge.calls == 8,
                            "every ordinary key queries containment");
                    check(!h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, KeyEvent.KEYCODE_ALL_APPS, 1, 3, 0, 9,
                                    false, false), 1), "healthy external reaches stock");
                    check(!h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, KeyEvent.KEYCODE_ALL_APPS, 1, 0, 0, 10,
                                    false, true), 1), "phone never inferred contained");
                    check(!h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, app, 1, 0, 0, 11, false, true), 1), "phone unchanged");
                    h.mInterceptStages.get(0).consumedDownTime = 11;
                    check(!h.interceptWonadContainedBeforeKeyCapture(null,
                            e(up, app, 1, 0, 0, 11, false, true), 1), "phone up unchanged");

                    h = new InterceptorHarness();
                    check(h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, app, 2, 3, 0, 20, false, true), 1),
                            "blocked external contained");
                    check(h.cancellations == 0, "never-started pair not cancelled");
                    check(h.interceptWonadContainedBeforeKeyCapture(null,
                            e(up, app, 2, 0, 0, 20, false, false), 1),
                            "blocked pair drains after display/focus transition");

                    h = new InterceptorHarness();
                    check(!h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, app, 3, 3, 0, 30, false, false), 1),
                            "healthy external down reaches stock");
                    h.mInterceptStages.get(0).consumedDownTime = 30;
                    check(h.interceptWonadContainedBeforeKeyCapture(null,
                            e(up, app, 3, 3, 0, 30, false, true), 1),
                            "healthy-down blocked-up contained");
                    check(h.cancellations == 1 && h.lastFlags == KeyGestureEvent.FLAG_CANCELLED,
                            "stock preload cancelled once");
                    check(h.lastCancelDisplay == 3, "cancellation retains old display owner");
                    check(h.mInterceptStages.get(0).consumedDownTime == -1,
                            "stock ledger unwound");

                    // Lost blocked external UP followed by a fresh phone pair on the same reused
                    // numeric device ID: fresh DOWN/UP pass, late old UP remains contained.
                    h = new InterceptorHarness();
                    check(h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, app, 4, 3, 0, 40, false, true), 1), "old pair blocked");
                    check(!h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, app, 4, 0, 0, 50, false, false), 1),
                            "fresh phone down not swallowed");
                    h.mInterceptStages.get(0).consumedDownTime = 50;
                    check(h.interceptWonadContainedBeforeKeyCapture(null,
                            e(up, app, 4, 3, 0, 40, false, false), 1),
                            "stale external up cannot complete phone pair");
                    check(h.mInterceptStages.get(0).consumedDownTime == 50,
                            "stale up leaves replacement stock ledger intact");
                    check(!h.interceptWonadContainedBeforeKeyCapture(null,
                            e(up, app, 4, 0, 0, 50, false, false), 1),
                            "fresh phone up reaches stock");

                    // Replacing an already-started external stock pair asks for exact old-owner
                    // cancellation but passes the fresh phone DOWN after clearing old bookkeeping.
                    h = new InterceptorHarness();
                    check(!h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, app, 5, 3, 0, 60, false, false), 1),
                            "old external stock begins");
                    h.mInterceptStages.get(0).consumedDownTime = 60;
                    check(!h.interceptWonadContainedBeforeKeyCapture(null,
                            e(down, app, 5, 0, 0, 70, false, false), 1),
                            "replacement phone down passes");
                    check(h.cancellations == 1 && h.lastCancelDisplay == 3,
                            "replacement cancels only old external owner");
                    check(h.mInterceptStages.get(0).consumedDownTime == -1,
                            "old stock ledger cleared before replacement stock stage");

                    h = new InterceptorHarness();
                    h.mInterceptStages.get(0).consumedDownTime = 80;
                    check(h.interceptWonadContainedBeforeKeyCapture(null,
                            e(up, KeyEvent.KEYCODE_ESCAPE, 6, 3, 0, 80,
                                    false, true), 1), "blocked captured ESC contained");
                    check(h.escapeCancellations == 1
                            && h.mInterceptStages.get(0).consumedDownTime == -1,
                            "blocked ESC cancels pending pair and stock ledger");
                    System.out.println("actual-interceptor-controls=44");
                }}
            }}
        """
        files = dict(ANDROID_STUBS)
        files["org/wonad/server/input/WonadInputBridge.java"] = textwrap.dedent(bridge)
        files["com/android/server/input/InterceptorHarness.java"] = textwrap.dedent(harness)
        self.assertEqual(
            compile_and_run(files, "com.android.server.input.InterceptorHarness").strip(),
            "actual-interceptor-controls=44",
        )

    def test_exact_stock_stage_uses_physical_pair_identity(self) -> None:
        source = CANDIDATE_KGC.read_text(encoding="utf-8")
        stage = java_block(source, "private abstract static class InterceptKeyStage")
        harness = f"""
            package com.android.server.input;
            import android.annotation.NonNull;
            import android.annotation.Nullable;
            import android.os.IBinder;
            import android.util.SparseArray;
            import android.view.KeyEvent;
            public final class StageHarness {{
                {stage}
                private static final class Stage extends InterceptKeyStage {{
                    boolean consumeNext;
                    protected boolean onKeyEvent(IBinder token, KeyEvent event) {{
                        boolean result = consumeNext;
                        consumeNext = false;
                        return result;
                    }}
                }}
                private static KeyEvent e(int action, int device, int display, int repeat,
                        long downTime) {{
                    return new KeyEvent(action, KeyEvent.KEYCODE_ALL_APPS, device, display,
                            repeat, 0, downTime, false, false);
                }}
                private static void check(boolean value, String message) {{
                    if (!value) throw new AssertionError(message);
                }}
                public static void main(String[] ignored) {{
                    Stage impl = new Stage();
                    InterceptKeyStage s = impl;
                    impl.consumeNext = true;
                    check(s.interceptKey(null, e(KeyEvent.ACTION_DOWN, 7, 3, 0, 10)),
                            "old external down consumed");
                    check(!s.interceptKey(null, e(KeyEvent.ACTION_DOWN, 7, 0, 0, 20)),
                            "fresh phone down retires missing-UP ledger");
                    check(s.mConsumedKeysForDevice.size() == 0,
                            "nonconsumed replacement leaves no empty device entry");
                    check(!s.interceptKey(null, e(KeyEvent.ACTION_UP, 7, 0, 0, 20)),
                            "fresh phone up not swallowed");

                    impl = new Stage();
                    s = impl;
                    impl.consumeNext = true;
                    check(s.interceptKey(null, e(KeyEvent.ACTION_DOWN, 8, 0, 0, 30)),
                            "replacement pair recorded");
                    check(!s.interceptKey(null, e(KeyEvent.ACTION_UP, 8, 3, 0, 25)),
                            "stale old up not consumed");
                    check(s.isKeyConsumed(e(KeyEvent.ACTION_DOWN, 8, 0, 1, 30)),
                            "stale up leaves replacement state");
                    check(s.interceptKey(null, e(KeyEvent.ACTION_UP, 8, 0, 0, 30)),
                            "exact replacement up consumed");
                    check(!s.isKeyConsumed(e(KeyEvent.ACTION_DOWN, 8, 0, 1, 30)),
                            "terminal exact pair released");

                    impl = new Stage();
                    s = impl;
                    impl.consumeNext = true;
                    s.interceptKey(null, e(KeyEvent.ACTION_DOWN, 9, 3, 0, 40));
                    s.forgetConsumedKey(e(KeyEvent.ACTION_UP, 9, 3, 0, 39));
                    check(s.isKeyConsumed(e(KeyEvent.ACTION_DOWN, 9, 3, 1, 40)),
                            "stale exact-forget cannot erase current pair");
                    s.forgetConsumedKey(9, KeyEvent.KEYCODE_ALL_APPS);
                    check(!s.isKeyConsumed(e(KeyEvent.ACTION_DOWN, 9, 3, 1, 40)),
                            "explicit replacement cleanup removes old pair");
                    System.out.println("stock-stage-controls=13");
                }}
            }}
        """
        files = dict(ANDROID_STUBS)
        files["com/android/server/input/StageHarness.java"] = textwrap.dedent(harness)
        self.assertEqual(compile_and_run(files, "com.android.server.input.StageHarness").strip(),
                         "stock-stage-controls=13")

    def test_exact_escape_cleanup_is_pair_owned(self) -> None:
        source = CANDIDATE_KGC.read_text(encoding="utf-8")
        pending = java_block(source, "private static final class PendingExitFocusedApp")
        cancel = java_block(source, "private boolean cancelPendingExitFocusedApp(")
        complete = java_block(source, "private void completePendingExitFocusedApp(")
        harness = f"""
            package com.android.server.input;
            import android.annotation.NonNull;
            import android.annotation.Nullable;
            import android.hardware.input.AidlKeyGestureEvent;
            import android.hardware.input.KeyGestureEvent;
            import android.os.Handler;
            import android.os.IBinder;
            import android.util.SparseArray;
            import android.view.KeyEvent;
            public final class EscapeHarness {{
                private static final int MSG_EXIT_FOCUSED_APP = 6;
                private final Handler mHandler = new Handler();
                private final SparseArray<PendingExitFocusedApp> mPendingExitFocusedApps =
                        new SparseArray<>();
                private int cancelled, completed, lastDisplay = -1;
                private IBinder lastToken;
                {pending}
                {cancel}
                {complete}
                private void handleKeyGesture(int device, int[] keys, int modifiers, int type,
                        int action, int display, IBinder token, int flags, Object launchData) {{
                    cancelled++; lastDisplay = display; lastToken = token;
                }}
                private void handleKeyGesture(AidlKeyGestureEvent event, IBinder token) {{
                    completed++;
                }}
                private static KeyEvent e(int action, int device, int display,
                        int repeat, long downTime) {{
                    return new KeyEvent(action, KeyEvent.KEYCODE_ESCAPE, device, display,
                            repeat, 0, downTime, false, true);
                }}
                private static void check(boolean value, String message) {{
                    if (!value) throw new AssertionError(message);
                }}
                public static void main(String[] ignored) {{
                    EscapeHarness h = new EscapeHarness();
                    IBinder owner = new IBinder() {{}};
                    AidlKeyGestureEvent first = new AidlKeyGestureEvent();
                    h.mPendingExitFocusedApps.put(4,
                            new PendingExitFocusedApp(10, 3, 7, owner, first));
                    check(!h.cancelPendingExitFocusedApp(
                            e(KeyEvent.ACTION_UP, 4, 0, 0, 9), false),
                            "stale old up cannot cancel current escape");
                    check(h.mPendingExitFocusedApps.size() == 1 && h.cancelled == 0,
                            "stale up preserves owner");
                    check(h.cancelPendingExitFocusedApp(
                            e(KeyEvent.ACTION_DOWN, 4, 0, 0, 20), true),
                            "new physical pair retires old escape");
                    check(h.cancelled == 1 && h.lastDisplay == 3 && h.lastToken == owner,
                            "cancellation uses original display and focus");
                    check(h.mHandler.removes == 1 && h.mHandler.lastRemoved == first,
                            "only exact delayed message removed");

                    AidlKeyGestureEvent second = new AidlKeyGestureEvent();
                    AidlKeyGestureEvent other = new AidlKeyGestureEvent();
                    h.mPendingExitFocusedApps.put(4,
                            new PendingExitFocusedApp(30, 3, 0, owner, second));
                    h.mPendingExitFocusedApps.put(5,
                            new PendingExitFocusedApp(40, 0, 0, null, other));
                    h.completePendingExitFocusedApp(second);
                    check(h.completed == 1 && h.mPendingExitFocusedApps.size() == 1,
                            "completion removes only exact message owner");
                    h.completePendingExitFocusedApp(second);
                    check(h.completed == 1, "retired message cannot fire twice");
                    check(h.cancelPendingExitFocusedApp(
                            e(KeyEvent.ACTION_UP, 5, 0, 0, 40), false),
                            "other device exact up cancels its own message");
                    check(h.mPendingExitFocusedApps.size() == 0 && h.cancelled == 2,
                            "escape state fully bounded and released");
                    System.out.println("escape-controls=14");
                }}
            }}
        """
        files = dict(ANDROID_STUBS)
        files["com/android/server/input/EscapeHarness.java"] = textwrap.dedent(harness)
        self.assertEqual(compile_and_run(files, "com.android.server.input.EscapeHarness").strip(),
                         "escape-controls=14")

    def test_exact_phone_window_manager_branch_compiles_and_cancels_preload(self) -> None:
        source = CANDIDATE_PWM.read_text(encoding="utf-8")
        owner_fields = source[
            source.index("    boolean mPreloadedRecentApps;") :
            source.index("    final Object mServiceAcquireLock", source.index(
                "    boolean mPreloadedRecentApps;"))
        ]
        fragment = source[
            source.index("case KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH:") :
            source.index("case KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_ASSISTANT:")
        ]
        methods = "\n".join([
            java_block(source, "private void preloadRecentApps()"),
            java_block(source, "private void preloadRecentApps(int deviceId, int displayId)"),
            java_block(source, "private void cancelPreloadRecentApps()"),
            java_block(source, "private void cancelPreloadRecentApps(int deviceId, int displayId)"),
            java_block(source, "private boolean ownsRecentAppsPreload(int deviceId, int displayId)"),
            java_block(source, "private void clearRecentAppsPreloadOwner()"),
            java_block(source, "private void toggleRecentApps()"),
            java_block(source, "private void toggleRecentApps(int deviceId, int displayId)"),
        ])
        harness = f"""
            package com.android.server.policy;
            import android.hardware.input.KeyGestureEvent;
            public final class PolicyHarness {{
                private static final int INVALID_DISPLAY = -1;
                {owner_fields}
                private boolean locked;
                private final StatusBarManagerInternal statusbar = new StatusBarManagerInternal();
                private static final class StatusBarManagerInternal {{
                    int preload, cancel, toggle;
                    void preloadRecentApps() {{ preload++; }}
                    void cancelPreloadRecentApps() {{ cancel++; }}
                    void toggleRecentApps() {{ toggle++; }}
                }}
                private StatusBarManagerInternal getStatusBarManagerInternal() {{
                    return statusbar;
                }}
                private boolean keyguardOn() {{ return locked; }}
                {methods}
                private void handle(KeyGestureEvent event) {{
                    boolean start = event.getAction() == KeyGestureEvent.ACTION_GESTURE_START;
                    boolean complete = event.getAction() == KeyGestureEvent.ACTION_GESTURE_COMPLETE
                            && !event.isCancelled();
                    int gestureType = event.getKeyGestureType();
                    int deviceId = event.getDeviceId();
                    int displayId = event.getDisplayId();
                    boolean keyguardOn = keyguardOn();
                    switch (gestureType) {{
                        {fragment}
                        default: break;
                    }}
                }}
                private static void check(boolean value, String message) {{
                    if (!value) throw new AssertionError(message);
                }}
                public static void main(String[] ignored) {{
                    PolicyHarness h = new PolicyHarness();
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_START,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, false, 1, 3));
                    check(h.statusbar.preload == 1 && h.mPreloadedRecentAppsDeviceId == 1
                            && h.mPreloadedRecentAppsDisplayId == 3, "healthy exact preload");
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_COMPLETE,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, true, 1, 3));
                    check(h.statusbar.preload == 1 && h.statusbar.cancel == 1
                            && h.statusbar.toggle == 0 && !h.mPreloadedRecentApps,
                            "cancelled completion unwinds");

                    h = new PolicyHarness();
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_START,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, false, 2, 4));
                    h.locked = true;
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_COMPLETE,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, false, 2, 4));
                    check(h.statusbar.preload == 1 && h.statusbar.cancel == 1
                            && h.statusbar.toggle == 0,
                            "keyguard transition unwinds");

                    h = new PolicyHarness();
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_START,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, false, 3, 3));
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_COMPLETE,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, false, 3, 3));
                    check(h.statusbar.preload == 1 && h.statusbar.cancel == 0
                            && h.statusbar.toggle == 1,
                            "healthy stock behavior retained");

                    // A newer phone/system preload owns the global slot; an old external canceled
                    // COMPLETE cannot cancel or toggle that unrelated owner.
                    h = new PolicyHarness();
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_START,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, false, 4, 3));
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_START,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, false, 5, 0));
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_COMPLETE,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, true, 4, 3));
                    check(h.statusbar.cancel == 0 && h.mPreloadedRecentApps
                            && h.mPreloadedRecentAppsDeviceId == 5
                            && h.mPreloadedRecentAppsDisplayId == 0,
                            "old external cancellation cannot disturb newer phone preload");
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_COMPLETE,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, false, 5, 0));
                    check(h.statusbar.toggle == 1 && !h.mPreloadedRecentApps,
                            "newer phone owner completes normally");

                    // HOME preloading uses an explicit unowned sentinel and is likewise isolated
                    // from an unrelated APP_SWITCH cancellation.
                    h = new PolicyHarness();
                    h.preloadRecentApps();
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_COMPLETE,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, true, 6, 3));
                    check(h.statusbar.cancel == 0 && h.mPreloadedRecentApps,
                            "external cancellation cannot disturb HOME preload");
                    h.cancelPreloadRecentApps();
                    check(h.statusbar.cancel == 1 && !h.mPreloadedRecentApps,
                            "HOME owner still cancels through stock path");

                    h = new PolicyHarness(); h.locked = true;
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_START,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, false, 7, 3));
                    check(h.statusbar.preload == 0 && h.statusbar.cancel == 0
                            && h.statusbar.toggle == 0,
                            "locked start unchanged");
                    System.out.println("policy-controls=18");
                }}
            }}
        """
        files = dict(ANDROID_STUBS)
        files["com/android/server/policy/PolicyHarness.java"] = textwrap.dedent(harness)
        self.assertEqual(compile_and_run(files, "com.android.server.policy.PolicyHarness").strip(),
                         "policy-controls=18")

    def test_candidate_has_only_expected_java_deltas(self) -> None:
        kgc = CANDIDATE_KGC.read_text(encoding="utf-8")
        pwm = CANDIDATE_PWM.read_text(encoding="utf-8")
        self.assertIn("private static final class WonadRecentsKeyContainment", kgc)
        self.assertEqual(kgc.count(
            "private boolean interceptWonadContainedBeforeKeyCapture("), 1)
        self.assertEqual(kgc.count("private static final class PendingExitFocusedApp"), 1)
        self.assertEqual(kgc.count("private boolean isKeyConsumed("), 1)
        self.assertEqual(kgc.count("private void forgetConsumedKey("), 2)
        guard = java_block(kgc, "private boolean interceptWonadContainedBeforeKeyCapture(")
        self.assertLess(guard.index("WonadInputBridge.consumeClaimedInput"),
                        guard.index("keyCode != KeyEvent.KEYCODE_APP_SWITCH"))
        self.assertIn("cancelPendingExitFocusedApp", guard)
        app_switch = pwm[
            pwm.index("case KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH:") :
            pwm.index("case KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_ASSISTANT:")
        ]
        self.assertEqual(app_switch.count("cancelPreloadRecentApps(deviceId, displayId);"), 1)
        self.assertEqual(app_switch.count("toggleRecentApps(deviceId, displayId);"), 1)
        self.assertRegex(app_switch, r"event\.isCancelled\(\) \|\| keyguardOn")
        self.assertIn("private boolean ownsRecentAppsPreload(int deviceId, int displayId)", pwm)
        self.assertIn("private void clearRecentAppsPreloadOwner()", pwm)


if __name__ == "__main__":
    unittest.main(verbosity=2)
