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
    "android/util/SparseArray.java": """
        package android.util;
        import java.util.HashMap;
        public final class SparseArray<E> {
            private final HashMap<Integer, E> values = new HashMap<>();
            public E get(int key) { return values.get(key); }
            public void put(int key, E value) { values.put(key, value); }
            public void remove(int key) { values.remove(key); }
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
            private final int action, keyCode, deviceId, displayId, repeatCount;
            private final boolean canceled, blocked;
            public KeyEvent(int action, int keyCode, int deviceId, int displayId,
                    int repeatCount, boolean canceled, boolean blocked) {
                this.action = action; this.keyCode = keyCode; this.deviceId = deviceId;
                this.displayId = displayId; this.repeatCount = repeatCount;
                this.canceled = canceled; this.blocked = blocked;
            }
            public int getAction() { return action; }
            public int getKeyCode() { return keyCode; }
            public int getDeviceId() { return deviceId; }
            public int getDisplayId() { return displayId; }
            public int getRepeatCount() { return repeatCount; }
            public boolean isCanceled() { return canceled; }
            public boolean blocked() { return blocked; }
        }
    """,
    "android/hardware/input/KeyGestureEvent.java": """
        package android.hardware.input;
        public final class KeyGestureEvent {
            public static final int KEY_GESTURE_TYPE_APP_SWITCH = 1;
            public static final int KEY_GESTURE_TYPE_LAUNCH_ASSISTANT = 2;
            public static final int ACTION_GESTURE_START = 3;
            public static final int ACTION_GESTURE_COMPLETE = 4;
            public static final int FLAG_CANCELLED = 8;
            private final int action, type;
            private final boolean cancelled;
            public KeyGestureEvent(int action, int type, boolean cancelled) {
                this.action = action; this.type = type; this.cancelled = cancelled;
            }
            public int getAction() { return action; }
            public int getKeyGestureType() { return type; }
            public boolean isCancelled() { return cancelled; }
        }
    """,
}


class CandidateTests(unittest.TestCase):
    maxDiff = None

    def test_authenticated_preimages_and_original_defect(self) -> None:
        self.assertEqual(sha256(INPUT_KGC), INPUT_KGC_SHA256)
        self.assertEqual(sha256(INPUT_PWM), INPUT_PWM_SHA256)
        original = INPUT_KGC.read_text(encoding="utf-8")
        dispatch = java_block(original, "public long interceptKeyBeforeDispatching(")
        self.assertNotIn("interceptWonadContainedRecentsKey", dispatch)
        stock = dispatch.index("INTERCEPT_STAGE_SHORTCUTS_BEFORE_KEY_CAPTURE).interceptKey")
        self.assertGreater(dispatch.index("WonadInputBridge.consumeClaimedInput", stock), stock)
        original_pwm = INPUT_PWM.read_text(encoding="utf-8")
        app_switch = original_pwm[
            original_pwm.index("case KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH:") :
            original_pwm.index("case KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_ASSISTANT:")
        ]
        self.assertNotIn("cancelPreloadRecentApps", app_switch)

    def test_candidate_order_is_targeted_not_global(self) -> None:
        source = CANDIDATE_KGC.read_text(encoding="utf-8")
        dispatch = java_block(source, "public long interceptKeyBeforeDispatching(")
        target = dispatch.index("interceptWonadContainedRecentsKey")
        self.assertGreater(target, dispatch.index("WonadInputBridge.intercept("))
        self.assertLess(target, dispatch.index("shouldInterceptShortcuts(focus)"))
        self.assertLess(
            target,
            dispatch.index("INTERCEPT_STAGE_SHORTCUTS_BEFORE_KEY_CAPTURE).interceptKey"),
        )
        self.assertEqual(dispatch.count("interceptWonadContainedRecentsKey"), 1)
        targeted = java_block(source, "private boolean interceptWonadContainedRecentsKey(")
        self.assertIn("KEYCODE_APP_SWITCH", targeted)
        self.assertIn("KEYCODE_RECENT_APPS", targeted)
        self.assertIn("CANCEL_STOCK_APP_SWITCH", targeted)
        self.assertIn("forgetConsumedKey(event)", targeted)

    def test_exact_state_helper_compiles_and_drains_pairs(self) -> None:
        source = CANDIDATE_KGC.read_text(encoding="utf-8")
        helper = java_block(source, "private static final class WonadRecentsKeyContainment")
        harness = f"""
            package com.android.server.input;
            import android.annotation.NonNull;
            import android.util.SparseArray;
            import android.util.SparseIntArray;
            import android.view.KeyEvent;
            public final class StateHarness {{
                {helper}
                private static KeyEvent e(int action, int key, int device, int repeat,
                        boolean canceled) {{
                    return new KeyEvent(action, key, device, 3, repeat, canceled, false);
                }}
                private static void check(boolean value, String message) {{
                    if (!value) throw new AssertionError(message);
                }}
                public static void main(String[] ignored) {{
                    final int down = KeyEvent.ACTION_DOWN, up = KeyEvent.ACTION_UP;
                    final int app = KeyEvent.KEYCODE_APP_SWITCH;
                    final int recent = KeyEvent.KEYCODE_RECENT_APPS;
                    WonadRecentsKeyContainment m = new WonadRecentsKeyContainment();
                    check(m.onKeyEvent(e(down, 99, 1, 0, false), true, false)
                            == WonadRecentsKeyContainment.PASS, "unrelated key");
                    check(m.onKeyEvent(e(down, app, 1, 0, false), false, false)
                            == WonadRecentsKeyContainment.PASS, "healthy down");

                    m = new WonadRecentsKeyContainment();
                    check(m.onKeyEvent(e(down, app, 1, 0, false), true, false)
                            == WonadRecentsKeyContainment.CONSUME, "blocked initial down");
                    check(m.onKeyEvent(e(down, app, 1, 1, false), false, false)
                            == WonadRecentsKeyContainment.CONSUME, "recovered repeat drained");
                    check(m.onKeyEvent(e(up, app, 1, 0, false), false, false)
                            == WonadRecentsKeyContainment.CONSUME, "recovered up drained");
                    check(m.onKeyEvent(e(down, app, 1, 0, false), false, false)
                            == WonadRecentsKeyContainment.PASS, "pair cleared");

                    m = new WonadRecentsKeyContainment();
                    check(m.onKeyEvent(e(up, app, 2, 0, false), true, true)
                            == WonadRecentsKeyContainment.CANCEL_STOCK_APP_SWITCH,
                            "blocked up cancels stock preload");
                    check(m.onKeyEvent(e(down, app, 2, 1, false), true, true)
                            == WonadRecentsKeyContainment.CANCEL_STOCK_APP_SWITCH,
                            "blocked repeat cancels immediately");
                    check(m.onKeyEvent(e(up, app, 2, 0, false), false, false)
                            == WonadRecentsKeyContainment.CONSUME,
                            "post-cancel up remains drained");
                    check(m.onKeyEvent(e(down, app, 2, 0, false), false, false)
                            == WonadRecentsKeyContainment.PASS, "post-cancel pair cleared");

                    m = new WonadRecentsKeyContainment();
                    check(m.onKeyEvent(e(down, recent, 3, 1, false), true, true)
                            == WonadRecentsKeyContainment.FORGET_STOCK_PAIR,
                            "completed one-shot stock pair forgotten");
                    check(m.onKeyEvent(e(up, recent, 3, 0, false), false, false)
                            == WonadRecentsKeyContainment.CONSUME,
                            "one-shot up drained after transition");

                    m = new WonadRecentsKeyContainment();
                    check(m.onKeyEvent(e(down, app, 4, 0, false), true, false)
                            == WonadRecentsKeyContainment.CONSUME, "device four blocked");
                    check(m.onKeyEvent(e(down, app, 5, 0, false), false, false)
                            == WonadRecentsKeyContainment.PASS, "other device isolated");
                    check(m.onKeyEvent(e(down, app, 4, 1, true), false, false)
                            == WonadRecentsKeyContainment.CONSUME, "cancellation drains");
                    check(m.onKeyEvent(e(down, app, 4, 0, false), false, false)
                            == WonadRecentsKeyContainment.PASS, "cancellation clears");
                    System.out.println("state-machine-controls=18");
                }}
            }}
        """
        files = dict(ANDROID_STUBS)
        files["com/android/server/input/StateHarness.java"] = textwrap.dedent(harness)
        self.assertEqual(compile_and_run(files, "com.android.server.input.StateHarness").strip(),
                         "state-machine-controls=18")

    def test_exact_interceptor_method_compiles_and_preserves_isolation(self) -> None:
        source = CANDIDATE_KGC.read_text(encoding="utf-8")
        helper = java_block(source, "private static final class WonadRecentsKeyContainment")
        method = java_block(source, "private boolean interceptWonadContainedRecentsKey(")
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
            import java.util.Map;
            public final class InterceptorHarness {{
                private static final int INTERCEPT_STAGE_SHORTCUTS_BEFORE_KEY_CAPTURE = 0;
                private final Object mContext = new Object();
                private final Object mWindowManagerInternal = new Object();
                private final Map<Integer, InterceptKeyStage> mInterceptStages = new HashMap<>();
                private final WonadRecentsKeyContainment mWonadRecentsKeyContainment =
                        new WonadRecentsKeyContainment();
                private int cancellations;
                private int lastFlags;
                InterceptorHarness() {{ mInterceptStages.put(0, new InterceptKeyStage()); }}
                private void handleKeyGesture(int device, int[] keys, int modifiers, int type,
                        int action, int display, IBinder token, int flags, Object launchData) {{
                    cancellations++;
                    lastFlags = flags;
                }}
                private static final class InterceptKeyStage {{
                    private boolean consumed;
                    private boolean isKeyConsumed(KeyEvent ignored) {{ return consumed; }}
                    private void forgetConsumedKey(KeyEvent ignored) {{ consumed = false; }}
                }}
                {method}
                {helper}
                private static KeyEvent e(int action, int key, int device, int display,
                        int repeat, boolean canceled, boolean blocked) {{
                    return new KeyEvent(action, key, device, display, repeat, canceled, blocked);
                }}
                private static void check(boolean value, String message) {{
                    if (!value) throw new AssertionError(message);
                }}
                public static void main(String[] ignored) {{
                    final int down = KeyEvent.ACTION_DOWN, up = KeyEvent.ACTION_UP;
                    final int app = KeyEvent.KEYCODE_APP_SWITCH;
                    InterceptorHarness h = new InterceptorHarness();
                    check(!h.interceptWonadContainedRecentsKey(null,
                            e(down, 99, 1, 3, 0, false, true), 1), "unrelated unchanged");
                    check(org.wonad.server.input.WonadInputBridge.calls == 0,
                            "unrelated never queries containment");
                    check(!h.interceptWonadContainedRecentsKey(null,
                            e(down, app, 1, 0, 0, false, true), 1), "phone unchanged");
                    check(!h.interceptWonadContainedRecentsKey(null,
                            e(down, app, 1, 3, 0, false, false), 1), "healthy external unchanged");
                    check(h.interceptWonadContainedRecentsKey(null,
                            e(down, app, 1, 3, 0, false, true), 1), "blocked external contained");
                    check(h.cancellations == 0, "never-started pair not cancelled");
                    check(h.interceptWonadContainedRecentsKey(null,
                            e(up, app, 1, 0, 0, false, false), 1),
                            "blocked pair drains after display/focus transition");

                    h = new InterceptorHarness();
                    h.mInterceptStages.get(0).consumed = true;
                    check(h.interceptWonadContainedRecentsKey(null,
                            e(up, app, 2, 3, 0, false, true), 1),
                            "healthy-down blocked-up contained");
                    check(h.cancellations == 1 && h.lastFlags == KeyGestureEvent.FLAG_CANCELLED,
                            "stock preload cancelled once");
                    check(!h.mInterceptStages.get(0).consumed, "stock ledger unwound");

                    h = new InterceptorHarness();
                    h.mInterceptStages.get(0).consumed = true;
                    check(h.interceptWonadContainedRecentsKey(null,
                            e(down, app, 3, 3, 1, false, true), 1),
                            "blocked repeat cancels immediately");
                    check(h.cancellations == 1 && !h.mInterceptStages.get(0).consumed,
                            "repeat cancellation unwinds stock");
                    check(h.interceptWonadContainedRecentsKey(null,
                            e(up, app, 3, 0, 0, false, false), 1),
                            "remaining pair drains after recovery");
                    check(h.cancellations == 1, "no duplicate cancellation");
                    System.out.println("actual-interceptor-controls=15");
                }}
            }}
        """
        files = dict(ANDROID_STUBS)
        files["org/wonad/server/input/WonadInputBridge.java"] = textwrap.dedent(bridge)
        files["com/android/server/input/InterceptorHarness.java"] = textwrap.dedent(harness)
        self.assertEqual(
            compile_and_run(files, "com.android.server.input.InterceptorHarness").strip(),
            "actual-interceptor-controls=15",
        )

    def test_exact_phone_window_manager_branch_compiles_and_cancels_preload(self) -> None:
        source = CANDIDATE_PWM.read_text(encoding="utf-8")
        fragment = source[
            source.index("case KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH:") :
            source.index("case KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_ASSISTANT:")
        ]
        harness = f"""
            package com.android.server.policy;
            import android.hardware.input.KeyGestureEvent;
            public final class PolicyHarness {{
                private boolean locked;
                private int preload, cancel, toggle;
                private boolean keyguardOn() {{ return locked; }}
                private void preloadRecentApps() {{ preload++; }}
                private void cancelPreloadRecentApps() {{ cancel++; }}
                private void toggleRecentApps() {{ toggle++; }}
                private void handle(KeyGestureEvent event) {{
                    boolean start = event.getAction() == KeyGestureEvent.ACTION_GESTURE_START;
                    boolean complete = event.getAction() == KeyGestureEvent.ACTION_GESTURE_COMPLETE
                            && !event.isCancelled();
                    int gestureType = event.getKeyGestureType();
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
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, false));
                    check(h.preload == 1 && h.cancel == 0 && h.toggle == 0, "healthy preload");
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_COMPLETE,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, true));
                    check(h.preload == 1 && h.cancel == 1 && h.toggle == 0,
                            "cancelled completion unwinds");
                    h = new PolicyHarness();
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_START,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, false));
                    h.locked = true;
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_COMPLETE,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, false));
                    check(h.preload == 1 && h.cancel == 1 && h.toggle == 0,
                            "keyguard transition unwinds");
                    h = new PolicyHarness();
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_START,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, false));
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_COMPLETE,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, false));
                    check(h.preload == 1 && h.cancel == 0 && h.toggle == 1,
                            "healthy stock behavior retained");
                    h = new PolicyHarness(); h.locked = true;
                    h.handle(new KeyGestureEvent(KeyGestureEvent.ACTION_GESTURE_START,
                            KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH, false));
                    check(h.preload == 0 && h.cancel == 0 && h.toggle == 0,
                            "locked start unchanged");
                    System.out.println("policy-controls=8");
                }}
            }}
        """
        files = dict(ANDROID_STUBS)
        files["com/android/server/policy/PolicyHarness.java"] = textwrap.dedent(harness)
        self.assertEqual(compile_and_run(files, "com.android.server.policy.PolicyHarness").strip(),
                         "policy-controls=8")

    def test_candidate_has_only_expected_java_deltas(self) -> None:
        kgc = CANDIDATE_KGC.read_text(encoding="utf-8")
        pwm = CANDIDATE_PWM.read_text(encoding="utf-8")
        self.assertIn("private static final class WonadRecentsKeyContainment", kgc)
        self.assertEqual(kgc.count("private boolean interceptWonadContainedRecentsKey("), 1)
        self.assertEqual(kgc.count("private boolean isKeyConsumed("), 1)
        self.assertEqual(kgc.count("private void forgetConsumedKey("), 1)
        app_switch = pwm[
            pwm.index("case KeyGestureEvent.KEY_GESTURE_TYPE_APP_SWITCH:") :
            pwm.index("case KeyGestureEvent.KEY_GESTURE_TYPE_LAUNCH_ASSISTANT:")
        ]
        self.assertEqual(app_switch.count("cancelPreloadRecentApps();"), 1)
        self.assertEqual(app_switch.count("toggleRecentApps();"), 1)
        self.assertRegex(app_switch, r"event\.isCancelled\(\) \|\| keyguardOn")


if __name__ == "__main__":
    unittest.main(verbosity=2)
