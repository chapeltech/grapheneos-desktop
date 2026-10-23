#!/usr/bin/env python3
"""Read-only cross-file checks for a frozen native-token generated directory.

These checks complement, and do not replace, the producer's extracted native
and Kotlin host projections. They do not invoke a platform build or runtime.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re


checks = 0


def require(value: bool, message: str) -> None:
    global checks
    checks += 1
    if not value:
        raise AssertionError(message)


def compact(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def params(source: str, name: str, *, definition: str | None = None,
           declaration: bool = False) -> list[str]:
    prefix = re.escape(definition + "::") if definition else r"(?<![\w:])"
    pattern = prefix + re.escape(name) + r"\s*\(([^()]*)\)"
    found = []
    for match in re.finditer(pattern, source):
        tail = source[match.end():].lstrip()
        if declaration and not (tail.startswith("override;") or
                                tail.startswith("= 0;")):
            continue
        fields = []
        for field in match.group(1).split(","):
            value = compact(field)
            # Remove an optional parameter name; template/type identifiers and
            # a trailing '&' survive. All checked signatures have scalar args.
            value = re.sub(r"(?<=[ &])(?:token|event|keyEvent|policyFlags|wonadClaimed|"
                           r"wonadAdmissionToken|wonadDisplayId|abandoned)$", "", value)
            fields.append(compact(value))
        found.append(fields)
    require(len(found) == 1, f"expected one {definition or 'declaration'}::{name}, got {len(found)}")
    return found[0]


def java_params(source: str, name: str) -> list[str]:
    pattern = (r"^\s*(?:public|private)?\s*(?:long|KeyEvent|void)\s+" +
               re.escape(name) + r"\s*\(([^()]*)\)")
    found = re.findall(pattern, source, re.MULTILINE)
    require(len(found) == 1, f"expected one Java method {name}, got {len(found)}")
    return [re.sub(r"\s+\w+$", "", compact(value)) for value in found[0].split(",")]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("generated", type=Path)
    args = parser.parse_args()
    source = {path.name: path.read_text() for path in args.generated.iterdir()
              if path.is_file()}
    policy = source["InputDispatcherPolicyInterface.h"]
    fake_h = source["FakeInputDispatcherPolicy.h"]
    fake_cpp = source["FakeInputDispatcherPolicy.cpp"]
    jni = source["com_android_server_input_InputManagerService.cpp"]
    signatures = {
        "interceptKeyBeforeDispatching": ["const sp<IBinder>&", "const KeyEvent&", "uint32_t", "int64_t"],
        "dispatchUnhandledKey": ["const sp<IBinder>&", "const KeyEvent&", "uint32_t", "bool", "int64_t", "ui::LogicalDisplayId"],
        "notifyWonadKeyHandled": ["const KeyEvent&", "int64_t", "ui::LogicalDisplayId", "bool"],
    }
    for method, expected in signatures.items():
        for label, content, definition, declaration in (
            ("policy", policy, None, True),
            ("fake header", fake_h, None, True),
            ("fake implementation", fake_cpp, "FakeInputDispatcherPolicy", False),
            ("JNI override", jni, None, True),
            ("JNI implementation", jni, "NativeInputManager", False),
        ):
            actual = params(content, method, definition=definition, declaration=declaration)
            require(actual == expected, f"{label} {method}: {actual!r} != {expected!r}")

    normalized = compact(jni)
    for method, descriptor in (
        ("interceptKeyBeforeDispatching", "(Landroid/os/IBinder;Landroid/view/KeyEvent;IJ)J"),
        ("dispatchUnhandledKey", "(Landroid/os/IBinder;Landroid/view/KeyEvent;IZJI)Landroid/view/KeyEvent;"),
        ("notifyWonadKeyHandled", "(JIIIJIZ)V"),
    ):
        binding = f'GET_METHOD_ID(gServiceClassInfo.{method}, clazz, "{method}", "{descriptor}")'
        require(binding in normalized, f"missing exact private JNI binding {method}/{descriptor}")
    java_signatures = {
        "interceptKeyBeforeDispatching": ["IBinder", "KeyEvent", "int", "long"],
        "dispatchUnhandledKey": ["IBinder", "KeyEvent", "int", "boolean", "long", "int"],
        "notifyWonadKeyHandled": ["long", "int", "int", "int", "long", "int", "boolean"],
    }
    for method, expected in java_signatures.items():
        require(java_params(source["InputManagerService.java"], method) == expected,
                f"IMS private Java declaration drifted for {method}")
    require(java_params(source["KeyGestureController.java"], "interceptKeyBeforeDispatching") ==
            java_signatures["interceptKeyBeforeDispatching"], "KGC private token signature drifted")
    require("tokenObj.get(), keyEventObj.get(), policyFlags, static_cast<jlong>(wonadAdmissionToken)" in normalized,
            "before-dispatch JNI does not pass token after policy flags")
    require("policyFlags, wonadClaimed ? JNI_TRUE : JNI_FALSE, static_cast<jlong>(wonadAdmissionToken), wonadDisplayId.val()" in normalized,
            "unhandled JNI scalar order drifted")
    require("static_cast<jlong>(wonadAdmissionToken), keyEvent.getId(), keyEvent.getDeviceId(), keyEvent.getKeyCode(), nanoseconds_to_milliseconds(keyEvent.getDownTime()), wonadDisplayId.val(), abandoned ? JNI_TRUE : JNI_FALSE" in normalized,
            "primitive cleanup lost token, abandoned bit, or Java downTime milliseconds")
    claimed = normalized.index("if (delayMillis == -3)")
    malformed = normalized.index("if (delayMillis < 0)", claimed)
    oversized = normalized.index("if (delayMillis > 60000)", malformed)
    conversion = normalized.index("return milliseconds_to_nanoseconds(delayMillis)", oversized)
    require(claimed < malformed < oversized < conversion,
            "private/negative/oversized JNI policy decode ordering drifted")

    entry = source["Entry.h"]
    adapter = source["WonadPolicyKeyAdapter.kt"]
    dispatcher = source["InputDispatcher.cpp"]
    require("WonadCompletionOwner { NONE, PENDING, FOREGROUND, TAKEN }" in entry,
            "terminal native ownership state missing")
    require("mutable bool wonadInboundReleased = false" in entry,
            "exact native release marker missing")
    require("LinkedHashMap<Long, DeliveredAuthority>" in adapter and
            "deliveries[call.token] === own" in adapter,
            "nonce primary authority or compare-own-record rollback missing")
    require("call.provisional?.let { state.failApplicationPair(it, it.physical) }" in adapter,
            "failed invocation can leave unmatched terminal application input")
    require("if (abandoned) state.failApplicationPair(retained.pair, retained.physical)" in adapter,
            "native abandoned cleanup cannot drain its exact pair")
    require("it.trustedClaimed && it.focus === focus && it.sourceEvent === value" in adapter and
            "it.fallbackEvent === value" in adapter,
            "copied public facts can inherit synchronous authority")
    require("fallbackScope.set(null)" in adapter and
            "fallbackScope.set(expected.previousFallback)" in adapter,
            "nested neutral unhandled call does not shadow/restore outer fallback")
    require("static std::atomic<int64_t> next{1}" in dispatcher and
            "candidate == INT64_MAX ? 0 : candidate + 1" in dispatcher and
            "while (candidate != 0)" in dispatcher,
            "process nonce cannot prove signed63 no-wrap exhaustion")
    require("wonadAdmissionToken <= 0 || entry.wonadInboundReleased" in dispatcher,
            "claimed callback return can republish a released inbound entry")
    require(not any(name in source for name in ("KeyEvent.java", "InputEvent.java", "Input.h")),
            "public event/SDK authority surface unexpectedly included")

    print(f"INDEPENDENT_PRIVATE_PROTOCOL_PASS checks={checks}")
    for name in sorted(source):
        print(hashlib.sha256((args.generated / name).read_bytes()).hexdigest(), name)


if __name__ == "__main__":
    main()
