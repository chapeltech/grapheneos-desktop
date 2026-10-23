#!/usr/bin/env python3
"""Conditional actual-method origin/target guard prototype; no source-tree writes."""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
import os
import argparse

HERE = Path(__file__).resolve().parent
EXPECTED_BEFORE = "12b902ba1571abb0f6455730918b04672a817273e43dcc4ca14ed7707aaf2cb9"

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def method(text, signature):
    start = text.index(signature)
    brace = text.index("{", start)
    depth, state, i = 0, "code", brace
    while i < len(text):
        c, after = text[i], text[i + 1] if i + 1 < len(text) else ""
        if state == "code":
            if c == '"': state = "string"
            elif c == "'": state = "char"
            elif c == "/" and after == "/": state = "line"; i += 1
            elif c == "/" and after == "*": state = "block"; i += 1
            elif c == "{": depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0: return text[start:i + 1]
        elif state in ("string", "char"):
            if c == "\\": i += 1
            elif (state == "string" and c == '"') or (state == "char" and c == "'"): state = "code"
        elif state == "line" and c == "\n": state = "code"
        elif state == "block" and c == "*" and after == "/": state = "code"; i += 1
        i += 1
    raise AssertionError(signature)

def once(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)

def run(argv, cwd=None):
    result = subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=60, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0, result.stdout
    return result.stdout

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    before = HERE / "before"
    assert digest(before / "MANIFEST.json") == EXPECTED_BEFORE
    inputs = json.loads((before / "MANIFEST.json").read_text())
    for name, pin in inputs.items():
        assert digest(before / name) == pin["sha256"]
        assert digest(Path(pin["source"])) == pin["sha256"]
    source = (before / "dispatcher/InputDispatcher.cpp").read_text()
    admission_path = HERE / "admission-before/InputDispatcher.cpp"
    assert digest(admission_path) == "ce11a8f478f4c444dd65ec475aa581c0ee9643e009a3536626c5683221af316f"
    admission_source = admission_path.read_text()
    before_policy = method(admission_source,
        "void InputDispatcher::doInterceptKeyBeforeDispatchingCommand(")
    proposed_policy = once(before_policy, "    KeyEvent event = createKeyEvent(entry);", """    const auto beforeTarget = witnessLocked(getFocusedWindowHandleLocked(displayId));
    if (entry.wonadOrigin && entry.wonadOrigin->route != WonadKeyOriginReceipt::Route::STOCK &&
            !entry.wonadOrigin->accepts(beforeTarget)) {
        entry.wonadOrigin->abandoned = true;
        entry.interceptKeyResult = KeyEntry::InterceptKeyResult::SKIP;
        return;
    }
    KeyEvent event = createKeyEvent(entry);""")
    proposed_policy = once(proposed_policy,
        "            if (wonadAdmissionToken <= 0 || entry.wonadInboundReleased) {", """            const auto finalTarget = witnessLocked(getFocusedWindowHandleLocked(displayId));
            if (wonadAdmissionToken <= 0 || entry.wonadInboundReleased || !entry.wonadOrigin ||
                    entry.wonadOrigin->route != WonadKeyOriginReceipt::Route::CLAIMED ||
                    !entry.wonadOrigin->accepts(finalTarget) || !beforeTarget.sameExact(finalTarget)) {
                if (entry.wonadOrigin) entry.wonadOrigin->abandoned = true;""")
    state = (before / "dispatcher/InputState.cpp").read_text()
    get_display = method(source, "ui::LogicalDisplayId InputDispatcher::getTargetDisplayId(")
    find_target = method(source, "InputDispatcher::findFocusedWindowTargetLocked(")
    # Include the return type which is on its own preceding line in actual source.
    find_target = "Result<sp<WindowInfoHandle>, InputEventInjectionResult>\n" + find_target
    proposed_display = once(get_display, "    ui::LogicalDisplayId displayId{ui::LogicalDisplayId::INVALID};",
        """    if (entry.type == EventEntry::Type::KEY) {
        const KeyEntry& key = static_cast<const KeyEntry&>(entry);
        if (key.wonadOrigin && key.wonadOrigin->route == WonadKeyOriginReceipt::Route::CLAIMED) {
            return key.wonadOrigin->admittedTarget.display;
        }
    }
    ui::LogicalDisplayId displayId{ui::LogicalDisplayId::INVALID};""")
    proposed_target = once(find_target,
        "    sp<WindowInfoHandle> focusedWindowHandle = getFocusedWindowHandleLocked(displayId);",
        """    sp<WindowInfoHandle> focusedWindowHandle = getFocusedWindowHandleLocked(displayId);
    if (entry.type == EventEntry::Type::KEY) {
        const KeyEntry& key = static_cast<const KeyEntry&>(entry);
        if (key.wonadOrigin && key.wonadOrigin->route != WonadKeyOriginReceipt::Route::STOCK &&
                !key.wonadOrigin->accepts(witnessLocked(focusedWindowHandle))) {
            key.wonadOrigin->abandoned = true;
            return injectionError(InputEventInjectionResult::FAILED);
        }
    }""")
    track = method(state, "bool InputState::trackKey(")
    proposed_track = once(track, "    switch (entry.action) {", """    const auto exact = entry.exactWonadOrigin();
    if (exact.valid()) {
        const ssize_t index = findKeyMemento(entry);
        if (entry.action == AKEY_EVENT_ACTION_UP &&
                (index < 0 || !(mKeyMementos[index].wonadOrigin == exact))) return false;
        if (entry.action == AKEY_EVENT_ACTION_DOWN && index >= 0 &&
                !(mKeyMementos[index].wonadOrigin == exact)) return false;
    }
    switch (entry.action) {""")
    # A claimed fallback needs a separately scoped fallback ledger (still OPEN).
    # Never let its UP erase stock's public-keyCode-only fallback mapping.
    proposed_track = once(proposed_track, "            if (entry.flags & AKEY_EVENT_FLAG_FALLBACK) {",
        "            if (!exact.valid() && (entry.flags & AKEY_EVENT_FLAG_FALLBACK)) {")
    add = method(state, "void InputState::addKeyMemento(")
    proposed_add = once(add, "    KeyMemento memento;", "    KeyMemento memento;\n    memento.wonadOrigin = entry.exactWonadOrigin();")
    cancel = method(state, "bool InputState::shouldCancelKey(")
    proposed_cancel = once(cancel, "    if (options.keyCode", """    if (options.wonadExactOrigin && !(memento.wonadOrigin == *options.wonadExactOrigin)) {
        return false;
    }
    if (options.keyCode""")
    loop_start = state.index("    for (KeyMemento& memento : mKeyMementos)")
    loop_end = state.index("    for (const MotionMemento&", loop_start)
    cancel_loop = state[loop_start:loop_end]
    proposed_cancel_loop = once(cancel_loop, "            events.push_back(\n", "            auto cancellation =\n")
    proposed_cancel_loop = once(proposed_cancel_loop, "/*repeatCount=*/0, memento.downTime));",
        """/*repeatCount=*/0, memento.downTime);
            if (options.wonadExactOrigin) {
                cancellation->wonadCancellationIdentity = memento.wonadOrigin;
            }
            events.push_back(std::move(cancellation));""")
    find_memento = method(state, "ssize_t InputState::findKeyMemento(")
    proposed_find_memento = once(find_memento,
        "        const KeyMemento& memento = mKeyMementos[i];", """        const KeyMemento& memento = mKeyMementos[i];
        const auto exact = entry.exactWonadOrigin();
        if (exact.valid()) {
            if (!(memento.wonadOrigin == exact) || memento.downTime != entry.downTime) continue;
        } else if (memento.wonadOrigin.valid()) {
            continue; // STOCK must not consume a colliding privately tagged pair.
        }""")
    # Actual notifyKey/injection are preserved as inputs, with guards proving
    # baseline origin blindness; this prototype does not pretend to wire ingress.
    notify = method(source, "void InputDispatcher::notifyKey(")
    inject = method(source, "InputEventInjectionResult InputDispatcher::injectInputEvent(")
    assert "args.deviceId, args.source, args.displayId, policyFlags" in notify
    assert "intendedDisplayId = calculateIntendedDisplayIdLocked(args)" in notify
    assert "POLICY_FLAG_INJECTED | POLICY_FLAG_TRUSTED" in inject
    assert "resolvedDeviceId = event->getDeviceId()" in inject
    substitutions = {
        "ORIGIN_HEADER": (HERE / "candidate/WonadKeyOrigin.h").read_text(),
        "STOCK_DISPLAY": get_display.replace("InputDispatcher::", "StockInputDispatcher::"),
        "PROPOSED_DISPLAY": proposed_display,
        "STOCK_TARGET": find_target.replace("InputDispatcher::", "StockInputDispatcher::"),
        "PROPOSED_TARGET": proposed_target,
        "STOCK_TRACK": track.replace("InputState::", "StockInputState::"),
        "PROPOSED_TRACK": proposed_track,
        "STOCK_ADD": add.replace("InputState::", "StockInputState::"),
        "PROPOSED_ADD": proposed_add,
        "STOCK_FIND_MEMENTO": find_memento.replace("InputState::", "StockInputState::"),
        "PROPOSED_FIND_MEMENTO": proposed_find_memento,
        "PROPOSED_CANCEL": proposed_cancel,
        "CANCEL_KEY_LOOP": proposed_cancel_loop,
        "ALLOCATOR": method(admission_source, "int64_t nextWonadAdmissionToken()"),
        "PROPOSED_POLICY": proposed_policy,
    }
    cpp = (HERE / "tests/OriginTargetTest.cpp.in").read_text()
    for name, value in substitutions.items(): cpp = cpp.replace("@@" + name + "@@", value)
    if args.evidence:
        assert args.evidence.resolve().is_relative_to(HERE)
        args.evidence.mkdir(parents=True, exist_ok=False)
        output = args.evidence
        temporary = None
    else:
        temporary = tempfile.TemporaryDirectory(prefix="wonad-origin-target-host-")
        output = Path(temporary.name)
    (output / "origin-target.cpp").write_text(cpp)
    (output / "InputDispatcher.proposed.cpp").write_text(proposed_display + "\n\n" + proposed_target + "\n")
    (output / "InputState.proposed.cpp").write_text(proposed_track + "\n\n" + proposed_add + "\n\n" + proposed_find_memento + "\n\n" + proposed_cancel + "\n\n" + proposed_cancel_loop)
    (output / "PolicyUnlock.proposed.cpp").write_text(proposed_policy + "\n")
    run(["/usr/bin/g++", "-std=c++20", "-O0", "-pthread", str(output / "origin-target.cpp"),
         "-o", str(output / "origin-target")])
    result = run([str(output / "origin-target")])
    print(result, end="")
    if args.evidence: (output / "replay-output.txt").write_text(result)
    if temporary: temporary.cleanup()

if __name__ == "__main__": main()
