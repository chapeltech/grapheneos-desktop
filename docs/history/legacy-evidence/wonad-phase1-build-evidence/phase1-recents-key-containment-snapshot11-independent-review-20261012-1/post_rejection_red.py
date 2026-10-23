#!/usr/bin/env python3
"""Expected-RED source-shaped checks for snapshot-11 Handler rejection.

These assertions describe the required fail-closed property: once a START may
have reached a stock endpoint, rejecting a terminal/cleanup enqueue may not
both erase the exact ticket and omit the matching stock cancellation.
"""

from pathlib import Path


SNAPSHOT = Path(
    "/u/elric/tree/wonad-phase1-build-evidence/"
    "phase1-recents-key-containment-kotlin-prototype-20261012-snapshot-11"
)
KGC = (SNAPSHOT / "generated/KeyGestureController.java").read_text()


def one(text: str, needle: str) -> int:
    assert text.count(needle) == 1, (needle, text.count(needle))
    return text.index(needle)


def block(start: str, end: str) -> str:
    first = one(KGC, start)
    last = KGC.index(end, first)
    return KGC[first:last]


# Lifecycle retirement is invoked while WMS still owns its global lock.  It
# cannot fall back to inline KGC/PWM, but enqueue rejection must stop/retain
# authority rather than merely log and return after the helper marked cleanup.
listener = block(
    "WonadPolicyKeyAdapter.registerCleanupListener(decision -> {",
    "        });\n        im.registerInputDeviceListener",
)
assert "if (!mHandler.post(" in listener
assert "throw new IllegalStateException" in listener, (
    "lifecycle cleanup accepts Handler rejection and loses its terminal obligation"
)


# The three input-side completion paths currently erase the helper ticket with
# takeQueuedTerminal(..., true).  A safe branch must also run the exact endpoint
# compensation (or fail-stop before erasing it), rather than log and continue.
for label, marker, required in (
    ("APP_SWITCH", 'Slog.e(TAG, "KGC handler rejected Wonad APP_SWITCH completion")',
        "dispatchWonadRecentTerminal"),
    ("Escape", 'Slog.e(TAG, "KGC handler rejected Wonad Escape cancellation")',
        "dispatchWonadEscapeCancel"),
    ("Alt-Tab", 'Slog.e(TAG, "KGC handler rejected Wonad Alt-Tab completion")',
        "dispatchWonadAltTabTerminal"),
):
    at = one(KGC, marker)
    rejection = KGC[KGC.rfind("if (!mHandler.post", 0, at):at]
    assert required in rejection or "throw new IllegalStateException" in rejection, (
        f"{label} post rejection erases/logs without exact terminal compensation"
    )

print("PASS Handler rejection retains or compensates every exact terminal")
