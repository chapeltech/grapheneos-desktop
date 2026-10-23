# Phase 1 post-target keyboard containment candidate

Status: **external-only, partial, unqualified host prototype**.

This directory does not modify the repository, custom7 stage, OS image, SDK,
APK, or runtime evidence. It is not a build or guest qualification. Its narrow
purpose is to project and compile-test the target-aware dispatch portion of the
Phase 1 external-shell input contract against exact custom7 source bytes.

## Implemented boundary

After InputDispatcher has resolved a focused input token and a KeyEvent reaches
`KeyGestureController.interceptKeyBeforeDispatching`, the candidate enforces:

- a fixed registered Wonad/Rust command still has priority and keeps the
  existing exact-claim authorization;
- ordinary keys, plain Meta/Alt, plain Tab, and ordinary Escape from an exact
  healthy claimed origin are returned to the focused external application;
- direct Android UI/system-action keys such as Home, Recents, App Switch, All
  Apps, Screenshot/SysRq, Lock, Assist/Voice Assist, DND, Accessibility,
  Notification, Settings, Search and display/keyboard-light actions are
  consumed as exact physical pairs for a claimed origin;
- only the Tab pair of Alt+Tab is consumed; the Alt pair remains balanced
  application input;
- claimed input returns before Android before-capture, after-capture,
  capturable, Meta fallback and ordinary global-shortcut stages;
- an app-returned claimed event is bound to the exact focused input token and
  physical event, bypasses stock unhandled shortcuts, and may generate only a
  lineage-bound KeyCharacterMap fallback;
- a fallback that maps to Home or another system-action role is consumed;
- an ordinary fallback can return to the same claimed app lineage without
  first re-entering `PhoneWindowManager.interceptKeyBeforeQueueing`;
- a claimed DOWN remains claimed/drained after claim retirement, replacement,
  blocked state, display-stamp drift, or same-slot device/key reuse;
- an unclaimed/phone DOWN remains authoritative for its exact terminal even if
  a claim is published in between; claim activation is not retroactive;
- per-device exceptional ledger exhaustion fails black for that physical
  device without consuming an unrelated phone keyboard, and is released only
  by an unchanged complete native all-key-UP census or exact device removal;
- lifecycle transitions publish BLOCKED/RETIRED into the pure pair helper
  synchronously before authority removal/replacement.

No stock Recents, All Apps, Caps action, long-Escape Toast/QUIT, queued action,
PWM endpoint-owner, or private WMS task-close mechanism is added for claimed
external input. Those rejected mechanisms from snapshots 1–11 are absent.

## Deliberately retained exceptions

The candidate retains the existing source order for:

1. `KeyCombinationManager` multi-key hardware safety gestures; and
2. SecurePaste handling.

The pinned multi-key implementation uses the virtual keyboard and default
display and its matching is device/display agnostic. Cross-device Power/Volume
mixing and default-display effects therefore remain an explicit open Phase 1
obligation. This record does not waive or qualify that obligation.

## OPEN blocker: pre-target keyboard policy

This candidate is **not total input containment**.

`PhoneWindowManager.interceptKeyBeforeQueueing` can execute Assist, Voice
Assist, PiP/system-navigation, StatusBar and global-key behavior before a
focused target is available. For ordinary USB/Bluetooth keyboards,
`KeyboardInputMapper::getDisplayId()` commonly returns `INVALID` when there is
no viewport. A numeric display or mutable top-focus guess would be unsafe and
is intentionally not introduced.

Existing port/descriptor association APIs are also insufficient qualification
proof: they are global/no-owner/no-ack, a descriptor can identify multiple
instances, display-info updates are asynchronous, and remapping while keys are
down can split DOWN/UP display stamps. A separately reviewed pre-target design
must carry immutable queue-origin, input-device generation/identity, initial
DOWN lineage, and exact target/claim evidence without calling WMS/InputReader
from the pure pair-state monitor. Until that is implemented and tested, this
candidate cannot satisfy the full external-shell total-control contract.

## Exact inputs and generated surface

`apply_candidate.py` authenticates these rewritten inputs before doing any
work:

- custom7 `InputManagerService.java`:
  `df0e4cc78508383cd60fd2cd534ba450a0df2071b211ee21115fa71f35470dc1`
- custom7 `KeyGestureController.java`:
  `3acaa08d5a39200bbcd521f760339c4d531936656899c195b9b9fa9b28aa66c5`
- repository `WonadInputBridge.kt`:
  `b512112fe58157e8e1a18baa3dbf0c0c338f073ea4d901c63d9949aaa11e60ff`
- repository `WonadUiBridge.kt`:
  `8d227e84eef912d1016698e018ca37642cff8ec0150a380eb25dbf7e8dc21da4`

It also authenticates the support-source pins listed in the script, including
PhoneWindowManager, KeyboardInputMapper, KeyCombinationManager and the exact
framework state-read implementations. A successful invocation creates only a
fresh caller-selected directory containing:

- `InputManagerService.java`
- `KeyGestureController.java`
- `WonadInputBridge.kt`
- `WonadUiBridge.kt`
- `WonadPolicyKeyContainment.kt`
- `WonadPolicyKeyAdapter.kt`

No public SDK, Binder or JNI surface is added.

## Historical defect mapping

The final host controls do not merely drop the snapshot 1–11 regressions:

- queued START, action-ticket and PWM endpoint state no longer exists, so the
  64-ticket backlog, post rejection, stale START, replacement cleanup and
  helper-to-KGC/WMS lock-cycle mechanisms are source-guarded absent;
- stock external Escape/Toast/QUIT and private task-close targets no longer
  exist; ordinary claimed Escape is application input;
- phone APP_SWITCH/Meta/Alt/Escape routes remain stock in the pure compiled
  matrix, including quick DOWN/UP and interleaving with claimed input;
- exact claimed dedicated-key DOWN/repeat/UP and Alt+Tab Tab terminals remain
  consumed even after focus/claim drift, including the captured-app orphan-UP
  class;
- the pair ledger retains exact `{device,keyCode,downTime}` and claim/binder/
  display/user/generation/incarnation identity, with same-slot replacement and
  stale-UP controls;
- device-scoped saturation and epoch-checked census controls prove unrelated
  phone devices remain stock;
- the adapter fixture exercises exact focus-token unhandled/fallback lineage,
  retired fallback fail-black, fallback Home consumption, and phone recovery;
- stock shortcut implementation methods are byte-equal to custom7 and are
  bypassed rather than rewritten for the post-target claimed path.

## Bounded host replay

Run the literal self-contained command:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-recents-key-containment-kotlin-prototype-20261012-snapshot-13-review/test_candidate.py
```

The replay authenticates all source pins, materializes a fresh six-file output,
checks source order and removed surfaces, and compiles/runs two bounded Kotlin
fixtures with the pinned custom7 Kotlin/JDK and 256/128 MiB heap caps. It does
not run Gradle, Soong, Docker, an emulator, or Android runtime code.

Expected terminal lines are:

```text
POST_TARGET_TOTAL_CONTROL_PASS checks=78
OPEN: pre-target PWM policy for keyboards without a viewport/display is unqualified
```

The PASS applies only to the stated host projection. It is not permission to
apply, stage, build, or qualify the candidate.
