# Phase 1 external blocked-input containment candidate

Status: **external patch/test preparation only**. Nothing here has been applied
to the Wonad repository, staged custom7/source7, an SDK, APK, OS image, or guest.
Passing host controls is not platform compilation or runtime qualification.

## Authenticated inputs and defect

The staged custom7 `KeyGestureController.java` input is SHA-256
`3acaa08d5a39200bbcd521f760339c4d531936656899c195b9b9fa9b28aa66c5`.
Its stock `INTERCEPT_STAGE_SHORTCUTS_BEFORE_KEY_CAPTURE` executes before the
general `WonadInputBridge.consumeClaimedInput` seam. Thus an already blocked,
claimed external event can execute configured non-capturable shortcuts,
RECENT_APPS/APP_SWITCH, brightness and keyboard-backlight actions, ALL_APPS,
SCREENSHOT, LOCK, FULLSCREEN, contextual/DND/accessibility actions, the focused
capture Escape timer, or the final WindowManager callback before fail-black
containment is consulted. That contradicts API-v3.md:174 and
EXTERNAL-SHELL.md:33: claimed/blank external input is consumed rather than
falling through to stock Android UI.

The staged `PhoneWindowManager.java` input is SHA-256
`25be0cd9384ef463af854067e4904701041ece23ef0e9b9f8cc348503e6e1898`.
APP_SWITCH START preloads Recents, while its old canceled COMPLETE did not
cancel preload. Moving containment earlier without pair cleanup could therefore
strand both stock key bookkeeping and the global preload.

## Candidate behavior

`candidate.patch` changes only authenticated copies of those two Java files:

1. Multi-key safety gestures, SecurePaste policy, and the fixed Wonad desktop
   alphabet retain priority. Immediately afterward, one generic guard consults
   the existing exact `consumeClaimedInput` authority before Meta opt-out and
   every stock before-capture action. A blocked claimed external event returns
   consumed; phone, unclaimed, and healthy external events retain stock flow.
2. Stock consumed-key bookkeeping records `{device,key,downTime}` rather than
   only `{device,key}`. A new repeat-zero DOWN retires a missing-UP ledger; a
   stale old UP cannot clear or consume a replacement phone pair.
3. APP_SWITCH and RECENT_APPS retain an additional exact pair state. A blocked
   first DOWN never enters stock and drains through terminal. If APP_SWITCH
   started while healthy and later becomes blocked, one canceled COMPLETE is
   sent for the original device/display owner, the exact stock ledger is
   forgotten, and the remaining pair drains. New downTime/device-ID reuse and
   late old UP cannot affect the replacement. Missing physical devices are
   pruned on the next Recents event; only a retired stock APP_SWITCH requests
   owner-checked cancellation.
4. PhoneWindowManager records the exact device/display that owns its single
   preload slot. Canceled/keyguard completion cancels only that owner. An old
   external completion cannot cancel a newer phone or HOME preload.
5. Focused-capture Escape delayed completions are exact device/downTime/message
   owned. A matching blocked continuation or new physical replacement removes
   only that message and emits one canceled COMPLETE using the original
   display/focus. A late removed message cannot execute, and other devices are
   isolated.

No public/private IPC, SDK, AIDL, Rust command alphabet, or ABI changes.

## Explicit boundaries

- Multi-key combinations remain ahead of containment as intentional platform
  safety gestures. SecurePaste keeps its existing policy-first ordering, then
  performs its own exact containment check before any grant.
- Inputflinger updates Caps/Num/Scroll lock meta state before this Java dispatch
  seam. The candidate consumes the blocked KeyEvent and suppresses the Java
  notification/action path, but cannot rewind that earlier native lock-state
  side effect. Closing that stronger interpretation would require a reviewed
  earlier native/queue seam; this candidate does not claim it.
- An action fully routed while the claim was healthy is not retroactively
  revoked. The candidate does unwind the two stateful before-capture paths that
  can otherwise complete after containment: APP_SWITCH and delayed Escape.
- Global after-capture Meta/Alt-Tab state which was already in flight before a
  claim blocks has no exact owner in pinned stock code. The generic guard
  prevents new blocked events from reaching that stage; it deliberately does
  not clear a potentially unrelated phone state without an ownership design.
- Pair6 injected APP_SWITCH on display 0. `claimedInputBlocked` rejects display
  0 as claim authority, so this external containment defect does not explain
  Pair6's phone-Home result. The separate TIS/focus diagnostics now show WMS
  display 0 versus stale TIS display 3 and remain owned by the other fix lane.

## Executed host controls

Command:

```text
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B test_candidate.py
```

Latest result on 2026-10-12: **8/8 PASS**, zero skips. The tests compile and
execute Java 21 extracted verbatim from the candidate, rather than a parallel
Python state model:

- authenticated preimage and RED ordering proof;
- exact generic guard method controls for phone/healthy isolation and blocked
  configured shortcut, ALL_APPS, SCREENSHOT, FULLSCREEN, LOCK, brightness,
  keyboard backlight, DND, APP_SWITCH, and focused-capture Escape;
- exact Recents state helper controls covering downTime, focus/display
  migration, lost UP, stale UP, device-ID reuse, bounded terminal state, and
  missing-device retirement;
- exact stock stage controls for physical-pair identity and stale cleanup;
- exact Escape cancellation/completion ownership controls;
- exact PhoneWindowManager owner-aware preload/cancel/toggle controls.

The retained JDK is from the authenticated client-tools rootfs. Tests create a
temporary `java.home` view solely because that immutable rootfs has absolute
`/etc` symlinks; no retained tool or host path is modified.

## Repository-test impact if application is authorized

`android/tests/test_native_shortcut_priority_compiled.py` currently expects a
blocked ordinary key to trace `multi, stock-before, contained`, and a stock
before-capture action to win without reaching containment. Those two assertions
must intentionally change to `multi, contained`: the full contract requires the
generic barrier before stock. Multi-key safety expectations remain unchanged;
fixed Wonad commands still precede stock. Its reduced Java fixture must also
stub/extract the new guard and pair-owned helpers.

`android/tests/test_native_signed_rpc_contract.py` still correctly requires the
fixed Wonad alphabet before stock. Input-bridge cleanup tests remain valid and
should be composed with the new exact dispatch/pair regressions. No repository
test has been edited in this external preparation.
