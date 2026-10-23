# Phase 1 external Recents-key containment candidate

Status: **external patch/test preparation only**. Nothing in this directory has
been applied to the Wonad worktree, staged custom7, source7, an SDK, an APK, an
OS image, or a guest. Passing these host tests is not runtime qualification.

## Concrete defect

The authenticated staged custom7 `KeyGestureController.java` input has SHA-256
`3acaa08d5a39200bbcd521f760339c4d531936656899c195b9b9fa9b28aa66c5`.
In `interceptKeyBeforeDispatching`, multi-key safety handling (607-611), secure
paste (613-626), and the fixed Wonad shortcut alphabet (628-636) run first.
Stock `INTERCEPT_STAGE_SHORTCUTS_BEFORE_KEY_CAPTURE` then runs at 646-650,
before the general fail-black `WonadInputBridge.consumeClaimedInput` call at
652-655.

The stock before-capture stage treats `KEYCODE_RECENT_APPS` as an immediate
complete gesture and `KEYCODE_APP_SWITCH` as a paired START/COMPLETE gesture.
Those keys are deliberately absent from the authenticated Rust desktop command
alphabet (`android/broker-rust/src/shortcuts.rs`, SHA-256
`b2150abcacd1b6f3dffecb3672082cd587d00cc9b2f4b06f3f2d4d133f5c9d90`).
Consequently, when an exact claimed external display is already fail-black,
stock can invoke global phone Recents before the containment decision is
reached. This contradicts the Phase 1 rule that a claimed-but-unavailable
external display is parked black and its input is consumed.

The authenticated staged `PhoneWindowManager.java` input has SHA-256
`25be0cd9384ef463af854067e4904701041ece23ef0e9b9f8cc348503e6e1898`.
Its APP_SWITCH START preloads Recents, but its canceled COMPLETE does nothing.
Moving containment ahead of stock without explicit pair cleanup would therefore
strand both the stock key ledger and `mPreloadedRecentApps` when a claim becomes
blocked between DOWN and UP.

## Proposed bounded behavior

`candidate.patch` changes only those two authenticated Java inputs:

1. After multi-key, secure-paste, and fixed Wonad shortcut processing, but before
   Meta opt-out and stock before-capture processing, inspect only APP_SWITCH and
   RECENT_APPS with the existing exact `consumeClaimedInput` authority decision.
2. An already-blocked first DOWN never reaches stock. Its repeat/UP/cancel events
   remain consumed even if the claim becomes healthy before the pair terminates.
3. If a healthy APP_SWITCH DOWN already entered stock and a repeat/UP observes a
   blocked claim, emit exactly one canceled APP_SWITCH COMPLETE, forget the exact
   stock device/key ledger entry, and drain the rest of that pair.
4. If stock already completed the one-shot RECENT_APPS action, a later blocked
   event cannot revoke it retroactively. The proposal forgets/drains only its
   remaining key bookkeeping. When the claim was already blocked at DOWN, the
   action is prevented.
5. `PhoneWindowManager` cancels an APP_SWITCH preload on canceled COMPLETE and
   also if keyguard appears between START and COMPLETE. Healthy START/COMPLETE
   still preload/toggle exactly once.
6. Display 0, unclaimed external displays, healthy claimed displays, unrelated
   keys, multi-key safety handling, and secure paste keep their existing order.

The pair map follows stock `InterceptKeyStage` identity: device ID plus key code.
It is only two possible keys per active device and removes an entry at UP/cancel.
Like the stock ledger, it cannot synthesize cleanup when a device disappears
without any terminal event. A later event is drained; hidden preload lifetime
across a no-event physical unplug remains a runtime/lifecycle coverage limit,
not an asserted pass.

## Executed host controls

Command:

```text
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B test_candidate.py
```

Result on 2026-10-12: **6/6 PASS** in 1.988 seconds. The test executes Java 21
compilation/runs of code extracted verbatim from the candidate rather than a
parallel Python model:

- exact containment state helper: 18 transition/isolation controls;
- exact targeted interceptor method plus helper: 15 routing/cancellation
  controls;
- exact PhoneWindowManager APP_SWITCH case: 8 preload/cancel/toggle controls;
- authenticated preimage/RED-structure, placement, and bounded-delta checks.

The retained JDK comes from the prior client-tools rootfs. The test creates a
temporary `java.home` view because that immutable rootfs contains absolute
`/etc` symlinks; neither the JDK input nor the host is modified.

## Existing repository-test impact if root authorizes application

- `android/tests/test_native_shortcut_priority_compiled.py` (SHA-256
  `63ddcb99ab1704d7d1302891669c5159619a849a8a2223ed44996d906817b101`)
  extracts the whole real dispatch method into a reduced Java fixture. It would
  fail to compile because the new targeted method/helper and stage ledger APIs
  are absent from that fixture. Its broad assertion that ordinary contained
  keys still pass through stock before-capture bookkeeping remains correct; it
  must gain the targeted APP_SWITCH/RECENT_APPS controls, not reverse the order
  for every system key.
- `android/tests/test_native_signed_rpc_contract.py` (SHA-256
  `26e9d4dbbb281c7614c4157ede2f9cec6174ef7fb0ccf9ed9788ba614c986852`)
  asserts that the fixed Wonad alphabet precedes stock before-capture. That
  assertion remains correct and should not change.
- `android/tests/test_native_input_cleanup_failures_compiled.py` (SHA-256
  `ada620d978c344f5021e16fef80bbe5a9a9cad86a21713157581cd243ee71b5d`)
  covers fail-black bridge cleanup and remains conceptually unchanged. A future
  repository regression should compose its blocked decisions with the new
  exact Recents pair tests.

Thus the only existing order-fixture change is adding the targeted exception
and its exact helper dependencies; the global stock-before-late-containment
control remains for non-Recents keys.

## Pair6 evidence and non-claim

The retained Pair6 Recents journal
`android/out/phase1-evidence-custom7-5/runtime-recents-packet7-20261011-6/recents/commands.json`
has SHA-256 `514dfb10cf661103b5ead8e6b7aa7a8f51c4dea645737182b0cdd9a1e4475aad`.
Its APP_SWITCH command explicitly used display 0. The existing
`claimedInputBlocked` returns false for display IDs at or below the default
display, so this external-display containment defect does **not** explain the
Pair6 phone Home result. Pair6 input routing remains unresolved. The current
generation7 Recents producer adds pre/post TouchInteractionService evidence to
discriminate stale Launcher focus, command blocking, and later Overview
processing; this proposal neither substitutes for nor prejudges that evidence.
