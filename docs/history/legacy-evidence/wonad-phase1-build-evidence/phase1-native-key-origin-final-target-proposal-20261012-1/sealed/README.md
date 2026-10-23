# Conditional native origin/final-target implementation proposal

2026-10-12. External evidence only. This is a tested target-constraint proposal,
not a complete Android implementation, a stageable patch or isolation approval.
No repository/source7/stage/SDK/image/key/runtime writes were made.

The original native gap is retained: notifyKey resolves intendedDisplayId for
queue policy but stores args.displayId in KeyEntry. A public INVALID display can
therefore move from external F1 to phone F2 before actual delivery. Globally
replacing KeyEntry.displayId would change normal STOCK focus migration and is
not the proposal.

## Proposed private contract

ARCHITECTURE.md was emitted before this implementation. First physical DOWN
requires a private immutable reader/mapper/pair/reset origin and a one-time
STOCK/CLAIMED/DRAIN route receipt. The receipt must exist before a later policy
invocation can observe a different target and reclassify the key as STOCK.
Ordinary UP/repeats retain that exact receipt; public facts cannot recreate it.

The target half preserves raw public displayId. Only CLAIMED receipts constrain
getTargetDisplayId. Actual focused-window resolution and every retry compare
an immutable witness: native display lifetime, focus-transition serial,
WindowInfo ID, strong binder token, exact strong Connection identity, owner
UID/PID and application token. The before-dispatch callback captures this
witness before Java unlock and rechecks it after return before native PENDING
ownership. F1→F2→F1 and handle/channel/display reuse do not renew authority.
An invalid claimed return uses the existing exact-token abandoned cleanup
outside mLock, not cleanup of a public KeyEvent ID or another invocation.

The InputState projection tags claimed mementos and finds them by the exact
private origin plus bound immutable native downTime and original public facts.
Simultaneous merged mappers with equal public key fields remain separate.
STOCK lookup cannot consume a tagged claimed memento. A private cancellation
selector synthesizes canceled UP only from the exact recorded DOWN and copies
only a cancellation identity, never an admission receipt/token. It does not
cancel another mapper/device/STOCK key. Original-connection enqueue and full
abandonment/lifecycle integration remain required; this fixture does not wire
those hooks or reinterpret stock POLICY cancellation as pair-scoped.

## Executed evidence

The immutable before snapshot binds sixteen actual pinned native files. The
runner extracts and compiles actual getTargetDisplayId,
findFocusedWindowTargetLocked, InputState trackKey/findKeyMemento/addKeyMemento,
shouldCancelKey and the key cancellation-construction loop. It also extracts
the real previously sealed private-admission native policy-unlock method.
Proposed fragments are generated into the evidence, not hand-written copies
of those methods. Android surrounding types and ingress/lifecycle witnesses
are narrow host stubs and are explicitly conditional.

The final host fixture passes 90 controls, including side-by-side actual STOCK
methods, null focus, phone DOWN/UP, intentionally allowed STOCK unmatched UP,
paused/key-wait retries, raw INVALID external-to-phone targeting with a receipt,
same-display replacement, focus/channel/display/owner drift, malformed/DRAIN
receipts, reset during Java unlock, mapper/public-slot collisions and actual
pair-scoped canceled-UP construction. The real notifyKey/injectInputEvent
methods are authenticated source-shape controls only, not executed here.
The no-receipt case deliberately prints
OPEN_EXPECTED_NO_RECEIPT_F1_F2_LEAK_REPRODUCED. That counterexample is not a
successful isolation test.

Replay the sealed runner without modifying its read-only payload:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B sealed/test_origin_proposal.py
```

## Required open integration

No origin issuing code, receipt authority/ledger or real lifecycle serial is
installed. `privatelyAttested` and witness lifecycle values in the header/host
fixture are explicit stand-ins, not trust supplied by a caller Boolean or a
mutable display/device cache. Before this can become a platform patch, it needs:

- Reader composite and endpoint/mapper incarnation, first-DOWN pair nonce,
  immutable physical facts, reset/config/production/retirement sequences, and
  retire-before-mapper-erase payloads. InputDevice generation is not authority.
- Private C++→AIDL→Rust filter→callback origin roundtrip; delayed SlowKeys keys
  cannot survive exact reset/removal/re-add with borrowed public downTime.
- A bounded per-origin route-history protocol, consistent STOCK first-DOWN
  ownership, exact terminal/repeat handling, lifetime-scoped overflow/drain,
  pair-scoped fallback history, and no cross-device phone suppression.
- Exact original-connection abandonment enqueue with acceptance/failure,
  monitor isolation, teardown/dispatch-disable and abort ownership controls.
- A private atomic Reader pair census plus reader activity cutoff and an
  acknowledged downstream filter/dispatcher/policy fence. Independent
  getKeyCodeState calls and the Java helper mutation epoch do not prove all-UP;
  without that fence quarantine must not be released early.
- Board-audited PhoneSafetyRealm membership/epoch and private scoped chord
  seams. Composite isExternal, .idc device.internal, TRUSTED/FILTERED flags,
  display association and public IDs are not hardware trust or chord authority.

The separate reader audit is bound in MANIFEST.json; its thirty Rust/source
controls are specifications, not a real Android origin protocol. Native ingress,
final-target complete integration, pretarget PWM/chords, physical-device
incarnation, capacity/terminal cancellation collateral, JNI/VM and full
framework/native compilation/runtime remain OPEN. Public SDK is unchanged.

All prior snapshot14 defects, snapshot15 stale-focus/F1→F2 REDs and private
admission seals remain preserved. The separate latest admission seam/STOCK
repair is work2/sealed manifest
10b131eb2e27a5349ca29701a9bf0f6542646a3266e6ab2511d11f82d076e760;
this proposal does not modify or supersede its independent acceptance scope.
