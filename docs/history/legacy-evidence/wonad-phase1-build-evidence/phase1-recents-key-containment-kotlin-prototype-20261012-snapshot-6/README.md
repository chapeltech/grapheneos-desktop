# External blocked-input containment candidate

This is a source-pinned, external-only candidate for the Phase 1
`KeyGestureController`/`PhoneWindowManager` containment defect. It is not
applied to the Wonad repository, custom7/source7, any SDK, OS image, or runtime
artifact, and its host fixtures are not Android runtime qualification.

## Inputs

- staged custom7 `KeyGestureController.java`:
  `3acaa08d5a39200bbcd521f760339c4d531936656899c195b9b9fa9b28aa66c5`
- staged custom7 `InputManagerService.java`:
  `df0e4cc78508383cd60fd2cd534ba450a0df2071b211ee21115fa71f35470dc1`
- staged custom7 `PhoneWindowManager.java`:
  `25be0cd9384ef463af854067e4904701041ece23ef0e9b9f8cc348503e6e1898`
- current private `WonadInputBridge.kt`:
  `b512112fe58157e8e1a18baa3dbf0c0c338f073ea4d901c63d9949aaa11e60ff`
- current private `WonadUiBridge.kt`:
  `8d227e84eef912d1016698e018ca37642cff8ec0150a380eb25dbf7e8dc21da4`
- reviewed design:
  `ae870d2ed969f6fa8212b5d35f369fc8ba899191d5e74838b21cbcb61d4021f2`

`apply_candidate.py` refuses any different input bytes and writes only a new
caller-selected directory. It does not edit its inputs.

## Candidate split

`candidate/WonadPolicyKeyContainment.kt` owns all new pure pair and stock-owner
state. Physical identity is exactly `{deviceId,keyCode,downTime}`. External
lineage retains the actual `ShortcutClaim` and owner Binder by object identity,
plus its immutable display/user/generation/incarnation fields. A numeric
display ID is never authority.

Every claim-owned DOWN is retained, including an ordinary key that initially
passes. This preserves physical-pair parity if the claim is blocked, expires,
or is replaced before its UP. Passive pre-safety cleanup resolves a retained
pair before consulting the current display claim, so a stale old event cannot
clear a replacement claim's stock owner.

`candidate/WonadPolicyKeyAdapter.kt` is a private system_server adapter. It
retains the exact claim, classifies it through `shortcutClaimCurrent`, and
drains only the original `KeyEvent`; it never clones or relabels the event.
UiBridge synchronously marks that exact identity BLOCKED before publishing a
new display barrier and RETIRED before unpublishing it. Delayed Escape
completion and claim retirement linearize on the same pure-state monitor;
retirement returns the exact Meta/Caps/Alt-Tab/PWM/Escape cleanup for dispatch
on KGC's handler. KGC's three legacy boolean mirrors are paired with atomic
exact-owner references; a posted old cleanup uses compare-and-clear and cannot
clobber a replacement owner installed before the runnable. Opening a barrier
affects only future physical pairs.

Owner installation is also a single monitored transaction: it revalidates the
active non-draining physical pair and live exact claim, applies exact displaced
owner cleanup, publishes the Java mirror, and sends the synchronous stock START
before lifecycle retirement can pass it. If retirement wins first, no mirror or
stock action is published and the event remains consumed. Unclaimed phone
owners have priority over claimed external owners; a phone start can displace
an external owner with exact cleanup, while an external claim cannot steal
pending phone Meta/Caps/Alt-Tab/APP_SWITCH state. Separate external claims
likewise cannot borrow one another's singleton stock state.

Generated Java is limited to places that own private stock state/actions:

- the generic pre-stock guard after multi-key safety, SecurePaste policy, and
  the fixed Wonad alphabet;
- exact Escape `Handler` message installation/removal;
- exact Meta/Caps/Alt-Tab booleans and gesture completion;
- a downTime-aware `InterceptKeyStage` ledger and trusted device-removal hook;
- exact PWM APP_SWITCH preload ownership and cancel/complete dispatch.

The PWM handoff stack is thread-local because the pinned InputManager local
handler invokes PWM synchronously; an unrelated system_server thread cannot
borrow an in-flight owner. Exceptional bounded-state saturation is released
only by an injected `NativeInputManagerService` census of every key code over
all devices plus the current device-ID inventory. Unknown/down/virtual or an
unavailable native dependency stays fail-closed. An all-released observation
retires remaining present-device lost-UP records with their exact owner
cleanup before releasing saturation. The one production
`InputManagerService` constructor call supplies that private dependency; the
existing test constructor remains fail-closed with `null`.

A monotonically checked mutation epoch brackets the native scan, so a
key/lifecycle mutation concurrent with the census rejects the stale reset.

The generated bridges add private Kotlin lifecycle/drain seams only. There is no public
SDK, Binder, AIDL, or wire change.

## Host replay

Run:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-recents-key-containment-kotlin-prototype-20261012-snapshot-6/test_candidate.py
```

Each compiler/VM invocation has a 256 MiB Kotlin or 128 MiB Java heap cap; this
is not a claim that total process RSS is below those heap limits. It generates
from the authenticated inputs in a temporary
directory, checks source ordering/identity invariants, and compiles/runs:

- 36 pure Kotlin ownership/state cases;
- 10 extracted KGC/PWM ordering cases;
- 5 stateful Meta/Caps/Alt-Tab/Escape/device-owner cases;
- 5 asynchronous publication/old-cleanup/replacement-owner cases;
- 4 exact stock-stage ledger cases;
- 11 adapter identity/lifecycle/drain assertions.

That is 71 host checks. Snapshot 1 remains preserved separately with the four
independently reproduced defects which this generation fixes: ordinary-pair
loss, replacement-owner passive cleanup, cross-thread PWM owner leakage, and
unreachable saturation recovery. Snapshot 3 is also preserved with independent
reproductions of eventless delayed-Escape retirement and a census/key-event
interleaving; this generation adds exact lifecycle notification, transactional
completion, and the census mutation epoch for those schedules. Snapshots 4 and
5 retain independently compiled replacement-cleanup, cleanup-before-publication,
post-retirement-install, and phone-Meta-clobber counterexamples. Snapshot 6
closes those schedules with transactional installation and explicit phone
priority; the literal command above replays snapshot 6's own immutable bytes.

## Limits

- The fixtures prove JVM/source composition, not Android runtime behavior.
- A full platform compile and a fresh real runtime campaign remain required.
- Inputflinger lock-key/meta/LED state is updated before KGC and is not rewound
  by this candidate.
- Resource saturation deliberately fails closed until a trusted complete
  key/device census; normal phone/unclaimed paths are covered outside that
  exceptional exhaustion state.
