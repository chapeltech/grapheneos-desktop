# Phase 1 blocked-input language and owner-state review

Status: read-only design review and implementation plan. It does not modify the
Wonad repository, source7/custom7, SDK, image, APK, build, or guest. The prior
external Java V3 remains byte-preserved at
`phase1-recents-key-containment-prototype-20261012-1` (KGC `da1dc7d1…`, PWM
`b7f96f38…`, patch `d4567671…`, tests `d616aedd…`, receipt `a4604dcf…`).

## Source facts

- Current `WonadInputBridge.kt` SHA-256 is
  `b512112fe58157e8e1a18baa3dbf0c0c338f073ea4d901c63d9949aaa11e60ff`.
  It already owns exact claim/lease state and fail-black decisions in Kotlin.
- `android/os-integration/Android.bp` SHA-256 is
  `9c31b895c21d1415e70d1f75092cb7ac4e0a3be91deb8e2d27d1e4fe76c4bc4f`.
  Its `wonad-input-kotlin` filegroup includes
  `input-integration/src/**/*.kt`; services/core already compiles that group.
  A new private Kotlin helper therefore needs no new module or public ABI.
- The authenticated staged KGC/PWM inputs remain `3acaa08d…`/`25be0cd9…`.
  KGC's three after-capture states are only process-global booleans:
  `mPendingMetaAction`, `mPendingCapsLockToggle`, and
  `mPendingHideRecentSwitcher` (fields 231–233; mutations 599–604 and
  994–1075). They contain no device, key, downTime, origin display, or focus
  identity.
- External V3 adds 359/removes 28 KGC Java lines and adds 41/removes 9 PWM Java
  lines. Most of that is new pure pair/ownership machinery, not unavoidable
  AOSP hook wiring. Retaining it all in Java conflicts with the project order
  Rust > Kotlin > Java.

## Correct language split

Use Kotlin, not Rust, for new ownership state. Rust is ideal for the fixed
desktop command policy, but this state must remain available when JNI/native
input is failed and must carry Android `KeyEvent`, `IBinder`, handler-message,
and stock gesture identities. Moving it through JNI would add a failure mode
and wire surface on the fail-black path. Kotlin is already compiled into
system_server and can expose narrow `@JvmStatic`/ordinary JVM methods to AOSP
Java without IPC or SDK changes.

Proposed new private source:

`android/input-integration/src/org/wonad/server/input/WonadPolicyKeyContainment.kt`

It should own:

- exact physical identity `{deviceId,keyCode,downTime}` plus an immutable origin
  value captured on the initial event;
- when available, the *exact object-identity* `WonadUiBridge.ShortcutClaim`
  published for that event's display.  Its immutable
  `{display,user,generation,incarnation,ownerBinder}` fields bind the physical
  pair to the original WMS claim and physical-attachment incarnation; a
  numeric display id alone is not lineage;
- an origin without an exact claim only for same-event/same-current-display
  bookkeeping.  Such an origin may never authorize a migrated continuation or
  survive numeric display-id reuse;
- Recents `STOCK`/`DRAINING` pairs and missing-device retirement decisions;
- exact delayed-Escape message/focus ownership;
- active Meta/Alt physical pairs and the exact owners described below;
- a tiny recent-app preload owner value used by PWM, if keeping two new Java
  scalar fields is not demonstrably smaller after compilation/tests.

Keep Java only where private AOSP state makes it necessary:

- place the generic guard after safety/SecurePaste/fixed Wonad priority;
- invoke private `handleKeyGesture`, `Handler`, and stock stage APIs from the
  returned Kotlin decision;
- change private `InterceptKeyStage` storage to downTime-aware exact pairs (or
  delegate storage through a small Kotlin field if that produces fewer hooks);
- wire PWM's existing preload/show/hide calls.

Target, not a pre-approved line budget: reduce new KGC Java from +359 to roughly
80–130 glue/bookkeeping lines, with pure state and hostile controls in Kotlin.
Do not contort stock code merely to hit a number; independent review should
compare the actual final diff.

## Concrete V3 continuation-display defect

V3 asks `consumeClaimedInput` only about the current event display. Sequence:

1. healthy claimed display 3 receives APP_SWITCH DOWN and starts stock preload;
2. its lease/claim becomes blocked;
3. focus moves and the same physical UP (`device,key,downTime`) is stamped with
   display 0;
4. `consumeClaimedInput` correctly refuses to infer phone 0 as claimed;
5. V3 sees a tracked STOCK pair but `blocked=false` and lets stock toggle.

The prior migration test covered a pair that was *already DRAINING*, not this
healthy-to-blocked migration. This is a real RED case, not a claim about Pair6
(whose DOWN itself was display 0).

Add a private Kotlin bridge operation whose authority is the helper's exact
previously observed pair record, for example:

`consumeClaimedPairInput(context, wm, event, flags, exactOrigin)`.

`exactOrigin` is not an integer supplied by KGC.  It is created inside the
bridge on the pair's initial event and, when a claim exists, retains the exact
`ShortcutClaim` object.  The bridge must require all of:

- the same physical `{deviceId,keyCode,downTime}`;
- the retained claim's immutable original display/user/generation/incarnation
  and owner Binder;
- either that exact claim still being current, or proof that the exact retained
  claim has been retired/replaced.  Retirement makes the *old pair* fail-black;
  it never grants authority over the replacement claim on the reused display;
- command-disabled drainage using the original event unchanged.  In
  particular, it must not clone or relabel `KeyEvent.displayId` to make Rust or
  Java believe that the event arrived on the old external display.

The lookup must not use top focus, accept an arbitrary external ID as
authority, create a command, or grant a lease.  A fresh phone DOWN with a new
downTime first retires and, if required, terminally unwinds the old owner, then
is evaluated as a new phone event; it must not inherit old-display containment.
A stale old UP is consumed without mutating the replacement.  If the initial
event had no exact claim token, a later migrated/reused-display event cannot be
authorized from the saved numeric id; only the ordinary current-event
containment check is available.

The present source already supplies the identity primitive: `ShortcutClaim`
is stable across heartbeat renewals, carries
`{display,user,generation,incarnation,owner}`, and
`shortcutClaimCurrent(expected)` compares exact object identity.  Its
`incarnation` was allocated from the exact `DisplayContent` attachment.  The
new helper should retain this opaque token, not copy only its scalar display
field.  Claim retirement/replacement is published before old-owner cleanup, so
the continuation test can fail closed without consulting a new claim.

## Exact after-capture ownership plan

The three global booleans cannot safely be cleared on any blocked event: that
could cancel a newer phone keyboard's state. Add one Kotlin observation per
physical event after multi-key safety handling and before stock state changes.
The observation records/retires active modifier pairs and carries the exact
closing or replaced token for this event.

- Meta action owner: the exact Meta physical pair and exact origin claim token
  which set `mPendingMetaAction`.
- Caps chord owner: the exact active Meta and Alt pair tokens snapshot when the
  chord becomes pending. Completion/cancellation must match one of those
  tokens; same device/key with a different downTime is a replacement.
- Alt-Tab owner: exact active Alt pair plus the TAB start pair, exact origin
  claim/attachment lineage, and the original stock focus/preload owner needed
  for one unwind COMPLETE.

When an event is a continuation of one of those owners, authority is checked
against the exact retained origin claim, not merely its origin display, as well
as the current event display.  A retired claim is a fail-black terminal state
for that old owner; a replacement claim with the same numeric display does not
inherit it. If the exact origin is now blocked or retired:

- Meta and Caps state is cleared without ALL_APPS/Caps-toggle action;
- an active Alt-Tab switcher emits exactly one canceled/terminal COMPLETE to
  hide only its exact old switcher/preload owner, then clears;
- the physical continuation is consumed through terminal even if its event is
  now stamped display 0.

A repeat-zero DOWN with a new downTime retires only the old exact owner, unwinds
its switcher if needed, and then lets the fresh phone/unclaimed pair follow stock
semantics. A late old UP remains consumed and cannot clear the replacement.
Different devices remain independent. Device-id reuse is distinguished by
downTime plus exact origin token; missing-device retirement is bounded and
owner-aware and may not globally clear an unrelated phone state.

PWM cancellation likewise needs the exact stock preload owner captured at the
original DOWN: `{deviceId,keyCode,downTime,originClaim/originDisplay}`.  The
cancel path must compare that owner before hiding/canceling.  It must not cancel
a newer phone, HOME, or replacement-display preload just because PWM's current
global preload flag is set.

This is the minimum defensible cancellation design. Merely setting all three
booleans false in the generic guard is rejected because it has no pair owner.

## Required tests before repository application

1. Pure Kotlin/JVM tests of the actual helper: blocked initial pairs, healthy to
   blocked, same-pair display migration to phone 0, exact-claim retirement,
   same numeric display with a new claim/incarnation/owner, lost UP, new
   downTime, stale old UP after replacement, device-ID reuse, multiple devices,
   missing-device pruning, and bounded state.  A hostile caller supplying only
   an old numeric display id must not gain continuation authority.
2. Actual Java-method extraction test composing the helper decision with stock
   KGC order. Blocked configured shortcut, ALL_APPS, SCREENSHOT, FULLSCREEN,
   LOCK, brightness/backlight, DND, and focused Escape must not reach stock.
3. Meta/Caps/Alt-Tab hostile sequences: external DOWN then blocked display-0 UP;
   claim retirement/replacement before UP; lost UP then fresh phone DOWN/UP;
   stale external UP after phone replacement; other-device phone state
   unaffected; exact one old-owner switcher unwind.
4. Exact PWM owner tests: old external cancellation cannot cancel/toggle a newer
   phone or HOME preload; keyguard cancellation and healthy completion remain.
5. Existing dispatch-order fixture updates only where the contract changes:
   blocked ordinary/action keys become `multi,contained`; safety, SecurePaste,
   and fixed Wonad priority remain unchanged.
6. Full platform compile and the real fresh runtime campaign remain mandatory;
   isolated JVM controls are not guest qualification.

## Still earlier than Java

Inputflinger updates lock-key meta/LED state before KGC policy. Kotlin can consume
the dispatch event and suppress Java/system UI action, but cannot rewind that
native state. If “consume external input” is interpreted to forbid even that
device meta-state change, a separate reviewed input-reader/dispatcher design is
required. This plan makes no such unproved claim.
