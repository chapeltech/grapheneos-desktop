# Phase 1 published app-input handle runtime investigation, revision 2

Date: 2026-10-11

Status: corrected design only. This note supersedes the scheduling and release
classification in revision 1, whose retained bytes have SHA-256
`9489af2c2b1c4948c972af03105687b9c6a2099a6c784bf4edbda3462a43f8ac`.
Revision 1 remains intact as
`phase1-published-input-handle-runtime-test-design-20261011-1.md`; it is not an
approved gate or release requirement.

No production source, test source, matrix definition, stage, build, Docker
container, emulator or guest was changed or started for this revision. In
particular, this design does **not** add a mandatory matrix gate or increase the
required matrix count.

## Correction to revision 1

Withholding only SystemUI's eventual
`setWonadNativeUiLease(display, user, generation, 0, null)` call cannot
deterministically preserve an old admitted app input handle after the real
lease deadline.

There are two independent framework paths which revision 1 did not account
for:

1. In `WonadUiBridge.kt`, the claim owns a `wm.mH` watchdog which executes under
   the WM global lock (`345-366`). It is scheduled immediately on setup
   (`380`) and, while the claim exists, reschedules itself every 250 ms
   (`357-359`, `427-432`). `reconcile` independently calls
   `InputNative.uiMode` with the current elapsed-realtime clock (`452-460`).
   Once that native authority is no longer live it calls
   `containAndRelease`, which first publishes the volatile blank containment
   barrier (`775-810`) and then hides/parks ordinary tasks and schedules the
   real transaction (`813-839`). None of this depends on Shell's serial
   executor reaching the SystemUI retirement Binder call.
2. On any later InputMonitor population, `WonadNativeBridge.configureInput`
   rechecks the current native lease (`1449-1464`). An ordinary app window goes
   through `clipNativeAppInput`; if `nativeLease` is already null, it adds the
   narrowly owned `DROP_INPUT` immediately (`1489-1494`). Thus a newly
   populated handle can become safe even if an older dispatcher snapshot was
   admitted earlier.

The reviewed source identities for those observations are:

- `android/input-integration/src/com/android/server/wm/WonadUiBridge.kt` —
  `8d227e84eef912d1016698e018ca37642cff8ec0150a380eb25dbf7e8dc21da4`;
- `android/input-integration/src/com/android/server/wm/WonadNativeBridge.kt` —
  `3fd2bd1317217220a5efbb4118f7fc762f7dd32d784b712c5ff1020e2221248c`;
- the inspected current custom-7 `InputMonitor.java` (byte-identical to the
  earlier reviewed ancestry) —
  `bdb799f17556ffad88f3165f9993b08768999db94e13efb12cb919d39b2d7734`.

Consequently, a test which delays the SystemUI 0/null call and then fails to
find an old admitted handle has not missed a required branch and has not found
a product defect. The independent WMS watchdog or a later handle population
may already have contained input. That result is **transition-state coverage
unavailable**, not failure and not proof of the precise old-handle transition.

The literal security contract remains unchanged: authority ends at the exact
lease deadline. This correction does not invent an immediate-deadline grace
period, nor does it silently add a new pointer-dispatch linearization rule.
`android/desktop-sdk/API-v3.md`
lines 168-175 specify the fixed client timeout and revocation effects; they do
not specify an `eventTime`/dispatch linearization rule and therefore do not, by
themselves, settle whether pointer admission must be instantaneous at that
clock value. They also do not grant up to one watchdog poll of continued input
authority. The 250 ms value above is an implementation poll cadence, not an
allowed grace period.

## What can be tested without a new scheduler seam

A bounded, non-qualifying investigation can send a burst of fresh pointer
events across the genuine deadline while preserving all production behavior.
It can search for a counterexample and add sampled stress evidence, but it
cannot force or prove that it sampled every possible interval between native
authority expiry and InputDispatcher's new published state.

A future investigation should:

1. Start from a fresh exact image and authenticate the same ordinary client,
   display incarnation/generation, target task/activity/window and fixture
   process throughout.
2. Observe at least one successful live renewal and retain the exact final WMS
   expiry value. Pause only the exact ordinary Wonad process, as the existing
   frozen-client gate does; do not synthesize lease revocation or delay WMS.
3. Use a guest-side, bounded-rate injector to enqueue uniquely identifiable
   mouse events before and after that deadline. Retain guest CLOCK_BOOTTIME
   bounds for each enqueue/dispatch attempt, its exact display and coordinates,
   and the unchanged event objects/return status. A host ADB command-start time
   is not an input-dispatch timestamp.
4. Extend a test-only fixture journal, in a separately reviewed future packet,
   to retain each received event's unique marker, `MotionEvent.eventTime` and a
   handler-entry elapsed-realtime timestamp in addition to counters. The
   existing aggregate pointer/mouse counters cannot identify which burst event
   arrived.
5. Collect raw InputDispatcher window inventories frequently enough to
   identify observed old-handle and contained-handle samples, including exact
   window/token/application-token identity and `DROP_INPUT`, visibility,
   touchability and Wonad consumer state. Treat dumpsys observations as
   bracketing samples, not an atomic publication timestamp.
6. Retain healthy-before and recovered-after delivery controls, a deterministic
   post-containment no-delivery control, raw counters/journal/dumps, system
   process identities and exact cleanup. Do not modify the established
   `frozen_client` command grammar; this investigation is separate.

The burst must not hold the WMS global lock, postpone the WMS watchdog, weaken
production containment, or use a production fault API. No result may be
relabelled as if it came from an event that was injected at a different time.

## Clock and ordering limits

The native deadline is expressed in Android elapsed realtime; `/proc/uptime`
is a guest CLOCK_BOOTTIME observation suitable for coarse independent
bracketing. Those clocks do not by themselves identify when InputDispatcher
accepted or targeted an event.

`MotionEvent.eventTime` is supplied on the event and is not proof of dispatcher
publication or application-handler execution. Conversely, a fixture callback
timestamp can be delayed by the app main thread and cannot prove that dispatch
began after the deadline. ADB process invocation timestamps are still weaker.
Raw dispatcher dumps are non-atomic samples and may bracket, but cannot
linearize, a transaction or an individual dispatch.

The pinned InputDispatcher has no Wonad lease deadline of its own: injected
motion crosses JNI and targeting consults the currently published
`WindowInfo`/`DROP_INPUT` state. The existing expiry-aware
`WonadInputBridge.claimedInputBlocked` seam is for key events, not pointer
dispatch. Even two byte-identical dispatcher dumps around a tap do not prove
that the same `WindowInfo` was continuously installed during the tap; an
unobserved replace-and-restore remains possible without an event/transaction
timeline.

Therefore a confirmed post-deadline counterexample requires authenticated
evidence that the **fresh event was enqueued/dispatched after the exact final
deadline**, reached the same original fixture/window, and was not merely an
event routed before expiry whose callback ran later. If available platform
tracing cannot establish that order, the result remains suggestive rather than
a confirmed deadline-delivery counterexample. Whether a confirmed
counterexample violates the release contract remains the separate normative
decision described below.

## Result classification

The independent auditor for any future investigation must use these classes:

- **confirmed deadline-delivery counterexample**: a uniquely identified fresh event is proven to
  have been enqueued/dispatched after the exact final deadline and is delivered
  to the unchanged original app/window before any new lease. This disproves an
  immediate-at-deadline pointer-admission property. It is not automatically a
  failure of the currently documented API-v3 revocation contract, whose
  dispatch linearization boundary is unspecified; making it release-failing
  first requires an explicit reviewed policy adopting that stronger property.
- **sampled no-delivery evidence**: authenticated post-deadline burst events
  are not delivered, with live-before and recovered-after controls. This is
  useful stress evidence for the sampled schedule, but it is not deterministic
  proof that no shorter old-handle interval exists.
- **sampled old-handle no-delivery evidence**: raw bracketing observations show
  the old admitted handle on both sides of one authenticated post-deadline
  event and the event is not delivered. This is stronger sampled evidence, but
  without a dispatcher event/transaction timeline it still cannot prove the
  handle was unchanged throughout the tap.
- **transition-state coverage unavailable**: no post-deadline sample observes
  the old admitted handle because the WMS watchdog or a later InputMonitor
  population has already installed containment. This is compatible with
  correct independent containment and is neither a product failure nor proof
  of the old-handle assertion.
- **invalid/inconclusive evidence**: clock order, final deadline, event identity,
  target identity, dispatcher state, healthy controls, cleanup or exact-image
  ancestry cannot be authenticated.

A post-containment denied tap can remain a deterministic assertion once raw
state proves the replacement `DROP_INPUT`/system consumer is published. The
healthy and recovered taps remain deterministic positive controls. Only the
deadline-transition sample is opportunistic under the presently reviewed
interfaces.

## Negative controls for a future evidence parser

Host tests should reject bundles in which a delivered event is reassigned to a
later injection, an event's marker or clock bounds change, the final successful
deadline changes, target/window/process identity changes, a new lease appears,
the sibling receives input, or healthy/recovered controls and cleanup are
missing. They should also prove that:

- an old-handle sample which is entirely before the deadline cannot count as
  post-deadline coverage;
- a callback after the deadline for an event enqueued before the deadline is
  not classified as a counterexample; and
- absence of an old-handle sample is reported as coverage unavailable rather
  than silently converted to pass or failure.

## Decision before Phase 1 integration

Do not implement or mandate revision 1's withheld-retirement gate. First
establish, from pinned platform tracing or another separately reviewed
test-only mechanism, whether dispatch enqueue/target selection can be ordered
against the exact deadline without weakening production behavior or holding
the WM lock. Until that exists, the burst proposal is an exploratory
counterexample search only. It does not change the current release matrix,
matrix count, existing frozen-client acceptance, or any production contract.
