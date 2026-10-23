# External blocked-input containment successor

This is an external-only, source-pinned Phase 1 candidate. It is not applied
to the Wonad repository, custom7/source7, an SDK, OS image, or runtime. Its
compiled host fixtures are not Android runtime qualification.

The generator authenticates these production inputs before writing a new
caller-selected output directory:

- `KeyGestureController.java` `3acaa08d5a39200bbcd521f760339c4d531936656899c195b9b9fa9b28aa66c5`
- `InputManagerService.java` `df0e4cc78508383cd60fd2cd534ba450a0df2071b211ee21115fa71f35470dc1`
- `PhoneWindowManager.java` `25be0cd9384ef463af854067e4904701041ece23ef0e9b9f8cc348503e6e1898`
- `WindowManagerInternal.java` `f940e0a8cb19b0e5902c23642043b8d24679fe914fe3d7f28db633c9d47da582`
- `WindowManagerService.java` `c2eb228520a585d86aa4097230f5c88700d32c08cbc8f2cf4da93b3787d6342c`
- `WonadInputBridge.kt` `b512112fe58157e8e1a18baa3dbf0c0c338f073ea4d901c63d9949aaa11e60ff`
- `WonadUiBridge.kt` `8d227e84eef912d1016698e018ca37642cff8ec0150a380eb25dbf7e8dc21da4`

`apply_candidate.py` also authenticates every support source used by the
bounded lock/order analysis. Those pins are evidence boundaries, not a claim
that the entire platform has been dynamically lock-checked.

## Candidate behavior

`WonadPolicyKeyContainment.kt` owns all new pure state. A physical key pair is
exactly `{deviceId,keyCode,downTime}`. A claimed origin retains the actual
`ShortcutClaim` and owner objects by identity plus immutable display, user,
generation, and incarnation values. No event display is rewritten.

Every claimed-origin DOWN is retained, including ordinary app input. If that
claim later blocks, expires, dies, or is replaced, the original UP is drained
against its retained lineage. Phone and unrelated displays remain stock.
Claim lifecycle publication synchronously changes pure state before the UI
barrier/claim changes, so eventless retirement cannot leave delayed owners
authoritative.

Stateful Meta, Caps, Alt-Tab, APP_SWITCH, and Escape owners are installed under
one pure-state monitor. Install callbacks may only update identity-bound local
mirrors. They do not invoke stock KGC, PWM, Shell, Toast, WMS, Handler, or
other external effects. A failing callback rolls back the exact new owner and
restores displaced local mirrors while preserving the original exception.

Claimed external APP_SWITCH, Alt-Tab, and Escape use a separately bounded
claimed-action-ticket ledger (`maximumActions=64`). A claimed ticket remains
counted until its exact completion/cancel obligation is handled, even after
physical UP. A frozen KGC Handler therefore cannot accumulate unbounded WMS
lifecycle-cleanup work while pair storage appears empty. Action-budget
exhaustion rejects only new claimed stateful actions. Phone/unclaimed stateful
gestures are not charged to this budget because their stock START and
completion run synchronously after the helper monitor is released; a full
claimed ledger therefore cannot consume or suppress phone typing/Home/Recents.

The input thread commits START against current exact lineage under a private
KGC action lock, releases the helper monitor, and invokes stock KGC/PWM
synchronously. Retirement before commit drops the action. If admission wins
first, later retirement converts completion to exact cancellation. Phone and
claimed Wonad actions share this lock, so a phone replacement cannot overtake
a claimed action between commit and delivery acknowledgement.

PWM has a distinct Recents-endpoint monitor covering preload/cancel/toggle and
show/hide state plus the reviewed one-way StatusBar delivery. Claimed START
publishes an identity reservation before entering PWM. Direct stock HOME,
show, hide, toggle, or preload invalidates a pending reservation inside that
endpoint domain; stale claimed START then reports “not applied” and KGC rolls
back without recording STARTED. If claimed START enters the endpoint domain
first, state and one-way delivery finish before a direct mutation can proceed.
The PWM endpoint monitor never calls KGC, the KGC action lock, or the helper's
lifecycle monitor. APP_SWITCH preload and Alt-Tab visibility remain separately
identity-bound, so later cleanup A cannot cancel/hide replacement B or a phone
switcher. Phone/unclaimed gestures remain synchronous stock operations.

Only WMS lifecycle cleanup is posted to the KGC Handler. If the Handler rejects
that post, the Java hook throws without taking the pure terminal ticket or
running stock work inline under WMS/global lifecycle locks. The surrounding
WMS cleanup framework may aggregate/log that failure and remain unavailable;
the bounded guarantee here is fail-black retention of the exact cancellation
obligation, not transaction rollback or process termination. It never reports
the owner finished while leaving its delivered PWM endpoint or Escape timer
active.

Legacy KGC Boolean mirrors are paired with atomic exact owners. Replacement
cleanup uses compare-and-clear and cannot clobber a new owner. Cleanup is
best-effort across independent owners: one failure cannot skip later exact
cleanup, and later failures are suppressed on the first.

Pair-table saturation is separate. Only a complete native all-device/all-key
census can release it. The census captures the mutation epoch before reading
devices/keys; concurrent event/lifecycle/action mutation makes it stale and
leaves saturation and owners unchanged.

## Claimed external Escape

Shell QUIT ignores the original focused token/display and selects the current
global task. This candidate sends no stock Shell QUIT START, COMPLETE, or
CANCEL for claimed external Escape. Phone/unclaimed Escape keeps stock order.

Before publishing a claimed Escape owner, a private WMI/WMS seam captures the
original input-channel token under WMS global and resolves exact
`WindowState`, `ActivityRecord`, `Task`, UID, display, and `ShortcutClaim`
objects. Embedded/ambiguous targets are rejected. On timeout, after helper
release, WMS re-resolves the token and requires the same identities, healthy
eligibility, that display's current focus, and top-focused display. Only then
is that exact Task removed under the same WMS lock. Phone/other-monitor focus,
same-slot or token/window/activity/task/claim replacement, and retirement are
no-ops. Numeric task/display IDs and public async Wonad commands are never
authority.

The informational Toast is also outside the helper monitor. A one-shot permit
is committed first; Toast runs after the synchronized call returns. A permit
winning before later retirement is already-admitted ordinary notification
work. Delayed close still has the stricter WMS revalidation above.

## Lock boundary

Snapshots 8-10 remain historical failed reviews. Snapshot 8 yielded
`WMS global -> helper -> NMS toast queue -> WMS global`. Snapshot 10 still
called stock KGC under helper; a concurrent custom gesture yielded
`WMS global -> helper -> KGC records/local handler map -> PWM/ATMS -> WMS
global`.

This successor removes both edges. Under helper, Java performs only local
atomic/mirror changes; it does not post or invoke stock callbacks. Stock
KGC/PWM, Toast, and private WMS close execute after helper release. WMS
lifecycle publishes only a bounded Handler post after helper release.
Wonad input effects take `KGC action lock -> KGC/local-handler records -> PWM
endpoint monitor`; direct stock Recents mutations take only the PWM endpoint
monitor. The endpoint monitor calls no helper/action-lock/KGC path and holds
through the one-way SystemUI send, so there is no reverse edge in the reviewed
chain.
The origin resolver itself performs bounded synchronous framework reads
(Settings/provider, user, keyguard, lock-task, display) while helper is held;
it is not described as pure, nonblocking, or Binder-free. Exact-source review
found no synchronous resolver path back to WMS global, but that is a bounded
analysis, not a whole-platform proof. See `LOCK-ORDER.md`.

## Immutable host replay

After this directory is frozen as snapshot 12:

```sh
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-recents-key-containment-kotlin-prototype-20261012-snapshot-12/test_candidate.py
```

The runner regenerates from authenticated inputs using pinned custom7
Kotlin/JDK with 256 MiB/128 MiB heap caps. It executes 109 bounded checks: 36
pure state, 9 action/budget/PWM, 5 endpoint-reservation, 7 exact-target model,
10 KGC/PWM composition, 5 stateful owner, 5 async replacement, 6 callback
failure, 3 cleanup aggregation, 7 deferred Escape, 1 action serialization, 4
stage-ledger, and 11 adapter cases. Source guards additionally bind generated
ordering, all five PWM endpoint mutations, and private WMI/WMS checks.

## Limits

- No platform compile or real Android execution has occurred.
- The exact-target test is a host model plus source guard, not compiled WMS.
- Fresh platform build and ordinary capture-keyboard runtime fixtures remain.
- Inputflinger lock/meta/LED state preceding KGC is not rewound.
- No public SDK, AIDL, Binder wire, or product APK changes are proposed; WMI
  additions are private in-process system_server seams.
