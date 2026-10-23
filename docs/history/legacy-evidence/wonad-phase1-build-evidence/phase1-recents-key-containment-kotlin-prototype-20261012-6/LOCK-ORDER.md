# Bounded concurrency review: post-target slice

Status: external host/source review only. This is not a platform lock proof,
build result, or runtime qualification.

## Pure helper boundary

`WonadPolicyKeyContainment` owns only bounded in-memory identity and pair state.
Its synchronized methods do not receive or invoke callbacks and have no
Android `Context`, WMS, Settings, Binder, Handler, KGC, PWM, Toast, task-close,
or native bridge reference.

The target-aware route uses three phases:

1. `prepareObservation` captures the exact physical identity, relevant exact
   claim object identities, and `lifecycleEpoch` under the helper monitor.
2. The monitor is released. `WonadPolicyKeyAdapter` performs fallible current
   claim, WMS/state and Settings-backed eligibility observations.
3. `beforeStock` re-enters the pure helper with immutable observations. Any
   intervening lifecycle epoch change makes the observation RETIRED/fail-black.

The pre-safety Meta/Caps bookkeeping decision is narrower: it reads only the
lock-free `shortcutClaimStates`/input-containment publications, then enters the
pure helper. It does not perform Settings, provider, WMI or other fallible
framework reads before `interceptMultiKeyCombination`.

## Lifecycle direction

WMS claim lifecycle code may run under the WMS global lock and call the pure
helper to publish BLOCKED/RETIRED. This direction is intentional:

```text
WMS global lock -> pure containment helper
```

There is no reverse helper-to-WMS/KGC/PWM/Binder callback. In particular, the
candidate contains no monitored callback that calls `handleKeyGesture`, Toast,
Settings, WMI, task removal, a Handler, or the native bridge.

Retirement ordering is:

```text
helper RETIRED -> unpublish exact ShortcutClaim -> bridge owner cleanup
```

Replacement follows the same ordering before publishing the new exact claim.
Containment publication marks a live exact claim BLOCKED before exposing a new
blank/protected barrier and marks it healthy only after removal of that
barrier. Same-numeric-display replacement is distinguished by object identity
and immutable generation/incarnation/owner fields.

## Unhandled/fallback authority

The adapter's independent `deliveryLock` protects only WeakHashMap/LinkedHashMap
state keyed by the exact focused input token and at most sixteen claimed
display authorities. It performs no framework or helper call while held.
Claim/framework observations and helper commits happen outside it. A window
token reused across distinct exact claim incarnations becomes ambiguous and
can suppress stock UI but cannot authorize application fallback delivery.

This authority is deliberately not a per-event delivery ledger: successful
handled traffic has no completion callback, so retaining every delivered event
would inevitably saturate under normal typing. The bounded focus/display marker
only suppresses stock unhandled UI; it grants no Wonad command.

Fallback inheritance is two-phase. `dispatchUnhandledKey` first performs the
real KeyCharacterMap lookup. Only when it returns a fallback does the adapter
push an exact thread-local `{focus token, display, fallback physical event,
claim lineage}` scope. Queue bypass and target-aware fallback routing require
that exact scope. `finally` pops it after the synchronous `interceptFallback`
call, including exceptions. Nested scopes link only through the active Java
call stack; handled events and null KeyCharacterMap results retain no fallback
entry and cannot exhaust a historical map.

## Pair and census serialization

Every helper mutation increments `mutationEpoch`. A native all-device/all-key
census captures the epoch before its reads and may clear exceptional saturation
only if the epoch is unchanged at commit. Device removal deletes only records
for that exact device. Saturation is device-scoped, so another phone keyboard
does not inherit a claimed keyboard's exhaustion.

No queued stock action/ticket remains. There is therefore no Handler backlog,
post-rejection terminal obligation, asynchronous stale START, PWM endpoint
replacement, long-Escape timer, or delayed task-close cleanup in this slice.

## Explicitly outside this proof

This lock review begins only after target resolution. For hardware keys,
InputDispatcher resolves the intended display under its native lock and calls
queue policy after releasing that lock; injected keys retain their supplied
display. Neither path alone supplies the immutable device-incarnation,
initial-DOWN, target-focus and exact-claim lineage required to suppress
pre-target PWM effects. A future mechanism must not guess top focus, relabel a
KeyEvent, or introduce InputReader/WMS calls under the pure helper monitor.

Multi-key hardware safety and SecurePaste remain before the total-control seam.
The source-bound multi-key implementation can combine device-agnostic keys and
can target the default display; this is an explicit open obligation, not a
property proven safe here.
