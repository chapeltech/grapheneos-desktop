# Snapshot 15 independent stale-authority review

Status: **expected RED against an external-only host projection**. This is not
an Android build, runtime result, release result, or approval to apply the
candidate.

## Reviewed immutable inputs

The target was the read-only directory
`phase1-recents-key-containment-kotlin-prototype-20261012-snapshot-15-review`.
The relevant observed hashes were:

- `WonadPolicyKeyContainment.kt`:
  `bc92cb29f9a574c205ccab6ce0b516191db68682b9eafc1064cc15a8f429c09e`
- `WonadPolicyKeyAdapter.kt`:
  `b3cc521d08b38e6564bf9b1d1e27941edc7ec5bb25d8652b555e95bd8e004fdf`
- `apply_candidate.py`:
  `f7b2e31d2db9103a88fb1f1ed08e762693eb044728a5d24af607ef8c8d8efbfb`
- `test_candidate.py`:
  `046bac0f7fd0056f540fa14ef49ac0c3c8e84c0a4d1c35049ba14bf73d9d6365`

The literal candidate replay was also observed passing its stated partial
scope in 12.6227 seconds:

```text
POST_TARGET_TOTAL_CONTROL_PASS checks=91
OPEN: pre-target PWM policy lacks exact device/incarnation/initial-origin proof
```

That replay does not cover the schedule below.

## Confirmed defect

`WonadPolicyKeyAdapter` records a `DisplayAuthority` for a focused input token
and display after any claimed application delivery. The entry has no exact
event identity and is not removed by `onClaimRetiring`, claim unpublication,
`onClaimRetired`, or a later stock event. `bypassUnhandledStock` accepts every
future event on that token/display solely because this historical entry is
present. `beginFallback` grants the same historical authority after a later
KeyCharacterMap lookup.

The compiled schedule uses the candidate's actual helper, adapter, and stubs:

1. Publish claim A for display 3 and deliver a complete ordinary DOWN/UP pair
   to focused token F.
2. Invoke `onClaimRetiring(A)`, unpublish A exactly, and invoke
   `onClaimRetired(A)`.
3. Send a different physical event on the still-live F/display-3 route. The
   candidate itself returns `stock`, proving the new event was not admitted by
   the old claim.
4. Ask the actual unhandled and fallback adapter methods about that new event.

Both incorrect outcomes occur:

- `bypassUnhandledStock(F, newStockEvent)` is true, suppressing KGC/PWM for an
  event which was never delivered under the claim;
- `beginFallback(F, newStockEvent, derivedFallback)` returns a scope, granting
  the old marker to a newly derived stock fallback.

This is not merely delayed cleanup for the earlier event: it changes the
policy of a distinct stock event after exact claim retirement. The existing
phone control uses display 0 and therefore does not exercise reuse of the
same focused token and display.

A permanent focus/display marker cannot represent exact dispatch lineage.
The eventual design needs an event-bound admission/completion mechanism or an
equally exact lifecycle/window authority boundary. A timeout, count-only
eviction, or mutable-current-claim check would either reopen stale handling or
lose the legitimate in-flight unhandled event across retirement.

## Reproduction

Files created only in this evidence directory:

- `Snapshot15AdapterRedTest.kt`:
  `5157364deea912217d837930b0cbe995022e3ef359a3e3b65df76f63eb593d53`
- `run_expected_red.py`:
  `f3c42f260fc29806a62f38273588d6725a6fbd12fa7162e95e1ecc37d56762a5`

Command:

```sh
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-recents-key-containment-snapshot15-independent-review-20261012-1/run_expected_red.py
```

Observed result: exit 0 from the expected-RED harness in 6.571 seconds. The
compiled candidate process failed with both required tokens:

```text
retired-marker-suppresses-fresh-stock-unhandled
retired-marker-authorizes-fresh-stock-fallback
SNAPSHOT15_EXPECTED_RED_REPRODUCED cases=2
```

The Kotlin compiler/JVM heaps were capped at 256/128 MiB. No repository,
custom7 stage, SDK, APK, OS image, Docker container, VM, or guest was changed
or executed.
