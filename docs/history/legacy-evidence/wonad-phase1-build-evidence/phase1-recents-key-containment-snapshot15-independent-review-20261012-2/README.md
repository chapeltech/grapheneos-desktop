# Snapshot 15 independent exact-dispatch-lineage review

Status: **expected RED against an external-only host/source projection**. This
successor record preserves and extends the immutable `-1` review; it does not
rewrite it. It is not an Android build, runtime result, or permission to apply
the candidate.

## Bound inputs

Snapshot 15 remained read-only at
`phase1-recents-key-containment-kotlin-prototype-20261012-snapshot-15-review`:

- helper:
  `bc92cb29f9a574c205ccab6ce0b516191db68682b9eafc1064cc15a8f429c09e`
- adapter:
  `b3cc521d08b38e6564bf9b1d1e27941edc7ec5bb25d8652b555e95bd8e004fdf`
- generator:
  `f7b2e31d2db9103a88fb1f1ed08e762693eb044728a5d24af607ef8c8d8efbfb`
- replay:
  `046bac0f7fd0056f540fa14ef49ac0c3c8e84c0a4d1c35049ba14bf73d9d6365`

The actual custom7 native integration sources inspected were:

- `frameworks/native/services/inputflinger/dispatcher/InputDispatcher.cpp`:
  `4598e3a96e0196a5965be2a4232736ba7e14616c8435b201ab6d394e44b762c9`
- `frameworks/native/services/inputflinger/dispatcher/Entry.h`:
  `57aa994e65bfeebdceec811dd2bd380c6918508df93ce4799b3e682c433442b0`
- `frameworks/base/services/core/jni/com_android_server_input_InputManagerService.cpp`:
  `0a71ebf0fb6697a1f21a6abe0e14e53d4b961e40a4baace0b8dedb0d5b8c08c5`

The snapshot's literal partial replay was independently observed passing 91
checks in 12.6227 seconds and continued to print its explicit pre-target OPEN
line.

## Confirmed defects

### 1. Policy focus is not necessarily the final dispatch target

`InputDispatcher::dispatchKeyLocked` captures `focusedWindowToken` and posts
the Java policy call at lines 1996--2004. The policy command deliberately
releases `InputDispatcher::mLock` around Java at lines 6877--6892. After the
policy returns, the dispatcher calls `findFocusedWindowTargetLocked` again at
lines 2028--2046. A focus change while the lock is released therefore permits:

1. the adapter to return APPLICATION and retain authority under policy token
   F1;
2. native dispatch to target current token F2 on the same display;
3. F2 to return the event unhandled;
4. `afterKeyEventLockedInterruptable` to call policy with the actual
   connection token F2 at lines 6970--7070;
5. the adapter's F1-keyed lookup to miss, reopening stock KGC/PWM processing
   and losing fallback lineage for an event admitted as claimed input.

The compiled adapter control models exactly the two tokens:
`beforeStock(F1,event).application` is true, while both
`bypassUnhandledStock(F2,event)` and `beginFallback(F2,...)` fail.

### 2. Historical marker changes a later stock event

After a completed claimed pair on F1/display 3, the test performs exact
`onClaimRetiring`, claim unpublication, and `onClaimRetired`. A different
physical event on the still-live F1/display-3 route is proven by the candidate
itself to return STOCK. Nevertheless, the permanent historical
`DisplayAuthority` makes `bypassUnhandledStock` true and grants a fallback
scope to that new stock event. Claim lifecycle and stock routing never remove
the marker.

The existing phone control uses display 0, so it does not cover same-token,
same-display reuse. The replacement-claim test intentionally makes the marker
ambiguous/fail-black and likewise does not prove exact event lineage.

## Bounded repair boundary

The two defects point to the same missing boundary: authority must follow the
exact native event/dispatch entry, not a historical Java focus/display pair.
One source-compatible private direction is an additional
`KeyEntry::InterceptKeyResult` state returned only by the trusted Java policy,
stored on the actual `EventEntry`, and passed by
`afterKeyEventLockedInterruptable` into the private JNI/IMS unhandled and
fallback call. It would:

- follow the actual final connection even when policy F1 differs from target
  F2;
- survive exact claim retirement for the already-admitted event;
- disappear automatically when a handled `EventEntry` is released;
- never authorize a later stock event; and
- add no app-facing SDK, Binder, or wire surface.

This is a design boundary, not an implemented or compiled fix. A
clear-on-next-event or latest-event Java map is not established safe: the
native dispatcher can publish multiple entries into a connection wait queue
before their completion responses arrive.

## Reproduction

Files in this evidence directory:

- `Snapshot15AdapterRedTest.kt`:
  `c372caa479970737f102714448e92609a1ca237d950b019b53b2194bed78abd2`
- `run_expected_red.py`:
  `c3353632c10fcef72a8be32bca614d533123645c8440adf6fb7d777330b53b01`

Command:

```sh
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-recents-key-containment-snapshot15-independent-review-20261012-2/run_expected_red.py
```

Observed expected-RED harness result: exit 0 in 6.464 seconds, with all four
required compiled failure tokens:

```text
policy-focus-final-target-reopens-unhandled-stock
policy-focus-final-target-loses-fallback-lineage
retired-marker-suppresses-fresh-stock-unhandled
retired-marker-authorizes-fresh-stock-fallback
SNAPSHOT15_EXACT_LINEAGE_EXPECTED_RED_REPRODUCED cases=4
```

Compilation/JVM heaps were capped at 256/128 MiB. No repository, stage, SDK,
APK, OS image, container, VM, or guest was changed or executed.
