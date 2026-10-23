# Independent review of key-containment snapshot 1

This is a bounded host-side review of the immutable prototype snapshot at
`/u/elric/tree/wonad-phase1-build-evidence/phase1-recents-key-containment-kotlin-prototype-20261012-snapshot-1`.
It does not modify the snapshot, the repository, the staged OS source, or an
Android guest, and it is not Android runtime or release qualification.

The reviewed snapshot's aggregate file-ledger SHA-256 is
`008cf05a8816453e6db561d1308f18cedb328034450fa688d4d8d25c7ef87315`.
The compiled probe uses the exact frozen `WonadPolicyKeyContainment.kt`
(`87efbd72fe0fe21850a2dc0317578a05d08b24d614e4089580586bec60ad1628`).

## Confirmed findings

1. A healthy claimed-display ordinary DOWN is not retained. The first-DOWN
   insertion at helper lines 300-310 is conditional on `blocked ||
   tracked(role)`, and `ORDINARY` is not tracked. If its claim is then retired,
   the exact matching UP, stamped as display 0, has no retained origin and is
   passed. The compiled probe reproduces that pair-parity break.
2. `passiveBeforeSafety` (lines 232-255) reasons from only the current claim and
   display. A stale APP_SWITCH UP belonging to retired claim A can therefore
   clear claim B's healthy replacement Meta owner before `beforeStock` finds
   and contains A's retained physical pair. The compiled probe reproduces the
   owner-specific cleanup violation.
3. the PWM dispatch handoff is one companion-global `ArrayDeque` (lines
   492-516), not thread-local or explicitly carried to PWM. During thread A's
   dispatch, unrelated thread B observes A's exact Wonad owner. The compiled
   probe reproduces the cross-thread owner leak.
4. Saturation can be cleared only by `reconcileDevices(...,
   allKeysReleased=true)` (lines 451-467), but the generated KGC calls only
   `removeDevice`. After overflow and removal of every involved device, state
   is empty but saturation remains set, so later phone input is consumed
   indefinitely. The compiled probe and generated-source check reproduce this.

The narrow correction directions are: retain every first DOWN with a current
claimed origin (including ordinary keys); make passive cleanup consult the
exact retained physical pair/origin; use an explicit or thread-local PWM owner
handoff; and wire saturation recovery only to a trusted complete device/key
census. An arbitrary saturation clear would weaken the intended fail-closed
behavior.

## Execution

Command:

```text
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -m unittest -v test_review.py
```

Observed result: 3 tests passed, 0 failed/skipped, in 5.913 seconds. The Kotlin
compile was bounded to 256 MiB heap and the fixture JVM to 64 MiB. No Docker,
Gradle, daemon, emulator, VM, signing key, network, or Android build was used.

Review files:

- `AdversarialContainmentFixture.kt` SHA-256
  `b1f138015c4edee6c460cea463763df74d3e8b389fc4f0f1ffc08b5ab7039220`
- `test_review.py` SHA-256
  `5c4605924da1a06f8dbf35f67a7af287cf926f39a127acd11612fbd9934125fd`

The existing positive prototype tests and this review are host models. They do
not prove InputDispatcher/PWM thread behavior or end-to-end Android lifecycle
behavior until a corrected projection is compiled and exercised in the pinned
OS/runtime environment.
