# Independent review of containment snapshot 3

Scope: read-only review of the immutable external prototype at
`phase1-recents-key-containment-kotlin-prototype-20261012-snapshot-3`.
The reviewed aggregate ledger is
`cb031b433999aa21f79190f4a440066b71786c8704c6acfb006c886b4349dcfb`;
the reviewed helper is
`2062eebf859a399142133d62be664f7dffc1ac2976e143439bb8660692402bb5`.
No repository, staged OS source, Android image, guest, Docker container, or
runtime state was changed.

Two concrete lifecycle defects were reproduced by compiling the exact frozen
helper with the pinned custom-7 Kotlin/JDK toolchain and a small independent
fixture:

1. **Eventless claim retirement leaves delayed stock action ownership live.**
   A healthy external Escape DOWN can install `EscapeOwner` and the delayed
   `MSG_EXIT_FOCUSED_APP`. If the exact UI claim is retired/blanked before any
   later key or device event, snapshot 3 has no lifecycle notification into
   the policy helper. `completeEscape(completion)` still returns the stale
   owner, so the generated KGC handler can execute quit against the old focus.
   `EventlessRetirementRepro.kt` printed
   `CONFIRMED stale Escape completion survives eventless claim retirement`.

2. **The device-listener saturation census is not atomic with key-policy
   mutation.** The listener runs on `mHandler`, while key interception may
   mutate helper state on the native policy callback thread. Native key-code
   reads occur before and outside the final synchronized `reconcileDevices`.
   A key can be scanned UP, then its DOWN can be stored and consumed while
   saturation remains active, after which stale `allKeysReleased=true` retires
   that new pair and clears saturation. Its later UP is allowed without the
   contained DOWN. `CensusInterleavingRepro.kt` printed
   `CONFIRMED stale concurrent census loses blocked DOWN/UP parity`.

The first issue requires exact claim lifecycle cleanup, including a real
ordering between claim retirement and delayed Escape completion; waiting for
the next key/device event is insufficient. The second requires a helper
mutation epoch captured before the physical census and unchanged at final
reconciliation, or an equivalent true serialization boundary. Snapshot 3 is
historical and does not qualify runtime behavior.

Observed commands used only the small pinned compilers, with 256 MiB Kotlin
and 128 MiB Java heaps. Each fixture compiled with the frozen
`candidate/WonadPolicyKeyContainment.kt` and ran once to exit 0. Temporary JARs
were not treated as evidence or publication artifacts.
