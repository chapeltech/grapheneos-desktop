# Immutable successor precision and remaining qualification limits

2026-10-12. Applies to `work2/sealed/MANIFEST.json`, SHA-256
`10b131eb2e27a5349ca29701a9bf0f6542646a3266e6ab2511d11f82d076e760`.
The seal is unchanged; this note clarifies wording and preserves open evidence.

The compatibility invocation does have a neutral AdmissionCall object with
token0, solely to shadow/restore an outer call. It has no nonzero/native
authoritative admission owner. The sealed README's stale phrase "no
AdmissionCall owner" must be read in that authority sense, not as absence of
the neutral call object. Claimed native completion still requires an exact
accepted nonzero registration; neutral compatibility cannot publish -3.

Exceptional saturation recovery is NOT qualified as an atomic all-UP proof.
Each existing reader getKeyCodeState call locks independently. A queued reader
DOWN may race between per-key reads without changing the pure policy helper's
mutationEpoch. The selected host fixture's allKeysReleased Boolean assumes,
but does not implement, a coherent reader census/fence. No claim of native or
runtime recovery safety follows from that host control.

The independent reader audit at
`/u/elric/tree/wonad-phase1-build-evidence/phase1-reader-key-incarnation-audit-20261012-S8nRoB/AUDIT.txt`
(SHA-256 `6780378d0d40ca5f856e0fe5e0960a3a65224b0adc9343e33efbd462d8599656`)
requires private atomic exact-pair census, activity cutoff and acknowledged
fence through delayed filters, dispatcher and policy. Without that qualified
protocol, exceptional quarantine cannot be released early. The audit's Rust
specification PASS is not native integration or physical-device qualification.

Raw F1/F2 origin/target drift, reader/mapper incarnation and private filter
round-trip, pre-target PWM, safety realm/chord isolation, cancellation collateral,
full platform compile, VM/JNI and physical-device runtime remain OPEN.
