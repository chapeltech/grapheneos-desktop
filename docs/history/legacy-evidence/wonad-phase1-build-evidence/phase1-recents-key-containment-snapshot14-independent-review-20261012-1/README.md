# Snapshot 14 independent expected-RED review

Date: 2026-10-12

Scope: external host-only adversarial review of the immutable, explicitly
partial/unqualified snapshot at:

`/u/elric/tree/wonad-phase1-build-evidence/phase1-recents-key-containment-kotlin-prototype-20261012-snapshot-14-review`

No repository, OS source, stage, SDK, packet, image or guest was changed. No
Docker, Gradle, Soong or Android runtime was run. Two bounded Kotlin fixtures
were compiled with the pinned custom7 Kotlin/JDK using `-J-Xmx256m`; each JVM
used `-Xmx128m`.

## Bound snapshot bytes

| File | SHA-256 |
| --- | --- |
| `candidate/WonadPolicyKeyContainment.kt` | `111fef054391010f89a31a719f2596acdc42d59852dbbae9d82c80319beb7d62` |
| `candidate/WonadPolicyKeyAdapter.kt` | `bbf5d2b1a1175ed6b750d2c79e9efd5a746ecba8451a32b88d762e8f2885a19a` |
| `apply_candidate.py` | `c4ed62779868ceeece124c661a1e2424906b5106217596a497a036967c168923` |
| `test_candidate.py` | `28d14166200106755110bb2288ebb6a9323c1318e02188dadc804baaf631966b` |
| `README.md` | `667f4eeea4f31fb225c6ec131902cdc5f435b2876a0847b1d86c25536e5ce8de` |
| `LOCK-ORDER.md` | `a4f35c64faccfcf46dac57c578b7fd7cb16a9d791b49eb61ff75168f452e21af` |

Review fixtures:

| File | SHA-256 |
| --- | --- |
| `Snapshot14HelperRedTest.kt` | `67de3b67f4df8746f495d267633ee29ebeafcf86e936f5f14cb9695a86a6c73e` |
| `Snapshot14AdapterRedTest.kt` | `67294bd58d1899b6f132b2d14acf5b0d12fa74da2bf79e84e3568091e1eb2253` |
| `run_expected_red.py` | `31a48a691d6df7f0f74d6dbeb1adca42592334ce90481ce70ca8dbe2b05a7101` |

## Command and observed result

```sh
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-recents-key-containment-snapshot14-independent-review-20261012-1/run_expected_red.py
```

Terminal result: exit 0 from the expected-RED harness in 12.27 seconds. The
two candidate JVMs each exited nonzero only because their correct-invariant
assertions observed the expected defects. The harness required all seven names
and printed:

```text
RED:ordinary-stock-down-claimed-up:initial stock ordinary DOWN was reclassified CONSUME
RED:system-stock-down-claimed-up:initial stock HOME DOWN was reclassified CONSUME
RED:barrier-down-cleared-up:barrier-consumed DOWN was followed by STOCK UP
RED:drain-overflow-current-event:overflowing replacement escaped as APPLICATION, saturated=false
RED:focus-null-down-focused-up:focus-null consumed DOWN was followed by APPLICATION UP
RED:handled-history-saturates-foreign-unhandled:an unrelated never-delivered event inherited saturated authority
RED:no-fallback-history-saturates-foreign-unhandled:a never-delivered event inherited leaked fallback saturation
SNAPSHOT14_EXPECTED_RED_REPRODUCED cases=7
```

## Confirmed defects

1. `statefulStock` retains only a narrow subset of stock DOWNs. An ordinary or
   dedicated phone/unclaimed DOWN followed by claim publication has no pair
   record; its terminal is consumed as a claimed terminal-without-DOWN. This
   violates the documented nonretroactive initial-DOWN rule.
2. A barrier-only DOWN with no current claim is consumed but not recorded. If
   the blank/protected barrier clears before its terminal, the UP becomes stock.
3. `deviceSaturated` is captured before replacement retirement. If `addDrain`
   fills the drain ledger and newly saturates the device, that same replacement
   can still escape as APPLICATION with `saturated=false`.
4. The adapter's focus-null fail-close rewrites only the returned Decision.
   The helper has already stored an APPLICATION token, so a focus appearing
   before UP can receive an orphan application terminal.
5. App-handled claimed events never enter `bypassUnhandledStock`, the only
   path that removes `DeliveryLedger.delivered`. Each completed handled pair
   therefore leaves a historical entry. Pair 257 saturates the token and an
   unrelated never-delivered event is thereafter treated as claimed lineage.
6. `bypassUnhandledStock` creates a fallback entry before IMS knows whether
   `KeyCharacterMap.getFallbackAction` exists. The null-fallback path has no
   cleanup hook. Repeated ordinary no-fallback events inevitably saturate the
   token and authorize fail-closed bypass for an unrelated event.

The two ledger mechanisms account for three executable cases; together the six
source defects produce the seven schedules above.

## Separate open boundary

These REDs are independent of the already disclosed pre-target limitation.
Snapshot 14 correctly stopped claiming that all raw hardware remains on
`INVALID_DISPLAY`, but it still has no immutable queue-time physical device
incarnation, focused-token/focus-epoch, exact claim/display-incarnation and
initial-DOWN proof. That separate design is recorded at:

`/u/elric/tree/wonad-phase1-build-evidence/phase1-pretarget-key-origin-association-design-20261012-1/README.md`

SHA-256:
`076231801f02c2cef427fc11b0b622559866415f4e414071a3fe367fbbb20f31`.

This record is evidence of host-reproduced candidate defects only. It is not a
platform compile, runtime failure, release decision, or approval of a future
successor.
