# Snapshot 5 independent containment review

This is a bounded source/JVM review of the immutable external proposal at
`phase1-recents-key-containment-kotlin-prototype-20261012-snapshot-5`
(aggregate file-ledger SHA-256
`9f29eea3a7dd87ad616e4405bea1856764921e659db34aa1cff8cd7f9490b734`).
It is historical defect evidence, not application authority or Android runtime
qualification. No repository, staged OS source, SDK, image, guest, or running
service was changed.

## Confirmed defects

### Cleanup before Java owner publication

Snapshot 5 fixed cleanup that runs *after* a replacement owner is published,
but the generated order was still helper `mark*()` followed by Java
`AtomicReference.set(owner)`. WMS could retire the exact helper owner and the
posted KGC cleanup could execute while the Java reference was still null. The
input callback then published an already-retired owner. For Alt-Tab this stale
reference permanently rejected later replacement Tab DOWN events.

- `PublicationAfterCleanupRepro.kt` SHA-256
  `fbbd10ce1d196e5f2130edc1aef6d4ddd28fd5c706cc7a529d219833f7816519`
- observed stdout:
  `CONFIRMED cleanup-before-publication leaves retired Alt-Tab owner and blocks replacement`

### Owner creation after retirement

`markMetaPending`, `markCapsPending`, `markRecentStarted`, and
`markEscapePending` accepted a stale `PairToken` without proving that its
record remained active, non-draining, and current. The reproduced APP_SWITCH
schedule was `beforeStock` -> exact claim retirement (with no owner yet to
cancel) -> unconditional `markRecentStarted(stalePair)`.

- `OwnerInstallAfterRetirementRepro.kt` SHA-256
  `5a17b9d69a810f9d42156affc466695d0bd70c772a28d7e9a47ec5789af19823`
- observed stdout:
  `CONFIRMED APP_SWITCH owner installs after exact claim retirement`

### Claimed-display Meta steals a pending phone action

The singleton helper `metaOwner` let a concurrent healthy claimed-display Meta
DOWN replace an unclaimed phone Meta owner. The exact phone UP then returned no
owner, while the later external UP received the action. This changes the stock
global pending-Boolean behavior and violates the intended phone/claimed-monitor
isolation.

- `ExternalMetaClobbersPhoneRepro.kt` SHA-256
  `0674ed124286f6acaef3b194fbb507682fd0ad9b9501132d7cbd8d09e132cfb8`
- observed stdout:
  `CONFIRMED claimed-display Meta pair steals pending phone Meta action`

## Explored but not independently classified as a defect

`CompletionAfterRetirementRepro.kt` (SHA-256
`1897e6a9a91f7c568fe1eb63372d492850af77e79b010aadfc63b1da206e288b`)
shows that a Meta completion can obtain its exact helper owner, then WMS can
retire the claim before the oneway stock gesture call. `completeMeta()` may,
however, be the legitimate linearization/commit point for this synchronous UP
operation. Without a stronger contract, this is an observed ordering rather
than an additional confirmed defect. Delayed Escape is materially different
because its timer action is not the immediate continuation of the physical UP.

The immutable snapshot README also documented a replay command under the
mutable working-candidate path rather than its own snapshot path. That is an
evidence reproducibility defect, not a runtime code defect.

## Bounded execution

Each fixture was separately compiled with the exact snapshot-5 helper and the
custom7 source-matched toolchain:

- `external/kotlinc/bin/kotlinc` SHA-256
  `64d62a197fbec5f32f77c6724cce33ead4034b2ec3f873c056cde19fe00f324e`
- `prebuilts/jdk/jdk21/linux-x86/bin/java` SHA-256
  `cfa21aeadd00925925c9e1287f5c08f3e04ee7f26a9e23d9dbfb16149153d842`
- compiler heap `256 MiB`; JVM heap `128 MiB`

These fixtures prove deterministic helper/generated-branch schedules only.
They do not prove a full-platform compile, Android thread scheduling, Binder or
Looper behavior, hardware input behavior, or runtime qualification.
