# Reviewed emulator source and APK-interface baseline

The reviewed development image is
`sha256:fb0090f3168206065c9707093afbde915f73926a0d0904022fd4442dbcffcedd`.
It uses GrapheneOS `2026100600`, neutral API v3 and the immutable published
`org.wonad:desktop-sdk:3.0.1`. The [SDK specification](../desktop-sdk/API-v3.md),
packaged transaction/JVM-signature/hash baseline and
[publication checks](../out/phase0-packaged-sdk-20261019-2/README.md) remain
unchanged. This is the APK-facing baseline: no wire/layout/numeric assignment
may be changed in place. Future additive v3 features require capability gating;
breaking changes require a new major and explicit migration. Preserve 3.0.0.

This is an incremental source/trust-boundary review, not independent certification,
a clean reproducible build, production signing or Pixel 10 hardware qualification.
The named emulator development certificate is not a production release key.
Actual user-X11 handoff remains required for the Phase 0 exit.

## Scope and language inventory

The [reconciled inventory](../out/phase0-recents-source-inventory-20261019-1/inventory.json)
checks every owned source, all inherited platform target hashes and pins,
packaged corrected sources and the ordered patch registry. Goldfish changes
and the new Launcher patch are replayed against pinned preimages. The earlier
stage marker and sealed inventories are not restaged or rewritten.

- Owned handwritten Rust: 14 files, 3,269 lines / 3,103 nonblank.
- Owned handwritten Kotlin: 27 files, 6,653 lines / 6,281 nonblank.
- AIDL: 12 files, 167 lines / 155 nonblank; generated signing Kotlin: 4 lines.
- 59 owned files total, including build/license/public-certificate/resources;
  no owned handwritten Java. Upstream production Java has 730 added / 37 deleted
  lines across 34 paths, including the emulator provider, not 34 new Java files.
- 51 ordered upstream patches, 77 targets. Launcher now has six patches and
  13 targets; the new canonical patch is `wonad-recents-display-task-cache.patch`.

Only three owned files differ from the prior supervised inventory. Their bytes
match authenticated source archives in this image. Existing Rust/AIDL/SDK and
all other owned source hashes are unchanged.

## Reviewed authority and lifecycle deltas

`WonadUiBridge.show` distinguishes opening a native plane from renewing an
already-live lease. Both still require current claim/owner/user/generation,
drawn native HOME and the same admitted lease before and after operations.
Admission loss restores containment; a stale call must not touch a replacement
claim. Keeping healthy input live is not authorization to revive a revoked lease.

The closing-launcher reconciliation requires a non-phone top-focused display,
current native lease/plane, no blocked/protected phone state, the exact finishing
launcher component/UID/user/permission/generation/catalogue and no current input
window. Its only fallback is the authenticated drawn neutral HOME, not an app,
new Task, phone focus request or APK-supplied numeric target. The active launcher
selector additionally excludes finishing activities without relaxing other guards.

`NativeDesktopController` treats a declined renewal as stale only after fresh
authorization and a validated native attachment-token mismatch. Same-attachment
declines and transport/auth failures remain real failures. Attempt-all cleanup
renews independent siblings and cannot let a stale monitor hide another failure.
No replacement monitor receives authority through this classification.

The Launcher change scopes existing task queries by display and adds an
ephemeral bounded query on a missing display. It does not grow global history,
move/focus tasks, select desktop policy, alter Screenshot policy or expose a new
privileged endpoint. Pinned/Recents/bubble/wallpaper filters and shell tracking
remain intact. Actual upstream-class/Jarjar/DEX original controls reproduce the
retained build before the corrected APK is signed and AVB-packaged.

These changes add no API, capability, signer bypass, platform/shared UID,
lineage/TOFU rule, networking, X11, grsh, Kerberos or credential handling to the OS.
The existing per-call active-user/ordinary-UID/unique-package/current-certificate,
consent/unlock/display, identity/generation/lease and containment guards remain
the contract. Wonad/StyX11 remain separate ordinary APKs; only Wonad has authority.

## Evidence and remaining limits

[Recents/native transfers](../out/phase0-recents-cache-candidate-20261019-1/README.md),
[native pixels and policy-free API coverage](../out/phase0-recents-cache-validation-20261019-1/README.md)
and [shipping update/restart and actual stock actions](../out/phase0-recents-handoff-20261019-1/README.md)
bind this image to real Qt/XTEST, 16 operations/four callbacks, actual black
released output, preserved app UIDs/consent/userdata marker and functional
Screenshot/Split. Original failures and harness differences are explicit.
All 29 staging/ownership tests also pass with the registered successor patch.

These are bounded checks, not all adversarial races, every ordinary-phone
function, full upstream comparisons, a 24-hour campaign, real user/SSH X11 or
physical release qualification. Those later-phase gates are not waived. Any
subsequent OS/API/trust change must reopen affected review and qualification.
