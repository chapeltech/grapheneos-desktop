# Phase 0 OS interfaces and privileged source boundary

The deployment roadmap targets **Pixel 10/frankel**. Source inventories here
describe the x86-64 development sibling; they do not qualify physical hardware.

## Current emulator binding — phone-return successor, APK18

The new delivery is `wonad:phase0-delivery-20261021-1`, immutable ID
`sha256:e949e93bd10d79fe007b53edc53d02cb8533c88aa5ace1244b3e2f1aa75508e7`.
Its [incremental privileged review and language inventory](PHASE0-PHONE-TASK-SOURCE-REVIEW.md)
extend the Recents baseline without changing API v3 / SDK 3.0.1, trust policy,
native input/broker, SystemUI, Launcher, APKs or host emulator. The
[runtime proof](../out/phase0-phone-task-return-20261021-2/README.md) fixes both
parked and visible external Tasks returning to the phone, with matching failing
old-image controls, full API/expiry/native-pixel and three-monitor checks.
[Separate OS and APK lifecycle checks](../out/phase0-phone-task-lifecycle-20261021-2/README.md)
and the [exact-image SDK verification](../out/phase0-phone-task-sdk-20261021-2/README.md)
pass. No user's emulator has been started or reset to select it. Actual user-X11
remains required for the final handoff. The
[current export/load and hardware-IME check](../out/phase0-phone-task-handoff-20261021-2/README.md)
passes full byte/graph verification, actual cached-store save/load, the standalone
post-load checker and ordinary InputConnection composition/focus transfer.
The old evidence below keeps its original
artifact identities and does not substitute for new-artifact qualification.

## Previous emulator binding — tested delivery assets, APK18

The previous development image was `wonad:phase0-delivery-20261020-1`, immutable ID
`sha256:6bd81515054a689e17fbf87d36c6661e3228a4bb8e8444404f6a38a457677c0f`.
Its [data-only packaging and desktop check](../out/phase0-delivery-assets-20261020-1/README.md)
binds the unchanged Recents OS/SDK/product APKs/emulator below, plus the exact
tested inactive conformance and separately signed fixture/IME assets. The
normal entrypoint does not install those test APKs. [Fresh-boot-origin and
continued cold-restart checks](../out/phase0-delivery-firstboot-20261020-1/README.md)
pass real frontend app launch/close and preserve phone Home, consent, UIDs,
APK/OS identities and userdata. Original harness failures and test-state
continuations are disclosed, not relabelled as uninterrupted first-boot passes.
The later [uninterrupted fresh-guest/cold-restart check](../out/phase0-fresh-firstboot-20261021-1/README.md)
passes that full bounded frontend sequence on the same image. The
[delivery-image SDK extraction](../out/phase0-delivery-sdk-20261021-1/README.md)
passes the current source/JVM/publication contract with all five immutable
artifact hashes unchanged. Neither check closes the older unexplained failures.
The [delivery-image policy-free API proof](../out/phase0-delivery-api-20261021-1/README.md)
uses its exact bundled test APKs in a separate fresh-guest derivative: all 16
operations, four callbacks, capabilities/facades and actual native black output
after release pass with the original OS/SDK/runtime bytes. It is not an API run
of the normal Wonad APK, adverse-lifecycle qualification or user-X11 handoff.
The no-argument launcher and existing Norse stack select this image without
starting or resetting the user's emulator. Actual user-X11 and final handoff
remain open; this is not Phase 0 completion or production/hardware qualification.
The [additional ordinary-phone UI check](../out/phase0-phone-gestures-20261020-1/README.md)
passes notification/Home gestures and an explicit external return, but retains
one earlier unexplained blocked observation; its original failure is not waived.
The [follow-up test correction](../out/phase0-phone-focus-recovery-20261020-1/README.md)
requires actual Home UI plus native touch/fling/settled-HOME evidence instead
of accepting Recents' shared foreground Activity. Two consecutive longer-stroke
cold boots pass read-only recovery and external launcher input. This changes
test input/observations only; it does not explain the original blocked state.
The [shipping-image supervision check](../out/phase0-supervision-recovery-20261020-1/README.md)
passes three populated ordinary-APK process recoveries with new lease generations,
retained Clock Task/geometry and unchanged phone/OS/APK identities. Native keyboard
focus restoration without an explicit external click still fails and is retained
as a separate limitation; this does not change the frozen lifecycle Binder or SDK.

## Recents OS parent — reviewed correction, APK18

The preceding selected development image was
`sha256:fb0090f3168206065c9707093afbde915f73926a0d0904022fd4442dbcffcedd`,
tag `wonad:phase0-recents-cache-20261019-1`. Its executable inputs are unchanged
in the delivery successor above. See the [reviewed source/API baseline](PHASE0-RECENTS-SOURCE-REVIEW.md),
[source inventory](../out/phase0-recents-source-inventory-20261019-1/inventory.json),
[Recents check](../out/phase0-recents-cache-candidate-20261019-1/README.md),
[pixel/API check](../out/phase0-recents-cache-validation-20261019-1/README.md) and
[shipping update/restart plus stock actions](../out/phase0-recents-handoff-20261019-1/README.md).
Actual user-X11/final freeze handoff remains open; this is not Phase 0 completion
or physical/production qualification. Earlier selected-image statements below
are historical and do not transfer their runtime scope to this image.

## Previous emulator binding — Xlib/XCB bridge fix, APK18, 2026-10-19

The previously selected development image was
`sha256:803be052400745949cccb4b538f37271e71cc171a8b99e6d679f5dda21ef3b3d`.
It corrects the [host Xlib/XCB bridge ABI mismatch](PHASE0-X11-BRIDGE-ABI.md)
over the APK18 image. OS, public SDK, APK, policy and QEMU bytes are unchanged;
one of the 271 emulator-runtime files changes. Its APK18 parent added the ordinary APK's
[launcher-focus policy correction](PHASE0-APK-LAUNCHER-FOCUS.md) to the
finishing-launcher OS below. All seven OS artifacts, SDK 3.0.1, StyX11 and native
policy libraries are unchanged from that OS parent. The current owned
handwritten Kotlin subtotal remains **27 files / 6,653 lines / 6,281 nonblank**;
the new APK helper is not privileged OS surface.

The [exact-image audit](../out/phase0-x11-bridge-20261019-1/README.md) binds
GUI/pixel tests, extended IME/dialog checks, ten quiet populated redocks and
preserved-data host-runtime replacement plus cold restart. The
[earlier OS/APK update tests](../out/phase0-launcher-focus-20261019-1/README.md)
remain separate evidence. Neither implies independent privileged review,
final interface-freeze/Phase 0 exit or physical-device qualification. The
selected-image statements in the earlier checkpoints below are historical.

Separate current-image checks cover the [packaged SDK publication](../out/phase0-packaged-sdk-20261019-2/README.md),
[ordinary policy-free API derivative](../out/phase0-x11-bridge-api-20261019-1/README.md)
and [fixed-size native fixture](../out/phase0-x11-bridge-fixed-20261019-1/README.md).
The [original phone Recents suite failed](../out/phase0-x11-bridge-recents-diagnostic-20261019-1/README.md):
all three destination/input scenarios complete, but a pre-existing phone task
loses its Screenshot action after unplug/redock. This is not a frozen-interface
or ordinary-phone qualification pass. The separately built candidate below
corrects the bounded Recents failure and has now replaced that selected image.

## Launcher display-cache correction

Candidate `sha256:fb0090f3168206065c9707093afbde915f73926a0d0904022fd4442dbcffcedd`
contains the [display-scoped Launcher cache correction](proposals/RECENTS-DISPLAY-TASK-CACHE.md).
The [source/build and Recents evidence](../out/phase0-recents-cache-candidate-20261019-1/README.md)
binds the actual corrected Launcher APK to an AVB-verified emulator OS and a
passing three-monitor GUI/input scenario. Screenshot/Split menu presence, not
their full functionality, is checked. Audited harness differences are explicit.
Separate [native-pixel and policy-free API checks](../out/phase0-recents-cache-validation-20261019-1/README.md)
pass launcher/phone input, exact native-size X11 pixels and all 16 frozen API
operations/four callbacks. The latter uses an explicitly separate ordinary
conformance-client derivative, not the product APK.
The upstream Java delta is nine added / three removed lines in one existing
Launcher file; no owned source, SDK, authority, policy or credential API is added.
All seven checked OS roles, MultiDisplayProvider, SDK 3.0.1, Wonad APK18,
StyX11 APK7 and the emulator runtime remain unchanged. The original stage
marker/inventories remain historical. The successor ledger now registers the
byte-identical canonical patch: 51 patches / 77 targets. Actual stock Screenshot
and Split functionality, an explicit APK17→18 update and cold restarts pass in
the separate shipping-launcher proof above. Broader review/final user handoff
and release qualification remain separate.

## Finishing-launcher source/build addendum — 2026-10-19

The current source adds `!activity.finishing` to the native active-catalogue
selector, addressing the separately reproduced phone-import cancellation focus
failure. The [correction and invariant review](PHASE0-ACTIVE-LAUNCHER.md) retains
the old failing selector and the quiet guest's initiating evidence. The new
`WonadNativeBridge.kt` SHA-256 is
`57100a046ad8915043f8e06be168ff8cdac28a90ebf41c0a718ef50c74b08546`.
The UI bridge and hotplug-renewal controller hashes below remain unchanged.

This adds four comment lines and one predicate to the existing Kotlin source;
the handwritten Kotlin subtotal becomes **27 files / 6,653 lines / 6,281 nonblank
lines**. Other language/file totals, upstream patches, public SDK and trust
contract are unchanged. Real-framework compilation, the byte-exact original
control, incremental services transformation, AVB and seven-role packaged OS
readback pass. The [exact-image bounded runtime audit](../out/phase0-active-launcher-20261019-1/runtime-audit.json)
also passes ten quiet populated redocks, cancelled/confirmed phone import and
ordinary-client API coverage. Remaining handoff checks and independent review
sign-off are not implied; at that checkpoint the default was still unchanged.

## Hotplug-renewal source/build addendum — 2026-10-19

The current tree additionally corrects the observed departing-monitor renewal
race in `NativeDesktopController.kt`. The
[review addendum](PHASE0-HOTPLUG-RENEWAL.md) binds controller source
`b5e2ce07023583dce4c2c0cb07a226d6581b481b62dff13ce58300b65e75bd89`
to the new SystemUI/OS build. Its 41 added / 11 deleted Kotlin lines change
private decline classification and attempt-all cleanup, not the public API,
SDK, signer, lease duration or APKs. The handwritten Kotlin subtotal becomes
**27 files / 6,649 lines / 6,277 nonblank lines**. Other language/file totals
and the upstream patch ledger are unchanged.

Real-framework original class reproduction, SystemUI packaging, AVB and seven-file
packaged readback pass. Separate bounded current-image desktop/IME/API checks
also pass; full qualification and promotion remain separate. The selected default
image described in the earlier keyboard-recovery checkpoint did not contain this change.
Do not reseal the earlier inventories or infer a completed interface freeze.

## Earlier keyboard-recovery candidate binding — 2026-10-19

The previously selected development image was
`sha256:e1fdd75f9f966d1fbc0cd3afb303622eaec607cd74148a974dad16f3953bfdb3`.
Its [source delta](../out/phase0-keyboard-recovery-20261019-1/source-delta.json)
accounts for all 59 owned files against the earlier supervised inventory below;
the original stage marker and that inventory remain unchanged. This selected
image's two subsequent owned privileged-source changes are:

- `WonadUiBridge.kt`: healthy lease renewal retains the live plane while still
  rechecking admission and replacement. It must not transiently blank/shield a
  healthy desktop. Opening, authority loss and replacement retain containment.
- `WonadNativeBridge.kt`: the existing WM-locked watchdog may reconcile an
  authenticated finishing launcher with no focused window to the already-drawn
  neutral HOME. Exact lease, active user/UID, component/permission, generation,
  catalogue and actual HOME ancestry/drawing checks remain required. This must
  not choose an app, raise a display or steal phone focus.

These are 47 added / 8 deleted Kotlin lines, with no new Java, Rust, AIDL, SDK
operation, policy or credential handling in the OS. This image's owned handwritten
Kotlin subtotal is **27 files / 6,619 lines / 6,249 nonblank lines**; other
owned language/file totals and the upstream patch ledger below are unchanged.

| Selected-image owned source | SHA-256 |
| --- | --- |
| `WonadNativeBridge.kt` | `0beed8c518f97b54a9b9f7cd9aae9ad2f24c9979346984e327e1ee6a74ddfc6a` |
| `WonadUiBridge.kt` | `6a4c198d6837ab515cb7af49a2c7eacfad0c31b79d5bd2c02c1be8f3b64cc06e` |
| `NativeDesktopController.kt` | `67e6e7c96eefb9d33db54494b571a5d037a3efd49b7dc80d562637cfb98e16ca` |

The [candidate evidence](../out/phase0-keyboard-recovery-20261019-1/README.md)
binds real-framework compilation (including exact reproduction of the 71
original bridge classes), services transformation/OS packaging, seven live OS
file checks, the unchanged SDK 3.0.1 publication and bounded runtime checks.
The separately packaged emulator keyboard pacing change is not a phone OS/API
change. This binding is **not independent privileged review sign-off or a
completed interface-freeze/Phase 0 exit**; the backlog retains those gates.

## Supervised emulator source inventory — 2026-10-19

The [successor inventory](../out/phase0-supervised-source-review-20261019-1/inventory.json)
binds product image
`sha256:3e977b15b3f0093506c95bf785d5ec7e2c9d6642e2afe49c51d592975c1deb47`
to the retained nullable-adapter stage, authenticated packaged supervision
sources and replayed Goldfish fixes. It compares every owned source with the
repository and every platform pre/postimage with its pinned upstream revision.
It does not alter or reseal the historical stage. At that checkpoint the
inventory was produced read-only with:

```sh
python3 -B android/tools/phase0_supervised_inventory.py \
  --source /u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-11
```

That older check requires the matching retained supervised owned-source tree;
it intentionally rejects the later keyboard-recovery and lease-renewal changes. Use
the candidate-specific source bindings above for the current tree, not a
resealed historical inventory.

| Owned source | Files | Lines | Nonblank lines |
| --- | ---: | ---: | ---: |
| Rust core and JNI | 14 | 3,269 | 3,103 |
| Handwritten Kotlin including SDK constants | 27 | 6,580 | 6,211 |
| AIDL declarations | 12 | 167 | 155 |
| Generated signing Kotlin | 1 | 4 | 3 |

There are **59 owned files**, including five build/license/certificate/resource
inputs and no handwritten owned Java. Compared with the authenticated corrected
stage, supervision adds `DesktopSupervisionPolicy.kt` (22 lines) and
`WonadClientSupervisor.kt` (120), and changes `NativeDesktopController.kt`
(6 added) and `WonadController.kt` (17 added / 5 deleted). Rust, SDK/AIDL and
system-server owned-source bytes are unchanged. Supervision's separate
[component/action/caller contract](../os-integration/SUPERVISION.md) does not
rewrite the immutable SDK publication.

| Patched upstream project | Ordered patches | Bound targets | Production net added/deleted lines |
| --- | ---: | ---: | ---: |
| frameworks/base | 41 | 60 | 1,439 / 47 |
| Launcher3 | 5 | 12 | 403 / 70 |
| Goldfish | 4 | 4 | 35 / 6 |

These are **50 ordered patches / 76 targets**. The old `git diff HEAD` counting
method omitted nine patch-created, untracked paths (eight production, one test).
The successor counts each authenticated pre/postimage, including new files;
the increased framework/Launcher totals are a counting correction, not newly
added framework work. Production Java totals **721 added / 34 deleted across
33 paths**, including the emulator provider startup-order fix. Kotlin helpers
embedded in platform patches are included in the platform ledger, not the
59-file owned-tree subtotal.

The corrected stage marker is
`8c2ad070dca8cad781c98dbb38f8c1817b6913cbb6b78b15321a6db0ba70c84d`;
the packaged supervision archive is
`48d5d7c30c1c109074424c222f09aa6f912de272c14beaab23860f4dc5b51db7`.
The tool replays front-buffer retention and Java initialization-order patches
in a temporary tree and checks their resulting hashes against the immutable
image's source bindings. Current owned-file hashes and all upstream pins,
patches, target hashes and language deltas are in the JSON ledger.

This is source-review evidence, **not full source-to-binary reproducibility,
independent review sign-off, runtime or production-signing qualification**.
The signer remains the named emulator development identity. See the
[review addendum](OS-GLUE-REVIEW-2026100600.md#supervised-emulator-review-addendum--2026-10-19)
for the changed trust-boundary behavior and remaining qualification limits.

## Historical custom11 inventory — 2026-10-14

The following is the **historical 2026-10-14 custom11 source inventory**, before the
nullable framework-adapter correction and subsequent OS-supervised APK startup.
Its counts, source hashes and stage marker do not describe the later running
images. It is not a security certification or a production release review.
The deployment roadmap now targets Pixel 10/frankel; this inventory's development
sibling targets `sdk_phone64_x86_64-cur-userdebug` at GrapheneOS `2026100600`.

The SDK publication below remains independently verifiable. The successor
inventory above includes [the APK lifecycle compatibility contract](../os-integration/SUPERVISION.md).
The original stage verifier correctly rejects the current changed patch ledger;
do not edit its historical marker to manufacture a match. Running-image evidence
is separate from this source review.

## Original source inventory

The dedicated checkout is
`/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-11`.
Its verified `external/wonad/.wonad-stage.json` is 28,286 bytes, SHA-256
`6e86389ee395a5e8a1099bb9c0e0c7fa041dc50c7dcecc926515bc30d2ba2b9b`.
The stage binds all **57 owned files**, upstream revisions, public signer,
ordered patch bytes, affected platform targets and staging tools. The
[preparation receipt](../out/phase1-custom11-source-preparation-20261014-1/receipt.json)
explicitly says the full OS build has not started.

With the matching original checkout and patch set, reproduce the complete per-file
hash/size/count and ordered patch ledger with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B android/tools/phase0_os_inventory.py \
  --source /u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-11
```

The read-only tool invokes the actual stage verifier before and after counting.
Counts include comments; nonblank counts exclude only empty/whitespace lines.
Generated signing Kotlin is separated; generated AIDL Java is not counted as
handwritten Kotlin/Java. These are physical source counts, not executable-code
or complete Android-framework size estimates.

| Owned source | Files | Lines | Nonblank lines |
| --- | ---: | ---: | ---: |
| Rust core and JNI | 14 | 3,269 | 3,103 |
| Handwritten Kotlin including SDK constants | 25 | 6,420 | 6,063 |
| AIDL declarations | 12 | 167 | 155 |
| Generated signing Kotlin | 1 | 4 | 3 |

There are **zero handwritten Java files in the 57-file owned tree**. Five other
files are build/license/public-certificate/resource inputs. AIDL generates Java
Binder code during compilation; that generated output is not a claim of zero
framework Java changes.

| Patched upstream project | Ordered patches | Bound targets | Production net added/deleted lines |
| --- | ---: | ---: | ---: |
| frameworks/base | 41 | 60 | 1,041 / 47 |
| Launcher3 | 5 | 12 | 305 / 70 |
| Goldfish | 2 | 2 | 6 / 0 |

These are **48 ordered patches / 74 target paths**, not the older 46/64 review.
Net counts come from `git diff --numstat HEAD`, so overlapping ordered patches
are not double-counted. Test-path deltas are separately retained in the tool's
full output and excluded from production totals. Production Java deltas are
716 added / 31 deleted across 32 paths, not the sizes of those Java classes.
They are necessary framework seams for WMS/task/display/surface containment,
input/gesture dispatch, IME/location-button routing, SystemUI/Shell integration
and Launcher Recents transfer. Framework Kotlin, resources/build definitions and
Goldfish changes remain visible in the full ledger; they are not hidden by the
Java subtotal. Minimization is a review obligation, not a zero-Java assertion.

## Trust boundaries

- [WonadController](../os-integration/src/org/wonad/desktop/broker/WonadController.kt)
  captures the Binder caller UID, derives its user and requires the active user,
  ordinary app-id range, unique `org.wonad.desktop` package ownership and exact
  application UID. It rejects shared UIDs, multiple current signers and signer
  history/lineage substitution. The single current certificate digest must match
  generated `WonadSigning`. Version/capability queries authenticate too; they
  cannot create authority while disabled/locked/undocked.
- [NativeDesktopController](../os-integration/src/org/wonad/desktop/broker/NativeDesktopController.kt)
  serializes lease operations, rechecks actual OS identity/environment, and
  fences retained queued/deferred work to its exact live session. Consent is
  per active user; interactive unlock and live trusted, secure, public, non-phone
  monitors gate admission. Task/display tokens, generation, revision and
  system-server identity epoch are not numeric Android-ID authority. Timeouts,
  callbacks and abandoned catalogue cleanup are owner-scoped.
- [Rust core](../broker-rust/src/lib.rs) is dependency-free `no_std`, forbids
  unsafe code and receives copied OS-authenticated scalar identity/geometry,
  never trusted APK identity claims or Android object pointers. Rust/JNI modules
  marshal bounded values; Kotlin owns Android objects and platform completion.
  Successful request admission is not proof that a WM transition applied.
- [WonadNativeBridge](../input-integration/src/com/android/server/wm/WonadNativeBridge.kt)
  and [WonadUiBridge](../input-integration/src/com/android/server/wm/WonadUiBridge.kt)
  implement exact UID/user/session/plane containment, readiness, task/input and
  stock-UI suppression. Claimed monitors fail black and consume input until
  fresh authorized, drawn planes exist; stale shell/window/sink retirement must
  not affect a replacement or expose stock desktop content. At the original
  custom11 checkpoint the source hashes were NativeBridge
  `44aec6236fcd41610c4e6c708ca94087835e96bba500eb26a5df15f51bbfb775`,
  UiBridge `f3255791a17f750e988794fc7f0a4f37c83cbe7155612cd4620200698231e566`,
  controller `0194a5f786b4de72ef877b240e45d53824d8512941e8f675df9c1eed8947e093`.
  The candidate-specific binding above supersedes those historical hashes.
- Phone Home/Recents/permissions/IME remain ordinary Android. Keyboard routing
  follows intentional focus: phone input is allowed; an already-admitted
  external event cannot be redirected asynchronously to the phone/replacement.
  Balanced held-key cleanup remains required. No permanent keyboard association
  or blanket phone-input ban is implied. Launcher “Send to Wonad” validates the
  exact current task and destination; cancellation, Screenshot and Split screen
  retain their ordinary behavior.
- Only ordinary Wonad consumes the privileged SDK. Its Haskell desktop policy
  and ordinary StyX11 document tasks, X11, grsh/Kerberos, network and credential
  policy remain outside the OS. A second policy client requires an OS trust
  decision, not an APK-only authority expansion.

The staged certificate digest is
`3183261f28256159ad5e488d8a34854e77f36e14348720daae7f8cae7a8c26ff`:
**Wonad Phase1 Emulator Development**, not production custody or AVB/OTA lineage.
Only its public certificate is staged; private DEV signing material remains
outside the source/image. This explicit development identity must not be
relabelled as the production release signer.

## Frozen APK contract and existing publication

The sole public interface is neutral `org.wonad.desktop.api`, API version3,
SDK coordinate `org.wonad:desktop-sdk:3.0.1`. The
[specification](../desktop-sdk/API-v3.md) freezes endpoint/facade identity,
transaction and parcel order, constants/reserved slots, capability bounds,
lease/heartbeat/timeouts, readiness, completion/revocation, token/epoch rules,
one-second catalogue cadence and nullable one-way picker admission.
The [machine contract](../tests/fixtures/desktop-sdk-contract-v3.json) signature is
`db6ac649c34d8c25ab0bdd4a46802639deb3972d376070c6c3cdd811d7962fff`.
API2 surfaces/fallbacks are absent; removed capability slots remain reserved.
Additive compatible evolution must not reorder/reinterpret existing wire values;
breaking changes require a new major and explicit migration.

The actual [successor28 publication](../out/native-current-successor-12-phase1-v3-runtime-20261014-28/sdk-repository/)
is bound by its [build receipt](../out/native-current-successor-12-phase1-v3-runtime-20261014-28/build-receipt.json).
Current-source independent publication verification passes without rebuilding:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B android/tools/verify_sdk_publication.py \
  android/out/native-current-successor-12-phase1-v3-runtime-20261014-28/sdk-repository \
  --source-root android
```

| Immutable publication artifact | SHA-256 |
| --- | --- |
| AAR | `c1e164b7c57efd7f0997a90c92707cdaca16d1e5d3a47eb61197eb7b14fc4b07` |
| sources.jar | `85d185c6c554d3f578c0961fecd007c67f98cb121390295c209843702eb7ae37` |
| contract.zip | `79a9e792af16b6d7e5bfb8b29e28d38842827523f0c62fc33bee126f8160a7f6` |
| module | `d5ed7757bae3ac8713f9792e6138d9cc4f70708fc8ac0b519369641a46b3675f` |
| POM | `82fb551543203b2d871c6da2a54863118bd40bd4ad3ca07500880a3b0058b2b2` |

Spec SHA-256 is `60dba59139f7c6c692c533095edc9243fb67ebe24c24696b45dce72ba542d856`;
machine-contract file SHA-256 is `519893e53906548144f5f407de0481f21d6b608f32cf53ffa658f28c1f235e8c`.
SDK3.0.1 is a documentation-only semantic clarification, not a wire/ABI change.

The [two clean-workspace rebuilds](../out/phase0-sdk-rebuild-20261020-1/README.md)
independently reproduce all five immutable artifacts above in separate
networkless containers. Each runs release JVM tests and publication verification
with build-cache reuse disabled; the captured SDK sources and exported JVM/wire
contract are unchanged. Both use the same pinned prebuilt toolchain. This closes
the SDK publication reproducibility check, not independent OS review, user-X11
handoff, production signing or the overall Phase 0 exit.

## Evidence boundary

Verified stage, source/model tests and actual SDK/client compilation do not prove
that a particular privileged OS has compiled or run. The original checkpoint
preceded its OS build; later emulator builds and tests have separate receipts
and must not inherit this inventory's counts or review claims. Historical
compiled7/runtime images do not inherit later source fixes. Phase0 does not require ARM64/production OTA, full
23-gate qualification or a 24-hour soak; it does require an honestly identified
working current-OS emulator and no waiver of the interface/trust boundaries above.
