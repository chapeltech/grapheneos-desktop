# Reviewed phone-task-return successor

The emulator delivery `wonad:phase0-delivery-20261021-1` is an alias of the
tested phone-return follow-up, immutable ID
`sha256:e949e93bd10d79fe007b53edc53d02cb8533c88aa5ace1244b3e2f1aa75508e7`.
This incremental review extends the [Recents source review](PHASE0-RECENTS-SOURCE-REVIEW.md),
not a clean OS build, independent certification or physical/production release.
GrapheneOS 2026100600 and neutral API v3 / SDK 3.0.1 remain the pinned baseline.

## Source and language boundary

The [source inventory](../out/phase0-phone-task-source-inventory-20261021-2/inventory.json)
binds 59 owned files, 52 ordered patches and 77 platform targets to this image.
It reconciles the new patch against its authenticated upstream Task preimage;
historical stage markers and sealed evidence are not rewritten.

- Rust: 14 owned files, 3,269 lines / 3,103 nonblank, unchanged.
- Kotlin: 27 owned files, 6,692 lines / 6,318 nonblank; +39 lines from Recents.
- AIDL: 12 files, 167 lines / 155 nonblank, unchanged; generated signing Kotlin
  remains four lines.
- No owned handwritten Java. Upstream production Java has 733 added / 37
  deleted lines across 34 existing paths. This correction adds three hook lines.

The required Task lifecycle hook is Java because the upstream class is Java;
all new behavior is Kotlin manipulating framework-owned Task/DisplayContent
objects. Rust/native input, broker, public SDK, SystemUI, Launcher and both
ordinary APKs are unchanged. No networking, X11, desktop policy, Kerberos or
credential handling enters the privileged extension.

## Reviewed guards and semantics

`Task.onDisplayChanged` captures the old actual DisplayContent before the native
change, then invokes `WonadUiBridge.onTaskDisplayChanged` after `super` under
the existing WM lock. It does not infer identity from a reusable numeric ID.

The helper requires distinct displays, an external-to-phone move, identical
WMS, an attached standard non-organizer leaf, the exact old native claim object,
and a claim/task/current-user match. `returningPhoneApp` reuses the native
ordinary-app UID/package/system-role/permission-controller classifier; its
phone exception is private and explicit. Existing native enumeration and all
other `app()` callers still reject phone tasks. The permission-controller lookup
uses the existing in-process package-manager internal interface, not new IPC.

Only the two Wonad force-hidden bits are cleared. Stock hiding flags survive.
Focusability, inherited windowing mode, bounds and surface geometry are restored
even if a visible task has no Wonad hiding bit. The earlier bit-only correction
was insufficient and is retained as a failing control. The helper does not
raise a root/display, resume an Activity explicitly, reopen a session, bypass
phone keyguard or change consent. Stock phone focus/security continues to win.

Same-display, phone-to-external, monitor-to-monitor, stale/replaced claim,
cross-WMS, wrong-user and excluded/system-task calls do nothing. Final physical
undock retires its claim first, leaving existing undock cleanup in control.
Returning one task cannot authorize or uncover its still-contained monitor.
There is no new public operation, capability, numeric assignment, signer rule,
lineage/TOFU bypass or UID exception.

## Exact-artifact evidence

The [bounded runtime proof](../out/phase0-phone-task-return-20261021-2/README.md)
contains matching old/new source-closure controls for both failures: a known
parked Task retaining force-hidden state on the phone, and a live Task retaining
external freeform geometry. Both corrected paths retain their Task/Activity
identity, full phone bounds and ordinary input. Full frozen API coverage,
actual expiry/black/input containment, fresh-generation recovery, native pixels,
three-monitor Recents/hotplug and uninterrupted first-boot/cold-restart pass.

Actual pinned-framework Kotlin/javac original-byte controls and corrected
compilation, Jarjar/priorityboost/R8, AVB packaging and 2,676 unrelated system-file
entry comparisons pass. These are incremental-cache build controls, not clean
full-OS reproducibility. The original six Task classes reproduce exactly.
Compiled helper/classifier tests include excluded paths and a no-hook control;
they supplement, not replace, the Android runtime results.

The [separate lifecycle proof](../out/phase0-phone-task-lifecycle-20261021-2/README.md)
passes the preserved-data OS-only switch and independent Wonad 17→18 and StyX11
6→7 updates. The [packaged SDK check](../out/phase0-phone-task-sdk-20261021-2/README.md)
revalidates immutable publication/JVM signatures against current sources; earlier
two clean SDK builds remain separate evidence.

The [handoff and ordinary hardware-IME proof](../out/phase0-phone-task-handoff-20261021-2/README.md)
passes the current three-image export/cached-store load and full post-load file
verifier. An additional fresh guest proves real Qt/XTEST preedit/commit/cancel,
native InputConnection transfer, ordinary dialogs and intentional phone input,
then restores its original IME settings. Its shell-selected ordinary test IME
does not qualify the Settings/picker UI or software keyboard UI.

## Limits and freeze rule

The emulator uses named development/test signing, not production key custody.
The earlier unexplained ordinary-phone gesture observation and post-client-death
focus requiring an explicit external click remain disclosed limitations. These
bounded tests do not qualify every phone function, all races, Phase 1 campaigns,
Pixel 10 hardware or a user-supplied SSH X11 connection. Phase 0 is not declared
complete by this review. Final user-X11/handoff evidence remains required.

The frozen contract includes observable semantics, not just method signatures.
Future breaking behavior needs a new major and migration; additive v3 features
must be capability-gated. Any further privileged source/trust change reopens
its affected review, source inventory, runtime and handoff gates.
