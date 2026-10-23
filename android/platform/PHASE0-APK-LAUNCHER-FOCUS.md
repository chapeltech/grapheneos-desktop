# APK-owned focus after an explicit launcher selection

This correction is in the ordinary Wonad APK. It adds no OS operation,
permission, callback, native library or privileged-source change. API v3 / SDK
3.0.1 and the existing seven OS artifact hashes remain unchanged.

## Observed failure and policy boundary

The [retained original run](../out/phase0-active-launcher-20261019-1/README.md#original-failing-native-pixel-run)
successfully launches and draws Clock, but external keyboard focus remains on
Wonad's neutral HOME. Every typed launcher filter matched. The APK forwarded
the catalogue selection but retained no explicit application-focus intent.
Its later passive layout frames deliberately request no focus change. Native
launch timing could therefore determine whether keyboard focus reached Clock.

The desktop's window selection belongs to the APK. An explicit chooser selection
now records a bounded, one-shot policy intent. Once a fresh matching Task is
visible and input-enabled in an authenticated, unblocked snapshot, the APK uses
its existing Haskell focus gesture and ordinary frame operation. A component
string is never converted into a native handle.

## Snapshot redaction matters

`NativeDesktopController.observe` deliberately reports both focus tokens as zero
while a picker is active, with `interactionBlocked=true`. Zero in that state is
not proof that the user focused the phone. The caller retains its pre-picker
external-focus observation, binds it to the current identity epoch, generation
and topology, and interprets focus again only after the block clears.

This detail is covered by an APK17-source negative control. APK17 passed one
GUI/pixel run, but that pass alone did not prove its proposed intent could survive
real picker redaction. The corrected implementation handles that snapshot shape
explicitly; the older pass and source remain under their original identities.

## Cancellation and limits

- Phone focus or another monitor in the unblocked snapshot cancels the intent.
  OS focus admission still independently rechecks the current native state.
- New explicit keyboard, panel or pointer-grab commands discard pending and
  queued automatic focus. New native application focus, topology changes and
  expiry also discard queued requests. A discarded request never reappears.
- Replaced epochs/generations, removed attachments and expired catalogues cancel
  the intent. Expiry remains bounded by the original catalogue lifetime; it does
  not extend any OS lease or picker ticket.
- Only one fresh matching package Task is eligible. Existing package tasks and
  ambiguous new windows use native reuse/ordinary window-manager interaction;
  the package string is not enough to select one of several existing windows.
- There is no focus-retry loop, pointer warp, synthetic mouse click, phone-input
  exclusion, implicit phone-task import or private-data repair.

## Verification

The compiled chooser/observer regression retains the original APK14 chooser
source and APK17's compiled-source snapshot as distinct negative controls. The
corrected source passes 56 checks, including redaction, actual chooser/observer
method bodies, queued cancellation, focus changes, stale identities and expiry.
The ordinary Android release build also compiles against the actual SDK and runs
the existing desktop unit tests and lint. Native Haskell/Rust library bytes are
reused exactly from the signed APK14, not claimed as a new native compilation.

Live qualification uses the unchanged physical-XTEST launcher/Clock scene and
pixel suite, followed by separate preserved-data OS and explicit APK updates.
Host controls alone are not rendering, Binder/WMS or hardware qualification.
