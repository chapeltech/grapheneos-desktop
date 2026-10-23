# Ordinary phone return from an attached Wonad monitor

## Retained failure

The fresh isolated delivery-conformance guest at
`/u/elric/.local/state/wonad/wonad-phase0-failure-containment-20261021-1`
failed before its intended heartbeat-expiry test. The product parent was
`sha256:6bd81515054a689e17fbf87d36c6661e3228a4bb8e8444404f6a38a457677c0f`;
the ordinary conformance-client derivative was
`sha256:9d3b1fcbe87e7478eed91a4268dc6fc58db82c42dd5fbbb9e4485ccc35f58280`.

After all 16 API operations and black-after-release output passed, a stock
`am start -W --display 0` reused fixture TwoActivity's original Task 17, which
had previously moved from phone to monitor through the trusted picker. The
task reached display 0, but retained `mForceHiddenFlags=8`, external freeform
bounds, STOPPED state and no surface. The launch timed out. No process had
been SIGSTOP'd, so this is **not** a heartbeat-expiry result.

The failed directory, command journal and native Activity/Window/Input dumps
remain unchanged. Broad logs and private guest state are not publication assets.
The harness stopped and removed only its own isolated container.

## Candidate source correction

Physical display removal already clears Wonad's task-hiding and geometry state.
Ordinary task migration while that monitor remains connected had no equivalent
hook. `wonad-native-phone-task-return.patch` now calls a Kotlin helper after
`Task.onDisplayChanged` updates the native display hierarchy, passing the old
actual DisplayContent captured before the change.

The current helper admits only an attached, non-organizer standard ordinary-app
leaf returning from the exact native claimed monitor to display 0 within the
same WMS and active claim user. It reuses native enumeration's UID/package and
system/permission-controller exclusions through a phone-only internal adapter;
ordinary native enumeration still rejects phone tasks. It clears only the
extension's two force-hidden bits, leaving stock hiding flags intact, and
restores focusability, inherited windowing mode, bounds and surface transform
even when a visible app had no hiding bit. It does not reopen a session, grant consent, raise a root or
explicitly resume an Activity. Monitor-to-monitor moves are untouched. Physical
undock retains its existing cleanup ownership because its claim is retired first.

This adds three necessary Java hook lines; the behavior remains Kotlin. No
public AIDL/SDK 3.0.1 bytes, numeric assignments or wire signatures change.
It is nevertheless an OS behavior change: affected source, ordinary-phone,
containment, handoff and image-binding gates must be rerun. Historical inventory
and runtime receipts must not be resealed or inherited as new qualification.

## Exact-artifact evidence

The corrected follow-up, `wonad:phase0-phone-task-return-20261021-2`, is also
delivery `wonad:phase0-delivery-20261021-1`, immutable ID
`sha256:e949e93bd10d79fe007b53edc53d02cb8533c88aa5ace1244b3e2f1aa75508e7`.
It is the next no-argument launch selection on xiombarg; the existing userdata
path is unchanged and no user emulator was started/reset to select it.

The [bounded runtime proof](../out/phase0-phone-task-return-20261021-2/README.md)
contains both known-Task returns with matching failing old-image controls:

- A captured Task moves to an authorized monitor, is parked by actual session
  release and returns through stock phone launch before fresh authorization.
  The original delivery control strands that same Task force-hidden on display 0.
- A visible Task returns without hiding/release/unplug. The first correction's
  control retains freeform `Rect(269,107 - 1651,884)` geometry on the phone.
- Both corrected cases retain their captured Task/Activity identity, restore
  full 1080x2400 phone bounds and accept ordinary input. The monitor remains
  contained when its session is retired.

The same proof binds all 16 API operations/four callbacks, exact ordinary-client
SIGSTOP/reason-5 expiry, native black/input containment, intentional phone input
while stopped, the consumed revocation callback and explicit new-generation
recovery of the original external Task. Eight native expiry frames are audited.
The normal product also passes 13 physical launcher filters, Contacts/Clock
input, exact phone/StyX11 pixels, one-point/one-pixel changes, three-monitor
Recents transfers/hotplug and uninterrupted clean boot/consent/cold restart.

[Separate lifecycle evidence](../out/phase0-phone-task-lifecycle-20261021-2/README.md)
passes an OS-only switch from the previous delivery and independent Wonad
17→18 / StyX11 6→7 explicit updates. UIDs, consent and userdata markers persist;
the unselected package and all seven OS identities stay unchanged for each APK
update. The [packaged SDK check](../out/phase0-phone-task-sdk-20261021-2/README.md)
preserves the immutable publication/source/JVM baseline.

The [source inventory](../out/phase0-phone-task-source-inventory-20261021-2/inventory.json)
and [incremental review](PHASE0-PHONE-TASK-SOURCE-REVIEW.md) bind 59 owned files,
52 patches and 77 targets. Original/corrected real-framework compilation,
six byte-exact original Task classes, services packaging and AVB checks preserve
all 2,676 unrelated system-file entries. This is an incremental cache build,
not a clean full OS build or physical release.

## Preserved failures and scope limits

The first correction `abe20b42…` remains a partial fix, not a delivery candidate;
its [original bounded proof](../out/phase0-phone-task-return-20261021-1/README.md)
keeps its actual passing scope and its separately retained live-return failure.
Neither old controls nor historical stages were rewritten as new qualification.

Two initial follow-up runs waited for an ordinary external app after the API
session had retired; native evidence shows that app correctly hidden behind
containment. The corrected harness opens ordinary authority/applies an observed
frame before waiting for that app to draw. Both old/new controls use identical
test source closures. No hiding/focus/data repair or relaxed timeout is used.
The API suite's requestClose can legitimately remove a fixture; its subsequent
phone launch is not reused-Task evidence. The dedicated parked test captures a
known Task after setup and proves that Task's complete move/release/return path.
One earlier old-live control stopped at consent and is not counted as a migration
control. All failed private guests, command journals and broad dumps are retained.

The helper/classifier's compiled tests and no-hook control supplement actual
runtime tests; they are not Android qualification by themselves. Isolated
Xvfb/authenticated-loopback X11 is not the user's supplied SSH X11 connection.
Final user-X11/handoff remains open, and Phase 1 campaigns, independent review
and Pixel 10/production qualification are not claimed.
