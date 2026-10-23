# Phase 1 native app-input lease-loss independent review

Date: 2026-10-11

This is a bounded source and host-test evidence review. It is not an OS build,
guest run, or runtime qualification.

## Original defect and negative control

When a display retained `nativeMode == true` but its authenticated native lease
had become unavailable, `clipNativeAppInput` returned without changing a newly
populated ordinary application's input handle. That could publish the stock
input configuration instead of blocking the new handle.

The pre-fix compiled negative control is preserved at
`custom6-app-input-lease-loss-before-fix-20261011/test_native_app_input_lease_loss_compiled.py`
(SHA-256 `9a62755d3fed4c4590c4347fbaf57348275b3bdde9e9d790be5825c9ef3d6b2a`).
Its README is SHA-256
`d08019304da2d589ba687e2e8375d603b589939fc923a549faf7da4f5b7fe277`.
The recorded command compiled successfully and then failed at the assertion
`sticky native display without a valid lease must drop newly populated app input`.
Phone, unclaimed-display, and live-lease controls had passed before that
assertion. The historical production source used there was SHA-256
`aeb2e4788d6037f0ebd09b354a67a78db772582a6a72627bcb61d4993e8432a8`.

## Reviewed correction

Final reviewed files:

- `android/input-integration/src/com/android/server/wm/WonadNativeBridge.kt`:
  SHA-256 `3fd2bd1317217220a5efbb4118f7fc762f7dd32d784b712c5ff1020e2221248c`.
- `android/tests/test_native_app_input_lease_loss_compiled.py`:
  SHA-256 `94d5318513eb599d89851a3fc658514498a2b35c6757d8a08bfd35fb026e1edf`.

The executable source was first reviewed at SHA-256
`2a792fa370ad562e67751d4c9bbd4d72104f953be27f7597dbe40e8ef9ae7f5a`.
The only later production delta reflowed and corrected the
`clipNativeAppInput` comment: live-lease clipping preserves focus, trust, and
drop flags, while the no-lease branch deliberately adds only a Wonad-owned
`DROP_INPUT`. No executable token changed. Replacing that exact comment with
the retained prior wording in memory reconstructs SHA-256 `2a792fa3...`, which
independently confirms the bounded comment-only delta.

The implementation keeps a weak, per-`InputWindowHandleWrapper` ownership
record only when Wonad changes `DROP_INPUT` from false to true. Every
`configureInput` first removes that record and clears only the bit Wonad owned.
The null-lease branch then adds only `DROP_INPUT` and records ownership only if
the masked setter reports a real false-to-true transition. Consequently:

- an existing stock `DROP_INPUT` is never claimed or cleared by Wonad;
- every other stock flag and focus/trust/crop/region property is preserved;
- repeated blocked population of the same wrapper restores then re-applies the
  bit before the single input-window transaction is published;
- healthy renewal, migration to the phone, an unclaimed/disconnected display,
  and a null display release only a Wonad-owned block; and
- weak keys do not retain destroyed window/handle objects.

No Binder, JNI, AIDL, APK, or Java-facing interface changed.

## Pinned-stock assumptions independently checked

The authenticated pinned framework files reviewed were:

- `InputConfigAdapter.java`, SHA-256
  `bc6c7f6bebf58341d62f3b6fe13b191365ae4a1878c4b25e3df30f7262c74582`;
- `InputWindowHandleWrapper.java`, SHA-256
  `5f6284f75e1e8af238eefd37f4401c3f285c2498cae97d0e141114c1e9cab8fb`;
- `InputMonitor.java`, SHA-256
  `bdb799f17556ffad88f3165f9993b08768999db94e13efb12cb919d39b2d7734`.

`InputConfigAdapter.getMask()` and stock population do not own
`DROP_INPUT`. The wrapper's masked setter returns false without mutation when
the masked value already matches, and otherwise mutates the requested mask,
marks the wrapper changed, and returns true. The wrapper has no custom
`equals`/`hashCode`, so the weak-map key has identity semantics; one wrapper is
allocated per `WindowState`. Actual population runs inside the input-update
runnable while holding `mService.mGlobalLock`, and application of the changed
handle occurs only after the Wonad hook returns. The non-input/tokenless overlay
population path does not call the hook, but any later eligible population does
restore ownership before publication.

The final test adds an explicit stock-flag-only control: lease loss must produce
exactly `STOCK_FLAG | DROP_INPUT` while retaining focus, trust, crop, and region.
It also source-checks the pinned stock mask/population/setter assumptions.

## Recorded host-test evidence

Root recorded, against production SHA `2a792fa3...` and pre-final test SHA
`74deb7a0f83ba03b64011679df4412470748fb9d76155773a8f2b03c70c74f54`,
the command:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=android/tests python3 -m unittest -v test_native_app_input_lease_loss_compiled test_native_bridge_safety test_native_desktop_focus_compiled test_native_ui_surface_migration_compiled test_native_prerequisite_input_readiness
```

Result: 27/27 passed in 16.769 seconds, exit 0.

The implementation owner recorded the final focused command against production
SHA `3fd2bd13...` and final test SHA `94d53185...`:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=android/tests python3 -m unittest -v test_native_app_input_lease_loss_compiled test_native_bridge_safety
```

Result: 17/17 passed in 5.493 seconds, exit 0.

Root independently reran that same final focused command in session 49702
against production SHA
`3fd2bd1317217220a5efbb4118f7fc762f7dd32d784b712c5ff1020e2221248c`
and test SHA
`94d5318513eb599d89851a3fc658514498a2b35c6757d8a08bfd35fb026e1edf`.
The session terminated with exit 0: 17/17 tests passed in 5.535 seconds.

## Limits

The regression establishes behavior for newly populated handles. It does not
establish when InputDispatcher ceases routing through a handle published before
lease loss, nor does it qualify SurfaceFlinger/InputDispatcher transaction
timing. Those earlier-published-handle and end-to-end timing questions require a
fresh built image and runtime guest/device evidence. No such build or guest was
run for this review.
