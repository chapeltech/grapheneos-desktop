# Phase 0: Xlib/XCB event-ownership ABI mismatch

The missing mouse releases reproduce without Android, QEMU or Wonad. The SDK's
bundled `lib64/qt/lib/libX11-xcb.so.1` writes `event_owner` at offset `0x40` in
Xlib's private connection structure; the container's matching Debian Xlib bridge
writes it at `0x48`. Qt intends to give its XCB reader exclusive ownership, but
the old bridge leaves Xlib believing it still owns that queue.

The private-Xvfb protocol trace records the final release delivered to Qt's
connection. Interposition at libxcb's public event-reading functions then catches
system `libX11.so.6` consuming that exact master-pointer release instead of Qt's
reader. Qt and Android consequently retain a pressed button. Merely waking Qt,
disabling XI2 or changing the dispatcher setting does not correct ownership.

This matches the upstream division of responsibility:
[Qt sets XCB queue ownership](https://github.com/qt/qtbase/blob/v6.5.3/src/plugins/platforms/xcb/qxcbconnection_basic.cpp),
while [Xlib checks that ownership before consuming events](https://github.com/mirror/libX11/blob/libX11-1.8.4/src/xcb_io.c).
The local disassemblies and live traces establish the actual mismatch; the
upstream source alone is not runtime proof.

## Correction

`build_phase0_x11_bridge_image.py` derives a candidate from the exact APK18 image
and replaces only the SDK bridge with the container's matching system bridge.
Both Debian `libx11-6` and `libx11-xcb1` are version `2:1.8.4-2+deb12u2`.
The manifest binds both system libraries as well as all 271 emulator-runtime
files. Their private ABI must remain a matched pair in future image builds.

There is no release-synthesis, focus retry, input policy change, disabled XI2,
product preload workaround, or OS/APK/QEMU rebuild. The new image has its own
whole-runtime identity; the old image and failed attempts remain unchanged.

Selected development image: `wonad:phase0-x11-bridge-20261019-1`, immutable image
`sha256:803be052400745949cccb4b538f37271e71cc171a8b99e6d679f5dda21ef3b3d`.
The [exact-image evidence](../out/phase0-x11-bridge-20261019-1/README.md) binds
bounded runtime checks and default selection. This does not complete the broader
Phase 0 interface-review/user-X11 handoff or qualify a physical phone release.

## Tests

`run_qt_mouse_release_probe.py` runs isolated authenticated Xvfb controls using
the exact shipped Qt libraries, plus a pure-Xlib control. `--xcb-boundaries`
observes libxcb returns and Qt dispatch without changing input;
`--xrecord` passively records the private server's requests/events.
`--system-x11-xcb` is a diagnostic preload control, not the packaged correction.
Every failed click terminates its attempt; subsequent clicks cannot repair it.

The quiet fixture/IME image test can add `--mouse-focus-cycles 10` before its
unchanged composition, dialog and intentional-phone-input assertions. It still
requires real focus/InputConnections, fixed native identities and exact original
IME-settings restoration. Pixel/keyboard, multi-monitor redock and shipping-
launcher preserved-data tests must pass against the actual corrected image.

The ABI finding is separate from renderer/flashing defects. It does not establish
Pixel 10 hardware qualification, phone OTA readiness or actual user/SSH X11
frontend acceptance. The emulator remains x86-64 KVM/X11 test infrastructure.

## Rebuild guard

The general container builder now checks the built image before publishing its
requested tag, including the previously unchecked non-promotion path. The
read-only `android/container/x11_bridge_abi.py` inventory requires the SDK bridge
to be byte-identical to the system bridge, matching Debian Xlib/bridge package
versions, and actual Qt XCB plugin dependency resolution to that pair. Missing
dependencies, changed manifest system-library hashes, complete-runtime hashes or
frozen library provenance fail closed. A matching SDK tree alone is insufficient:
its runtime map does not include the container's system Xlib.

The builder records `built-x11-bridge.json` beside its whole-runtime record. It
does not copy/repair libraries, alter qualified runtime bytes or inherit a pass
for a newly rebuilt pair. A changed SDK/base must be built with a matching pair
and independently requalified. The shared native candidate publisher now applies
the same check, covering `build-native-candidate.py`, `build-phase0-local.py`,
`build-phase0-candidate.py` and `build-phase1-conformance-candidate.py`. It checks
the requested tag both before and after library inspection; a conflicting tag
is preserved. This is not a blanket audit of every historical diagnostic recipe.

Run the unit and exact-image controls with:

```sh
python3 -B -m unittest discover -s android/tests -p test_container_bundle.py -v
WONAD_TEST_X11_BRIDGE_IMAGES=1 python3 -B -m unittest discover \
  -s android/tests -p test_x11_bridge_abi.py -v
```

The opt-in controls use the exact delivery image and retained older image
`sha256:599d7180e8cf0f059aba403c282d79e0716454fa3946f83f25130e9d0531fa44`,
whose bridge has the same bad `4fa8d65d…` hash. The direct APK18 parent was pruned;
it is not silently assumed to remain available. Metadata-only child-image tests
exercise the real builder's publish/reject paths and remove only their own
label-checked, parent-layer-identical test images. These controls boot no Android
guest and touch no X11 authorization, phone userdata or running services.
The shared-publisher controls also create/remove unique test aliases for the
retained good/bad images, checking that original references stay unchanged.
They never remove either parent image ID. Historical explicitly unqualified
diagnostic recipes remain available for reproducing their original bad runtime;
their existence must not be mistaken for a newly qualified or selected image.
