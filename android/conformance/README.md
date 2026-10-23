# Wonad OS v3 conformance APK

This module is the Phase-1 policy-free client for the frozen desktop API. It
uses the authenticated package name `org.wonad.desktop`, so it **replaces** the
product Wonad APK during a run. It does not co-install with it. It links only
`:desktop-sdk`; there is no Haskell policy, JNI library, hidden API, platform
permission request, network/storage channel, or product source-set dependency.

The APK provides the three fixed, caller-guarded OS facades:

* `.ExternalHomeActivity` — exact `SECONDARY_HOME`, external-display-only;
* `.ExternalShellActivity` — validates the frozen
  `org.wonad.desktop.shell.GENERATION` and
  `org.wonad.desktop.shell.DISPLAY_TOKEN` extras and document URI; and
* `.LauncherActivity` — validates the frozen `catalog` and `generation` extras.

All three are exported with `android.permission.STATUS_BAR_SERVICE` as the
caller guard. The APK does not request or receive that permission. Invalid,
phone-display, stale, and mismatched facade launches finish without drawing.

## Build and sign

```sh
gradle --no-daemon -p android \
  :conformance:testDebugUnitTest :conformance:lintDebug \
  :conformance:assembleRelease
```

`assembleRelease` intentionally emits an unsigned APK. Sign it outside this
tree with the **same frozen Wonad release certificate whose SHA-256 is pinned in
the candidate OS**. No debug/test key is a substitute, and the build has no
debug-key fallback. The fixture APK is a different package and is built and
signed separately:

```sh
gradle --no-daemon -p android :fixture:assembleDebug
```

## Full scripted run

Prerequisites are an unlocked candidate OS, explicit user consent already
enabled, one live secure external display, the correctly release-signed
conformance APK, and the ordinary fixture APK. The driver never grants consent,
unlocks the phone, changes a signer, or uses a hidden API.

```sh
python3 android/tools/conformance_smoke.py \
  --serial emulator-5580 \
  --display-id 3 \
  --apk /path/to/signed-wonad-conformance.apk \
  --fixture-apk android/fixture/build/outputs/apk/debug/fixture-debug.apk
```

Omit `--apk` after a same-signer update has already installed the target. The
driver launches two ordinary fixture tasks, starts the fixed `full` script,
focuses one external task and sends one real Ctrl+Meta+J shortcut, then cancels
the trusted phone transfer picker with Escape.

If keyboard focus is still on the external display, use `--focus-phone-picker`
to model a deliberate mouse click on the authenticated phone dialog's title.
This opt-in action checks the actual SystemUI UID, secure/drawn phone window,
stable window token and in-bounds geometry. The unchanged cancellation guard
still requires the exact dialog to own genuine phone keyboard focus before
sending the sole Escape. It never uses a WindowManager focus command.

The script negotiates `getApiVersion` and `getCapabilities`, calls `openSession`
and every `IDesktopSession` operation, observes all four callback types, and
requires every published v3 capability. Contained and signed frames merely copy
the broker's current observation; there is no workspace/layout policy. It
focuses one fixture and closes the other, paginates and cancels the APK launcher,
cancels the system transfer picker, disables shortcuts, and explicitly releases
the lease.

The host starts a self-targeting `.ConformanceInstrumentation` declared inside
the same signed APK. The phone control Activity and status service are both
unexported: an ordinary third-party app cannot trigger the authenticated client
as a deputy. The canonical, bounded status channel is:

```sh
adb shell dumpsys activity service org.wonad.desktop/.ConformanceService
```

It prints one `WONAD_CONFORMANCE_STATUS {json}` line containing the run nonce,
phase, negotiated API/capabilities, display IDs, unique operation coverage,
callback counts, facade validations, and terminal failure/pass state. Logcat,
screen appearance, or the phone control Activity alone are not a pass result.
Full-mode instrumentation retains its terminal service state for two seconds
before `finish()` force-stops the instrumented APK. The host still requires the
actual terminal service dump and successful instrumentation completion; the
instrumentation result is not a substitute for the dump.

## Bounded Phase-0 supervised-image check

The tested, separate API-only image is `wonad:phase0-api-test-20261019-2`, ID
`sha256:d75782298a695d9c9503f8e66636b1253eca7da33abe6c0e8d9b24f193b59ee1`.
It inherits the product image's seven OS artifacts, SDK and emulator unchanged;
only the ordinary policy-free client is selected, with a separately signed
ordinary fixture. It does **not** replace `wonad-emulator` or the Norse phone.
Never install its version-1 client over an existing product APK14.

On xiombarg, with Docker, native x86-64 KVM and the exact image available:

```sh
api_test_parent=$(mktemp -d /tmp/wonad-api-check.XXXXXXXX)
python3 -B android/tools/run_phase0_api_test.py \
  --image sha256:d75782298a695d9c9503f8e66636b1253eca7da33abe6c0e8d9b24f193b59ee1 \
  --output "$api_test_parent/run"
```

The harness owns a private authenticated Xvfb, fresh userdata and one bounded
KVM guest. It taps the real OS consent button, verifies distinct ordinary APK
UIDs, runs every frozen operation/callback/capability and all three facades,
and compares OS bytes, SELinux, boot ID and protected process PIDs before/after.
It stops/removes only its fenced container and retains private test evidence.
No user X11 connection, Baldr state, production credential, privileged fault APK
or consent-setting seed is used. Transfer cancellation includes explicit phone
pointer focus; shortcut injection here is Android input, not a Qt/XTEST test.
The independent product-image GUI test covers the real X11 frontend.

[Retained passing evidence](../out/phase0-api-conformance-20261019-1/result.json)
records all 16 operations, four callbacks and capability mask 2024. This bounded
coverage passed in two independent fresh boots. A
[further bounded run](../out/phase0-api-conformance-20261019-3/result.json)
also verifies one complete 1920×1080 black frame from the actual emulator X11
window after explicit release/onRevoked, retaining losslessly compressed raw
readback. Android secure-screenshot redaction is not used as that proof.
Any such finite observation is not a failure/lock/hotplug campaign. This
run is not Phase-1 clean-boot/soak/fault qualification or physical Pixel 10
qualification. The original strict Phase-1 builders and auditors are unchanged.

## Fresh-guest candidate lane

Do not install this version-1 APK over product Wonad version 12.  The integrated
Phase-1 lane instead derives a **separate, explicitly unqualified** image from
an immutable product candidate.  Its current filesystem whiteouts
`/opt/wonad/wonad.apk` and bundles the same-signed conformance APK.  A new empty
userdata directory therefore receives an ordinary first install: no downgrade,
uninstall, data clear, or consent-setting write is used.

The client packet's APK verifier must come from an immutable image that really
contains the receipted SDK, Gradle, JDK and offline dependency bytes.  A
long-lived container ID is not a substitute: its writable layer is not present
when an image-only verifier starts.  Freeze the already authenticated
development tool bytes through the explicit Dockerfile/context builder, then
build a fresh packet in disposable networkless containers:

```sh
# This older packet is the authenticated bootstrap receipt whose exact
# SDK/JDK/Gradle inputs were frozen into the new immutable tools image.
OLD_PACKET=android/out/phase1-emulator-client-packet-20261010-7
OLD_PACKET_SHA=fdcab19a332fa02fc1fe3e58406039cbf480964ccfebd4ffc25bb0e5fc0e988f

python3 android/container/build-phase1-client-tools.py \
  --source-container 51db87997ccb6b27fb5932a88b1187a748dd1908afdc32940f542a879f6b3aae \
  --packet-receipt "$OLD_PACKET/receipt.json" \
  --expected-receipt-sha256 "$OLD_PACKET_SHA" \
  --output android/out/phase1-client-tools-image-20261011-3 \
  --tag wonad:phase1-client-tools-20261011-3

TOOLS_IMAGE=sha256:f7ad3758f4913b44b320c252dfb1a6590aa34f6252a671b0db56fda3263889e1
TOOLS_MANIFEST_SHA=3ac8bdf7330f8c0b9d8dbedfc97d9b58d9eaa295a2c91d9ad18f9fbcfa2b1dd6
test "$(cat android/out/phase1-client-tools-image-20261011-3/built-image.id)" = "$TOOLS_IMAGE"
python3 android/tools/phase1_emulator_client_packet.py build \
  --successor android/out/native-current-successor-12-phase1-v3-20261010-14 \
  --output android/out/phase1-emulator-client-packet-20261011-2 \
  --tools-image "$TOOLS_IMAGE" \
  --tools-image-manifest android/out/phase1-client-tools-image-20261011-3/manifest.json \
  --tools-image-manifest-sha256 "$TOOLS_MANIFEST_SHA"

python3 android/tools/phase1_emulator_client_packet.py verify \
  --packet android/out/phase1-emulator-client-packet-20261011-2 \
  --expected-receipt-sha256 868f8eaa89ad052f2d21bd3e9e50e25f24ac0623bbc698fac4bacf41c111ac05
```

The tools-image builder copies no Wonad or platform private key.  It inventories
every selected byte before and after copying, admits only the ordinary fixture
debug keystore, builds with networking disabled, proves exact parent-layer
ancestry, and reopens the resulting image to check every receipt-required file.
The packet builder records the image-build manifest, uses one disposable
networkless container, consumes it after the build, and independently repeats
live verification in a second disposable container.

After the source-matched custom product and strict product candidate exist, run
the following with literal paths and immutable image IDs:

```sh
PRODUCT=/absolute/path/to/custom/out/target/product/emu64x
PRODUCT_IMAGE=sha256:... # output of build-native-candidate.py strict Phase-1 mode
PACKET=/absolute/path/to/the/sealed/phase1-emulator-client-packet
# Paste the separately retained 64-hex digest printed when that exact packet
# was created. Never derive the expected identity from the receipt being
# verified, and do not substitute a historical numbered packet from a prior
# source freeze.
PACKET_RECEIPT_SHA256=...

python3 android/container/build-phase1-conformance-candidate.py \
  --product "$PRODUCT" \
  --packet "$PACKET" \
  --expected-receipt-sha256 "$PACKET_RECEIPT_SHA256" \
  --base-image "$PRODUCT_IMAGE" \
  --output android/out/phase1-fresh-conformance-candidate-1 \
  --tag wonad:phase1-conformance-candidate-1

CONFORMANCE_IMAGE=$(cat android/out/phase1-fresh-conformance-candidate-1/built-image.id)
python3 android/tools/phase1_conformance_guest.py \
  --image "$CONFORMANCE_IMAGE" \
  --product "$PRODUCT" \
  --packet "$PACKET" \
  --expected-receipt-sha256 "$PACKET_RECEIPT_SHA256" \
  --output android/out/phase1-fresh-conformance-run-1

python3 android/tools/phase1_conformance_acceptance.py \
  --report android/out/phase1-fresh-conformance-run-1/report.json \
  --product "$PRODUCT" \
  --packet "$PACKET" \
  --expected-receipt-sha256 "$PACKET_RECEIPT_SHA256"
```

The runtime producer requires native amd64 Linux, Docker and `/dev/kvm`.  It
boots one newly created state volume, proves the three target packages were
absent, installs only conformance and the ordinary fixture, and taps the real
SystemUI consent control.  It records protected phone-process epochs before
external-display attachment and requires them to survive attachment, installs,
consent and conformance.  The independent auditor reconstructs those epochs
from raw `pidof` and `/proc` observations, reopens the UI/package/conformance
evidence, and revalidates the exact custom product, image, packet and signers.

The platform-signed fault APK is deliberately not installed or executed by
this positive lane.  Its exact bytes and signer are bound to the packet and
independently compared with the actual custom SystemUI signer; completion-
timeout/fault-injection qualification remains a separate runtime gate.  Neither
building this image nor passing this lane is a product/runtime/physical-device release
qualification.

## Long-lived runtime and planned callback recovery

The separate `runtime` instrumentation mode holds a policy-free lease for the
clean-boot and soak drivers. Its nonce-gated host instructions can checkpoint or
copy/replay the exact observed placements; they do not choose a product layout.
Complete one-shot API coverage remains the distinct `full` mode.

The TEST client can arm one exact next `onRevoked` callback for `LOCKED=3`,
`USER_CHANGED=4` or `CLIENT_FAILED=5`. The last reason is needed when a deliberately
frozen client resumes after its heartbeat lease expires. The expectation binds
the original generation, identity epoch and a one-shot host nonce, expires after
120 seconds, and requires an explicit subsequent reopen command after the
prerequisites have actually been restored. Wrong, unarmed, expired, stale and
replayed callbacks still fail. A heartbeat exception or Binder death is not an
actual revocation callback and does not satisfy this expectation.

When an exact host-armed callback follows `remember-observed`, the runner can
retain that descriptive layout for a single explicit `restore-observed` after
successful authorized reopening. The fresh lease is bound before readiness is
published. Task and display tokens from the former lease are never submitted:
recovery requires an unambiguous exact package/title/constraint match in the
new snapshot and the same connector hints, geometry and density. It copies only
the saved rectangles, visibility/input and z-order onto fresh observed tokens.
Descriptor equality does **not** prove task identity; the host must separately
audit actual Android task/activity/process lifetimes. Changed, missing or
ambiguous descriptions fail instead of selecting a replacement. Generation and
identity-epoch values are not inferred counters. A successful applied/ready
restore consumes the plan; unexpected revocation, ordinary final undock and
terminal close discard it. The original same-lease hotplug replay still rejects
generation/epoch changes and requires a newer topology.

Heartbeat schedulers capture their exact lease owner, generation, sequence and
error slot. Retirement fences publication before the unchanged bounded shutdown
wait; a delayed retired call cannot publish a replacement lease's error or
heartbeat count. Executor/transport models are not evidence of an Android stall.

This adds no SDK method, OS permission or production recovery policy. Source
tests are not proof of Android expiry, black/input shields, process continuity
or a completed soak. Packet 12 contains only the older reason-3/4 helper; use a
freshly compiled and signed source-matched packet for reason 5, never relabel or
waive the old packet's source mismatch. Packet 12 also lacks this separate
cross-lease descriptive recovery; its old same-lease restore cannot qualify a
lock/user-switch recovery action. The SystemUI-death recovery path and
complete nine-action/24-hour campaign remain separate unfinished work.
