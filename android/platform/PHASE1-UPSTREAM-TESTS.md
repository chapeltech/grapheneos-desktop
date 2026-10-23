# Phase 1 matched upstream tests

Phase 1 requires applicable AOSP/GrapheneOS tests to run against both the clean
and Wonad builds from the same source pin. A failure already present in the
clean build may be documented; the Wonad build may not omit a shared case,
add an unreviewed case or produce a worse result. Thirteen explicitly reviewed
Wonad-only WmTests additions are required to pass. These tests supplement, but do not replace, the
exact-image fault matrix or 24-hour runtime qualification.

The frozen plan is
[`phase1-upstream-tests-2026100600.json`](phase1-upstream-tests-2026100600.json).
It names full modules from both pinned source trees:

- `WmTests`;
- `SystemUITests`;
- `WMShellUnitTests`;
- focused input/ATMS WmTests plus `FrameworksInputMethodSystemServerTests`;
- `Launcher3Tests` and `Launcher3QuickStepTests`.
- `InputTests:KeyGestureControllerTests`, including the exact four GrapheneOS
  Secure Paste `gos-postsubmit` cases at the modified shortcut-interception seam.

The four source-declared Secure Paste cases must all pass on the custom side.
Common skipped/failed/error outcomes do not satisfy this required overlap.
Baseline failures may still be documented, including a failure resolved by a
passing custom build; unrelated shared baseline failures retain the broader
no-new-regression policy.

The plan binds the exact `atest` commands, clean environment, source/OUT
locations, minimum case counts, result names, target, build number and emulator
serial. Both source trees contain exactly one definition of every selected
module. Do not narrow a command after observing a failure; change the reviewed
plan and invalidate both sides instead.

## Run each side

Start an emulator containing the exact receipted product as `emulator-5580`.
Run only one candidate at a time. Finish and seal both OS builds first; never
test against the OUT of a running build. Use the dedicated foreground owner
[`run_phase1_upstream_guest.py`](../tools/run_phase1_upstream_guest.py), not the
interactive desktop launcher or a reused AVD. In one terminal, start the clean
guest:

```sh
python3 android/tools/run_phase1_upstream_guest.py \
  --role baseline \
  --build-receipt /absolute/evidence/x86-baseline.json \
  --build-receipt-sha256 BASELINE_RECEIPT_SHA256 \
  --state /absolute/new/private/upstream-baseline-state \
  --output /absolute/new/evidence/upstream-baseline-guest
```

Both directory paths must be absent, have existing parents, and be outside the
Wonad repository and both protected source/build trees. The owner creates
private fresh userdata and mounts only the exact product read-only, without
relabeling it. It authenticates the build, source freeze and retained OUT before
and after owning the guest. It uses the fixed immutable runtime image
`sha256:3804c2d3125e5ce57e9597cefc7d496b2aca7c6c02081b6858e50f9c7ef82822`,
KVM, an eight-CPU/eight-GiB container, and a private headless X server. Host
networking is intentional for the test runner's private source-pinned ADB;
only loopback console/ADB listeners on ports 5580/5581 are permitted. gRPC,
netsim listeners and X-server TCP are disabled. It installs no APKs and does
not alter settings, enable consent or create external displays.

Wait for `Authenticated fresh guest is ready as emulator-5580.` and the
owner's `READY.json` before running Atest in a second terminal. Keep the owner
running for the complete test run. Its private boot-check ADB server has stopped
by this point; the Atest runner starts its own private server. The runner refuses to begin until the guest is
fully booted, SELinux is Enforcing, the fingerprint is exact, every present
privileged artifact hashes to its build receipt and every receipted-absent
artifact is absent. It uses the source-pinned `prebuilts/runtime/adb`, not an
ambient SDK.

Each suite runs in a separate container using the exact receipted builder image
ID. The pinned source is mounted read-only; the receipted build OUT is never
mounted. A fresh disposable test OUT is the sole writable host bind. Containers
have no network, a read-only root filesystem, no capabilities and
`no-new-privileges`. Device access uses a private, source-pinned ADB server via a
read-only Unix-socket bind. The runner fully reauthenticates the source freeze,
receipted build and complete currently retained OUT inventory before and after
testing. Removed intermediates do not need to be rebuilt merely because the OS
receipt was safely pruned.

Writable binds use Docker's explicit `readonly=false` field. The first real
host attempt exposed and preserved a rejected bare `rw` field before any Go
test executed; repaired argv was subsequently checked against real Docker in
the pinned builder profile. A CLI/Go-version diagnostic is not native test
coverage and cannot be supplied to the comparison as a passing run.

For the clean build:

```sh
python3 android/tools/run_phase1_upstream_tests.py run \
  --role baseline \
  --build-receipt /absolute/evidence/x86-baseline.json \
  --build-receipt-sha256 BASELINE_RECEIPT_SHA256 \
  --plan "$PWD/android/platform/phase1-upstream-tests-2026100600.json" \
  --test-out /absolute/new/disposable/atest-baseline \
  --output /absolute/new/evidence/upstream-baseline
```

After the baseline runner finishes, use Ctrl-C in the guest-owner terminal.
Wait for its final receipt path and digest; it stops only its exact owned
container and retains the stopped container, userdata and diagnostics. Its
`session.json` is guest ownership/boot evidence, not a test result. Do not
reuse that state for the custom side. In the first terminal, start:

```sh
python3 android/tools/run_phase1_upstream_guest.py \
  --role custom \
  --build-receipt /absolute/evidence/x86-custom.json \
  --build-receipt-sha256 CUSTOM_RECEIPT_SHA256 \
  --state /absolute/new/private/upstream-custom-state \
  --output /absolute/new/evidence/upstream-custom-guest
```

Wait for the new guest's `READY.json`, then run in the second terminal:

```sh
python3 android/tools/run_phase1_upstream_tests.py run \
  --role custom \
  --build-receipt /absolute/evidence/x86-custom.json \
  --build-receipt-sha256 CUSTOM_RECEIPT_SHA256 \
  --plan "$PWD/android/platform/phase1-upstream-tests-2026100600.json" \
  --test-out /absolute/new/disposable/atest-custom \
  --output /absolute/new/evidence/upstream-custom
```

Stop the custom owner with Ctrl-C only after its test runner finishes, and
retain its printed session digest separately. If boot, listener validation,
input authentication or tests fail, preserve that attempt and use new state,
test-OUT and evidence paths for a retry rather than overwriting it.

The disposable directory must not exist, and must be outside the source,
receipted build OUT and evidence directories; its parent must already exist.
Each output retains the exact command/container records, stdout, native Atest
case ledger, pre/post device and protected-input records, and cleanup proof in
a portable schema-2 bundle. A timeout or cleanup failure leaves diagnostics but
cannot create a qualifying receipt. The two SHA-256 values printed by the runners are out-of-band receipt
authenticators and must be retained separately.

## Compare

After the x86 build comparison itself verifies, create the matched test result:

```sh
python3 android/tools/phase1_upstream_test_comparison.py compare \
  --baseline /absolute/new/evidence/upstream-baseline/run-receipt.json \
  --baseline-sha256 BASELINE_TEST_RECEIPT_SHA256 \
  --custom /absolute/new/evidence/upstream-custom/run-receipt.json \
  --custom-sha256 CUSTOM_TEST_RECEIPT_SHA256 \
  --build-comparison /absolute/evidence/x86-comparison.json \
  --build-comparison-sha256 BUILD_COMPARISON_SHA256 \
  --output /absolute/new/evidence/upstream-comparison.json
```

The comparator accepts only schema-2 isolated-run bundles and replays their
container, raw-results, toolchain, device and cleanup proof. It fully rehashes
both live build receipts and verifies their exact build comparison. It requires
identical source pins, plan bytes, builder/toolchain/device-class identities,
suite sets and shared case identities, with distinct baseline/custom guest
boots. The custom case set must equal the baseline set plus the exact thirteen
reviewed WmTests additions in `phase1_upstream_test_comparison.py`. Those are
bound to the staged `wonad-focused-display-tests.patch` and
`wonad-display-settings-lifetime.patch` hashes and must all pass; missing,
skipped or unreviewed additions fail. It
records common and resolved baseline failures and refuses every new or worsened
custom result (`passed` < `skipped` < `failure` < `error`). Verify the retained
comparison offline with `verify-comparison` and the same explicit inputs and
out-of-band digests.

The historical `capture` action only archives schema-1 results. Neither those
captures nor hand-written command/device records qualify a current release.

The final aggregate Phase 1 release index replays and binds this exact plan,
both run receipts, this comparison, and the x86 baseline/custom build receipts.
It additionally requires the repository-reviewed generic native-evidence plan
[`phase1-generic-upstream-plan-2026100600.json`](phase1-generic-upstream-plan-2026100600.json).
AOSP-host results must come from the fixed source-pinned Soong/Blueprint Go
invocations, reconstructed from native `go test -json` events and sealed
isolated-container evidence. AOSP-emulator coverage replays the schema-2
Atest bundle, exact source/build bindings and reviewed additions. Arbitrary
commands, hand-written JUnit envelopes, prose logs and operator failure lists
cannot qualify either class.

The pinned-source audit found no source-declared applicable GrapheneOS-specific
host module for these seams. That coverage class needs authenticated bounded
source-applicability evidence, not a passing test or an unrelated allocator
suite. The producer
[`phase1_grapheneos_host_applicability.py`](../tools/phase1_grapheneos_host_applicability.py)
and its
[reviewed definition](phase1-grapheneos-host-applicability-2026100600.json)
retain exact mapping/module inventories and scope limits. Native read-only
source scans match the baseline and custom trees (2,096 mappings, four GOS
mappings, 1,224 Blueprint files, 4,530 modules and 128 host-capable modules).
Those scans and fifteen host tests are not qualifying build-bound receipts;
each side still needs the producer's complete live build/source/toolchain
verification. Its result is explicitly `not_applicable_source_declared`, with
no test cases or pass claim. The actual relevant
GrapheneOS Secure Paste checks are device-only (`KeyGestureControllerTests` is
disabled on Ravenwood) and are mandatory in the sixth emulator suite above.
Neither an applicability audit nor the six-suite comparison replaces AOSP-host
execution. Until the complete matched native evidence verifies, the upstream
Phase 1 checkbox remains open.

The AOSP-host producer is `phase1_generic_upstream_evidence.py run-aosp-host`.
It runs all ten reviewed normal/race Go invocations in separate read-only,
network-disabled containers, capped at four CPUs/48 GiB with `GOMAXPROCS=4`,
`GOMEMLIMIT=40GiB` and `-p=1` package serialization. The normal invocations
still run the complete suites (including the large in-memory Zip64 tests);
only the upstream race invocations use their existing `-short` flag. The
reviewed generic-plan SHA-256 is
`ba5c43e1bc2a2239aaf4677d483bb9d7eb3c62e0b9a6f94924a06bf503a1c386`.
Production startup and the Soong invocation require at least 44 GiB available
host RAM. Do not crowd a live OS build with this lane or narrow test scope to
fit a smaller memory limit.
Each invocation must report actual native test cases; package-only success or
compilation failure does not establish test execution. The disposable test OUT
must be a new path outside the source, receipted OUT and Wonad repository.
The output is a portable `host-run-receipt.json` bundle, not a manually imported
JUnit report.

The second native baseline attempt in
`/u/elric/tree/wonad-phase1-upstream-native-20261011-r2.Y83jCJ` passed 2,605
Blueprint cases in each of its normal/race invocations, then failed during
Soong's two full Zip64 tests under the previous 8-GiB profile. The original
streams, sealed inputs and authenticated workspace cleanup remain beside
`ATTEMPT-FAILED.md`. The complete native run did not qualify, and the corrected
memory profile has not yet completed a real retry. Later invocation failures
now preserve original container inspect data before removing only that owned
container. All 33 generic-evidence host tests pass; this is producer/parser
evidence, not a replacement for the pending baseline/custom native pair.
