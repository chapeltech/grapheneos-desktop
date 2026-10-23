# Phase 1 Frankel ARM baseline readiness review — 2026-10-12

## Scope and result

This is a bounded, read-only review of the next Pixel 10 (`frankel`) ARM64
baseline build. It did not run vendor generation, source cleanup, Docker, an
ARM build, an emulator, signing, or the 11,378,664,978-byte archive hash.

The reviewed vendor handoff and direct comparison-build launcher are
compatible: after a successful generation-6 vendor run, the existing ARM
launcher independently authenticates the complete generated vendor tree and
the clean baseline worktree. The build is **not ready to launch yet** because
vendor generation remains held and `vendor/google_devices/frankel` is still
absent. Current memory is also only marginally above the ARM launch floor.

Reviewed identities:

- `android/tools/run_frankel_build.py`:
  `7ff1350466d813b3dd6cc9f597131a3240025ff965ca4cb2f768f0564a838be1`
- `android/tools/frankel_build_comparison.py`:
  `6b963fa8d2c888a3972891e235685043d1564cb73ff91e9064a1e8ae44174cbe`
- `android/tests/test_frankel_build_tools.py`:
  `aa859609b8f36694c76be2067afa785a57b5dcaa668733f3ef9f3359170d587f`
- `android/tools/run_frankel_vendor.py`:
  `35b2b23b94e9c29a87b21a87c3ff3f5a8bfb003ac797efc2040c524932ff55fc`
- `android/platform/generate-frankel-vendor.sh`:
  `eb8155555900e68e3e53714d0ca40c5bbe55ad5fe6abea1c9d97393fda19b854`
- `android/platform/release-build.sh`:
  `756561b653494734861442cc0f05a57775ce36d2d13e96ab98b6de71ebf8c47c`
- generation-6 admission owner record:
  `5da5c07fe4ad745be2a24325890677f59a4c88f76eb4dd5eb6475cb4007837d6`
- `android/platform/FRANKEL-BUILD-COMPARISON.md`:
  `0a7f2e23aa8687cdc094064d4ee13c1c136fc1dff5366cdbd5d87b9f2871b181`
- `android/platform/PHASE1-PROVENANCE.md`:
  `99c82527b283f2e5982ba41e05d408f4c8cf375ff6e85357467e63b75f942d66`

## Current source and topology

The only dedicated Frankel checkout observed was:

`/u/elric/tree/wonad-grapheneos-2026100600-frankel-baseline-1`

Its source, `.repo`, `out`, and `vendor/adevtool` directory identities were
observed as device `64513`, owned by UID/GID `1000:1000`; `out/` was empty.
The adevtool HEAD was
`17df3b79a73e67ad68387b35c7d41c85e1d8103c`. The generated vendor tree,
Wonad/Updater staging, key/private roots and every reviewed adevtool cache were
absent; `vendor/adevtool/dl` contained only `.find-ignore`.

Generation 6 deliberately has separate roles:

- the pristine checkout is the mutable `/grapheneos` bind where adevtool will
  create `vendor/google_devices/frankel`;
- the Wonad repository is a read-only `/wonad` bind supplying the authenticated
  generator;
- the external generation-6 work directory is `/adevtool-images` and receives
  the factory archive through FICLONE only;
- host-pinned provenance code performs cache cleanup before and after the
  immutable Node 24.21.0/Yarn 1.22.19 builder action.

The generation-6 work directory is **not** an Android `OUT_DIR`. The later ARM
launcher instead mounts the prepared source at `/sources` and one fresh
external output at `/sources/out`; Android uses its normal relative `out`
path through that mount. Both binds are writable, the build has no network,
and its named container is retained.

## Required vendor handoff and freeze

Only after separate root authorization and after all competing VM/build lanes
are terminal, generation uses the already reviewed command:

```sh
/usr/bin/bash \
  /u/elric/tree/wonad-phase1-build-evidence/prepare-phase1-frankel-vendor-cache-20261012-6.sh \
  --run
```

Before an ARM launch, the retained generation evidence must show all of the
following without repair or retry:

1. result status `generated`, builder exit 0, exact owned container proven
   stopped and not OOM-killed, and both host cleanups successful;
2. unchanged source/root/`.repo`/`out`/`vendor/adevtool` identities and exact
   attempt-lock binding;
3. authenticated cache receipt, FICLONE-only work record, preflight, log,
   result and retained container identity, each with an out-of-band digest;
4. all regenerable adevtool caches absent and source `out/` still empty;
5. no Wonad stage, Updater marker or key/private root in the baseline source.

The generation result's small required-file check is handoff evidence, not the
full source freeze. The pinned Frankel specification currently contains 6,448
file digests and 1,237 directories; the build audit additionally requires the
ordinary `adevtool-version-check.mk`, for 6,449 exact generated files. The ARM
launcher/comparator rewalks and hashes that full inventory, checks the build ID
`CP3A.261005.005`, checks the exact adevtool revision guard, and refuses every
extra/missing path.

The source snapshot which must be sealed into the build preflight and later
receipt also includes the authenticated manifest and complete project ledger,
all project HEAD/tracked states, repo-tool identity, build-visible Git
materializations, toolchain inputs, and the complete generated-input ledger.
For the baseline, tracked changes must be empty and staging must be exactly
absent. Do not `git add` or commit the generated vendor files: the baseline
contract expects them as the sole role-owned generated inputs.

## Exact next baseline commands

The following proposed output names are currently absent. They are not
reserved; the launcher must still independently prove every path and container
name fresh immediately before launch.

After the vendor result above is independently accepted and after a fresh
resource/process admission:

```sh
cd /u/elric/tree/wonad
/usr/bin/python3 -B android/tools/run_frankel_build.py \
  --role baseline \
  --source /u/elric/tree/wonad-grapheneos-2026100600-frankel-baseline-1 \
  --out /u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-baseline-out-20261012-1 \
  --log /u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-baseline-build-20261012-1.log \
  --container-name wonad-phase1-frankel-baseline-2026100600-001
```

This fixed command builds the complete reviewed target set:
`vendorbootimage vendorkernelbootimage target-files-package
otatools-package`, using `frankel-cur-user`, `-j6`, high-memory pool 1,
build number `2026100600`, and timestamp `1791386354`. A nonzero exit or lost
supervision must retain the output, log, preflight and named container; do not
resume or erase it.

After an exit-0 build and its built-in artifact/Siso checks, capture and verify
the baseline receipt while source, output, log and retained container remain:

```sh
/usr/bin/python3 -B android/tools/frankel_build_comparison.py capture \
  --role baseline \
  --source /u/elric/tree/wonad-grapheneos-2026100600-frankel-baseline-1 \
  --out-dir /u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-baseline-out-20261012-1 \
  --build-log /u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-baseline-build-20261012-1.log \
  --container wonad-phase1-frankel-baseline-2026100600-001 \
  --output /u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-baseline-receipt-20261012-1.json

/usr/bin/python3 -B android/tools/frankel_build_comparison.py verify \
  --receipt /u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-baseline-receipt-20261012-1.json \
  --expected-sha256 ACTUAL_OUT_OF_BAND_BASELINE_RECEIPT_SHA256
```

The custom build cannot yet be scheduled: no second dedicated Frankel checkout
was observed. It needs a distinct same-pin checkout, the identical vendor
identity, exact schema-4 Wonad/Updater stage and public development
certificate, a distinct output/log/container, then the same receipt capture.
Only after both authenticated receipts exist should the existing `compare` and
`verify-comparison` commands produce the matched ARM delta.

## Resource readiness

The ARM launcher fixes 6 CPUs, 48 GiB memory, 48 GiB memory-plus-swap (no
additional container swap), and 4,096 PIDs. It observes resources before its
full source audit and again immediately before Docker launch. Both observations
require 42 GiB `MemAvailable`, 96 GiB free on the output filesystem, and 16 GiB
free on the Docker-root filesystem. These are admission floors, not a disk
reservation or measured ARM peak.

The bounded observation made during this review was:

| resource | observed | floor | headroom |
|---|---:|---:|---:|
| host `MemAvailable` | 42.066 GiB | 42 GiB | 0.066 GiB |
| `/u` (source/output filesystem) | 112.787 GiB | 96 GiB | 16.787 GiB |
| `/var` (Docker-root filesystem) | 74.986 GiB | 16 GiB | 58.986 GiB |

Memory therefore had only 70,598,656 bytes of admission headroom. No ARM build
should start with another VM, compiler, vendor, matrix or packaging lane live,
even if a transient sample barely passes. Vendor generation will retain an
11.38-GB logical reflink and create the generated proprietary tree on `/u`;
its actual allocated expansion is not known before the first real run. Recheck
all floors after generation. If `/u` drops below 96 GiB, the ARM launcher must
refuse rather than reclaiming historical evidence or weakening the floor.
Even a passing 96-GiB launch observation does not prove the first unmeasured
ARM build will fit.

## Public release workflow integration

The direct comparison launcher integrates cleanly with generation 6 because it
trusts no summary boolean: it authenticates the resulting vendor bytes and
source state itself.

The current public `release-build.sh prepare-vendor` branch does **not** embody
the repaired host/builder boundary. It runs whichever host `yarnpkg`/`yarn` is
found and invokes adevtool on the host. It must not be used for this baseline
or cited as generation-6 evidence. The nearby comparison documentation which
still shows that command is stale with respect to the repaired path.

Minimal future integration is:

1. make the public `prepare-vendor` action delegate to the reusable
   `run_frankel_vendor.py` contract through explicit cache receipt/archive,
   fresh work/log/preflight/result/container and expected-digest inputs;
2. keep `clean_vendor_cache` host-side before/after and keep only frozen
   Node/Yarn/adevtool generation in the immutable builder;
3. add an independent verifier for the retained vendor result/container, or
   bind its authenticated digest into later source/build evidence; do not
   weaken the existing full source rehash;
4. update the stale preparation documentation only after that public entry
   point has the same fail-closed lifecycle and exclusivity controls as G6.

`release-build.sh build` is not the baseline comparator: it stages Wonad and
Updater and enters the separate production build/evidence chain. It can consume
a correctly generated custom source later, but production signing still
requires a reviewed monotonic build number, project-owned update URL, frozen
clients/SDK, external GrapheneOS release keys, swap policy, target-files and
otatools evidence, signed factory/full OTA assembly, offline public-key
verification, installation/update/rollback tests and Pixel 10 hardware
qualification. None of those requirements is waived or satisfied here.
