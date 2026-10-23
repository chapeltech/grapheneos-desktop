# Pixel 10 ARM64 baseline/custom build comparison

The active device contract is Pixel 10 (`frankel`). The `2026100600` source
pin is unchanged. Earlier vendor-generation records remain historical input
evidence, not a current source freeze, ARM OS build or phone qualification.
The x86-64 emulator lane remains separate and its Pixel 8 AVD profile is not
a physical-device target.

`run_frankel_build.py` and `frankel_build_comparison.py` provide the pinned,
fail-closed build-comparison lane for GrapheneOS release `2026100600` and Pixel
10 (`frankel-cur-user`). This is evidence for reviewing the Phase-1 OS delta.
It is not release signing, an installable factory package, an OTA publication,
or runtime/hardware qualification.

## Fixed contract

The launcher accepts only:

- the signed `2026100600` manifest and all of its exact project revisions;
- the exact local builder image ID
  `sha256:f719a4a56095b613790ef9afcba2aabda795217ac98e08c24ba5cec65bd4ee33`;
- an ordinary host process running as UID/GID `1000:1000`;
- `frankel-cur-user`, build number `2026100600`, build timestamp `1791386354`,
  six normal jobs and one high-memory job, with the complete targets
  `vendorbootimage vendorkernelbootimage target-files-package otatools-package`;
- a named, retained Docker container with no network, no added devices or
  groups, all capabilities dropped, and exactly two writable bind mounts;
- a fresh external `OUT_DIR`, build log, preflight record and container name.

The fixed container bounds are six CPUs, 48 GiB RAM, 48 GiB total memory plus
swap (no additional container swap), and 4,096 PIDs. The launcher observes
resources before the full source audit and again immediately before launch,
after creating the fresh OUT directory. Both observations require at least
42 GiB host `MemAvailable`, 96 GiB available space on the OUT filesystem and
16 GiB on the Docker-root filesystem, and bind the exact directory identities.
The two records and fixed limits are sealed into the preflight. Capture and
receipt verification reject omitted/drifted bounds or an OOM-killed container.
These admission policies are conservative, not measured ARM peak usage or a
guarantee that a full build will fit; failures retain their original evidence.

The image is selected by its immutable ID, not its mutable tag. The container
entry point is `/usr/bin/env -i`, followed by the complete reviewed process
environment. Host/image `OUT_DIR`, `SOONG_NINJA`, Android target, remote-build,
and other build-control variables therefore cannot reach the build process.
The source still uses Android's default relative `out`; `/sources/out` is the
fresh external bind mount.

The capture side independently requires the built-in local Docker context and
the literal `/var/run/docker.sock`, and matches the launch-time daemon/boot
identity, attempt nonce, container labels and exact Docker argv recorded in the
preflight. The retained container must be a non-restarting, non-paused, clean
exit with the exact namespaces, capability/device/tmpfs/restart settings and
exactly two non-duplicated `rprivate` mounts and bind arguments.

Both roles require the generated Pixel 10 vendor tree to match every file,
directory and digest in the pinned GrapheneOS
`vendor/adevtool/vendor-specs/google_devices/frankel.yml`. The generated
`adevtool-version-check.mk` must name the exact signed-manifest adevtool
revision, all adevtool download/module caches must be absent, and the inherited
device config must name `CP3A.261005.005`.

The baseline role allows that vendor tree and no other generated or modified
source. It forbids `external/wonad` and Updater staging. The custom role requires
the exact schema-4 stage, the selected external public Wonad certificate, and
the project-owned HTTPS Updater marker/configuration. No preparation or repair
is performed by the launcher.

## Prepare inputs separately

Use two distinct, dedicated repo checkouts outside this repository. Before the
comparison lane, generate the same Frankel vendor tree in each checkout with
the pinned adevtool and then remove its downloads, `node_modules`, generated
tool code and dependency output. Existing project tooling performs those
steps, but it deliberately remains separate from this launcher:

```sh
WONAD_GRAPHENEOS_RELEASE_SOURCE=/absolute/baseline-source \
  android/platform/release-build.sh prepare-vendor

WONAD_GRAPHENEOS_RELEASE_SOURCE=/absolute/custom-source \
  android/platform/release-build.sh prepare-vendor
```

Stage only the custom checkout:

```sh
python3 android/platform/stage-os.py \
  --source /absolute/custom-source \
  --signer-certificate /absolute/public-wonad-certificate.x509

python3 android/platform/configure-updater.py \
  --source /absolute/custom-source \
  --url https://updates.example.invalid/wonad/
```

Run vendor preparation in the pinned builder with its Node 24/Yarn environment,
not the host's arbitrary Node version. This step compiles fifteen Android host
tools as well as downloading/extracting the factory image. Pinned Soong uses
Siso and chooses Go `NumCPU()+2`; CPU quota alone does not bound that value.
The prepared baseline's separate literal vendor driver uses four validated
CPU-affinity slots, a four-CPU quota, 32-GiB/no-extra-swap memory limit, 2,048-PID
cap and bounded private tmpfs. It refuses a live native/OS/vendor/VM lane.
No vendor/full-OS build should overlap another memory-heavy lane. A successful
Docker create-only profile check is not vendor generation or build evidence.

The URL above is an example; use the reviewed project-owned HTTPS channel. Do
not put private keys in either checkout. The comparison build does not require
or accept GrapheneOS release keys.

## Launch the two builds

Choose paths which do not yet exist. Do not remove the named containers after
the builds; the receipts authenticate their exited configuration.

```sh
python3 android/tools/run_frankel_build.py \
  --role baseline \
  --source /absolute/baseline-source \
  --out /absolute/evidence/frankel-baseline-out \
  --log /absolute/evidence/frankel-baseline.log \
  --container-name wonad-phase1-frankel-baseline-2026100600-001

python3 android/tools/run_frankel_build.py \
  --role custom \
  --source /absolute/custom-source \
  --out /absolute/evidence/frankel-custom-out \
  --log /absolute/evidence/frankel-custom.log \
  --container-name wonad-phase1-frankel-custom-2026100600-001 \
  --certificate /absolute/public-wonad-certificate.x509
```

A failed attempt is never resumed or erased by the launcher. Its output,
partial log, preflight and named container remain diagnostic evidence. Use new
literal paths and a new name for another attempt.

## Capture and authenticate receipts

Each capture prints one lowercase SHA-256. Record it outside the JSON and do
not infer it from a mutable filename.

```sh
python3 android/tools/frankel_build_comparison.py capture \
  --role baseline \
  --source /absolute/baseline-source \
  --out-dir /absolute/evidence/frankel-baseline-out \
  --build-log /absolute/evidence/frankel-baseline.log \
  --container wonad-phase1-frankel-baseline-2026100600-001 \
  --output /absolute/evidence/frankel-baseline-receipt.json

python3 android/tools/frankel_build_comparison.py capture \
  --role custom \
  --source /absolute/custom-source \
  --out-dir /absolute/evidence/frankel-custom-out \
  --build-log /absolute/evidence/frankel-custom.log \
  --container wonad-phase1-frankel-custom-2026100600-001 \
  --certificate /absolute/public-wonad-certificate.x509 \
  --output /absolute/evidence/frankel-custom-receipt.json
```

Receipts bind the authenticated manifest ledger, complete role-owned source
delta, full generated vendor ledger, schema-4/Updater state, Siso/Clang/JDK/
Soong inputs, exact builder and retained container, build log, vendor boot and
vendor-kernel-boot images, target-files archive, build fingerprint, and the
unique Soong `otatools.zip`. They also bind the installed framework,
`services.jar`, SystemUI APK and both Wonad native libraries. The clean
baseline must lack the native libraries; the custom output must introduce them
and must change the reviewed framework/SystemUI artifacts.

Receipt schema 3 also binds the per-project build-visible worktree
representation (authenticated LFS payloads, exact CRLF checkout materializations,
and absent-versus-empty authenticated gitlinks) and a complete tool ledger for the Frankel comparator,
x86 comparison helpers, provenance and release-receipt helpers, Docker locality
proof, launcher and stage verifier. Both receipts, the comparison document and
the verifier require the same current ledger. Artifact references are streamed
rather than materialized in memory; every artifact path component must remain
inside the literal output tree without symlinks. Parseable evidence is read and
hashed through one `O_NOFOLLOW` descriptor and its pathname identity is checked
again afterward.

This is an evidence-format break: schema-1 or schema-2 Frankel
receipts/comparisons and any schema-3 evidence created before a tool changes
cannot be reused. Re-run both
build captures and comparison with the same reviewed tool checkout.

Verify each receipt while its source, output, log and retained container still
exist:

```sh
python3 android/tools/frankel_build_comparison.py verify \
  --receipt /absolute/evidence/frankel-baseline-receipt.json \
  --expected-sha256 BASELINE_SHA256

python3 android/tools/frankel_build_comparison.py verify \
  --receipt /absolute/evidence/frankel-custom-receipt.json \
  --expected-sha256 CUSTOM_SHA256
```

Create and authenticate the delta document:

```sh
python3 android/tools/frankel_build_comparison.py compare \
  --baseline /absolute/evidence/frankel-baseline-receipt.json \
  --baseline-sha256 BASELINE_SHA256 \
  --custom /absolute/evidence/frankel-custom-receipt.json \
  --custom-sha256 CUSTOM_SHA256 \
  --output /absolute/evidence/frankel-baseline-custom-comparison.json

python3 android/tools/frankel_build_comparison.py verify-comparison \
  --comparison /absolute/evidence/frankel-baseline-custom-comparison.json \
  --expected-sha256 COMPARISON_SHA256 \
  --baseline /absolute/evidence/frankel-baseline-receipt.json \
  --baseline-sha256 BASELINE_SHA256 \
  --custom /absolute/evidence/frankel-custom-receipt.json \
  --custom-sha256 CUSTOM_SHA256
```

The comparison requires identical signed-manifest, vendor, builder, toolchain
and build-fingerprint identities; distinct source/output/container attempts;
an absent baseline stage; an exact custom stage; and a changed target-files
archive. It records which other product artifacts are equal or changed instead
of assuming that every image must differ.

## Still external to this lane

The vendor factory and OTA archives must be supplied/generated before launch;
this tooling never downloads them. Production release keys, the prior signed
Frankel release, project update-server credentials/content, monotonic release
number selection, release signing, factory/install/OTA assembly, installation
on a Pixel 10, rollback/update tests and hardware qualification remain separate
Phase-1 gates. Use `release-build.sh` and the release receipt/verifier only
after the unsigned baseline/custom delta has been reviewed.
