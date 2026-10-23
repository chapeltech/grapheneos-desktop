# Phase 1 immutable build provenance

Phase 1 uses three immutable input/freeze records. They are intentionally not
collapsed into one self-asserted JSON file:

1. a builder record binds the reviewed container image and execution config;
2. a pre-build source record binds every signed-manifest project plus every
   permitted generated or modified source byte;
3. a client record binds the frozen SDK publication and release-signed
   conformance APK to its fresh compile receipt.

`android/tools/phase1_provenance.py` creates and re-verifies these records. A
production ARM build adds three execution records made and checked by
`android/tools/run_release_build.py`: a live bind proof, a successful execution
record and a container-consumption record. A signed release carries those
records, the exact container build log and all other public evidence beneath
`wonad-provenance/`. The current pre-build source-record format is schema 5;
the client record is schema 3, the builder record is schema 1, and each build
execution record is schema 1. The distinct release receipt is schema 4: it
hashes every bundled evidence byte and names `production` as the selected
target. These schema numbers describe separate records and are not
interchangeable. The authenticated release-receipt SHA-256 remains the
out-of-band trust anchor.

After the independent build, release, client and runtime producers finish,
[the aggregate release index](PHASE1-RELEASE-INDEX.md) replays their semantic
verifiers and cross-binds all Phase 1 exit evidence. It does not replace these
three records or the signed release receipt. Its authenticated SHA-256 becomes
the final single out-of-band anchor for the complete Phase 1 publication; a
hash-only or self-asserted producer record cannot satisfy it.

The aggregate also requires the public protected-key ceremony and structured
custody observations, concrete private candidate-channel ownership and
publication controls, and the exact
[installation/update/recovery runbook](PHASE1-INSTALL-UPDATE-RECOVERY.md).
Those operational records are inputs to the final review, not conclusions
inferred from artifact hashes.

## Builder record

The GrapheneOS lock pins the image digest, platform, Dockerfile digest and the
Node/yarn versions needed by `adevtool`. Capture the local image by its locked
name (or exact digest):

```sh
python3 android/tools/phase1_provenance.py capture-builder \
  --image wonad-grapheneos-builder:2026100600 \
  --output /safe/evidence/phase1-builder.json

python3 android/tools/phase1_provenance.py verify-builder \
  --record /safe/evidence/phase1-builder.json
```

Capture inspects the complete immutable image ID, rootfs layer chain and
runtime config. It runs a network-disabled, read-only version probe. It does
not inspect the environment of an unrelated running container.

## Pre-build source record

Run this after vendor generation, Wonad staging and Updater configuration, and
immediately before compiling:

```sh
python3 android/tools/phase1_provenance.py create-source \
  --source /sources/grapheneos-2026100600 \
  --builder-record /safe/evidence/phase1-builder.json \
  --output /safe/evidence/phase1-source.json \
  --jobs 32

python3 android/tools/phase1_provenance.py verify-source \
  --source /sources/grapheneos-2026100600 \
  --builder-record /safe/evidence/phase1-builder.json \
  --record /safe/evidence/phase1-source.json \
  --jobs 32
```

`release-build.sh build` performs this capture itself when
`WONAD_BUILDER_PROVENANCE` and a new external `WONAD_SOURCE_PROVENANCE` path
are supplied. It verifies the record again immediately before launching the
authenticated container, re-verifies it after compilation while ignoring only
declared output trees, and then rehashes the source record, builder record and
GrapheneOS lock immediately before successful execution evidence is written.

After compilation, signing and receipt creation may recheck the same snapshot
with `--allow-build-outputs`. That option skips only `out/` and `releases/`;
it does not weaken the source, vendor, staging, cache or key-tree rules. It is
not accepted by `create-source`, so the authenticated snapshot always comes
from a clean pre-build tree.

The source gate verifies:

- exact bytes and commit of the authenticated `default.xml`;
- the complete path/name/revision/remote ledger for every manifest project;
- every project HEAD and the exact `repo` tool revision;
- each authenticated gitlink's object ID and exact absent or empty-directory
  worktree representation;
- each narrowly accepted Git LFS payload and LF-to-CRLF checkout, including
  authenticated cached attributes, raw object identity and exact materialized
  byte hash and size;
- the explicit Android build/toolchain/prebuilt project subset;
- exact owned framework, Launcher, Goldfish emulator and Updater changes;
- every ordinary file in `external/wonad` and the complete generated
  `vendor/google_devices` tree (with mandatory frankel product/revision guards);
- absence of every other untracked or ignored file, including `node_modules`,
  `vendor/adevtool/dl`, and arbitrary `Android.bp` files;
- absence of non-empty `out`, `out_adevtool_deps`, `keys`, and `releases`
  trees at build start.

This means vendor-generation caches must live outside the source checkout or
be removed before the record is created. Symlinks and private-key-like files
in generated inputs are rejected. Empty directories are not build inputs and
are not receipted, except that the empty-versus-absent representation of an
authenticated gitlink is explicitly bound as described above.

`release-build.sh prepare-vendor` installs with the frozen yarn lock, generates
the Pixel 10 vendor tree, and removes `node_modules`, downloaded archives,
compiled adevtool caches and `out_adevtool_deps` even on failure. The same
fail-closed cleanup is repeated immediately before source capture. The manual
equivalent is:

```sh
python3 android/tools/phase1_provenance.py clean-vendor-cache \
  --source /sources/grapheneos-2026100600
```

The source record is deterministic: source schema 5 contains no wall-clock
time, host path, username or private-key inventory. A byte or mode change after
capture makes verification fail. The x86 and Frankel build receipts copy the
complete per-project materialization ledger and its digest; a baseline/custom
comparison requires those representations to be exactly equal.

## Production container execution chain

The source freeze claims source only; it is not proof that its embedded builder
was used. `release-build.sh build` therefore requires fresh external paths for
`WONAD_BUILD_OUT`, `WONAD_BUILD_LOG` and
`WONAD_BUILD_EXECUTION_PROVENANCE`, plus a fresh build-scoped
`WONAD_BUILD_CONTAINER` name. `WONAD_BUILD_EXECUTION_PROVENANCE.preflight.json`
records the intended attempt. The sibling
`WONAD_BUILD_EXECUTION_PROVENANCE.bind-proof.json` is written while the exact
container is running but blocked before compilation.

The launcher accepts only `/usr/bin/docker` through the local
`unix:///var/run/docker.sock` built-in default context. It binds the CLI and
socket file identities, daemon identity, host boot ID, immutable image ID,
mutable tag resolution and `linux/amd64` platform. The actual container is
created by immutable image ID with no network, all capabilities dropped,
`no-new-privileges`, a blocking single-file `json-file` log contract
(`max-size=1t`, `max-file=1`), UID/GID 1000:1000 and only these read-write
mounts:

```text
authenticated GrapheneOS source -> /sources
fresh external OUT_DIR          -> /sources/out
```

The exact bind specifications remain part of the contract. Docker may return
both `HostConfig.Binds` and the two inspection rows in either order, so
evidence canonicalizes them by destination while requiring exact field sets
and types, unique sources and destinations, `rw` mode and the complete expected
contents.

Host file descriptors keep both directory identities live throughout the
build. Before releasing the build gate, in-container `stat` results for both
mounts must exactly equal the host device/inode/mode/owner records. The process
uses `/usr/bin/env -i` with fixed locale, timezone, build identity, PATH and an
empty private mode-0700 `/tmp/wonad-home`; inherited Android/RBE/Soong state is
rejected. `lunch frankel-cur-user`, `m` and `script/finalize.sh` exist only in
that recorded container command. There is no host invocation or fallback.

Only a zero-exit, non-OOM, exact retained container followed by image, Docker,
path, input-record, source-freeze and finalized-artifact revalidation can
produce the atomic successful execution record. The complete container output
is retained at `WONAD_BUILD_LOG`; its exact bytes are later copied to
`wonad-provenance/build.log` and checked against the execution record.

The successful exited container deliberately remains until
`release-build.sh sign`. On the same host boot and daemon, `sign` revalidates
the execution and then removes that exact container by full ID, proves both the
ID and exact name are absent, and writes fresh external
`WONAD_BUILD_CONSUMPTION_PROVENANCE`. All of this completes before the
production `keys/frankel` link can exist. The three execution files and the log
are copied into the signed release as:

```text
wonad-provenance/build-execution.json
wonad-provenance/build-bind-proof.json
wonad-provenance/build-container-consumption.json
wonad-provenance/build.log
```

Offline receipt verification loads the proof bytes rather than trusting only
their hashes, cross-binds their nonce/container/source/OUT/local-Docker
identities and demands an exact evidence inventory. Failed attempts can leave
diagnostic preflight, log and stopped-container state but cannot mint a
successful record or enter a release receipt.

## SDK and conformance client record

First create a fresh successor compile receipt. Sign only its unsigned
conformance APK with the same production Wonad identity whose public
certificate is staged into the OS. Then run:

```sh
python3 android/tools/phase1_provenance.py create-clients \
  --sdk-publication /safe/build/sdk-repository \
  --conformance-apk /safe/build/conformance-release-signed.apk \
  --source-receipt /safe/build/build-receipt.json \
  --signer-certificate /safe/public/wonad-release.x509.pem \
  --apksigner /sources/grapheneos/prebuilts/sdk/tools/linux/bin/apksigner \
  --qualification production \
  --output /safe/evidence/phase1-clients.json
```

The gate replays the strict SDK publication verifier against the frozen source,
checks every frozen source file and publication file against the compile
receipt, verifies the APK signature, and compares every non-signature APK entry
with the receipted unsigned APK. Adding a signature cannot replace the manifest,
DEX, resources or any other payload. For production evidence it also queries
the APK's v3 signing-certificate lineage separately: `apksigner verify
--print-certs` reports only current signers, so a one-signer result alone does
not prove that historical signing certificates are absent. Any production
proof-of-rotation or unrecognized lineage-query result fails closed.

Use `--qualification development` for emulator-only signers. Development and
production records are distinct and cannot be relabelled during verification.
The tool accepts only the public X.509 certificate. It never accepts, hashes or
records an APK private key. At signing preflight, the driver canonicalizes the
public certificate for every GrapheneOS signing role and rejects the release if
the Wonad APK identity equals any of them. In particular, the Wonad pin cannot
silently alias the platform certificate.

For `release-build.sh sign`, supply the production record and its inputs via
`WONAD_CLIENT_PROVENANCE`, `WONAD_SDK_PUBLICATION`, `WONAD_CONFORMANCE_APK`,
`WONAD_CONFORMANCE_SOURCE_RECEIPT`, `WONAD_APK_CERTIFICATE` and
`WONAD_APKSIGNER`. The driver replays client verification before private OS
keys are linked, then atomically stages the public evidence into the generated
release. The offline receipt verifier checks the complete evidence tree and
rejects missing, extra, stale, development-qualified or signer-mismatched
content.

## Target separation

One source freeze records both reviewed lunch configurations:

- `frankel-cur-user` / ARM64 is `production` and may claim factory, full OTA and
  incremental OTA artifacts;
- `sdk_phone64_x86_64-cur-userdebug` is a source-matched development runtime.

The freeze itself explicitly claims no binary artifacts. Each ARM release
receipt selects only `production`; the presence of the x86 target and its two
Goldfish configuration hashes therefore cannot be mistaken for receipted
emulator bytes. Emulator client records use `development`, never `production`.

## Remaining external inputs

Production completion still requires externally protected Wonad APK signing
material, GrapheneOS AVB/OTA/factory signing material, an owned update channel,
and authenticated publication of the final receipt digest. None belongs in a
provenance inventory or source checkout. Pixel 10 hardware qualification and
the 24-hour soak are runtime evidence, not substitutes for these build records.
