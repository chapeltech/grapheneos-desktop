# Pixel 10 release receipt

`android/tools/release_receipt.py` freezes the exact contents of the signed
GrapheneOS Pixel 10 release directory after `script/generate-release.sh` has
completed. Release-receipt schema 4 also binds the authenticated container
execution, its live bind-mount proof, its exact build log and proof that the
build container was removed before release keys became reachable. The receipt
tool does not handle or inspect release keys.

## Production build and signing lifecycle

The build and sign actions are one evidence lifecycle. Run both as UID/GID
1000:1000 on the same local Linux host, boot and Docker daemon. Do not reboot,
restart or replace Docker, move or replace the source/OUT directories, retag
the builder image, or manually remove the successful build container between
the two actions. The launcher deliberately binds all of those identities.

Choose an external directory owned by UID/GID 1000:1000. The OUT path, log,
execution path, their derived evidence paths, consumption path and container
name must all be fresh. They must be outside both the GrapheneOS checkout and
the Wonad checkout. A representative setup is:

```sh
export WONAD_GRAPHENEOS_RELEASE_SOURCE=/srv/build/grapheneos-2026100600
export WONAD_BUILD_NUMBER=2026101000
export WONAD_BUILDER_PROVENANCE=/srv/evidence/phase1-builder.json
export WONAD_SOURCE_PROVENANCE=/srv/evidence/frankel-2026101000/source.json
export WONAD_BUILD_OUT=/srv/build-out/frankel-2026101000
export WONAD_BUILD_LOG=/srv/evidence/frankel-2026101000/build.log
export WONAD_BUILD_EXECUTION_PROVENANCE=/srv/evidence/frankel-2026101000/execution.json
export WONAD_BUILD_CONSUMPTION_PROVENANCE=/srv/evidence/frankel-2026101000/consumption.json
export WONAD_BUILD_CONTAINER=wonad-phase1-frankel-release-2026101000-01
export WONAD_APK_CERTIFICATE=/srv/public/wonad-release.x509.pem
export WONAD_UPDATE_URL=https://updates.wonad.example/releases/

android/platform/release-build.sh build
```

`build` performs the following fail-closed sequence:

1. It creates and verifies the source freeze, authenticates the local Docker
   CLI, Unix socket, built-in default context, daemon, host boot and exact
   `linux/amd64` builder image ID. Docker endpoint/configuration overrides and
   inherited Android build variables are rejected.
2. It creates the external OUT directory, writes
   `execution.json.preflight.json`, and creates a named, network-disabled
   container by immutable image ID with the `json-file` log driver explicitly
   set to blocking with one 1-TB file (`max-size=1t`, `max-file=1`). This
   fail-closed practical bound prevents daemon defaults from silently rotating
   an ordinary build log. The source and OUT roots are its only read-write
   binds.
3. The container clears its environment, creates an empty mode-0700
   `/tmp/wonad-home` owned by 1000:1000, then waits behind a per-attempt gate.
   While it is running and gated, the launcher proves that `/sources` and
   `/sources/out` have the same device and inode identities as the held host
   directories and writes `execution.json.bind-proof.json`.
4. Only then is the gate released. The container selects
   `frankel-cur-user`, runs the pinned `m` targets and `script/finalize.sh`.
   Docker retains its output and, after exit, the launcher streams it into the
   new external build log.
5. A zero exit is not sufficient by itself. The launcher rechecks the Docker
   host and image, held paths, source freeze, lock, builder/source record bytes,
   finalized target-files and otatools before atomically writing
   `execution.json`. The exited container is retained for signing preflight.

There is no host-build fallback: `release-build.sh` contains no `lunch` or `m`
invocation. The success record contains the exact cleared environment, command,
immutable image ID, container configuration and zero-exit lifecycle. A claimed
builder record, a failed/missing container, tag drift, a remote daemon, or a
host-side build cannot produce valid success evidence.

After `build`, retain all of the following unchanged:

```text
WONAD_BUILD_OUT
WONAD_BUILD_LOG
WONAD_BUILD_EXECUTION_PROVENANCE
WONAD_BUILD_EXECUTION_PROVENANCE.preflight.json
WONAD_BUILD_EXECUTION_PROVENANCE.bind-proof.json
the named exited WONAD_BUILD_CONTAINER
```

Set the remaining client and key variables documented by
`release-build.sh --help`, then run:

```sh
android/platform/release-build.sh sign
```

Before `keys/frankel` is created, `sign` replays source and client provenance,
online-verifies the exact retained container and all build evidence, removes
that container by its full ID, confirms both its ID and exact name are absent,
and atomically writes `WONAD_BUILD_CONSUMPTION_PROVENANCE`. Re-running this gate
is idempotent only when that existing record still proves the same container is
absent. This ordering prevents a stopped container with a read-write source
bind from being restarted after private keys are linked.

A failed build never writes `execution.json`. It may retain a stopped container
and its preflight/log/bind evidence for diagnosis; that attempt cannot be
signed. Do not relabel or manually synthesize any of these files.

The signed release contains the exact public evidence below:

```text
wonad-provenance/source-provenance.json
wonad-provenance/client-provenance.json
wonad-provenance/build-execution.json
wonad-provenance/build-bind-proof.json
wonad-provenance/build-container-consumption.json
wonad-provenance/build.log
```

The external preflight file is diagnostic attempt evidence and is not bundled.
The receipt hashes every bundled byte and cross-binds the execution, live bind
proof, log, consumed container, source, builder, lock and staged verifier-tool
identities.

Create the receipt from the Wonad checkout:

```sh
python3 android/tools/release_receipt.py create \
  --source /path/to/dedicated/grapheneos \
  --build-number 2026101000
```

The source must match `android/grapheneos.lock.json`, have both
`external/wonad/.wonad-stage.json` and `.wonad-updater-stage.json`, and contain
the GrapheneOS output at:

```text
releases/<build>/release-frankel-<build>/
```

The Wonad stage record binds the ordered platform patch names and SHA-256s,
the exact post-stage framework/Launcher target bytes, the complete staged
source inventory, the public Wonad release certificate and the staging,
receipt and artifact-verifier tool hashes. Receipt creation rechecks every
tracked manifest project and permits only those exact owned framework,
Launcher and Updater edits.

Creation requires the factory and optimized install archives, the install
archive's detached signature, full OTA, signed target-files archive, image
archive, alpha/beta/stable/testing channel metadata and the complete production
evidence set above. Every ordinary file in the release directory, including
the extracted release tools and container build log, is hashed. Links, special
files and key-like paths are rejected. The JSON is written atomically as
`release-receipt.json` inside that directory.

The copied directory can then be checked without the source tree, network,
lock file or signing keys:

```sh
python3 android/tools/release_receipt.py verify \
  --receipt /path/to/release-frankel-2026101000/release-receipt.json
```

Offline verification rejects duplicate JSON fields and every missing, extra or
changed file. It also rechecks the OTA build identity and all channel records.

Before copying the release to an untrusted verification host, publish an
authenticated SHA-256 of `release-receipt.json`. Independently record the five
executable verifier-tool identities in a JSON file outside the release tree:

```json
{
  "schema": 1,
  "tools": {
    "avbtool": {"sha256": "…", "size": 123},
    "check_ota_package_signature": {"sha256": "…", "size": 123},
    "check_target_files_signatures": {"sha256": "…", "size": 123},
    "unpack_bootimg": {"sha256": "…", "size": 123},
    "validate_target_files": {"sha256": "…", "size": 123}
  }
}
```

Publish that file's SHA-256 through the release channel too. Do not derive
either expected digest from the bundle being verified. The structural and
signature gate authenticates both values before parsing the receipt or
executing release-supplied tools. All three key inputs are public material
exported from the protected release-key ceremony; never pass `avb.pem`, a
`.pk8`, or an SSH private key.

```sh
python3 android/tools/verify_release_artifacts.py \
  --receipt /path/to/release-frankel-2026101000/release-receipt.json \
  --avb-public-key /path/to/public/frankel/avb_pkmd.bin \
  --ota-certificate /path/to/public/frankel/releasekey.x509.pem \
  --factory-public-key /path/to/public/factory.pub \
  --expected-receipt-sha256 "$AUTHENTICATED_RECEIPT_SHA256" \
  --trusted-otatools-manifest /path/to/authenticated/otatools.json \
  --expected-otatools-manifest-sha256 "$AUTHENTICATED_OTATOOLS_SHA256" \
  > /path/to/evidence/frankel-2026101000-artifact-verification.json
```

The verifier refuses an unauthenticated receipt and unpinned, unreceipted or
missing otatools. It safely checks all ZIP
member names and duplicates, then uses the release's pinned `avbtool`,
`validate_target_files`, `check_target_files_signatures`,
`check_ota_package_signature`, and `unpack_bootimg`. It anchors root `vbmeta` to
the public RSA-4096 AVB blob, follows and verifies chained partitions and
descriptors, verifies the OTA whole-file and payload signatures against the
single certificate installed in `otacerts.zip`, and verifies the optimized
factory archive's SSH signature. Static metadata must identify a `frankel`
`user` build with release keys, `ro.debuggable=0`, `ro.secure=1`, compiled
SELinux policy and no permissive boot argument.

Keep the JSON evidence outside `release-frankel-*`: adding it inside after the
receipt is created is correctly treated as an unexpected file. The release
driver should run the receipt `create`, receipt `verify`, and the command above
in that order, then authenticate both JSON files and all three public trust
anchors in release-channel metadata.

The receipt establishes exact artifact/source identity, not authenticity of
the receipt itself. The mandatory expected SHA-256 (or an equivalent detached
signature verified before invoking this tool) supplies that authenticity. The artifact verifier establishes
offline signature and static release-configuration validity; runtime SELinux
state and verified boot still require the Phase 2 physical-device checks.

## Predecessor/successor incremental pair

An incremental candidate is an addition to two immutable full releases, not a
mutation of either release directory. Both endpoints must already have passed
`sign` and contain valid `release-receipt.json` files. Build numbers are exactly
ten decimal digits and the successor must be numerically greater. With the
external production key directory selected, generate the pair with:

```sh
export WONAD_GRAPHENEOS_RELEASE_SOURCE=/path/to/dedicated/grapheneos
export WONAD_PREDECESSOR_BUILD_NUMBER=2026101000
export WONAD_BUILD_NUMBER=2026101001
export WONAD_RELEASE_KEY_DIR=/path/to/external/frankel-keys
android/platform/release-build.sh delta
```

The driver revalidates both endpoint receipts and the successor source/stage,
creates an exclusive pair lock, and refuses an existing OTA or receipt. It then
invokes the official pinned command exactly as
`script/generate-delta.sh frankel <old> <new>`. The stable-script project is
commit `09d651841b55e42b9cee7392f0ce29ebda8c8fb5`; the reviewed script SHA-256 is
`2e0f80721588ff8f45b298f8242e8af658297c1916ff276b9456c1b4e957ef63`.
The temporary `keys/frankel` link is removed before receipt creation.

The resulting files are siblings beneath `releases/<new>/`:

```text
frankel-incremental-<old>-<new>.zip
frankel-incremental-<old>-<new>-receipt.json
```

`release_pair_receipt.py` binds the SHA-256 of both complete full-release
receipts, both source/patch/tool/signer/channel identities, the incremental
OTA, its exact pre/post metadata, and the pinned GrapheneOS generator. It
rejects downgrade metadata, signer or update-channel changes, an older
successor timestamp, links, tampering and overwrite. It never receives or
records a private-key path.

Publish an authenticated SHA-256 of the pair receipt separately from the
bundle. Offline verification needs the same three public trust anchors and
authenticated otatools manifest used for full releases:

```sh
export WONAD_AVB_PUBLIC_KEY=/path/to/public/frankel/avb_pkmd.bin
export WONAD_OTA_CERTIFICATE=/path/to/public/frankel/releasekey.x509.pem
export WONAD_FACTORY_PUBLIC_KEY=/path/to/public/factory.pub
export WONAD_EXPECTED_PAIR_RECEIPT_SHA256="$AUTHENTICATED_PAIR_RECEIPT_SHA256"
export WONAD_TRUSTED_OTATOOLS_MANIFEST=/path/to/authenticated/otatools.json
export WONAD_EXPECTED_OTATOOLS_MANIFEST_SHA256="$AUTHENTICATED_OTATOOLS_SHA256"
export WONAD_VERIFICATION_EVIDENCE=/path/outside/source/frankel-pair-verification.json
android/platform/release-build.sh verify-delta
```

On a verification host without the source checkout, preserve the canonical
`releases/<old>/...` and `releases/<new>/...` layout and invoke the underlying
offline verifier directly:

```sh
python3 android/tools/verify_release_pair.py \
  --receipt /bundle/releases/2026101001/frankel-incremental-2026101000-2026101001-receipt.json \
  --avb-public-key /path/to/public/frankel/avb_pkmd.bin \
  --ota-certificate /path/to/public/frankel/releasekey.x509.pem \
  --factory-public-key /path/to/public/factory.pub \
  --expected-pair-receipt-sha256 "$AUTHENTICATED_PAIR_RECEIPT_SHA256" \
  --trusted-otatools-manifest /path/to/authenticated/otatools.json \
  --expected-otatools-manifest-sha256 "$AUTHENTICATED_OTATOOLS_SHA256" \
  > /path/to/evidence/frankel-pair-verification.json
```

`verify_release_pair.py` authenticates the pair receipt before parsing it,
offline-verifies every file and signature in both full endpoints under the
same AVB, OTA and factory public lineage, safely parses the incremental ZIP,
and runs the independently authenticated successor
`check_ota_package_signature`. That official tool verifies both the OTA
whole-file signature and the A/B payload signature. The signed metadata must
name the exact predecessor fingerprint/build and successor
fingerprint/build/timestamp. Evidence is created atomically outside the source
and release tree. This is artifact verification only; applying the update on a
physical Pixel 10 remains a Phase 2 gate.
