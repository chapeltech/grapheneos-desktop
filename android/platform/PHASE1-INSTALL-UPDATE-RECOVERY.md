# Phase 1 Pixel 10 installation, update and recovery runbook

For availability, physical-phone preparation and the 5120×1440 monitor
checklist, start with [the Pixel 10 handoff](../PIXEL10-INSTALL.md). No flashable
Wonad phone release is currently supplied. This runbook must not be used to
promote an emulator image or an unsigned/test-key build into one.

This runbook applies only to the exact `frankel` artifacts selected by a
verified Phase 1 release index. Phase 1 produces a flashable candidate; it does
not claim that these steps have passed on physical hardware. The first physical
execution and rollback rehearsal are Phase 2 evidence.

Never replace a path, hash, signer, build number or update endpoint in a sealed
release. A replacement creates a new candidate and requires new evidence.

## Required authenticated inputs

Keep private signing material away from the installation host. The installer
needs only:

- `phase1-release-index.json` and its independently authenticated SHA-256;
- the predecessor/successor release trees and incremental-pair receipt named by
  that index;
- the public AVB key metadata blob, OTA certificate and factory-image SSH key;
- the independently authenticated otatools manifest and its SHA-256; and
- the exact verifier checkout and tools hashed by the release index.

Before copying an archive to a phone, run all three offline checks from a clean
host with networking disabled:

```sh
python3 android/tools/phase1_release_index.py verify \
  --evidence-root "$PHASE1_EVIDENCE_ROOT" \
  --index "$PHASE1_EVIDENCE_ROOT/phase1-release-index.json" \
  --expected-sha256 "$PHASE1_RELEASE_INDEX_SHA256"

python3 android/tools/release_receipt.py verify \
  --receipt "$SUCCESSOR_RELEASE/release-receipt.json"

python3 android/tools/verify_release_pair.py \
  --receipt "$PAIR_RECEIPT" \
  --avb-public-key "$AVB_PUBLIC_KEY" \
  --ota-certificate "$OTA_CERTIFICATE" \
  --factory-public-key "$FACTORY_PUBLIC_KEY" \
  --expected-pair-receipt-sha256 "$PAIR_RECEIPT_SHA256" \
  --trusted-otatools-manifest "$OTATOOLS_MANIFEST" \
  --expected-otatools-manifest-sha256 "$OTATOOLS_MANIFEST_SHA256" \
  > "$EXTERNAL_EVIDENCE_DIR/pair-verification.json"
```

Also run `verify_release_artifacts.py` for each endpoint as documented in
[`RELEASE-RECEIPT.md`](RELEASE-RECEIPT.md). Expected hashes must come from the
authenticated release channel, never from the bundle being checked. Stop if a
verifier reports an extra file, a different signer, a development key, a
non-`frankel` product, a non-`user` build, permissive SELinux configuration, or
an unexpected update URL.

## Data and bootloader consequences

Unlocking or relocking a Pixel bootloader erases user data. Back up application
data and exported authenticator or recovery material before starting. Treat the
candidate as a clean installation; importing old userdata or restoring a raw
userdata image is outside Phase 1.

Use a direct USB connection and a supported, current `adb`/`fastboot`. The
receipted `flash-all.sh` enforces its minimum fastboot version and refuses a
device whose bootloader product is not the factory image's exact device. Do not
edit that script, bypass its product check, add `--force`, disable verification,
or flash individual partitions from another release.

## Clean factory installation

1. On the phone, enable OEM unlocking only after backups are complete. Boot to
   the bootloader and unlock it using the normal device-confirmed fastboot flow.
   The wipe is expected.
2. Extract the **verified optimized factory archive** into a new empty
   directory. Reject links, overwrites and extraction warnings. The extracted
   `flash-all.sh`, image archive, firmware and `avb_pkmd.bin` must be the bytes
   covered by the release receipt.
3. With exactly one fastboot device attached, run the unmodified receipted
   script from that directory:

   ```sh
   ./flash-all.sh
   ```

   The generated script checks the hardware product, updates both bootloader
   slots as required, installs the release's custom AVB public key, wipes
   userdata and flashes the complete image. Any non-zero exit is a failed
   installation; do not continue by manually skipping the failed operation.
4. Boot the OS once while the bootloader remains unlocked. Record the displayed
   verified-boot warning, build fingerprint, build number, product, boot state,
   SELinux mode and update URL for Phase 2 comparison.
5. Relock only after the exact candidate boots and the recorded AVB key identity
   matches the release. Confirm the relock on the device. Relocking wipes data
   again. A device that cannot boot the candidate while locked has failed the
   Phase 2 verified-boot gate.

Phase 1 does not authorize installing this candidate on a daily-use phone.

## OTA update

The predecessor and successor must be the exact pair bound by the release
index: same product, project update URL, AVB/OTA/factory lineage and monotonically
increasing build number **and strictly increasing build timestamp**. The pinned
Updater compares the metadata timestamp with the installed `ro.build.date.utc`;
it reports "already updated" when the offered timestamp is equal or older, even
if the incremental build number is higher. The release index requires positive
exact-integer timestamps from both full-release receipts and matching embedded
pair endpoints, then rejects an equal or older successor. Verify the pair and
release index offline before exposing either build to update metadata.

For another release built from the same source pin, explicitly select and record
`WONAD_BUILD_DATETIME` for the successor unsigned build so that it is greater
than the predecessor's receipted timestamp. The release driver's default is the
manifest commit time, which does not advance for a same-source build-number bump.
Do not change dates in sealed receipts or metadata after building; rebuild and
requalify the candidate with the selected timestamp instead. The frozen pair
producer's independent equal-timestamp rejection remains pending a safe
tool/source/provenance update; its standalone passing result is not a substitute
for the stricter release-index eligibility gate.

For the normal path, publish the sealed candidate's channel metadata over HTTPS
alongside its signed full and incremental OTA packages, then let the system
Updater apply the eligible update. The pinned channel files are ordinary
plaintext, not independently signed documents: HTTPS authenticates their
delivery, and the Updater verifies the downloaded OTA's signatures. Do not
describe channel text as signed OTA-package metadata.

The default channel requests `frankel-stable`; an administrative candidate
label alone does not change that request. Record the actual Updater channel
selection. Both channel metadata and the requested OTA paths must be served
from the configured base URL, directly or through reviewed HTTPS redirects;
a separate artifact-host URL alone does not configure the client. Do not
redirect a custom-signed build to GrapheneOS's official endpoint. Capture the
pre-update fingerprint, slot and user-data sentinel; then capture the
post-update fingerprint, slot, verified-boot state and sentinel.

Recovery sideload is a repair path, not evidence for a successful automatic
update. If it is required, use the exact verified full OTA from the successor,
select the stock recovery's ADB sideload action on the device, and run:

```sh
adb sideload "$SUCCESSOR_FULL_OTA"
```

Do not sideload an older build, a package from another signing lineage, or an
incremental OTA whose asserted predecessor is not the installed build. Phase 1
does not claim support for Android-version downgrade.

## Failed boot or failed update

Preserve the first failure evidence before changing state: host command output,
bootloader messages, active slot, recovery reason, serial console if available,
and the authenticated identities of every input. Do not expose private user
data in a public defect record.

Try only these bounded recovery paths:

1. Retry booting the other slot when the bootloader/recovery reports that the
   update changed slots and the previous slot remains intact.
2. Sideload the exact verified full OTA for the installed signing lineage.
3. Unlock if necessary and rerun the exact verified factory package, accepting
   the resulting data wipe.

If the candidate cannot recover without mixing artifacts, disabling verified
boot, editing the factory script or repairing userdata manually, record a
high-severity Phase 1/2 defect and withdraw it.

## Return to stock GrapheneOS or Google firmware

Returning to stock is a new clean installation and ordinarily wipes data.
Obtain a current official factory image directly from the selected upstream
publisher and follow that publisher's current installation instructions. Never
serve an official image through the Wonad channel or present this project's
keys as upstream keys.

Before flashing stock, unlock the bootloader if required. The official factory
process must replace the OS and the custom AVB key; verify that the resulting
fingerprint and boot key belong to the chosen official release before
relocking. Do not attempt an older Android release or firmware rollback merely
because its version once ran on the phone: anti-rollback state and newer
firmware may make that unsupported or unsafe.

Phase 2 must execute and record the return-to-stock path. Until that happens,
this is procedural guidance rather than a tested rollback claim.

## Evidence retained after every rehearsal

Retain the authenticated release-index digest, release/pair verification JSON,
exact host-tool versions, device product and serial (redacted in public copies),
pre/post fingerprints and slots, lock state, verified-boot state, SELinux mode,
Updater result, wipe decision, and every command exit status. Link the immutable
record from the defect register or final review; never add it to a release tree
after that tree's receipt has been sealed.
