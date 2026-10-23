# Phase-1 authenticated target-files archive inventory: bounded design review

2026-10-11. DESIGN ONLY. No implementation, target-files archive opening,
extraction, cryptographic verification, release publication, or guest launch
was performed. This is the next component after the external semantic policy
prototype v3, not another semantic-policy or release-gate success claim.

## Exact current authority and findings

Reviewed current repository sources (SHA-256):

- `android/tools/release_pair_receipt.py`:
  `ae0c98a23a75cd28ea48a97b78be1ac8174e91c99a51e263f75bc74496918e44`.
- `android/tools/verify_release_pair.py`:
  `8dbe40805db0e636a2787814490975e35273a1aeb1912b3353e122b68822a3f6`.
- `android/tools/release_receipt.py`:
  `a13052880e4af6cc7cb7d4a91e155b5606c4e9d5131111e716cf8dab76c5a932`.
- `android/tools/verify_release_artifacts.py`:
  `bc61b4b98ea37a17e6691b3815bbff1aeeb278b377373e802193fe6e298052c7`.
- `android/tools/stage_contract.py`:
  `763c4bfafe891ea92a5aa0b56239e15ebd3f4fe10100b378df38d93a1eeeedc5`.
- `android/tools/phase1_release_index.py`:
  `4832f4d5153e7856748f52fe34950d6fd16bc8f5478dbf0d3825909f7d5b5069`.

Reviewed named pinned source7 files:

- `build/make/tools/releasetools/common.py`:
  `2cb306baa8f44c7ea55a590e905e6b10a906c3fa40cf5c71420f51f23e9d2c8d`.
- `build/soong/zip/zip.go`:
  `f384bba27584ca0e1601c25e74ec5c59f685cf3f2116b16e071f4e28ac87d6be`.
- `build/soong/third_party/zip/reader.go`:
  `4973bed5832bd6965ec795415601ef87602ae03083b51ed950fcb58ec2be2aed`.

External prototype-v3 receipt:
`phase1-os-apk-signer-continuity-prototype-20261011-3/receipt.json`, SHA-256
`974e63741260965546218c61d04896f880ca5be5b14c326234078d02231ca7d7`.
Its single-captured-source loader is
`authenticated_source.py`, SHA-256
`2e28fedfb28277a4c70ada9430a38a5cb7eeb6fc20fb07ed7309f8125dc5da8a`.
The v3 receipt's 5 loader and 56 semantic tests remain separate evidence;
they do not authenticate any actual archive or APK.

Confirmed source-level compatibility issue: `SafeZip.__enter__` at
`verify_release_artifacts.py:133-142` rejects every UNIX `S_IFLNK` ZIP
record. Pinned `zip.go:1135+` deliberately emits those records with the
link target as member bytes; `common.py:2178-2193` understands them and
recreates links during extraction. An archive inventory must retain such
members as opaque bytes. Its success will NOT repair or close the existing
full-release verifier's symlink acceptance boundary. No actual signed
frankel archive was inspected, so real occurrence/impact is not yet measured.

Confirmed bounding limitation: `SafeZip` calls `ZipFile`/`infolist()` before
enforcing `MAX_ENTRIES`; central-directory allocation has already occurred.
It validates member paths/types/expanded-size totals, but it does not supply
the required pre-allocation EOCD/Zip64 directory bounds or FD lifetime.
The upstream Go reader also allocates from the advertised directory count
and later compares only its low 16 bits (`reader.go:78-115`); it is not a
drop-in strict bounded inventory gate. `common.py:2207-2240` is an extraction
helper with an older Zip64 offset workaround, not an independent inventory
validator. Do not copy its positional extra-field workaround into this tool.

## Smallest new component and scope

Proposed fresh external directory (not created):
`/u/elric/tree/wonad-phase1-build-evidence/phase1-os-target-files-archive-inventory-20261011-1/`.

Files would be `produce_archive_inventory.py`,
`audit_archive_inventory.py`, `test_archive_inventory.py`, and an immutable
implementation receipt. No existing repository/frozen16/source7 file changes
are needed to implement or test this narrow component.

The producer's only artifact-selection inputs are one canonical pair receipt
path and its independently supplied expected SHA-256, plus a fresh output
directory. It must derive both full-receipt and signed-target-files paths;
no arbitrary ZIP path, user-selected member list, extraction directory,
command, signing key, or skip-verification option. Example future command,
not executable/authorized now:

```text
/usr/bin/python3 -B <fresh-component>/produce_archive_inventory.py \
  --pair-receipt <canonical-releases>/<successor>/frankel-incremental-<predecessor>-<successor>-receipt.json \
  --expected-pair-receipt-sha256 <actual-out-of-band-pair-digest> \
  --output <fresh-owned-inventory-output>
/usr/bin/python3 -B <fresh-component>/audit_archive_inventory.py \
  --inventory-receipt <fresh-owned-inventory-output>/receipt.json \
  --expected-inventory-receipt-sha256 <actual-retained-inventory-digest> \
  --pair-receipt <same-original-canonical-pair-path> \
  --expected-pair-receipt-sha256 <same-actual-out-of-band-pair-digest>
```

Keep the scope exactly `authenticated_pair_selected_target_files_archive_observations`.
It must say `release_gate_closed=false`, `cryptography_performed=false`,
`package_identity_derived=false`, `extraction_performed=false` and
`runtime_qualified=false`. Do not emit the v3 semantic endpoint schema:
that schema requires actual package/signer/APEX claims absent at this stage.

For minimum execution dependencies, implement a narrow strict receipt-selector
and cross-binding reader using the standard library, not imported repository
verifiers. This reader authenticates and cross-binds exact receipt bytes; it
does NOT claim to replace `verify_pair_receipt`, full release inventory,
provenance, OTA metadata/signatures, or official cryptographic verification.
Publication must still separately require those existing full verifiers.
If instead reusing frozen validator functions, explicitly authenticate the
entire reachable local import closure and execute those captured bytes,
rather than hash a pathname then import/reopen it. That is a larger dependency
surface, not necessary for this inventory-only component.

## Receipt authentication and exact path bindings

1. Require the pair path in the canonical `releases/<successor>/` layout.
   Open trusted parent directories with directory FDs and no-follow component
   traversal; refuse symlinked parents/final files, FIFOs/devices/sockets and
   foreign output paths. Use `O_NONBLOCK` with a regular-file `fstat` check
   so an unexpected FIFO cannot block before rejection. No `.resolve()`-then-
   reopen or arbitrary endpoint aliases. An absolute trusted release root is
   operational context, not a replacement for the out-of-band digest.
2. Capture pair JSON through one stable regular FD, maximum 4 MiB, hash those
   bytes before strict unique-key UTF-8 JSON parsing. Reject non-finite numbers,
   bool/float schema or size aliases, duplicate keys and unsupported schemas.
3. Pair schema is exact integer 1, kind
   `wonad-grapheneos-incremental-pair`, target `frankel`. Its current top-level
   keys are `schema, kind, target, predecessor, successor, incremental_ota,
   official_delta_generator, receipt_generator, pair_verifier`. Each endpoint
   has `number, receipt, build, target, source, grapheneos_lock, wonad_stage,
   updater_stage, phase1_provenance, apk_signer_sha256`.
4. Derive each endpoint receipt from
   `<number>/release-frankel-<number>/release-receipt.json`; require the pair's
   `receipt.path` to equal that literal derived relative path and its reference
   to have exactly `path, sha256, size`, SHA-256 lowercase hex, positive exact
   integer size. Both numbers are ten decimal digits, successor number greater.
   Capture/authenticate each full receipt from its own FD before parsing.
5. Full receipt schema is exact integer 4 and kind
   `wonad-grapheneos-release`; require its current top-level keys. For selector
   binding, reconstruct the pair endpoint with its actual receipt reference
   and full receipt's `build, target, source, grapheneos_lock, wonad_stage,
   updater_stage, phase1_provenance, apk_signer_sha256`; require full object
   equality with the embedded endpoint. Do not silently accept a relabelled
   number, date, source, stage, SDK/client provenance, channel or signer field.
   These fields are *receipted assertions*, not newly observed signers.
6. Target must be exactly Pixel 10/frankel/arm64-v8a/user/frankel-cur-user.
   Require positive exact-int endpoint timestamps with successor strictly
   greater (matching the current aggregate Updater date guard, not the older
   pair producer's equal-date allowance). Require unchanged receipted Wonad
   signer and update URL. Record those joins without claiming cryptographic
   certificate verification or channel ownership.
7. Select `full_receipt.artifacts.signed_target_files`; it must be literal
   `frankel-target_files.zip`, an ordinary direct child of that endpoint's
   canonical release directory. Its full receipt `files[name]` must contain
   exactly positive `size` and lowercase `sha256`. Authenticate the ZIP's
   complete raw bytes through the very FD subsequently passed to `ZipFile`.
   The pair itself contains no direct target-files hash: the required chain is
   out-of-band pair digest -> full receipt digest -> `files[artifact_role]`.
8. Retain the pair/full receipts as exact authenticated byte snapshots with
   hash/size references, plus original relative origins. Re-hash each input FD
   and compare identity before final publication; require selected pathname
   still names that FD's device/inode. This detects replacement/ordinary
   in-place drift, without claiming protection against an actively malicious
   privileged writer able to change and restore bytes during reads. The owned
   release tree must remain immutable during the authorized real scan.

## Bounded ZIP observation algorithm

Suggested fixed initial structural ceilings, all recorded in receipt and
reviewed before execution: archive bytes <=128 GiB, entries 1..250000,
central directory <=128 MiB, one expanded member <=64 GiB, total expanded
members <=128 GiB, one member name <=4096 encoded bytes, symlink payload
<=64 KiB, raw listing and sorted inventory each <=256 MiB. These are admission
ceilings, NOT measured RSS/time requirements or a claim that a real frankel
archive fits. Payload chunk size <=1 MiB; one endpoint/member at a time;
no parallel decompression, recursive archive processing, or extraction.

Before constructing `ZipFile`, use bounded `pread` to inspect the final
22+65535-byte EOCD window. Require a structurally valid unambiguous terminal
record with exact comment length/end-of-file; no appended junk or multi-disk
archive. Resolve sentinel fields through the adjacent valid Zip64 locator
and bounded Zip64 EOCD with checked offsets/lengths, single disk, exact
untruncated counts and directory range before EOCD. Do not reject valid
Zip64 merely for exceeding 32-bit values. Reject missing/duplicate/malformed
Zip64 needed-field data, impossible/inconsistent counts, out-of-file offsets,
and count/directory bounds before the parser can allocate its member list.
A bounded central-directory walk must enforce actual count/record lengths
before allocation too: an advertised small count alone cannot constrain an
oversized real member list. Compare those preflight observations with the
library's parsed list/offsets; do not adopt the Go low-16-bit count comparison.

Use `zipfile.ZipFile` on the same already-authenticated FD/file object, with
Zip64 enabled, to stream member decompression and CRC checks. Do not write a
second ZIP implementation for DEFLATE or manually rewrite parsed offsets.
Allow only STORE(0)/DEFLATE(8), reject encryption/strong-encryption and
unsupported flag features; allow supported UTF-8 and data-descriptor flags.
Compare local header name/method/flags with its central entry, validate
needed Zip64 fields/data descriptors through library plus preflight checks,
and reject overlapping physical data/header ranges or ranges entering the
central-directory/end records. All extra-field TLVs must be structurally
bounded; unknown well-formed extras can be recorded by hash, not interpreted.

Check `orig_filename` as well as `filename` to prevent NUL-truncation aliases.
Names are exact canonical relative POSIX paths: no NUL/control characters,
backslashes, absolute paths, empty/dot/dotdot segments, repeated/trailing
slashes except exactly one directory slash. Do not case-fold or normalize
Unicode identities. Map directories to their slash-free canonical member
key and reject duplicate keys, regular/directory aliases, and a physical
file/symlink used as a directory prefix. Validate UTF-8/legacy ZIP name
decoding and retain original name bytes as hex in raw listing so decoded
path decisions can be independently replayed.

Classify members from UNIX type bits plus directory syntax: ordinary regular
file, directory, or UNIX symlink only; absent type bits imply the library's
ordinary DOS regular/directory interpretation and remain observable as such.
Reject contradictory directory/type bits, special device/FIFO/socket modes
and directory records with nonempty payload. Explicit directories count and
are inventoried, even though the existing `SafeZip.entries` excludes them.

For symlinks, hash the decompressed link-target payload exactly as bytes,
with `type=symlink`, without decoding it into a host path, resolving it,
creating a link, or following it. Absolute targets, `..`, dangling links and
cycles are opaque contents at THIS no-extraction boundary, not traversal.
Do not turn a link into an ordinary APK/file by following its target.
Nested ZIP/APK/APEX/CAPEX payloads are likewise just regular member bytes.

Stream each selected `ZipInfo` to EOF, independently accumulate CRC32 and
SHA-256, count every emitted byte, enforce per-member/global limits while
reading, and compare exact size and CRC against central metadata including
zero CRC values. Reject truncation, decompression failure, unsupported method,
bad CRC and output beyond the expected/bounded length. `read()`/whole-member
allocation and `extract*()` are forbidden. Directory observations have empty
payload SHA-256/CRC with size zero, verified by the same bounded checks.

Record a raw central-order JSONL listing and a deterministic sorted-member
JSONL observation ledger with bounded exclusive writes. Bind hashes/sizes
for both; each raw central entry must yield exactly one observation and
counts/totals must reconcile. Hash the full archive again after streaming
through the same FD, require expected digest/size and stable fstat identity,
then atomically publish a fresh non-overwriting receipt (exclusive/link-based
publication, fsync; never `os.replace` a prior authority file). Preserve
failure diagnostics in their owned fresh directory; never publish success
for a partial scan.

## Proposed exact output grammar

Receipt top-level fields:

```text
schema: exact integer 1
kind: phase1_authenticated_target_files_archive_inventory
status: observed
scope: authenticated_pair_selected_target_files_archive_observations
release_gate_closed, cryptography_performed, package_identity_derived,
extraction_performed, runtime_qualified: all literal false
pair: {origin, sha256, size, snapshot:{path,sha256,size}}
implementation: {producer:{name,sha256,size}, auditor:{name,sha256,size},
                 interpreter:{path,sha256,size,version},
                 stdlib_zipfile:{path,sha256,size}, zlib_runtime_identity,
                 structural_policy:{...exact ceilings...}}
endpoints: {predecessor:<endpoint>, successor:<endpoint>}
```

Each endpoint:

```text
build: {number, timestamp, post_build}
release_receipt: {origin,sha256,size,snapshot:{path,sha256,size}}
receipted_endpoint_identity: <exact pair endpoint object>
archive: {role:"signed_target_files",origin,sha256,size}
fd_observation: {device,inode,mode,size,mtime_ns,ctime_ns,
                 before_hash,after_hash,path_still_names_fd:true}
zip_structure: {zip64,entry_count,central_directory_offset,
                central_directory_bytes,central_directory_sha256,
                eocd_offset,comment_bytes,expanded_total,
                regular_count,directory_count,symlink_count,
                raw_listing:{path,sha256,size},
                member_inventory:{path,sha256,size}}
```

Sorted JSONL observation row, exact keys:

```text
endpoint, namespace:"target-files", member, zip_name, central_index,
type:"regular"|"directory"|"symlink", creator_system, unix_mode,
external_attr, flags, compression_method, compressed_size,
expanded_size, crc32:<8 lowercase hex digits>, sha256,
local_header_offset, compressed_data_offset, raw_listing_index
```

Raw central-order listing contains the same parser source facts plus original
name bytes hex, bounded extra-field hashes and declared local offsets/sizes;
no package/signer/role/APEX fields. All numeric fields use exact Python ints
and strict JSON grammar, never JS floating-point round trips. Original
inode/device/timing fields are observations, not portable cryptographic IDs;
the independent auditor rederives content identities, not inode equality
across different machines.

## Independent auditor and hostile fixtures

The auditor authenticates its receipt before parsing, authenticates both
endpoint receipt snapshots and original input bytes from its independent
expected pair digest, repeats selector/path binding and structural/member
observations from fresh regular FDs, and compares canonical contents/counts/
hashes to every advertised ledger row and raw listing. It must not trust
`status=observed`, producer booleans, producer counters or a passed flag.
Implement auditor selector and evidence grammar independently; sharing the
reviewed stdlib ZIP decompressor is acceptable, but simply calling the
producer to reproduce its dictionary is not an independent audit.

Pin the exact new producer/auditor source snapshots and all runtime/source
dependencies before execution. Do not reuse self-claimed hashes from an
unauthenticated report, import loader/pyc reopening after hashing, prototype
synthetic fixture loaders as actual archive evidence, or historical source6/
custom5 identities. This next stage requires no apksigner/aapt2/deapexer
dependency or certificate-role policy because it makes none of their claims.

Small generated fixtures only, in fresh temporary owned directories:

- valid STORE/DEFLATE, empty regular files/directories, Unicode names,
  ordinary symlink bytes (including absolute/relative/dangling/cyclic targets),
  multiple physical members with the same *payload* but distinct names;
- tiny forced Zip64 local header, Zip64 EOCD/count/offset fixture, descriptor
  forms; no 4+GiB allocation or long upstream Zip64 stress suite;
- wrong pair/full-receipt/archive hash, role relabel/path alias, timestamp
  bool/float/equal/regression, duplicate JSON field, source/stage endpoint
  mismatch, substituted full receipt, parent/final symlink and FIFO;
- exact duplicate member, regular/directory canonical alias, NUL truncation,
  backslash/absolute/dotdot/repeated slash/control names, prefix type conflict;
- link payload bytes accepted without filesystem effects; device/FIFO/socket
  modes and contradictory directory modes rejected;
- count and directory limits checked *before* library allocation; forged
  small EOCD count, oversized/overlapping central ranges, multi-disk,
  appended junk, missing/truncated/duplicate malformed needed Zip64 records;
- encryption, unsupported compression, oversized declared/actual expanded
  length, streaming total limit, truncated data/descriptor, local-name/method/
  flag disagreement, shared/overlapping physical offsets and wrong zero/nonzero
  CRC; no unchecked compressed bomb fixture;
- deterministic pathname substitution/in-place drift boundaries, final archive
  mismatch; source snapshot swap after authentication must not execute changed
  bytes; unreviewed tool drift refused;
- altered/missing/extra/reordered ledger rows, raw-to-canonical alias,
  false totals, stale endpoint evidence, exact-int hostile fields, tampered
  receipt/snapshot/listing refs, existing output refused, partial failure never
  emits a success receipt; auditor must reject producer-only forged claims.

Hostile tests and independent review precede any authorized real scan. Actual
archive identities and measured resource peaks are currently unavailable;
there are no release ZIP digests to fill in or real commands ready to launch.
Streaming bounds avoid payload-sized RAM/extraction storage, but directory
objects/sorting/listings still require bounded metadata RAM and output disk;
record actual elapsed/RSS/bytes on the first approved run, sequential with
other heavy lanes. This design does not guarantee a total RSS ceiling.

## Result and next authorized action

No archive inventory implementation was authorized by this task. The smallest
next approval is this external producer + independent auditor + small hostile
host tests, retaining the exact limited `observed` scope. Existing full-release
symlink compatibility and official shared-UID/path-comparison defects remain
separate production-verifier work, not waived by archive observations.
Package identity, actual cryptographic signatures, signing-role assignment,
common-package continuity, shared UID, APEX/CAPEX traversal and payload keys
must follow as separately authenticated stages before publication. The pair4
runtime artifact binding/GO remains the current priority.
