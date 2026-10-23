# Phase 1 OS signer-continuity semantic prototype

Date: 2026-10-11

Status: **external semantic prototype only; not a release gate and not runtime
or cryptographic evidence**.

This directory implements the fail-closed comparison policy proposed by the
source review without changing Wonad, GrapheneOS, the staged source, frozen
tools, receipts, or image inputs. All test inventories, certificate digests,
tool digests, receipt identities, paths, and raw-evidence references are
synthetic. The prototype does not open a target-files ZIP, execute a signing
tool, parse an APK/APEX, possess a key, or verify a signature.

## Reviewed source boundary

The implementation was derived after reading the complete retained review:

- `phase1-os-apk-signer-continuity-design-review-20261011-1.json`, SHA-256
  `b38704b9b85d7d0818f3bdcdde4c1af18fc398043bb6c6e7f46901da175b8055`.

The source claims in that review were checked against the preserved custom-7
tree at build/make commit
`b0f697df8cc9519408ca0a404e918cd51bde0735` and these exact files:

- `check_target_files_signatures.py` —
  `c58b011df51c70db0d9a5ffc394fc40bab1d0113e2a0fabb6f9fec09640ec8e9`;
- `apex_utils.py` —
  `cba4dcffb78e0dd3eb26ddfa7cbf5de8c17f132991824de93ca71430a01502e5`;
- `sign_target_files_apks.py` —
  `066729a5083916d43e23616dc8b7b1b363cc18d2a2c0a661745b3209d1fe014d`;
- `common.py` —
  `2cb306baa8f44c7ea55a590e905e6b10a906c3fa40cf5c71420f51f23e9d2c8d`;
- `script/generate-release.sh` —
  `01f7847ecdc6600bd2e3ffebe45cf79cee4fead1d6b61686c4d3c70e9c548311`;
- `PHASE1-SIGNING-CEREMONY.md` —
  `4c605144a00c0ebf15628612f85910dbec784e0e8ad49bd0c60c04665553766b`.

The historical source-level RED remains unmodified at
`../test_phase1_os_apk_signer_continuity_design_20261011_1.py`, SHA-256
`55b412462f44f53304efa7f0b87ee15d5484a8e0ac0b485b523bd7e9afb6262d`.
It still reports 2 passes, 1 failure, and 2 errors: archive-path comparison
misses a moved package, and both matching and mismatching shared-UID examples
hit the pinned checker's nonexistent `APK.certs` attribute.

## Implemented semantic boundary

`signer_continuity_policy.py` accepts only a fixed-seed policy and two
pre-authenticated endpoint inventories. It requires:

- distinct authenticated endpoint receipt and signed-target-files identities,
  exact trusted-tool maps, strict raw-evidence references, and no extra schema
  fields;
- an exact expected package/split and APEX inventory at both endpoints;
- comparison by parsed Android package/APEX identity, not archive path, while
  reporting allowed path moves;
- exact stable signer sets and role assignments across the pair;
- exact joins from actual DER SHA-256 signer sets to nine distinct independent
  role certificates, with all nine roles covered by actual packages;
- exact sharedUserId membership and identical signer sets within each group;
- source-bound, explicitly enumerated `PRESIGNED` and `vendor_external`
  exceptions with fixed actual signer sets;
- separate APEX archive, verified outer APK, payload public key,
  `avbtool verify_image`, `.capex` decompression, and embedded-APK boundaries;
  and
- strict `apksigner` success with the deprecated/fallback certificate path
  forbidden.

Content bytes may differ between releases. Additions/removals, assignment
changes, shared-UID changes, signer changes, tool drift, evidence aliasing, and
unreviewed lineage fields fail closed.

## Tests

Command:

```text
PYTHONDONTWRITEBYTECODE=1 python3 -B /u/elric/tree/wonad-phase1-build-evidence/phase1-os-apk-signer-continuity-prototype-20261011-1/test_signer_continuity_policy.py
```

Result at 2026-10-11T20:11:37Z: **45 tests passed in 0.031 seconds**.
The suite includes healthy controls plus hostile package moves/signers,
inventory additions/removals and coordinated omissions, duplicate identities,
all-nine coverage, assignment/source drift, vendor and PRESIGNED exceptions,
shared UID sets, split disagreement, malformed hashes, tool drift, failed and
fallback APK verification, raw-evidence alias/traversal, APEX outer signer,
payload key/source/verification, embedded APKs, duplicate APEXes, `.apex` /
`.capex` type confusion, missing decompression evidence, and endpoint
substitution.

## Required real producer/auditor work

This prototype cannot close the release gate. A production implementation must
still:

1. authenticate the release pair, full endpoint receipts, exact target-files
   files, and before/after archive bytes without symlink or substitution gaps;
2. establish measured memory/disk/extraction limits and safely enumerate the
   complete APK, split, APEX, `.capex`, and embedded-APK inventory;
3. use pinned `aapt2` for actual package/split/sharedUserId identity and pinned
   `apksigner` for successful verification plus actual DER SHA-256 identities,
   retaining bounded raw command transcripts and forbidding deprecated fallback;
4. derive role assignments and PRESIGNED/vendor exceptions from authenticated
   unsigned/source signing metadata and reviewed generate-release mappings,
   rather than trusting labels supplied by a signed inventory;
5. authenticate the complete runtime dependency closure, including the
   `apksigner` wrapper/JAR/runtime, `aapt2`, `deapexer`, `debugfs_static`,
   `fsck.erofs`, and `avbtool`;
6. decompress `.capex`, verify outer APEX certificates independently, bind the
   actual bundled `apex_pubkey`, execute official payload verification, and
   inspect every embedded APK;
7. atomically seal raw evidence and a canonical report, then have an
   independently frozen auditor replay it from the exact endpoint artifacts
   before release-index publication; and
8. retain a separately corrected/authenticated official `-c` checker as an
   additional check without treating it as the complete identity/APEX policy.

No real predecessor/successor target-files pair or cryptographic verifier was
run here.
