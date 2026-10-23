# Authenticated target-files ZIP observations (external host component)

This is inventory-only development code. It opens only user-authenticated
receipted archives and emits physical ZIP member observations. It does not
extract files, follow embedded symlinks, derive package identities, verify
signatures, assign signing roles, inspect APEX payloads, or qualify releases.
No actual signed release archive has been scanned by this implementation.

The producer and auditor have independently implemented receipt selectors,
EOCD/Zip64/central/local checks and streaming observation paths. The auditor
never imports or invokes the producer. Both use Python's ZIP metadata reader
and bounded stdlib zlib raw-DEFLATE decompression; the latter measures actual
expanded output rather than trusting ZipExtFile's declared-size truncation.

Source snapshots are authenticated and compiled from the same captured bytes
by `run_snapshot.py`. Independently authenticate the bootstrap's exact
published hash before invoking it. Direct producer/auditor CLI execution
refuses work without the captured implementation binding.

Frozen initial source identities:

- producer: `9a5091fb2db9ed571dcd015d1ad4d5cf92da2da76f1627291a20078095e9942a`
- auditor: `3e8c18f18cc92b0841f91397d05441aaf4bed7a6eb47ec839aa4117f329e1fa0`
- bootstrap: `f257862f2f40b7879bc53dc4888542bea733d0c8d4fc3f6e23bbc95748081041`
- tests: `c2f6dc83d5daa3fa7fc4822d77c79a2169dd6114dddb7bb98df329b9e864d583`

Only small generated fixtures have been executed:

```text
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B test_archive_inventory.py
```

Result: 31/31 passed, zero skips, 0.453s, tool chunk `4b3527`.
The suite includes actual bootstrap producer/auditor CLI subprocesses against
synthetic endpoint receipts and temporary ZIPs, not real release verification.
It covers supported STORE/DEFLATE/Zip64/data-descriptor cases, opaque symlink
payloads/directories, strict authentication/path/date/JSON joins, preallocation
bounds, CRC (including forged zero), underdeclared/trailing/truncated expansion,
namespace/type/physical alias rejection, inode/path drift, independent evidence
rederivation, nonoverwriting atomic publication and retained failure records.

Future invocation, requiring separately authenticated actual pair digest and
explicit approval for a real scan; placeholders below are not selected inputs:

```text
/usr/bin/python3 -B run_snapshot.py produce \
  --expected-producer-sha256 9a5091fb2db9ed571dcd015d1ad4d5cf92da2da76f1627291a20078095e9942a \
  --expected-auditor-sha256 3e8c18f18cc92b0841f91397d05441aaf4bed7a6eb47ec839aa4117f329e1fa0 \
  -- --pair-receipt <canonical-pair-path> \
  --expected-pair-receipt-sha256 <actual-out-of-band-pair-digest> \
  --output <fresh-owned-output-directory>
/usr/bin/python3 -B run_snapshot.py audit \
  --expected-producer-sha256 9a5091fb2db9ed571dcd015d1ad4d5cf92da2da76f1627291a20078095e9942a \
  --expected-auditor-sha256 3e8c18f18cc92b0841f91397d05441aaf4bed7a6eb47ec839aa4117f329e1fa0 \
  -- --inventory-receipt <owned-output>/receipt.json \
  --expected-inventory-receipt-sha256 <actual-inventory-receipt-digest> \
  --pair-receipt <same-canonical-pair-path> \
  --expected-pair-receipt-sha256 <same-actual-out-of-band-pair-digest>
```

The narrow selector authenticates exact pair/full-receipt bytes and binds the
selected archive role/hash and receipted endpoint identity. It deliberately
does not independently validate every provenance field, OTA/delta artifact,
full release file inventory, official checker or certificate. Its synthetic
fixtures therefore contain explicit synthetic identity assertions and do not
pretend to be valid full releases. Existing complete release/pair verifiers
remain separate publication prerequisites.

Outputs contain strict receipt/snapshot hash references, central-order raw
JSONL, lexically sorted member JSONL and exact portable content identities.
FD device/inode/timestamps are producer observations, not portable authenticity
claims; the auditor separately reopens/reobserves original bytes. Files are
streamed to owned temporary files and linked exclusively after fsync, never
overwriting prior evidence. An interrupted/failed scan retains completed
owned evidence and `failure.json`, not a success receipt.

Structural ceilings are fixed and receipted; metadata RAM, scan elapsed time
and real archive compatibility are unmeasured. No total RSS ceiling or
real-release execution readiness is established. Scans assume an owned
immutable release tree; stable FDs, hashes and pathname checks do not claim
to defeat a privileged writer modifying/restoring bytes during a read. The
existing production SafeZip symlink rejection and upstream APK checker
shared-UID/path comparison limitations are not repaired or waived here.
