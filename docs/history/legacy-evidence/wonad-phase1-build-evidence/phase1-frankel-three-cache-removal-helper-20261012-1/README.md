# Prepared exact-three-cache remover — NOT authorized to run

Only these interrupted extraction-cache subtrees are in the immutable code allowlist:

- `/u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-vendor-cache-work-20261012-6/unpacked/frankel-CP3A.261005.005-tmp`
- `/u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-vendor-cache-work-20261012-7/unpacked/frankel-CP3A.261005.005-tmp`
- `/u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-vendor-cache-work-20261012-8/unpacked/frankel-CP3A.261005.005-tmp`

WORK5 is excluded. WORK roots, `unpacked` parent directories, ZIP clones, canonical factory archive/receipt, logs/preflights/results/attempt locks, source/.repo/out/vendor payload, existing Docker containers, keys and userdata remain protected. Opaque factory ramdisk symlink entries inside the selected subtrees are unlinked, never followed; FIFOs/devices/sockets and regular-file hardlinks are refused. Directory entries are deliberately visited from an authenticated exact old inventory, not from a recursive parent/glob deletion command.

The sealed read-only owner record `275c378a564ed3ccb107cd93fc670168166ba37ff9391d17757aabeaae93fc6a` and all its exact reference hashes are reauthenticated. The original observation helper `b2abe8cdabc01dbbde344a760d74a08213e07d459a0d615c184fb0b281dcbfbd` is compiled from its stable hashed bytes, without rewriting it or creating historical bytecode caches. Its exact original Docker-profile inspector preserves G7 32 GiB, G8 40 GiB and G9 48 GiB profiles; the current 48 GiB vendor matcher is never used to waive an old-profile mismatch.

Before any source advisory lock or mutable output, the main path requires the explicit action flag, actual reviewed helper SHA and exact SHA of a future literal root/user authorization receipt. That receipt does not yet exist and must not be fabricated by this preparation. Only root may create it after the user's target-specific stopped-workspace exception and full source/test review. The helper requires UID/GID1000, exact targets/scope/source/old audit pin/helper/test pins and unique strict JSON with no extra fields.

Once separately authorized, the source directory lock is held across fresh protected custody checks, running-container RW-source/cache overlap and vendor-process rejection, exact original stopped-container/nonce/bind/resource proofs, complete descriptor-relative no-follow cache census and current FIEMAP equality, removal and final custody/space checks. Each old container must also retain its exact original terminal state and start/finish timestamps: restart-then-stop is not original custody. OOM remains failure but is compatible with a proven original terminal state. No container start/stop/remove/reconfigure occurs.

Every absolute directory component is opened with `O_DIRECTORY|O_NOFOLLOW`. Cache entry FDs stay on the parent's mount ID, current mountinfo forbids mounted target/descendant paths, and the old inode/owner/mode/type/size/timestamp/extent inventory must match before the first mutation. Removal uses only `unlink(child,dir_fd=...)` or `rmdir(child,dir_fd=...)` on admitted entries, with per-entry revalidation. There is no chmod, broad parent removal or ZIP/image byte hash/extraction.

The fresh output must be absent: `/u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-three-cache-pruning-20261012-1`. It receives durable exclusive `intent.json` before cache mutations, an append-and-fsync removed-entry journal, then a no-overwrite `pruning-receipt.json`. The receipt preserves primary/partial failures, already-completed removals even if journal writes fail, protected identities and actual before/after statvfs bytes. A receipt-volume error emits the partial record to stderr instead of silently returning success or replacing an earlier pruning error. Unknown failures are not declared successful pruning. Removing interrupted byte state is explicitly irreversible without a prior byte copy; the retained official ZIP can regenerate complete partitions, not exact crash prefixes.

The observed 23.13 GiB unshared extent estimate is not reserved or a guaranteed filesystem delta. The receipt reports actual free space; fresh ARM admission is required afterward. The source lock/no-writer checks are within the trusted administrator/agent no-restart policy, not a guarantee against arbitrary root/Docker administrators or undisclosed writers. Physical mount/inode races from privileged actors are outside that policy. No cryptographic release/runtime qualification follows from cleanup.

## Host tests

`PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -m unittest -v test_remove_three_vendor_caches`

Actual final result: 24/24 PASS, 0.046 s, tool chunk `668e13`. Tests only use disposable host fixtures, pinned read-only receipt metadata and mocked container inspectors/removal operations/source locks. No real cache target is opened by the remover, deleted, or changed; no actual source lock or Docker operation is invoked. The synthetic full lifecycle tests prove partial receipt fields but do not count as a real pruning receipt. Initial source-authoring syntax and misplaced-test errors are retained separately, not presented as production RED defects.

## Future authorization shape — pending user/root decision

The only accepted authorization path is `/u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-three-cache-cleanup-root-authorization-20261012-1.json`. It must have exactly these keys:

`schema`, `kind`, `user_exception`, `scope`, `targets`, `source`, `audit_owner_sha256`, `helper_sha256`, `host_tests_sha256`.

Required kind is `phase1_exact_three_interrupted_vendor_cache_cleanup_authorization_v1`; scope is `discard_only_interrupted_extraction_bytes_preserve_all_other_custody`. The root must bind the real reviewed helper/test hashes and exact literal target/source/old owner identities. `user_exception=true` is only truthful after user approval; no such record is created here.

A future root-reviewed command would use `/usr/bin/python3 -B remove_three_vendor_caches.py --execute-after-explicit-cache-exception-and-root-review --reviewed-helper-sha256 <actual-reviewed-helper-SHA> --authorization-sha256 <actual-root-user-authorization-SHA>`. This is a description, not an executable authorization. No actual CLI main, check-only live admission, source lock, cache mutation, Docker operation, build or guest was executed during preparation.
