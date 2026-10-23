# Read-only failed vendor extraction-cache audit; cleanup NOT authorized

The original G6/G7/G8/G9 receipts select WORK5/6/7/8 respectively. Every work root currently contains only its retained official ZIP clone and `unpacked/`. The only child of `unpacked/` is `frankel-CP3A.261005.005-tmp`. The bounded census covered 348 entries and 268 regular files across those four exact temporary extraction trees, not the source checkout or filesystem generally.

| Attempt / work | Cache regular allocation and observed unshared extents | Cache root inode | Current exact-owned Docker terminal state |
| --- | ---: | ---: | --- |
| G6 / WORK5 | 1,807,400,960 B | 748053014 | exited, PID 0, exit 1, OOM false; original 32 GiB |
| G7 / WORK6 | 8,276,877,312 B | 850928068 | exited, PID 0, exit 137, OOM false; original 32 GiB |
| G8 / WORK7 | 8,276,877,312 B | 1268892996 | exited, PID 0, exit 1, OOM true; original 40 GiB |
| G9 / WORK8 | 8,276,877,312 B | 2400338690 | exited, PID 0, exit 1, OOM false; original 48 GiB |

FIEMAP was read with flags 0, without forcing sync, reading file contents, hashing ZIP/partition bytes, or extracting anything. It reports 26,638,032,896 B (24.81 GiB) of currently unshared regular-file extents, with pairwise-disjoint physical ranges across the four cache trees and no unknown/delayed/shared cache extents counted. Directory/symlink allocation adds only 16,384 B and is excluded from the estimate. All regular files have one hard link. Each ZIP clone instead has 11,378,667,520 B of mapped **shared** extents and zero observed exclusive extents: do not count its apparent size as reclaimable storage.

At the summary observation, source filesystem availability was 81,595,912,192 B. Adding the observed four-cache unshared extents gives 108,233,945,088 B (100.8 GiB), approximately 4.8 GiB above the 96 GiB admission floor. This is a current metadata estimate, not reserved future storage or a guaranteed post-delete `statvfs` delta. ARM must pass its real admission after any specifically authorized cleanup and intervening fixture writes.

## Exact prospective scope

The three larger caches alone total 24,830,631,936 B (23.13 GiB), projecting 106,426,544,128 B (99.12 GiB) at this observation. A minimal scope could retain WORK5's smaller cache and consider only these **literal** targets:

- `/u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-vendor-cache-work-20261012-6/unpacked/frankel-CP3A.261005.005-tmp`
- `/u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-vendor-cache-work-20261012-7/unpacked/frankel-CP3A.261005.005-tmp`
- `/u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-vendor-cache-work-20261012-8/unpacked/frankel-CP3A.261005.005-tmp`

If more headroom is explicitly chosen, the fourth literal candidate is `/u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-vendor-cache-work-20261012-5/unpacked/frankel-CP3A.261005.005-tmp`.

This proposal is not permission to remove any target. The standing stopped-workspace preservation policy requires an explicit exception for the selected cache subtree(s). Preserve all WORK roots and `unpacked/` parent directories, all official ZIP clones, canonical factory cache/archive/receipt, original logs/preflights/results/attempt locks, Docker containers, source/.repo/out/vendor payload, keys, userdata, and unrelated failure evidence. No globs, broad parent deletion, source-cache cleanup, or Docker mutation belongs in this scope.

## Evidence and reproducibility distinction

The original receipts bind WORK directory device/inode/owner/mode, ZIP path/size/official hash identity, canonical factory metadata, source root identities, attempt-lock identity/hash, preflight, and exact container identity/profile. These current joins all pass. They do **not** bind an immutable inventory of the interrupted `unpacked/*-tmp` bytes. Deleting a selected temporary subtree can preserve every listed receipt-bound root/ZIP/lock/log/preflight/result/container identity, but it intentionally destroys the exact crash-time partial extraction state. The sealed metadata/FIEMAP inventory cannot reconstruct those un-hashed partial bytes.

The retained ZIP and pinned upstream algorithm can regenerate the **complete expected partitions**, not necessarily byte-identical interrupted outputs. WORK5's `product.img` is only 229,867,520 B; the later caches' version is 4,859,404,288 B. All four remain `-tmp`, with no successful atomic rename to the completed unpack directory. Call them disposable regeneration candidates only after the forensic-preservation trade-off is accepted; do not describe them as already-qualified vendor output or exact replay of failure.

Authenticated factory identity is `frankel-cp3a.261005.005-factory-3721e6ac.zip`, 11,378,664,978 B, SHA256 `3721e6accc2e87d851ee7966d794318078ec74c7cc32343daa10968264d6bb62`, from canonical receipt SHA256 `458273099a83f97c60ed6ba1a7a40e14704f850b04068443946ca65e78dbe6c3`. Its bytes were NOT rehashed by this audit.

The twelve original named source inputs were individually matched to their original preflight hashes; see `current_source_inputs` in the summary. In particular, upstream `vendor/adevtool/src/config/paths.ts` is `418823cca30a381208e13acd7ea30d5ff37be411f1492ccd05f290ba4c95bd8e`, and `vendor/adevtool/src/frontend/source.ts` is `001de5cab8ae7524ba862135d7663a467a7b49ae0fea733d044090c40a728ca9`. `paths.ts:34–35` maps the authenticated work bind to `unpacked/`. `source.ts:139–160` removes a previous temporary subtree, recreates it from the official image, removes write permissions and atomically renames only after successful unpack. `source.ts:177–192` independently verifies the official ZIP SHA before extraction. Future regeneration must use a separately admitted authenticated vendor workflow and fresh workspace, retaining full official dependency preparation; this audit does not authorize it.

## Required proof immediately before any authorized cleanup

1. Authenticate this evidence record, original receipt/preflight/lock/log hashes, and exact selected canonical target paths and device/inode/owner/type identities. Reject aliases, changed root identity, mounted descendants, hard-linked regular files, unexpected special entries or any non-allowlisted sibling.
2. Under the existing trusted no-restart/no-competing-writer policy, acquire the source advisory lock and hold it through cleanup. Reinspect each **exact old ID** and original profile/nonce/binds. Require exited, PID 0, not running/paused/restarting/dead; OOM is a failed build outcome but does not negate stopped state. Do not validate the 40 GiB G8 container with the current 48 GiB matcher or infer stop from a stale receipt.
3. Reject any actually live relevant vendor/build/VM lane or competing source/work writer. Retained failed containers remain preserved and must never be restarted. An advisory lock and trusted policy cannot exclude an arbitrary Docker administrator; no hostile-admin guarantee is claimed.
4. Use a separately reviewed, exact fd-relative/no-follow removal allowlist confined to the selected cache roots, with fresh failure/removed-entry evidence and bounded revalidation. This proposal deliberately contains no deletion command or implementation.
5. Recheck that all protected roots/ZIPs/locks/logs/preflights/results and exact Docker identities remain; seal an honest pruning receipt naming the discarded partial state, then measure actual free space and run fresh ARM admission. Reclaim accounting is not build success or release qualification.

## Observations and limits

`g6-observation.json` through `g9-observation.json` retain each individual raw Docker inspection, exact current file metadata, FIEMAP count/flags/totals and hash of each physical mapping ledger. `summary-observation.json` binds all four original receipts and twelve current source inputs. `audit.py` is stdout-only, uses metadata ioctls without archive/partition data reads, and performs no deletion/container mutation. `replay.py` rejoins raw inspection hashes, original nonce/name/lock/source/canonical-factory custody, file ownership and cache totals.

The first ad-hoc supplemental replay incorrectly required raw Docker bytes from separate inspections to be identical and failed for G6 because Docker reordered its three-element `Mounts` array. Each exact mount **set**, original profile, state and identity passed; the retained per-generation raw transcript is independently hashed. The corrected replay keeps the independent observation epochs distinct and passes. The earlier full stdout census exceeded the display output limit; it is not a retained complete raw record. The bounded final per-attempt projections and summary are complete and separately pinned.

No deletion, cleanup permission, source-wide walk, image hash/extraction, Docker start/stop/removal, key/userdata access, OS build or runtime qualification occurred.
