# Native baseline retry 4 — failed memory admission

Observed terminal on 11 October 2026. This is retained diagnostic evidence,
not a qualifying native-host receipt or release result.

The exact foreground process was PID 3334030, unified execution session 53775.
The session returned exit status 2, and subsequent process/container checks
confirmed the process and every owned test container were absent. Its original
terminal diagnostic was:

```text
phase1_generic_upstream_evidence.py: Full AOSP-host tests require at least 44 GiB available RAM; wait for competing builds to finish
```

Complete source authentication finished, and the normal and race Blueprint
invocations both exited 0. Root replayed their original `go-test.jsonl` streams
with `parse_go_json`: each has 2,632 ledger entries, comprising 2,621 passed and
11 skipped entries. These include package-level Go entries, not just named
test cases. Both exact container records retain successful owned cleanup:

- normal: `0ba6a4213effd7ef35ec4ca1818443c2a46ee4f5bb34e34e1f17619ad8847374`;
- race: `c906b9a6927caf5c9344966cd49f1255b354e69ca5af98a045bc847dd21c2ec0`.

The memory guard rejected the next invocation before a Soong test container
started. The other eight required invocations, post-run input authentication
and final receipt publication did not complete. There is no
`host-run-receipt.json`, and partial Blueprint success does not qualify this
campaign. No full OS build was running alongside it.

## Inputs retained unchanged

- `aosp-baseline/inputs/generator.py`:
  `ca8df17d791b4fd1c807180ae998d4b92c6af6511c2cd67e195dcb7736a3f292`;
- `aosp-baseline/inputs/plan.json`:
  `ba5c43e1bc2a2239aaf4677d483bb9d7eb3c62e0b9a6f94924a06bf503a1c386`;
- `aosp-baseline/inputs/build-receipt.json`:
  `f71729d38c1f5e1da8ce34975c7269bff53cb9e8b46de7455eacdaf676f4afb3`;
- `aosp-baseline/cleanup.json`:
  `85281c944668116a6166b07aaecc19d016606b5f72bda2e3a8e18f9ee0e4f0b4`.

Retain the native Go streams, container records and preflight observations.
Do not overwrite this attempt or manufacture a successful receipt from it.

## Bounded cleanup

The runner's authenticated cleanup removed only its own fresh disposable
workspace, `/u/elric/tree/wonad-phase1-upstream-native-20261011-r4.7j9Lkw/disposable-aosp-baseline`.
The retained cleanup record binds device 64513, inode 1894392971, UID/GID
1000:1000 and nonce `9befe4d7dc00326eec9146a3258a8a8c`.
Its disposable inventory was 4,020 entries / 399,615,528 bytes; both the
workspace and rename quarantine are absent. This cache is reproducible, not
recoverable as original files. The protected GrapheneOS source, receipted build
OUT and failed-attempt evidence were not deleted.

## Memory diagnosis and retry boundary

The read-only process audit observed a 1,908,880-KiB RSS high-water mark and
roughly 1.73 GiB of anonymous resident memory after source authentication,
with only one thread remaining. The retained preflight JSON totals roughly
1.63 MB. The source collector's two complete 72-worker project-tree audits
leave allocator/thread arenas resident after their data dies; retained evidence
size does not explain the process footprint.

The proposed fix isolates the unchanged complete source collection in a
one-shot child whose exit releases those arenas. It must preserve every
source check, the ten normal/race invocations, the 44-GiB admission guard and
the 48-GiB container cap. Any retry needs a new parent, test workspace,
container prefix and output. No retry or memory fix is proved by this record.
