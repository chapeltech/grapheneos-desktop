# Custom-5 build superseded: contained keyboard routing

Date: 2026-10-11. This is an intentional development-build stop, not a compiler
failure, a passing build receipt, or a release qualification.

## Stop decision

The actual custom-5 `KeyGestureController.interceptKeyBeforeDispatching` handles
trusted paste and returns before the only Wonad containment check. A blank or
protected claimed monitor can therefore grant/pass a paste event instead of
consuming it. `WonadUiBridge` deliberately publishes containment before fallible
focus reconciliation. Native InputDispatcher snapshots the target display and
focus token before the later policy callback and supplies that exact display in
the KeyEvent; a null, moved or stale focus token cannot be used to waive input
containment.

The reproduction extracts and compiles the actual frozen dispatch method with
the pinned JDK and modeled bridge/paste collaborators. It is bounded compiled
control-flow evidence, not an emulator clipboard exploit or Android runtime
acceptance. Both blank and protected cases returned `NOT_CONSUMED`, produced a
paste grant for UID 10123/display 3, and called the containment bridge zero
times. Root independently reran the reproduction and observed the same traces.

- Original result:
  `/u/elric/tree/wonad/android/out/phase1-static-contained-paste-repro-20261011-1/run/result.json`,
  SHA-256 `2d0a4e982046da3dcc1caec764fa8d348be0fda7b5df77ced35c599166caa712`.
- Independent result:
  `/u/elric/tree/wonad/android/out/phase1-contained-paste-root-replay-20261011.GapNkV/run/result.json`,
  SHA-256 `7143107f9e36a67c3caf12943f07bcbfa813d740f092364a37f7590ed9ea6cb2`.
- Frozen Java source SHA-256:
  `398d1c08872625bc7af0567c5f15e7c64b5d6cd835c807b5b21a6e7c1dfeeaeb`.

## Exact retained build identity

- Source: `/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-5`.
- OUT: `/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-3`.
- Container: `wonad-phase1-x86-custom-2026100600-3`.
- Full ID: `e0b8c6076f4eb1453ffad03bb5e0c3d1f39a68ee6e6b5fa0eae0f1891b3f1c60`.
- Log: `/u/elric/tree/wonad-phase1-build-evidence/phase1-x86-custom-2026100600-build-3.log`.
- Preflight SHA-256:
  `d39fb04a196dc7625aa9de7311f402d43619a21c0eb054c6cb9055371ed32972`.
- Stage-marker SHA-256:
  `5015daa149185f2376ff719026b8e7cf86556d8dc81f1e3e225f54f077b12cd3`.
- Continuation-driver SHA-256:
  `cde0b5f59708e1ac16324c29599ffd6282030dcc2dcaad178844e3320ae45cb6`.

Before the stop, Docker independently showed that exact ID running, not OOM
killed, and the build was around 77% complete. No source, patch, frozen helper,
log or preflight input was modified while it ran. The stop command targets only
the complete recorded container ID. The launcher preserves its log, source,
partial OUT and container on nonzero exit. No build receipt/comparison, image,
prune, or runtime qualification is to be derived from this attempt.

## Authoritative terminal state

The intentional stop is complete. An independent exact-ID inspection recorded
Docker status `exited`, `Running=false`, `Paused=false`, `Restarting=false`,
`Dead=false`, PID 0, exit 137 and `OOMKilled=false`, with no Docker error. The
container started at `2026-10-11T06:38:24.550020658Z` and finished at
`2026-10-11T10:53:56.815779309Z`. No matching launcher or build process remains.
The retained log ends at 129,280 / 164,999 actions (78%). Exit 137 therefore
records the deliberate operator stop; it is not evidence of an OOM, compiler
failure, successful build, or qualified artifact.

The partial OUT remains present and has not been pruned. Its root is device
64513, inode 723136731, UID/GID 1000/1000 and mode 0700; a read-only measurement
reported 71,620,825,088 allocated bytes (about 66.7 GiB). It is not a successful
receipt or image. The stopped container, source, log, preflight, and abort
evidence remain the durable history of this attempt.

Input containment/claim-incarnation and generation-safe preclaim
shortcut-lease fixes are being applied and tested in the workspace. No fixed
source has yet been staged for a replacement, and no replacement build has
been launched. Any replacement must use newly staged source and new
build/output/evidence paths; never mutate this preserved source in place. Any
later partial-OUT disposal requires a separately authenticated exact-path
inventory and explicit authorization and must preserve this record and the
other retained evidence.

## Bounded disposable-OUT cleanup

At 2026-10-11 11:23:22 UTC root confirmed the exact partial OUT was absent
after the bounded cleanup completed with exit status 0 (execution session
61660). This removed only the generated intermediates from this aborted build;
they are reproducible from the preserved source/driver, not recoverable as
deleted files. No source, container, log, preflight, marker or successful
baseline output was removed.

The retained read-only preflight is
`phase1-x86-custom-2026100600-build-3-out-disposal-preflight.json`, SHA-256
`a6d6624f039bd9d0240eff2ca7fb6de258b9c7d32b0043f9398635a3d2076d57`.
The exact-purpose audit helper is `audit-custom5-aborted-out-20261011.py`,
SHA-256 `831b9fe0b02d0cd656d4ef07c09c8f82c2cedafa068d10b8198315106fa7ea26`.
It confirmed root device/inode/UID/GID/mode
`64513/723136731/1000/1000/0700`, 71,620,825,088 allocated bytes,
449,453 regular files, 175,454 descendant directories, 809 symlinks and exactly
one unused FIFO/socket each. There was no nested mount, no live process open
reference, and only the recorded terminal container retained an OUT bind.
The complete audit was rerun immediately before deletion. The commands were
bounded to the literal target, without following symlinks or crossing mounts:

```sh
find /u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-3 \
  -xdev -depth -mindepth 1 -delete
rmdir -- /u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-3
```

Postflight reauthenticated the log, preflight, driver and source stage-marker
against the same SHA-256 values in the retained cleanup preflight. The exact
container remained `exited`, not running, not OOM-killed, exit 137, PID 0.
`/u` then reported 150,554,193,920 bytes available. This is space recovery from
disposable output, not a successful build, candidate image or qualification.
