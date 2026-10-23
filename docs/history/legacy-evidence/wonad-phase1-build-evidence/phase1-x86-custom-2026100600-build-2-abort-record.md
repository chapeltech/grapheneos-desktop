# Phase-1 x86 custom build 2 — intentional abort record

Recorded: 2026-10-11.

This was a development build of the `phase1-custom-4` staged source. It was
intentionally stopped at 5,272 / 167,940 Ninja actions (3%) after independent
review found that `NativeDesktopController.recentsDestination` could fall back
from a removed selected display to another live display. Continuing could only
have produced a candidate known to violate the Phase-1 fail-closed Recents
requirement. This attempt has no successful build receipt and qualifies no
artifact.

The first interrupt stopped the host launcher. The still-running build
container was then explicitly stopped with a 30-second timeout. Its resulting
exit status 137 is operator termination, not an OOM: Docker records
`OOMKilled=false`.

Retained evidence:

- Build log: `phase1-x86-custom-2026100600-build-2.log`, SHA-256
  `99e330f57da3821975043c3dab4d7c6211c0e768624505eec054d7972a67f31b`.
- Launcher preflight: `phase1-x86-custom-2026100600-build-2.log.preflight.json`,
  SHA-256
  `c4441a11719adf83dc270eb56e22ce686ae4ad9e3bf72a981b18c3e96e5f4f39`.
- Driver: `continue-phase1-x86-custom-4-from-baseline-receipt-8.sh`,
  SHA-256
  `a57d784dcabfb14b115f392b3cb1fe3596050dbbb749cc8d20d972aeec27e243`.
- Staged source:
  `/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-4`.
- Retained stopped container:
  `wonad-phase1-x86-custom-2026100600-2`, immutable ID
  `109bf2090b955eb35b41bbe3fc0aa5b53061b93b8c22cd1084ca3d320b804386`,
  builder image
  `sha256:f719a4a56095b613790ef9afcba2aabda795217ac98e08c24ba5cec65bd4ee33`.
- Docker lifecycle: started `2026-10-11T05:59:55.450407825Z`, finished
  `2026-10-11T06:14:36.238660338Z`, status `exited`, exit 137,
  `OOMKilled=false`.

The partial OUT root was
`/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-2`, device 64513,
inode 2133144630, UID/GID 1000/1000, mode 0700. Immediately before cleanup it
contained 66,019 regular files, 148,746 descendant directories, 805 symlinks,
two other build transients, and 14,383,140,864 allocated bytes. No process,
mount, successful receipt, or later build referenced it. It was therefore
approved for exact-path cleanup before the replacement `custom-5` build. The
root and contents are disposable intermediates; the retained evidence above is
the durable failure record.

The replacement source removes the fallback, has compiled regression coverage
for removed, stale-generation and ambiguous destinations, and must use fresh
source, OUT, log, preflight, container, receipt, prune and comparison identities.
