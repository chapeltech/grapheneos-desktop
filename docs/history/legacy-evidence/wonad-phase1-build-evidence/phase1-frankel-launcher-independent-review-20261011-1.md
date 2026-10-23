# Phase 1 Frankel launcher independent review — 2026-10-11

## Scope

This is a bounded, read-only review of the frozen Pixel 10 (`frankel`) ARM64
build launcher safety slice. It is not evidence that an ARM build ran, a
measurement of ARM peak resource use, runtime qualification, release
qualification, or production approval.

Reviewed files and observed SHA-256 identities:

- `android/tools/run_frankel_build.py`: `7ff1350466d813b3dd6cc9f597131a3240025ff965ca4cb2f768f0564a838be1`
- `android/tools/frankel_build_comparison.py`: `6b963fa8d2c888a3972891e235685043d1564cb73ff91e9064a1e8ae44174cbe`
- `android/tests/test_frankel_build_tools.py`: `aa859609b8f36694c76be2067afa785a57b5dcaa668733f3ef9f3359170d587f`

The identities were checked before and after the review and remained equal.

## Focused test execution

From `/u/elric/tree/wonad`, the exact command run was:

```text
python3 -m unittest android.tests.test_frankel_build_tools
```

Observed result:

```text
..............................
----------------------------------------------------------------------
Ran 30 tests in 0.306s

OK
```

This test command did not launch a Docker container, vendor preparation, an OS
build, an emulator, or a guest.

## Checks performed

The review checked that the launcher and independent receipt/comparison tool
consistently bind and validate:

- the `frankel-cur-user` lunch target, fixed `-j6`,
  `NINJA_HIGHMEM_NUM_JOBS=1`, and the exact targets
  `vendorbootimage`, `vendorkernelbootimage`, `target-files-package`, and
  `otatools-package`;
- the immutable builder image ID and fixed cleared process environment;
- Docker network isolation, UID/GID, dropped capabilities, source and external
  OUT bind topology, and retained named-container behavior;
- 6 CPUs, 48 GiB memory, 48 GiB memory-plus-swap, and a 4096 PID limit (equal
  memory and memory-swap values deliberately allow no additional container
  swap);
- admission floors of 42 GiB host `MemAvailable`, 96 GiB free on the OUT
  filesystem, and 16 GiB free on the Docker-root filesystem;
- one native resource observation before the source audit and a second after
  fresh OUT creation, immediately before preflight/log publication and Docker
  invocation, including monotonic ordering and exact directory identities;
- exact launcher contract, command, source/toolchain snapshot, Docker locality,
  attempt/locality labels, and resource evidence in the preflight and receipt;
- retained-container exit status 0, `OOMKilled=false`, exact resource limits,
  mounts, image/process profile, and exact retained logs;
- full receipt revalidation and equal baseline/custom build contracts with
  distinct source, OUT, and container identities.

The current host's OUT parent and Docker root were observed on distinct XFS
filesystems during this review, so their separate free-space floors do not
double-count the same free blocks on this host.

## Result and limitations

No concrete introduced defect, qualification bypass, or current Docker-profile
compatibility mismatch was found within this bounded scope.

No vendor preparation, network download, full source audit, Docker container,
OS build, emulator, guest, or ARM build was run. The 42/96/16 GiB thresholds
are launch-admission guards, not empirical ARM peak measurements. A first real
ARM build may still exhaust resources; this review does not claim otherwise.
