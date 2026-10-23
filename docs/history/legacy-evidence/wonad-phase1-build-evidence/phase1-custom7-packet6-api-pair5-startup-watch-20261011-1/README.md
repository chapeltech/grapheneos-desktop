# API startup watcher (unexecuted, unreviewed preparation)

This directory contains unreviewed preparation for a bounded, read-only
diagnostic watcher plus mock-only host tests. It is not approved for use, a
conformance producer, runtime result, or qualification gate. No
`authorization.json` or `evidence/` directory was created, and the watcher was
never run against Docker, ADB, an emulator, API pair 5, or any other guest.

The production entry point is deliberately inert unless root independently
creates the exact `authorization.json`, supplies its SHA-256, and passes
`--execute-after-root-authorization`. That record must bind one running
container's full ID, name, nonce, immutable image, guest boot ID, conformance
run ID, state directory, user, and KVM group. The watcher also authenticates
the reviewed pair driver, selection, container-profile source, Docker-locality
source, and its own bytes before and after observations.

After exact container-profile and guest-boot checks, it waits only for the
full-mode `enabling-external-ui` status. It then records at most three bundles
at offsets 0, 4, and 9 seconds. Each subprocess is bounded to 3 seconds and
512 KiB; each bundle is bounded to 10 seconds. The only guest commands are
read-only `dumpsys`, `logcat -d`, and `/proc` boot-ID reads. It has no start,
stop, signal, settings, input, install, log-clear, or producer-output path.
Every terminal document states
`READ_ONLY_DIAGNOSTIC_NOT_RUNTIME_EVIDENCE_OR_PASS`, `runtime_pass=false`, and
`release_qualification=false`.

The production constants bind the now-stopped pair-5 paths. Consequently this
exact file must not be pointed at another target. A later fresh boot requires
a separately reviewed create-only successor (or an exact reviewed authority
whose fixed pair-5 paths are still applicable), not a retargeting of retained
evidence.

Mock-only validation command:

```text
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -m unittest -v test_watch_api_startup.py
```

Final observed result on 2026-10-11: 9 tests passed in 0.353 seconds. Coverage includes
success with exactly three samples, wrong container identity, stopped state,
resource-profile drift, wrong guest boot ID, timed-out and oversized reads,
malformed/duplicate/foreign run status, and source-authority mutation. A
compile-only in-memory check of both Python sources also passed. These are
host mocks only and make no claim about a guest or image.
