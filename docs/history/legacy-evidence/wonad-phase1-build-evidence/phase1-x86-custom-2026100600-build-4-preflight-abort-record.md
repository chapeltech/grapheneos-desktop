# Custom6 build-4 preflight — intentionally stopped before compilation

Root started the fresh continuation at 2026-10-11 12:46 UTC, unified session
79843, driver PID 3492599 and launcher PID 3492897. Exact schema-4 stage and
public-certificate binding passed, followed by baseline receipt `-8`
reauthentication. The launcher entered its custom-source audit.

A read-only OS-glue review then found that a sticky claimed monitor with no
valid live lease lets a newly populated ordinary app handle keep Android's
default input admission. The compiled production-method extraction test
`android/tests/test_native_app_input_lease_loss_compiled.py` compiled and failed
at the explicit unavailable-lease assertion. Its original SHA-256 is
`9a62755d3fed4c4590c4347fbaf57348275b3bdde9e9d790be5825c9ef3d6b2a`.
The original reviewed NativeBridge SHA-256 is
`aeb2e4788d6037f0ebd09b354a67a78db772582a6a72627bcb61d4993e8432a8`.
This reproduces a new input-handle population defect, not a claim about
zero-latency withdrawal of previously published handles.

At 12:56:42 UTC root authenticated the exact driver argv, launcher parentage,
and shared PGID/SID 3492599. The intended external OUT, log and Docker container
were absent before signalling. Root sent SIGTERM to that exact owned group;
session 79843 then returned exit 143. A postflight process-group query found no
remaining member, and Docker still proved the intended container absent.

No compiler/build container, OUT, preflight record or build log had been created:

- source: `/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-6`;
- intended OUT: `/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-4`;
- intended container: `wonad-phase1-x86-custom-2026100600-4`;
- intended log: `phase1-x86-custom-2026100600-build-4.log`.

The historical continuation driver remains unchanged, SHA-256
`c5cccca05036385537f226723c2891839ab64f3a768607eb4523b15b0bb0d439`.
The actual source remains separate and unchanged, preserving marker SHA-256
`188202963aeee9c1ffe45fbd334c0d066d5b39888be85a126d96046e8ba4e3bc`.
There is no successful custom6 build receipt, image or qualification. This was
an intentional preflight stop, not a compiler failure or OOM. No source, build
OUT, userdata or historical evidence was removed. A corrected build must use
a separate staged source and fresh attempt paths after the fix is independently
reviewed and tested.
