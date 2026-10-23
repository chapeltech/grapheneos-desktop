# Native baseline AOSP-host attempt 2 — failed, not qualification

The authenticated run terminated with exit 2. The retained original generator
reported `Host-test container differs from the sealed isolation profile` after
the Soong invocation failed. No complete `host-run-receipt.json` was produced.
The disposable workspace was removed by the runner's authenticated cleanup;
the original preflight, sealed inputs, invocation streams and cleanup remain.

Blueprint normal and race invocations each recorded 2,605 passed native test
cases. Soong was incomplete: `TestZip2Zip64` and `TestCopyFromZip64` reached
`signal: killed`; the affected packages failed. Passing portions are not a
qualifying complete run or a reason to omit the failed large-buffer tests.

During diagnosis, a read-only Docker daemon event query showed two OOM events
for the exact Soong container
`dcfcb5084ba80ece9e1f8b9e169b0ddc259eb7a98e1461aadb67857a3bd5251e`
at Unix times 1791707139 and 1791707407, followed by exit 1 and removal.
Those earlier query results were observed in the tool transcript, not sealed
as an original inspect file. The later retained daemon query in
`DOCKER-FAILURE-EVENTS.json` returned no events: Docker's bounded retrospective
event history no longer retained this interval. Do not treat that empty query
as either native OOM proof or proof that no OOM occurred. The original Go
stream independently retains the killed-process failures.

The original resource profile capped each invocation at 8 GiB. The normal
Zip64 tests build multiple 4-GiB-plus in-memory archives, so the next reviewed
profile retains all ten full normal/race invocations while setting `-p=1`,
`GOMAXPROCS=4`, `GOMEMLIMIT=40GiB`, and a 48-GiB container limit with no extra
swap. Production runs now require at least 44 GiB available host RAM, and
failure paths retain the exact observed container inspect before removal.
Do not run that memory-intensive retry alongside the current OS build.

Original generator SHA-256:
`de2d3a44a296631ad04514041956fe9e370e487d084237200c53461d185eb895`.
Original plan SHA-256:
`aaa5281d70338bc3d87d8fbbca2682b1d5e3ab9865d8992ae936009aefa40870`.

Retained evidence SHA-256 values:

- Blueprint normal stream: `53d676c9a9aa7d9e4bb7f2aef7b961ed96cf0e3de0c6f29d3fd566b9b75b973e`.
- Blueprint race stream: `05959fb54220c772d210d7795f67d268ff5005c00c7b489a0d1910dcf3fca6e8`.
- Soong stream: `e72626df8339e9cec3432263f34766f8504dd821cf5071361b5238713015c2ae`.
- Workspace cleanup: `8db7ef141bf6cf2d2c88b2ece4c72d1ba3b97b8e0ad2f764afdfb9508ba2ce5d`.
- Later daemon observation: `eb4f49b03bd68af7c13c050e0bd3a4a944543f03c120fb51a2fcd4592f6415ce`.

This note is a failure/diagnosis record, not a native passing receipt. Preserve
this attempt unchanged; use a new output/workspace/name for a later retry.
