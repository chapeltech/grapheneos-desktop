# Native AOSP host attempt 1 — terminal, not qualified

The baseline run in unified exec session 36133 terminated with exit code 1.
It completed the build/source/retained-OUT preflight, but the first Blueprint
invocation did not create a Docker container or execute a Go test.

Docker rejected the generated writable bind option `rw` because `--mount`
requires a supported mount field. The subsequent inspect error obscured that
original command failure in the terminal traceback. The original output is
preserved at `aosp-baseline/invocations/blueprint/go-test.jsonl`, SHA-256
`d1232b5aafbf25a35881edd5a0fdcb466d8d853d87f2a5cbc372137bfbd84175`.
This is a Docker error log, not a native test result despite its planned name.

The producer removed only its authenticated disposable test workspace.
`aosp-baseline/cleanup.json`, SHA-256
`09caecd9eef337eb28f44bd47486dde73da79f5ddd478a18a51c28cc5505b60b`,
records both workspace and quarantine absent. Source, receipted OUT, preflight
evidence, copied generator and logs remain unchanged. No host-run receipt
exists and no upstream test pass is claimed.

The host and isolated Atest generators were corrected to use
`readonly=false`. A separate real-Docker diagnostic launched the exact
immutable builder/source-RO/fresh-test-OUT/resource-isolated profile and ran
the pinned `go version` command, which reported `go1.25.4 linux/amd64`.
Its evidence directory is
`/u/elric/tree/wonad-phase1-upstream-cli-smoke-20261011.65v9sr8w`.
Container `444de1928d46dd13c963d4efe95cfb675844165443803f195c747715ab52c640`
was independently inspected against the profile and removed by exact identity.
That CLI diagnostic is not upstream coverage or release qualification.

The next qualifying attempt must use a new evidence/output/workspace path
and reauthenticate all inputs with the repaired generator. The first attempt's
files must not be overwritten or promoted into a passing record.
