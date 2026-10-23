# Native host-memory admission diagnostics — bounded review

Date: 2026-10-11. This is source/host-test evidence, not a native campaign,
Docker execution, OS build, guest result or release qualification.

Native attempt 5 remains terminal. Its original diagnostic did not record the
actual rejection-time MemAvailable observation. No later sample or this change
can reconstruct that missing fact. Original attempt inputs and partial results
remain unchanged and cannot be combined into a passing receipt.

## Reviewed change

The current `require_host_memory()` reads `/proc/meminfo` exactly once, records
the observation-completion Unix timestamp and reports source, threshold and
the exact parsed MemAvailable bytes/KiB when rejecting an insufficient sample.
Read failures and missing, malformed or ambiguous lines fail closed with typed
failure status and unavailable numeric fields instead of an invented value.

Root review caught cross-line permissiveness in the first diagnostic revision's
`\s` expression. The final implementation enumerates physical candidate lines
and accepts only horizontal whitespace within a full line; split value/unit,
whitespace-only and valid-plus-malformed duplicate controls now fail closed.

Unchanged policy: 44 GiB host admission, the before-campaign and pre-normal-
Soong checks, all ten normal/race invocations, full normal Zip64 coverage,
48-GiB/no-additional-swap container limits, and the reviewed plan. This helper
is outside `STAGE_TOOL_PATHS` and the live x86 build's staging-tool ledger; no
frozen OS source or live build helper changed.

Final files:

- `android/tools/phase1_generic_upstream_evidence.py`, SHA-256
  `cf04b0eadac75217837b53e87749a50fbb5e4713ba1eacbe6704461e5aa6a0a9`;
- `android/tests/test_phase1_generic_upstream_evidence.py`, SHA-256
  `69f083a4dc8ab236380351193a169e13951ce7903fa98f08cdeb091435f9b128`.

## Observed tests

The implementation owner passed the four focused controls and all 36 generic
module tests. Root independently ran:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=android/tests python3 -m unittest -q test_phase1_generic_upstream_evidence test_phase1_upstream_isolated_comparison test_phase1_upstream_test_comparison
```

Session 31787 terminated with exit 0: 73/73 passed in 5.525 seconds on the
final source/test bytes. Tests cover equal/above-threshold acceptance, exact
below-threshold diagnostics, malformed/split/duplicate input and read failure,
plus existing evidence/container/coverage/comparator boundaries.

The bounded retained-JSON RSS replay does not identify attempt 5's rejection
cause or prove sufficient memory for the whole campaign. A new native attempt
must retain these final helper bytes, satisfy the unchanged admission policy,
complete every invocation and post-run authentication, and use fresh paths.
None was launched for this change; the sole heavy lane is the custom7 OS build.
