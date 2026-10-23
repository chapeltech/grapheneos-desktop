# Phase 1 OS signer-continuity semantic prototype v3

Date: 2026-10-11

Status: **external semantic prototype only; not a release gate, runtime
qualification, archive inventory, or cryptographic evidence**.

V3 preserves v1 and v2, including the v2 receipt, byte-for-byte. It corrects
one loader binding defect in v2 while retaining the complete v2 semantic and
scope limitations. No repository, GrapheneOS/Wonad source, staged tree,
packet, image, key, signature, archive, receipt, or runtime was changed.

## Frozen basis

- design review SHA-256:
  `b38704b9b85d7d0818f3bdcdde4c1af18fc398043bb6c6e7f46901da175b8055`;
- v1 policy SHA-256:
  `4570e425bec60944de4e1d181d1a43d8a5cf224fae930736bdf1ab682534f788`;
- v1 test SHA-256:
  `be948981966804e26bf1487da26bb438a968f2602ee2f86c7bf3ef782a6600c0`;
- v2 receipt SHA-256:
  `41cc3e81aa0ff2a6b3ccb494cc64d7922b939736caed599e0c45652433ad961d`;
- v2 policy SHA-256:
  `fabf2a059337368a008b114a7dba43090a3350f05984726430c32c6b1ecb5995`;
- v2 fixture support SHA-256:
  `52f1f3804a3f2f46420b93ccf98fa99dc47ac6e4f3eaf4bf0ad55e09381206ff`.

## Loader correction

V2 read and hashed source bytes, then used
`spec_from_file_location(...).loader.exec_module(...)`. That loader reopens
the pathname and may also consult bytecode cache state, so the bytes executed
were not necessarily the bytes authenticated.

`authenticated_source.py` performs one `Path.read_bytes()` call, authenticates
that captured byte string, compiles that same byte string, and executes the
code object into a fresh `ModuleType`. It explicitly sets `__file__`,
`__package__`, `__loader__`, and `__spec__`, and does not add the module to
`sys.modules`. The policy's `_load_frozen_v1` and fixture support's
`_load_v1_policy` and `_load_v1_tests` all use this helper. They do not use an
import source loader and cannot execute post-hash pathname contents or a `.pyc`
fallback.

## Actual tests

The deterministic v2 RED suite hash-loads the exact frozen v2 policy/support,
uses only controlled temporary source, and changes each temporary pathname
between v2's hash and import-loader reopen:

```text
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B test_v2_snapshot_load_red.py
```

Result: **3 tests ran, 3 expected assertion failures, exit 1**. Each frozen-v2
loader returned the controlled post-hash marker rather than the authenticated
marker. Neither v2 nor v1 was modified.

The v3 loader suite performs the same timing deterministically by changing the
temporary pathname from a mocked `compile` boundary. It proves that the
captured authenticated bytes supply the marker and function, the changed path
remains changed but is not executed, the module is not cached, hash mismatch
does not compile, all three callers route exact path/digest/name triples
through the helper, and the real fixture/policy functions still work:

```text
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B test_snapshot_loader.py
```

Result: **5/5 passed** in 0.003 seconds.

The semantic suite replays all 45 frozen v1 tests and the 11 v2
schema/archive-member hostile and control cases through v3:

```text
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B test_signer_continuity_policy_v3.py
```

Result at 2026-10-11T20:49:59Z: **56/56 passed** in 0.043 seconds.

## Preserved limitations and next design only

All endpoint inventories, signer identities, paths, and evidence references
remain synthetic. V3 opens no target-files archive, extracts nothing, and
performs no APK/APEX/CAPEX identity or cryptographic verification. It closes no
release gate.

The next smallest real producer remains an authenticated, bounded target-files
archive-inventory emitter. Its proposed boundary is: authenticate the exact
release-pair receipt and both exact archive bytes; inventory a fresh regular
file descriptor with central-directory/path/count/size/compression limits;
reject duplicate physical members; and atomically emit canonical endpoint,
namespace, member, type, size, CRC, and SHA-256 observations plus raw listing
evidence for an independent auditor. It must stop before package identity,
signer, role, shared UID, or APEX payload claims. This component is design-only
and was not implemented here.
