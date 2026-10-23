# Phase 1 OS signer-continuity semantic prototype v2

Date: 2026-10-11

Status: **external semantic prototype only; not a release gate, runtime
qualification, archive inventory, or cryptographic evidence**.

This fresh directory preserves v1 and its receipt byte-for-byte. V2 hash-loads
the frozen v1 policy and tests, adds two fail-closed input invariants, and then
delegates every v1 semantic check to the frozen implementation. All fixtures
remain synthetic. No Wonad/GrapheneOS source, staged tree, packet, image,
receipt, key, signature, ZIP, APEX, or running system was modified or used.

## Frozen basis

- design review:
  `../phase1-os-apk-signer-continuity-design-review-20261011-1.json`, SHA-256
  `b38704b9b85d7d0818f3bdcdde4c1af18fc398043bb6c6e7f46901da175b8055`;
- v1 receipt: `../phase1-os-apk-signer-continuity-prototype-20261011-1/receipt.json`,
  SHA-256
  `651a262fcc236fd4c97c1f12c49e919bb45d2bdff45ad6a1e62b78e260c2dea2`;
- v1 policy: SHA-256
  `4570e425bec60944de4e1d181d1a43d8a5cf224fae930736bdf1ab682534f788`;
- v1 test: SHA-256
  `be948981966804e26bf1487da26bb438a968f2602ee2f86c7bf3ef782a6600c0`.

The v2 loaders verify those last two hashes before importing any fixture or
policy behavior.

## V2 invariants

1. The policy, predecessor, and successor `schema` fields must each have
   Python type exactly `int` and value exactly `1`. In particular, `True` no
   longer aliases integer `1`.
2. Every physical `archive_member` has one logical owner within its containing
   archive namespace and endpoint:
   - partition APK/split members and outer APEX/CAPEX members share the
     `target-files` namespace;
   - embedded APK members use a namespace for the enclosing actual APEX name;
   - identical embedded relative paths in two distinct APEX payloads are
     valid;
   - identical text in target-files and an embedded APEX namespace is valid;
   - the same member text in predecessor and successor is valid because they
     are different archive endpoints; and
   - cross-owner aliases within one namespace fail, including partition
     package/split aliases, outer APEX aliases, and outer-APEX/partition
     collisions. Structurally malformed suffixes still fail under v1.

Repeated records for the same logical package/split or APEX identity are left
to v1's more specific duplicate-identity checks; they remain rejected.

## Actual tests

Frozen v1 unchanged:

```text
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B ../phase1-os-apk-signer-continuity-prototype-20261011-1/test_signer_continuity_policy.py
```

Result: **45/45 passed** in 0.031 seconds.

The dedicated RED suite runs the desired invariants against the actual frozen
v1 entry point:

```text
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B test_v1_hardening_red.py
```

Result: **5 tests ran, 5 expected assertion failures, exit 1**. V1 accepted
both boolean-schema cases and all three cross-owner alias cases.

The v2 suite replays all 45 frozen semantic tests through the v2 entry point
and adds 11 hostile/control tests:

```text
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B test_signer_continuity_policy_v2.py
```

Result at 2026-10-11T20:44:22Z: **56/56 passed** in 0.043 seconds.

## Next smallest real producer component (not implemented)

The next bounded component should be an authenticated archive-inventory
emitter. It should authenticate an exact release-pair receipt and both exact
target-files bytes, open each archive with bounded `SafeZipFile`-style limits,
reject duplicate/aliased central-directory members, and atomically emit a
canonical member manifest containing endpoint identity, namespace, member
path, type (`apk`, `apex`, or `capex`), size, and SHA-256. It should retain the
raw archive listing and exact producer/tool source identities for a separate
auditor.

That component deliberately stops before package identity, signer, or APEX
payload claims. Subsequent producers still need pinned `aapt2`, strict
`apksigner` DER-certificate extraction, authenticated source role mappings,
CAPEX decompression, APEX outer/payload verification, complete embedded-APK
enumeration, and an independent auditor. V2 therefore closes no release gate.
