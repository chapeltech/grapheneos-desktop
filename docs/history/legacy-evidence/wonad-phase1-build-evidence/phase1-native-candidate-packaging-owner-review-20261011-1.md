# Phase-1 native-candidate packaging owner review — 2026-10-11

## Scope and result

This is a bounded implementation and host-test record for strict x86 native
candidate packaging and its two strict downstream consumers. It is not a
candidate-image build, Android boot, runtime test, release qualification, or
physical-device result.

The final implementation has no known concrete defect in the reviewed scope.
It:

- binds strict packaging to immutable base image
  `sha256:0bf80454dbaa59bacd955d3e0140d8c91c4dcbd4d6e3e941274cdf10cb374b3f`,
  its exact reviewed manifest and exact unqualified labels;
- removes `/product` and `/opt/wonad` in the new layer, then reconstructs them
  from the exact reviewed StyX/grsh support allowlist and fresh product, client,
  wrapper, notices and evidence inputs;
- uses the packet's immutable, hash-bound `apksigner` executable and JAR to
  inspect the exact receipted finished `SystemUI.apk` and packet `fault.apk`,
  requires their one v3 signer to equal the packet's development platform
  signer, and inventories both raw verification transcripts;
- independently replays/cross-binds that proof in the bundled verifier, fresh
  conformance derived builder, and native runtime matrix admission;
- clears inherited qualification/evidence claims by constructing a fresh,
  explicitly unqualified manifest and by requiring the exact final label set;
- checks an output tag before work and again immediately before publication.

Docker does not offer compare-and-swap tag publication. The second check closes
the long build interval, but both primary and derived publication still require
the local candidate-tag namespace to remain quiescent during the final
check/tag instruction interval.

## Reviewed immutable predecessor

Root's earlier read-only, networkless verifier run was session `95569`, exit 0.
The saved verifier manifest is:

`/u/elric/tree/wonad/android/out/native-v3-candidate-close-settle-20261010-1/manifest.json`

- raw file SHA-256:
  `0776da645016d2d49039d9c00019ff8c6f1ffd6f8ef8831afd5d4358ba1ad3cf`
- canonical manifest SHA-256:
  `7aa1f429dc6be79bc19fc248e679ef270fc147a8988009ebcdbfece9a1af6bfe`
- exact inventory: 37 paths (11 `/product` and 26 `/opt/wonad`)
- the saved inventory exactly equals the implementation's
  `REVIEWED_BASE_FILES` set

The exact-37 constraint is deliberately applied only by
`validate_phase1_base_image` to this reviewed predecessor. Generic offline
verification accepts a newly packaged strict candidate's six legitimate added
files (four authenticated build documents and two signer transcripts), after
which the derived builder applies the strict Phase-1 evidence schema. This
repairs an integration blocker without weakening predecessor inheritance.

## Red-before provenance

The first three focused regressions were written before the initial fixes. On
the old implementation they produced one failure and two errors:

- an unreviewed inherited evidence path was accepted;
- no final publication recheck helper existed;
- no exact SystemUI/fault signer verifier existed.

A later real-verifier-path regression passed a strict candidate manifest with
the six new evidence files through mocked Docker stdout only. Before the scoped
inventory fix it errored in `native.verified_base_manifest` because the exact
37-file predecessor allowlist was applied unconditionally.

Two derived-builder regressions were also red before their fixes:

- a duplicated `sha256sum` row was collapsed by a dictionary and accepted;
- an intervening output tag was not rechecked immediately before publication.

The final code requires both three raw checksum rows and three unique paths,
and the derived builder publishes through the same final
`native.publish_candidate` gate.

## Final file identities

- `android/container/build-native-candidate.py`:
  `70ccf59510dfcf11217e640c180016c7fb5d2d22b1da9adb38bd59c100cd226d`
- `android/container/Dockerfile.native-candidate`:
  `f498d9f7c5648814cc3e5bf1ca2f80b808b14608735070c87561a216470914ff`
- `android/container/entrypoint.py`:
  `946dc7d337bfd78ff25bc3efb568717f1b0596c98e799476713a8a11ab5a56ba`
- `android/container/build-phase1-conformance-candidate.py`:
  `e7fefbb11298e0bbecfd8b0db6c0986175700a911f24de27fff6b756455ad8c7`
- `android/tools/run_native_matrix.py`:
  `f29b136a2ea62c02c7c722f2746a4ce92b8ea666e87ba1c0656d028d7d68be8e`
- `android/tests/test_native_candidate_container.py`:
  `bfac79328d0ac61dfac788df3aeaa4918cb5e1b101ff24f3edb42e2ff4b2b552`
- `android/tests/test_phase1_fresh_conformance.py`:
  `c5ede09bc2e6ac7550906669012fac56478eb7f79275ec6d8664460449d979a2`
- `android/tests/test_native_matrix.py`:
  `d92ae9f6f113bba66afd09a0864a9bda454a5ac08a6b44d92a564c58de1cd5cc`
- `android/EXTERNAL-SHELL.md`:
  `ea7f16149243c3e595431d8097cc42e10658cb34e595fc3fef38094405f3ba26`

All seven changed Python production/test modules compile from source.

## Host-test evidence

Before the final three regressions were added, the system-Python combined run
reported 117 tests with 116 passes and one documented Pillow-environment skip
in 3.728 seconds. The skipped native-matrix CLI parser test independently
passed 1/1 in 3.116 seconds under the existing Pillow 12.3 interpreter. Root
then replayed that coherent revision as 117/117 with no skips in session
`70413` (7.400 seconds).

After the final inventory, duplicate-row and derived-publication fixes, the
owner ran:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=android/tests \
  /srv/wonad-os37-pending-permission-3/wonad-styx-live.0DimSmO9/x11-test-venv/bin/python3 \
  -m unittest -v test_native_candidate_container \
  test_phase1_fresh_conformance test_native_matrix
```

Result: 120/120 pass, zero skips, 7.589 seconds. The independent metadata
reviewer replayed 120/120 with zero skips in session `62352` (7.618 seconds)
and found no remaining concrete defect in this bounded slice. Root's final
broader combined regression was 400/400 with zero skips in session `24785`
(14.535 seconds).

The independent machine-readable review is retained at
`/u/elric/tree/wonad-phase1-build-evidence/phase1-native-candidate-packaging-consumer-review-20261011-1.json`,
SHA-256
`ff4c55d7e3bef00ba949109c8e3fe1d969584080aac7738d2cc092d9c91c1d3f`
(13,665 bytes). It independently pins all eight production/test inputs,
records the 120-test replay and derived-base function-chain probe, and preserves
the same non-atomic publication and no-image/no-runtime limitations.

No Docker container, candidate build, OS build, emulator, Android guest, APK
installation, or runtime campaign was launched by this implementation/test
work. The signer transcripts exercised here are synthetic hostile/valid host
fixtures. Actual transcript creation for the new candidate, verification of
that new immutable image, and runtime qualification remain post-build work.

## Exact post-build command template

Do not run this until the live custom-7 OS build has completed successfully and
the custom receipt and exact baseline/custom comparison have been produced and
independently verified. The two unresolved input identities (comparison and
custom receipt) are intentionally represented by four path/hash placeholders:

```text
python3 android/container/build-native-candidate.py \
  --product /u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-5/target/product/emu64x \
  --apk /u/elric/tree/wonad/android/out/phase1-emulator-client-packet-20261011-3/wonad.apk \
  --output /u/elric/tree/wonad/android/out/phase1-native-candidate-custom7-5-1 \
  --base-image sha256:0bf80454dbaa59bacd955d3e0140d8c91c4dcbd4d6e3e941274cdf10cb374b3f \
  --tag wonad:native-v3-candidate-phase1-custom7-5-1 \
  --phase1-build-evidence \
  --phase1-comparison <ABSOLUTE_CUSTOM7_COMPARISON_JSON> \
  --phase1-comparison-sha256 <CUSTOM7_COMPARISON_SHA256> \
  --phase1-baseline-receipt /u/elric/tree/wonad/android/out/phase1-x86-baseline-2026100600-receipt-8.json \
  --phase1-baseline-receipt-sha256 f71729d38c1f5e1da8ce34975c7269bff53cb9e8b46de7455eacdaf676f4afb3 \
  --phase1-custom-receipt <ABSOLUTE_CUSTOM7_RECEIPT_JSON> \
  --phase1-custom-receipt-sha256 <CUSTOM7_RECEIPT_SHA256> \
  --phase1-client-packet /u/elric/tree/wonad/android/out/phase1-emulator-client-packet-20261011-3 \
  --phase1-client-packet-receipt-sha256 986f00bcebc7e215200621eac6bbbc2c580a2617759700106f0cba9d1c8abfad
```

At execution time, recheck that the output directory and tag are absent, the
base image is locally present under its exact immutable ID, packet-3 remains at
the stated receipt hash, and the build/comparison receipts authenticate the
exact retained custom-7 product. Success would produce only an unqualified
candidate; it would not itself satisfy runtime or release gates.
