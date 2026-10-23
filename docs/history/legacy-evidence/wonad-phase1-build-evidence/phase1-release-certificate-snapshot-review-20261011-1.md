# Release-index certificate identity and algorithm correction

This is host verifier regression evidence only. It does not attest a production
signing ceremony, sign an artifact, qualify an image or execute a phone/guest.

## Reproduced defects

Root passed the actual packet3 public Wonad certificate to the previous
`validate_public_certificate`. Both `RSA-4096` and `ECDSA-P256` declarations
were accepted for that same certificate. The validator authenticated DER and
subject but trusted the allowed algorithm label without inspecting the key.
Two new genuine-certificate test methods failed before the correction (four
failed subtests/assertions, tool chunk `869cf0`). They covered relabelling a
real RSA-3072 key and admitting RSA-2048 through an allowed RSA-3072 label.

Independent review additionally found a split-snapshot defect: the frozen
provenance helper hashed file A, then parsed DER/subject by pathname. Swapping
to B for those subprocesses and restoring A before algorithm inspection could
mix A's file hash with B's DER identity. Root reproduced that exact schedule
with two genuine P-256 test certificates and the real OpenSSL subprocesses.
`test_path_swap_back_cannot_mix_certificate_identity` failed before the
snapshot correction (tool chunk `07c99c`, one failure).

## Final implementation

Only the release-index verifier, its tests and its contract documentation were
changed. `phase1_provenance.py`, all sixteen stage-tool closure inputs, staged
custom7 source and the live OS build inputs were not edited.

`public_certificate_snapshot` obtains one stable, hash/size-authenticated
byte snapshot. Pinned OpenSSL parses DER, subject and key information from that
same stdin payload, never via a mutable certificate pathname. Hermetic locale
and OpenSSL configuration are fixed, and the tool identity/version is checked
again uncached after parsing. The record must exactly match that DER identity,
subject, RSA size or EC curve. Only RSA-3072/4096 and P-256/P-384 are accepted;
RSA-PSS, RSA-2048, secp256k1, ambiguous parser output, parser failure, snapshot
drift and tool drift are rejected. Certificate signature algorithm is not used
as subject-key identity. The existing returned public-certificate shape and
aggregate schema are unchanged.

Ephemeral unit-test private keys are discarded directly to `/dev/null` by
OpenSSL; they do not enter public evidence or production key custody.

## Verification

- Focused algorithm/snapshot and ceremony tests: 17/17 passed, 2.653 seconds,
  tool session `72232`, terminal exit 0.
- Final combined release-index, Frankel build and release launcher tests:
  128/128 passed, 3.610 seconds, session `65576`, terminal exit 0.
- An earlier neighboring invocation accidentally named two nonexistent test
  modules and failed import (session `48714`); it is not passing evidence. The
  final command below uses the actual module names and supersedes it.

An independent replay passed the complete 89-test release-index suite in
2.616 seconds and accepted the final scoped implementation with no remaining
concrete defect. Its strict structured review is
`phase1-release-index-certificate-snapshot-review-20261011-1.json`, SHA-256
`741c45ce422e43a0f6ff20903064fc54935705bea2ba09889c0eea41653856b4`.
This does not globally repair the frozen provenance helper's old path-based
certificate parser; that helper is bypassed only on the corrected index path.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=android/tests python3 -m unittest -q \
  test_phase1_release_index test_frankel_build_tools test_release_build_launcher
```

Final reviewed inputs:

- `android/tools/phase1_release_index.py`:
  `5b09fb4873d61f173ea5ed59c6568ededf7dafe38d766621d98db40de02d8ec4`
- `android/tests/test_phase1_release_index.py`:
  `1fa61965d2c362522b584808d0516b56c1ff08d41c24de4edac4761e51e5f8e3`
- `android/platform/PHASE1-RELEASE-INDEX.md`:
  `fd935c5b6e0db828f2ce600b7e2ae5b21e73e15ec9fe8aeadaa0c33030ee1dbc`

Packet3 public PEM input:
`65e326ada8f623cd6e1852d6fefba8262f445bcd5949966e10361c6d770c70a3`.
This is development-only input, not the unselected production signer.

Protected-key identities, real signed release pair, channel ownership and
physical OTA qualification remain outstanding. No production/aggregate receipt
was created by this correction.
