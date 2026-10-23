# Wonad SDK 3.0.1 documentation-contract prototype

This directory is preparatory external evidence. It does not change the Wonad
repository, the API-v3 machine contract, an SDK repository, an APK, GrapheneOS,
a release index, a signer or runtime qualification. In particular, it leaves
the successor-19/packet-8 critical path on exact SDK 3.0.0 bytes.

The proposed smallest compatible correction is a documentation-only Maven
patch version, `org.wonad:desktop-sdk:3.0.1`, while `API_VERSION` remains 3.
No 3.0.1 publication exists. Its five primary artifact hashes and sizes are
explicitly null in `known-publications.json`, and the verifier refuses to
qualify it.

## Normative draft and source evidence

`API-v3.0.1-draft.md` is a complete, version-specific normative draft derived
from reviewed current `android/desktop-sdk/API-v3.md` SHA-256
`c4346a29317f6cf58a5549fb199c7d97aec437c31a5ece85525b3141f879daf5`.
It preserves every API-v3 section and adds source-true picker semantics:

- the one-second admission gate is a single process-global native `Picker`,
  shared across launcher and transfer kinds and all sessions/scopes for the
  hosting process lifetime; a process restart constructs a new picker;
- a successful open at monotonic time `T` rejects opens before `T+1000` and
  admits at the exact boundary only if every other condition also passes;
- cancellation, valid or invalid selection, expiry and scope/session changes
  neither reset nor extend that gate;
- nullable synchronous `launcherPage` reports no rejection reason;
- one-way `showTransferPicker` is fire-and-forget, and Binder return is not an
  admission or outcome acknowledgement;
- `interactionBlocked` is general protected-phone-UI state, not an exact
  acknowledgement for a particular picker request; API v3 has no exact picker
  accepted/rejected/displayed/selected/cancelled callback.

The unmodified picker implementation was copied byte-for-byte from
`android/broker-rust/src/native_picker.rs` at SHA-256
`b22bb4ffa4f1ecf12bca0a5b745149faff0dc1876707b2c0e6bb97eb317a04d5`.
The process-global ownership statement is independently tied to the exact
`static PICKER: Mutex<Picker>` declaration in
`android/broker-jni/src/native.rs` at SHA-256
`7bfe2e25d31c3a427a5af9e34527f4bb1e966e7477f4f9060b28991dec145737`.
`native_picker_boundary_test.rs` compiles the captured production module
directly, without reimplementing it.

The draft intentionally does not invent an acknowledgement API. If exact
per-request picker outcomes become a requirement, that is a separately
reviewed additive API design and publication (at least a new compatible API-v3
surface and capability contract), not a documentation correction.

## Immutable 3.0.0 distinction

The known public 3.0.0 inventory is the independently documented successor-13
publication. Its five primary artifact hashes are:

| Artifact | SHA-256 | Bytes |
| --- | --- | ---: |
| `desktop-sdk-3.0.0.aar` | `c1e164b7c57efd7f0997a90c92707cdaca16d1e5d3a47eb61197eb7b14fc4b07` | 44046 |
| `desktop-sdk-3.0.0-sources.jar` | `85d185c6c554d3f578c0961fecd007c67f98cb121390295c209843702eb7ae37` | 18612 |
| `desktop-sdk-3.0.0-contract.zip` | `ceb247ebddcbb97bfb085deaa5aa5314e143e4918978eb4f8b5ba5354cecbb5f` | 18537 |
| `desktop-sdk-3.0.0.pom` | `b519f9fb748dd17a02a220fdf1cbb0baab3a9a3dbd85c24895db1582c5ed32d0` | 1002 |
| `desktop-sdk-3.0.0.module` | `50f709c0361e15c38365eda0a488043f7fbdbffc6b09aa64e7b92489177c5099` | 3077 |

Its contract ZIP contains API documentation SHA-256
`1e0245930a69af3aa5687ac4bbc1c4134cc9433704a8d6d85b3a23500cc3189a`.
Later runtime compile evidence used the same 3.0.0 coordinate label with a
different contract ZIP (`3c8436ce...`) containing current documentation
`c4346a29...`. This prototype records that as a noncanonical historical compile
observation, not a replacement publication. It is a concrete reason to require
a patch-version coordinate for changed normative documentation.

The machine baseline and canonical signature remain unchanged:
`db6ac649c34d8c25ab0bdd4a46802639deb3972d376070c6c3cdd811d7962fff`.
Any future 3.0.1 build that changes that signature is not this docs-only patch.

## Prototype verifier

`versioned_publication.py` first validates unique-key, exact-type, exact-field
version inventory and all frozen source/document/artifact bytes. For known
3.0.0 it then runs the exact SHA-pinned production
`verify_sdk_publication.py` from successor-13. That production verifier retains
all complete Maven-tree, archive, AIDL wire, JVM ABI, source, baseline and
signature checks. Only after it succeeds does the prototype cross-bind the
exact version, coordinate, five artifact hashes and three contract members,
then re-hash every input to detect drift. The prototype adds no bypass or
weaker archive mode.

For 3.0.1 the verifier accepts the draft inventory as a draft but rejects a
publication-verification request because artifact hashes remain unknown. An
unknown version, a filled-in draft hash without a reviewed status transition,
a version-label substitution, a missing/extra artifact, a duplicate JSON key,
an alias boolean/integer, a changed document, or any production-verifier
failure is closed.

Run the bounded checks:

```sh
cd /u/elric/tree/wonad-phase1-build-evidence/phase1-sdk-3.0.1-doc-contract-prototype-20261012-1
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest -v test_versioned_publication.py
rustc --edition=2021 --test native_picker_boundary_test.rs \
  -o /tmp/wonad-native-picker-boundary-test
/tmp/wonad-native-picker-boundary-test --test-threads=1
python3 -B versioned_publication.py --verify-version 3.0.0
```

`python3 -B versioned_publication.py --verify-version 3.0.1` must fail with
“hashes remain unknown.”

## Complete migration map for a future reviewed publication

Nothing below is authorized by this prototype. These changes must occur only
after the exact-3.0.0 runtime campaign is no longer frozen.

| Area | Concrete current consumers | Required 3.0.1 consequence |
| --- | --- | --- |
| Normative source | `android/desktop-sdk/API-v3.md`, `android/desktop-sdk/README.md`, `android/EXTERNAL-SHELL.md` | Replace the normative source with the reviewed complete draft; state 3.0.1; preserve the old 3.0.0 table rather than rewriting history; add a new exact 3.0.1 table only from actual builds. |
| Publisher coordinate | `android/desktop-sdk/build.gradle.kts` | Change only Maven version to 3.0.1. API negotiation remains 3. Build all five fresh artifacts; do not rename/copy 3.0.0. |
| Production publication verifier | `android/tools/verify_sdk_publication.py`, `android/tests/test_sdk_publication.py` | Version every exact filename/path/XML/module-metadata expectation to 3.0.1; retain every current ZIP/tree/mode/size/wire/JVM/source/signature check. Add an explicit regression rejecting the known 3.0.0 artifact set under 3.0.1. |
| Machine contract | `android/tools/sdk_contract.py`, `android/tests/fixtures/desktop-sdk-contract-v3.json`, `android/tests/test_sdk_contract.py` | No semantic or signature change is expected. Re-run the complete ledger; reject any ABI, AIDL, constant or canonical-signature drift. Do not regenerate a different baseline merely to make a test pass. |
| Compile producer/auditor | `android/tools/build_native_successor.py`, `android/tools/native_current_compile_acceptance.py`, `android/tests/test_native_current_compile.py` | Change exact coordinate expectations and source closure; produce a fresh successor in a new output; independently verify the complete publication. Never relabel an older successor receipt. |
| Stage trust closure | `android/tools/stage_contract.py` includes `verify_sdk_publication.py`; `android/platform/stage-os.py`, `android/tools/release_receipt.py`, and provenance validators consume that ledger | A verifier change changes the stage-tool hash. Re-authenticate, restage to a fresh source tree, and generate fresh stage/release receipts. Existing OS/candidate evidence remains historical and cannot be reinterpreted. A docs-only SDK patch need not alter GrapheneOS runtime code, but the release closure still changes. |
| Client evidence | `android/tools/phase1_provenance.py`, `android/tools/phase1_emulator_client_packet.py`, `android/tools/release_receipt.py`, their acceptance tests | Update exact coordinate/path expectations; make a fresh client packet/candidate and copy the actual new doc/publication inventory. Project dependencies may compile identical classes, but no APK or packet byte equality may be assumed. Rebuild, re-sign with the already authorized selected development/release identity as applicable, and record actual hashes. No new key is implied. |
| Release assembly/index | `android/tools/phase1_release_index.py`, `android/tests/test_phase1_release_index.py`, `android/platform/PHASE1-RELEASE-INDEX.md`, `android/platform/PHASE1-PROVENANCE.md`, release-pair tools | Update the exact SDK coordinate only with fresh client/source/publication receipts; bind every actual artifact hash; generate a fresh aggregate index/pair. Old indices remain immutable 3.0.0 records. |
| Downstream modules | `:desktop`, `:broker-core`, `:conformance`, `:session-security` use `project(":desktop-sdk")` | Re-run all SDK, broker, desktop, conformance, security and publication tests. The source project avoids an external dependency substitution, but release receipts and bundled docs still change. |
| Signature and promotion | SDK publication has no implicit APK signature; repository promotion and APK signing are separate | Keep the API-v3 contract signature exactly unchanged. Obtain hashes from two independently verified publication builds before filling the 3.0.1 inventory. Use existing authorized signer custody workflows only; this prototype creates, reads and authorizes no private key. |

Suggested gated order:

1. Freeze and retain all current 3.0.0/runtime evidence.
2. Apply the reviewed normative source and version changes in a new source
   generation; update production verifier/tests without reducing any check.
3. Run the complete source/ABI/wire suite, then build two independent 3.0.1
   Maven repositories and require byte-identical five-primary-artifact hashes
   (apart from the already defined Maven index timestamp exclusion).
4. Fill a new immutable 3.0.1 inventory from those actual outputs; replace no
   3.0.0 row. Independently run the production and versioned verifiers.
5. Re-authenticate the changed stage-tool/source closure, produce fresh
   successor/client/candidate/release receipts, and re-run the normal runtime
   campaign. Documentation accuracy is not runtime qualification.
6. Only after independent aggregate verification may release metadata refer to
   3.0.1. Unknown hashes, mixed coordinate paths, old receipts, or a changed
   machine signature remain terminal failures.

## Limits

The Python and Rust results here prove bounded host semantics and fail-closed
inventory behavior only. They do not prove Binder scheduling, SystemUI UI
visibility, a Pixel device, a GrapheneOS image, signer custody, Maven promotion,
client compatibility in the field or any runtime gate. The current public API
still has no exact picker rejection callback; this draft documents that gap
instead of pretending a client timeout closes it.
