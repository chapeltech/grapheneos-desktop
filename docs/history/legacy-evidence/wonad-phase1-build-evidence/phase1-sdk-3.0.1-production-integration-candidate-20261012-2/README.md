# SDK 3.0.1 production-integration candidate

This directory is external preparatory evidence. Nothing here has been applied
to `/u/elric/tree/wonad`, built, published, signed, staged into GrapheneOS or
runtime-qualified. `current/` captures the exact reviewed production inputs;
`proposed/` is a candidate source snapshot with the smallest reviewed 3.0.1
integration delta plus fail-closed downstream evidence binding. The original
candidate and its expected-RED/189-test replay remain preserved separately.
The live SDK, shared tools, stage, OS, packets and runtime
evidence remain unchanged.

## Outcome

The viable change is a Maven documentation patch,
`org.wonad:desktop-sdk:3.0.1`, while Binder `API_VERSION` remains exactly 3.
The proposed normative document describes the current source behavior:

- picker admission cadence is one process-global native clock shared by
  launcher and transfer picker requests;
- an admitted request at `T` moves the earliest next admission to `T+1000ms`;
  cancellation, selection, expiry and scope/session changes do not reset it;
- `launcherPage` is synchronous and nullable, but null has no exact reason;
- `showTransferPicker` is one-way/fire-and-forget, so Binder return is not an
  accepted/displayed/selected/cancelled outcome;
- `interactionBlocked` is general protected-phone-UI state, not a per-request
  acknowledgement.

No AIDL, Kotlin API, JVM ABI, constant, transaction, parcel order, capability
or runtime implementation changes. The exact machine-contract signature stays
`db6ac649c34d8c25ab0bdd4a46802639deb3972d376070c6c3cdd811d7962fff`.

## Candidate inventory

Changed production snapshots:

1. `android/desktop-sdk/API-v3.md`, `README.md`, and `build.gradle.kts`;
2. `android/EXTERNAL-SHELL.md`, preserving the canonical 3.0.0 table as
   history and adding no unknown 3.0.1 artifact hashes;
3. `android/tools/verify_sdk_publication.py`, versioned to 3.0.1 while retaining
   every current exact Maven tree, ZIP, mode, source, AIDL, JVM and signature
   check; its authenticated result additionally emits exact SHA-256/size/mode
   for all three contract members;
4. exact coordinate/document-member consumers in
   `build_native_successor.py`, `native_current_compile_acceptance.py`,
   `phase1_provenance.py`, `release_receipt.py`, and
   `phase1_release_index.py`; the native compile auditor independently derives
   all three member identities from the sealed ZIP, and native/provenance
   validators require SHA-256 values to be strings rather than coercing them;
5. focused publication/current-compile/provenance/release-receipt test
   snapshots.

Unchanged but mandatory for the future integration test run are
`sdk_contract.py`, the schema-3 machine fixture, their tests, release-index
tests, `stage_contract.py`, `stage-os.py`, the packet producer and release-pair
verifiers. `integration-map.json` binds every current/proposed file and these
unchanged dependencies.

The exact proposed normative document is SHA-256
`60dba59139f7c6c692c533095edc9243fb67ebe24c24696b45dce72ba542d856`
(17,997 bytes). That is a reviewed source candidate, not a claim that any
3.0.1 publication exists. All five 3.0.1 artifact hash/size fields and every
future receipt/result remain explicitly null.

## Why the document digest is a primary trust input

The contract ZIP already requires exact source equality for `API-v3.md`, the
machine JSON and bundled verifier. The candidate production verifier also
returns an exact `contract_members` map with SHA-256, byte count and normalized
mode for each. `build_native_successor` stores that complete result beside the
complete Maven file inventory. The compile auditor independently opens the
already inventory-bound sealed ZIP and recomputes all three SHA-256/size/mode
rows before accepting the producer result. Client provenance replays the full
publication verifier and compares its result and inventory with the compile
receipt; release receipt and release index retain their downstream bindings.
Thus the
normative document is independently named and content-bound in addition to
being transitively covered by the contract ZIP hash; it is not merely prose or
an advisory repository file.

## Canonical 3.0.0 and relabel protection

`integration-map.json` retains the independently documented canonical 3.0.0
five-artifact inventory and its original API document member. A later runtime
compile labeled 3.0.0 carried different document/contract ZIP bytes; it remains
an explicitly noncanonical observation. It cannot seed 3.0.1.

The candidate verifier expects the exact 3.0.1 directory, filenames, POM,
Gradle module metadata and Maven index. An old 3.0.0 repository, a mixed tree,
or a POM/module/index relabel fails. The focused synthetic test includes an
actual 3.0.0-coordinate mutation.

## First-publication bootstrap

No predeclared artifact hash is needed to verify the first actual 3.0.1 build:
the production verifier authenticates the complete shape, source equality,
machine signature, derived JVM ABI and normative contract members. The safe
promotion sequence is:

1. retain all existing 3.0.0 and current runtime evidence unchanged;
2. apply this exact reviewed source delta in a fresh source generation;
3. run the full SDK/source/wire/ABI and downstream host suites;
4. build two fresh Maven repositories from that same frozen source generation,
   verify each independently, and compare all five immutable primary artifacts;
   only Maven `lastUpdated` and its sidecars may differ;
5. create a new immutable external 3.0.1 publication inventory from those
   observed outputs without editing the frozen source or replacing 3.0.0;
6. independently replay the verifier and inventory, then create fresh
   successor/client/stage/build/runtime/release evidence.

This avoids a hash bootstrap loop: actual hashes are evidence produced after
the two builds, not constants inserted into source before a build.

## Why a fresh OS stage and rebuild are mandatory

`verify_sdk_publication.py`, `phase1_provenance.py` and `release_receipt.py`
are members of `stage_contract.STAGE_TOOL_PATHS`. Their hashes change in this
candidate. The SDK documentation, Gradle version and verifier also enter the
fresh successor/client source closure. Existing stage markers compare the
complete tool ledger and therefore cannot accept the new bytes. Consequently:

- restage a fresh authenticated GrapheneOS checkout;
- make fresh x86 and Pixel 10/Frankel builds and receipts;
- make fresh client packets/candidates and rerun the normal runtime campaign;
- build a new aggregate release index/pair.

Even if the generated classes or OS runtime code happen to be byte-identical,
old evidence proves the old tool/source/coordinate closure, not 3.0.1. A
documentation-only SDK patch is not authority to relabel an old OS or skip the
normal production signer/custody workflow.

## Bounded checks

These checks are host-only. They start no Docker container, Gradle/JVM daemon,
emulator, VM or build:

```sh
cd /u/elric/tree/wonad-phase1-build-evidence/phase1-sdk-3.0.1-production-integration-candidate-20261012-2
PYTHONDONTWRITEBYTECODE=1 python3 -B verify_candidate.py
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest -v test_candidate.py
cd proposed/android/tests
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest -v test_sdk_publication.py
```

The separate complete captured host replay ran 192/192 tests (the original
189 plus three permanent binding regressions) with zero skips. It is retained
under `phase1-sdk-3.0.1-full-host-replay-20261012-2`; its guarded subprocess
ledger permits only Git, Git LFS, OpenSSL, the current Python, and temporary
fixture-local `apksigner` scripts. The copied full SDK publication test uses
synthetic ZIP/class fixtures only;
it does not invoke Gradle. Future integration must additionally run every
current production test suite, two independent real publication builds, fresh
stage/build/client/runtime verification and the complete release index.

## Limits

This candidate does not establish any 3.0.1 artifact identity, publication,
repository promotion, OS build, APK byte, signer action, runtime behavior,
device result or release qualification. It deliberately does not modify the
live repository, current SDK/tool inputs, or any active build/runtime lane.
