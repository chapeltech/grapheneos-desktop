# Desktop SDK publication

`desktop-sdk` is the policy-free, frozen Phase-1 API v3 library.  It is
published independently from the Wonad APK so third-party APK builds consume
the same Binder wire contract as the OS.

Publish to the local staging repository with:

```sh
./gradlew :desktop-sdk:publishReleasePublicationToPhase1Repository
```

The new candidate coordinate is `org.wonad:desktop-sdk:3.1.0`; it adds opt-in
fixed shortcut keys and an ordinary client prompt. Existing methods and wire
values remain compatible. The original 3.0.1 artifacts must never be overwritten.
Its machine ledger is `tests/fixtures/desktop-sdk-contract-v3.1.json`; the
original `desktop-sdk-contract-v3.json` remains the legacy compatibility oracle.

The preceding Maven coordinate is `org.wonad:desktop-sdk:3.0.1`.  The immutable version
directory contains exactly an AAR, sources JAR, contract ZIP, POM and Gradle
module metadata, plus Maven checksum sidecars.  The types-only AAR has no
permissions, components, resources, policy or native library.  The contract
ZIP contains exactly:

- `API-v3.md`
- `desktop-sdk-contract-v3.json`
- executable `verify-desktop-sdk-contract.py`

From the Android source directory, fail closed on any unexpected repository or
archive content with:

```sh
python3 tools/verify_sdk_publication.py \
  desktop-sdk/build/phase1-repository
```

The equivalent Gradle entry point, which publishes first, is
`./gradlew :desktop-sdk:verifyPhase1Publication`.

To compare two independently built staging repositories:

```sh
python3 tools/verify_sdk_publication.py out/publication-a \
  --compare out/publication-b
```

The comparison first verifies each publication completely, then requires
byte-identical hashes for all five immutable versioned artifacts.  Maven
generates `maven-metadata.xml/versioning/lastUpdated` from publication wall
clock time; only that repository-index timestamp and its checksum sidecars are
excluded from reproducibility comparison.  They are still syntax- and
checksum-verified in each repository.

The schema-3 contract includes a deterministic ledger of every exported JVM
class and every public/protected field and method, including descriptors,
generic signatures, checked exceptions and constant values. The verifier
derives that ledger directly from the published AAR; changing a Kotlin or AIDL
binary signature therefore cannot pass merely because the class filenames are
unchanged.

Run the negative host tests with:

```sh
python3 -m unittest -v tests/test_sdk_publication.py
```

Publishing never signs with an implicit or development identity. Signing and
repository promotion are separate release operations using the selected Wonad
signer. The immutable canonical 3.0.0 publication remains historical evidence;
3.0.1 is a documentation-only patch to the same API-v3 machine contract and
must be built twice and independently verified before any artifact hashes are
promoted into release metadata.

The [two-workspace rebuild proof](../out/phase0-sdk-rebuild-20261020-1/README.md)
now reproduces all five existing 3.0.1 publication artifacts byte-for-byte in
distinct networkless containers and clean workspaces, with build-cache reuse
disabled. Both outputs pass source-contract, JVM and publication checks. The
pinned prebuilt tools image is shared; this is not a whole-OS reproducible build,
independent privileged review, production signing or complete Phase 0 handoff.
