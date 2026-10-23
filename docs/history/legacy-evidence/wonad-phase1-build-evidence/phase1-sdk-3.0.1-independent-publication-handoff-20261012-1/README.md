# SDK 3.0.1 two-publication handoff

This external handoff prepares two independent, library-only publications of
the currently reviewed Wonad SDK 3.0.1 source. It has not been executed. It
does not build or sign an APK, build an Android product, launch a VM, restart
the existing SDK tools container, or alter the historical SDK 3.0.0
publication.

## Frozen inputs

- `source-manifest.json`:
  `de356f5143e4c7d3be53fef4cb69030f0986b355336fb9ea86110b00d516ace3`
- exact 112-file record set:
  `6080720b9f15eac84ab5fe8d9ed1b3a95c8ce86f6518fe8a57a95fcd9cd6ba1b`
  (590,983 bytes)
- existing tool-authority plan:
  `android/out/native-current-successor-12-phase1-v3-runtime-20261012-19/plan.json`,
  `6d22d4ef85fb06190cebb305400b5709e24e1e2b3c549dbec43c73b69f4a2ed9`
- authority SDK-tools record:
  `a812e0e9a8d8d5720219cb5d878a2f44b47ae5154b69c54fa294aad53fc4219d`
  (the ten reviewed tools, 437 cached Gradle artifacts, and existing
  development-key identity)
- exact existing tools container:
  `51db87997ccb6b27fb5932a88b1187a748dd1908afdc32940f542a879f6b3aae`,
  image
  `sha256:3932d980fa538e61d95708d0cb037c0ebb8257bc2639c46f468d5ec7c75fd597`
- driver: `d59e9735be4b71391c19187ec412bbffe17e01ec3b2339160088181fd11e02d3`
- host tests: `28319f9d117540b484f7264b20718c2d62d64fc3cc3ae9b850e1e6735346478c`

The manifest and all 112 current paths were rehashed after the focus-routing
staging work; no path or byte changed. Actual SDK 3.0.1 artifact hashes remain
unknown until execution.

## Two-stage execution

Preparation is intentionally separate from compilation. It creates two
non-overwriting external source copies, authenticates the live immutable tools
container without restarting it, explicitly observes
`/opt/android-sdk/build-tools/35.0.0/aidl`, verifies all pre-existing tool and
cache pins, and emits a plan digest:

```sh
/usr/bin/python3.14 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-sdk-3.0.1-independent-publication-handoff-20261012-1/run_two_publications.py \
  prepare \
  --output /u/elric/tree/wonad-phase1-build-evidence/phase1-sdk-3.0.1-independent-publication-run-20261012-1
```

Only after independent review of the printed plan digest may the one-shot
build run:

```sh
/usr/bin/python3.14 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-sdk-3.0.1-independent-publication-handoff-20261012-1/run_two_publications.py \
  build \
  --output /u/elric/tree/wonad-phase1-build-evidence/phase1-sdk-3.0.1-independent-publication-run-20261012-1 \
  --expected-plan-sha256 PENDING_REVIEWED_PREPARE_DIGEST
```

For each lane A and B, the reviewed command is exactly an offline,
no-daemon, no-parallel, two-worker, 2 GiB-heap invocation of:

```text
:desktop-sdk:clean
:desktop-sdk:testReleaseUnitTest
:desktop-sdk:verifyPhase1Publication
```

The driver copies each fresh Maven repository out separately, runs the exact
source-matched verifier against each, inventories every output file, and runs
the verifier's `--compare` path. That comparison requires byte-identical hashes
for the AAR, sources JAR, contract ZIP, POM, and Gradle module metadata. Only
the already documented Maven repository `lastUpdated` index family is outside
that five-primary comparison; each repository index and all sidecars are still
independently validated.

Remote work directories are unique and retained for review. An attempted
build is never retried in the same output root. All subprocess argv, stdout,
return codes, start/end times, and repository file hashes are retained.

## Host-only validation

The following command ran without Docker or Gradle:

```sh
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3.14 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-sdk-3.0.1-independent-publication-handoff-20261012-1/test_run_two_publications.py -v
```

Result: 12 tests passed in 0.178 seconds. Coverage includes the current exact
112-file freeze, authority/tool hashes, immutable gate profile and lifecycle,
the newly mandatory AIDL identity, exact library-only Gradle argv, distinct
source/repository paths, strict 3.0.1/five-primary verifier protocols,
symlink rejection, independent byte-exact copying, and fail-before-side-effect
output validation.

This preparation is not a publication result, Android/JVM runtime ABI result,
OS-stage result, or production-release claim.
