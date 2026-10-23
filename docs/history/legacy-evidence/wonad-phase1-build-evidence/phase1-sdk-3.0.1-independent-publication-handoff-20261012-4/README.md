# Wonad SDK 3.0.1 independent-publication handoff, generation 4

This create-only handoff supersedes generation 3 after the first real build
correctly failed because the reviewed publication verifier rejected a contract
member inherited as mode `0400`. Generation 3 and its failed run remain
untouched. The reviewed SDK Gradle change now canonicalizes only generated
source-JAR entries and contract archive members to `0644`; the nested contract
verifier remains `0755`.

The generation-4 driver is behavior-identical to generation 3. Its only two
byte changes are the exact source-manifest and 112-record digest constants.
The manifest differs in exactly one selected source record:
`android/desktop-sdk/build.gradle.kts`, now SHA-256
`b206916a535f32c5fc9a30b87cb096f557c1100d872e1dc265d1f6710c3cf519`
and 3285 bytes. All other 111 source records are unchanged.

The handoff still requires two independent, fresh source trees and output Maven
repositories, the exact immutable gate and tool/cache identities, offline
no-daemon two-worker/2-GiB library-only Gradle commands, full verification of
each repository, and equality of all five primary artifacts. It does not
modify or relabel canonical 3.0.0 artifacts.

Future prepare command (not executed here):

```sh
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3.14 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-sdk-3.0.1-independent-publication-handoff-20261012-4/run_two_publications.py \
  prepare --output \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-sdk-3.0.1-independent-publication-run-20261012-4
```

Only after independent review of the printed plan SHA-256 may the separate
one-shot `build --expected-plan-sha256 <observed-plan-sha256>` action run.
Unknown 3.0.1 artifact hashes remain unknown until those real publications
complete.

The 18 focused checks are host-only parser, source-freeze, inventory,
configuration, command-order, and hostile-fixture tests. This handoff did not
run prepare, Docker, Gradle, a JVM, publication, signing, an Android build, or a
VM and makes no ABI, reproducibility, runtime, or release claim.
