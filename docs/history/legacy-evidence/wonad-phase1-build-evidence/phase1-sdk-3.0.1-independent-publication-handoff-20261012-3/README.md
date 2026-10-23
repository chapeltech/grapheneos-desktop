# Wonad SDK 3.0.1 independent-publication handoff, generation 3

This is the final create-only external handoff for two future library-only SDK
3.0.1 publications. It supersedes generation 2 without modifying generation 2
or generation 1. No prepare action, Docker command, Gradle invocation, JVM
daemon, publication, Android build, signing, or VM was run by this handoff.

Generation 3 retains generation 2's exact 112-file local and remote source
inventories, immutable tools-container identity, AIDL/tool/cache binding,
offline library-only commands, post-build inventories, independent repository
verification, and five-primary reproducibility comparison. Its only functional
changes close the reviewed real Gradle configuration inputs:

- `/opt/gradle-8.11.1/gradle.properties` must be absent;
- distribution `init.d` must be absent, empty, or contain exactly one
  non-executable regular `readme.txt`, whose full metadata, size, and SHA-256
  are captured in the reviewed plan;
- `JAVA_OPTS` joins the already forbidden ambient Gradle/JVM/project property
  variables in both the live container environment and the remote probe;
- each A and B Gradle invocation is immediately preceded and followed by an
  exact configuration observation, before any post-build source or output
  collection.

The build remains sequential A then B, offline, no-daemon, two workers, and a
2 GiB Gradle heap. It runs only desktop-sdk clean, release unit tests, and the
publication verifier. It does not build the Android product, APKs, Haskell, or
Rust and does not modify or relabel the canonical historical 3.0.0 artifacts.

Future prepare command (not executed here):

```sh
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3.14 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-sdk-3.0.1-independent-publication-handoff-20261012-3/run_two_publications.py \
  prepare --output \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-sdk-3.0.1-independent-publication-run-20261012-3
```

Only after independent review of the printed plan digest may the separate
one-shot `build --expected-plan-sha256 <observed-plan-sha256>` action run.
Artifact hashes remain unknown until those two real publications complete.

Limits: the 18 checks are host-only parser, inventory, command-order, and
hostile-fixture tests. They do not establish Gradle/JVM ABI, Android runtime,
release, signing, or reproducibility evidence. Generations 1 and 2 and the
generation-1 prepare output remain immutable historical evidence.
