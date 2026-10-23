# Wonad SDK 3.0.1 independent-publication handoff, generation 2

This is a create-only external handoff for two future library-only SDK 3.0.1
publications. It supersedes generation 1 without modifying it or its observed
prepare output. No Gradle publication or Android build was executed here.

Generation 1 authenticated the selected 112 source files, but did not prove
that the fresh local or remote source roots contained *only* those files. An
extra init script or source file could therefore have influenced Gradle while
all selected-file hashes still matched. Generation 2 closes that bounded gap:

- the two local source copies have exact file-and-directory inventories,
  reject symlinks and special nodes, and must remain byte-, inode-, ownership-,
  and mode-identical before and after both publications;
- each remote source root is fully inventoried before Gradle and must contain
  exactly the reviewed source file and directory set;
- each post-Gradle selected source set is rehashed, while the bounded complete
  desktop-sdk build-output tree and exact expected Maven repository files are
  recorded and independently verified;
- ambient `GRADLE_USER_HOME`, Gradle/JVM option variables, and
  `ORG_GRADLE_PROJECT_*` variables are forbidden;
- `/root/.gradle/gradle.properties`, both user init files, and nonempty user
  `init.d` are forbidden without reading or exposing possible secret content;
- the public Gradle distribution `init.d` inventory is content-hashed and
  plan-bound, then all configuration observations are rechecked around builds.

The build command remains library-only, offline, no-daemon, sequential A then
B, two workers, and a 2 GiB Gradle heap. It runs the desktop SDK unit tests and
the repository verifier, then compares exactly the five immutable primary
artifacts. It does not build the product, APKs, Haskell, or Rust, and does not
modify or relabel the historical 3.0.0 publication.

Future prepare command (not executed):

```sh
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3.14 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-sdk-3.0.1-independent-publication-handoff-20261012-2/run_two_publications.py \
  prepare --output \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-sdk-3.0.1-independent-publication-run-20261012-2
```

Only after independent review of the printed plan digest may the separate
one-shot `build --expected-plan-sha256 <observed-plan-sha256>` action run.
Artifact hashes remain unknown until those real publications occur.

Limits: the 17 checks are host-only parser, inventory, command, and hostile
fixture tests. They are not Gradle/JVM ABI, Android build, runtime, release,
signing, or reproducibility evidence. Generation 1 and its prepare attempt
remain historical rather than being upgraded by this handoff.
