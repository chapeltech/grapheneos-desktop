# Independent schema-5 staging review

2026-10-12. Bounded verdict: the integrated staging infrastructure is merge-ready
with the native patch registry still EMPTY (active schema 4). The original
proposal alone is not the accepted artifact: root hardening below is necessary.
No native patch activation, source7 staging, platform build or runtime behavior
is qualified or authorized by this report.

The complete 714-line proposal was read:
`phase1-native-stage-schema5-proposal-20261012-1/native-schema5-merge.patch`,
SHA256 `34c9e9400f2f8f23e5c5c2f4e713a989a785948dfd6154d5125631262b94c872`.
Current production-method hashes are bound in `run-1/result.json`; all four
remained unchanged during the independent controls. Parent integrated receipt
separately binds all 22 production/test inputs.

## Accepted source/host scope

- Native pin is derived from exact lock-authenticated default.xml size/SHA,
  equality of working and committed manifest bytes, locked HEAD, tag object and
  peeled tag, and a unique frameworks/native project with the expected project
  name, grapheneos remote and revision. Current native HEAD is never itself the
  authority. Real authenticated manifest control returns
  `1c83ac6ae533c74ecb0486369c0d2f9e79783b3d`.
- Nonempty native registry activates schema 5 and the fourth native lane;
  consumers do not select legacy compatibility from a supplied marker. The
  contract requires exact ordered patch/tool ledgers, exact patch-derived target
  union, ordinary files, and active lane/revision fields. Schema 4 fixtures must
  now contain the real complete target union; arbitrary one-target markers are
  not evidence of compatibility.
- Stage/verify/plan/target hashing, provenance owned-path validation, x86 and
  Frankel comparison, launchers, release source/artifact verification and release
  index gates consume the shared active contract or its validated comparison
  result. Native role propagation also covers candidate producer and guest/
  acceptance inventories. No missing native consumer was found in this review.
- `os_input_dispatcher` is installed `system/lib64/libinputflinger.so`:
  libinputflinger links libinputdispatcher, whose source includes the patched
  InputDispatcher.cpp. `os_android_servers` is
  `system/lib64/libandroid_servers.so`: libandroid_servers whole-links
  libservices.core containing the patched IMS JNI source. Both are mandatory
  stock-present baseline artifacts, NOT custom-only/NATIVE_ONLY artifacts.
  A schema-5 custom result must witness both changing, in addition to the legacy
  mandatory changed artifacts. Frankel uses the same strict delta helper.

## Defects corrected in root integration

1. Schema-5-with-missing-native targets previously fell back to legacy changed
   artifacts. Current delta helper requires exact integer schema 4/5, native
   presence iff schema 5 and a nonempty native target dictionary. Independent
   negative controls reject missing, empty, list, null targets; list/null outer
   inventories; wrong/bool/float/string/null schemas; and schema-4 native data.
2. Target-relative checks did not protect a symlinked project root or parent.
   Current ordinary_directory/reject_symlinked_path checks protect absolute
   ancestors, before source resolution, before certificate/write, and in shared
   plan/verify/hashing/authenticated-manifest functions. Independent root and
   ancestor alias controls reject all three helper operations and a manifest
   directory alias. Normal synthetic root remains accepted.
3. A temporary patch-plan tree inside a pre-existing Git tree could inherit that
   Git root; Git-format patches could silently skip, blessing original bytes.
   Current planner initializes an isolated Git repository and verifies exact
   rev-parse root. Independent actual-method fixture deliberately locates scratch
   inside an existing Git tree and uses a diff --git header; it produces exact
   patched bytes/hashes and leaves original bytes unchanged. Plain ---/+++ alone
   was not an adequate negative control.

## Retained validation

`run_controls.py` calls actual current methods (no candidate overlay or staging
main); `run-1/result.json` records PASS 34 assertions and complete schema-4 union
of 74 targets. The synthetic project, patch, nested Git scratch and symlink
fixtures remain preserved here; no cleanup or user-source writes occurred.
Independent native artifact role unittest run passed 6 cases.

Parent integrated broad regression receipt reports 249 cases PASS and 22 input
hashes unchanged. Output was independently read and SHA verified:
`phase1-native-stage-root-integration-20261012-1/root-regression-output.txt`,
`fcc8d7036b438a62b653e2e7f9a3114a25aef3f950e6bdef674cb8360c977ddd`.
This is attributed parent execution evidence, not a claim that this reviewer
reran the entire suite. The rooted schema-5 supplemental 15-case execution was
reported separately by parent; the independent 34-control result is the direct
execution basis for this verdict.

## Boundaries

Native registry remains `()`: no source7 marker rewrite or native image build is
implied. This review authenticates staging/provenance/artifact plumbing only.
It does not qualify the private key candidate's queue-origin/display/device
incarnation/final-target isolation, hardware chords or collateral cancellation,
or full JNI/native/framework compilation or Android/physical-device runtime.
In particular, KGC's separate native getKeyCodeState reads plus helper
mutationEpoch do not form a coherent atomic InputReader census. Reader DOWN can
race without helper epoch change, so saturation recovery/clearing of retained
drains is not accepted as trusted atomic observation by this staging report.
