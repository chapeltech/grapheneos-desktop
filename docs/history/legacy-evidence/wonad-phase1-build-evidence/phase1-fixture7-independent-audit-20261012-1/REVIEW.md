# Fixture7 independent read-only review

No concrete build-artifact or scope blocker was found. This is an authenticated compile/test fixture, **not runtime-qualified**.

Actual receipt SHA256: `003d0138bc9eade9e948eadd6806eee812160d7a962e939d559f827f2c4f272e` (36,346 B). Actual APK SHA256: `c31c051ed1919b7c8ffe34573ec04f1cd64ccea56ee4418407cebbe457003261` (2,483,973 B). Every one of the 57 receipt-named ordinary artifact files was rehashed and size-checked; the exact output inventory is those files plus the receipt. All 28 current repository sources equal the retained fixture7 snapshot/plan. Both recorded 30-file compiled-source inventories match the exact generated/private staging plan.

## Source and mechanical delta

The complete fixture6-to-fixture7 driver diff is generation/path/name substitution and exactly two changed source pins. The host-test diff is generation/import/path substitution only; build/profile/settings/SDK/signer/JVM/lint/DEX guards are preserved. The only differences across all 28 fixture6/fixture7 source snapshots are `PaletteFixtureContractTest.kt` and `PermissionFixtureContractTest.kt`.

The first test now requires the exact three original dangerous permissions plus normal `CAPTURE_KEYBOARD`, with exactly four declarations so duplicates cannot hide behind `toSet()`. The second preserves an independent exact three-dangerous-permission ledger assertion, adds the fourth normal permission to the manifest assertion, rejects duplicate declarations and extends the exact launchers by the three capture components. This corrects stale contracts rather than removing the original permission/launcher invariants. The failed fixture6 receipt remains `3e7fa6a3329801f86d6c551b302d092771b3d33078f4f38864ee85b09ea41201`; its output/snapshot/reports were not edited.

## Actual evidence rederivation

- Eight real JVM XML suites independently contain exactly the 41 source-declared unique cases, no failures/errors/skips, and match the receipt case-for-case. Thirteen are the pure capture counter/public reflection cases. `Gradle SKIPPED` configuration/Android-test preparation tasks are not being relabelled as 41 skipped JVM tests; the 41 actual testcase nodes all passed.
- Real Gradle terminal exit is 0 with no capsule error, offline one-worker private command and `BUILD SUCCESSFUL` footer. This review launched no Gradle process.
- Actual lint XML has zero Error/Fatal and 33 Warning entries: SetTextI18n 27, and one each CustomSplashScreen, DataExtractionRules, DiscouragedApi, MissingApplicationIcon, NonResizeableActivity, ViewConstructor. These warnings remain recorded, not silently treated as zero. They are not runtime delivery evidence.
- The real compiled manifest parses to 16 unique activity components, 14 exact MAIN/LAUNCHER filters and exactly CAMERA/CAPTURE_KEYBOARD/FINE_LOCATION/COARSE_LOCATION. It has no shared UID and remains ordinary debuggable, not testOnly. The three capture activities are exported resizable ordinary document tasks, `documentLaunchMode=always`, nonexcluded from Recents, separate explicit labels/affinities and standard launch mode.
- All three extracted DEX files equal the corresponding bytes within the hashed actual APK. DEX checksums, size/header/endian and class tables pass. The actual 1,121-class set preserves every one of the predecessor's 1,104 class names; it includes all 16 components and real capture method/reflection strings. This proves class-set preservation, **not** independent behavioral equivalence or bit-identical old method bodies. Held production source pins are separately unchanged.
- The receipt-bound official apksigner transcript reports successful v2 verification, exactly one Android Debug RSA2048 signer `fdbf6a6940f8a1059fea942db2272abfb19e39716f544c92962a6e98103c4e88`, equal to the preserved fixture5 signer. This host-only review authenticated/reparsed that raw transcript and APK hash; it did not execute cryptography again or read private key bytes.
- The entire inventoried fixture5 predecessor tree still matches the plan. No failed6 or predecessor artifacts were altered.

## Post-build host-test seam

Direct replay of the unchanged fixture7 host suite is 23 PASS plus one ERROR: `test_stdout_only_plan_proposal_does_not_create_plan_output_or_staged_source` mocks a fresh PLAN but leaves the real OUT path selected. Since fixture7 has now been built, `create_plan()` correctly refuses an existing OUT. This is a stale post-build test seam, not a failed APK or permission to weaken the freshness guard.

A separate external runner replayed those exact unchanged 24 tests with only `V.OUT` replaced by an absent path in a fresh temporary host directory; all 24 passed in 0.082 s. PLAN handling and actual output are unchanged. Both raw outputs are retained. No claim is made that the original unmodified direct command currently reports 24 PASS.

## Remaining runtime scope

Android Activity integration now actually compiled, but the JVM suite's Android contracts are source/XML checks, and its reflection cases use host fake parameter classes. No real device/emulator has yet proven public reflection accessibility, CAPTURE_KEYBOARD platform grant/honoring, separate installed task/UID/focus identities, captured external Escape delivery, no Android QUIT/Toast, or phone/unclaimed stock behavior.

The source deliberately defaults capture OFF, requires explicit visible ON/OFF, reports API unavailable/errors/mismatch without fabricated success, counts only bounded aggregate actions/Escape/repeat/cancel and logs no typed text. Its local window-token identity is expressly not authoritative InputDispatcher token proof. `ATTRIBUTES_APPLIED` is requested attribute evidence, not system capture evidence; runtime must join real WMS/input/task observations and actual callbacks. The expected current semantic branch is claimed-external Escape key delivery with no Android delayed task close, preserving phone/unclaimed stock; this compilation does not qualify that OS behavior.

No repository/SDK/source writes, tools-container mutation, key reads/exports/new keys, build/signing, installation, guest, cache deletion or runtime qualification occurred in this review. The retained rederivation imports the source-reviewed original audit methods to replay their artifact grammar and adds independent receipt/source/output/XML/ZIP byte joins; it is not a second implementation of APK cryptography.
