# Fixture6 actual Gradle test failure

The fresh root-owned build session44042 terminated with exit1, terminal chunk940a31. The original failed build receipt remains at `android/out/native-keyboard-capture-fixture-6/build-receipt.json`, SHA-256 `3e7fa6a3329801f86d6c551b302d092771b3d33078f4f38864ee85b09ea41201`.

Actual Gradle ran41 tests and reported3 failures: PaletteFixtureContractTest.paletteClientsAreSeparateOrdinaryRealLauncherActivities, PermissionFixtureContractTest.secondDesktopFixtureIsARealDistinctLauncherActivityWithoutBehaviorChanges, and PermissionFixtureContractTest.manifestDeclaresOnlyTheThreeRealDangerousPermissionsAndAnOrdinarySeparateActivity. BUILD FAILED in31s,23 executed tasks. The two prior contracts still required precisely three total permissions/eleven launchers; the integrated fixture has the same three dangerous permissions plus normal CAPTURE_KEYBOARD and three new ordinary capture launcher Activities. This is a fixture contract integration defect, not an OS runtime result.

Root will preserve the failed project, all prior sources, logs and receipt, copy its actual JVM XML here for diagnosis, and correct only the two stale test contracts to explicitly require the intended exact four-permission/fourteen-launcher manifest. No assertions are removed, no failures are relabelled as passes, and any rebuild must use fresh fixture7 authority/output/project rather than modifying this failed run.

No guest, APK qualification, production key, OS source change, or original evidence cleanup occurred.
