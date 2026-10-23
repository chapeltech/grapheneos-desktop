"""Small JVM/source regression, not Binder/Android/guest qualification.

Compiles the exact helper, callback queue and status sources with the frozen
published SDK DTO classes. Only the Android Binder superclass/SystemClock and
JUnit assertion framework are explicit host doubles. Test method bodies are
the actual newly added Kotlin unit tests, with annotations/imports removed.
No Gradle, APK, native compiler, container, or guest is invoked.
"""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path('/u/elric/tree/wonad')
CLIENT = ROOT / 'android/conformance/src/main/kotlin/org/wonad/desktop'
TEST = ROOT / 'android/conformance/src/test/kotlin/org/wonad/desktop/ConformancePickerProgressTest.kt'
BASE = ROOT.parent / 'wonad-grapheneos-2026100600'
JDK = BASE / 'prebuilts/jdk/jdk21/linux-x86'
KOTLINC = BASE / 'external/kotlinc/bin/kotlinc'
ANDROID = BASE / 'prebuilts/sdk/35/public/android.jar'
AAR = ROOT / 'android/out/native-current-successor-12-phase1-v3-runtime-20261011-18/sdk-repository/org/wonad/desktop-sdk/3.0.0/desktop-sdk-3.0.0.aar'
AAR_SHA = 'c1e164b7c57efd7f0997a90c92707cdaca16d1e5d3a47eb61197eb7b14fc4b07'
OLD = ROOT / 'android/out/native-current-successor-12-phase1-v3-runtime-20261011-18/source/android/conformance/src/main/kotlin/org/wonad/desktop/ConformanceRunner.kt'
OLD_SHA = 'c3b3122df6a9b75d55ffdec37554058b01447a7bd65789e36022054d2c967034'

CALLBACK_DOUBLE = '''package org.wonad.desktop.api
interface IDesktopCallback {
    abstract class Stub {
        abstract fun onSnapshot(snapshot: DesktopSnapshot)
        abstract fun onCommand(generation: Long, command: Int, argument: Int, taskToken: Long, displayToken: Long)
        abstract fun onResult(generation: Long, requestId: Long, result: Int, revision: Long)
        abstract fun onRevoked(generation: Long, reason: Int)
    }
}
'''
CLOCK_DOUBLE = '''package android.os
object SystemClock { @JvmStatic fun elapsedRealtime(): Long = System.nanoTime() / 1_000_000 }
'''
ASSERTIONS = '''package org.wonad.desktop
var assertions = 0
fun assertTrue(value: Boolean) { check(value) { "assertTrue" }; assertions++ }
fun assertFalse(value: Boolean) { check(!value) { "assertFalse" }; assertions++ }
fun assertEquals(expected: Any?, actual: Any?) { check(expected == actual) { "$expected != $actual" }; assertions++ }
fun <T: Throwable> assertThrows(type: Class<T>, action: () -> Unit): T {
    try { action() } catch (failure: Throwable) {
        check(type.isInstance(failure)) { "expected ${type.name}, got $failure" }
        assertions++; return type.cast(failure)
    }
    error("expected ${type.name}, no exception")
}
fun main() {
    val tests = ConformancePickerProgressTest()
    tests.realCallbackDtosRequireFreshBlockedThenFreshUnblockedLauncherObservations()
    tests.progressRejectsEqualOlderWrongGenerationAndOppositeBlockingState()
    tests.cadenceWaitsOnlyTheRemainingIntervalAtEarlyExactAndLateBoundaries()
    tests.cadenceRejectsNegativeRegressingOverflowedAndFrozenClocks()
    tests.cadencePropagatesInterruptedSleepAndPreservesPreexistingInterruption()
    println("actual_picker_unit_methods=5 host_assertions=$assertions binder_transport=double dto=frozen_sdk")
}
'''


def ordering(source):
    launcher = source.split('ledger.phase("exercising-launcher", displayIds)', 1)[1]
    end = launcher.split('operation("enableShortcuts")', 1)[0]
    required = [
        'val beforeCatalogueRevision = snapshot.revision',
        'val first = checkNotNull(remote.launcherPage(generation, 0, display.token, 0))',
        'val catalogueReturnedElapsed = SystemClock.elapsedRealtime()',
        'snapshot = callback.awaitSnapshot("fresh launcher catalogue blocking")',
        'ConformancePickerProgress.opened(ConformancePickerProgress.observe(it),',
        'val catalogueBlockedRevision = snapshot.revision',
        'operation("showLauncher")',
        'val beforeCancel = checkNotNull(callback.latestSnapshot())',
        'val cancellationFloor = ConformancePickerProgress.cancellationFloor(',
        'operation("selectLauncher")',
        'snapshot = callback.awaitSnapshot("launcher cancellation")',
        'ConformancePickerProgress.cancelled(ConformancePickerProgress.observe(it),',
        'ConformancePickerProgress.awaitCatalogueCadence(catalogueReturnedElapsed,',
        'operation("showTransferPicker")',
        'callback.awaitSnapshot("trusted phone transfer picker")',
        'it.generation == generation && it.interactionBlocked',
        'ledger.phase("wait-transfer-back", displayIds)',
    ]
    positions = [end.index(value) for value in required]
    if positions != sorted(positions):
        raise AssertionError('launcher/cancel/cadence/transfer order differs')
    if end.count('remote.showTransferPicker(') != 1:
        raise AssertionError('transfer request must be singular')
    if 'sleep = { Thread.sleep(it) }' not in end:
        raise AssertionError('interruptible sleeper is required')
    return end


class PickerClientHostTests(unittest.TestCase):
    def test_exact_kotlin_helper_callback_queues_and_unit_bodies(self):
        self.assertEqual(AAR_SHA, hashlib.sha256(AAR.read_bytes()).hexdigest())
        with tempfile.TemporaryDirectory(prefix='wonad-picker-client-host-') as name:
            temporary = Path(name)
            with zipfile.ZipFile(AAR) as archive:
                dto = temporary / 'sdk.jar'
                dto.write_bytes(archive.read('classes.jar'))
            test = TEST.read_text()
            test = re.sub(r'^import org\.junit[^\n]*\n', '', test, flags=re.M)
            test = test.replace('@Test ', '')
            extras = {'Tests.kt': test, 'Assertions.kt': ASSERTIONS,
                      'CallbackDouble.kt': CALLBACK_DOUBLE, 'ClockDouble.kt': CLOCK_DOUBLE}
            for filename, value in extras.items():
                (temporary / filename).write_text(value)
            output = temporary / 'test.jar'
            sources = [CLIENT / 'ConformancePickerProgress.kt', CLIENT / 'ConformanceEvents.kt',
                       CLIENT / 'ConformanceStatus.kt', *(temporary / key for key in extras)]
            compiled = subprocess.run(
                [str(KOTLINC), '-J-Xmx512m', *(str(path) for path in sources), '-classpath',
                 str(dto) + ':' + str(ANDROID), '-include-runtime', '-d', str(output)],
                env={**os.environ, 'JAVA_HOME': str(JDK)}, capture_output=True, text=True, timeout=90)
            self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
            ran = subprocess.run([str(JDK / 'bin/java'), '-Xmx256m', '-cp',
                str(output) + ':' + str(dto) + ':' + str(ANDROID), 'org.wonad.desktop.AssertionsKt'],
                capture_output=True, text=True, timeout=20)
            self.assertEqual(0, ran.returncode, ran.stdout + ran.stderr)
            self.assertRegex(ran.stdout, r'actual_picker_unit_methods=5 host_assertions=\d+ binder_transport=double dto=frozen_sdk')
            print(ran.stdout.strip())

    def test_actual_runner_orders_fresh_snapshots_and_one_cadence_bound_transfer(self):
        end = ordering((CLIENT / 'ConformanceRunner.kt').read_text())
        self.assertIn('generation, beforeCatalogueRevision)', end)
        self.assertIn('generation, cancellationFloor)', end)
        self.assertIn('generation, catalogueBlockedRevision)', end)
        self.assertIn('callback.awaitSnapshot("trusted phone transfer picker cancellation", 60_000)', end)
        self.assertNotIn('SystemClock.sleep', end)

    def test_retained_old_runner_is_red_for_current_order_contract(self):
        source = OLD.read_bytes()
        self.assertEqual(OLD_SHA, hashlib.sha256(source).hexdigest())
        with self.assertRaises(ValueError):
            ordering(source.decode())
        old_cancel = source.decode().split('callback.awaitSnapshot("launcher cancellation")', 1)[1].split('ledger.phase("wait-transfer-cancel"', 1)[0]
        self.assertIn('it.generation == generation && !it.interactionBlocked', old_cancel)
        self.assertNotIn('revision', old_cancel)


if __name__ == '__main__':
    unittest.main(verbosity=2)
