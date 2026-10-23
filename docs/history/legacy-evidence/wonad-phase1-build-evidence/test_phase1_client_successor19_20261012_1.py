"""Prepared-driver host checks only; no producer, container or compiler."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

DIRECTORY = Path(__file__).resolve().parent
PATH = DIRECTORY / 'run-phase1-client-successor19-20261012-1.py'
spec = importlib.util.spec_from_file_location('successor19_preparation_driver', PATH)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class Successor19PreparationTests(unittest.TestCase):
    def capture(self):
        return json.loads(driver.raw_file(driver.CAPTURE), object_pairs_hook=driver.unique)

    def publication(self):
        value = self.capture()
        names = set(value['sdk']['immutable_files']) | set(value['sdk']['timestamp_family'])
        return value, {name: driver.raw_file(Path(value['sdk']['prior_repository']) / name) for name in names}

    def test_actual_current_source_closure_and_private_delta(self):
        value, builder = driver.checked_capture()
        self.assertEqual(112, len(value['source_files']))
        self.assertEqual(586117, value['source_total_bytes'])
        self.assertEqual(['android/conformance/src/main/kotlin/org/wonad/desktop/ConformanceRunner.kt'],
                         value['source_delta']['changed'])
        self.assertEqual([
            'android/conformance/src/main/kotlin/org/wonad/desktop/ConformancePickerProgress.kt',
            'android/conformance/src/test/kotlin/org/wonad/desktop/ConformancePickerProgressTest.kt',
        ], value['source_delta']['added'])
        self.assertEqual([], value['source_delta']['removed'])
        self.assertEqual(sorted(value['source_files']), builder.source_names())
        self.assertNotIn('/out/', '\n'.join(value['source_files']))
        self.assertEqual('PENDING_ACTUAL_AUTHORIZED_PREPARE', value['new_producer_plan_sha256'])
        self.assertEqual('ROOT_REVIEWED_UNCHANGED_SDK_CONFIRMATION', value['root_sdk_branch_choice'])
        self.assertEqual('PENDING_SEPARATE_ROOT_PREPARE_GO_THEN_REVIEWED_PLAN_BUILD_GO',
                         value['root_execution_authorization'])

    def test_prepare_and_build_fail_before_heavy_work_while_sdk_choice_pending(self):
        for mode in ('--prepare-after-root-authorization', '--build-after-root-authorization'):
            with self.subTest(mode=mode), patch.object(driver, 'checked_capture', return_value=(self.capture(), None)), \
                    patch.object(driver, 'SDK_BRANCH_AUTHORIZATION', 'PENDING_ROOT_SDK_BRANCH_CHOICE'), \
                    patch.object(driver, 'exclusive_heavy_lane') as lane, \
                    patch.object(driver, 'prepared_plan') as plan, patch.object(driver.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'SDK branch choice remains PENDING'):
                    driver.main([mode])
                lane.assert_not_called(); plan.assert_not_called(); run.assert_not_called()

    def test_read_only_checks_do_not_inspect_tool_containers_or_admit_build(self):
        with patch.object(driver, 'checked_capture', return_value=(self.capture(), None)), \
                patch.object(driver, 'exclusive_heavy_lane') as lane, patch.object(driver.subprocess, 'run') as run:
            self.assertEqual(0, driver.main(['--check-capture-read-only']))
            lane.assert_not_called(); run.assert_not_called()
            with self.assertRaisesRegex(ValueError, 'digest is invented'):
                driver.main(['--check-capture-read-only', '--expected-plan-sha256', 'a' * 64])

    def test_fresh_named_output_and_unchanged_authority_commands(self):
        value = self.capture()
        self.assertFalse(os.path.lexists(driver.OUTPUT))
        self.assertNotIn('20261011-18', str(driver.OUTPUT))
        self.assertEqual('/usr/bin/python3', value['commands']['prepare'][0])
        self.assertEqual(['prepare', '--version-code', '12', '--version-name', 'phase1-neutral-v3-native-12'],
                         value['commands']['prepare'][-5:])
        self.assertEqual(['build', '--expected-plan-sha256'], value['commands']['build_prefix'][-2:])
        self.assertEqual('ROOT_REVIEWED_UNCHANGED_SDK_CONFIRMATION', driver.SDK_BRANCH_AUTHORIZATION)
        self.assertIn('does NOT close', value['sdk']['preservation_contingency'])

    def test_actual_immutable_maven25_and_timestamp_family5_verify(self):
        value, actual = self.publication()
        self.assertEqual(25, len(value['sdk']['immutable_files']))
        self.assertEqual(5, len(value['sdk']['timestamp_family']))
        driver.sdk_continuity(value, actual)
        changed = dict(actual)
        name = 'org/wonad/desktop-sdk/maven-metadata.xml'
        changed[name] = re.sub(b'<lastUpdated>[0-9]{14}</lastUpdated>',
                              b'<lastUpdated>20261012010203</lastUpdated>', actual[name])
        for algorithm in ('md5', 'sha1', 'sha256', 'sha512'):
            changed[name + '.' + algorithm] = hashlib.new(algorithm, changed[name]).hexdigest().encode()
        driver.sdk_continuity(value, changed)

    def test_maven_byte_relabel_inventory_metadata_and_checksum_hostiles(self):
        value, actual = self.publication()
        name = 'org/wonad/desktop-sdk/maven-metadata.xml'
        immutable = next(iter(value['sdk']['immutable_files']))
        hostile = []
        changed = dict(actual); changed[immutable] += b'changed immutable'; hostile.append(changed)
        changed = dict(actual); changed.pop(immutable); hostile.append(changed)
        changed = dict(actual); changed[immutable.replace('3.0.0', '3.0.1')] = changed.pop(immutable); hostile.append(changed)
        changed = dict(actual); changed[name] = changed[name].replace(b'<release>3.0.0</release>', b'<release>3.0.1</release>'); hostile.append(changed)
        changed = dict(actual); changed[name] += b'<lastUpdated>20261012010203</lastUpdated>'; hostile.append(changed)
        for algorithm in ('md5', 'sha1', 'sha256', 'sha512'):
            changed = dict(actual); changed[name + '.' + algorithm] = b'0' * len(changed[name + '.' + algorithm]); hostile.append(changed)
        for changed in hostile:
            with self.subTest(changed_keys=sorted(k for k in changed if changed[k] != actual.get(k))), self.assertRaises(ValueError):
                driver.sdk_continuity(value, changed)

    def test_guard_recognizes_heavy_lanes_and_leaves_sleep_adb_alone(self):
        blocked = [
            ['qemu-kvm'], ['qemu-system-x86_64'], ['emulator'], ['ninja'], ['siso'], ['soong_build'],
            ['python3', '/scope/build_native_successor.py'], ['python3', '/scope/run_native_matrix.py'],
            ['python3', '/scope/phase1_conformance_guest.py'],
            ['python3', '/scope/run_phase1_conformance_recents_guest.py'],
            ['python3', '/scope/phase1_frankel_vendor_driver_20261011_1.py', '--run'],
            ['bash', '/scope/vendor/adevtool/scripts/run-build.sh'],
            ['bash', '/scope/continue-phase1-x86-custom-7-from-baseline-receipt-8.sh'],
            ['java', 'org.gradle.launcher.daemon.bootstrap.GradleDaemon'],
            ['java', 'org.jetbrains.kotlin.daemon.KotlinCompileDaemon'],
        ]
        for argv in blocked:
            with self.subTest(argv=argv): self.assertTrue(driver.command_conflict(argv))
        for argv in ([], ['sleep', 'infinity'], ['adb', '-L', 'tcp:5037', 'fork-server', 'server']):
            with self.subTest(argv=argv): self.assertFalse(driver.command_conflict(argv))

    def test_stable_regular_file_and_duplicate_json_and_unresolved_plan_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix='wonad-successor19-fixture-') as name:
            directory = Path(name)
            regular = directory / 'regular'; regular.write_bytes(b'fixture')
            self.assertEqual(b'fixture', driver.raw_file(regular))
            alias = directory / 'alias'; alias.symlink_to(regular)
            with self.assertRaises(ValueError): driver.raw_file(alias)
            with self.assertRaises(ValueError): driver.raw_file(regular, limit=2)
        with self.assertRaises(ValueError): json.loads('{"x":1,"x":2}', object_pairs_hook=driver.unique)
        for digest in (None, '', 'PENDING', 'a' * 63, 'g' * 64):
            with self.subTest(digest=digest), self.assertRaisesRegex(ValueError, 'unresolved'):
                driver.prepared_plan(self.capture(), digest)

    def test_actual_and_future_vendor_helpers_and_wrappers_are_whole_basename_lanes(self):
        names = [
            'phase1_frankel_vendor_driver_20261011_1.py',
            'phase1_frankel_vendor_cache_driver_20261011_4.py',
            'phase1_frankel_vendor_cache_driver_20261012_5.py',
            'prepare-phase1-frankel-vendor-20261011-1.sh',
            'prepare-phase1-frankel-vendor-cache-20261011-4.sh',
            'prepare-phase1-frankel-vendor-cache-20261012-5.sh',
        ]
        for name in names:
            for flag in ('--run', '--check-only'):
                with self.subTest(name=name, flag=flag):
                    self.assertTrue(driver.command_conflict(['python3', '/exact/evidence/' + name, flag]))
            for bad in ('prefix-' + name, name + '.backup', name + 'suffix'):
                with self.subTest(non_family=bad):
                    self.assertFalse(driver.command_conflict(['python3', '/exact/evidence/' + bad, '--run']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
