"""Bound generation-7 host controls; no real admission, Docker or guest execution."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


sys.path.insert(0, '/u/elric/tree/wonad/android/tools')
DRIVER_PATH = Path('/u/elric/tree/wonad-phase1-build-evidence/'
                   'run-phase1-custom7-api-recents-packet8-20261012-7.py')
spec = importlib.util.spec_from_file_location('custom7_future_packet8_driver', DRIVER_PATH)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class PreparedBindingTests(unittest.TestCase):
    def test_actual_packet_wrong_and_selection_are_fully_bound(self):
        self.assertEqual('phase1-emulator-client-packet-20261012-8', driver.PACKET.name)
        self.assertEqual('phase1-wrong-signer-bundle-20261012-8', driver.WRONG.parent.name)
        self.assertEqual('phase1-custom7-api-recents-packet8-selection-20261012-7.json',
                         driver.SELECTION.name)
        self.assertEqual('b30fbb787eb8f39cb573db076a2ac0954cf98f61d375b49d465cc42b355ef3ee',
                         driver.PACKET_SHA)
        self.assertEqual('73fc21230017574673b8633f47721404a3b1a5057e2c9087137095a06a833aea',
                         driver.WRONG_SHA)
        self.assertEqual('9159b8e83a3b29a181a522f91e9bf574af259f3f28f63fc6ede11e7e7fe3e52d',
                         driver.SELECTION_SHA)
        for path, expected in ((driver.PACKET / 'receipt.json', driver.PACKET_SHA),
                               (driver.WRONG, driver.WRONG_SHA),
                               (driver.SELECTION, driver.SELECTION_SHA)):
            self.assertEqual(expected, driver.digest(path))
        driver.actual_identity_ready()  # Grammar only; no host/Docker admission.

    def test_only_two_actual_binding_literals_change_preserved_driver(self):
        prior = driver.EVIDENCE / 'run-phase1-custom7-api-recents-packet8-20261012-7-pre-image-binding.py'
        self.assertEqual('7250509a99f598687d5e7540c26a2f04c2b3b5da42e3707813e3338911c6103c',
                         driver.digest(prior))
        actual = DRIVER_PATH.read_text()
        actual = actual.replace("WRONG_SHA = '" + driver.WRONG_SHA + "'",
                                "WRONG_SHA = '" + driver.PENDING['wrong'] + "'")
        actual = actual.replace("SELECTION_SHA = '" + driver.SELECTION_SHA + "'",
                                "SELECTION_SHA = '" + driver.PENDING['selection'] + "'")
        self.assertEqual(prior.read_text(), actual)
        prior_tests = driver.EVIDENCE / 'test_phase1_custom7_api_recents_driver_20261012_7_pre_image_binding.py'
        self.assertEqual('828d8ffea53e596d7893c1e45b26d54751d07feeea8d76b840b3cfe6385b0fab',
                         driver.digest(prior_tests))

    def test_actual_selection_has_exact13_fields_original_product_and_manifest_copies(self):
        value = driver.load(driver.SELECTION)
        self.assertEqual({'schema', 'scope', 'native_image_id', 'derived_image_id',
            'native_manifest', 'native_manifest_sha256', 'derived_manifest',
            'derived_manifest_sha256', 'product', 'packet_receipt_sha256',
            'baseline_receipt_sha256', 'custom_receipt_sha256', 'comparison_sha256'},
            set(value))
        self.assertIs(type(value['schema']), int)
        self.assertEqual(1, value['schema'])
        self.assertEqual('custom7-packet8-two-separate-fresh-guests-not-runtime-qualified', value['scope'])
        self.assertEqual(str(driver.PRODUCT_ORIGIN), value['product'])
        self.assertEqual(driver.PACKET_SHA, value['packet_receipt_sha256'])
        expected = {
            'native': ('sha256:0e425e724cb6f53cb1ef6ae080c39dfdfcf810b5e6fe7c262e419e2b750a01b4',
                       '72cf4f3e03cd3774c88095ce3bf933f6ba23b043bb9a87de5b1d7f5cbaa66bd7',
                       'phase1-native-candidate-custom7-5-5'),
            'derived': ('sha256:e23259f2cd466b9635d4348c57ac07b0d02750ff89ca0b650b7dc3e45f79b772',
                        'e967bcd1c419935453f9f7d44176eca9a0eead42083ab9c3181bd37c20dc4b51',
                        'phase1-conformance-candidate-custom7-5-7'),
        }
        for role, (image, sha, origin) in expected.items():
            self.assertEqual(image, value[role + '_image_id'])
            self.assertEqual(sha, value[role + '_manifest_sha256'])
            path = Path(value[role + '_manifest'])
            self.assertEqual(driver.AUTHORITY / (role + '-manifest-packet8-20261012-7.json'), path)
            self.assertEqual(sha, driver.digest(path))
            self.assertEqual((driver.ROOT / 'android/out' / origin / 'manifest.json').read_bytes(),
                             path.read_bytes())
        native = driver.load(Path(value['native_manifest']))
        for role in ('baseline_receipt', 'custom_receipt', 'comparison'):
            self.assertEqual(value[role + '_sha256'],
                             native['phase1_build_evidence'][role]['expected_sha256'])
        self.assertEqual(driver.PACKET_SHA,
                         native['phase1_build_evidence']['client_packet']['expected_sha256'])

    def test_outputs_are_fresh_separate_and_have_no_current_latest_alias(self):
        self.assertNotEqual(driver.OUTPUTS['api'], driver.OUTPUTS['recents'])
        self.assertEqual('runtime-api-packet8-20261012-7', driver.OUTPUTS['api'].name)
        self.assertEqual('runtime-recents-packet8-20261012-7', driver.OUTPUTS['recents'].name)
        for path in (*driver.OUTPUTS.values(), driver.PACKET, driver.WRONG, driver.SELECTION):
            self.assertNotRegex(str(path), r'(?:^|[-_/])(current|latest)(?:$|[-_/])')
        for path in driver.OUTPUTS.values():
            self.assertFalse(path.exists())
        self.assertTrue(driver.SELECTION.is_file())
        self.assertTrue(driver.PACKET.is_dir())

    def test_current_host_sources_are_exactly_pinned(self):
        self.assertEqual('d132b503da89f8b1ed538ba41210d2eca4fce6ade768db75aaaba4d39cd1e682',
                         driver.SOURCE_SHA['android/tools/phase1_conformance_recents.py'])
        self.assertEqual('62984b8df64dbb2fb22f39fbffc1c4bdc4719a2463456f9a8c4c34696826ac92',
                         driver.SOURCE_SHA['android/tools/phase1_conformance_recents_acceptance.py'])
        for relative, expected in driver.SOURCE_SHA.items():
            self.assertEqual(expected, driver.digest(driver.ROOT / relative), relative)

    def test_generation6_driver_and_failures_are_not_targeted_or_modified(self):
        prior = driver.EVIDENCE / 'run-phase1-custom7-api-recents-packet7-20261011-6.py'
        self.assertEqual('2ceca8ac982a4e4cbae040290d732454b9a00db23bbe2b237f0d8ce1ec68007d',
                         driver.digest(prior))
        old_outputs = ('runtime-api-packet7-20261011-6', 'runtime-recents-packet7-20261011-6')
        self.assertTrue(all((driver.AUTHORITY / name).exists() for name in old_outputs))
        self.assertTrue(all(name not in str(driver.OUTPUTS) for name in old_outputs))


class FailClosedAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.selection = {'product': str(driver.PRODUCT_ORIGIN),
                          'derived_image_id': 'sha256:' + 'a' * 64}

    def test_each_remaining_pending_identity_blocks_with_actual_packet(self):
        actual = '1' * 64
        for role, field in (('wrong', 'WRONG_SHA'), ('selection', 'SELECTION_SHA')):
            values = {'PACKET_SHA': driver.PACKET_SHA,
                      'WRONG_SHA': actual, 'SELECTION_SHA': actual}
            values[field] = driver.PENDING[role]
            patches = [mock.patch.object(driver, name, value) for name, value in values.items()]
            with self.subTest(role=role), contextlib.ExitStack() as stack:
                for patch in patches:
                    stack.enter_context(patch)
                with self.assertRaisesRegex(ValueError, 'NOT READY'):
                    driver.actual_identity_ready()

    def test_replacing_actual_packet_with_fictitious_pending_marker_is_rejected(self):
        with mock.patch.object(driver, 'PACKET_SHA', driver.PENDING['packet']), \
             mock.patch.object(driver, 'WRONG_SHA', '1' * 64), \
             mock.patch.object(driver, 'SELECTION_SHA', '2' * 64), \
             self.assertRaisesRegex(ValueError, 'NOT READY'):
            driver.actual_identity_ready()

    def test_malformed_or_empty_identity_never_counts_as_ready(self):
        for value in (None, '', '0' * 63, 'g' * 64, True):
            with self.subTest(value=value), mock.patch.object(driver, 'PACKET_SHA', value), \
                 mock.patch.object(driver, 'WRONG_SHA', '1' * 64), \
                 mock.patch.object(driver, 'SELECTION_SHA', '2' * 64), \
                 self.assertRaisesRegex(ValueError, 'NOT READY'):
                driver.actual_identity_ready()

    def test_check_and_execute_stop_before_local_or_docker_probes(self):
        for arguments in (['--check-only', '--lane', 'api'],
                          ['--execute-after-root-authorization', '--lane', 'recents']):
            with self.subTest(arguments=arguments), \
                 mock.patch.object(driver, 'SELECTION_SHA', driver.PENDING['selection']), \
                 mock.patch.object(driver, 'local_inputs') as local, \
                 mock.patch.object(driver.subprocess, 'check_output') as docker, \
                 mock.patch.object(driver.os, 'execve') as execute, \
                 self.assertRaisesRegex(ValueError, 'NOT READY'):
                driver.main(arguments)
            local.assert_not_called(); docker.assert_not_called(); execute.assert_not_called()

    def test_selected_has_its_own_pending_guard_before_file_or_docker_access(self):
        with mock.patch.object(driver, 'SELECTION_SHA', driver.PENDING['selection']), \
             mock.patch.object(driver, 'digest') as digest, \
             mock.patch.object(driver.subprocess, 'check_output') as docker, \
             self.assertRaisesRegex(ValueError, 'NOT READY'):
            driver.selected()
        digest.assert_not_called(); docker.assert_not_called()

    def test_execution_requires_exactly_one_explicit_mode(self):
        for arguments in ([], ['--check-only', '--execute-after-root-authorization']):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(ValueError, 'Choose check-only'):
                driver.main(arguments)

    def test_lane_commands_remain_separate_and_bind_future_packet(self):
        api, recents = (driver.commands(self.selection, lane) for lane in ('api', 'recents'))
        self.assertNotEqual(api[2], recents[2])
        self.assertNotEqual(api[-1], recents[-1])
        for command in (api, recents):
            self.assertEqual(self.selection['derived_image_id'], command[command.index('--image') + 1])
            self.assertIn(str(driver.PACKET), command)
            self.assertIn(driver.PACKET_SHA, command)
            self.assertNotIn('settings', command)
            self.assertNotIn('put', command)

    def test_independent_auditor_commands_are_lane_specific(self):
        api, recents = (driver.commands(self.selection, lane, audit=True)
                        for lane in ('api', 'recents'))
        self.assertNotEqual(api[2], recents[2])
        self.assertIn(str(driver.OUTPUTS['api'] / 'report.json'), api)
        self.assertIn(str(driver.OUTPUTS['recents'] / 'report.json'), recents)
        self.assertNotIn('--image', api + recents)

    def test_changed_pinned_source_blocks_before_packet_docker_or_kvm(self):
        with mock.patch.object(driver.os, 'getuid', return_value=1000), \
             mock.patch.object(driver.os, 'getgid', return_value=1000), \
             mock.patch.object(driver, 'digest', return_value='0' * 64), \
             mock.patch.object(driver.subprocess, 'check_output') as docker, \
             self.assertRaisesRegex(ValueError, 'Reviewed runtime source changed'):
            driver.local_inputs()
        docker.assert_not_called()

    def test_foreign_kvm_guest_is_preserved_and_rejected(self):
        foreign = 'b' * 64
        info = {'Id': foreign, 'Image': 'sha256:' + 'c' * 64,
                'HostConfig': {'Devices': [{'PathOnHost': '/dev/kvm'}]},
                'Config': {'Labels': {}}, 'Mounts': []}
        with mock.patch.object(driver, 'docker_output', side_effect=[foreign + '\n', json.dumps([info])]), \
             self.assertRaisesRegex(ValueError, 'Another KVM/native/GUI guest'):
            driver.running_guest_check(self.selection, 'api')

    def test_no_running_container_is_admitted_without_mutation(self):
        with mock.patch.object(driver, 'docker_output', return_value='') as probe:
            self.assertEqual([], driver.running_guest_check(self.selection, 'recents'))
        probe.assert_called_once_with(['ps', '-q', '--no-trunc'])

    def test_resource_runner_names_keep_prior_guards_and_add_vendor_family(self):
        blocked = ('run_native_matrix.py', 'run_frankel_build.py',
            'phase1_conformance_guest.py', 'run_phase1_conformance_recents_guest.py',
            'native_input_smoke.py', 'continue-phase1-x86-custom-7-1.sh',
            'run_frankel_vendor.py', 'generate-frankel-vendor.sh',
            'prepare-phase1-frankel-vendor-cache-20261012-6.sh',
            'phase1_frankel_vendor_cache_driver_20261011_4.py')
        for name in blocked:
            with self.subTest(name=name):
                self.assertTrue(driver.resource_runner_name(name))
        for name in ('node', 'yarn', 'unrelated-server.py', 'run_frankel_vendor.md',
                     'prepare-phase1-frankel-vendor-cache-not-a-script.txt'):
            with self.subTest(name=name):
                self.assertFalse(driver.resource_runner_name(name))

    @staticmethod
    def fake_process(argv):
        raw = b'\0'.join(arg.encode() for arg in argv) + b'\0'
        class FakeProcess:
            name = '987654321'
            def __truediv__(self, name):
                if name == 'cmdline':
                    return SimpleNamespace(open=lambda _mode: io.BytesIO(raw))
                if name == 'cgroup':
                    return SimpleNamespace(read_text=lambda: 'unrelated-cgroup')
                raise AssertionError('Unexpected process read: ' + name)
        return FakeProcess()

    def test_each_vendor_producer_or_wrapper_blocks_runtime_admission(self):
        for name in ('run_frankel_vendor.py', 'generate-frankel-vendor.sh',
                     'prepare-phase1-frankel-vendor-cache-20261012-6.sh',
                     'phase1_frankel_vendor_cache_driver_20261011_4.py'):
            argv = ['/usr/bin/python3', '/bounded/' + name]
            with self.subTest(name=name), \
                 mock.patch.object(driver.Path, 'iterdir', return_value=[self.fake_process(argv)]), \
                 mock.patch.object(driver.os, 'execve') as execute, \
                 self.assertRaisesRegex(ValueError, name):
                driver.live_process_check([], 'api', self.selection)
            execute.assert_not_called()

    def test_exact_peer_command_is_allowed_but_a_foreign_variant_is_not(self):
        peer = driver.commands(self.selection, 'recents')
        with mock.patch.object(driver.Path, 'iterdir', return_value=[self.fake_process(peer)]):
            driver.live_process_check([], 'api', self.selection)
        foreign = peer + ['--foreign-argument']
        with mock.patch.object(driver.Path, 'iterdir', return_value=[self.fake_process(foreign)]), \
             self.assertRaisesRegex(ValueError, 'Preserve live'):
            driver.live_process_check([], 'api', self.selection)

    def test_unrelated_node_process_is_not_mistaken_for_vendor_work(self):
        argv = ['/usr/bin/node', '/unrelated/server.js']
        with mock.patch.object(driver.Path, 'iterdir', return_value=[self.fake_process(argv)]):
            driver.live_process_check([], 'api', self.selection)

    def test_duplicate_selection_fields_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON field'):
            json.loads('{"derived_image_id":"old","derived_image_id":"new"}',
                       object_pairs_hook=driver.unique)

    def test_synthetic_ready_check_only_still_cannot_exec(self):
        with contextlib.ExitStack() as stack:
            for field, value in (('PACKET_SHA', '1' * 64), ('WRONG_SHA', '2' * 64),
                                 ('SELECTION_SHA', '3' * 64)):
                stack.enter_context(mock.patch.object(driver, field, value))
            stack.enter_context(mock.patch.object(driver, 'local_inputs'))
            stack.enter_context(mock.patch('docker_locality_proof.command_environment',
                                           return_value={'HOME': '/u/elric'}))
            stack.enter_context(mock.patch('docker_locality_proof.trusted_local_docker',
                                           return_value=(None, None, None, {'id': 'local'})))
            resources = stack.enter_context(mock.patch('run_native_matrix.resources',
                                                       return_value={'jobs': 2}))
            stack.enter_context(mock.patch.object(driver, 'selected', return_value=self.selection))
            stack.enter_context(mock.patch.object(driver, 'running_guest_check', return_value=[]))
            stack.enter_context(mock.patch.object(driver, 'live_process_check'))
            stack.enter_context(mock.patch.object(Path, 'exists', return_value=False))
            stack.enter_context(mock.patch.object(Path, 'is_symlink', return_value=False))
            execute = stack.enter_context(mock.patch.object(driver.os, 'execve'))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            self.assertEqual(0, driver.main(['--check-only', '--lane', 'api']))
        resources.assert_called_once_with(2)
        execute.assert_not_called()
        self.assertEqual('admitted_nonreserving_not_guest_verified',
                         json.loads(output.getvalue())['status'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
