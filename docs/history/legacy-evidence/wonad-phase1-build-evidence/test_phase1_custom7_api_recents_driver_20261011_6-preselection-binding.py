"""Host-only launch-guard tests; no container/guest/tool execution."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, '/u/elric/tree/wonad/android/tools')
spec = importlib.util.spec_from_file_location('custom7_fresh_driver',
    '/u/elric/tree/wonad-phase1-build-evidence/run-phase1-custom7-api-recents-packet7-20261011-6.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class DraftBindingTests(unittest.TestCase):
    def test_actual_packet7_current_sources_but_no_fabricated_image_selection(self):
        self.assertEqual(driver.PACKET_SHA,
                         driver.digest(driver.PACKET / 'receipt.json'))
        self.assertEqual('d0ccf5bd861b95e086ad6b96359943d429ab383b141d4db2282f7cc9b9a6c97e', driver.WRONG_SHA)
        self.assertEqual(driver.WRONG_SHA, driver.digest(driver.WRONG))
        self.assertEqual('PENDING_ACTUAL_NATIVE4_DERIVED6_SELECTION', driver.SELECTION_SHA)
        self.assertFalse(driver.SELECTION.exists())
        self.assertEqual(driver.PRODUCT_ORIGIN,
            Path('/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-5/target/product/emu64x'))
        for name, expected in driver.SOURCE_SHA.items():
            self.assertEqual(expected, driver.digest(driver.ROOT / name), name)
        self.assertFalse(any(value.exists() for value in driver.OUTPUTS.values()))


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        # Synthetic pins are test-only; no packet7/image/selection artifact is
        # manufactured or claimed to exist by this host guard suite.
        for field, value in [('PACKET_SHA', '1' * 64), ('WRONG_SHA', '2' * 64),
                             ('SELECTION_SHA', '3' * 64)]:
            patch = mock.patch.object(driver, field, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.selection = {'product': str(driver.PRODUCT_ORIGIN),
                          'derived_image_id': 'sha256:' + 'a' * 64}

    def test_pending_selection_fails_closed(self):
        with mock.patch.object(driver, 'SELECTION_SHA', None), self.assertRaisesRegex(ValueError, 'NOT READY'):
            driver.selected()

    def test_each_lane_has_distinct_output_and_same_exact_candidate_packet(self):
        api, recents = (driver.commands(self.selection, lane) for lane in ('api', 'recents'))
        self.assertNotEqual(api[2], recents[2])
        self.assertEqual(api[api.index('--image') + 1], self.selection['derived_image_id'])
        self.assertEqual(recents[recents.index('--image') + 1], self.selection['derived_image_id'])
        self.assertNotEqual(api[-1], recents[-1])
        for command in (api, recents):
            self.assertIn(driver.PACKET_SHA, command)
            self.assertIn(str(driver.PACKET), command)
            self.assertNotIn('settings', command)
            self.assertNotIn('put', command)

    def test_auditors_remain_separate_and_exact(self):
        for lane in ('api', 'recents'):
            command = driver.commands(self.selection, lane, audit=True)
            self.assertIn(str(driver.OUTPUTS[lane] / 'report.json'), command)
            self.assertNotIn('--image', command)
            self.assertIn(driver.PACKET_SHA, command)
        self.assertNotEqual(driver.commands(self.selection, 'api', audit=True)[2],
                            driver.commands(self.selection, 'recents', audit=True)[2])

    def test_execution_must_be_an_explicit_mode(self):
        for args in ([], ['--check-only', '--execute-after-root-authorization']):
            with self.subTest(args=args), self.assertRaisesRegex(ValueError, 'Choose check-only'):
                driver.main(args)

    def test_check_only_cannot_exec_a_producer(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(driver, 'local_inputs'))
            budget = stack.enter_context(mock.patch('run_native_matrix.resources', return_value={'jobs': 2}))
            stack.enter_context(mock.patch('docker_locality_proof.command_environment', return_value={'HOME': '/u/elric'}))
            stack.enter_context(mock.patch('docker_locality_proof.trusted_local_docker', return_value=(None, None, None, {'id': 'local'})))
            stack.enter_context(mock.patch.object(driver, 'selected', return_value=self.selection))
            stack.enter_context(mock.patch.object(driver, 'running_guest_check', return_value=[]))
            stack.enter_context(mock.patch.object(driver, 'live_process_check'))
            stack.enter_context(mock.patch.object(Path, 'exists', return_value=False))
            stack.enter_context(mock.patch.object(Path, 'is_symlink', return_value=False))
            execute = stack.enter_context(mock.patch.object(driver.os, 'execve'))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            self.assertEqual(driver.main(['--check-only', '--lane', 'api']), 0)
            budget.assert_called_once_with(2)
            execute.assert_not_called()

    def test_foreign_kvm_guest_is_preserved_and_rejected(self):
        foreign = 'b' * 64
        info = {'Id': foreign, 'Image': 'sha256:' + 'c' * 64,
                'HostConfig': {'Devices': [{'PathOnHost': '/dev/kvm'}]},
                'Config': {'Labels': {}}, 'Mounts': []}
        with mock.patch.object(driver.subprocess, 'check_output', side_effect=[foreign + '\n', json.dumps([info])]), \
             self.assertRaisesRegex(ValueError, 'Another KVM/native/GUI guest'):
            driver.running_guest_check(self.selection, 'api')

    def test_no_running_kvm_guests_is_admitted(self):
        with mock.patch.object(driver.subprocess, 'check_output', return_value='') as probe:
            self.assertEqual(driver.running_guest_check(self.selection, 'recents'), [])
            probe.assert_called_once_with(['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock',
                                          'ps', '-q', '--no-trunc'], env=mock.ANY,
                                          text=True, timeout=30)

    def debug(self):
        proof = driver.load(driver.DEBUG_PROOF)
        return json.loads(proof['inspect_result']['output'])[0], proof['top_result']['output']

    def test_literal_sleep_adb_debug_is_preserved_not_an_allowed_qemu_guest(self):
        info, top = self.debug()
        with mock.patch.object(driver.subprocess, 'check_output', side_effect=[
                driver.DEBUG_ID + '\n', json.dumps([info]), top]) as probe:
            self.assertEqual(driver.running_guest_check(self.selection, 'api'), [])
            self.assertEqual(probe.call_count, 3)
            self.assertEqual(probe.call_args.args[0], ['/usr/bin/docker', '--host',
                                                    'unix:///var/run/docker.sock', 'top',
                                                    driver.DEBUG_ID, '-eo', 'pid,ppid,comm,args'])

    def test_debug_with_any_extra_process_is_rejected(self):
        info, top = self.debug()
        for command in ('qemu-system-x86_64 -avd foo', 'sh', 'sleep 1'):
            with self.subTest(command=command), mock.patch.object(driver.subprocess, 'check_output',
                    return_value=top + '3000000 2362784 unknown ' + command + '\n'), \
                 self.assertRaisesRegex(ValueError, 'only the exact observed'):
                driver.preserved_debug_check(info)

    def test_debug_changed_image_config_bind_or_mount_is_rejected_before_top(self):
        original, _ = self.debug()
        for field in ('Image', 'Config', 'HostConfig', 'Mounts'):
            info = copy.deepcopy(original)
            if field == 'Image':
                info[field] = 'sha256:' + 'c' * 64
            elif field == 'Config':
                info[field]['Cmd'] = ['emulator']
            elif field == 'HostConfig':
                info[field]['Binds'][0] = '/different:/runtime:z'
            else:
                info[field][0]['RW'] = False
            with self.subTest(field=field), mock.patch.object(driver.subprocess, 'check_output') as probe, \
                 self.assertRaisesRegex(ValueError, 'identity/profile changed'):
                driver.preserved_debug_check(info)
            probe.assert_not_called()

    def test_debug_changed_pid_or_restarted_container_is_rejected(self):
        original, _ = self.debug()
        for field, value in [('Pid', 1), ('StartedAt', 'later'), ('Running', False)]:
            info = copy.deepcopy(original)
            info['State'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'identity/profile changed'):
                driver.preserved_debug_check(info)

    def process(self, argv, cgroup=''):
        item = mock.MagicMock()
        item.name = '3000001'
        cmdline = mock.MagicMock()
        cmdline.open.return_value = io.BytesIO(b'\0'.join(arg.encode() for arg in argv) + b'\0')
        groups = mock.Mock()
        groups.read_text.return_value = cgroup
        item.__truediv__.side_effect = lambda name: {'cmdline': cmdline, 'cgroup': groups}[name]
        return item

    def test_any_matrix_mode_including_freeze_is_excluded(self):
        process = self.process(['python3', '/u/elric/tree/wonad/android/tools/run_native_matrix.py', 'freeze'])
        with mock.patch.object(Path, 'iterdir', return_value=[process]), \
             self.assertRaisesRegex(ValueError, 'Preserve live build/native/GUI/foreign guest'):
            driver.live_process_check([], 'api', self.selection)

    def test_debug_qemu_is_never_a_guest_exemption(self):
        process = self.process(['qemu-system-x86_64', '-avd', 'foo'], '/docker/' + driver.DEBUG_ID)
        with mock.patch.object(Path, 'iterdir', return_value=[process]), \
             self.assertRaisesRegex(ValueError, 'Preserve live build/native/GUI/foreign guest'):
            driver.live_process_check([], 'api', self.selection)

    def test_oversized_process_cmdline_is_rejected_without_partial_classification(self):
        process = self.process(['x' * 65537])
        with mock.patch.object(Path, 'iterdir', return_value=[process]), \
             self.assertRaisesRegex(ValueError, 'Process command line exceeds bounded observation'):
            driver.live_process_check([], 'api', self.selection)

    def test_foreign_qemu_kvm_process_is_rejected(self):
        process = self.process(['qemu-kvm', '-name', 'foreign'])
        with mock.patch.object(Path, 'iterdir', return_value=[process]), \
             self.assertRaisesRegex(ValueError, 'Preserve live build/native/GUI/foreign guest'):
            driver.live_process_check([], 'api', self.selection)

    def test_empty_kernel_thread_cmdline_is_not_a_false_positive(self):
        process = self.process([])
        process.__truediv__.return_value = None
        cmdline = mock.MagicMock()
        cmdline.open.return_value = io.BytesIO(b'')
        process.__truediv__.side_effect = lambda name: cmdline if name == 'cmdline' else mock.Mock()
        with mock.patch.object(Path, 'iterdir', return_value=[process]):
            driver.live_process_check([], 'api', self.selection)

    def test_exact_peer_guest_qemu_is_allowed(self):
        peer = 'd' * 64
        process = self.process(['qemu-system-x86_64', '-avd', 'foo'], '/docker/' + peer)
        with mock.patch.object(Path, 'iterdir', return_value=[process]):
            driver.live_process_check([peer], 'api', self.selection)

    def test_peer_producer_requires_exact_pinned_argv(self):
        argv = driver.commands(self.selection, 'recents')
        with mock.patch.object(Path, 'iterdir', return_value=[self.process(argv)]):
            driver.live_process_check([], 'api', self.selection)
        with mock.patch.object(Path, 'iterdir', return_value=[self.process(argv + ['--unknown'])]), \
             self.assertRaisesRegex(ValueError, 'Preserve live build/native/GUI/foreign guest'):
            driver.live_process_check([], 'api', self.selection)

    def test_real_original_product_satisfies_repository_path_binding(self):
        from phase1_conformance_guest import candidate_builder
        native = driver.load(driver.AUTHORITY / 'native-manifest-packet4-20261011-1.json')
        candidate_builder.validate_phase1_base_evidence(native, driver.PRODUCT_ORIGIN)

    def test_real_staging_copy_fails_repository_path_binding(self):
        from phase1_conformance_guest import candidate_builder
        native = driver.load(driver.AUTHORITY / 'native-manifest-packet4-20261011-1.json')
        staging = driver.ROOT / 'android/out/phase1-native-candidate-custom7-5-1/product'
        with self.assertRaisesRegex(ValueError, 'not the product authenticated by the base candidate'):
            candidate_builder.validate_phase1_base_evidence(native, staging)

    def peer_info(self, peer):
        # A retained real Running inspection supplies the complete repository
        # container grammar. Only fixture image/output bindings are adapted.
        note = driver.EVIDENCE / 'phase1-custom7-packet4-two-boot-runtime-failure-20261011-1.json'
        self.assertEqual(driver.digest(note),
                         '13769b4beb42d62b397bca4ac900325795d22b0e8c838a14b31d052545896b4f')
        info = json.loads(driver.load(note)['api']['running_inspect']['output'])[0]
        directory = driver.OUTPUTS[peer] / 'guest' if peer == 'recents' else driver.OUTPUTS[peer]
        state = str(directory / 'emulator-state')
        info['Image'] = self.selection['derived_image_id']
        info['Mounts'][0]['Source'] = state
        info['HostConfig']['Binds'] = [state + ':/state:rw,Z']
        return info

    def test_api_guard_admits_exact_recents_nested_guest_using_real_inspector(self):
        info = self.peer_info('recents')
        with mock.patch.object(driver.subprocess, 'check_output',
                side_effect=[info['Id'] + '\n', json.dumps([info])]):
            self.assertEqual(driver.running_guest_check(self.selection, 'api'), [info['Id']])

    def test_recents_guard_admits_exact_direct_api_guest_using_real_inspector(self):
        info = self.peer_info('api')
        with mock.patch.object(driver.subprocess, 'check_output',
                side_effect=[info['Id'] + '\n', json.dumps([info])]):
            self.assertEqual(driver.running_guest_check(self.selection, 'recents'), [info['Id']])

    def test_old_flat_recents_state_and_foreign_state_are_rejected(self):
        for wrong in (driver.OUTPUTS['recents'] / 'emulator-state',
                      driver.OUTPUTS['api'] / 'emulator-state'):
            info = self.peer_info('recents')
            info['Mounts'][0]['Source'] = str(wrong)
            info['HostConfig']['Binds'] = [str(wrong) + ':/state:rw,Z']
            with self.subTest(wrong=wrong), mock.patch.object(driver.subprocess, 'check_output',
                    side_effect=[info['Id'] + '\n', json.dumps([info])]), \
                 self.assertRaisesRegex(ValueError, 'Another KVM/native/GUI guest'):
                driver.running_guest_check(self.selection, 'api')

    def test_nested_path_cannot_bypass_real_peer_profile(self):
        info = self.peer_info('recents')
        info['HostConfig']['Memory'] = 16 * 1024**3
        with mock.patch.object(driver.subprocess, 'check_output',
                side_effect=[info['Id'] + '\n', json.dumps([info])]), \
             self.assertRaisesRegex(ValueError, 'identity/isolation/resource profile'):
            driver.running_guest_check(self.selection, 'api')

    def test_pending_artifacts_block_before_docker_and_local_inputs(self):
        for field in ('PACKET_SHA', 'WRONG_SHA', 'SELECTION_SHA'):
            with self.subTest(field=field), mock.patch.object(driver, field, None), \
                 mock.patch.object(driver, 'local_inputs') as inputs, \
                 mock.patch.object(driver.subprocess, 'check_output') as docker, \
                 self.assertRaisesRegex(ValueError, 'NOT READY'):
                driver.main(['--check-only', '--lane', 'api'])
            inputs.assert_not_called()
            docker.assert_not_called()

    def test_each_pending_post_consent_host_source_pin_blocks_before_docker(self):
        affected = ('android/tools/phase1_conformance_guest.py',
                    'android/tools/phase1_conformance_acceptance.py',
                    'android/tools/phase1_conformance_recents_guest_acceptance.py')
        for name in affected:
            pending = 'PENDING_SYNTHETIC_REVIEWED_HOST_SOURCE'
            # Earlier sources are synthetically authenticated in this unit test;
            # the selected pending input must stop before any Docker probe.
            expected = {key: 'a' * 64 for key in driver.SOURCE_SHA}
            expected[name] = pending
            with self.subTest(source=name), \
                 mock.patch.dict(driver.SOURCE_SHA, expected, clear=True), \
                 mock.patch.object(driver.os, 'getuid', return_value=1000), \
                 mock.patch.object(driver.os, 'getgid', return_value=1000), \
                 mock.patch.object(driver, 'digest', return_value='a' * 64), \
                 mock.patch.object(driver.subprocess, 'check_output') as probe, \
                 self.assertRaisesRegex(ValueError, 'Reviewed runtime source changed: ' + name):
                driver.local_inputs()
            probe.assert_not_called()

    def test_docker_probes_have_explicit_endpoint_and_sanitized_environment(self):
        with mock.patch.dict(driver.os.environ, {'HOME': '/u/elric', 'PATH': '/untrusted/bin',
                                                'LD_PRELOAD': '/untrusted/preload.so'}, clear=True), \
             mock.patch.object(driver.subprocess, 'check_output', return_value='[]') as probe:
            driver.docker_output(['image', 'inspect', 'sha256:' + 'a' * 64])
        probe.assert_called_once_with(
            ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock',
             'image', 'inspect', 'sha256:' + 'a' * 64],
            env={'HOME': '/u/elric', 'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'},
            text=True, timeout=30)

    def test_docker_environment_override_is_rejected_before_probe(self):
        with mock.patch.dict(driver.os.environ, {'HOME': '/u/elric', 'DOCKER_HOST': 'tcp://foreign:2375'}, clear=True), \
             mock.patch.object(driver.subprocess, 'check_output') as probe, \
             self.assertRaisesRegex(ValueError, 'overrides are forbidden'):
            driver.docker_output(['ps'])
        probe.assert_not_called()

    def test_duplicate_selection_json_cannot_be_accepted(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON field'):
            json.loads('{"derived_image_id":"old","derived_image_id":"new"}', object_pairs_hook=driver.unique)


if __name__ == '__main__':
    unittest.main(verbosity=2)
