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
    '/u/elric/tree/wonad-phase1-build-evidence/run-phase1-custom7-api-recents-packet4-20261011-1.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class AdmissionTests(unittest.TestCase):
    def setUp(self):
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
            probe.assert_called_once_with(['docker', 'ps', '-q', '--no-trunc'], text=True, timeout=30)

    def debug(self):
        proof = driver.load(driver.DEBUG_PROOF)
        return json.loads(proof['inspect_result']['output'])[0], proof['top_result']['output']

    def test_literal_sleep_adb_debug_is_preserved_not_an_allowed_qemu_guest(self):
        info, top = self.debug()
        with mock.patch.object(driver.subprocess, 'check_output', side_effect=[
                driver.DEBUG_ID + '\n', json.dumps([info]), top]) as probe:
            self.assertEqual(driver.running_guest_check(self.selection, 'api'), [])
            self.assertEqual(probe.call_count, 3)
            self.assertEqual(probe.call_args.args[0], ['docker', 'top', driver.DEBUG_ID,
                                                    '-eo', 'pid,ppid,comm,args'])

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

    def test_duplicate_selection_json_cannot_be_accepted(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON field'):
            json.loads('{"derived_image_id":"old","derived_image_id":"new"}', object_pairs_hook=driver.unique)


if __name__ == '__main__':
    unittest.main(verbosity=2)
