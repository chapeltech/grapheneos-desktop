"""Host-only generation-7 launch-guard tests; no Docker/guest execution."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


sys.path.insert(0, '/u/elric/tree/wonad/android/tools')
DRIVER_PATH = Path('/u/elric/tree/wonad-phase1-build-evidence/'
                   'run-phase1-custom7-api-recents-packet8-20261012-7.py')
spec = importlib.util.spec_from_file_location('custom7_future_packet8_driver', DRIVER_PATH)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class PreparedBindingTests(unittest.TestCase):
    def test_future_artifacts_are_literal_fresh_paths_and_all_pending(self):
        self.assertEqual('phase1-emulator-client-packet-20261012-8', driver.PACKET.name)
        self.assertEqual('phase1-wrong-signer-bundle-20261012-8', driver.WRONG.parent.name)
        self.assertEqual('phase1-custom7-api-recents-packet8-selection-20261012-7.json',
                         driver.SELECTION.name)
        self.assertEqual(set(driver.PENDING.values()),
                         {driver.PACKET_SHA, driver.WRONG_SHA, driver.SELECTION_SHA})
        self.assertFalse(driver.PACKET.exists())
        self.assertFalse(driver.WRONG.exists())
        self.assertFalse(driver.SELECTION.exists())

    def test_outputs_are_fresh_separate_and_have_no_current_latest_alias(self):
        self.assertNotEqual(driver.OUTPUTS['api'], driver.OUTPUTS['recents'])
        self.assertEqual('runtime-api-packet8-20261012-7', driver.OUTPUTS['api'].name)
        self.assertEqual('runtime-recents-packet8-20261012-7', driver.OUTPUTS['recents'].name)
        for path in (*driver.OUTPUTS.values(), driver.PACKET, driver.WRONG, driver.SELECTION):
            self.assertNotRegex(str(path), r'(?:^|[-_/])(current|latest)(?:$|[-_/])')
            self.assertFalse(path.exists())

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

    def test_every_pending_identity_blocks_individually(self):
        actual = '1' * 64
        for role, field in (('packet', 'PACKET_SHA'), ('wrong', 'WRONG_SHA'),
                            ('selection', 'SELECTION_SHA')):
            values = {'PACKET_SHA': actual, 'WRONG_SHA': actual, 'SELECTION_SHA': actual}
            values[field] = driver.PENDING[role]
            patches = [mock.patch.object(driver, name, value) for name, value in values.items()]
            with self.subTest(role=role), contextlib.ExitStack() as stack:
                for patch in patches:
                    stack.enter_context(patch)
                with self.assertRaisesRegex(ValueError, 'NOT READY'):
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
                 mock.patch.object(driver, 'local_inputs') as local, \
                 mock.patch.object(driver.subprocess, 'check_output') as docker, \
                 mock.patch.object(driver.os, 'execve') as execute, \
                 self.assertRaisesRegex(ValueError, 'NOT READY'):
                driver.main(arguments)
            local.assert_not_called(); docker.assert_not_called(); execute.assert_not_called()

    def test_selected_has_its_own_pending_guard_before_file_or_docker_access(self):
        with mock.patch.object(driver, 'digest') as digest, \
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
