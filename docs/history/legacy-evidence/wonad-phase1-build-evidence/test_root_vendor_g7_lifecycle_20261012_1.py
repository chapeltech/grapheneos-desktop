"""Independent host-only lifecycle regressions; every Docker/cleanup seam mocked."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, '/u/elric/tree/wonad/android/tests')
from test_run_frankel_vendor import mocked_execution, vendor

assert hashlib.sha256(Path(vendor.__file__).read_bytes()).hexdigest() == 'a016e708552b543cc8a23b75bc01f80cc6bcf973152ca37d83de169d5e9fbf88'


def state(status):
    return {'State': {'Status': status, 'ExitCode': 0, 'OOMKilled': False}}


class RootLifecycleRegressions(unittest.TestCase):
    def test_unknown_create_timeout_skips_post_create_cleanup(self):
        with mocked_execution() as (config, _ids, clean, writes), \
             mock.patch.object(vendor, 'docker_checked',
                 side_effect=subprocess.TimeoutExpired(['docker', 'create'], 30)):
            self.assertEqual(2, vendor.execute(config))
            self.assertEqual(1, len(clean))
            result = writes[config.result]
            self.assertTrue(result['container']['create_attempted'])
            self.assertIsNone(result['container']['id'])
            self.assertEqual('TimeoutExpired', result['primary']['exception']['class'])
            self.assertIn('not proven stopped', result['cleanup']['exception']['message'])

    def test_ascii_malformed_create_output_retains_the_safe_control(self):
        with mocked_execution() as (config, _ids, clean, writes), \
             mock.patch.object(vendor, 'docker_checked', return_value=b'malformed-id\n'), \
             mock.patch.object(vendor, 'docker_inspect', side_effect=vendor.Refusal('unknown ID')):
            self.assertEqual(2, vendor.execute(config))
            self.assertEqual(1, len(clean))
            self.assertFalse(writes[config.result]['container']['authoritatively_stopped'])

    def test_interrupted_live_container_preserves_primary_and_skips_cleanup(self):
        identity = 'a' * 64
        def validate(_info, _config, _identity, _nonce, *, stopped):
            if stopped:
                raise vendor.Refusal('still running')
            return True
        with mocked_execution() as (config, _ids, clean, writes), \
             mock.patch.object(vendor, 'docker_checked', return_value=(identity + '\n').encode()), \
             mock.patch.object(vendor, 'docker_inspect', side_effect=[
                 (state('created'), b'created'), (state('running'), b'running')]), \
             mock.patch.object(vendor, 'validate_container', side_effect=validate), \
             mock.patch.object(vendor, 'run_builder', side_effect=KeyboardInterrupt('primary stop')):
            with self.assertRaisesRegex(KeyboardInterrupt, 'primary stop'):
                vendor.execute(config)
            self.assertEqual(1, len(clean))
            result = writes[config.result]
            self.assertEqual('KeyboardInterrupt', result['primary']['exception']['class'])
            self.assertEqual('Refusal', result['container']['stop_proof_exception']['class'])

    def test_stop_proof_exception_does_not_mask_builder_exception(self):
        identity = 'b' * 64
        with mocked_execution() as (config, _ids, clean, writes), \
             mock.patch.object(vendor, 'docker_checked', return_value=(identity + '\n').encode()), \
             mock.patch.object(vendor, 'docker_inspect', side_effect=[
                 (state('created'), b'created'), RuntimeError('stop proof')]), \
             mock.patch.object(vendor, 'validate_container', return_value=True), \
             mock.patch.object(vendor, 'run_builder', side_effect=RuntimeError('builder primary')):
            self.assertEqual(2, vendor.execute(config))
            self.assertEqual(1, len(clean))
            result = writes[config.result]
            self.assertEqual('builder primary', result['primary']['exception']['message'])
            self.assertEqual('stop proof', result['container']['stop_proof_exception']['message'])

    def test_each_nested_source_directory_replacement_skips_final_cleanup(self):
        identity = 'c' * 64
        for relative in ('.repo', 'out', 'vendor/adevtool'):
            with self.subTest(relative=relative), mocked_execution() as (config, _ids, clean, writes):
                def replace(*unused):
                    selected = config.source / relative
                    selected.rename(selected.with_name(selected.name + '.preserved'))
                    selected.mkdir()
                    return 0
                with mock.patch.object(vendor, 'docker_checked', return_value=(identity + '\n').encode()), \
                     mock.patch.object(vendor, 'docker_inspect', side_effect=[
                         (state('created'), b'created'), (state('exited'), b'exited')]), \
                     mock.patch.object(vendor, 'validate_container', return_value=True), \
                     mock.patch.object(vendor, 'run_builder', side_effect=replace):
                    self.assertEqual(2, vendor.execute(config))
                self.assertEqual(1, len(clean))
                self.assertIn('identity changed', writes[config.result]['cleanup']['exception']['message'])

    def test_postlaunch_attempt_lock_replacement_skips_cleanup_and_is_not_sealed(self):
        identity = 'd' * 64
        with mocked_execution() as (config, _ids, clean, writes):
            def replace(*unused):
                config.attempt_lock.unlink()
                config.attempt_lock.write_text('{"replacement":true}\n')
                return 0
            with mock.patch.object(vendor, 'docker_checked', return_value=(identity + '\n').encode()), \
                 mock.patch.object(vendor, 'docker_inspect', side_effect=[
                     (state('created'), b'created'), (state('exited'), b'exited')]), \
                 mock.patch.object(vendor, 'validate_container', return_value=True), \
                 mock.patch.object(vendor, 'run_builder', side_effect=replace):
                self.assertEqual(2, vendor.execute(config))
            self.assertEqual(1, len(clean))
            binding = writes[config.result]['inputs']['attempt_lock']
            self.assertIsNone(binding['final'])
            self.assertIsNotNone(binding['binding_exception'])

    def test_directory_mode_change_is_identity_drift_not_success(self):
        identity = 'e' * 64
        with mocked_execution() as (config, _ids, clean, writes):
            def change(*unused):
                target = config.source / '.repo'
                os.chmod(target, (target.stat().st_mode & 0o7777) ^ 0o010)
                return 0
            with mock.patch.object(vendor, 'docker_checked', return_value=(identity + '\n').encode()), \
                 mock.patch.object(vendor, 'docker_inspect', side_effect=[
                     (state('created'), b'created'), (state('exited'), b'exited')]), \
                 mock.patch.object(vendor, 'validate_container', return_value=True), \
                 mock.patch.object(vendor, 'run_builder', side_effect=change):
                self.assertEqual(2, vendor.execute(config))
            self.assertEqual(1, len(clean))
            self.assertEqual('failed_cleanup', writes[config.result]['status'])

    def test_precreate_identity_change_never_calls_docker_create(self):
        with mocked_execution() as (config, _ids, clean, writes):
            original = vendor.prepare_reflink
            def replace(_config):
                target = config.source / 'out'
                target.rename(config.source / 'out.preserved')
                target.mkdir()
                return original(_config)
            with mock.patch.object(vendor, 'prepare_reflink', side_effect=replace), \
                 mock.patch.object(vendor, 'docker_checked') as create:
                self.assertEqual(2, vendor.execute(config))
            create.assert_not_called()
            self.assertEqual(1, len(clean))
            self.assertFalse(writes[config.result]['container']['create_attempted'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
