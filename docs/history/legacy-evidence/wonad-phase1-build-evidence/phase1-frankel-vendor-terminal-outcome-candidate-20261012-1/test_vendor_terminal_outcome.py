"""External source/lifecycle proposal only; all Docker/cache mutation seams mocked."""
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

REPO = Path('/u/elric/tree/wonad')
ORIGINAL = REPO / 'android/tools/run_frankel_vendor.py'
sys.path.insert(0, str(REPO / 'android/tests'))
import test_run_frankel_vendor as baseline

def selected_vendor():
    candidate = os.environ.get('WONAD_VENDOR_CANDIDATE')
    if candidate is None:
        return baseline.vendor
    # __file__ models the actual prospective installation path. No parser/run action is invoked.
    module = types.ModuleType('external_vendor_terminal_candidate')
    module.__file__ = str(ORIGINAL)
    sys.modules[module.__name__] = module
    exec(compile(Path(candidate).read_bytes(), str(ORIGINAL), 'exec'), module.__dict__)
    return module

vendor = selected_vendor()

@contextmanager
def selected_fixture_module():
    previous = baseline.vendor
    baseline.vendor = vendor
    try:
        yield
    finally:
        baseline.vendor = previous

def terminal(info, *, oom=True, exit_code=1):
    value = copy.deepcopy(info)
    value['State'].update(Status='exited', Running=False, Paused=False,
        Restarting=False, Dead=False, Pid=0, OOMKilled=oom, ExitCode=exit_code,
        StartedAt='2026-10-12T01:45:58.521430877Z',
        FinishedAt='2026-10-12T01:54:32.330163595Z')
    return value

class TerminalStateTests(unittest.TestCase):
    def fixture(self, root):
        profile = baseline.DockerProfileTests()
        config = profile.config(root)
        identity, nonce, info = profile.info(config)
        return config, identity, nonce, info
    def test_actual_retained_g8_oom_state_can_prove_terminal_not_success(self):
        observation = Path('/u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-vendor-g8-actual-oom-root-observation-20261012-1.json')
        data = observation.read_bytes()
        self.assertEqual('c602d17bcd37ff22db022c08e7428d9151f45bcb69778e8c077d9b23f965b164', hashlib.sha256(data).hexdigest())
        actual_subset = json.loads(data)['actual_state']
        # Actual retained subset grafted onto explicitly SYNTHETIC complete owned-profile fixture.
        with tempfile.TemporaryDirectory() as root, selected_fixture_module():
            config, identity, nonce, created = self.fixture(root)
            info = terminal(created)
            info['State'].update(actual_subset)
            self.assertTrue(vendor.validate_container(info, config, identity, nonce, stopped=True))
            self.assertTrue(vendor.source_cleanup_is_safe(True, identity, True))
            self.assertEqual('failed_builder', vendor.outcome_status(1, None, None))
    def test_only_exact_boolean_oom_may_prove_terminal(self):
        with tempfile.TemporaryDirectory() as root, selected_fixture_module():
            config, identity, nonce, created = self.fixture(root)
            for invalid in (None, 0, 1, 'true', [], {}):
                info = terminal(created); info['State']['OOMKilled'] = invalid
                with self.subTest(invalid=invalid), self.assertRaises(vendor.Refusal):
                    vendor.validate_container(info, config, identity, nonce, stopped=True)
    def test_bool_or_unknown_process_exit_is_not_terminal_evidence(self):
        with tempfile.TemporaryDirectory() as root, selected_fixture_module():
            config, identity, nonce, created = self.fixture(root)
            for key, value in [('Pid', False), ('Pid', None), ('Pid', 12), ('ExitCode', False),
                               ('ExitCode', None), ('ExitCode', '1'), ('StartedAt', None),
                               ('FinishedAt', ''), ('FinishedAt', 1)]:
                info = terminal(created); info['State'][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(vendor.Refusal):
                    vendor.validate_container(info, config, identity, nonce, stopped=True)
    def test_unknown_identity_profile_mount_ownership_or_state_refuses_terminal(self):
        with tempfile.TemporaryDirectory() as root, selected_fixture_module():
            config, identity, nonce, created = self.fixture(root)
            changes = [('Id', None), ('Name', '/unowned'), ('Image', 'sha256:' + 'f' * 64),
                ('User', '0:0'), ('nonce', 'f' * 64), ('Memory', vendor.MEMORY + 1),
                ('mount', 'foreign'), ('Running', True), ('Status', 'running'), ('Paused', True),
                ('Restarting', True), ('Dead', True), ('Pid', 1)]
            for key, value in changes:
                info = terminal(created)
                if key == 'User': info['Config']['User'] = value
                elif key == 'nonce': info['Config']['Labels']['org.wonad.phase1.vendor-attempt'] = value
                elif key == 'Memory': info['HostConfig'][key] = value
                elif key == 'mount': info['Mounts'][0]['Source'] = value
                elif key in info['State']: info['State'][key] = value
                else: info[key] = value
                with self.subTest(key=key), self.assertRaises(vendor.Refusal):
                    vendor.validate_container(info, config, identity, nonce, stopped=True)
    def test_created_state_still_rejects_oom(self):
        with tempfile.TemporaryDirectory() as root, selected_fixture_module():
            config, identity, nonce, created = self.fixture(root)
            created['State']['OOMKilled'] = True
            with self.assertRaises(vendor.Refusal):
                vendor.validate_container(created, config, identity, nonce, stopped=False)

class OutcomeLifecycleTests(unittest.TestCase):
    def lifecycle(self, *, oom, code, mutation=None, error=None):
        with selected_fixture_module(), baseline.mocked_execution() as (config, identities, clean, writes):
            config.builder_image = 'sha256:' + 'a' * 64
            config.adevtool_commit = 'b' * 40
            identity, nonce, created = baseline.DockerProfileTests().info(config)
            ended = terminal(created, oom=oom, exit_code=code)
            if mutation is not None: mutation(ended)
            with mock.patch.object(vendor.secrets, 'token_hex', return_value=nonce), \
                 mock.patch.object(vendor, 'docker_checked', return_value=(identity + '\n').encode()), \
                 mock.patch.object(vendor, 'docker_inspect', side_effect=[
                     (created, vendor.canonical(created)), (ended, vendor.canonical(ended))]), \
                 mock.patch.object(vendor, 'run_builder', side_effect=error, return_value=code), \
                 mock.patch.object(vendor, 'verify_generated_vendor', return_value={'verified': True}) as verify:
                returned = vendor.execute(config)
            return returned, writes[config.result], len(clean), verify.call_count
    def test_real_validator_oom_nonzero_lifecycle_allows_only_owned_cleanup(self):
        returned, result, clean, verify = self.lifecycle(oom=True, code=1)
        self.assertEqual(1, returned)
        self.assertTrue(result['container']['authoritatively_stopped'])
        self.assertTrue(result['container']['stopped_inspect']['oom_killed'])
        self.assertIsNone(result['container']['stop_proof_exception'])
        self.assertEqual(2, clean)
        self.assertEqual('failed_builder', result['status'])
        self.assertIsNone(result['generated_vendor']); self.assertEqual(0, verify)
    def test_oom_zero_exit_never_qualifies_generated_or_invokes_verifier(self):
        returned, result, clean, verify = self.lifecycle(oom=True, code=0)
        self.assertNotEqual(0, returned)
        self.assertEqual(2, clean)
        self.assertTrue(result['container']['authoritatively_stopped'])
        self.assertNotEqual('generated', result['status'])
        self.assertIsNone(result['generated_vendor']); self.assertEqual(0, verify)
    def test_healthy_zero_exit_keeps_generation_success_behavior(self):
        returned, result, clean, verify = self.lifecycle(oom=False, code=0)
        self.assertEqual(0, returned); self.assertEqual('generated', result['status'])
        self.assertEqual(2, clean); self.assertEqual(1, verify)
    def test_wrong_final_identity_skips_cleanup_and_generation(self):
        returned, result, clean, verify = self.lifecycle(oom=True, code=1,
            mutation=lambda info: info.update(Id='f' * 64))
        self.assertEqual(2, returned); self.assertEqual(1, clean)
        self.assertFalse(result['container']['authoritatively_stopped'])
        self.assertIsNotNone(result['container']['stop_proof_exception'])
        self.assertEqual(0, verify)
    def test_running_final_state_skips_cleanup_and_generation(self):
        returned, result, clean, verify = self.lifecycle(oom=True, code=1,
            mutation=lambda info: info['State'].update(Status='running', Running=True, Pid=17))
        self.assertEqual(2, returned); self.assertEqual(1, clean)
        self.assertFalse(result['container']['authoritatively_stopped']); self.assertEqual(0, verify)
    def test_original_builder_exception_preserved_when_oom_state_is_terminal(self):
        returned, result, clean, verify = self.lifecycle(oom=True, code=1,
            error=RuntimeError('original host attachment failure'))
        self.assertEqual(2, returned); self.assertEqual(2, clean)
        self.assertEqual('original host attachment failure', result['primary']['exception']['message'])
        self.assertTrue(result['container']['authoritatively_stopped']); self.assertEqual(0, verify)
    def test_oom_stopped_container_still_cannot_clean_replaced_source_metadata(self):
        with selected_fixture_module(), baseline.mocked_execution() as (config, identities, clean, writes):
            config.builder_image = 'sha256:' + 'a' * 64
            config.adevtool_commit = 'b' * 40
            identity, nonce, created = baseline.DockerProfileTests().info(config)
            ended = terminal(created)
            def replace_before_stop(*unused):
                selected = config.source / '.repo'
                selected.rename(config.source / '.repo-preserved')
                selected.mkdir()
                return 1
            with mock.patch.object(vendor.secrets, 'token_hex', return_value=nonce), \
                 mock.patch.object(vendor, 'docker_checked', return_value=(identity + '\n').encode()), \
                 mock.patch.object(vendor, 'docker_inspect', side_effect=[
                     (created, vendor.canonical(created)), (ended, vendor.canonical(ended))]), \
                 mock.patch.object(vendor, 'run_builder', side_effect=replace_before_stop), \
                 mock.patch.object(vendor, 'verify_generated_vendor') as verify:
                self.assertEqual(2, vendor.execute(config))
            result = writes[config.result]
            self.assertTrue(result['container']['authoritatively_stopped'])
            self.assertEqual(1, len(clean)); verify.assert_not_called()
            self.assertEqual('failed_builder', result['status'])
            self.assertIn('identity changed', result['cleanup']['exception']['message'])
    def test_success_gate_requires_zero_exact_integer_nonoom_and_terminal_reference(self):
        healthy = {'exit_code': 0, 'oom_killed': False}
        self.assertIsNone(vendor.require_successful_stopped_build(0, True, healthy))
        for exit_code, stopped, reference in ((False, True, healthy), (0.0, True, healthy),
                (None, True, healthy), (0, False, healthy), (0, True, None),
                (0, True, {}), (0, True, dict(healthy, oom_killed=True)),
                (0, True, dict(healthy, exit_code=False)), (0, True, dict(healthy, exit_code=1))):
            with self.subTest(exit_code=exit_code, stopped=stopped, reference=reference), \
                    self.assertRaises(vendor.Refusal):
                vendor.require_successful_stopped_build(exit_code, stopped, reference)

if __name__ == '__main__': unittest.main(verbosity=2)
