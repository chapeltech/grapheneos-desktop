#!/usr/bin/env python3
"""Bounded pure profile/admission tests; never create, start, build or download."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path('/u/elric/tree/wonad-phase1-build-evidence')
spec = importlib.util.spec_from_file_location(
    'vendor_driver', ROOT / 'phase1_frankel_vendor_driver_20261011_1.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
PROOF = ROOT / 'phase1-frankel-vendor-create-only-20261011-3'
INFO = json.loads((PROOF / 'inspect.json').read_bytes())[0]
CREATED = json.loads((PROOF / 'created-id.json').read_bytes())
RECEIPT = json.loads((PROOF / 'receipt.json').read_bytes())


class VendorTests(unittest.TestCase):
    def test_current_helper_and_real_inspect_bindings(self):
        self.assertEqual(h.ref(h.HELPER), RECEIPT['input_binding']['inputs'][str(h.HELPER)])
        self.assertEqual(h.ref(h.DRIVER), RECEIPT['input_binding']['inputs'][str(h.DRIVER)])
        self.assertEqual(h.ref(PROOF / 'inspect.json'), RECEIPT['inspect'])
        self.assertTrue(h.validate_created(INFO, CREATED['id'], CREATED['nonce']))
        self.assertTrue(h.owned_never_started(INFO, CREATED['id'], CREATED['nonce']))

    def test_order_normalization_is_not_identity_relaxation(self):
        changed = copy.deepcopy(INFO)
        changed['HostConfig']['Binds'].reverse()
        changed['Mounts'].reverse()
        self.assertTrue(h.validate_created(changed, CREATED['id'], CREATED['nonce']))
        self.assertTrue(h.owned_never_started(changed, CREATED['id'], CREATED['nonce']))
        for values in ([], None, INFO['HostConfig']['Binds'] * 2,
                       [INFO['HostConfig']['Binds'][0]] * 2,
                       [str(h.SOURCE) + ':/grapheneos:ro', str(h.WONAD) + ':/wonad:ro']):
            with self.subTest(binds=values):
                changed = copy.deepcopy(INFO)
                changed['HostConfig']['Binds'] = values
                with self.assertRaises(ValueError):
                    h.validate_created(changed, CREATED['id'], CREATED['nonce'])
                with self.assertRaises(ValueError):
                    h.owned_never_started(changed, CREATED['id'], CREATED['nonce'])

    def test_reject_profile_mutations(self):
        mutations = [
            (('Id',), '0' * 64), (('Name',), '/unowned'), (('Image',), 'sha256:' + '0' * 64),
            (('Config', 'Image'), 'sha256:' + '0' * 64), (('Config', 'Labels'), {}),
            (('Config', 'User'), '0:0'), (('Config', 'WorkingDir'), '/'),
            (('Config', 'Entrypoint'), ['/bin/bash']), (('Config', 'Cmd'), ['-i', '/bin/true']),
            (('Config', 'AttachStdin'), True), (('Config', 'AttachStdout'), False),
            (('Config', 'AttachStderr'), False), (('Config', 'OpenStdin'), True),
            (('Config', 'Tty'), True), (('Config', 'ExposedPorts'), {'6080/tcp': {}}),
            (('Config', 'Volumes'), {'/keys': {}}), (('Path',), '/bin/true'), (('Args',), []),
            (('State', 'Status'), 'exited'), (('State', 'Running'), True),
            (('State', 'Pid'), 123), (('State', 'StartedAt'), '2026-10-11T12:00:00Z'),
            (('State', 'FinishedAt'), '2026-10-11T12:00:00Z'),
            (('State', 'OOMKilled'), True), (('HostConfig', 'Memory'), 0),
            (('HostConfig', 'MemorySwap'), -1), (('HostConfig', 'NanoCpus'), 0),
            (('HostConfig', 'CpusetCpus'), '0-71'), (('HostConfig', 'PidsLimit'), 0),
            (('HostConfig', 'ReadonlyRootfs'), False), (('HostConfig', 'NetworkMode'), 'host'),
            (('HostConfig', 'Privileged'), True), (('HostConfig', 'AutoRemove'), True),
            (('HostConfig', 'RestartPolicy'), {'Name': 'always', 'MaximumRetryCount': 0}),
            (('HostConfig', 'Tmpfs'), {}), (('HostConfig', 'CapDrop'), []),
            (('HostConfig', 'CapAdd'), ['SYS_ADMIN']), (('HostConfig', 'SecurityOpt'), []),
            (('HostConfig', 'Devices'), [{'PathOnHost': '/dev/kvm'}]),
            (('HostConfig', 'DeviceRequests'), [{}]), (('HostConfig', 'GroupAdd'), ['kvm']),
            (('HostConfig', 'PortBindings'), {'6080/tcp': [{'HostPort': '6080'}]}),
            (('HostConfig', 'VolumesFrom'), ['unowned']), (('HostConfig', 'ExtraHosts'), ['x:1.2.3.4']),
            (('HostConfig', 'PidMode'), 'host'), (('HostConfig', 'IpcMode'), 'host'),
            (('HostConfig', 'UTSMode'), 'host'), (('HostConfig', 'UsernsMode'), 'host'),
            (('Mounts',), []),
        ]
        for path, value in mutations:
            with self.subTest(path=path):
                changed = copy.deepcopy(INFO)
                target = changed
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(ValueError):
                    h.validate_created(changed, CREATED['id'], CREATED['nonce'])
        print(f'Profile mutation rejection cases: {len(mutations)}')

    def admission(self, *, memory=h.MEMORY, free=h.MIN_SOURCE_FREE,
                  online='0-71', affinity={0, 1, 2, 3}, lanes=None, containers=b''):
        def read_text(path, *args, **kwargs):
            if str(path) == '/proc/meminfo':
                return f'MemAvailable: {memory // 1024} kB\n'
            if str(path) == '/sys/devices/system/cpu/online':
                return online
            raise AssertionError(f'Unexpected admission read: {path}')
        with mock.patch.object(Path, 'read_text', read_text), \
             mock.patch.object(h.os, 'statvfs', return_value=SimpleNamespace(f_bavail=free, f_frsize=1)), \
             mock.patch.object(h.os, 'sched_getaffinity', return_value=affinity), \
             mock.patch.object(h, 'live_lanes', return_value=lanes or []), \
             mock.patch.object(h, 'checked', return_value=containers):
            return h.resources({})

    def test_admission_boundary(self):
        observed = self.admission()
        self.assertEqual(observed['mem_available_bytes'], 32 * 1024 ** 3)
        self.assertEqual(observed['source_free_bytes'], 64 * 1024 ** 3)
        self.assertEqual(observed['observed_live_lanes'], [])

    def test_admission_rejects_lanes_and_resource_shortfalls(self):
        cases = [({'memory': h.MEMORY - 1024}, 'MemAvailable'),
                 ({'free': h.MIN_SOURCE_FREE - 1}, 'source free space'),
                 ({'online': '0-2'}, 'online/allowed'),
                 ({'affinity': {0, 1, 2}}, 'online/allowed'),
                 ({'lanes': [{'pid': 123, 'lane': 'native AOSP host tests'}]}, 'lanes are live'),
                 ({'containers': b'wonad-upstream-native-live\n'}, 'lanes are live'),
                 ({'containers': b'wonad-phase1-x86-live\n'}, 'lanes are live'),
                 ({'containers': b'wonad-phase1-frankel-live\n'}, 'lanes are live')]
        for values, message in cases:
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, message):
                self.admission(**values)
        print(f'Admission rejection cases: {len(cases)}')

    def test_literal_command_and_env_isolation(self):
        nonce = '0' * 64
        for action, name in (('run', h.NAME), ('create', h.PROOF_NAME)):
            argv = h.command(action, name, nonce)
            self.assertEqual(argv[:len(h.DOCKER)], h.DOCKER)
            self.assertEqual(argv[-len(h.PAYLOAD):], h.PAYLOAD)
            self.assertEqual(h.PAYLOAD[0], '-i')
            self.assertNotIn('--privileged', argv)
            self.assertNotIn('--device', argv)
            self.assertNotIn('-p', argv)
            self.assertNotIn('NINJA_ARGS=', '\n'.join(argv))
            self.assertNotIn('SOONG_UI_NINJA_ARGS=', '\n'.join(argv))
            self.assertIn('NINJA_HIGHMEM_NUM_JOBS=1', h.PAYLOAD)
            self.assertIn('prepare-vendor', h.INNER)

    def test_real_authentication_input_is_pinned(self):
        self.assertEqual(h.INPUT_SHA['android/platform/allowed_signers'],
                         '344f59c6f058699e63fea68e35953b341c14e3bf1fbc1256f6baa84aa2aca1d0')

    def test_raw_cleanup_observations(self):
        cleanup = json.loads((PROOF / 'cleanup.json').read_bytes())
        for key, stem, arguments, expected_status in (
            ('remove_result', 'remove-result', ['container', 'rm', CREATED['id']], 0),
            ('name_absence', 'name-absence',
             ['container', 'inspect', '--format', '{{.Id}}', h.PROOF_NAME], 1),
            ('id_absence', 'id-absence',
             ['container', 'inspect', '--format', '{{.Id}}', CREATED['id']], 1)):
            self.assertEqual(h.ref(PROOF / (stem + '.json')), cleanup[key])
            observation = json.loads((PROOF / (stem + '.json')).read_bytes())
            self.assertEqual(observation['argv'], h.DOCKER + arguments)
            self.assertEqual(observation['returncode'], expected_status)
            for channel in ('stdout', 'stderr'):
                self.assertEqual(h.ref(PROOF / (stem + '.' + channel)), observation[channel])
            stdout = (PROOF / (stem + '.stdout')).read_bytes()
            stderr = (PROOF / (stem + '.stderr')).read_bytes()
            if key == 'remove_result':
                self.assertEqual(stdout, (CREATED['id'] + '\n').encode())
                self.assertEqual(stderr, b'')
            else:
                self.assertEqual(stdout, b'')
                self.assertIn(b'No such object:', stderr)
                self.assertIn(arguments[-1].encode(), stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
