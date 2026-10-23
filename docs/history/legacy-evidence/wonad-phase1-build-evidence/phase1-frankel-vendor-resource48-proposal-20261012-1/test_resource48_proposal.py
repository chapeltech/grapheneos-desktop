"""Host-double resource proposal tests: no actual admission, Docker or cleanup."""
import ast
from contextlib import contextmanager
import copy
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

from render_resource_proposal import BASE, candidate_bytes

REPO = Path('/u/elric/tree/wonad')
sys.path.insert(0, str(REPO / 'android/tests'))
import test_run_frankel_vendor as baseline

def load_source(payload):
    module = types.ModuleType('external_resource48_candidate')
    module.__file__ = str(REPO / 'android/tools/run_frankel_vendor.py')
    sys.modules[module.__name__] = module
    exec(compile(payload, module.__file__, 'exec'), module.__dict__)
    return module

vendor = load_source(candidate_bytes())
GIB = 1024**3

@contextmanager
def selected_fixture():
    old = baseline.vendor
    baseline.vendor = vendor
    try:
        yield
    finally:
        baseline.vendor = old

class ResourceProposalTests(unittest.TestCase):
    def observe(self, payload=None, *, total=48*GIB, available=42*GIB,
                free=64*GIB, source_fsid=42, work_fsid=42,
                online='0-71\n', allowed=None, processes=None, containers=None):
        config = types.SimpleNamespace(source=Path('/fixture/source'),
                                       work=Path('/fixture/work/attempt'))
        if payload is None:
            payload = f'MemTotal: {total // 1024} kB\nMemAvailable: {available // 1024} kB\n'
        def read(path, *unused, **kwargs):
            if str(path) == '/proc/meminfo':
                self.assertEqual('ascii', kwargs.get('encoding'))
                return payload
            if str(path) == '/sys/devices/system/cpu/online':
                return online
            raise AssertionError('Unexpected read: ' + str(path))
        def filesystem(path):
            return types.SimpleNamespace(f_bavail=free, f_frsize=1,
                f_fsid=source_fsid if path == config.source else work_fsid)
        with mock.patch.object(Path, 'read_text', read), \
             mock.patch.object(vendor.os, 'statvfs', side_effect=filesystem), \
             mock.patch.object(vendor.os, 'sched_getaffinity', return_value=
                               set(range(72)) if allowed is None else allowed), \
             mock.patch.object(vendor, 'live_process_lanes', return_value=processes or []), \
             mock.patch.object(vendor, 'running_container_lanes', return_value=containers or []):
            return vendor.resources(config, {})

    def test_exact_caps_floors_and_observed_evidence(self):
        self.assertEqual(48*GIB, vendor.MEMORY)
        self.assertEqual(42*GIB, vendor.MIN_MEM_AVAILABLE)
        self.assertEqual(64*GIB, vendor.MIN_SOURCE_FREE)
        result = self.observe()
        self.assertEqual(48*GIB, result['mem_total_bytes'])
        self.assertEqual(42*GIB, result['mem_available_bytes'])
        self.assertEqual([0,1,2,3], result['cpus_online_and_allowed'])
        self.assertTrue(result['limits_are_conservative_unmeasured'])

    def test_physical_and_available_thresholds_are_independent(self):
        for total, available in ((48*GIB-1024, 42*GIB),
                                 (48*GIB, 42*GIB-1024),
                                 (40*GIB, 40*GIB)):
            with self.subTest(total=total, available=available), self.assertRaises(vendor.Refusal):
                self.observe(total=total, available=available)
        self.assertEqual(64*GIB, self.observe(total=64*GIB, available=47*GIB)['mem_total_bytes'])

    def test_missing_duplicate_malformed_nonpositive_and_impossible_memory_rejected(self):
        total = 'MemTotal: 50331648 kB\n'
        available = 'MemAvailable: 44040192 kB\n'
        for hostile in (available, total, total+total+available,
                        total+available+available, total+'MemAvailable: -1 kB\n',
                        total+'MemAvailable: 4.2 kB\n', total+'MemAvailable: 44040192 MB\n',
                        total+'MemAvailable: ４４０４０１９２ kB\n',
                        total+'MemAvailable: 0 kB\n',
                        'MemTotal: 0 kB\n'+available,
                        total+'MemAvailable: 67108864 kB\n',
                        total+'MemAvailable: 44040192 kB junk\n'):
            with self.subTest(hostile=hostile), self.assertRaises(vendor.Refusal):
                self.observe(hostile)

    def test_read_failure_and_nonascii_observation_fail_closed(self):
        for error in (PermissionError('denied'), UnicodeError('nonascii')):
            with mock.patch.object(Path, 'read_text', side_effect=error), self.assertRaises(type(error)):
                vendor.resources(types.SimpleNamespace(), {})

    def test_storage_same_filesystem_affinity_and_lane_guards_unchanged(self):
        hostile = [dict(free=64*GIB-1), dict(work_fsid=43),
                   dict(online='1-71\n'), dict(allowed={1,2,3}),
                   dict(processes=[{'lane':'vendor'}]),
                   dict(containers=[{'lane':'guest'}])]
        for kwargs in hostile:
            with self.subTest(kwargs=kwargs), self.assertRaises(vendor.Refusal):
                self.observe(**kwargs)

    def test_create_command_profile_48_no_extra_swap_four_cpu_unchanged(self):
        with tempfile.TemporaryDirectory() as root, selected_fixture():
            config = baseline.DockerProfileTests().config(root)
            command = vendor.create_command(config, 'c'*64)
            self.assertEqual(str(48*GIB), command[command.index('--memory')+1])
            self.assertEqual(str(48*GIB), command[command.index('--memory-swap')+1])
            self.assertEqual('4', command[command.index('--cpus')+1])
            self.assertEqual('0-3', command[command.index('--cpuset-cpus')+1])
            self.assertEqual('2048', command[command.index('--pids-limit')+1])
            self.assertEqual(3, command.count('--volume'))
            self.assertIn('--read-only', command)
            self.assertNotIn('/dev/kvm', command)

    def test_exact_profile_rejects_historical_40_or_extra_swap(self):
        with tempfile.TemporaryDirectory() as root, selected_fixture():
            config = baseline.DockerProfileTests().config(root)
            identity, nonce, profile = baseline.DockerProfileTests().info(config)
            self.assertTrue(vendor.validate_container(profile, config, identity, nonce, stopped=False))
            for memory, swap in ((40*GIB,40*GIB), (48*GIB,49*GIB), (49*GIB,49*GIB)):
                info = copy.deepcopy(profile)
                info['HostConfig'].update(Memory=memory, MemorySwap=swap)
                with self.subTest(memory=memory, swap=swap), self.assertRaises(vendor.Refusal):
                    vendor.validate_container(info, config, identity, nonce, stopped=False)

    def test_only_resources_function_and_selected_constants_change(self):
        before = ast.parse(BASE.read_bytes())
        after = ast.parse(candidate_bytes())
        def definitions(tree):
            return {node.name: ast.dump(node, include_attributes=False)
                    for node in tree.body if isinstance(node,(ast.FunctionDef,ast.ClassDef))}
        old, new = definitions(before), definitions(after)
        self.assertEqual(set(old),set(new))
        self.assertEqual(['resources'], [name for name in old if old[name]!=new[name]])
        def constants(tree):
            return {node.targets[0].id: ast.dump(node.value, include_attributes=False)
                    for node in tree.body if isinstance(node,ast.Assign) and
                    len(node.targets)==1 and isinstance(node.targets[0],ast.Name)}
        old, new = constants(before), constants(after)
        self.assertEqual({'MIN_MEM_AVAILABLE'},set(new)-set(old))
        self.assertEqual(['MEMORY'],[name for name in old if old[name]!=new[name]])

    def test_no_fake_heap_environment_or_target_omission(self):
        environment = vendor.builder_environment(types.SimpleNamespace(adevtool_commit='a'*40))
        self.assertFalse(any(row.startswith(('GOMEMLIMIT=','GOGC=','SOONG_PARTIAL_ANALYSIS='))
                             for row in environment))
        original = load_source(BASE.read_bytes())
        self.assertEqual(original.builder_environment(types.SimpleNamespace(adevtool_commit='a'*40)),
                         environment)
        self.assertEqual(original.REQUIRED_SOURCE_INPUTS, vendor.REQUIRED_SOURCE_INPUTS)
        self.assertEqual(original.REQUIRED_REPO_INPUTS, vendor.REQUIRED_REPO_INPUTS)

if __name__ == '__main__':
    unittest.main(verbosity=2)
