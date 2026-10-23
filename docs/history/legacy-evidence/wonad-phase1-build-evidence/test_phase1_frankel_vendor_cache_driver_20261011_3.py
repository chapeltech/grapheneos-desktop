#!/usr/bin/env python3
"""Host-only tests.  Never clone the 11-GB archive or invoke Docker/builds."""
from __future__ import annotations

import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path('/u/elric/tree/wonad-phase1-build-evidence')
HELPER = ROOT / 'phase1_frankel_vendor_cache_driver_20261011_3.py'
spec = importlib.util.spec_from_file_location('vendor_cache_driver3', HELPER)
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

OLD_PROOF = ROOT / 'phase1-frankel-vendor-create-only-20261011-4'
OLD_INFO = json.loads((OLD_PROOF / 'inspect.json').read_bytes())[0]
OLD_CREATED = json.loads((OLD_PROOF / 'created-id.json').read_bytes())
PRE_DEBUG_HELPER_SHA256 = '4c760db22a134debf3b33c6f81fd75b1ed2f81de4010b5fe5bad1408bbd1b3ae'
PRE_DEBUG_TEST_SHA256 = 'f761cb2587defa438984ff453078e913a96a1f73e35d8b45ba14ef49fda861a2'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def profile_info():
    info = copy.deepcopy(OLD_INFO)
    info['Name'] = '/' + h._core.PROOF_NAME
    labels = {'org.wonad.phase1.vendor-attempt': OLD_CREATED['nonce'],
              'org.wonad.phase1.vendor-mode': 'create-only'}
    info['Config']['Labels'] = labels
    info['Config']['Cmd'] = h.PAYLOAD
    info['Args'] = h.PAYLOAD
    bind = str(h._core.PROOF_WORK) + ':/adevtool-images:rw'
    info['HostConfig']['Binds'].append(bind)
    info['Mounts'].append({'Type': 'bind', 'Source': str(h._core.PROOF_WORK),
                           'Destination': '/adevtool-images', 'Mode': 'rw',
                           'RW': True, 'Propagation': 'rprivate'})
    return info


class CacheReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        payload = h._core.CACHE_RECEIPT.read_bytes()
        cls.receipt = h._core.unique_json(payload, 'test receipt')

    def test_actual_receipt_and_cache_are_stat_authenticated_without_archive_read(self):
        real_open = os.open
        opened = []

        def observed(path, flags, *args):
            opened.append(str(path))
            if Path(path) == h.ARCHIVE:
                raise AssertionError('11-GB archive must not be opened by host admission')
            return real_open(path, flags, *args)

        with mock.patch.object(h.os, 'open', side_effect=observed):
            result = h.cache_snapshot()
        self.assertEqual(result['receipt']['sha256'], h.CACHE_RECEIPT_SHA256)
        self.assertEqual(result['archive']['bytes'], h.ARCHIVE_BYTES)
        self.assertTrue(result['archive_bytes_not_rehashed_by_host_admission'])
        self.assertNotIn(str(h.ARCHIVE), opened)

    def test_strict_cache_receipt_mutations_fail(self):
        mutations = [
            (('schema',), 2), (('kind',), 'wrong'), (('result',), 'downloaded'),
            (('runtime_qualified',), True),
            (('source_authority', 'baseline_root'), '/tmp/source'),
            (('source_authority', 'adevtool_commit'), '0' * 40),
            (('source_authority', 'build_index_sha256'), '0' * 64),
            (('source_authority', 'configured_build_id'), 'wrong'),
            (('source_authority', 'url_derivation'), 'operator supplied'),
            (('archive', 'path'), '/tmp/archive.zip'),
            (('archive', 'filename'), 'wrong.zip'), (('archive', 'bytes'), 1),
            (('archive', 'sha256'), '0' * 64), (('archive', 'device'), 1),
            (('archive', 'inode'), 1), (('archive', 'mode'), '0600'),
            (('archive', 'uid'), 0), (('archive', 'gid'), 0),
            (('archive', 'symlink'), True),
            (('inventory',), self.receipt['inventory'][:-1]),
            (('transfer', 'exit_code'), 1), (('transfer', 'size_download'), 1),
            (('verification', 'final_sha256_recheck_passed'), False),
            (('disk', 'reserve_preserved'), False),
            (('negative_claims', 'container_started'), True),
        ]
        for keys, value in mutations:
            with self.subTest(keys=keys):
                changed = copy.deepcopy(self.receipt)
                target = changed
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                with self.assertRaises(ValueError):
                    h.validate_cache_receipt(changed)
        changed = copy.deepcopy(self.receipt)
        changed['negative_claims']['invented'] = False
        with self.assertRaises(ValueError):
            h.validate_cache_receipt(changed)

    def test_duplicate_json_keys_fail_at_every_level(self):
        for payload in (b'{"schema":1,"schema":1}',
                        b'{"outer":{"x":1,"x":2}}'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                h._core.unique_json(payload, 'duplicate test')

    def test_source_backed_cache_override_is_exact(self):
        expected = {
            'vendor/adevtool/src/config/paths.ts':
                '418823cca30a381208e13acd7ea30d5ff37be411f1492ccd05f290ba4c95bd8e',
            'vendor/adevtool/src/images/device-image.ts':
                'f2a8a827b609dbf5bd31488de5b762eb6777408bd29c45521cefdc9d798bbfc0',
            'vendor/adevtool/src/frontend/source.ts':
                '001de5cab8ae7524ba862135d7663a467a7b49ae0fea733d044090c40a728ca9',
            'vendor/adevtool/src/commands/download.ts':
                'a734b1570c8cd4099b242b8893de77ac6683a08e92f83eff5c19319044d27984',
            'vendor/adevtool/src/images/download.ts':
                '2d4384422de6c48999ed716024bb92e1a23efeb865a50cfdf7a45dec84c3ffee',
        }
        for relative, digest in expected.items():
            path = h.SOURCE / relative
            self.assertEqual(sha(path), digest)
            self.assertEqual(h._core.SOURCE_SHA[relative], digest)
        paths = (h.SOURCE / 'vendor/adevtool/src/config/paths.ts').read_text()
        frontend = (h.SOURCE / 'vendor/adevtool/src/frontend/source.ts').read_text()
        download = (h.SOURCE / 'vendor/adevtool/src/commands/download.ts').read_text()
        self.assertIn("process.env['ADEVTOOL_IMG_DOWNLOAD_DIR']", paths)
        self.assertIn('if (!(await imageToUnpack.isPresent()))', frontend)
        self.assertIn('ADEVTOOL_IMG_DOWNLOAD_DIR', download)


class CaptureAndReflinkTests(unittest.TestCase):
    def test_capture_rejects_path_swap_after_open(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            replacement = Path(directory) / 'replacement'
            path.write_bytes(b'first')
            replacement.write_bytes(b'second')
            real_open = os.open
            swapped = False

            def swap_after_open(value, flags, *args):
                nonlocal swapped
                fd = real_open(value, flags, *args)
                if Path(value) == path and not swapped:
                    os.replace(replacement, path)
                    swapped = True
                return fd

            with mock.patch.object(h.os, 'open', side_effect=swap_after_open), \
                    self.assertRaisesRegex(ValueError, 'changed (?:before capture|during capture|during capture|pathname)'):
                h.capture_regular(path, 1024)

    def test_ficlone_exact_flags_mode_sync_and_no_copy_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = parent / 'factory.zip'
            source.write_bytes(b'authenticated factory bytes')
            source.chmod(0o644)
            source_stat = source.stat()
            work = parent / 'work'
            calls = []
            opens = []
            real_open = os.open

            def tracked_open(path, flags, *args):
                opens.append((str(path), flags))
                return real_open(path, flags, *args)

            def fake_clone(destination_fd, operation, source_fd):
                calls.append((operation, os.fstat(source_fd).st_ino))
                os.ftruncate(destination_fd, source_stat.st_size)

            patches = {
                'ARCHIVE': source, 'ARCHIVE_NAME': source.name,
                'ARCHIVE_BYTES': source_stat.st_size,
                'ARCHIVE_DEVICE': source_stat.st_dev,
                'ARCHIVE_INODE': source_stat.st_ino,
            }
            with mock.patch.multiple(h._core, **patches), \
                    mock.patch.object(h._core.os, 'open', side_effect=tracked_open):
                result = h.prepare_reflink_workspace(work, source, ioctl_fn=fake_clone)
            self.assertEqual(calls, [(h.FICLONE, source_stat.st_ino)])
            destination = work / source.name
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o444)
            self.assertEqual(destination.stat().st_size, source_stat.st_size)
            source_flags = next(flags for path, flags in opens if path == str(source))
            destination_flags = next(flags for path, flags in opens if path == str(destination))
            self.assertTrue(source_flags & os.O_NOFOLLOW)
            self.assertTrue(destination_flags & os.O_NOFOLLOW)
            self.assertTrue(destination_flags & os.O_EXCL)
            self.assertEqual(result['creation'], 'FICLONE only; no copy/download fallback')

    def test_ficlone_failure_is_retained_and_never_falls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = parent / 'factory.zip'
            source.write_bytes(b'x' * 32)
            source.chmod(0o644)
            source_stat = source.stat()
            work = parent / 'failed-work'
            invocations = []

            def refuse(*args):
                invocations.append(args)
                raise OSError(95, 'operation not supported')

            patches = {'ARCHIVE': source, 'ARCHIVE_NAME': source.name,
                       'ARCHIVE_BYTES': source_stat.st_size,
                       'ARCHIVE_DEVICE': source_stat.st_dev,
                       'ARCHIVE_INODE': source_stat.st_ino}
            with mock.patch.multiple(h._core, **patches), self.assertRaises(OSError):
                h.prepare_reflink_workspace(work, source, ioctl_fn=refuse)
            self.assertEqual(len(invocations), 1)
            self.assertTrue(work.is_dir())
            self.assertTrue((work / source.name).exists())
            self.assertEqual((work / source.name).stat().st_size, 0)

    def test_check_and_create_modes_do_not_call_clone_in_source(self):
        source = HELPER.read_text()
        core = h.CORE.read_text()
        self.assertNotIn('prepare_reflink_workspace', source.split('def preparation(check_only):', 1)[0])
        create_body = core.split('def create_only():', 1)[1].split('def run_vendor', 1)[0]
        self.assertNotIn('prepare_reflink_workspace', create_body)
        self.assertIn('if check_only:', source)
        self.assertLess(source.index('if check_only:'), source.index('prepare_reflink_workspace'))


class ProcessAndContainerAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        proof = json.loads(h.DEBUG_PROOF.read_bytes())
        cls.debug_info = json.loads(proof['inspect_result']['output'])[0]
        cls.debug_top = proof['top_result']['output'].encode()

    def test_full_argv_process_classification_and_controls(self):
        cases = [
            (['python3', 'a', 'b', 'c', 'd', 'e', '/x/phase1_emulator_client_packet.py', 'build'],
             'emulator packet build'),
            (['python3', '/x/build_native_successor.py', 'build'], 'APK successor build'),
            (['python3', '/x/native_compile_finalize.py'], 'APK successor finalize'),
            (['python3', '/x/phase1_conformance_guest.py'], 'fresh conformance guest'),
            (['python3', '/x/run_phase1_conformance_recents_guest.py'], 'fresh Recents guest'),
            (['python3', '/x/run-phase1-custom7-api-recents-packet6.py'], 'API/Recents guest wrapper'),
            (['python3', '/x/run_native_matrix.py'], 'native/GUI matrix'),
            (['bash', '/x/run-phase1-native-matrix-custom7.sh'], 'native/GUI matrix wrapper'),
            (['qemu-kvm', '-machine', 'q35'], 'KVM guest'),
            (['/opt/android/emulator/qemu/linux-x86_64/qemu-system-x86_64'], 'QEMU guest'),
            (['python3', '/x/build-native-candidate.py'], 'native candidate image build'),
            (['python3', '/x/build-phase1-conformance-candidate.py'],
             'conformance candidate image build'),
            (['bash', '/x/freeze-phase1-native-matrix-custom7.sh'],
             'native/GUI matrix evidence freeze'),
            (['python3', '/x/run-phase1-wrong-signer-bundle7.py'],
             'APK wrong-signer bundle build'),
            (['docker', 'build', '.'], 'Docker image build'),
        ]
        for argv, expected in cases:
            with self.subTest(argv=argv):
                self.assertEqual(h.process_kind(argv), expected)
        for argv in (['docker', 'run', '--network', 'none', 'asgard', 'verify'],
                     ['python3', '/srv/ai/read-only-audit.py'],
                     ['docker', 'run', '--read-only', 'wonad:test', 'verify']):
            with self.subTest(control=argv):
                self.assertIsNone(h.process_kind(argv))

    def test_proc_scan_blocks_oversize_and_unreadable_but_allows_gone(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / '123'
            proc.mkdir()
            (proc / 'stat').write_text('123 (x) S 1 0 0\n')
            (proc / 'cmdline').write_bytes(b'python3\0' + b'x' * h.MAX_CMDLINE + b'\0')
            with self.assertRaisesRegex(ValueError, 'exceeds'):
                h.live_lanes(root, ignored=set())
            with mock.patch.object(h._core, 'read_process', side_effect=PermissionError(13, 'denied')), \
                    self.assertRaisesRegex(ValueError, 'Cannot authenticate process'):
                h.live_lanes(root, ignored=set())
            with mock.patch.object(h._core, 'read_process', side_effect=FileNotFoundError(2, 'gone')):
                self.assertEqual(h.live_lanes(root, ignored=set()), [])

    def container(self, name='/asgard-kdc'):
        return {'Id': 'a' * 64, 'Name': name,
                'State': {'Running': True},
                'Config': {'Labels': {}, 'Entrypoint': ['/bin/sleep'], 'Cmd': ['3600']},
                'HostConfig': {'Devices': None, 'ReadonlyRootfs': True, 'NetworkMode': 'none'},
                'Mounts': []}

    def test_container_exclusions_are_profile_specific(self):
        self.assertIsNone(h.container_kind(self.container('/asgard-kdc')))
        self.assertIsNone(h.container_kind(self.container('/ai-read-only-verifier')))
        changed = self.container('/guest')
        changed['HostConfig']['Devices'] = [
            {'PathOnHost': '/dev/kvm', 'PathInContainer': '/dev/kvm'}]
        self.assertEqual(h.container_kind(changed), 'running KVM guest container')
        changed = self.container('/wonad-phase1-conformance-deadbeef')
        self.assertEqual(h.container_kind(changed), 'running Wonad build/test/VM container')
        changed = self.container('/ordinary')
        changed['Config']['Labels'] = {'org.wonad.phase1-fresh-conformance': 'abc'}
        self.assertEqual(h.container_kind(changed), 'running labelled Wonad build/test/VM container')
        changed = self.container('/ordinary')
        changed['Config']['Entrypoint'] = ['qemu-kvm']
        self.assertEqual(h.container_kind(changed), 'running VM container')
        changed = self.container('/wonad-current-cross-successor18')
        self.assertEqual(h.container_kind(changed),
                         'running APK successor cross-build container')

    def test_exact_debug_profile_and_process_epoch_is_the_only_kvm_exception(self):
        expected_lane = [{'container': h.DEBUG_ID,
                          'name': self.debug_info['Name'],
                          'lane': 'running KVM guest container'}]
        with mock.patch.object(h, '_original_running_container_lanes',
                               side_effect=[copy.deepcopy(expected_lane),
                                            copy.deepcopy(expected_lane)]) as inventories, \
             mock.patch.object(h._core, 'inspect',
                               side_effect=[(copy.deepcopy(self.debug_info), b'first'),
                                            (copy.deepcopy(self.debug_info), b'second')]) as inspections, \
             mock.patch.object(h._core, 'checked', return_value=self.debug_top) as checked:
            self.assertEqual([], h.running_container_lanes({'PATH': 'bounded'}))
        self.assertEqual(inventories.call_count, 2)
        self.assertEqual(inspections.call_count, 2)
        self.assertEqual(checked.call_count, 2)
        self.assertEqual('KVM guest', h.process_kind(['qemu-kvm', '-machine', 'q35']))
        self.assertEqual('running KVM guest container', h.container_kind(self.debug_info))

    def test_different_debug_id_is_never_exempted(self):
        lane = [{'container': 'b' * 64, 'name': self.debug_info['Name'],
                 'lane': 'running KVM guest container'}]
        with mock.patch.object(h, '_original_running_container_lanes',
                               return_value=copy.deepcopy(lane)), \
             mock.patch.object(h._core, 'inspect') as inspect, \
             mock.patch.object(h._core, 'checked') as checked:
            self.assertEqual(lane, h.running_container_lanes({}))
        inspect.assert_not_called()
        checked.assert_not_called()

    def test_every_debug_profile_or_epoch_mutation_fails_closed(self):
        mutations = [
            (('Image',), 'sha256:' + '0' * 64),
            (('Name',), '/wonad-emulator-debug-replacement'),
            (('Path',), 'qemu-kvm'),
            (('Args',), ['1']),
            (('Config', 'Cmd'), ['qemu-kvm']),
            (('HostConfig', 'NetworkMode'), 'host'),
            (('HostConfig', 'Devices'), []),
            (('Mounts',), self.debug_info['Mounts'][:-1]),
            (('State', 'Pid'), self.debug_info['State']['Pid'] + 1),
            (('State', 'StartedAt'), '2026-10-11T00:00:00Z'),
            (('State', 'OOMKilled'), True),
        ]
        for keys, value in mutations:
            with self.subTest(keys=keys):
                changed = copy.deepcopy(self.debug_info)
                target = changed
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                with self.assertRaises(ValueError):
                    h.preserved_debug_check(changed, {}, checked_fn=lambda *_: self.debug_top)

    def test_debug_top_extra_missing_or_qemu_process_fails_closed(self):
        variants = [
            self.debug_top + b'999 2362784 qemu-kvm qemu-kvm -machine q35\n',
            b'\n'.join(self.debug_top.splitlines()[:-1]) + b'\n',
            self.debug_top.replace(b'sleep infinity', b'qemu-kvm -machine q35'),
            b'x' * (h.MAX_DEBUG_TOP_BYTES + 1),
        ]
        for raw in variants:
            with self.subTest(raw=raw[:80]), self.assertRaises(ValueError):
                h.preserved_debug_check(copy.deepcopy(self.debug_info), {},
                                        checked_fn=lambda *_args, raw=raw: raw)

    def test_debug_exception_does_not_hide_other_lanes(self):
        debug = {'container': h.DEBUG_ID, 'name': self.debug_info['Name'],
                 'lane': 'running KVM guest container'}
        foreign = {'container': 'c' * 64, 'name': '/foreign-qemu',
                   'lane': 'running KVM guest container'}
        with mock.patch.object(h, '_original_running_container_lanes', side_effect=[
                    [copy.deepcopy(debug)], [copy.deepcopy(debug), copy.deepcopy(foreign)]]), \
             mock.patch.object(h._core, 'inspect',
                               return_value=(copy.deepcopy(self.debug_info), b'inspect')), \
             mock.patch.object(h._core, 'checked', return_value=self.debug_top):
            self.assertEqual([foreign], h.running_container_lanes({}))

    def admission(self, *, memory=h.MEMORY, free=h.MIN_SOURCE_FREE,
                  online='0-71', affinity={0, 1, 2, 3}, lanes=None, containers=None,
                  fsids=(1, 1)):
        def read_text(path, *args, **kwargs):
            if str(path) == '/proc/meminfo':
                return f'MemAvailable: {memory // 1024} kB\n'
            if str(path) == '/sys/devices/system/cpu/online':
                return online
            raise AssertionError(path)
        stat_rows = [SimpleNamespace(f_bavail=free, f_frsize=1, f_fsid=fsids[0]),
                     SimpleNamespace(f_bavail=free, f_frsize=1, f_fsid=fsids[1])]
        with mock.patch.object(Path, 'read_text', read_text), \
             mock.patch.object(h._core.os, 'statvfs', side_effect=stat_rows), \
             mock.patch.object(h._core.os, 'sched_getaffinity', return_value=affinity), \
             mock.patch.object(h._core, 'live_lanes', return_value=lanes or []), \
             mock.patch.object(h._core, 'running_container_lanes', return_value=containers or []):
            return h.resources({})

    def test_resource_and_lane_admission_boundaries(self):
        self.assertEqual(self.admission()['mem_available_bytes'], h.MEMORY)
        cases = [
            ({'memory': h.MEMORY - 1024}, 'MemAvailable'),
            ({'free': h.MIN_SOURCE_FREE - 1}, 'free space'),
            ({'online': '0-2'}, 'online/allowed'),
            ({'affinity': {0, 1, 2}}, 'online/allowed'),
            ({'fsids': (1, 2)}, 'one filesystem'),
            ({'lanes': [{'pid': 1, 'lane': 'emulator packet build'}]}, 'lanes are live'),
            ({'containers': [{'container': 'a' * 64, 'lane': 'KVM'}]}, 'lanes are live'),
        ]
        for values, message in cases:
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, message):
                self.admission(**values)


class DockerProfileTests(unittest.TestCase):
    def test_literal_command_has_exact_cache_env_and_three_binds(self):
        nonce = '0' * 64
        for action, name, work in (
                ('run', h._core.NAME, h._core.WORK),
                ('create', h._core.PROOF_NAME, h._core.PROOF_WORK)):
            argv = h.command(action, name, nonce, work)
            self.assertEqual(argv[:len(h.DOCKER)], h.DOCKER)
            self.assertEqual(argv[-len(h.PAYLOAD):], h.PAYLOAD)
            self.assertEqual(argv.count('--volume'), 3)
            self.assertEqual(sorted(argv[index + 1] for index, value in enumerate(argv)
                                    if value == '--volume'), sorted(h.expected_binds(work)))
            self.assertIn('ADEVTOOL_IMG_DOWNLOAD_DIR=/adevtool-images', h.PAYLOAD)
            self.assertEqual(h.PAYLOAD.count('ADEVTOOL_IMG_DOWNLOAD_DIR=/adevtool-images'), 1)
            self.assertNotIn('--privileged', argv)
            self.assertNotIn('--device', argv)
            self.assertNotIn('-p', argv)

    def test_real_inspect_shaped_profile_and_mutations(self):
        info = profile_info()
        self.assertTrue(h.validate_created(info, OLD_CREATED['id'], OLD_CREATED['nonce'],
                                           h._core.PROOF_WORK))
        self.assertTrue(h.owned_never_started(info, OLD_CREATED['id'], OLD_CREATED['nonce'],
                                              h._core.PROOF_WORK))
        mutations = [
            (('HostConfig', 'Memory'), 0), (('HostConfig', 'MemorySwap'), -1),
            (('HostConfig', 'NanoCpus'), 0), (('HostConfig', 'CpusetCpus'), '0-71'),
            (('HostConfig', 'PidsLimit'), 0), (('HostConfig', 'ReadonlyRootfs'), False),
            (('HostConfig', 'NetworkMode'), 'host'), (('HostConfig', 'Privileged'), True),
            (('HostConfig', 'CapDrop'), []), (('HostConfig', 'CapAdd'), ['SYS_ADMIN']),
            (('HostConfig', 'SecurityOpt'), []),
            (('HostConfig', 'Devices'), [{'PathOnHost': '/dev/kvm'}]),
            (('HostConfig', 'PortBindings'), {'1/tcp': [{'HostPort': '1'}]}),
            (('Config', 'User'), '0:0'), (('Config', 'WorkingDir'), '/'),
            (('Config', 'Entrypoint'), ['/bin/sh']), (('Config', 'Cmd'), ['true']),
            (('Config', 'ExposedPorts'), {'1/tcp': {}}), (('Mounts',), []),
        ]
        for keys, value in mutations:
            with self.subTest(keys=keys):
                changed = copy.deepcopy(info)
                target = changed
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                with self.assertRaises(ValueError):
                    h.validate_created(changed, OLD_CREATED['id'], OLD_CREATED['nonce'],
                                       h._core.PROOF_WORK)
        for binds in (info['HostConfig']['Binds'][:-1],
                      info['HostConfig']['Binds'] + [info['HostConfig']['Binds'][-1]],
                      [item.replace(':/adevtool-images:rw', ':/adevtool-images:ro')
                       for item in info['HostConfig']['Binds']]):
            changed = copy.deepcopy(info)
            changed['HostConfig']['Binds'] = binds
            with self.assertRaises(ValueError):
                h.validate_created(changed, OLD_CREATED['id'], OLD_CREATED['nonce'],
                                   h._core.PROOF_WORK)


class GateAndWrapperTests(unittest.TestCase):
    def test_first_admission_failure_precedes_clone_evidence_and_docker(self):
        with mock.patch.object(h, 'base_checks', return_value=({'fixed': 1}, {'PATH': 'x'})), \
             mock.patch.object(h._core, 'fresh'), \
             mock.patch.object(h._core, 'missing_container'), \
             mock.patch.object(h._core, 'resources', side_effect=ValueError('live packet')), \
             mock.patch.object(h._core, 'prepare_reflink_workspace') as clone, \
             mock.patch.object(h._core, 'write_new') as write, \
             mock.patch.object(h._core, 'run_vendor') as run:
            with self.assertRaisesRegex(ValueError, 'live packet'):
                h.preparation(False)
        clone.assert_not_called()
        write.assert_not_called()
        run.assert_not_called()

    def test_check_only_never_clones_or_publishes(self):
        with mock.patch.object(h, 'base_checks', return_value=({'fixed': 1}, {'PATH': 'x'})), \
             mock.patch.object(h._core, 'fresh'), \
             mock.patch.object(h._core, 'missing_container'), \
             mock.patch.object(h._core, 'resources', return_value={'ok': True}), \
             mock.patch.object(h._core, 'prepare_reflink_workspace') as clone, \
             mock.patch.object(h._core, 'write_new') as write, \
             mock.patch.object(h._core, 'run_vendor') as run:
            with contextlib.redirect_stdout(io.StringIO()):
                h.preparation(True)
        clone.assert_not_called()
        write.assert_not_called()
        run.assert_not_called()

    def test_second_admission_drift_and_lane_fail_before_docker(self):
        clone = {'directory': 'work'}
        first = {'fixed': 1}
        second = {'fixed': 2, 'work': clone}
        for resource_effect, bases in (
                ([{'ok': 1}, ValueError('late guest')], [first]),
                ([{'ok': 1}, {'ok': 2}], [first, second])):
            with self.subTest(resource_effect=resource_effect), \
                 mock.patch.object(h, 'base_checks', side_effect=[(row, {'PATH': 'x'}) for row in bases]), \
                 mock.patch.object(h._core, 'fresh'), \
                 mock.patch.object(h._core, 'missing_container'), \
                 mock.patch.object(h._core, 'resources', side_effect=resource_effect), \
                 mock.patch.object(h._core, 'prepare_reflink_workspace', return_value=clone), \
                 mock.patch.object(h._core, 'write_new') as write, \
                 mock.patch.object(h._core, 'run_vendor') as run:
                with self.assertRaises(ValueError):
                    h.preparation(False)
            write.assert_not_called()
            run.assert_not_called()

    def test_modeled_success_has_two_admissions_and_one_final_run(self):
        clone = {'directory': 'work'}
        before = {'fixed': 1}
        after = {'fixed': 1, 'work': clone}
        result = SimpleNamespace(returncode=0)
        with mock.patch.object(h, 'base_checks', side_effect=[
                    (before, {'PATH': 'x'}), (after, {'PATH': 'x'})]), \
             mock.patch.object(h._core, 'fresh'), \
             mock.patch.object(h._core, 'missing_container') as missing, \
             mock.patch.object(h._core, 'resources', side_effect=[{'gate': 1}, {'gate': 2}]) as gates, \
             mock.patch.object(h._core, 'prepare_reflink_workspace', return_value=clone) as clone_fn, \
             mock.patch.object(h._core, 'write_new', return_value={'sha256': 'x'}) as write, \
             mock.patch.object(h._core, 'run_vendor', return_value=result) as run:
            with contextlib.redirect_stdout(io.StringIO()):
                h.preparation(False)
        self.assertEqual(gates.call_count, 2)
        self.assertEqual(missing.call_count, 2)
        clone_fn.assert_called_once()
        write.assert_called_once()
        run.assert_called_once()

    def test_wrapper_refuses_arbitrary_arguments_before_python(self):
        wrapper = h.DRIVER
        for args in (['--source', '/tmp/x'], ['--bogus']):
            result = subprocess.run(['/usr/bin/bash', str(wrapper), *args], check=False,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
            self.assertEqual(result.returncode, 2)
            self.assertRegex(result.stderr, br'(?:refus|usage)')
        text = wrapper.read_text()
        self.assertIn('set -- --check-only', text)
        self.assertIn('--check-only|--run|--create-only-proof', text)
        self.assertIn('exec /usr/bin/python3 -B', text)

    def test_no_output_or_work_was_created_by_host_tests(self):
        for path in (h._core.WORK, h._core.LOG, h._core.PREFLIGHT, h._core.PROOF):
            self.assertFalse(os.path.lexists(path), str(path))


class PreservationTests(unittest.TestCase):
    def test_historical_material_and_abandoned_collision_draft_are_unchanged(self):
        expected = {
            ROOT / 'prepare-phase1-frankel-vendor-20261011-1.sh':
                'a0129fddac134ac036ddd4d5c6d63faa8e5a614f376ff3968e5e2c642e20b16d',
            ROOT / 'phase1_frankel_vendor_driver_20261011_1.py':
                'b9daf74f7b3716d7c6447dcafb14e46bb4ba6c7fdccd2360d243cdb878f0c6bf',
            ROOT / 'phase1-frankel-vendor-create-only-20261011-2/receipt.json':
                '778fbd49078ae7e5560c946f989c25ec1c044b791db6b07a1a9ebfd85100936b',
            ROOT / 'phase1-frankel-vendor-create-only-20261011-4/receipt.json':
                '47e2d933cde63e7c3f442fd25d1c5399066ac3dcc746b7d131922212c38d30b4',
            ROOT / 'prepare-phase1-frankel-vendor-cache-20261011-2.sh':
                '1bbc176c8bd5ced6dc461d739112860f2ca5437758124738102c9be0134e523e',
            ROOT / 'phase1_frankel_vendor_cache_driver_20261011_2.py': h.CORE_SHA256,
        }
        for path, digest in expected.items():
            with self.subTest(path=path):
                self.assertEqual(sha(path), digest)

    def test_policy_core_is_compiled_from_the_authenticated_capture(self):
        payload, observed = h.capture_regular(h.CORE, h.MAX_CORE_BYTES)
        self.assertEqual(observed['sha256'], h.CORE_SHA256)
        self.assertEqual(payload, h._core_bytes)
        self.assertEqual(h._core_ref, observed)


if __name__ == '__main__':
    unittest.main(verbosity=2)
