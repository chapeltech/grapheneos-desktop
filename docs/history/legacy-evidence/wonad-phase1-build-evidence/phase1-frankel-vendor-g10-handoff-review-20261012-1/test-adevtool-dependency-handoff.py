"""Real stream/copy tests and hostile retained-handoff replays, not an OS build."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('vendor_handoff_tests',
                                             ROOT / 'android/tools/run_frankel_vendor.py')
vendor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vendor)
api = vendor.dependency_handoff_api()
GOOD_STDOUT = b'building\nninja: 22m34.62s Build Succeeded: 7485 steps - 5.53/s\n'
GOOD_STDERR = (b'03:41:50 Build sandboxing disabled due to nsjail error.\n'
               b'sched_setaffinity: Invalid argument\nsched_setaffinity: Invalid argument\n')


@contextmanager
def retained_fixture():
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        root = work / 'wonad-dependency-build'
        programs = root / 'programs'
        programs.mkdir(parents=True)
        config = types.SimpleNamespace(work=work, adevtool_commit='1' * 40)
        receipt = {
            'schema': 1, 'kind': 'phase1_adevtool_dependency_handoff_v1',
            'status': 'built_and_verified', 'adevtool_commit': config.adevtool_commit,
            'command': api.COMMAND, 'targets': list(api.TARGETS),
            'upstream_script_sha256': api.SCRIPT_SHA, 'upstream_paths_sha256': api.PATHS_SHA,
            'skip_flag_scope': 'redundant second build only after fresh full build',
            'compiler_exit_code': 0,
            'classification': api.classify_transcripts(0, GOOD_STDOUT, GOOD_STDERR),
            'programs': {},
        }
        for name, payload in (('stdout', GOOD_STDOUT), ('stderr', GOOD_STDERR)):
            (root / (name + '.raw')).write_bytes(payload)
            receipt[name] = api.reference('/adevtool-images/wonad-dependency-build/' + name + '.raw', payload)
        for name in api.TARGETS:
            payload = b'fixture-program:' + name.encode()
            (programs / name).write_bytes(payload)
            receipt['programs'][name] = {
                'installed_path': '/grapheneos/out_adevtool_deps/host/linux-x86/bin/' + name,
                'retained': api.reference('/adevtool-images/wonad-dependency-build/programs/' + name, payload)}
        def save():
            (root / 'receipt.json').write_text(json.dumps(receipt, sort_keys=True) + '\n')
        save()
        yield config, root, receipt, save


class TranscriptTests(unittest.TestCase):
    def test_observed_diagnostics_retained_and_classified(self):
        result = api.classify_transcripts(0, GOOD_STDOUT, GOOD_STDERR)
        self.assertEqual(3, len(result['retained_warnings']))
        self.assertEqual(GOOD_STDERR.decode().splitlines(),
                         [row['raw_line'] for row in result['retained_warnings']])

    def test_clean_stderr_is_allowed_after_real_success_footer(self):
        self.assertEqual([], api.classify_transcripts(0, GOOD_STDOUT, b'')['retained_warnings'])

    def test_nonzero_bool_and_missing_exit_fail(self):
        for code in (1, -11, 137, None, False, True, '0'):
            with self.subTest(code=code), self.assertRaisesRegex(RuntimeError, 'exact zero'):
                api.classify_transcripts(code, GOOD_STDOUT, GOOD_STDERR)

    def test_missing_footer_does_not_accept_tools_or_known_warnings(self):
        for output in (b'', b'Build Succeeded\n', GOOD_STDOUT.replace(b'7485', b'0')):
            with self.subTest(output=output), self.assertRaisesRegex(RuntimeError, 'footers'):
                api.classify_transcripts(0, output, GOOD_STDERR)

    def test_failed_marker_not_overridden_by_success_footer(self):
        for marker in (b'FAILED: target\n', b'ninja: build stopped: failed\n'):
            with self.subTest(marker=marker), self.assertRaisesRegex(RuntimeError, 'Failure marker'):
                api.classify_transcripts(0, GOOD_STDOUT + marker, b'')

    def test_unknown_stderr_and_modified_warning_fail(self):
        for line in (b'ERROR: wrong tool\n', b'sched_setaffinity: Permission denied\n',
                     b'24:00:00 Build sandboxing disabled due to nsjail error.\n',
                     b'prefix sched_setaffinity: Invalid argument\n',
                     b'error setpriority(5): Permission denied\n', b'\n'):
            with self.subTest(line=line), self.assertRaisesRegex(RuntimeError, 'Unknown'):
                api.classify_transcripts(0, GOOD_STDOUT, line)

    def test_warning_count_bound(self):
        for stderr in (GOOD_STDERR + b'sched_setaffinity: Invalid argument\n',
                       GOOD_STDERR + GOOD_STDERR.splitlines(keepends=True)[0]):
            with self.subTest(stderr=stderr), self.assertRaisesRegex(RuntimeError, 'count'):
                api.classify_transcripts(0, GOOD_STDOUT, stderr)

    def test_transcript_limits_and_encoding_fail(self):
        with mock.patch.object(api, 'STDOUT_LIMIT', 1), self.assertRaisesRegex(RuntimeError, 'limit'):
            api.classify_transcripts(0, GOOD_STDOUT, b'')
        with self.assertRaisesRegex(RuntimeError, 'limit'):
            api.classify_transcripts(0, GOOD_STDOUT, b'x' * 4097)
        with self.assertRaises(UnicodeError):
            api.classify_transcripts(0, GOOD_STDOUT, b'\xff')

    def test_bootstrap_and_final_siso_footer_both_retained(self):
        self.assertEqual(2, len(api.classify_transcripts(
            0, GOOD_STDOUT + GOOD_STDOUT, b'')['siso_success_footers']))


class StreamAndProgramTests(unittest.TestCase):
    def test_real_child_streams_byte_exact_and_real_exit_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = [sys.executable, '-B', '-c',
                       'import os; os.write(1,b"stdout\\x00\\n"); os.write(2,b"stderr\\n"); raise SystemExit(7)']
            with mock.patch.object(api.sys, 'stdout', types.SimpleNamespace(buffer=open(os.devnull, 'wb'))) as out, \
                 mock.patch.object(api.sys, 'stderr', types.SimpleNamespace(buffer=open(os.devnull, 'wb'))) as err:
                try:
                    status = api.capture_build(command, root / 'out', root / 'err')
                finally:
                    out.buffer.close(); err.buffer.close()
            self.assertEqual(7, status)
            self.assertEqual(b'stdout\x00\n', (root / 'out').read_bytes())
            self.assertEqual(b'stderr\n', (root / 'err').read_bytes())

    def test_capture_rejects_existing_output_without_truncating(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'out').write_bytes(b'original')
            with self.assertRaises(FileExistsError):
                api.capture_build(['/should/not/start'], root / 'out', root / 'err')
            self.assertEqual(b'original', (root / 'out').read_bytes())

    def test_program_bytes_retained_even_when_source_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, retained = root / 'source', root / 'retained'
            source.write_bytes(b'ordinary fixture program')
            source.chmod(0o700)
            result = api.retain_program(source, retained)
            source.unlink()
            self.assertEqual(hashlib.sha256(retained.read_bytes()).hexdigest(),
                             result['retained']['sha256'])

    def test_empty_nonexecutable_symlink_and_oversize_program_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.touch(mode=0o700)
            with self.assertRaisesRegex(RuntimeError, 'empty'):
                api.retain_program(source, root / 'empty-copy')
            source.write_bytes(b'fixture'); source.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, 'executable'):
                api.retain_program(source, root / 'nonexec-copy')
            link = root / 'link'; link.symlink_to(source)
            with self.assertRaisesRegex(RuntimeError, 'canonical'):
                api.retain_program(link, root / 'link-copy')
            with self.assertRaisesRegex(RuntimeError, 'limit'):
                api.regular_bytes(source, 1)


class HostReceiptTests(unittest.TestCase):
    def test_full_host_replay_all_fourteen_bytes_and_raw_streams(self):
        with retained_fixture() as (config, root, receipt, save):
            result = vendor.verify_dependency_evidence(config)
            self.assertTrue(result['fresh_full_dependency_build_verified'])
            self.assertEqual(set(api.TARGETS), set(result['programs']))
            self.assertEqual(receipt['classification'], result['classification'])

    def test_program_tamper_missing_symlink_and_extra_fail(self):
        for mutation in ('tamper', 'missing', 'symlink', 'extra'):
            with self.subTest(mutation=mutation), retained_fixture() as (config, root, receipt, save):
                path = root / 'programs/aapt2'
                if mutation == 'tamper': path.write_bytes(b'changed')
                elif mutation == 'missing': path.unlink()
                elif mutation == 'symlink':
                    path.unlink(); path.symlink_to(root / 'programs/toybox')
                else: (root / 'programs/unreviewed').write_bytes(b'extra')
                with self.assertRaises((vendor.Refusal, FileNotFoundError)):
                    vendor.verify_dependency_evidence(config)

    def test_raw_stream_tamper_and_even_rebound_unknown_warning_fail(self):
        for rebound in (False, True):
            with self.subTest(rebound=rebound), retained_fixture() as (config, root, receipt, save):
                payload = b'ERROR: other diagnostic\n'
                (root / 'stderr.raw').write_bytes(payload)
                if rebound:
                    receipt['stderr'] = api.reference(receipt['stderr']['path'], payload)
                    save()
                with self.assertRaises(vendor.Refusal):
                    vendor.verify_dependency_evidence(config)

    def test_wrong_command_skip_scope_source_commit_or_target_inventory_fail(self):
        changes = {'command': api.COMMAND[:-1], 'targets': list(api.TARGETS[:-1]),
                   'skip_flag_scope': 'skip dependency build', 'adevtool_commit': '2' * 40,
                   'upstream_script_sha256': '0' * 64, 'upstream_paths_sha256': '0' * 64,
                   'status': 'failed', 'schema': True}
        for key, value in changes.items():
            with self.subTest(key=key), retained_fixture() as (config, root, receipt, save):
                receipt[key] = value; save()
                with self.assertRaises(vendor.Refusal):
                    vendor.verify_dependency_evidence(config)

    def test_nonzero_exit_and_forged_classification_fail(self):
        for key, value in (('compiler_exit_code', 1), ('compiler_exit_code', False),
                           ('classification', {})):
            with self.subTest(key=key, value=value), retained_fixture() as (config, root, receipt, save):
                receipt[key] = value; save()
                with self.assertRaises(vendor.Refusal):
                    vendor.verify_dependency_evidence(config)

    def test_retained_or_installed_path_retarget_fails(self):
        for retained in (False, True):
            with self.subTest(retained=retained), retained_fixture() as (config, root, receipt, save):
                row = receipt['programs']['aapt2']
                if retained: row['retained']['path'] = '/different/aapt2'
                else: row['installed_path'] = '/different/aapt2'
                save()
                with self.assertRaises(vendor.Refusal):
                    vendor.verify_dependency_evidence(config)

    def test_missing_program_and_unknown_receipt_field_fail(self):
        for extra in (False, True):
            with self.subTest(extra=extra), retained_fixture() as (config, root, receipt, save):
                if extra: receipt['extra'] = True
                else: del receipt['programs']['aapt2']
                save()
                with self.assertRaises(vendor.Refusal):
                    vendor.verify_dependency_evidence(config)

    def test_duplicate_json_key_and_extra_evidence_fail(self):
        with retained_fixture() as (config, root, receipt, save):
            (root / 'receipt.json').write_text('{"schema":1,"schema":1}')
            with self.assertRaisesRegex(vendor.Refusal, 'Duplicate'):
                vendor.verify_dependency_evidence(config)
            save(); (root / 'extra').touch()
            with self.assertRaisesRegex(vendor.Refusal, 'Unexpected'):
                vendor.verify_dependency_evidence(config)


class UpstreamAndShellTests(unittest.TestCase):
    def test_exact_upstream_script_and_paths_are_pinned(self):
        checkout = Path('/u/elric/tree/wonad-grapheneos-2026100600-frankel-baseline-1')
        if not checkout.exists(): self.skipTest('Frankel checkout unavailable')
        for relative, expected in (('vendor/adevtool/scripts/run-build.sh', api.SCRIPT_SHA),
                                   ('vendor/adevtool/src/config/paths.ts', api.PATHS_SHA)):
            self.assertEqual(expected, hashlib.sha256((checkout / relative).read_bytes()).hexdigest())
        source = (checkout / 'vendor/adevtool/src/config/paths.ts').read_bytes()
        self.assertEqual(api.TARGETS, vendor.reviewed_adevtool_targets(source))
        self.assertIn("process.env['ADEVTOOL_SKIP_DEP_BUILD'] === '1'", source.decode())
        self.assertIn('builtDependencies && (await isFile(progPath))', source.decode())

    def test_shell_uses_flag_only_after_checked_complete_build(self):
        source = vendor.GENERATOR.read_text()
        self.assertEqual(1, source.count('ADEVTOOL_SKIP_DEP_BUILD=1'))
        self.assertLess(source.index("receipt['status'] = 'built_and_verified'"),
                        source.index('ADEVTOOL_SKIP_DEP_BUILD=1 vendor/adevtool/bin/run generate-all'))
        self.assertEqual(14, len(api.COMMAND[3:]))
        self.assertNotIn('SOONG_PARTIAL_ANALYSIS=', source)
        self.assertEqual(0, subprocess.run(['/usr/bin/bash', '-n', str(vendor.GENERATOR)],
                                          capture_output=True, timeout=5).returncode)


if __name__ == '__main__':
    unittest.main()
