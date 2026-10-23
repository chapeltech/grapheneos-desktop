import ast
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from contextlib import redirect_stdout

HERE = Path(__file__).resolve().parent
REPO = Path('/u/elric/tree/wonad')

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

CANDIDATE = load('external_picker_candidate', HERE / 'candidate/conformance_smoke.py')
CONTROLS = load('existing_picker_controls', REPO / 'android/tests/test_conformance_module.py')
sys.path.insert(0, str(REPO / 'android/tools'))
from phase1_conformance_common import terminal_status_from_log, ConformanceError

class Clock:
    def __init__(self): self.value = 0.0
    def now(self): return self.value
    def sleep(self, duration): self.value += duration

class Commands:
    def __init__(self, clock):
        self.clock, self.calls = clock, []
        self.displays = CONTROLS.picker_displays()
        self.windows = CONTROLS.picker_windows()
        self.status = dict(schema=1, state='running', phase='wait-transfer-back',
                           run=CONTROLS.RUN, generation=3818846956659248757)
        self.after = None
        self.status_count = 0
        self.inject = None
    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.inject:
            value = self.inject(argv, kwargs)
            if value is not None: return value
        self.clock.value += 0.01
        args = argv[3:]
        if args[:4] == ['shell', 'cmd', 'package', 'list']:
            raw = b'package:com.android.systemui uid:10148\n'
        elif args == ['shell', 'dumpsys', 'activity', 'service', CANDIDATE.SERVICE]:
            self.status_count += 1
            status = self.after if self.after is not None and self.status_count % 2 == 0 else self.status
            raw = (CANDIDATE.MARKER + json.dumps(status) + '\n').encode()
        elif args == ['shell', 'dumpsys', 'window', 'displays']: raw = self.displays.encode()
        elif args == ['shell', 'dumpsys', 'window', 'windows']: raw = self.windows.encode()
        elif args == ['shell', 'input', 'keyboard', '-d', '0', 'keyevent', 'KEYCODE_ESCAPE']: raw = b''
        else: raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, raw)
    def escapes(self):
        return [argv for argv, _ in self.calls if 'KEYCODE_ESCAPE' in argv]

class PickerRawDiagnosticsTests(unittest.TestCase):
    def fixture(self):
        clock = Clock(); runner = Commands(clock); lines = []
        device = CANDIDATE.Device('adb', 'emulator-5580')
        return clock, runner, lines, device
    def run_picker(self, clock, runner, lines, device, **kwargs):
        CANDIDATE.cancel_focused_transfer_picker(device, CONTROLS.RUN,
            timeout=kwargs.pop('timeout', 1.0), command_timeout=0.2, poll_interval=0.1,
            monotonic=clock.now, sleep=clock.sleep, diagnostic_emit=lines.append,
            diagnostic_runner=runner, **kwargs)
    def values(self, lines):
        self.assertTrue(all(line.startswith(CANDIDATE.PICKER_DIAGNOSTIC_MARKER) for line in lines))
        values = [json.loads(line[len(CANDIDATE.PICKER_DIAGNOSTIC_MARKER):]) for line in lines]
        self.assertEqual(list(range(1, len(values) + 1)), [row['sequence'] for row in values])
        return values
    def test_secure_predicate_and_phase_helpers_byte_semantics_unchanged(self):
        def bodies(path):
            return {node.name: ast.dump(node, include_attributes=False)
                    for node in ast.parse(path.read_text()).body if isinstance(node, ast.FunctionDef)}
        original = bodies(REPO / 'android/tools/conformance_smoke.py')
        candidate = bodies(HERE / 'candidate/conformance_smoke.py')
        for name in ('_phone_focus_token', '_window_blocks', 'focused_transfer_picker',
                     '_require_transfer_phase', 'parse_status', 'systemui_uid'):
            self.assertEqual(original[name], candidate[name], name)
        self.assertEqual((15.0, 3.0, 0.25), (CANDIDATE.PICKER_TIMEOUT,
            CANDIDATE.PICKER_COMMAND_TIMEOUT, CANDIDATE.PICKER_POLL_INTERVAL))
    def test_matched_secure_window_one_escape_and_all_raw_before_decision(self):
        args = self.fixture(); self.run_picker(*args)
        clock, runner, lines, device = args
        rows = self.values(lines); ends = [row for row in rows if row['kind'] == 'command_end']
        self.assertEqual(['uid', 'before_status', 'window_displays', 'window_windows',
                          'after_status', 'sole_escape'], [row['role'] for row in ends])
        decision = next(row['sequence'] for row in rows if row['kind'] == 'decision')
        self.assertTrue(all(row['sequence'] < decision for row in ends[:-1]))
        self.assertEqual(1, len(runner.escapes()))
        self.assertEqual('completed', rows[-1]['result'])
        self.assertFalse(hasattr(device, '_picker_diagnostics'))
        for row in ends:
            raw = base64.b64decode(row['raw_base64'], validate=True)
            self.assertEqual(len(raw), row['raw_bytes'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row['raw_sha256'])
        status = [row['value'] for row in rows if row['kind'] == 'parsed_status']
        self.assertEqual([3818846956659248757] * 2, [value['generation'] for value in status])
    def test_classifier_agrees_on_all_secure_predicate_hostiles(self):
        mutations = [('', CONTROLS.picker_windows()),
            (CONTROLS.picker_displays() * 2, CONTROLS.picker_windows()),
            (CONTROLS.picker_displays('deadbeef'), CONTROLS.picker_windows()),
            (CONTROLS.picker_displays(), CONTROLS.picker_windows() + CONTROLS.picker_window()),
            (CONTROLS.home_displays(), CONTROLS.home_windows())]
        for old, new in [('mTopFocusedDisplayId=0', 'mTopFocusedDisplayId=3'),
            ('mOwnerUid=10148', 'mOwnerUid=10000'),
            ('package=com.android.systemui', 'package=foreign.systemui'),
            ('ty=SYSTEM_DIALOG', 'ty=APPLICATION'), (' SECURE', ' NOT_SECURE'),
            ('mHasSurface=true', 'mHasSurface=false'), ('mDrawState=HAS_DRAWN', 'mDrawState=DRAW_PENDING'),
            ('isOnScreen=true', 'isOnScreen=false'), ('isVisible=true', 'isVisible=false'),
            ('mDisplayId=0', 'mDisplayId=3'), ('Requested w=', 'Absent w=')]:
            mutations.append((CONTROLS.picker_displays(), CONTROLS.picker_windows().replace(old, new)))
        for displays, windows in mutations:
            with self.subTest(windows=windows[-80:]):
                self.assertFalse(CANDIDATE.focused_transfer_picker(displays, windows, 10148))
                self.assertTrue(CANDIDATE.picker_rejection_reasons(displays, windows, 10148))
                args = self.fixture(); args[1].displays, args[1].windows = displays, windows
                with self.assertRaises(TimeoutError): self.run_picker(*args, timeout=0.11)
                self.assertFalse(args[1].escapes())
                self.assertTrue([row for row in self.values(args[2]) if row['kind'] == 'predicate'])
    def test_after_phase_change_retains_raw_before_primary_error(self):
        args = self.fixture(); args[1].after = dict(args[1].status, phase='changed')
        with self.assertRaisesRegex(RuntimeError, 'left the exact'): self.run_picker(*args)
        rows = self.values(args[2])
        self.assertTrue(any(row['kind'] == 'command_end' and row['role'] == 'after_status' for row in rows))
        self.assertEqual('RuntimeError', rows[-1]['exception_type'])
        self.assertFalse(args[1].escapes())
    def test_partial_timeout_keeps_original_exception_raw_hash_and_elapsed_budget(self):
        args = self.fixture(); original = subprocess.TimeoutExpired(['adb'], 0.2, output=b'partial\x00status')
        def inject(argv, kwargs):
            if argv[-1] == 'windows':
                args[0].value += kwargs['timeout']
                raise original
        args[1].inject = inject
        with self.assertRaises(subprocess.TimeoutExpired) as caught: self.run_picker(*args)
        self.assertIs(original, caught.exception)
        rows = self.values(args[2]); raw = next(row for row in rows if row.get('timed_out'))
        self.assertEqual(original.output, base64.b64decode(raw['raw_base64']))
        self.assertEqual('TimeoutExpired', rows[-1]['exception_type'])
        self.assertFalse(args[1].escapes())
    def test_nonzero_keeps_raw_returncode_before_runtime_error(self):
        args = self.fixture()
        args[1].inject = lambda argv, kwargs: subprocess.CompletedProcess(argv, 23, b'raw failure\r\n')
        with self.assertRaisesRegex(RuntimeError, 'adb command failed'): self.run_picker(*args)
        rows = self.values(args[2]); end = next(row for row in rows if row['kind'] == 'command_end')
        self.assertEqual(23, end['returncode'])
        self.assertEqual(b'raw failure\r\n', base64.b64decode(end['raw_base64']))
        self.assertFalse(args[1].escapes())
    def test_zero_output_is_honest_failed_read_not_success(self):
        args = self.fixture()
        args[1].inject = lambda argv, kwargs: subprocess.CompletedProcess(argv, 0, b'')
        with self.assertRaises(ValueError): self.run_picker(*args)
        rows = self.values(args[2]); end = next(row for row in rows if row['kind'] == 'command_end')
        self.assertEqual(0, end['raw_bytes']); self.assertEqual('', end['raw_base64'])
        self.assertEqual('failed', rows[-1]['result'])
    def test_oversized_read_is_limited_without_cropped_predicate_or_input(self):
        args = self.fixture()
        with self.assertRaises(CANDIDATE.PickerDiagnosticLimit):
            self.run_picker(*args, diagnostic_bounds={'max_raw': 8})
        rows = self.values(args[2]); limit = next(row for row in rows if row['kind'] == 'raw_limit')
        self.assertFalse(limit['raw_retained']); self.assertNotIn('raw_base64', limit)
        self.assertFalse(args[1].escapes()); self.assertEqual('failed', rows[-1]['result'])
    def test_oversized_timeout_does_not_erase_primary_timeout(self):
        args = self.fixture(); original = subprocess.TimeoutExpired(['adb'], 0.2, output=b'x' * 40)
        def inject(argv, kwargs): raise original
        args[1].inject = inject
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            self.run_picker(*args, diagnostic_bounds={'max_raw': 8})
        self.assertIs(original, caught.exception)
        self.assertEqual('TimeoutExpired', self.values(args[2])[-1]['exception_type'])
    def test_aggregate_budget_stops_before_next_command_or_escape(self):
        for bounds in ({'max_events': 4}, {'max_bytes': 4096}):
            args = self.fixture()
            with self.assertRaises(CANDIDATE.PickerDiagnosticLimit):
                self.run_picker(*args, diagnostic_bounds=bounds)
            self.assertFalse(args[1].calls)
            self.assertEqual('failed', self.values(args[2])[-1]['result'])
    def test_expired_deadline_after_raw_observation_never_escape(self):
        args = self.fixture()
        def inject(argv, kwargs):
            if argv[-1] == CANDIDATE.SERVICE and args[1].status_count == 1:
                args[0].value = 1.01
                return subprocess.CompletedProcess(argv, 0,
                    (CANDIDATE.MARKER + json.dumps(args[1].status)).encode())
        args[1].inject = inject
        with self.assertRaises(TimeoutError): self.run_picker(*args)
        rows = self.values(args[2]); self.assertEqual('failed', rows[-1]['result'])
        self.assertFalse(args[1].escapes())
        self.assertTrue(all(kwargs['timeout'] <= 0.2 for _, kwargs in args[1].calls))
    def test_malformed_status_raw_is_retained_before_parse_failure(self):
        args = self.fixture()
        args[1].inject = lambda argv, kwargs: (subprocess.CompletedProcess(argv, 0, b'incomplete status')
            if argv[-1] == CANDIDATE.SERVICE else None)
        with self.assertRaises(ValueError): self.run_picker(*args)
        rows = self.values(args[2]); end = [row for row in rows if row['kind'] == 'command_end'][-1]
        self.assertEqual(b'incomplete status', base64.b64decode(end['raw_base64']))
        self.assertFalse(args[1].escapes())
    def test_tagged_lines_cannot_satisfy_terminal_status_or_fake_runtime_pass(self):
        args = self.fixture(); self.run_picker(*args)
        with self.assertRaises(ConformanceError): terminal_status_from_log('\n'.join(args[2]))
        with self.assertRaises(ValueError): CANDIDATE.parse_status('\n'.join(args[2]))
    def test_existing_observer_restored_and_nonpicker_device_call_unchanged(self):
        args = self.fixture(); sentinel = object(); args[3]._picker_diagnostics = sentinel
        self.run_picker(*args); self.assertIs(sentinel, args[3]._picker_diagnostics)
    def test_invalid_bounds_stop_before_any_command(self):
        for value in (0, -1, float('inf'), float('nan'), True):
            args = self.fixture()
            with self.assertRaises(ValueError): self.run_picker(*args, timeout=value)
            self.assertFalse(args[1].calls)
    def test_original_functional_control_suite_with_candidate_not_runtime_claim(self):
        original = CONTROLS.MODULE; CONTROLS.MODULE = CANDIDATE
        try:
            suite = unittest.defaultTestLoader.loadTestsFromModule(CONTROLS)
            captured = io.StringIO()
            with redirect_stdout(captured):
                result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
            self.assertTrue(result.wasSuccessful(), result.failures + result.errors)
            self.assertGreater(result.testsRun, 10)
        finally: CONTROLS.MODULE = original
    def test_journal_failure_never_hides_primary_timeout(self):
        args = self.fixture(); original = subprocess.TimeoutExpired(['adb'], 0.2, output=b'partial')
        def inject(argv, kwargs): raise original
        args[1].inject = inject
        def broken_after_start(line):
            value = json.loads(line[len(CANDIDATE.PICKER_DIAGNOSTIC_MARKER):])
            if value['kind'] in {'command_end', 'timeout_partial_not_retained', 'terminal'}:
                raise BrokenPipeError('closed diagnostic pipe')
            args[2].append(line)
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            CANDIDATE.cancel_focused_transfer_picker(args[3], CONTROLS.RUN,
                monotonic=args[0].now, sleep=args[0].sleep, diagnostic_emit=broken_after_start,
                diagnostic_runner=args[1])
        self.assertIs(original, caught.exception); self.assertFalse(args[1].escapes())
    def test_host_command_startup_error_recorded_not_android_shutdown_claim(self):
        args = self.fixture(); original = OSError('host adb could not exec')
        def inject(argv, kwargs): raise original
        args[1].inject = inject
        with self.assertRaises(OSError) as caught: self.run_picker(*args)
        self.assertIs(original, caught.exception)
        rows = self.values(args[2]); end = next(row for row in rows if row['kind'] == 'command_end')
        self.assertEqual('OSError', end['command_exception_type'])
        self.assertFalse(end['raw_available']); self.assertIsNone(end['returncode'])
        self.assertEqual('failed', rows[-1]['result'])
    def test_diagnostic_emit_overhead_counts_before_escape_input(self):
        args = self.fixture()
        def advance_before_action(line):
            args[2].append(line)
            value = json.loads(line[len(CANDIDATE.PICKER_DIAGNOSTIC_MARKER):])
            if value['kind'] == 'decision': args[0].value = 15.1
        with self.assertRaises(TimeoutError):
            CANDIDATE.cancel_focused_transfer_picker(args[3], CONTROLS.RUN,
                monotonic=args[0].now, sleep=args[0].sleep, diagnostic_emit=advance_before_action,
                diagnostic_runner=args[1])
        self.assertFalse(args[1].escapes())
    def test_emitter_failure_before_command_never_executes_input_or_read(self):
        args = self.fixture()
        def broken(line): raise BrokenPipeError('closed diagnostic pipe')
        with self.assertRaises(BrokenPipeError):
            CANDIDATE.cancel_focused_transfer_picker(args[3], CONTROLS.RUN,
                diagnostic_emit=broken, diagnostic_runner=args[1])
        self.assertFalse(args[1].calls)

if __name__ == '__main__': unittest.main()
