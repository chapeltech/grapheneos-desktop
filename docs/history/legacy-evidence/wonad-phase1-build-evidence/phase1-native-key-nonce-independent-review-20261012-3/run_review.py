#!/usr/bin/env python3
"""Replay immutable neutral-call successor in fresh external-only paths."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import traceback

HERE = Path(__file__).resolve().parent
SNAPSHOT = Path('/u/elric/tree/wonad-phase1-build-evidence/phase1-private-key-admission-api-stock-successor-20261012-1/work2/sealed')
BEFORE = SNAPSHOT.parents[1] / 'work/sealed'
IDENTITY = '10b131eb2e27a5349ca29701a9bf0f6542646a3266e6ab2511d11f82d076e760'
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value

def main():
    run = HERE / 'replay-1'; run.mkdir()
    result = {'manifest': IDENTITY, 'snapshot': str(SNAPSHOT), 'commands': [], 'status': 'RUNNING'}
    try:
        assert digest(SNAPSHOT / 'MANIFEST.json') == IDENTITY
        subprocess.run(['sha256sum', '--check', 'SHA256SUMS'], cwd=SNAPSHOT, check=True, stdout=subprocess.PIPE)
        for path in [SNAPSHOT, *SNAPSHOT.rglob('*')]:
            assert not path.is_symlink() and path.stat().st_mode & 0o222 == 0, path
        manifest = json.loads((SNAPSHOT / 'MANIFEST.json').read_text())
        pins = {row['path']: row['sha256'] for row in manifest['source_inputs'].values()}
        pins.update(manifest['extra_native_source_inputs']); pins.update(manifest['tools'])
        pins[manifest['source_manifest']['path']] = manifest['source_manifest']['sha256']
        for path, expected in pins.items(): assert digest(Path(path)) == expected, path
        result['authenticated_pins'] = pins
        generated = run / 'generated'
        subprocess.run([sys.executable, '-B', str(SNAPSHOT / 'apply_candidate.py'), '--output', str(generated)], check=True)
        changed = []
        for path in sorted(generated.iterdir()):
            assert path.read_bytes() == (SNAPSHOT / 'host/generated' / path.name).read_bytes()
            if path.read_bytes() != (BEFORE / 'host/generated' / path.name).read_bytes(): changed.append(path.name)
        assert changed == ['KeyGestureController.java'], changed
        result['implementation_delta_from_86911f'] = changed
        candidate = module('neutral_candidate', SNAPSHOT / 'test_candidate.py')
        original_run = candidate.run
        def record(argv, *, expected=None):
            output = original_run(argv, expected=expected)
            result['commands'].append({'argv': argv, 'output': output, 'expected': expected})
            if output.strip(): print(output.strip(), flush=True)
            return output
        candidate.run = record
        candidate.source_guards(generated); candidate.compile_and_run(generated, run)
        result['direct_source_checks'] = candidate.checks
        checker = module('private_interfaces', HERE.parent / 'phase1-native-key-nonce-independent-review-20261012-1/verify_private_protocol.py')
        original_params = checker.java_params
        def params(source, name):
            if name != 'interceptKeyBeforeDispatching' or 'public long interceptKeyBeforeDispatching(' not in source:
                return original_params(source, name)
            rows = re.findall(r'public long interceptKeyBeforeDispatching\(([^()]*)\)', source)
            types = [[re.sub(r'\s+\w+$', '', checker.compact(v)) for v in row.split(',')] for row in rows]
            assert sorted(types, key=len) == [['IBinder','KeyEvent','int'], ['IBinder','KeyEvent','int','long']]
            start = source.index('public long interceptKeyBeforeDispatching(')
            body = source[start:source.index('public long interceptKeyBeforeDispatching(', start + 1)]
            assert '.beginAdmissionCall(0L)' in body and 'long result = -1;' in body
            assert 'result = interceptKeyBeforeDispatching(focus, event, policyFlags, 0L);' in body
            assert '} finally {' in body and '.finishAdmissionCall(' in body and 'wonadCall, result);' in body
            assert body.index('.beginAdmissionCall(0L)') < body.index('try {') < body.index('result = interceptKeyBeforeDispatching') < body.index('} finally {') < body.index('.finishAdmissionCall(') < body.index('return result;')
            return ['IBinder','KeyEvent','int','long']
        checker.java_params = params
        previous = sys.argv; sys.argv = ['verify_private_protocol.py', str(generated)]
        try: checker.main()
        finally: sys.argv = previous
        result['independent_interface_checks'] = checker.checks
        stubs = sorted(str(p) for p in (SNAPSHOT / 'tests/stubs').rglob('*.kt'))
        record([str(candidate.KOTLIN), '-J-Xmx256m', '-include-runtime', str(generated / 'WonadPolicyKeyContainment.kt'),
                str(generated / 'WonadPolicyKeyAdapter.kt'), *stubs,
                str(HERE.parent / 'phase1-native-key-nonce-independent-review-20261012-2/PhoneNullFocusMatrix.kt'),
                '-d', str(run / 'phone-matrix.jar')])
        record([str(candidate.JAVA), '-Xmx128m', '-cp', str(run / 'phone-matrix.jar'),
                'org.wonad.server.input.PhoneNullFocusMatrixKt'], expected='INDEPENDENT_PHONE_NULL_FOCUS_MATRIX_PASS')
        result['status'] = 'PASS'
    except BaseException:
        result['status'] = 'FAIL'; result['error'] = traceback.format_exc(); raise
    finally:
        result['artifacts'] = {str(p.relative_to(run)): digest(p) for p in sorted(run.rglob('*')) if p.is_file()}
        (run / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print('INDEPENDENT_NEUTRAL_SUCCESSOR_' + result['status'], run / 'result.json', flush=True)
if __name__ == '__main__': main()
