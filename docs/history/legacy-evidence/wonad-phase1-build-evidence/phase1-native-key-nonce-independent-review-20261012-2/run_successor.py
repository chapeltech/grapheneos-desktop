#!/usr/bin/env python3
"""Preserved external replay and explicit superseding phone/caller controls."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import traceback

HERE = Path(__file__).resolve().parent
SNAPSHOT = Path('/u/elric/tree/wonad-phase1-build-evidence/phase1-private-key-admission-api-stock-successor-20261012-1/work/sealed')
OLD = Path('/u/elric/tree/wonad-phase1-build-evidence/phase1-recents-key-containment-kotlin-prototype-20261012-7/sealed-2')
IDENTITY = '86911f6affc9128a34f9c6a736e2aeb5ace554587471fb1f4986fdaaae818b17'

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-name', default='successor-replay-2')
    args = parser.parse_args()
    assert Path(args.run_name).name == args.run_name and args.run_name not in ('.', '..')
    run = HERE / args.run_name; run.mkdir()
    result = {'manifest': IDENTITY, 'snapshot': str(SNAPSHOT), 'status': 'RUNNING', 'commands': []}
    try:
        assert digest(SNAPSHOT / 'MANIFEST.json') == IDENTITY
        subprocess.run(['sha256sum', '--check', 'SHA256SUMS'], cwd=SNAPSHOT, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        manifest = json.loads((SNAPSHOT / 'MANIFEST.json').read_text())
        for path in [SNAPSHOT, *SNAPSHOT.rglob('*')]:
            assert not path.is_symlink() and path.stat().st_mode & 0o222 == 0, path
        pins = {row['path']: row['sha256'] for row in manifest['source_inputs'].values()}
        pins.update(manifest['extra_native_source_inputs']); pins.update(manifest['tools'])
        pins[manifest['source_manifest']['path']] = manifest['source_manifest']['sha256']
        for path, expected in pins.items(): assert digest(Path(path)) == expected, path
        result['authenticated_pins'] = pins
        generated = run / 'generated'
        subprocess.run([sys.executable, '-B', str(SNAPSHOT / 'apply_candidate.py'), '--output', str(generated)], check=True)
        old_files = {p.name for p in (OLD / 'host/generated').iterdir() if p.is_file()}
        assert {p.name for p in generated.iterdir()} == old_files
        changed = []
        for name in sorted(old_files):
            assert (generated / name).read_bytes() == (SNAPSHOT / 'host/generated' / name).read_bytes(), name
            if digest(generated / name) != digest(OLD / 'host/generated' / name): changed.append(name)
        assert changed == ['KeyGestureController.java', 'WonadPolicyKeyAdapter.kt'], changed
        result['changed_implementation_files'] = changed
        candidate = module('successor_candidate', SNAPSHOT / 'test_candidate.py')
        original_run = candidate.run
        def recording(argv, *, expected=None):
            output = original_run(argv, expected=expected)
            result['commands'].append({'argv': argv, 'output': output, 'expected': expected})
            if output.strip(): print(output.strip(), flush=True)
            return output
        candidate.run = recording
        candidate.source_guards(generated); candidate.compile_and_run(generated, run)
        result['producer_replay_checks'] = candidate.checks

        # Reuse the preserved cross-file verifier, explicitly adapting only its
        # KGC single-overload assumption to require BOTH reviewed exact forms.
        checker = module('independent_previous_interfaces', HERE.parent /
            'phase1-native-key-nonce-independent-review-20261012-1/verify_private_protocol.py')
        previous_params = checker.java_params
        def java_params(source, name):
            if name != 'interceptKeyBeforeDispatching' or 'public long interceptKeyBeforeDispatching(' not in source:
                return previous_params(source, name)
            rows = re.findall(r'public long interceptKeyBeforeDispatching\(([^()]*)\)', source)
            types = [[re.sub(r'\s+\w+$', '', checker.compact(v)) for v in row.split(',')] for row in rows]
            assert sorted(types, key=len) == [['IBinder', 'KeyEvent', 'int'], ['IBinder', 'KeyEvent', 'int', 'long']], types
            assert 'return interceptKeyBeforeDispatching(focus, event, policyFlags, 0L);' in source
            return ['IBinder', 'KeyEvent', 'int', 'long']
        checker.java_params = java_params
        previous_argv = sys.argv; sys.argv = ['verify_private_protocol.py', str(generated)]
        try: checker.main()
        finally: sys.argv = previous_argv
        result['independent_interface_checks'] = checker.checks
        stubs = sorted(str(p) for p in (SNAPSHOT / 'tests/stubs').rglob('*.kt'))
        recording([str(candidate.KOTLIN), '-J-Xmx256m', '-include-runtime',
            str(generated / 'WonadPolicyKeyContainment.kt'), str(generated / 'WonadPolicyKeyAdapter.kt'),
            *stubs, str(HERE / 'PhoneNullFocusMatrix.kt'), '-d', str(run / 'phone-matrix.jar')])
        recording([str(candidate.JAVA), '-Xmx128m', '-cp', str(run / 'phone-matrix.jar'),
            'org.wonad.server.input.PhoneNullFocusMatrixKt'], expected='INDEPENDENT_PHONE_NULL_FOCUS_MATRIX_PASS')
        result['status'] = 'PASS'
    except BaseException:
        result['status'] = 'FAIL'; result['error'] = traceback.format_exc(); raise
    finally:
        result['artifacts'] = {str(p.relative_to(run)): digest(p) for p in sorted(run.rglob('*')) if p.is_file()}
        (run / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print('INDEPENDENT_SUCCESSOR_' + result['status'], run / 'result.json', flush=True)

if __name__ == '__main__': main()
