"""Preserve a fresh host regression invocation, not platform/runtime evidence."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/u/elric/tree/wonad')
HERE = Path(__file__).resolve().parent
MODULES = [
    'android.tests.test_stage_os.StageSafety',
    'android.tests.test_stage_os.FrameworkPatches',
    'android.tests.test_stage_os.PatchTargetInventory',
    'android.tests.test_phase1_provenance',
    'android.tests.test_phase1_release_index',
    'android.tests.test_x86_build_comparison',
    'android.tests.test_frankel_build_tools',
    'android.tests.test_release_receipt',
    'android.tests.test_release_build_launcher',
    'android.tests.test_native_artifact_roles',
]
FILES = [
    'android/platform/stage-os.py', 'android/tools/stage_contract.py',
    'android/tools/phase1_provenance.py', 'android/tools/phase1_release_index.py',
    'android/tools/x86_build_comparison.py', 'android/tools/frankel_build_comparison.py',
    'android/tools/release_receipt.py', 'android/tools/run_frankel_build.py',
    'android/tools/run_x86_build.py', 'android/container/build-native-candidate.py',
    'android/tools/phase1_conformance_common.py', 'android/tools/phase1_conformance_guest.py',
    'android/tools/phase1_conformance_acceptance.py',
    'android/tools/phase1_conformance_recents_acceptance.py',
    'android/tests/test_stage_os.py', 'android/tests/test_native_artifact_roles.py',
    'android/tests/test_phase1_provenance.py', 'android/tests/test_phase1_release_index.py',
    'android/tests/test_x86_build_comparison.py', 'android/tests/test_frankel_build_tools.py',
    'android/tests/test_release_receipt.py', 'android/tests/test_release_build_launcher.py',
]
def inventory():
    return {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in FILES}

if __name__ == '__main__':
    raw = HERE/'root-regression-output.txt'
    receipt = HERE/'root-regression-result.json'
    if raw.exists() or receipt.exists():
        raise SystemExit('Preserving existing run; use a new evidence directory')
    before = inventory()
    command = [sys.executable, '-B', '-m', 'unittest', *MODULES]
    started = time.monotonic()
    with raw.open('xb') as stream:
        run = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
    after = inventory()
    record = {'schema': 1, 'scope': 'host-fixtures-not-Android-runtime',
              'command': command, 'returncode': run.returncode,
              'elapsed_seconds': time.monotonic()-started,
              'inputs_before': before, 'inputs_after': after,
              'inputs_unchanged': before == after,
              'output_sha256': hashlib.sha256(raw.read_bytes()).hexdigest()}
    with receipt.open('x') as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'returncode': run.returncode, 'inputs_unchanged': before == after,
                      'receipt': str(receipt), 'output': str(raw)}))
    raise SystemExit(run.returncode if before == after else 2)
