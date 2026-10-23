"""Root-owned repeat of the unchanged sealed successor host replay."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path

SOURCE = Path('/u/elric/tree/wonad-phase1-build-evidence/phase1-sdk-3.0.1-full-host-replay-20261012-2/run_host_replay.py')
EXPECTED = '5b9e4b9428f33da65226f6af0cd8bc3002ceef7c004585a58440873c3f839da4'
assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == EXPECTED
spec = importlib.util.spec_from_file_location('root_captured_sdk_host_replay', SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
# Only the create-new output path changes. All 798+798 captured input files,
# reviewed fourteen-file delta, subprocess guards and six suites stay fixed.
module.RESULTS = Path(__file__).resolve().parent / 'results'
assert not module.RESULTS.exists()
with contextlib.redirect_stdout(io.StringIO()):
    code = module.main()
record = json.loads((module.RESULTS / 'result.json').read_bytes())
print(json.dumps({key: record[key] for key in (
    'success', 'tests', 'failures', 'errors', 'skipped', 'reported_seconds',
    'suite_counts', 'input_inventory', 'test_output', 'limitations')}, indent=2))
print('result_sha256=' + hashlib.sha256((module.RESULTS / 'result.json').read_bytes()).hexdigest())
print('root_replay_output=' + str(module.RESULTS))
raise SystemExit(code)
