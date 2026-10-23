import gc
import json
import os
from pathlib import Path
import sys
sys.dont_write_bytecode = True
observations = []
def observe(stage):
    status = {}
    for line in Path('/proc/self/status').read_text().splitlines():
        key, _, value = line.partition(':')
        if key in {'VmRSS', 'VmHWM', 'VmSize', 'RssAnon', 'RssFile', 'RssShmem', 'Threads'}:
            status[key] = value.strip()
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, _, value = line.partition(':')
        if key in {'MemAvailable', 'MemFree', 'Cached', 'SwapFree'}:
            memory[key] = value.strip()
    observations.append({'stage': stage, 'pid': os.getpid(), 'proc_self_status': status, 'host_meminfo': memory})
observe('fresh_python_before_current_imports')
sys.path.insert(0, '/u/elric/tree/wonad/android/tools')
import phase1_generic_upstream_evidence as generic
observe('after_current_generic_and_dependency_imports')
root = Path('/u/elric/tree/wonad-phase1-upstream-native-20261011-r5.udpFmQ/aosp-baseline')
file_names = ('source-freeze-before.json', 'build-out-before.json', 'build-before.json',
              'source-binding.json', 'builder-before.json', 'docker-before.json')
retained_summaries = {name: generic.load_json(root / name) for name in file_names}
retained_summary_bytes = {name: (root / name).stat().st_size for name in file_names}
observe('after_retaining_six_before_summaries')
invocations = {}
stream_bytes = {}
for identifier in ('blueprint', 'blueprint_race'):
    directory = root / 'invocations' / identifier
    raw_path = directory / 'go-test.jsonl'
    stream_bytes[identifier] = raw_path.stat().st_size
    observe('before_' + identifier + '_parse')
    cases = generic.parse_go_json(raw_path, identifier, 0)
    generic.require_executed_go_test(cases, identifier)
    observe('after_' + identifier + '_parse_cases_retained')
    invocations[identifier] = {'case_count': len(cases), 'cases': cases, 'exit_code': 0,
        'raw': generic.isolated_atest.portable_ref(root, raw_path, allow_empty=False),
        'container': generic.isolated_atest.portable_ref(root, directory / 'container.json', allow_empty=False)}
    observe('after_' + identifier + '_portable_refs_and_summary_retained')
observe('final_both_invocations_and_six_before_summaries_retained')
gc.collect()
observe('after_gc_both_invocations_and_summaries_still_retained')
print(json.dumps({'scope': 'read-only fresh owned Python retained-evidence replay; no source inventory, compiler, lane launch or guard change',
    'not_exact_historical_memavailable_reproduction': True, 'tool': generic.file_identity(Path(generic.__file__).resolve()),
    'root': str(root), 'before_summary_byte_counts': retained_summary_bytes, 'before_summary_total_bytes': sum(retained_summary_bytes.values()),
    'stream_byte_counts': stream_bytes, 'stream_total_bytes': sum(stream_bytes.values()),
    'invocation_summaries': {name: {key: value for key, value in summary.items() if key != 'cases'} for name, summary in invocations.items()},
    'observations': observations}, indent=2, sort_keys=True))
