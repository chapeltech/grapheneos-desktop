#!/usr/bin/env python3
"""Freeze a fresh external conditional proposal; never edit predecessors."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
STAGE = Path('/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7')
AUDIT = Path('/u/elric/tree/wonad-phase1-build-evidence/phase1-reader-key-incarnation-audit-20261012-S8nRoB')
ADMISSION = Path('/u/elric/tree/wonad-phase1-build-evidence/phase1-private-key-admission-api-stock-successor-20261012-1/work2/sealed')

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def tool(path):
    exact = Path(path).resolve()
    return {'invoked_path': str(path), 'real_path': str(exact), 'sha256': digest(exact)}

def main():
    seal = HERE / 'sealed'
    assert not seal.exists(), 'preserve any existing seal'
    assert digest(ADMISSION / 'MANIFEST.json') == '10b131eb2e27a5349ca29701a9bf0f6542646a3266e6ab2511d11f82d076e760'
    assert digest(AUDIT / 'AUDIT.txt') == '6780378d0d40ca5f856e0fe5e0960a3a65224b0adc9343e33efbd462d8599656'
    assert digest(AUDIT / 'projection.rs') == '3f7e226e8da2438c79c415ee6ec0cc505a6838331e9f695c5e32c2590d25aeb2'
    assert digest(AUDIT / 'result.json') == 'f1c6894a5660389cb6e45a57c894730fe22c1ee9fbcb524e1fcbed9afa25ef4c'
    assert digest(STAGE / '.repo/manifests/default.xml') == '32d30e70ee59d373a17fe8090bdded898afa80651f27c331caca4578b3008888'
    seal.mkdir()
    for relative in ('README.md', 'ARCHITECTURE.md', 'capture_before.py',
                     'test_origin_proposal.py', 'seal_proposal.py'):
        shutil.copyfile(HERE / relative, seal / relative)
    for relative in ('before', 'admission-before', 'candidate', 'tests'):
        shutil.copytree(HERE / relative, seal / relative)
    audit_copy = seal / 'reader-audit-reference'
    audit_copy.mkdir()
    for relative in ('AUDIT.txt', 'projection.rs', 'result.json'):
        shutil.copyfile(AUDIT / relative, audit_copy / relative)
    replay = subprocess.run([sys.executable, '-B', str(seal / 'test_origin_proposal.py'),
                             '--evidence', str(seal / 'host')],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            timeout=60, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    print(replay.stdout, end='')
    assert replay.returncode == 0, replay.returncode
    assert 'CONDITIONAL_NATIVE_TARGET_STOCK_PROJECTION_PASS checks=90' in replay.stdout
    assert 'OPEN_EXPECTED_NO_RECEIPT_F1_F2_LEAK_REPRODUCED' in replay.stdout
    files = {str(p.relative_to(seal)): digest(p) for p in sorted(seal.rglob('*')) if p.is_file()}
    manifest = {
        'schema': 1,
        'kind': 'conditional-private-origin-final-target-actual-method-proposal',
        'date': '2026-10-12',
        'source_root': str(STAGE),
        'locked_manifest': {'path': '.repo/manifests/default.xml',
            'sha256': '32d30e70ee59d373a17fe8090bdded898afa80651f27c331caca4578b3008888'},
        'manifest_project_revisions': {
            'frameworks/base': '84183aff99be5e156dc0446a6fa2d4a7150f4bc3',
            'frameworks/native': '1c83ac6ae533c74ecb0486369c0d2f9e79783b3d'},
        'before_manifest_sha256': '12b902ba1571abb0f6455730918b04672a817273e43dcc4ca14ed7707aaf2cb9',
        'latest_private_admission_reference': {
            'path': str(ADMISSION),
            'manifest_sha256': '10b131eb2e27a5349ca29701a9bf0f6542646a3266e6ab2511d11f82d076e760',
            'native_policy_source_sha256': 'ce11a8f478f4c444dd65ec475aa581c0ee9643e009a3536626c5683221af316f'},
        'reader_audit_reference': {'path': str(AUDIT),
            'report_sha256': files['reader-audit-reference/AUDIT.txt'],
            'projection_sha256': files['reader-audit-reference/projection.rs'],
            'result_sha256': files['reader-audit-reference/result.json'],
            'qualification': 'standalone-Rust-specification-and-source-shape-only'},
        'compiled_host_controls': {'conditional_checks': 90,
            'actual_method_extraction': True, 'android_surrounding_types_stubbed': True,
            'missing_receipt_counterexample_reproduced': True,
            'compiler_command': '/usr/bin/g++ -std=c++20 -O0 -pthread host/origin-target.cpp -o host/origin-target',
            'output_sha256': files['host/replay-output.txt']},
        'tools': {'python': tool(sys.executable), 'g++': tool('/usr/bin/g++')},
        'full_native_origin_implementation': False,
        'stageable_patch': False,
        'sdk_changes': False,
        'repo_source7_stage_build_key_runtime_writes': False,
        'qualification_open': ['reader/filter provenance and route receipt issuance',
            'true lifecycle epochs and exact retirement', 'bounded history and capacity recovery',
            'atomic native census and downstream fence', 'private pair-scoped fallback',
            'exact original-connection abandonment enqueue', 'phone safety/chord enrollment',
            'Android native/framework build and physical runtime'],
        'files': files,
    }
    (seal / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    checksum_files = {**files, 'MANIFEST.json': digest(seal / 'MANIFEST.json')}
    (seal / 'SHA256SUMS').write_text(''.join(f'{pin}  {name}\n' for name, pin in sorted(checksum_files.items())))
    for path in seal.rglob('*'):
        if path.is_file(): path.chmod(0o555 if path.name == 'origin-target' else 0o444)
    for path in sorted((p for p in seal.rglob('*') if p.is_dir()), reverse=True): path.chmod(0o555)
    seal.chmod(0o555)
    print('SEALED_MANIFEST_SHA256=' + digest(seal / 'MANIFEST.json'))

if __name__ == '__main__': main()
