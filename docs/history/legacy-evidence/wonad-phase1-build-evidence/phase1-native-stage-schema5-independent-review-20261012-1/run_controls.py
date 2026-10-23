#!/usr/bin/env python3
"""Read-only production-method review; synthetic writes remain external."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from unittest import mock

ROOT = Path('/u/elric/tree/wonad')
HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'android/tools'))
import stage_contract as S
import x86_build_comparison as X
import frankel_build_comparison as F

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    run = HERE / 'run-1'; run.mkdir()
    paths = [ROOT / 'android/tools/stage_contract.py', ROOT / 'android/platform/stage-os.py',
             ROOT / 'android/tools/x86_build_comparison.py', ROOT / 'android/tools/frankel_build_comparison.py']
    pins = {str(p): digest(p) for p in paths}
    spec = importlib.util.spec_from_file_location('staging_independent', paths[1])
    O = importlib.util.module_from_spec(spec); spec.loader.exec_module(O)
    result = {'production_method_pins': pins, 'checks': 0, 'status': 'RUNNING'}
    def verify(value): result['checks'] += 1; assert value
    def rejects(operation):
        try: operation()
        except (ValueError, X.ComparisonError): verify(True); return
        verify(False)
    def git(repo, *args):
        return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.STDOUT)
    try:
        verify(S.NATIVE_PATCH_NAMES == () and S.stage_schema() == 4)
        native = {'frameworks_native': {'services/inputflinger/dispatcher/Entry.h': '1' * 64}}
        verify(X.required_changed_artifacts({'marker': {'schema': 5, 'platform_targets': native}}) ==
               X.REQUIRED_CHANGED | X.NATIVE_POLICY_CHANGED)
        verify(X.required_changed_artifacts({'marker': {'schema': 4, 'platform_targets': {}}}) == X.REQUIRED_CHANGED)
        for targets in ({}, {'frameworks_native': {}}, {'frameworks_native': []}, {'frameworks_native': None}, None, []):
            rejects(lambda t=targets: X.required_changed_artifacts({'marker': {'schema': 5, 'platform_targets': t}}))
        for schema in (4, True, 5.0, '5', None, 6):
            rejects(lambda v=schema: X.required_changed_artifacts({'marker': {'schema': v, 'platform_targets': native}}))
        for role, path in {'os_input_dispatcher': 'system/lib64/libinputflinger.so',
                           'os_android_servers': 'system/lib64/libandroid_servers.so'}.items():
            verify(X.OS_PATHS[role] == path and F.OS_ARTIFACTS[role] == path and role not in X.NATIVE_ONLY)
            rejects(lambda p=path: X.artifact_record(run, p, allow_absent=False))

        marker = {field: '1' * 40 for project, names, field in S.platform_lanes().values()}
        marker.update(schema=4, files={'public.der': '2' * 64}, signer_sha256='2' * 64,
                      signer_certificate={}, patches={}, tools={},
                      platform_targets={label: {name: '3' * 64 for name in S.patch_target_names(names)}
                                        for label, (project, names, field) in S.platform_lanes().items()})
        owned = S.marker_owned_targets(marker); verify(bool(owned))
        malformed = json.loads(json.dumps(marker)); malformed['platform_targets']['frameworks_base'].pop(
            next(iter(malformed['platform_targets']['frameworks_base'])))
        rejects(lambda: S.marker_owned_targets(malformed))
        result['schema4_complete_target_count'] = len(owned)

        repo = run / 'original'; repo.mkdir(); (repo / 'Entry.h').write_text('before\n')
        git(repo, 'init', '--quiet'); git(repo, 'add', 'Entry.h')
        git(repo, '-c', 'user.name=External Fixture', '-c', 'user.email=fixture@invalid',
            '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Synthetic original')
        patch = run / 'native.patch'
        patch.write_text('diff --git a/Entry.h b/Entry.h\n--- a/Entry.h\n+++ b/Entry.h\n@@ -1 +1 @@\n-before\n+after\n')
        outer = run / 'git-parent'; outer.mkdir(); git(outer, 'init', '--quiet')
        class Scratch:
            def __init__(self, **kwargs): self.path = outer / 'scratch'; self.path.mkdir()
            def __enter__(self): return str(self.path)
            def __exit__(self, *args): pass
        with mock.patch.object(O.tempfile, 'TemporaryDirectory', Scratch):
            changes = O.framework_plan(repo, [patch])
        verify(changes == [(repo / 'Entry.h', b'before\n', b'after\n')])
        verify(O.target_hashes(repo, [patch], changes) == {'Entry.h': hashlib.sha256(b'after\n').hexdigest()})
        verify(git(outer / 'scratch', 'rev-parse', '--show-toplevel').decode().strip() == str(outer / 'scratch'))
        verify((repo / 'Entry.h').read_bytes() == b'before\n')

        linked = run / 'linked-project'; linked.symlink_to(repo, target_is_directory=True)
        parent = run / 'linked-parent'; parent.symlink_to(run, target_is_directory=True)
        current = {'Entry.h': hashlib.sha256(b'before\n').hexdigest()}
        for path in (linked, parent / 'original'):
            rejects(lambda p=path: O.framework_plan(p, [patch]))
            rejects(lambda p=path: O.verify_targets(p, current, 'native'))
            rejects(lambda p=path: O.target_hashes(p, [patch], []))
        fake_source = run / 'manifest-alias-source'; (fake_source / '.repo').mkdir(parents=True)
        (fake_source / '.repo/manifests').symlink_to(repo, target_is_directory=True)
        rejects(lambda: S.authenticated_native_revision(fake_source, {}))
        lock = json.loads((ROOT / 'android/grapheneos.lock.json').read_text())
        verify(S.authenticated_native_revision(Path('/u/elric/tree/wonad-grapheneos-2026100600'), lock) ==
               S.NATIVE_MANIFEST_REVISION)
        verify(all(digest(Path(path)) == expected for path, expected in pins.items()))
        result['status'] = 'PASS'
    finally:
        (run / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print('INDEPENDENT_SCHEMA_STAGE_' + result['status'], 'checks=' + str(result['checks']), run / 'result.json')

if __name__ == '__main__': main()
