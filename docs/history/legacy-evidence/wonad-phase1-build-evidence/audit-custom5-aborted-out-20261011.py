"""Read-only, exact-identity audit of the intentionally stopped custom-5 OUT.

This does not delete anything or assert successful build/qualification. Run
with read-only host /proc access; output must be retained outside the OUT.
"""
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

TARGET = Path('/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-3')
CONTAINER = 'e0b8c6076f4eb1453ffad03bb5e0c3d1f39a68ee6e6b5fa0eae0f1891b3f1c60'
IDENTITY = (64513, 723136731, 1000, 1000, 0o700)
PROTECTED = {
    '/u/elric/tree/wonad-phase1-build-evidence/phase1-x86-custom-2026100600-build-3.log':
        '7fd0c2987ff85d309fb9dd3271e7c9925896cae96e6ba9557a8d8f08fd08061b',
    '/u/elric/tree/wonad-phase1-build-evidence/phase1-x86-custom-2026100600-build-3.log.preflight.json':
        'd39fb04a196dc7625aa9de7311f402d43619a21c0eb054c6cb9055371ed32972',
    '/u/elric/tree/wonad-phase1-build-evidence/continue-phase1-x86-custom-5-from-baseline-receipt-8.sh':
        'cde0b5f59708e1ac16324c29599ffd6282030dcc2dcaad178844e3320ae45cb6',
    '/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-5/external/wonad/.wonad-stage.json':
        '5015daa149185f2376ff719026b8e7cf86556d8dc81f1e3e225f54f077b12cd3',
}


def identity():
    node = TARGET.lstat()
    assert stat.S_ISDIR(node.st_mode) and TARGET.resolve(strict=True) == TARGET
    return (node.st_dev, node.st_ino, node.st_uid, node.st_gid, stat.S_IMODE(node.st_mode))


def run():
    assert identity() == IDENTITY
    ids = subprocess.check_output(['docker', 'ps', '-aq', '--no-trunc'], text=True).split()
    containers = json.loads(subprocess.check_output(['docker', 'inspect', *ids]))
    c = next(item for item in containers if item['Id'] == CONTAINER)
    assert c['State']['Status'] == 'exited' and c['State']['Running'] is False
    assert c['State']['OOMKilled'] is False and c['State']['Pid'] == 0
    assert c['State']['ExitCode'] == 137
    assert c['Image'] == 'sha256:f719a4a56095b613790ef9afcba2aabda795217ac98e08c24ba5cec65bd4ee33'
    references = []
    for item in containers:
        for mount in item['Mounts']:
            q = Path(mount['Source'])
            if mount['Type'] == 'bind' and (q == TARGET or TARGET in q.parents or q in TARGET.parents):
                references.append({'container': item['Id'], 'running': item['State']['Running'], 'mount': mount})
    assert len(references) == 1 and references[0]['container'] == CONTAINER
    assert references[0]['mount']['Source'] == str(TARGET) and not references[0]['running']
    mounts = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        q = Path(line.split()[4])
        if q == TARGET or TARGET in q.parents:
            mounts.append(str(q))
    assert not mounts
    checked, zombies, refs = 0, 0, []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            status = (proc / 'status').read_text()
            if any(line.startswith('State:') and 'Z (zombie)' in line for line in status.splitlines()):
                zombies += 1
                continue
            checked += 1
            links = [proc / name for name in ('cwd', 'root', 'exe')]
            links += list((proc / 'fd').iterdir())
            for entry in links:
                try:
                    value = os.readlink(entry)
                    if value == str(TARGET) or value.startswith(str(TARGET) + '/'):
                        refs.append({'pid': proc.name, 'entry': str(entry), 'target': value})
                except FileNotFoundError:
                    pass
        except FileNotFoundError:
            pass
    assert not refs
    counts = collections.Counter()
    for directory, dirs, files in os.walk(TARGET, followlinks=False):
        for name in dirs + files:
            mode = (Path(directory) / name).lstat().st_mode
            kind = ('file' if stat.S_ISREG(mode) else 'directory' if stat.S_ISDIR(mode)
                    else 'symlink' if stat.S_ISLNK(mode) else 'fifo' if stat.S_ISFIFO(mode)
                    else 'socket' if stat.S_ISSOCK(mode) else 'other')
            counts[kind] += 1
    assert counts == {'file': 449453, 'directory': 175454, 'symlink': 809, 'fifo': 1, 'socket': 1}
    specials = []
    for name, kind in (('.ninja_fifo', 'fifo'), ('.path_interposer_log', 'socket')):
        path = TARGET / name
        node = path.lstat()
        assert node.st_uid == 1000 and node.st_gid == 1000 and not path.is_symlink()
        assert (stat.S_ISFIFO(node.st_mode) if kind == 'fifo' else stat.S_ISSOCK(node.st_mode))
        result = subprocess.run(['fuser', '--', str(path)], capture_output=True)
        assert result.returncode == 1
        specials.append({'name': name, 'kind': kind, 'device': node.st_dev, 'inode': node.st_ino,
                         'fuser_returncode': result.returncode})
    protected = {}
    for raw, expected in PROTECTED.items():
        path = Path(raw)
        assert path.is_file() and not path.is_symlink()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == expected
        protected[raw] = {'sha256': digest, 'size': path.stat().st_size}
    allocated = int(subprocess.check_output(['du', '-sx', '-B1', '--', str(TARGET)], text=True).split()[0])
    assert identity() == IDENTITY
    return {'kind': 'aborted_development_output_disposal_preflight',
            'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'target': str(TARGET), 'identity': list(IDENTITY), 'allocated_bytes': allocated,
            'descendant_counts': dict(counts),
            'container': {'id': c['Id'], 'image': c['Image'], 'name': c['Name'], 'state': c['State']},
            'container_bind_references': references, 'nested_mounts': mounts,
            'non_zombie_processes_checked': checked, 'zombies_without_live_references': zombies,
            'open_references': refs, 'specials': specials, 'retained_files': protected,
            'disposition': 'Disposable partial build output only; source/container/log/preflight/driver retained; no passing-build claim.'}


if __name__ == '__main__':
    print(json.dumps(run(), indent=2, sort_keys=True))
