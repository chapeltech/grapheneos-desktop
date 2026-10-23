"""Read-only root audit of the actual never-started vendor preparation proof.

This does not qualify vendor generation or an OS build and does not read the
11 GB factory archive. It imports the already reviewed captured policy only
to compare the literal Docker argv, not to perform admission or preparation.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
PROOF = Path('/u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-vendor-cache-create-only-20261011-6')


def digest(path, expected):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    assert path.resolve(strict=True) == path and before.st_size <= 8 * 1024 * 1024
    payload = path.read_bytes()
    after = path.lstat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    assert len(payload) == expected['bytes'] and hashlib.sha256(payload).hexdigest() == expected['sha256'], path
    return payload


r = json.loads(digest(PROOF / 'receipt.json', {
    'bytes': 8833, 'sha256': '2e262baf6725186cd8532fd5c7a6fc14b18af5f1b4a757f000446129d000623b'}))
assert r['schema'] == 1 and r['kind'] == 'phase1_frankel_vendor_cache_docker_create_only_v1'
for key in ('never_started', 'exact_owned_container_removed', 'not_runtime_qualification', 'not_vendor_generation_or_build'):
    assert r[key] is True
assert r['factory_archive_cloned_or_exposed'] is False
cid, name, nonce = r['container_id'], r['container_name'], r['nonce']
assert cid == '241b7bd54f4d3e53481a14335c0c21ab63b24f9f5249d76a7539d4bfd5b7a7ca'
assert name == 'wonad-phase1-frankel-vendor-cache-create-only-20261011-6'
files = {key: json.loads(digest(PROOF / filename, r[key])) for key, filename in [
    ('command', 'command.json'), ('inspect', 'inspect.json'),
    ('pre_removal_inspect', 'pre-removal-inspect.json'), ('created_id', 'created-id.json'), ('cleanup', 'cleanup.json')]}
assert files['inspect'] == files['pre_removal_inspect'] and len(files['inspect']) == 1
assert files['created_id'] == {'id': cid, 'name': name, 'nonce': nonce}
info = files['inspect'][0]
cfg, host, state = info['Config'], info['HostConfig'], info['State']
image = 'sha256:f719a4a56095b613790ef9afcba2aabda795217ac98e08c24ba5cec65bd4ee33'
assert info['Id'] == cid and info['Name'] == '/' + name and info['Image'] == cfg['Image'] == image
assert cfg['Labels'] == {'org.wonad.phase1.vendor-attempt': nonce, 'org.wonad.phase1.vendor-mode': 'create-only'}
assert state['Status'] == 'created' and state['Pid'] == state['ExitCode'] == 0
for key in ('Running', 'Paused', 'Restarting', 'Dead', 'OOMKilled'):
    assert state[key] is False
assert state['StartedAt'] == state['FinishedAt'] == '0001-01-01T00:00:00Z'
expected_profile = {
    'Memory': 34359738368, 'MemorySwap': 34359738368, 'NanoCpus': 4000000000,
    'CpusetCpus': '0-3', 'PidsLimit': 2048, 'ReadonlyRootfs': True, 'Privileged': False,
    'NetworkMode': 'bridge', 'CapDrop': ['ALL'], 'CapAdd': None, 'Devices': [], 'PortBindings': {},
    'SecurityOpt': ['label=disable', 'no-new-privileges=true'],
    'Tmpfs': {'/tmp': 'rw,nosuid,nodev,size=4294967296,mode=1777'},
    'AutoRemove': False, 'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
    'PidMode': '', 'IpcMode': 'private', 'UTSMode': '', 'UsernsMode': '',
}
for key, expected in expected_profile.items():
    assert host[key] == expected, (key, host[key])
for key in ('DeviceRequests', 'DeviceCgroupRules', 'GroupAdd', 'VolumesFrom', 'Links', 'ExtraHosts'):
    assert host[key] in (None, [], {})
assert not cfg.get('ExposedPorts') and not cfg.get('Volumes')
source = '/u/elric/tree/wonad-grapheneos-2026100600-frankel-baseline-1'
wonad = '/u/elric/tree/wonad'
work = str(PROOF / 'empty-image-cache')
expected_mounts = [
    {'Type': 'bind', 'Source': source, 'Destination': '/grapheneos', 'Mode': 'rw', 'RW': True, 'Propagation': 'rprivate'},
    {'Type': 'bind', 'Source': wonad, 'Destination': '/wonad', 'Mode': 'ro', 'RW': False, 'Propagation': 'rprivate'},
    {'Type': 'bind', 'Source': work, 'Destination': '/adevtool-images', 'Mode': 'rw', 'RW': True, 'Propagation': 'rprivate'},
]
assert sorted(info['Mounts'], key=lambda m: m['Destination']) == sorted(expected_mounts, key=lambda m: m['Destination'])
assert sorted(host['Binds']) == sorted([source + ':/grapheneos:rw', wonad + ':/wonad:ro', work + ':/adevtool-images:rw'])
assert len(r['input_binding']['inputs']) == 25
for path, reference in r['input_binding']['inputs'].items():
    digest(Path(path), reference)
assert files['command']['observed_inputs'] == r['input_binding'] and files['command']['never_start'] is True
helper = PROOF.parent / 'phase1_frankel_vendor_cache_driver_20261011_4.py'
spec = importlib.util.spec_from_file_location('root_vendor4_review', helper)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert files['command']['argv'] == module._core.command('create', name, nonce, Path(work))
assert cfg['User'] == '1000:1000' and cfg['WorkingDir'] == '/grapheneos'
assert cfg['Entrypoint'] == ['/usr/bin/env'] and info['Path'] == '/usr/bin/env'
assert cfg['Cmd'] == info['Args'] == module._core.PAYLOAD
assert not any(Path(work).iterdir())
cache = r['input_binding']['cache']
for key in ('archive', 'directory'):
    entry = cache[key]
    observed = Path(entry['path']).lstat()
    values = {'device': observed.st_dev, 'inode': observed.st_ino, 'uid': observed.st_uid,
              'gid': observed.st_gid, 'mode': stat.S_IMODE(observed.st_mode)}
    if key == 'archive':
        values.update(bytes=observed.st_size, nlink=observed.st_nlink)
    assert all(entry[k] == value for k, value in values.items()), key
digest(Path(cache['directory']['path']) / 'receipt.json', cache['receipt'])
cleanup = files['cleanup']
assert cleanup['exact_id_removed'] == cid and cleanup['name_and_nonce_authenticated'] is True and cleanup['never_started'] is True
for key, stem in [('remove_result', 'remove-result'), ('name_absence', 'name-absence'), ('id_absence', 'id-absence')]:
    operation = json.loads(digest(PROOF / (stem + '.json'), cleanup[key]))
    stdout = digest(PROOF / (stem + '.stdout'), operation['stdout'])
    stderr = digest(PROOF / (stem + '.stderr'), operation['stderr'])
    if key == 'remove_result':
        assert operation['returncode'] == 0 and not stderr and stdout.decode().strip() == cid
        assert operation['argv'][-3:] == ['container', 'rm', cid]
    else:
        assert operation['returncode'] == 1 and not stdout.strip()
        target = name if key == 'name_absence' else cid
        assert stderr.strip() == ('Error response from daemon: No such container: ' + target).encode()
for target in (cid, name):
    result = subprocess.run(['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', 'container', 'inspect', '--format', '{{.Id}}', target],
                            capture_output=True, timeout=30)
    assert result.returncode == 1 and not result.stdout.strip()
    assert result.stderr.strip() == ('Error response from daemon: No such container: ' + target).encode()
for filename in ('phase1-frankel-vendor-cache-work-20261011-3', 'phase1-frankel-baseline-vendor-cache-20261011-4.log',
                 'phase1-frankel-baseline-vendor-cache-20261011-4.preflight.json'):
    assert not (PROOF.parent / filename).exists(), filename
print('ROOT PASS proof6: 25 current input hashes; literal command/payload/profile/three binds; never-started; authenticated cleanup/current absence; original cache stat identity only; fresh future outputs.')
