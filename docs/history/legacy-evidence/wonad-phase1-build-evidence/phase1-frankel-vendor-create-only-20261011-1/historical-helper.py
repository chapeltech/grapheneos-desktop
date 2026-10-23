#!/usr/bin/env python3
"""One literal vendor attempt; optional Docker create-only proof never starts it.

No arbitrary source, image or payload is accepted. This is development
preparation, not source freeze, successful build, vendor or runtime evidence.
The four-CPU affinity makes pinned Soong NumCPU()+2 choose six Siso jobs; it
does not bound microfactory dependency count or total RSS. Cgroup memory/PID
limits are still required. The 4-GiB tmpfs and other admission budgets are
conservative, unmeasured limits, not observations of vendor peak usage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
WONAD = Path('/u/elric/tree/wonad')
EVIDENCE = Path('/u/elric/tree/wonad-phase1-build-evidence')
SOURCE = Path('/u/elric/tree/wonad-grapheneos-2026100600-frankel-baseline-1')
DRIVER = EVIDENCE / 'prepare-phase1-frankel-vendor-20261011-1.sh'
HELPER = EVIDENCE / 'phase1_frankel_vendor_driver_20261011_1.py'
LOG = EVIDENCE / 'phase1-frankel-baseline-vendor-20261011-1.log'
PREFLIGHT = EVIDENCE / 'phase1-frankel-baseline-vendor-20261011-1.preflight.json'
NAME = 'wonad-phase1-frankel-vendor-2026100600-001'
PROOF_NAME = 'wonad-phase1-frankel-vendor-create-only-20261011-1'
PROOF = EVIDENCE / 'phase1-frankel-vendor-create-only-20261011-1'
IMAGE = 'sha256:f719a4a56095b613790ef9afcba2aabda795217ac98e08c24ba5cec65bd4ee33'
DOCKER = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock']
MEMORY = 32 * 1024 ** 3
MIN_SOURCE_FREE = 64 * 1024 ** 3
TMPFS = 'rw,nosuid,nodev,size=4294967296,mode=1777'
INPUT_SHA = {
    'android/grapheneos.lock.json': 'ad259dde404f13a9d24e394b6ef8b19301ae436071316867ef1219e98f7486d6',
    'android/platform/release-build.sh': '756561b653494734861442cc0f05a57775ce36d2d13e96ab98b6de71ebf8c47c',
    'android/tools/phase1_provenance.py': 'b0b0708f3405e6ea6b8fdb4fdd0abf8120208259a398bea12010b944a930fb50',
    'android/tools/verify_sources.py': '478a9fc83f7d316918487880383b11a39540ce28c40b2722f9f0fd9c312cbcf8',
    'android/tools/verify_checkout.py': '72a2fc049c11236dc010b52a53b3d0722be0898ff906b215131b23e0d9d5dd39',
    'android/tools/checkout_health.py': '168d309707daf8f30dfcf8785d43359effc8ec99e6c523a9de1ebdaf82376fa2',
}
SOURCE_SHA = {
    '.repo/manifests/default.xml': '32d30e70ee59d373a17fe8090bdded898afa80651f27c331caca4578b3008888',
    'vendor/adevtool/config/device/frankel.yml': '2521e1a357d029336b4574c2ae9897dc4b9cf2cba729c6a3376bd65f705b79a1',
    'vendor/adevtool/config/device/common/gen10pixel.yml': '92dd7f9cfdb3bdef2922892048f323407b6896f5e93f7ca8f73816488254ceca',
    'vendor/adevtool/config/build-index/build-index-main.yml': 'a108c6dd08afe9ad5e3fe09f36ae513b2fac34c7d18a2a66d5a90ebb742933f4',
    'vendor/adevtool/vendor-specs/google_devices/frankel.yml': 'd3e8ba76ad3711a101105278bb3217984061828dfd89fe34718f067a2cdf987c',
    'vendor/adevtool/yarn.lock': '69475c004b6271a3817e7c79bebf7459e9e3c80684864cd60bdf88d944904f8f',
    'vendor/state/frankel.json': '3c139de11a8bbe8f3f4fb16f339da60bfdbe598492d7f2b346bc3e68794d8759',
}
PROCESS_ENV = [
    'PATH=/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'HOME=/tmp/wonad-vendor-home', 'LANG=C.UTF-8', 'LC_ALL=C.UTF-8',
    'TMPDIR=/tmp', 'YARN_CACHE_FOLDER=/tmp/wonad-vendor-yarn-cache',
    'WONAD_GRAPHENEOS_RELEASE_SOURCE=/grapheneos',
    'WONAD_YARN_BIN=/usr/bin/yarnpkg', 'NINJA_HIGHMEM_NUM_JOBS=1',
    'PYTHONDONTWRITEBYTECODE=1', 'GIT_OPTIONAL_LOCKS=0', 'GIT_NO_LAZY_FETCH=1',
]
INNER = (
    'mkdir -m 0700 -- /tmp/wonad-vendor-home /tmp/wonad-vendor-yarn-cache; '
    'test "$(node --version)" = v24.21.0; '
    'test "$(/usr/bin/yarnpkg --version)" = 1.22.19; '
    'exec /bin/bash /wonad/android/platform/release-build.sh prepare-vendor'
)
PAYLOAD = ['-i', *PROCESS_ENV, '/bin/bash', '--noprofile', '--norc', '-e', '-c', INNER]
sys.path.insert(0, str(WONAD / 'android/tools'))
import docker_locality_proof as locality  # noqa: E402


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'


def ref(path):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
            path.resolve(strict=True) == path, f'Not an ordinary canonical file: {path}')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    after = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_mtime_ns', 'st_ctime_ns')
    require(all(getattr(before, key) == getattr(after, key) for key in fields),
            f'Input changed during observation: {path}')
    return {'bytes': before.st_size, 'sha256': digest.hexdigest()}


def directory(path):
    value = path.lstat()
    require(stat.S_ISDIR(value.st_mode) and path.resolve(strict=True) == path,
            f'Not a literal canonical directory: {path}')
    require((value.st_uid, value.st_gid) == (1000, 1000), f'Unexpected owner: {path}')
    return {'path': str(path), 'device': value.st_dev, 'inode': value.st_ino,
            'mode': value.st_mode, 'uid': value.st_uid, 'gid': value.st_gid}


def fresh(path):
    directory(path.parent)
    require(not os.path.lexists(path), f'Fresh output already exists: {path}')


def run(arguments, environment):
    return subprocess.run(DOCKER + arguments, env=environment, check=False,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)


def checked(arguments, environment):
    result = run(arguments, environment)
    require(result.returncode == 0 and not result.stderr,
            f'Docker read/create operation failed: {result.stderr.decode(errors="replace").strip()}')
    return result.stdout


def inspect(identity, environment):
    raw = checked(['container', 'inspect', identity], environment)
    rows = locality.parse_json(raw, 'vendor container inspect')
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict),
            'Container inspect is ambiguous')
    return rows[0], raw


def missing_container(name, environment):
    result = run(['container', 'inspect', '--format', '{{.Id}}', name], environment)
    require(result.returncode == 1 and not result.stdout.strip() and
            re.search(r'No such (?:object|container):\s*' + re.escape(name) + r'\s*$',
                      result.stderr.decode(errors='replace')),
            f'Cannot prove fresh container name: {name}')


def cpu_set(text):
    result = set()
    for piece in text.strip().split(','):
        ends = piece.split('-')
        require(1 <= len(ends) <= 2 and all(item.isdecimal() for item in ends),
                'Malformed online CPU set')
        low, high = int(ends[0]), int(ends[-1])
        require(0 <= low <= high <= 65535, 'Invalid online CPU range')
        result.update(range(low, high + 1))
    return result


def ancestors():
    result = set()
    current = os.getpid()
    while current > 0 and current not in result:
        result.add(current)
        current = int(Path(f'/proc/{current}/stat').read_text().rpartition(') ')[2].split()[1])
    return result


def live_lanes():
    ignored = ancestors()
    active = []
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal() or int(path.name) in ignored:
            continue
        try:
            state = (path / 'stat').read_text().rpartition(') ')[2].split()[0]
            if state in {'Z', 'X'}:
                continue
            args = [(part.decode(errors='replace')) for part in
                    (path / 'cmdline').read_bytes().split(b'\0') if part]
        except FileNotFoundError:
            continue
        if not args:
            continue
        executable = Path(args[0]).name
        matched = None
        if executable in {'emulator', 'soong_ui', 'soong_build'} or executable.startswith('qemu-system-'):
            matched = executable
        for arg in args[:5]:
            name = Path(arg).name
            if name in {'run_x86_build.py', 'run_frankel_build.py', 'run_release_build.py'}:
                matched = name
            elif name == 'phase1_generic_upstream_evidence.py' and 'run-aosp-host' in args:
                matched = 'native AOSP host tests'
            elif name == 'run-build.sh' and '/vendor/adevtool/' in arg:
                matched = 'adevtool host dependency build'
            elif name.startswith('continue-phase1-x86-') and name.endswith('.sh'):
                matched = 'x86 build continuation'
            elif name == DRIVER.name:
                matched = 'vendor preparation driver'
            elif name == HELPER.name and '--run' in args:
                matched = 'vendor preparation driver'
        if 'generate-all' in args and any('/vendor/adevtool/' in value for value in args):
            matched = 'adevtool vendor generation'
        if matched:
            active.append({'pid': int(path.name), 'lane': matched})
    return sorted(active, key=lambda row: row['pid'])


def resources(environment):
    available = None
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            fields = line.split()
            require(len(fields) == 3 and fields[2] == 'kB', 'Invalid MemAvailable unit')
            available = int(fields[1]) * 1024
    require(available is not None and available >= MEMORY,
            f'Vendor preparation needs >=32 GiB MemAvailable; observed {available}')
    source_fs = os.statvfs(SOURCE)
    free = source_fs.f_bavail * source_fs.f_frsize
    require(free >= MIN_SOURCE_FREE,
            f'Vendor preparation needs >=64 GiB source free space; observed {free}')
    require(cpu_set(Path('/sys/devices/system/cpu/online').read_text()) >= {0, 1, 2, 3} and
            set(os.sched_getaffinity(0)) >= {0, 1, 2, 3}, 'CPUs 0-3 are not online/allowed')
    lanes = live_lanes()
    running = checked(['container', 'ls', '--filter', 'status=running',
                       '--format', '{{.Names}}'], environment).decode().splitlines()
    for name in running:
        if name.startswith(('wonad-upstream-', 'wonad-phase1-x86-', 'wonad-phase1-frankel-')):
            lanes.append({'container': name, 'lane': 'native/OS/vendor container'})
    require(not lanes, 'Relevant native/OS/vendor/VM lanes are live: ' + json.dumps(lanes))
    return {'mem_available_bytes': available, 'source_free_bytes': free,
            'cpus_online_and_allowed': [0, 1, 2, 3], 'observed_live_lanes': lanes,
            'limits_are_conservative_unmeasured': True}


def base_checks():
    require((os.getuid(), os.getgid()) == (1000, 1000), 'Run as exact UID/GID 1000:1000')
    roots = {str(path): directory(path) for path in (WONAD, EVIDENCE, SOURCE, SOURCE / '.repo', SOURCE / 'out')}
    require(not any((SOURCE / 'out').iterdir()), 'Dedicated source out/ is not empty')
    for relative in ('vendor/google_devices/frankel', 'external/wonad', '.wonad-updater-stage.json',
                     'keys', 'private-keys', 'private_keys', 'secrets', 'out_adevtool_deps',
                     'vendor/adevtool/node_modules', 'vendor/adevtool/lib', 'vendor/adevtool/dist',
                     'vendor/adevtool/.cache', 'vendor/adevtool/cache', 'vendor/adevtool/.yarn'):
        require(not os.path.lexists(SOURCE / relative),
                f'Preserving unexpected pre-existing source/cache content; refuse preparation: {relative}')
    dl = SOURCE / 'vendor/adevtool/dl'
    require(sorted(item.name for item in dl.iterdir()) == ['.find-ignore'],
            'Preserving pre-existing adevtool download diagnostics; only tracked marker expected')
    inputs = {}
    for root, references in ((WONAD, INPUT_SHA), (SOURCE, SOURCE_SHA)):
        for relative, expected in references.items():
            observed = ref(root / relative)
            require(observed['sha256'] == expected, f'Authenticated preparation input differs: {relative}')
            inputs[str(root / relative)] = observed
    inputs[str(DRIVER)] = ref(DRIVER)
    inputs[str(HELPER)] = ref(HELPER)
    environment = locality.command_environment()
    cli, socket, context, daemon = locality.trusted_local_docker(environment)
    image_rows = locality.parse_json(checked(['image', 'inspect', IMAGE], environment), 'builder inspect')
    require(isinstance(image_rows, list) and len(image_rows) == 1 and
            image_rows[0].get('Id') == IMAGE and image_rows[0].get('Os') == 'linux' and
            image_rows[0].get('Architecture') == 'amd64', 'Locked builder identity/platform differs')
    return {'roots': roots, 'inputs': inputs, 'local_docker': {
        'cli': cli, 'socket': socket, 'context': context, 'daemon': daemon},
        'builder_id': IMAGE}, environment


def command(action, name, nonce):
    return DOCKER + [
        action, '--name', name, '--platform', 'linux/amd64', '--network', 'bridge',
        '--attach', 'stdout', '--attach', 'stderr',
        '--user', '1000:1000', '--cap-drop', 'ALL', '--security-opt', 'label=disable',
        '--security-opt', 'no-new-privileges=true', '--read-only',
        '--memory', str(MEMORY), '--memory-swap', str(MEMORY),
        '--cpus', '4', '--cpuset-cpus', '0-3', '--pids-limit', '2048',
        '--restart', 'no', '--tmpfs', '/tmp:' + TMPFS,
        '--workdir', '/grapheneos', '--entrypoint', '/usr/bin/env',
        '--label', 'org.wonad.phase1.vendor-attempt=' + nonce,
        '--label', 'org.wonad.phase1.vendor-mode=' + ('create-only' if action == 'create' else 'prepare'),
        '--volume', str(SOURCE) + ':/grapheneos:rw',
        '--volume', str(WONAD) + ':/wonad:ro', IMAGE, *PAYLOAD]


def validate_created(info, identity, nonce):
    require(re.fullmatch(r'[0-9a-f]{64}', identity) is not None and info.get('Id') == identity,
            'Created container exact ID differs')
    cfg, host, state = info.get('Config', {}), info.get('HostConfig', {}), info.get('State', {})
    require(info.get('Name') == '/' + PROOF_NAME and info.get('Image') == IMAGE and
            cfg.get('Image') == IMAGE and cfg.get('Labels') == {
                'org.wonad.phase1.vendor-attempt': nonce,
                'org.wonad.phase1.vendor-mode': 'create-only'}, 'Created owner/image/nonce differs')
    require(state.get('Status') == 'created' and state.get('Running') is False and
            state.get('Paused') is False and state.get('Restarting') is False and
            state.get('Dead') is False and state.get('OOMKilled') is False and
            state.get('Pid') == 0 and state.get('ExitCode') == 0 and
            state.get('StartedAt') == '0001-01-01T00:00:00Z' and
            state.get('FinishedAt') == '0001-01-01T00:00:00Z', 'Container was started or changed state')
    require(cfg.get('User') == '1000:1000' and cfg.get('WorkingDir') == '/grapheneos' and
            cfg.get('Entrypoint') == ['/usr/bin/env'] and cfg.get('Cmd') == PAYLOAD and
            info.get('Path') == '/usr/bin/env' and info.get('Args') == PAYLOAD,
            'Created exact payload grammar differs')
    require(cfg.get('AttachStdin') is False and cfg.get('AttachStdout') is True and
            cfg.get('AttachStderr') is True and cfg.get('OpenStdin') is False and
            cfg.get('StdinOnce') is False and cfg.get('Tty') is False,
            'Created stdio/TTY grammar differs')
    expected = {'Memory': MEMORY, 'MemorySwap': MEMORY, 'NanoCpus': 4_000_000_000,
                'CpusetCpus': '0-3', 'PidsLimit': 2048, 'ReadonlyRootfs': True,
                'NetworkMode': 'bridge', 'Privileged': False, 'AutoRemove': False,
                'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                'Tmpfs': {'/tmp': TMPFS}, 'CapDrop': ['ALL'],
                'SecurityOpt': ['label=disable', 'no-new-privileges=true'],
                'Binds': [str(SOURCE) + ':/grapheneos:rw', str(WONAD) + ':/wonad:ro']}
    require(all(host.get(key) == value for key, value in expected.items()),
            'Created resource/security/bind profile differs')
    for key in ('CapAdd', 'Devices', 'DeviceRequests', 'DeviceCgroupRules', 'GroupAdd',
                'PortBindings', 'VolumesFrom', 'Links', 'ExtraHosts'):
        require(host.get(key) in (None, [], {}), f'Unexpected created capability/device/port/mount: {key}')
    require(not cfg.get('ExposedPorts') and not cfg.get('Volumes') and
            host.get('PidMode') == '' and host.get('IpcMode') == 'private' and
            host.get('UTSMode') == '' and host.get('UsernsMode') == '',
            'Unexpected namespace/public port/anonymous volume')
    mounts = info.get('Mounts')
    require(isinstance(mounts, list) and len(mounts) == 2, 'Unexpected number of created bind mounts')
    actual = sorted((row.get('Type'), row.get('Source'), row.get('Destination'), row.get('Mode'),
                     row.get('RW'), row.get('Propagation')) for row in mounts)
    require(actual == sorted([
        ('bind', str(SOURCE), '/grapheneos', 'rw', True, 'rprivate'),
        ('bind', str(WONAD), '/wonad', 'ro', False, 'rprivate')]), 'Created bind roots differ')
    return True


def owned_never_started(info, identity, nonce):
    """The narrower authority needed to remove only our exact unstarted ID."""
    cfg, host, state = info.get('Config', {}), info.get('HostConfig', {}), info.get('State', {})
    require(re.fullmatch(r'[0-9a-f]{64}', identity) is not None and info.get('Id') == identity and
            info.get('Name') == '/' + PROOF_NAME and info.get('Image') == IMAGE and
            cfg.get('Image') == IMAGE and cfg.get('Labels') == {
                'org.wonad.phase1.vendor-attempt': nonce,
                'org.wonad.phase1.vendor-mode': 'create-only'}, 'Owned cleanup ID/name/nonce differs')
    require(state.get('Status') == 'created' and state.get('Running') is False and
            state.get('Pid') == 0 and state.get('StartedAt') == '0001-01-01T00:00:00Z',
            'Refuse cleanup: owned container is not still never-started')
    require(host.get('Binds') == [str(SOURCE) + ':/grapheneos:rw', str(WONAD) + ':/wonad:ro'],
            'Owned cleanup source/Wonad bind identities differ')
    mounts = info.get('Mounts')
    require(isinstance(mounts, list) and len(mounts) == 2 and
            sorted((row.get('Type'), row.get('Source'), row.get('Destination'), row.get('Mode'),
                    row.get('RW'), row.get('Propagation')) for row in mounts) == sorted([
                ('bind', str(SOURCE), '/grapheneos', 'rw', True, 'rprivate'),
                ('bind', str(WONAD), '/wonad', 'ro', False, 'rprivate')]),
            'Owned cleanup exact bind roots differ')
    return True


def write_new(path, value):
    return write_raw_new(path, canonical(value))


def write_raw_new(path, payload):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return ref(path)


def create_only():
    before, environment = base_checks()
    fresh(PROOF)
    missing_container(PROOF_NAME, environment)
    nonce = secrets.token_hex(32)
    argv = command('create', PROOF_NAME, nonce)
    PROOF.mkdir(mode=0o700)
    write_new(PROOF / 'command.json', {'argv': argv, 'nonce': nonce, 'never_start': True,
                                     'observed_inputs': before, 'scope': 'create-only, not preparation'})
    identity = checked(argv[len(DOCKER):], environment).decode().strip()
    require(re.fullmatch(r'[0-9a-f]{64}', identity) is not None, 'Created ID is malformed')
    write_new(PROOF / 'created-id.json', {'id': identity, 'name': PROOF_NAME, 'nonce': nonce})
    try:
        info, raw = inspect(identity, environment)
        write_raw_new(PROOF / 'inspect.json', raw)
        validate_created(info, identity, nonce)
        after, _ = base_checks()
        require(before == after, 'Inputs/bind directory identities changed during create-only proof')
    finally:
        second, raw_second = inspect(identity, environment)
        write_raw_new(PROOF / 'pre-removal-inspect.json', raw_second)
        owned_never_started(second, identity, nonce)
        removed = checked(['container', 'rm', identity], environment).decode().strip()
        require(removed == identity, 'Exact owned container removal output differs')
        missing_container(PROOF_NAME, environment)
        missing_container(identity, environment)
        write_new(PROOF / 'cleanup.json', {'exact_id_removed': identity,
                  'name_and_nonce_authenticated': True, 'never_started': True})
    final, _ = base_checks()
    require(before == final, 'Input/bind identities changed during exact owned cleanup')
    receipt = {'schema': 1, 'kind': 'phase1_frankel_vendor_real_docker_create_only_v1',
               'container_id': identity, 'container_name': PROOF_NAME, 'nonce': nonce,
               'never_started': True, 'exact_owned_container_removed': True,
               'not_vendor_generation_or_build': True, 'not_runtime_qualification': True,
               'command': ref(PROOF / 'command.json'), 'inspect': ref(PROOF / 'inspect.json'),
               'pre_removal_inspect': ref(PROOF / 'pre-removal-inspect.json'),
               'created_id': ref(PROOF / 'created-id.json'), 'cleanup': ref(PROOF / 'cleanup.json'),
               'input_binding': before, 'resources': {'memory_bytes': MEMORY, 'memory_swap_bytes': MEMORY,
               'cpuset_cpus': '0-3', 'nano_cpus': 4_000_000_000, 'pids': 2048, 'tmpfs': TMPFS},
               'admission_not_run': 'Creation only; native lane exclusion deliberately not a readiness claim'}
    result = write_new(PROOF / 'receipt.json', receipt)
    print('CREATE-ONLY profile proof; exact never-started container removed; NOT vendor generation/build')
    print(str(PROOF / 'receipt.json'))
    print(result['sha256'])


def preparation(check_only):
    before, environment = base_checks()
    fresh(LOG)
    fresh(PREFLIGHT)
    missing_container(NAME, environment)
    budget = resources(environment)
    if check_only:
        print('Read-only admission check passed now; NOT a vendor/build result or reserved resources')
        print(json.dumps(budget, sort_keys=True))
        return
    nonce = secrets.token_hex(32)
    argv = command('run', NAME, nonce)
    after, _ = base_checks()
    require(before == after, 'Preparation inputs changed before final admission')
    budget = resources(environment)
    write_new(PREFLIGHT, {'schema': 1, 'kind': 'phase1_frankel_vendor_literal_preflight_v1',
                         'argv': argv, 'inputs': before, 'admission': budget,
                         'not_source_freeze_or_vendor_result': True, 'time_unix': int(time.time())})
    descriptor = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        result = subprocess.run(argv, env=environment, stdout=stream, stderr=subprocess.STDOUT)
        stream.flush()
        os.fsync(stream.fileno())
    print(f'Vendor workflow exited {result.returncode}; retained {NAME}, {LOG}, {PREFLIGHT}')
    print('No source freeze, baseline ARM build, signing or runtime qualification is claimed')
    if result.returncode:
        raise SystemExit(result.returncode)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--check-only', action='store_true')
    actions.add_argument('--run', action='store_true')
    actions.add_argument('--create-only-proof', action='store_true')
    args = parser.parse_args()
    try:
        if args.create_only_proof:
            create_only()
        else:
            preparation(not args.run)
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, locality.ProofError) as error:
        print('Vendor driver refused: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
