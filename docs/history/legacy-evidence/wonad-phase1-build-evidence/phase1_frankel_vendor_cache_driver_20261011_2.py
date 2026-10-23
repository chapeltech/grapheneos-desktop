#!/usr/bin/env python3
"""Literal Frankel vendor preparation using one authenticated factory cache.

The default action is a read-only admission check.  ``--run`` is the only
action which creates the external image workspace, and it may populate that
workspace only with an FICLONE of the authenticated public factory archive.
There is deliberately no byte-copy or download fallback.  Adevtool itself
rechecks the indexed archive digest before unpacking it.

``--create-only-proof`` creates and removes a never-started Docker container
to record the three-bind profile.  It does not clone or expose the factory
archive and is not vendor-generation, build, or runtime evidence.
"""
from __future__ import annotations

import argparse
import errno
import fcntl
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
CACHE = EVIDENCE / 'phase1-frankel-factory-cache-20261011-1'
CACHE_RECEIPT = CACHE / 'receipt.json'
ARCHIVE_NAME = 'frankel-cp3a.261005.005-factory-3721e6ac.zip'
ARCHIVE = CACHE / ARCHIVE_NAME
WORK = EVIDENCE / 'phase1-frankel-vendor-cache-work-20261011-1'
DRIVER = EVIDENCE / 'prepare-phase1-frankel-vendor-cache-20261011-2.sh'
HELPER = EVIDENCE / 'phase1_frankel_vendor_cache_driver_20261011_2.py'
TEST = EVIDENCE / 'test_phase1_frankel_vendor_cache_driver_20261011_2.py'
LOG = EVIDENCE / 'phase1-frankel-baseline-vendor-cache-20261011-2.log'
PREFLIGHT = EVIDENCE / 'phase1-frankel-baseline-vendor-cache-20261011-2.preflight.json'
NAME = 'wonad-phase1-frankel-vendor-cache-2026100600-002'
PROOF_NAME = 'wonad-phase1-frankel-vendor-cache-create-only-20261011-5'
PROOF = EVIDENCE / 'phase1-frankel-vendor-cache-create-only-20261011-5'
PROOF_WORK = PROOF / 'empty-image-cache'

IMAGE = 'sha256:f719a4a56095b613790ef9afcba2aabda795217ac98e08c24ba5cec65bd4ee33'
DOCKER = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock']
MEMORY = 32 * 1024 ** 3
MIN_SOURCE_FREE = 64 * 1024 ** 3
TMPFS = 'rw,nosuid,nodev,size=4294967296,mode=1777'
MAX_CMDLINE = 65536
FICLONE = 0x40049409

CACHE_RECEIPT_SHA256 = '458273099a83f97c60ed6ba1a7a40e14704f850b04068443946ca65e78dbe6c3'
ARCHIVE_SHA256 = '3721e6accc2e87d851ee7966d794318078ec74c7cc32343daa10968264d6bb62'
ARCHIVE_BYTES = 11378664978
CACHE_DEVICE = 64513
CACHE_INODE = 2362021952
ARCHIVE_DEVICE = 64513
ARCHIVE_INODE = 2362021956
ADEVTOOL_COMMIT = '17df3b79a73e67ad68387b35c7d41c85e1d8103c'
BUILD_INDEX_SHA256 = 'a108c6dd08afe9ad5e3fe09f36ae513b2fac34c7d18a2a66d5a90ebb742933f4'

INPUT_SHA = {
    'android/grapheneos.lock.json': 'ad259dde404f13a9d24e394b6ef8b19301ae436071316867ef1219e98f7486d6',
    'android/platform/allowed_signers': '344f59c6f058699e63fea68e35953b341c14e3bf1fbc1256f6baa84aa2aca1d0',
    'android/platform/release-build.sh': '756561b653494734861442cc0f05a57775ce36d2d13e96ab98b6de71ebf8c47c',
    'android/tools/phase1_provenance.py': 'b0b0708f3405e6ea6b8fdb4fdd0abf8120208259a398bea12010b944a930fb50',
    'android/tools/docker_locality_proof.py': '09b68ceabeb83ed997608a427f8bd5e4196a229d0e3ffd5fc59a98cff85da780',
    'android/tools/verify_sources.py': '478a9fc83f7d316918487880383b11a39540ce28c40b2722f9f0fd9c312cbcf8',
    'android/tools/verify_checkout.py': '72a2fc049c11236dc010b52a53b3d0722be0898ff906b215131b23e0d9d5dd39',
    'android/tools/checkout_health.py': '168d309707daf8f30dfcf8785d43359effc8ec99e6c523a9de1ebdaf82376fa2',
}

SOURCE_SHA = {
    '.repo/manifests/default.xml': '32d30e70ee59d373a17fe8090bdded898afa80651f27c331caca4578b3008888',
    'vendor/adevtool/config/device/frankel.yml': '2521e1a357d029336b4574c2ae9897dc4b9cf2cba729c6a3376bd65f705b79a1',
    'vendor/adevtool/config/device/common/gen10pixel.yml': '92dd7f9cfdb3bdef2922892048f323407b6896f5e93f7ca8f73816488254ceca',
    'vendor/adevtool/config/build-index/build-index-main.yml': BUILD_INDEX_SHA256,
    'vendor/adevtool/vendor-specs/google_devices/frankel.yml': 'd3e8ba76ad3711a101105278bb3217984061828dfd89fe34718f067a2cdf987c',
    'vendor/adevtool/yarn.lock': '69475c004b6271a3817e7c79bebf7459e9e3c80684864cd60bdf88d944904f8f',
    'vendor/state/frankel.json': '3c139de11a8bbe8f3f4fb16f339da60bfdbe598492d7f2b346bc3e68794d8759',
    'vendor/adevtool/src/config/paths.ts': '418823cca30a381208e13acd7ea30d5ff37be411f1492ccd05f290ba4c95bd8e',
    'vendor/adevtool/src/images/device-image.ts': 'f2a8a827b609dbf5bd31488de5b762eb6777408bd29c45521cefdc9d798bbfc0',
    'vendor/adevtool/src/frontend/source.ts': '001de5cab8ae7524ba862135d7663a467a7b49ae0fea733d044090c40a728ca9',
    'vendor/adevtool/src/commands/download.ts': 'a734b1570c8cd4099b242b8893de77ac6683a08e92f83eff5c19319044d27984',
    'vendor/adevtool/src/images/download.ts': '2d4384422de6c48999ed716024bb92e1a23efeb865a50cfdf7a45dec84c3ffee',
}

PROCESS_ENV = [
    'PATH=/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'HOME=/tmp/wonad-vendor-home', 'LANG=C.UTF-8', 'LC_ALL=C.UTF-8',
    'TMPDIR=/tmp', 'YARN_CACHE_FOLDER=/tmp/wonad-vendor-yarn-cache',
    'ADEVTOOL_IMG_DOWNLOAD_DIR=/adevtool-images',
    'WONAD_GRAPHENEOS_RELEASE_SOURCE=/grapheneos',
    'WONAD_YARN_BIN=/usr/bin/yarnpkg', 'NINJA_HIGHMEM_NUM_JOBS=1',
    'PYTHONDONTWRITEBYTECODE=1', 'GIT_OPTIONAL_LOCKS=0', 'GIT_NO_LAZY_FETCH=1',
]
INNER = (
    'mkdir -m 0700 -- /tmp/wonad-vendor-home /tmp/wonad-vendor-yarn-cache; '
    'test "$(node --version)" = v24.21.0; '
    'test "$(/usr/bin/yarnpkg --version)" = 1.22.19; '
    'test "$ADEVTOOL_IMG_DOWNLOAD_DIR" = /adevtool-images; '
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


def _same_stat(left, right):
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_uid', 'st_gid',
              'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
    return all(getattr(left, key) == getattr(right, key) for key in fields)


def ref(path):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
            path.resolve(strict=True) == path, f'Not an ordinary canonical file: {path}')
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        require(_same_stat(before, opened), f'File changed before authenticated read: {path}')
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        require(_same_stat(opened, after), f'Input changed during observation: {path}')
    finally:
        os.close(descriptor)
    require(_same_stat(before, path.lstat()), f'Input path changed during observation: {path}')
    return {'bytes': before.st_size, 'sha256': digest.hexdigest()}


def directory(path, *, expected=None):
    path = Path(path)
    value = path.lstat()
    require(stat.S_ISDIR(value.st_mode) and path.resolve(strict=True) == path,
            f'Not a literal canonical directory: {path}')
    require((value.st_uid, value.st_gid) == (1000, 1000), f'Unexpected owner: {path}')
    record = {'path': str(path), 'device': value.st_dev, 'inode': value.st_ino,
              'mode': stat.S_IMODE(value.st_mode), 'uid': value.st_uid, 'gid': value.st_gid}
    if expected is not None:
        require(all(record.get(key) == wanted for key, wanted in expected.items()),
                f'Directory identity differs: {path}')
    return record


def fresh(path):
    path = Path(path)
    directory(path.parent)
    require(not os.path.lexists(path), f'Fresh output already exists: {path}')


def unique_json(payload, label):
    def pairs(values):
        result = {}
        for key, value in values:
            require(isinstance(key, str) and key not in result,
                    f'Duplicate or non-string JSON key in {label}: {key!r}')
            result[key] = value
        return result
    try:
        value = json.loads(payload, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f'Invalid JSON in {label}: {error}') from error
    require(isinstance(value, dict), f'{label} must be one JSON object')
    return value


def validate_cache_receipt(value):
    require(set(value) == {'schema', 'kind', 'scope', 'runtime_qualified', 'result',
                           'source_authority', 'archive', 'transfer', 'verification',
                           'disk', 'inventory', 'negative_claims', 'next_step'},
            'Factory cache receipt top-level schema differs')
    require(value['schema'] == 1 and
            value['kind'] == 'phase1_frankel_public_factory_archive_download_receipt_v1' and
            value['scope'] == 'authenticated public prerequisite archive cache only' and
            value['runtime_qualified'] is False and
            value['result'] == 'downloaded_and_sha256_authenticated',
            'Factory cache receipt role/result differs')
    authority = value['source_authority']
    require(isinstance(authority, dict) and set(authority) == {
        'preflight', 'baseline_root', 'adevtool_commit', 'build_index_sha256',
        'configured_build_id', 'url_derivation'}, 'Factory cache authority schema differs')
    require(authority['baseline_root'] == str(SOURCE) and
            authority['adevtool_commit'] == ADEVTOOL_COMMIT and
            authority['build_index_sha256'] == BUILD_INDEX_SHA256 and
            authority['configured_build_id'] == 'CP3A.261005.005',
            'Factory cache source/build authority differs')
    preflight = authority['preflight']
    require(preflight == {'path': 'preflight.json',
                           'sha256': '8a92daf524d9994a75d2342023cbbeb1c8cd2afa6be4e42cee10828f76f0bdc2',
                           'bytes': 4434}, 'Factory cache preflight authority differs')
    archive = value['archive']
    require(isinstance(archive, dict) and set(archive) == {
        'path', 'filename', 'url', 'bytes', 'sha256', 'device', 'inode', 'mode',
        'uid', 'gid', 'symlink', 'fsynced_before_receipt',
        'partial_path_absent_after_promotion'}, 'Factory cache archive schema differs')
    require(archive == {
        'path': str(ARCHIVE), 'filename': ARCHIVE_NAME,
        'url': 'https://dl.google.com/dl/android/aosp/' + ARCHIVE_NAME,
        'bytes': ARCHIVE_BYTES, 'sha256': ARCHIVE_SHA256,
        'device': ARCHIVE_DEVICE, 'inode': ARCHIVE_INODE, 'mode': '0644',
        'uid': 1000, 'gid': 1000, 'symlink': False,
        'fsynced_before_receipt': True, 'partial_path_absent_after_promotion': True,
    }, 'Factory cache archive identity differs')
    require(value['inventory'] == [
        'download-response-headers.txt', ARCHIVE_NAME,
        'preflight-response-headers.txt', 'preflight.json', 'receipt.json'],
        'Factory cache inventory differs')
    negative = value['negative_claims']
    require(isinstance(negative, dict) and negative and
            all(isinstance(item, bool) and item is False for item in negative.values()),
            'Factory cache negative claims differ')
    verification = value['verification']
    require(isinstance(verification, dict) and
            verification.get('partial_size_check_passed') is True and
            verification.get('partial_sha256_check_passed') is True and
            verification.get('final_sha256_recheck_passed') is True and
            verification.get('post_transfer_strict_header_parse_passed') is True,
            'Factory cache verification result differs')
    return True


def archive_identity(path=ARCHIVE):
    value = Path(path).lstat()
    require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and
            Path(path).resolve(strict=True) == Path(path), 'Factory cache archive is not canonical/regular')
    record = {'path': str(path), 'device': value.st_dev, 'inode': value.st_ino,
              'mode': stat.S_IMODE(value.st_mode), 'uid': value.st_uid,
              'gid': value.st_gid, 'bytes': value.st_size, 'nlink': value.st_nlink}
    require(record == {'path': str(ARCHIVE), 'device': ARCHIVE_DEVICE,
                       'inode': ARCHIVE_INODE, 'mode': 0o644, 'uid': 1000,
                       'gid': 1000, 'bytes': ARCHIVE_BYTES, 'nlink': 1},
            'Factory cache archive stat identity differs')
    return record


def cache_snapshot():
    cache = directory(CACHE, expected={'device': CACHE_DEVICE, 'inode': CACHE_INODE,
                                       'mode': 0o700, 'uid': 1000, 'gid': 1000})
    require(sorted(item.name for item in CACHE.iterdir()) == [
        'download-response-headers.txt', ARCHIVE_NAME,
        'preflight-response-headers.txt', 'preflight.json', 'receipt.json'],
        'Factory cache on-disk inventory differs')
    receipt_ref = ref(CACHE_RECEIPT)
    require(receipt_ref == {'sha256': CACHE_RECEIPT_SHA256, 'bytes': 4682},
            'Factory cache receipt identity differs')
    value = unique_json(CACHE_RECEIPT.read_bytes(), 'factory cache receipt')
    validate_cache_receipt(value)
    archive = archive_identity()
    return {'directory': cache, 'receipt': receipt_ref, 'archive': archive,
            'archive_sha256_from_authenticated_receipt': ARCHIVE_SHA256,
            'archive_bytes_not_rehashed_by_host_admission': True}


def git_head(path):
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                   'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_LAZY_FETCH': '1'}
    result = subprocess.run(['/usr/bin/git', '-C', str(path), 'rev-parse', 'HEAD'],
                            env=environment, check=False, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30)
    require(result.returncode == 0 and not result.stderr and
            re.fullmatch(rb'[0-9a-f]{40}\n', result.stdout) is not None,
            'Cannot authenticate adevtool Git revision')
    return result.stdout.decode().strip()


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
    return result


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


def ancestors(proc_root=Path('/proc')):
    result = set()
    current = os.getpid()
    while current > 0 and current not in result:
        result.add(current)
        raw = (proc_root / str(current) / 'stat').read_text()
        current = int(raw.rpartition(') ')[2].split()[1])
    return result


def process_kind(arguments):
    require(isinstance(arguments, list) and arguments and
            all(isinstance(item, str) and item for item in arguments),
            'Malformed process argv')
    names = [Path(item).name for item in arguments]
    exact = {
        'emulator': 'Android emulator', 'qemu-kvm': 'KVM guest',
        'soong_ui': 'Soong compiler', 'soong_build': 'Soong compiler',
        'ninja': 'native compiler', 'siso': 'native compiler', 'gradle': 'Gradle build',
        'run_x86_build.py': 'x86 OS build', 'run_frankel_build.py': 'Frankel OS build',
        'run_release_build.py': 'release OS build',
        'phase1_conformance_guest.py': 'fresh conformance guest',
        'run_phase1_conformance_recents_guest.py': 'fresh Recents guest',
        'run_native_matrix.py': 'native/GUI matrix',
        'run_phase1_upstream_guest.py': 'upstream test guest',
        'run_phase1_upstream_tests.py': 'upstream Atest run',
        'build_native_successor.py': 'APK successor build',
        'native_compile_finalize.py': 'APK successor finalize',
        'phase1_emulator_client_packet.py': 'emulator packet build',
        'build-native-candidate.py': 'native candidate image build',
        'build-phase1-conformance-candidate.py': 'conformance candidate image build',
    }
    for name in names:
        if name in exact:
            return exact[name]
        if name.startswith('qemu-system-'):
            return 'QEMU guest'
        if name.startswith('continue-phase1-x86-') and name.endswith('.sh'):
            return 'x86 build continuation'
        if re.fullmatch(r'run-phase1-.*-api-recents-.*\.py', name):
            return 'API/Recents guest wrapper'
        if name.startswith('run-phase1-native-matrix-') and name.endswith(('.py', '.sh')):
            return 'native/GUI matrix wrapper'
        if name.startswith('run-phase1-emulator-client-packet') and name.endswith(('.py', '.sh')):
            return 'emulator packet wrapper'
        if ('native-candidate' in name or 'conformance-candidate' in name) and name.endswith(('.py', '.sh')):
            return 'candidate image wrapper'
    if 'generate-all' in arguments and any('/vendor/adevtool/' in item for item in arguments):
        return 'adevtool vendor generation'
    if any(Path(item).name == 'run-build.sh' and '/vendor/adevtool/' in item
           for item in arguments):
        return 'adevtool dependency build'
    if (any(name in {'docker', 'buildx'} for name in names) and
            ('build' in arguments or 'buildx' in arguments)):
        return 'Docker image build'
    if 'run-aosp-host' in arguments and 'phase1_generic_upstream_evidence.py' in names:
        return 'native AOSP host tests'
    if HELPER.name in names and '--run' in arguments:
        return 'vendor cache preparation'
    if DRIVER.name in names and '--run' in arguments:
        return 'vendor cache preparation wrapper'
    return None


def _read_bounded(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        chunks = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(8192, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        require(total <= maximum, f'Process evidence exceeds {maximum} bytes: {path}')
        return b''.join(chunks)
    finally:
        os.close(descriptor)


def read_process(proc_dir):
    raw_state = _read_bounded(proc_dir / 'stat', 4096)
    try:
        state = raw_state.decode('ascii').rpartition(') ')[2].split()[0]
    except (UnicodeDecodeError, IndexError) as error:
        raise ValueError(f'Malformed process stat: {proc_dir}') from error
    if state in {'Z', 'X'}:
        return state, []
    raw = _read_bounded(proc_dir / 'cmdline', MAX_CMDLINE)
    require(not raw or raw.endswith(b'\0'), f'Malformed process cmdline: {proc_dir}')
    try:
        arguments = [item.decode('utf-8') for item in raw.split(b'\0') if item]
    except UnicodeDecodeError as error:
        raise ValueError(f'Non-UTF-8 process cmdline: {proc_dir}') from error
    return state, arguments


def live_lanes(proc_root=Path('/proc'), ignored=None):
    ignored = ancestors(proc_root) if ignored is None else set(ignored)
    active = []
    for path in proc_root.iterdir():
        if not path.name.isdecimal() or int(path.name) in ignored:
            continue
        try:
            state, arguments = read_process(path)
        except OSError as error:
            if error.errno in {errno.ENOENT, errno.ESRCH}:
                continue
            raise ValueError(f'Cannot authenticate process {path.name}: {error}') from error
        if state in {'Z', 'X'} or not arguments:
            continue
        lane = process_kind(arguments)
        if lane:
            active.append({'pid': int(path.name), 'lane': lane, 'argv': arguments})
    return sorted(active, key=lambda row: row['pid'])


def container_kind(info):
    require(isinstance(info, dict), 'Malformed running-container inspection')
    if info.get('State', {}).get('Running') is not True:
        return None
    cfg = info.get('Config')
    host = info.get('HostConfig')
    mounts = info.get('Mounts')
    require(isinstance(cfg, dict) and isinstance(host, dict) and isinstance(mounts, list),
            'Malformed running-container profile')
    name = info.get('Name')
    require(isinstance(name, str) and name.startswith('/'), 'Malformed running-container name')
    labels = cfg.get('Labels') or {}
    require(isinstance(labels, dict), 'Malformed running-container labels')
    devices = host.get('Devices') or []
    require(isinstance(devices, list), 'Malformed running-container devices')
    if any(isinstance(row, dict) and
           ('/dev/kvm' in {row.get('PathOnHost'), row.get('PathInContainer')})
           for row in devices):
        return 'running KVM guest container'
    if any(isinstance(row, dict) and
           ('/dev/kvm' in {row.get('Source'), row.get('Destination')}) for row in mounts):
        return 'running KVM guest container'
    command = []
    for value in (cfg.get('Entrypoint'), cfg.get('Cmd')):
        if isinstance(value, list):
            command.extend(item for item in value if isinstance(item, str))
        elif isinstance(value, str):
            command.append(value)
    if command and process_kind(command) in {'Android emulator', 'KVM guest', 'QEMU guest'}:
        return 'running VM container'
    blocked_prefixes = (
        '/wonad-upstream-', '/wonad-phase1-x86-', '/wonad-phase1-frankel-',
        '/wonad-phase1-conformance-', '/wonad-phase1-native-', '/wonad-native-',
        '/wonad-laptop', '/wonad-phase1-client-', '/wonad-phase1-successor-',
    )
    if name.startswith(blocked_prefixes):
        return 'running Wonad build/test/VM container'
    if any(key in labels for key in (
            'org.wonad.phase1-fresh-conformance', 'org.wonad.phase1-upstream-guest',
            'org.wonad.phase1.native-matrix', 'org.wonad.phase1.vendor-attempt')):
        return 'running labelled Wonad build/test/VM container'
    return None


def running_container_lanes(environment):
    output = checked(['container', 'ls', '--filter', 'status=running', '--quiet', '--no-trunc'],
                     environment)
    try:
        identities = [line.decode('ascii') for line in output.splitlines() if line]
    except UnicodeDecodeError as error:
        raise ValueError('Non-ASCII running-container identity') from error
    active = []
    for identity in identities:
        require(re.fullmatch(r'[0-9a-f]{64}', identity) is not None,
                'Malformed running-container identity')
        result = run(['container', 'inspect', identity], environment)
        if (result.returncode == 1 and not result.stdout.strip() and
                re.search(r'No such (?:object|container):\s*' + re.escape(identity) + r'\s*$',
                          result.stderr.decode(errors='replace'))):
            continue
        require(result.returncode == 0 and not result.stderr,
                f'Cannot authenticate running container {identity}')
        rows = locality.parse_json(result.stdout, 'running container inspect')
        require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict) and
                rows[0].get('Id') == identity, 'Running-container inspect identity differs')
        lane = container_kind(rows[0])
        if lane:
            active.append({'container': identity, 'name': rows[0].get('Name'), 'lane': lane})
    return active


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
            f'Vendor preparation needs >=64 GiB source/work free space; observed {free}')
    require(source_fs.f_fsid == os.statvfs(WORK.parent).f_fsid,
            'Source and external reflink workspace are not on one filesystem')
    require(cpu_set(Path('/sys/devices/system/cpu/online').read_text()) >= {0, 1, 2, 3} and
            set(os.sched_getaffinity(0)) >= {0, 1, 2, 3}, 'CPUs 0-3 are not online/allowed')
    lanes = live_lanes()
    lanes.extend(running_container_lanes(environment))
    require(not lanes, 'Relevant build/test/VM lanes are live: ' + json.dumps(lanes))
    return {'mem_available_bytes': available, 'source_and_work_free_bytes': free,
            'cpus_online_and_allowed': [0, 1, 2, 3], 'observed_live_lanes': lanes,
            'limits_are_conservative_unmeasured': True}


def base_checks(work=None):
    require((os.getuid(), os.getgid()) == (1000, 1000), 'Run as exact UID/GID 1000:1000')
    roots = {str(path): directory(path) for path in
             (WONAD, EVIDENCE, SOURCE, SOURCE / '.repo', SOURCE / 'out')}
    require(not any((SOURCE / 'out').iterdir()), 'Dedicated source out/ is not empty')
    for relative in ('vendor/google_devices/frankel', 'external/wonad', '.wonad-updater-stage.json',
                     'keys', 'private-keys', 'private_keys', 'secrets', 'out_adevtool_deps',
                     'vendor/adevtool/node_modules', 'vendor/adevtool/lib', 'vendor/adevtool/dist',
                     'vendor/adevtool/.cache', 'vendor/adevtool/cache', 'vendor/adevtool/.yarn'):
        require(not os.path.lexists(SOURCE / relative),
                f'Preserving unexpected pre-existing source/cache content: {relative}')
    dl = SOURCE / 'vendor/adevtool/dl'
    require(sorted(item.name for item in dl.iterdir()) == ['.find-ignore'],
            'Only the tracked adevtool download marker may exist in pristine source')
    inputs = {}
    for root, references in ((WONAD, INPUT_SHA), (SOURCE, SOURCE_SHA)):
        for relative, expected in references.items():
            observed = ref(root / relative)
            require(observed['sha256'] == expected, f'Authenticated input differs: {relative}')
            inputs[str(root / relative)] = observed
    inputs[str(DRIVER)] = ref(DRIVER)
    inputs[str(HELPER)] = ref(HELPER)
    inputs[str(TEST)] = ref(TEST)
    commit = git_head(SOURCE / 'vendor/adevtool')
    require(commit == ADEVTOOL_COMMIT, 'Pinned adevtool Git commit differs')
    cache = cache_snapshot()
    environment = locality.command_environment()
    cli, socket, context, daemon = locality.trusted_local_docker(environment)
    image_rows = locality.parse_json(checked(['image', 'inspect', IMAGE], environment), 'builder inspect')
    require(isinstance(image_rows, list) and len(image_rows) == 1 and
            image_rows[0].get('Id') == IMAGE and image_rows[0].get('Os') == 'linux' and
            image_rows[0].get('Architecture') == 'amd64', 'Locked builder identity/platform differs')
    result = {'roots': roots, 'inputs': inputs, 'cache': cache, 'adevtool_commit': commit,
              'local_docker': {'cli': cli, 'socket': socket, 'context': context, 'daemon': daemon},
              'builder_id': IMAGE}
    if work is not None:
        result['work'] = work_snapshot(work)
    return result, environment


def work_snapshot(work=WORK):
    work = Path(work)
    root = directory(work)
    require(root['device'] == ARCHIVE_DEVICE and root['mode'] == 0o700,
            'Reflink workspace filesystem/mode differs')
    require(sorted(item.name for item in work.iterdir()) == [ARCHIVE_NAME],
            'Reflink workspace inventory differs before launch')
    target = work / ARCHIVE_NAME
    value = target.lstat()
    require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and
            target.resolve(strict=True) == target and value.st_dev == ARCHIVE_DEVICE and
            value.st_ino != ARCHIVE_INODE and value.st_size == ARCHIVE_BYTES and
            stat.S_IMODE(value.st_mode) == 0o444 and (value.st_uid, value.st_gid) == (1000, 1000),
            'Reflinked factory archive identity differs')
    return {'directory': root, 'archive': {'path': str(target), 'device': value.st_dev,
            'inode': value.st_ino, 'bytes': value.st_size, 'mode': stat.S_IMODE(value.st_mode),
            'uid': value.st_uid, 'gid': value.st_gid, 'nlink': value.st_nlink},
            'creation': 'FICLONE only; no copy/download fallback',
            'digest_rechecked_later_by_pinned_adevtool': ARCHIVE_SHA256}


def prepare_reflink_workspace(work=WORK, source=ARCHIVE, *, ioctl_fn=None):
    work, source = Path(work), Path(source)
    fresh(work)
    source_before_path = archive_identity(source)
    os.mkdir(work, 0o700)
    parent_fd = os.open(work.parent, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
    work_fd = None
    source_fd = None
    destination_fd = None
    try:
        os.fsync(parent_fd)
        work_fd = os.open(work, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
        source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        source_before = os.fstat(source_fd)
        require(source_before.st_dev == ARCHIVE_DEVICE and source_before.st_ino == ARCHIVE_INODE and
                source_before.st_size == ARCHIVE_BYTES and stat.S_ISREG(source_before.st_mode),
                'Factory archive changed before FICLONE')
        destination = work / ARCHIVE_NAME
        destination_fd = os.open(destination,
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                                 0o600)
        (ioctl_fn or fcntl.ioctl)(destination_fd, FICLONE, source_fd)
        os.fchmod(destination_fd, 0o444)
        os.fsync(destination_fd)
        destination_stat = os.fstat(destination_fd)
        source_after = os.fstat(source_fd)
        require(_same_stat(source_before, source_after), 'Factory archive changed during FICLONE')
        require(stat.S_ISREG(destination_stat.st_mode) and destination_stat.st_nlink == 1 and
                destination_stat.st_dev == source_before.st_dev and
                destination_stat.st_ino != source_before.st_ino and
                destination_stat.st_size == source_before.st_size and
                stat.S_IMODE(destination_stat.st_mode) == 0o444,
                'FICLONE destination identity differs')
        os.fsync(work_fd)
    finally:
        for descriptor in (destination_fd, source_fd, work_fd, parent_fd):
            if descriptor is not None:
                os.close(descriptor)
    require(source_before_path == archive_identity(source), 'Factory cache pathname changed during FICLONE')
    return work_snapshot(work)


def same_preparation_inputs(before, after):
    expected = {key: after[key] for key in before}
    require(before == expected, 'Preparation inputs changed between admission gates')
    return True


def command(action, name, nonce, work):
    require(action in {'run', 'create'} and re.fullmatch(r'[0-9a-f]{64}', nonce) is not None,
            'Invalid literal vendor command action/nonce')
    work = Path(work)
    return DOCKER + [
        action, '--name', name, '--platform', 'linux/amd64', '--network', 'bridge',
        '--attach', 'stdout', '--attach', 'stderr', '--user', '1000:1000',
        '--cap-drop', 'ALL', '--security-opt', 'label=disable',
        '--security-opt', 'no-new-privileges=true', '--read-only',
        '--memory', str(MEMORY), '--memory-swap', str(MEMORY),
        '--cpus', '4', '--cpuset-cpus', '0-3', '--pids-limit', '2048',
        '--restart', 'no', '--tmpfs', '/tmp:' + TMPFS,
        '--workdir', '/grapheneos', '--entrypoint', '/usr/bin/env',
        '--label', 'org.wonad.phase1.vendor-attempt=' + nonce,
        '--label', 'org.wonad.phase1.vendor-mode=' + ('create-only' if action == 'create' else 'prepare'),
        '--volume', str(SOURCE) + ':/grapheneos:rw',
        '--volume', str(WONAD) + ':/wonad:ro',
        '--volume', str(work) + ':/adevtool-images:rw', IMAGE, *PAYLOAD]


def expected_binds(work):
    return [str(SOURCE) + ':/grapheneos:rw', str(WONAD) + ':/wonad:ro',
            str(work) + ':/adevtool-images:rw']


def exact_binds(host, work):
    values = host.get('Binds')
    expected = expected_binds(work)
    return (isinstance(values, list) and len(values) == len(expected) and
            all(isinstance(value, str) for value in values) and
            sorted(values) == sorted(expected))


def validate_created(info, identity, nonce, work=PROOF_WORK):
    require(re.fullmatch(r'[0-9a-f]{64}', identity) is not None and info.get('Id') == identity,
            'Created container exact ID differs')
    cfg, host, state = info.get('Config', {}), info.get('HostConfig', {}), info.get('State', {})
    require(info.get('Name') == '/' + PROOF_NAME and info.get('Image') == IMAGE and
            cfg.get('Image') == IMAGE and cfg.get('Labels') == {
                'org.wonad.phase1.vendor-attempt': nonce,
                'org.wonad.phase1.vendor-mode': 'create-only'},
            'Created owner/image/nonce differs')
    require(state.get('Status') == 'created' and state.get('Running') is False and
            state.get('Paused') is False and state.get('Restarting') is False and
            state.get('Dead') is False and state.get('OOMKilled') is False and
            state.get('Pid') == 0 and state.get('ExitCode') == 0 and
            state.get('StartedAt') == '0001-01-01T00:00:00Z' and
            state.get('FinishedAt') == '0001-01-01T00:00:00Z',
            'Container was started or changed state')
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
                'SecurityOpt': ['label=disable', 'no-new-privileges=true']}
    require(all(host.get(key) == value for key, value in expected.items()) and
            exact_binds(host, work), 'Created resource/security/bind profile differs')
    for key in ('CapAdd', 'Devices', 'DeviceRequests', 'DeviceCgroupRules', 'GroupAdd',
                'PortBindings', 'VolumesFrom', 'Links', 'ExtraHosts'):
        require(host.get(key) in (None, [], {}),
                f'Unexpected created capability/device/port/mount: {key}')
    require(not cfg.get('ExposedPorts') and not cfg.get('Volumes') and
            host.get('PidMode') == '' and host.get('IpcMode') == 'private' and
            host.get('UTSMode') == '' and host.get('UsernsMode') == '',
            'Unexpected namespace/public port/anonymous volume')
    mounts = info.get('Mounts')
    require(isinstance(mounts, list) and len(mounts) == 3,
            'Unexpected number of created bind mounts')
    actual = sorted((row.get('Type'), row.get('Source'), row.get('Destination'), row.get('Mode'),
                     row.get('RW'), row.get('Propagation')) for row in mounts)
    require(actual == sorted([
        ('bind', str(SOURCE), '/grapheneos', 'rw', True, 'rprivate'),
        ('bind', str(WONAD), '/wonad', 'ro', False, 'rprivate'),
        ('bind', str(work), '/adevtool-images', 'rw', True, 'rprivate'),
    ]), 'Created bind roots differ')
    return True


def owned_never_started(info, identity, nonce, work=PROOF_WORK):
    cfg, host, state = info.get('Config', {}), info.get('HostConfig', {}), info.get('State', {})
    require(re.fullmatch(r'[0-9a-f]{64}', identity) is not None and info.get('Id') == identity and
            info.get('Name') == '/' + PROOF_NAME and info.get('Image') == IMAGE and
            cfg.get('Image') == IMAGE and cfg.get('Labels') == {
                'org.wonad.phase1.vendor-attempt': nonce,
                'org.wonad.phase1.vendor-mode': 'create-only'},
            'Owned cleanup ID/name/nonce differs')
    require(state.get('Status') == 'created' and state.get('Running') is False and
            state.get('Pid') == 0 and state.get('StartedAt') == '0001-01-01T00:00:00Z',
            'Refuse cleanup: owned container is not still never-started')
    require(exact_binds(host, work), 'Owned cleanup bind identities differ')
    mounts = info.get('Mounts')
    require(isinstance(mounts, list) and len(mounts) == 3 and validate_created(
        info, identity, nonce, work), 'Owned cleanup exact profile differs')
    return True


def write_new(path, value):
    return write_raw_new(path, canonical(value))


def write_raw_new(path, payload):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        count = stream.write(payload)
        require(count == len(payload), f'Short write: {path}')
        stream.flush()
        os.fsync(stream.fileno())
    return ref(path)


def retain_operation(stem, arguments, result):
    stdout = write_raw_new(PROOF / (stem + '.stdout'), result.stdout)
    stderr = write_raw_new(PROOF / (stem + '.stderr'), result.stderr)
    return write_new(PROOF / (stem + '.json'), {
        'argv': DOCKER + arguments, 'returncode': result.returncode,
        'stdout': stdout, 'stderr': stderr})


def create_only():
    before, environment = base_checks()
    fresh(PROOF)
    missing_container(PROOF_NAME, environment)
    first_admission = resources(environment)
    nonce = secrets.token_hex(32)
    PROOF.mkdir(mode=0o700)
    PROOF_WORK.mkdir(mode=0o700)
    argv = command('create', PROOF_NAME, nonce, PROOF_WORK)
    after, _ = base_checks()
    same_preparation_inputs(before, after)
    second_admission = resources(environment)
    missing_container(PROOF_NAME, environment)
    write_new(PROOF / 'command.json', {
        'argv': argv, 'nonce': nonce, 'never_start': True, 'observed_inputs': before,
        'first_admission': first_admission, 'second_admission': second_admission,
        'empty_external_cache': directory(PROOF_WORK),
        'scope': 'create-only profile; no archive clone, preparation, build, or runtime'})
    identity = checked(argv[len(DOCKER):], environment).decode().strip()
    require(re.fullmatch(r'[0-9a-f]{64}', identity) is not None, 'Created ID is malformed')
    write_new(PROOF / 'created-id.json', {'id': identity, 'name': PROOF_NAME, 'nonce': nonce})
    try:
        info, raw = inspect(identity, environment)
        write_raw_new(PROOF / 'inspect.json', raw)
        validate_created(info, identity, nonce, PROOF_WORK)
    finally:
        second, raw_second = inspect(identity, environment)
        write_raw_new(PROOF / 'pre-removal-inspect.json', raw_second)
        owned_never_started(second, identity, nonce, PROOF_WORK)
        removal_args = ['container', 'rm', identity]
        removal = run(removal_args, environment)
        removal_ref = retain_operation('remove-result', removal_args, removal)
        require(removal.returncode == 0 and not removal.stderr and
                removal.stdout.decode().strip() == identity,
                'Exact owned container removal output differs')
        name_absence = missing_container(PROOF_NAME, environment)
        name_absence_ref = retain_operation('name-absence',
            ['container', 'inspect', '--format', '{{.Id}}', PROOF_NAME], name_absence)
        id_absence = missing_container(identity, environment)
        id_absence_ref = retain_operation('id-absence',
            ['container', 'inspect', '--format', '{{.Id}}', identity], id_absence)
        write_new(PROOF / 'cleanup.json', {'exact_id_removed': identity,
                  'name_and_nonce_authenticated': True, 'never_started': True,
                  'remove_result': removal_ref, 'name_absence': name_absence_ref,
                  'id_absence': id_absence_ref})
    final, _ = base_checks()
    same_preparation_inputs(before, final)
    require(not any(PROOF_WORK.iterdir()), 'Create-only cache bind ceased to be empty')
    receipt = {'schema': 1, 'kind': 'phase1_frankel_vendor_cache_docker_create_only_v1',
               'container_id': identity, 'container_name': PROOF_NAME, 'nonce': nonce,
               'never_started': True, 'exact_owned_container_removed': True,
               'factory_archive_cloned_or_exposed': False,
               'not_vendor_generation_or_build': True, 'not_runtime_qualification': True,
               'command': ref(PROOF / 'command.json'), 'inspect': ref(PROOF / 'inspect.json'),
               'pre_removal_inspect': ref(PROOF / 'pre-removal-inspect.json'),
               'created_id': ref(PROOF / 'created-id.json'), 'cleanup': ref(PROOF / 'cleanup.json'),
               'input_binding': before, 'resources': {'memory_bytes': MEMORY,
               'memory_swap_bytes': MEMORY, 'cpuset_cpus': '0-3',
               'nano_cpus': 4_000_000_000, 'pids': 2048, 'tmpfs': TMPFS}}
    result = write_new(PROOF / 'receipt.json', receipt)
    print('CREATE-ONLY profile proof; exact never-started container removed; NOT vendor generation/build')
    print(str(PROOF / 'receipt.json'))
    print(result['sha256'])


def run_vendor(argv, environment):
    descriptor = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        result = subprocess.run(argv, env=environment, stdout=stream, stderr=subprocess.STDOUT)
        stream.flush()
        os.fsync(stream.fileno())
    return result


def preparation(check_only):
    before, environment = base_checks()
    for path in (LOG, PREFLIGHT, WORK):
        fresh(path)
    missing_container(NAME, environment)
    first_admission = resources(environment)
    if check_only:
        print('Read-only admission passed; no reflink/work directory/container was created')
        print(json.dumps(first_admission, sort_keys=True))
        return
    clone = prepare_reflink_workspace(WORK, ARCHIVE)
    after, _ = base_checks(WORK)
    same_preparation_inputs(before, after)
    require(after['work'] == clone, 'Reflink workspace changed before second admission')
    second_admission = resources(environment)
    missing_container(NAME, environment)
    nonce = secrets.token_hex(32)
    argv = command('run', NAME, nonce, WORK)
    write_new(PREFLIGHT, {
        'schema': 1, 'kind': 'phase1_frankel_vendor_cache_literal_preflight_v1',
        'argv': argv, 'inputs': before, 'reflink_workspace': clone,
        'first_admission': first_admission, 'second_admission': second_admission,
        'two_admissions_before_docker': True,
        'no_copy_or_download_fallback_for_factory_archive': True,
        'not_source_freeze_or_vendor_result': True, 'time_unix': int(time.time())})
    result = run_vendor(argv, environment)
    print(f'Vendor workflow exited {result.returncode}; retained {NAME}, {WORK}, {LOG}, {PREFLIGHT}')
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
        print('Vendor cache driver refused: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
