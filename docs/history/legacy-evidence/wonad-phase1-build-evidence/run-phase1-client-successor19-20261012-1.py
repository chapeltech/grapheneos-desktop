#!/usr/bin/env python3
"""Prepared successor19 capture/build driver. No default execution or guests.

Read-only capture checks do not inspect containers or claim build admission.
prepare and build are distinct explicit root-authorized future steps. The
repository producer performs fresh native/Gradle compilation, never reuse.
"""
import argparse
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path('/u/elric/tree/wonad')
EVIDENCE = ROOT.parent / 'wonad-phase1-build-evidence'
CAPTURE = EVIDENCE / 'phase1-client-successor19-capture-plan-20261012-4.json'
CAPTURE_SHA = 'c560280e75ce773f0c6a596bb1d5b59a522ee22e65c97aa659cc11eaec19306f'
OUTPUT = ROOT / 'android/out/native-current-successor-12-phase1-v3-runtime-20261012-19'
SDK_BRANCH_AUTHORIZATION = 'ROOT_REVIEWED_UNCHANGED_SDK_CONFIRMATION'
PYTHON = Path('/usr/bin/python3.14')
PYTHON_SHA = '0d64bd6d66d68dac91cdadafc46e22d4f09f22bdc997aaae870f42865b024a3e'
EXTRA_TOOLS = {
    'android/tools/docker_locality_proof.py': '09b68ceabeb83ed997608a427f8bd5e4196a229d0e3ffd5fc59a98cff85da780',
    'android/tools/phase1_provenance.py': 'b0b0708f3405e6ea6b8fdb4fdd0abf8120208259a398bea12010b944a930fb50',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON field: ' + key)
        result[key] = value
    return result


def raw_file(path, limit=32 * 1024 ** 2):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'Canonical ordinary file required')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit, 'Bounded regular file required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        current = path.lstat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(all(getattr(before, field) == getattr(after, field) == getattr(current, field)
                    for field in fields) and len(data) == before.st_size, 'File changed during observation')
        return data
    finally:
        os.close(fd)


def checked_ref(row):
    data = raw_file(Path(row['path']))
    require(len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256'],
            'Exact capture input changed: ' + row['path'])
    return data


def checked_capture():
    require(Path('/usr/bin/python3').resolve(strict=True) == PYTHON and
            hashlib.sha256(raw_file(PYTHON)).hexdigest() == PYTHON_SHA, 'Pinned host interpreter changed')
    raw = raw_file(CAPTURE)
    require(hashlib.sha256(raw).hexdigest() == CAPTURE_SHA, 'Exact reviewed capture instructions required')
    value = json.loads(raw, object_pairs_hook=unique)
    require(value['status'] == 'PREPARED_NOT_EXECUTED_NOT_BUILD_ADMITTED' and value['output'] == str(OUTPUT)
            and value['new_producer_plan_sha256'] == 'PENDING_ACTUAL_AUTHORIZED_PREPARE',
            'External instructions must not masquerade as an actual producer plan')
    for row in (*value['prior'].values(), value['client_owner_record'],
                *value['eager_compile_auditor_module_closure'].values()):
        checked_ref(row)
    for relative, digest in EXTRA_TOOLS.items():
        require(hashlib.sha256(raw_file(ROOT / relative)).hexdigest() == digest, 'Locality helper changed')
    sys.path.insert(0, str(ROOT / 'android/tools'))
    builder = importlib.import_module('build_native_successor')
    require(builder.source_records(ROOT, builder.source_names()) == value['source_files'] and
            len(value['source_files']) == 112, 'Complete current source including new helper/tests changed')
    return value, builder


def command_conflict(argv):
    if not argv:
        return False
    names = {Path(arg).name for arg in argv}
    executable = Path(argv[0]).name
    return (executable.startswith('qemu-system') or executable in
        {'qemu-kvm', 'emulator', 'ninja', 'siso', 'soong_ui', 'soong_build', 'soong_ui.bash'} or
        any(re.fullmatch(r'phase1_frankel_vendor(?:_cache)?_driver_[0-9]{8}_[1-9][0-9]{0,3}\.py', name)
            or re.fullmatch(r'prepare-phase1-frankel-vendor(?:-cache)?-[0-9]{8}-[1-9][0-9]{0,3}\.sh', name)
            for name in names) or
        bool(names & {'build_native_successor.py', 'run_native_matrix.py', 'run_frankel_build.py',
        'run_x86_emulator_build.py', 'run_release_build.py', 'run_phase1_upstream_tests.py',
        'run_phase1_runtime_qualification.py', 'phase1_conformance_guest.py',
        'run_phase1_conformance_recents_guest.py', 'phase1_frankel_vendor_driver_20261011_1.py'}) or
        any(name.startswith('continue-phase1-x86-') and name.endswith('.sh') for name in names) or
        (executable == 'java' and any('GradleDaemon' in arg or 'KotlinCompileDaemon' in arg for arg in argv)) or
        ('run-build.sh' in names and any('/vendor/adevtool/' in arg for arg in argv)))


def exclusive_heavy_lane():
    ignored = set()
    pid = os.getpid()
    while pid > 0 and pid not in ignored:
        ignored.add(pid)
        pid = int(Path('/proc', str(pid), 'stat').read_text().rpartition(') ')[2].split()[1])
    conflicts = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal() or int(entry.name) in ignored:
            continue
        try:
            with (entry / 'cmdline').open('rb') as stream:
                raw = stream.read(65537)
            require(len(raw) <= 65536, 'Oversized process command line; cannot admit heavy lane')
            argv = [arg.decode(errors='replace') for arg in raw.rstrip(b'\0').split(b'\0')] if raw else []
            if command_conflict(argv):
                conflicts.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
    require(not conflicts, 'Preserve existing vendor/OS/native/guest/client lane: ' + str(conflicts))


def sdk_continuity(value, actual_files):
    previous_root = Path(value['sdk']['prior_repository'])
    expected_names = set(value['sdk']['immutable_files']) | set(value['sdk']['timestamp_family'])
    require(set(actual_files) == expected_names and len(actual_files) == 30, 'SDK publication inventory changed')
    for name, row in value['sdk']['immutable_files'].items():
        before = raw_file(previous_root / name)
        require(hashlib.sha256(before).hexdigest() == row['sha256'] and len(before) == row['bytes'] and
                actual_files[name] == before, 'Immutable Maven 3.0.0 member changed: ' + name)
    name = 'org/wonad/desktop-sdk/maven-metadata.xml'
    raw = actual_files[name]
    require(len(re.findall(b'<lastUpdated>[0-9]{14}</lastUpdated>', raw)) == 1, 'Ambiguous Maven timestamp')
    normalized = re.sub(b'<lastUpdated>[0-9]{14}</lastUpdated>', b'<lastUpdated>TIMESTAMP</lastUpdated>', raw)
    require(hashlib.sha256(normalized).hexdigest() == value['sdk']['normalized_metadata_sha256'],
            'Maven metadata differs beyond its sole publication timestamp')
    for algorithm in ('md5', 'sha1', 'sha256', 'sha512'):
        require(actual_files[name + '.' + algorithm] == hashlib.new(algorithm, raw).hexdigest().encode(),
                'Maven timestamp checksum sidecar differs')


def prepared_plan(value, digest):
    require(re.fullmatch('[0-9a-f]{64}', digest or ''), 'Actual reviewed producer plan SHA remains unresolved')
    path = OUTPUT / 'plan.json'
    raw = raw_file(path)
    require(hashlib.sha256(raw).hexdigest() == digest, 'Actual producer plan digest changed')
    actual = json.loads(raw, object_pairs_hook=unique)
    previous = json.loads(checked_ref(value['prior']['plan.json']), object_pairs_hook=unique)
    require(actual['sources'] == value['source_files'] and actual['output'] == str(OUTPUT) and
            actual['version_code'] == 12 and actual['version_name'] == value['version_name'], 'New exact source/identity changed')
    for field in ('helper', 'auditor', 'gate', 'sdk_tools', 'cross_tools', 'cross_image', 'signer_sha256'):
        require(actual[field] == previous[field], 'Prepared dependency/tool/signer drift: ' + field)
    freeze = json.loads(raw_file(OUTPUT / 'source-freeze.json'), object_pairs_hook=unique)
    require(freeze['files'] == value['source_files'] and freeze['source_path'] == str(OUTPUT / 'source'),
            'Actual fresh 112-file source freeze differs')
    return actual


def post_build(value):
    auditor = importlib.import_module('native_current_compile_acceptance')
    receipt = json.loads(raw_file(OUTPUT / 'build-receipt.json'), object_pairs_hook=unique)
    require(auditor.audit(receipt, lambda name: raw_file(OUTPUT / name)) ==
            {name: row['sha256'] for name, row in value['source_files'].items()}, 'Independent new compile audit differs')
    publication = receipt['sdk_publication']['files']
    sdk_continuity(value, {name: raw_file(OUTPUT / 'sdk-repository' / name) for name in publication})
    suite = ET.fromstring(raw_file(OUTPUT / value['required_new_junit_suite']))
    expected = set(re.findall(r'@Test fun ([A-Za-z0-9_]+)\(',
        raw_file(ROOT / 'android/conformance/src/test/kotlin/org/wonad/desktop/ConformancePickerProgressTest.kt').decode()))
    require(suite.tag == 'testsuite' and all(suite.get(name) == '0' for name in ('failures', 'errors', 'skipped'))
            and suite.get('tests') == '5' and len(suite.findall('testcase')) == 5 and len(expected) == 5
            and {case.get('name') for case in suite.findall('testcase')} == expected
            and all(case.get('classname') == 'org.wonad.desktop.ConformancePickerProgressTest'
                    and not list(case) for case in suite.findall('testcase')),
            'Five exact new Kotlin JUnit cases must really pass without skips')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--check-capture-read-only', action='store_true')
    modes.add_argument('--prepare-after-root-authorization', action='store_true')
    modes.add_argument('--build-after-root-authorization', action='store_true')
    parser.add_argument('--expected-plan-sha256')
    args = parser.parse_args(argv)
    value, builder = checked_capture()
    if args.check_capture_read_only:
        require(args.expected_plan_sha256 is None, 'No producer digest is invented during preparation')
        require(not os.path.lexists(OUTPUT), 'Fresh successor19 output already exists')
        print('PREPARED INPUTS VERIFIED: 112 current files; producer prepare/build still require separate GO')
        return 0
    require(SDK_BRANCH_AUTHORIZATION == 'ROOT_REVIEWED_UNCHANGED_SDK_CONFIRMATION' and
            value['root_sdk_branch_choice'] == SDK_BRANCH_AUTHORIZATION,
            'SDK branch choice remains PENDING; no prepare/build is authorized by this proposal')
    if args.build_after_root_authorization:
        prepared_plan(value, args.expected_plan_sha256)
        require(not os.path.lexists(OUTPUT / 'build-receipt.json'), 'Never overwrite completed build')
        command = value['commands']['build_prefix'] + [args.expected_plan_sha256]
        label = 'build'
    else:
        require(args.expected_plan_sha256 is None and not os.path.lexists(OUTPUT), 'Fresh first preparation required')
        command = value['commands']['prepare']
        label = 'prepare'
    exclusive_heavy_lane()
    builder.resources(build=args.build_after_root_authorization)
    locality = importlib.import_module('docker_locality_proof')
    locality.trusted_local_docker(locality.command_environment(dict(os.environ)))
    # Fresh per-generation operational lock; no predecessor locks/output touched.
    lock_path = EVIDENCE / 'phase1-client-successor19-20261012-1.lock'
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'rb') as lock:
        node = os.fstat(lock.fileno())
        require(stat.S_ISREG(node.st_mode) and node.st_uid == os.getuid() and
                stat.S_IMODE(node.st_mode) == 0o600 and node.st_nlink == 1,
                'Only the owned regular successor19 lock is admissible')
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        log = EVIDENCE / ('phase1-client-successor19-' + label + '-20261012-1.log')
        with log.open('xb') as stream:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT,
                env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, timeout=3600)
        require(result.returncode == 0, 'Original producer failed; preserve log/output, no retry')
    if args.build_after_root_authorization:
        post_build(value)
        print('NEW COMPILE/AUDIT/SDK CONTINUITY PASSED; NOT RUNTIME QUALIFIED')
    else:
        digest = hashlib.sha256(raw_file(OUTPUT / 'plan.json')).hexdigest()
        prepared_plan(value, digest)
        print('ACTUAL PREPARED PLAN ' + digest + '; separate root review/build GO required')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
