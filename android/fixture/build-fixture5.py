#!/usr/bin/env python3
"""Prepare/build only the separately reviewed, private ordinary fixture5 APK.

Plan generation is read-only except its new JSON. Build requires that exact
reviewed plan SHA, copies only inventoried files, and never uses /work/android.
No download, guest, promotion or runtime qualification exists here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile
import zlib

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
CID = '51db87997ccb6b27fb5932a88b1187a748dd1908afdc32940f542a879f6b3aae'
IMAGE = 'sha256:3932d980fa538e61d95708d0cb037c0ebb8257bc2639c46f468d5ec7c75fd597'
REMOTE = '/work/native-fixture5-root'
OUT = ROOT / 'android/out/native-banded-fixture-5'
PLAN = ROOT / 'android/out/native-fixture5-build-plan-1.json'
OLD = ROOT / 'android/out/native-banded-fixture-4'
SDK = '/opt/android-sdk/build-tools/35.0.0/'
GRADLE = '/opt/gradle-8.11.1/bin/gradle'
JDK = '/usr/lib/jvm/java-21-openjdk-amd64'
SIGNER = 'fdbf6a6940f8a1059fea942db2272abfb19e39716f544c92962a6e98103c4e88'
TOOLS = [GRADLE, '/opt/gradle-8.11.1/lib/gradle-launcher-8.11.1.jar', JDK + '/bin/java', JDK + '/release',
         SDK + 'apksigner', SDK + 'lib/apksigner.jar', SDK + 'aapt2', SDK + 'dexdump',
         '/opt/android-sdk/platforms/android-35/android.jar']
HELD = {
    'android/fixture/src/main/java/org/wonad/fixture/FixtureActivity.java': '873cabb0202995e3ae75d13e7177fee95efc108c7987c7a8fa06541e290ee562',
    'android/fixture/src/main/kotlin/org/wonad/fixture/FixtureKeyJournal.kt': '4ff2f3b3c1b572618807f93c3068e8f992c63f2ea7f7a3a2e166338f48fb457a',
    'android/fixture/src/test/kotlin/org/wonad/fixture/FixtureKeyJournalTest.kt': 'e4d21ef879d0e1d49b0ed05dda82c2503ee137d8a2c5c806b0833e739a3b99fa',
    'android/fixture/src/main/kotlin/org/wonad/fixture/BandedPaletteActivity.kt': 'cd4ba5f9355c3858f03e1faf51c368e2042bf564cc6823f9115aa623cdf730a1',
    'android/fixture/src/test/kotlin/org/wonad/fixture/BandedPaletteFixtureContractTest.kt': 'db46eee417e1fc42b34b75199118c7fd048a98433f97f4a2ccd09873ef6db5bf',
}


def require(value, message):
    if not value: raise ValueError(message)


def sha(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def ref(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'Regular pinned source required: ' + str(path))
    return dict(path=str(path), sha256=sha(path), bytes=path.stat().st_size)


def write_new(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())


def command(argv):
    return subprocess.check_output(list(map(str, argv)), text=True, stderr=subprocess.STDOUT).strip()


def docker(*argv):
    return command(['docker', 'exec', CID, *argv])


def tools_identity():
    value = json.loads(command(['docker', 'inspect', CID]))[0]
    require(value['Id'] == CID and value['Image'] == IMAGE and value['Name'] == '/wonad-android-gate-tools' and
            value['State']['Running'] is True and value['State']['OOMKilled'] is False and value['Mounts'] == [],
            'Exact existing inert tools container/image/no-mount identity required')
    return dict(container_id=CID, image=IMAGE, pid=value['State']['Pid'], started_at=value['State']['StartedAt'])


def tool_hashes():
    rows = docker('sha256sum', *TOOLS).splitlines()
    require(len(rows) == len(TOOLS) and all(line.endswith('  ' + path) for line, path in zip(rows, TOOLS)),
            'Actual tool hash inventory malformed')
    result = {path: line[:64] for path, line in zip(TOOLS, rows)}
    require(all(re.fullmatch('[0-9a-f]{64}', digest) for digest in result.values()), 'Actual tool SHA missing')
    return result


def fixture_settings(source):
    includes = re.findall(r'^include\("(:[a-z-]+)"\)$', source, re.M)
    require(includes == [':probe', ':fixture', ':ime-fixture', ':session-security', ':native-prerequisites',
                         ':native-task-reuse', ':transition-fault', ':desktop-sdk', ':broker-core', ':desktop'],
            'Original settings module inventory changed; review a new plan')
    prefix, suffix = source.split('include(":probe")', 1)
    require(suffix.strip() == '\n'.join('include("' + name + '")' for name in includes[1:]),
            'Unexpected settings statements after includes')
    return prefix + 'include(":fixture")\n'


def source_inventory():
    paths = [ROOT / 'android/build.gradle.kts', ROOT / 'android/settings.gradle.kts', ROOT / 'android/fixture/build.gradle.kts']
    for p in sorted((ROOT / 'android/fixture/src').rglob('*')):
        require(not p.is_symlink(), 'Fixture source symlink rejected')
        if p.is_file(): paths.append(p)
    records = {str(p.relative_to(ROOT)): ref(p) for p in sorted(paths)}
    require(len(records) == 23 and all(name in records and records[name]['sha256'] == digest for name, digest in HELD.items()),
            'Exact23 inputs and both held fixture changes required')
    return records


def expected_tests(sources):
    result = []
    for name in sorted(sources):
        if '/src/test/' not in name: continue
        text = (ROOT / name).read_text()
        package = re.findall(r'^package (\S+)$', text, re.M)
        classes = re.findall(r'^class (\w+)\s*\{', text, re.M)
        methods = re.findall(r'@Test\s+fun (\w+)\(', text)
        require(package == ['org.wonad.fixture'] and len(classes) == 1 and methods and len(set(methods)) == len(methods),
                'Exact ordinary nonparameterized JVM test identities required')
        result += [package[0] + '.' + classes[0] + '.' + name for name in methods]
    require(len(result) == len(set(result)) == 28, 'Actual source test inventory must be28, not a summary claim')
    return sorted(result)


def tree_records(directory):
    require(directory.is_dir() and not directory.is_symlink(), 'Preserved artifact root is not real')
    result = {}
    for path in sorted(directory.rglob('*')):
        require(not path.is_symlink(), 'Preserved fixture4 symlink rejected')
        if path.is_file(): result[str(path.relative_to(directory))] = dict(ref(path), mode=path.stat().st_mode & 0o777)
        elif path.is_dir(): result[str(path.relative_to(directory))] = dict(kind='directory', mode=path.stat().st_mode & 0o777)
        else: raise ValueError('Unexpected fixture4 nonregular evidence')
    return result


def gradle_argv():
    return [GRADLE, '--offline', '--no-daemon', '--rerun-tasks', '--max-workers=4', '-p', REMOTE,
            ':fixture:testDebugUnitTest', ':fixture:lintDebug', ':fixture:assembleDebug']


def create_plan():
    require(not OUT.exists() and not OUT.is_symlink() and not PLAN.exists(), 'NEW output/plan must be absent')
    identity = tools_identity()
    docker('test', '!', '-e', REMOTE)
    sources = source_inventory()
    settings = fixture_settings((ROOT / 'android/settings.gradle.kts').read_text())
    staged = {name.removeprefix('android/'): dict(sha256=value['sha256'], bytes=value['bytes'], host_source=name)
              for name, value in sources.items() if name != 'android/settings.gradle.kts'}
    staged['settings.gradle.kts'] = dict(sha256=hashlib.sha256(settings.encode()).hexdigest(), bytes=len(settings.encode()),
        generated_from_pinned_source='android/settings.gradle.kts', text=settings)
    manifest = ET.parse(ROOT / 'android/fixture/src/main/AndroidManifest.xml').getroot()
    attr = '{http://schemas.android.com/apk/res/android}name'
    activities = sorted('org.wonad.fixture' + p.attrib[attr] for p in manifest.findall('./application/activity'))
    launchers = sorted('org.wonad.fixture' + p.attrib[attr] for p in manifest.findall('./application/activity')
        if any(c.attrib.get(attr) == 'android.intent.category.LAUNCHER' for c in p.findall('./intent-filter/category')))
    require(len(activities) == 13 and len(launchers) == 11, 'Original13 activities/11 real launchers must stay intact')
    value = dict(scope='isolated_coherent_fixture5_compile_plan_no_runtime_qualification', qualification='NOT_RUNTIME_QUALIFIED',
        helper=ref(__file__), host_test=ref(ROOT / 'android/tests/test_fixture5_build_plan.py'), sources=sources,
        actual_tools=identity, tools_sha256=tool_hashes(), old_fixture4_complete_tree=tree_records(OLD),
        remote=REMOTE, output=str(OUT), staged_copy_hash_plan=staged,
        settings_adaptation='Exact original repository/plugin/root-name prefix, only :fixture included; original settings pinned but not compiled',
        expected_actual_jvm_cases=expected_tests(sources), expected_actual_jvm_count=28,
        gradle_argv=gradle_argv(), environment={'ANDROID_HOME': '/opt/android-sdk', 'JAVA_HOME': JDK},
        apk_remote=REMOTE + '/fixture/build/outputs/apk/debug/fixture-debug.apk', signer_sha256=SIGNER,
        exact_activities=activities, exact_launchers=launchers, lint_errors_required=0, lint_warnings_must_be_recorded=True,
        sdk=35, min_sdk=30, target_sdk=35, version_code=1, application_id='org.wonad.fixture',
        dex_preserves_all_original_classes=True, fresh_band_init_and_journal_dex_required=True,
        var_floor_bytes=8*1024**3, u_floor_bytes=512*1024**2, expected_small_private_build_budget_bytes=512*1024**2,
        no_shared_work_android_access=True, no_downloads=True, no_guest_promotion_registration=True,
        remaining_prerequisite='Parent full helper/plan review and explicit build authorization')
    write_new(PLAN, value)
    print(json.dumps(ref(PLAN)), flush=True)


def load_plan(expected):
    require(expected and sha(PLAN) == expected, 'Exact reviewed fixture5 plan SHA required')
    value = json.loads(PLAN.read_text())
    require(value['scope'] == 'isolated_coherent_fixture5_compile_plan_no_runtime_qualification' and value['helper'] == ref(__file__) and
            value['host_test'] == ref(ROOT / 'android/tests/test_fixture5_build_plan.py') and value['remote'] == REMOTE and
            value['output'] == str(OUT) and value['sources'] == source_inventory() and value['actual_tools'] == tools_identity() and
            value['tools_sha256'] == tool_hashes() and value['gradle_argv'] == gradle_argv() and
            value['expected_actual_jvm_cases'] == expected_tests(value['sources']) and tree_records(OLD) == value['old_fixture4_complete_tree'],
            'Reviewed tools/source/test/old-artifact plan changed')
    expected_staged = {name.removeprefix('android/'): dict(sha256=record['sha256'], bytes=record['bytes'], host_source=name)
        for name, record in value['sources'].items() if name != 'android/settings.gradle.kts'}
    settings = fixture_settings((ROOT / 'android/settings.gradle.kts').read_text())
    expected_staged['settings.gradle.kts'] = dict(sha256=hashlib.sha256(settings.encode()).hexdigest(), bytes=len(settings.encode()),
        generated_from_pinned_source='android/settings.gradle.kts', text=settings)
    require(value['staged_copy_hash_plan'] == expected_staged, 'Exact fixture-only staged config/source mapping changed')
    return value


def compiled_inventory(plan):
    names = sorted(plan['staged_copy_hash_plan'])
    rows = docker('sha256sum', *[REMOTE + '/' + name for name in names]).splitlines()
    require(rows == [plan['staged_copy_hash_plan'][name]['sha256'] + '  ' + REMOTE + '/' + name for name in names],
            'Actual private compiled snapshot SHA differs')
    return {name: row[:64] for name, row in zip(names, rows)}


def audit_jvm(directory, expected):
    actual = []
    paths = sorted(directory.glob('TEST-*.xml'))
    require(len(paths) == 6, 'All six actual JVM suites required')
    for path in paths:
        root = ET.parse(path).getroot()
        cases = list(root.iter('testcase'))
        require(root.get('tests') == str(len(cases)) and all(root.get(k) == '0' for k in ('failures', 'errors', 'skipped')),
                'Actual JVM suite failed/skipped/count mismatch')
        for case in cases:
            require(not any(case.find(k) is not None for k in ('failure', 'error', 'skipped')), 'Actual JVM case not passed')
            actual.append(case.attrib['classname'] + '.' + case.attrib['name'])
    require(sorted(actual) == expected and len(actual) == len(set(actual)) == 28, 'Actual JVM identities are not exact28')
    return dict(tests=28, actual_cases=sorted(actual), failures=0, errors=0, skipped=0)


def dex_classes(apk):
    """Independent original DEX class-table validation, including checksums."""
    result = set()
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), 'Duplicate APK ZIP member')
        dex = sorted(name for name in names if re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex', name))
        require(dex and not any(name.endswith('.dex') and name not in dex for name in names), 'Unexpected APK DEX member shape')
        for name in dex:
            data = archive.read(name)
            require(len(data) >= 112 and data[:4] == b'dex\n' and data[4:7] in (b'035', b'037', b'038', b'039', b'040') and data[7] == 0,
                    'Unsupported/truncated original DEX header')
            require(struct.unpack_from('<I', data, 8)[0] == zlib.adler32(data[12:]) and data[12:32] == hashlib.sha1(data[32:]).digest(),
                    'Original DEX checksum/signature differs')
            size, header, endian = struct.unpack_from('<III', data, 32)
            require(size == len(data) and header == 112 and endian == 0x12345678, 'Original DEX size/header/endian mismatch')
            strings_n, strings_o, types_n, types_o = struct.unpack_from('<IIII', data, 56)
            classes_n, classes_o = struct.unpack_from('<II', data, 96)
            require(all(n > 0 and offset >= 112 and offset + n*stride <= len(data) for n, offset, stride in
                ((strings_n, strings_o, 4), (types_n, types_o, 4), (classes_n, classes_o, 32))), 'Original DEX class/string/type tables invalid')
            for i in range(classes_n):
                type_index = struct.unpack_from('<I', data, classes_o + i*32)[0]
                require(type_index < types_n, 'Invalid DEX class index')
                string_index = struct.unpack_from('<I', data, types_o + type_index*4)[0]
                require(string_index < strings_n, 'Invalid DEX class descriptor index')
                offset = struct.unpack_from('<I', data, strings_o + string_index*4)[0]
                require(112 <= offset < len(data), 'Invalid DEX descriptor offset')
                for count in range(5):
                    require(offset < len(data), 'Truncated DEX string length')
                    byte = data[offset]; offset += 1
                    if byte < 128: break
                else: raise ValueError('Invalid DEX descriptor ULEB128')
                end = data.find(b'\x00', offset)
                require(end >= offset, 'Unterminated DEX descriptor')
                descriptor = data[offset:end].decode('ascii')
                require(re.fullmatch(r'L[^.;\s]+(?:/[^.;\s]+)*;', descriptor) and descriptor not in result,
                        'Missing/duplicate real DEX class descriptor')
                result.add(descriptor)
    return sorted(result)


def audit_apk(plan, cert, badging, dump, actual_classes, old_classes):
    require(re.findall(r'^Signer #\d+ certificate SHA-256 digest: (\w+)$', cert, re.M) == [SIGNER], 'Actual APK signer changed/multiple')
    require(re.findall(r"^package: name='([^']+)' versionCode='([^']+)'", badging, re.M) == [('org.wonad.fixture', '1')] and
            re.findall(r"^minSdkVersion:'([^']+)'$", badging, re.M) == ['30'] and
            re.findall(r"^targetSdkVersion:'([^']+)'$", badging, re.M) == ['35'] and
            re.findall(r'^application-debuggable$', badging, re.M) == ['application-debuggable'] and
            not re.search(r'^testOnly=', badging, re.M), 'Actual ordinary APK package/version/SDK/debug shape mismatch')
    require(sorted(re.findall(r"^launchable-activity: name='([^']+)'", badging, re.M)) == plan['exact_launchers'],
            'Compiled ordinary launcher inventory differs')
    require(set(old_classes).issubset(actual_classes) and all('L' + name.replace('.', '/') + ';' in actual_classes for name in plan['exact_activities']) and
            'Lorg/wonad/fixture/FixtureKeyJournal;' in actual_classes, 'Compiled DEX lost original or required new real classes')
    chunks = re.split(r'(?m)^Class #[0-9]+[^\n]*\n', dump)
    band = [chunk for chunk in chunks if re.search(r"Class descriptor\s*:\s*'Lorg/wonad/fixture/BandedPaletteActivity\$onCreate\$1;'", chunk)]
    journal = [chunk for chunk in chunks if re.search(r"Class descriptor\s*:\s*'Lorg/wonad/fixture/FixtureKeyJournal;'", chunk)]
    require(len(band) == len(journal) == 1 and 'setDefaultFocusHighlightEnabled:(Z)V' in band[0] and
            'setFocusableInTouchMode:(Z)V' in band[0] and 'observe' in journal[0] and 'snapshot' in journal[0],
            'Actual band initializer/journal DEX methods absent')
    return dict(signer_sha256=SIGNER, preserved_original_dex_classes=len(old_classes), actual_dex_classes=len(actual_classes),
                compiled_band_decoration_setter_and_focusability_present=True, compiled_journal_present=True)


def capsule():
    require(Path.cwd() == Path(REMOTE) and Path('/.dockerenv').exists(), 'Build capsule only in exact private tools project')
    task = json.loads(Path('fixture5-task.json').read_text())
    require(task['gradle_argv'] == gradle_argv() and task['environment'] == {'ANDROID_HOME': '/opt/android-sdk', 'JAVA_HOME': JDK},
            'Private capsule exact offline command/environment changed')
    before = time.time(); child = None; error = None; code = None
    try:
        env = dict(os.environ, **task['environment'])
        with Path('gradle.log').open('xb') as log:
            child = subprocess.Popen(task['gradle_argv'], env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            write_new('gradle-owned.json', dict(pid=child.pid, pgid=child.pid, argv=task['gradle_argv'], started=before))
            while child.poll() is None:
                space = os.statvfs('/')
                require(space.f_bavail * space.f_frsize >= task['var_floor_bytes'], 'Private tools filesystem floor reached')
                require(time.time() - before < 900, 'Actual fixture Gradle timeout')
                time.sleep(1)
            code = child.wait()
    except BaseException as exc:
        error = repr(exc)
        if child is not None and child.poll() is None:
            # Only the fresh start_new_session process group; never stop shared tools.
            os.killpg(child.pid, signal.SIGTERM)
            try: child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=10)
            code = child.returncode
    finally:
        write_new('gradle-terminal.json', dict(argv=task['gradle_argv'], exit_code=code, error=error,
            actual_owned_pid=child.pid if child else None, started=before, completed=time.time(), shared_tools_container_never_stopped=True))
    require(error is None and type(code) is int and code == 0, 'Actual fixture Gradle failed; preserve logs/workspace')


def build(reviewed):
    plan = load_plan(reviewed)
    require(not OUT.exists() and not OUT.is_symlink(), 'New fixture5 output must be absent; never restart/overwrite')
    docker('test', '!', '-e', REMOTE)
    for directory, floor in ((ROOT, plan['u_floor_bytes']), (Path('/var/tmp'), plan['var_floor_bytes'] + plan['expected_small_private_build_budget_bytes'])):
        s = os.statvfs(directory); require(s.f_bavail*s.f_frsize >= floor, 'Actual fixture build filesystem floor not met')
    OUT.mkdir(mode=0o700)
    receipt = dict(scope='actual_coherent_fixture5_compile_only', qualification='NOT_RUNTIME_QUALIFIED',
                   plan=ref(PLAN), helper=ref(__file__), started=time.time(), actual_tools=plan['actual_tools'])
    try:
        snapshot = OUT / 'source'
        for name, value in plan['sources'].items():
            target = snapshot / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
            require(sha(target) == value['sha256'], 'New host source snapshot differed')
        settings = OUT / 'private-settings.gradle.kts'; settings.write_text(plan['staged_copy_hash_plan']['settings.gradle.kts']['text'])
        docker('mkdir', REMOTE)
        for name, value in plan['staged_copy_hash_plan'].items():
            parent = str(Path(REMOTE + '/' + name).parent)
            docker('mkdir', '-p', parent)
            source = snapshot / value['host_source'] if 'host_source' in value else settings
            command(['docker', 'cp', source, CID + ':' + REMOTE + '/' + name])
        receipt['compiled_sources_before'] = compiled_inventory(plan)
        task = OUT / 'fixture5-task.json'
        write_new(task, {key: plan[key] for key in ('gradle_argv', 'environment', 'var_floor_bytes')})
        command(['docker', 'cp', task, CID + ':' + REMOTE + '/fixture5-task.json'])
        command(['docker', 'cp', Path(__file__), CID + ':' + REMOTE + '/fixture5-build.py'])
        execution_inputs = {'fixture5-task.json': ref(task), 'fixture5-build.py': ref(__file__)}
        actual_exec_hashes = docker('sha256sum', *[REMOTE + '/' + name for name in sorted(execution_inputs)]).splitlines()
        require(actual_exec_hashes == [execution_inputs[name]['sha256'] + '  ' + REMOTE + '/' + name for name in sorted(execution_inputs)],
                'Actual private build capsule/task copy changed')
        receipt['actual_staged_execution_inputs'] = execution_inputs
        argv = ['docker', 'exec', '--workdir', REMOTE, CID, 'python3', '-B', REMOTE + '/fixture5-build.py', 'capsule']
        with (OUT / 'capsule.stdout').open('xb') as stdout, (OUT / 'capsule.stderr').open('xb') as stderr:
            child = subprocess.Popen(argv, stdout=stdout, stderr=stderr)
            print('Actual fixture5 Docker exec client PID', child.pid, 'CID', CID, flush=True)
            result = child.wait()
        receipt['actual_exec'] = dict(argv=argv, client_pid=child.pid, exit_code=result)
        for name in ('gradle.log', 'gradle-owned.json', 'gradle-terminal.json'):
            command(['docker', 'cp', CID + ':' + REMOTE + '/' + name, OUT / name])
        require(type(result) is int and result == 0, 'Actual build exec failed; preserve partial evidence, do not retry')
        terminal = json.loads((OUT / 'gradle-terminal.json').read_text())
        require(terminal['argv'] == plan['gradle_argv'] and type(terminal['exit_code']) is int and terminal['exit_code'] == 0 and terminal['error'] is None,
                'Actual Gradle terminal record did not pass')
        require(re.search(r'^BUILD SUCCESSFUL in ', (OUT / 'gradle.log').read_text(), re.M), 'Actual Gradle success footer absent')
        receipt['compiled_sources_after'] = compiled_inventory(plan)
        require(receipt['compiled_sources_before'] == receipt['compiled_sources_after'], 'Actual compiled sources changed')
        require(docker('sha256sum', *[REMOTE + '/' + name for name in sorted(execution_inputs)]).splitlines() == actual_exec_hashes,
                'Actual private build capsule/task changed during Gradle')
        for local, remote in [('fixture.apk', 'fixture/build/outputs/apk/debug/fixture-debug.apk'),
            ('jvm-results', 'fixture/build/test-results/testDebugUnitTest'), ('lint.xml', 'fixture/build/reports/lint-results-debug.xml')]:
            command(['docker', 'cp', CID + ':' + REMOTE + '/' + remote, OUT / local])
        receipt['jvm'] = audit_jvm(OUT / 'jvm-results', plan['expected_actual_jvm_cases'])
        lint = ET.parse(OUT / 'lint.xml').getroot()
        require(not any(p.get('severity') in ('Error', 'Fatal') for p in lint), 'Actual fixture lint errors')
        receipt['lint'] = dict(errors=0, warnings=sum(p.get('severity') == 'Warning' for p in lint))
        cert = docker(SDK + 'apksigner', 'verify', '--verbose', '--print-certs', plan['apk_remote'])
        badging = docker(SDK + 'aapt2', 'dump', 'badging', plan['apk_remote'])
        manifest = docker(SDK + 'aapt2', 'dump', 'xmltree', plan['apk_remote'], '--file', 'AndroidManifest.xml')
        for name, text in [('apksigner.txt', cert), ('badging.txt', badging), ('compiled-manifest.txt', manifest)]:
            (OUT / name).write_text(text + '\n')
        with zipfile.ZipFile(OUT / 'fixture.apk') as archive:
            names = archive.namelist()
            dex_names = sorted(name for name in names if re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex', name))
            dex_dump = []
            for name in dex_names:
                target = OUT / name; target.write_bytes(archive.read(name))
                command(['docker', 'cp', target, CID + ':' + REMOTE + '/' + name])
                dex_dump.append(docker(SDK + 'dexdump', '-d', REMOTE + '/' + name))
        (OUT / 'dexdump.txt').write_text('\n'.join(dex_dump))
        actual = dex_classes(OUT / 'fixture.apk'); old = dex_classes(OLD / 'fixture.apk')
        receipt['apk_audit'] = audit_apk(plan, cert, badging, '\n'.join(dex_dump), actual, old)
        receipt['artifact'] = ref(OUT / 'fixture.apk')
        load_plan(reviewed)
        require(all(sha(snapshot / name) == value['sha256'] for name, value in plan['sources'].items()), 'Preserved host snapshot changed')
        receipt.update(status='compile_tests_artifact_verified_no_runtime_qualification', guests_started=False,
                       old_fixture4_complete_tree_unchanged=True, promotion_or_registration=False)
    except BaseException as exc:
        receipt.update(status='failed', actual_error=repr(exc), partial_failure_preserved=True)
        raise
    finally:
        receipt['completed'] = time.time()
        receipt['evidence_files'] = {str(p.relative_to(OUT)): ref(p) for p in sorted(OUT.rglob('*')) if p.is_file()}
        write_new(OUT / 'build-receipt.json', receipt)
        print(json.dumps(dict(receipt=ref(OUT / 'build-receipt.json'), status=receipt['status'])), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('plan', 'verify-plan', 'build', 'capsule'))
    parser.add_argument('--reviewed-plan-sha256')
    args = parser.parse_args()
    if args.phase == 'plan': create_plan()
    elif args.phase == 'verify-plan': load_plan(args.reviewed_plan_sha256); print('Plan/source/tools conserved; no build executed')
    elif args.phase == 'capsule': capsule()
    else: build(args.reviewed_plan_sha256)


if __name__ == '__main__': main()
