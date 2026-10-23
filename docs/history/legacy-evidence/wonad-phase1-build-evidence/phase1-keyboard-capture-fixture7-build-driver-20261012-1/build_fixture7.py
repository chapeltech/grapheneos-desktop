#!/usr/bin/env python3
"""Prepare/build only the separately reviewed, private ordinary fixture7 APK.

Plan proposal is read-only and prints JSON only. Build requires that exact
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
import stat
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile
import zlib

sys.dont_write_bytecode = True
ROOT = Path('/u/elric/tree/wonad')
HERE = Path(__file__).resolve().parent
HOST_TEST = HERE / 'test_build_fixture7.py'
DOCKER = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock']
CID = '51db87997ccb6b27fb5932a88b1187a748dd1908afdc32940f542a879f6b3aae'
IMAGE = 'sha256:3932d980fa538e61d95708d0cb037c0ebb8257bc2639c46f468d5ec7c75fd597'
REMOTE = '/work/native-keyboard-capture-fixture7-root'
OUT = ROOT / 'android/out/native-keyboard-capture-fixture-7'
PLAN = HERE / 'plan.json'
OLD = ROOT / 'android/out/native-banded-fixture-5'
SDK = '/opt/android-sdk/build-tools/35.0.0/'
GRADLE = '/opt/gradle-8.11.1/bin/gradle'
JDK = '/usr/lib/jvm/java-21-openjdk-amd64'
SIGNER = 'fdbf6a6940f8a1059fea942db2272abfb19e39716f544c92962a6e98103c4e88'
TOOLS = [GRADLE, '/opt/gradle-8.11.1/lib/gradle-launcher-8.11.1.jar', JDK + '/bin/java', JDK + '/release',
         SDK + 'apksigner', SDK + 'lib/apksigner.jar', SDK + 'aapt2', SDK + 'dexdump',
         '/opt/android-sdk/platforms/android-35/android.jar',
         '/root/.gradle/caches/modules-2/files-2.1/junit/junit/4.13.2/8ac9e16d933b6fb43bc7f576336b8f4d7eb5ba12/junit-4.13.2.jar',
         '/root/.gradle/caches/modules-2/files-2.1/org.hamcrest/hamcrest-core/1.3/42a25dc3219429f0e5d060061f71acb49bf010a0/hamcrest-core-1.3.jar', '/usr/bin/python3']
HELD = {
    'android/fixture/src/main/java/org/wonad/fixture/FixtureActivity.java': '873cabb0202995e3ae75d13e7177fee95efc108c7987c7a8fa06541e290ee562',
    'android/fixture/src/main/kotlin/org/wonad/fixture/FixtureKeyJournal.kt': '4ff2f3b3c1b572618807f93c3068e8f992c63f2ea7f7a3a2e166338f48fb457a',
    'android/fixture/src/test/kotlin/org/wonad/fixture/FixtureKeyJournalTest.kt': 'e4d21ef879d0e1d49b0ed05dda82c2503ee137d8a2c5c806b0833e739a3b99fa',
    'android/fixture/src/main/kotlin/org/wonad/fixture/BandedPaletteActivity.kt': 'cd4ba5f9355c3858f03e1faf51c368e2042bf564cc6823f9115aa623cdf730a1',
    'android/fixture/src/test/kotlin/org/wonad/fixture/BandedPaletteFixtureContractTest.kt': 'db46eee417e1fc42b34b75199118c7fd048a98433f97f4a2ccd09873ef6db5bf',
}

SOURCE_PINS = json.loads(r'''{
    "android/build.gradle.kts": "33303e785b76d23da1a13b4be61842f52731ccf39ae6e89eeab89539b3916623",
    "android/fixture/build.gradle.kts": "58a8cabe52ccc0a29f8e194be76ef645ff47d49f663bf0411a3d5b93759d950e",
    "android/fixture/src/main/AndroidManifest.xml": "06aaa2c31d3a86bbca8b0b9fd893a23bd8e1ebb90f982ac7a1a089df110d0c4d",
    "android/fixture/src/main/java/org/wonad/fixture/FixedActivity.java": "04ee31908898fda54ec03a8624aaacbe37678a7c842e80eeb8219cdf41f84e28",
    "android/fixture/src/main/java/org/wonad/fixture/FixtureActivity.java": "873cabb0202995e3ae75d13e7177fee95efc108c7987c7a8fa06541e290ee562",
    "android/fixture/src/main/java/org/wonad/fixture/LaunchActivity.kt": "33c77933c78dbeee2e412b0c2307e8c764f41c5570c710e51d11a902c41c94fb",
    "android/fixture/src/main/java/org/wonad/fixture/OneActivity.java": "e43a6bb1fc7cc8e3506b1eda3354ae72b72ce241e3ec0268572be21ab88b8a36",
    "android/fixture/src/main/java/org/wonad/fixture/TwoActivity.java": "447e7dc4a1a48dcb14a076e858679417ca83bf9c9c71fa8e32f730750bbde71c",
    "android/fixture/src/main/kotlin/org/wonad/fixture/BandedPaletteActivity.kt": "cd4ba5f9355c3858f03e1faf51c368e2042bf564cc6823f9115aa623cdf730a1",
    "android/fixture/src/main/kotlin/org/wonad/fixture/CompositionEditText.kt": "ffc942f359b7c1b4b4738ef1b708c38200465beb0644b64dca09dc0d3a75c0d9",
    "android/fixture/src/main/kotlin/org/wonad/fixture/FixtureKeyJournal.kt": "4ff2f3b3c1b572618807f93c3068e8f992c63f2ea7f7a3a2e166338f48fb457a",
    "android/fixture/src/main/kotlin/org/wonad/fixture/KeyboardCaptureActivity.kt": "06008e051a58a0855b927327ecdc838fb8709a8d253882513ac02b1e5e95702b",
    "android/fixture/src/main/kotlin/org/wonad/fixture/KeyboardCaptureCounters.kt": "220ce93d74624b4b4cf9fcb86657bee2b9e94a1d176c7be36b3ab7ad00c29000",
    "android/fixture/src/main/kotlin/org/wonad/fixture/PaletteActivity.kt": "fed6cbd92be929b7877a5e920c96a70d536fb49cfd0ca33d37d02dea40e7e20f",
    "android/fixture/src/main/kotlin/org/wonad/fixture/PaletteProbeLedger.kt": "c0cddc11a4c54999ce4a81f2abea772da61e7900aee6b969ea18e72971db4b72",
    "android/fixture/src/main/kotlin/org/wonad/fixture/PermissionActivity.kt": "10d563313cb9ad9862f1361b6fde944807f460dcfc7bcb6dbea4a91fab9e5c4f",
    "android/fixture/src/main/kotlin/org/wonad/fixture/PermissionRequestLedger.kt": "bc0645a77adb9f0b47fbf08fe64e6183ccf9c04c3f84c65b7c325223561a291e",
    "android/fixture/src/main/kotlin/org/wonad/fixture/PublicKeyboardCaptureRequest.kt": "d991a4fb254cd992d93d052faeebdda84db7e5f1919ba9b69297a66c398966be",
    "android/fixture/src/main/kotlin/org/wonad/fixture/ResetActivity.kt": "68f19e4ac8daa3b4815aa095c4e4177bb064f25f47ba6d06c4ab37e86d589f3c",
    "android/fixture/src/test/kotlin/org/wonad/fixture/BandedPaletteFixtureContractTest.kt": "db46eee417e1fc42b34b75199118c7fd048a98433f97f4a2ccd09873ef6db5bf",
    "android/fixture/src/test/kotlin/org/wonad/fixture/FixtureKeyJournalTest.kt": "e4d21ef879d0e1d49b0ed05dda82c2503ee137d8a2c5c806b0833e739a3b99fa",
    "android/fixture/src/test/kotlin/org/wonad/fixture/KeyboardCaptureCountersTest.kt": "c805a243bb9131c3370e41d67c918d21c78358dcb5e8cdd37ff3f5c958916dca",
    "android/fixture/src/test/kotlin/org/wonad/fixture/PaletteFixtureContractTest.kt": "911bb49c776767394b96cf89295d2a0dca3b84009f738d20380e09e9809550ca",
    "android/fixture/src/test/kotlin/org/wonad/fixture/PaletteProbeLedgerTest.kt": "3a7500f6c71d5e24b2b48b5feeb6020ce4a84bda16a352f2c74d14b22fffe596",
    "android/fixture/src/test/kotlin/org/wonad/fixture/PermissionFixtureContractTest.kt": "674d02103f642693805a5fbd7f5141756b012dacc5c95a8f93a52b11bba6fa33",
    "android/fixture/src/test/kotlin/org/wonad/fixture/PermissionRequestLedgerTest.kt": "bc536cd98d389a7d24f3609a928e3f6afb936969d659ebce443c1b5690b26126",
    "android/fixture/src/test/kotlin/org/wonad/fixture/PublicKeyboardCaptureRequestTest.kt": "0639417b6c001f5fabdde8907408142eefb0d1c9e50e15a09c6b2007b25d56db",
    "android/settings.gradle.kts": "69301de73f1b81924b40b03b439858361e67064db2457dc944172fd1d2f3babe"
}''')
SETTINGS_SHA = SOURCE_PINS['android/settings.gradle.kts']
GRADLE_PROPERTIES = '''org.gradle.jvmargs=-Xmx512m -Xms64m -XX:MaxMetaspaceSize=256m -XX:ActiveProcessorCount=1 -Dfile.encoding=UTF-8 -Duser.home=/root
org.gradle.workers.max=1
org.gradle.daemon=false
kotlin.compiler.execution.strategy=in-process
kotlin.incremental=false
'''
TEST_INIT = '''gradle.beforeProject { project ->
    project.tasks.withType(org.gradle.api.tasks.testing.Test).configureEach {
        maxHeapSize = "128m"
        maxParallelForks = 1
        jvmArgs("-XX:ActiveProcessorCount=1")
    }
}
'''


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
    return subprocess.check_output(list(map(str, argv)), text=True, stderr=subprocess.STDOUT,
        env={'PATH':'/usr/bin:/bin', 'LANG':'C.UTF-8', 'LC_ALL':'C.UTF-8'}, timeout=60).strip()


def docker(*argv):
    return command([*DOCKER, 'exec', CID, *argv])


def tools_identity():
    value = json.loads(command([*DOCKER, 'inspect', CID]))[0]
    require(value['Id'] == CID and value['Image'] == IMAGE and value['Name'] == '/wonad-android-gate-tools' and
            value['State']['Running'] is True and value['State']['OOMKilled'] is False and value['Mounts'] == [] and
            value['Path'] == 'sleep' and value['Args'] == ['infinity'] and
            value['HostConfig']['Privileged'] is False and value['HostConfig']['Memory'] == 0 and
            value['HostConfig']['NanoCpus'] == 0 and value['Config']['User'] == '',
            'Exact existing inert tools container/image/no-mount identity required')
    return dict(container_id=CID, image=IMAGE, pid=value['State']['Pid'], started_at=value['State']['StartedAt'],
        name=value['Name'], path=value['Path'], args=value['Args'], mounts=[],
        existing_profile=dict(memory=0, nano_cpus=0, user='', privileged=False,
            whole_memory_unbounded=True, this_driver_never_changes_profile=True))


def tool_hashes():
    rows = docker('sha256sum', *TOOLS).splitlines()
    require(len(rows) == len(TOOLS) and all(line.endswith('  ' + path) for line, path in zip(rows, TOOLS)),
            'Actual tool hash inventory malformed')
    result = {path: line[:64] for path, line in zip(TOOLS, rows)}
    require(all(re.fullmatch('[0-9a-f]{64}', digest) for digest in result.values()), 'Actual tool SHA missing')
    return result


def fixture_settings(source):
    require(hashlib.sha256(source.encode()).hexdigest() == SETTINGS_SHA,
            'Exact current full settings SHA required; arbitrary grammar rejected')
    prefix, suffix = source.split('include(":probe")', 1)
    modules = [':probe', ':fixture', ':ime-fixture', ':session-security', ':native-prerequisites',
               ':native-task-reuse', ':transition-fault', ':desktop-sdk', ':conformance',
               ':broker-core', ':desktop']
    includes = re.findall(r'^include\("(:[a-z-]+)"\)$', source, re.M)
    require(includes == modules and suffix.count('if (') == 1 and
            re.findall(r'^\s+include\("(:styx-[a-z-]+)"\)$', suffix, re.M) ==
            [':styx-probe', ':styx-desktop', ':styx-auth'],
            'Current exact base/opt-in settings module grammar changed')
    return prefix + 'include(":fixture")\n'

def source_inventory():
    paths = [ROOT / 'android/build.gradle.kts', ROOT / 'android/settings.gradle.kts', ROOT / 'android/fixture/build.gradle.kts']
    for p in sorted((ROOT / 'android/fixture/src').rglob('*')):
        require(not p.is_symlink(), 'Fixture source symlink rejected')
        if p.is_file(): paths.append(p)
    records = {str(p.relative_to(ROOT)): ref(p) for p in sorted(paths)}
    require(len(records) == 28 and {name:record['sha256'] for name,record in records.items()} == SOURCE_PINS and
            all(name in records and records[name]['sha256'] == digest for name, digest in HELD.items()),
            'Exact current28 repository inputs and held original fixture fixes required')
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
    require(len(result) == len(set(result)) == 41, 'Actual source-declared test inventory must be41 in8 classes, not an executed summary claim')
    require(len({row.rsplit('.',1)[0] for row in result}) == 8, 'Exactly8 source test suites required')
    return sorted(result)


def tree_records(directory):
    require(directory.is_dir() and not directory.is_symlink(), 'Preserved artifact root is not real')
    result = {}
    for path in sorted(directory.rglob('*')):
        require(not path.is_symlink(), 'Preserved fixture5 symlink rejected')
        if path.is_file(): result[str(path.relative_to(directory))] = dict(ref(path), mode=path.stat().st_mode & 0o777)
        elif path.is_dir(): result[str(path.relative_to(directory))] = dict(kind='directory', mode=path.stat().st_mode & 0o777)
        else: raise ValueError('Unexpected fixture5 nonregular evidence')
    return result


def gradle_argv():
    return [GRADLE, '--offline', '--no-daemon', '--rerun-tasks', '--max-workers=1',
            '--init-script', REMOTE + '/fixture7-test-memory.init.gradle', '-p', REMOTE,
            ':fixture:testDebugUnitTest', ':fixture:lintDebug', ':fixture:assembleDebug']


def build_environment():
    return {'ANDROID_HOME':'/opt/android-sdk', 'JAVA_HOME':JDK,
            'ANDROID_USER_HOME':'/root/.android', 'GRADLE_USER_HOME':'/root/.gradle',
            'JAVA_OPTS':'-Xmx128m -Xms32m -XX:ActiveProcessorCount=1',
            'JAVA_TOOL_OPTIONS':'-XX:ActiveProcessorCount=1'}


def generated_inputs():
    return {'settings.gradle.kts':fixture_settings((ROOT/'android/settings.gradle.kts').read_text()),
            'gradle.properties':GRADLE_PROPERTIES,
            'fixture7-test-memory.init.gradle':TEST_INIT}


def staged_plan(sources):
    result = {name.removeprefix('android/'):dict(sha256=value['sha256'],bytes=value['bytes'],host_source=name)
              for name,value in sources.items() if name!='android/settings.gradle.kts'}
    for name,text in generated_inputs().items():
        result[name]=dict(sha256=hashlib.sha256(text.encode()).hexdigest(),
                         bytes=len(text.encode()),generated_text=text,
                         generated_from_current_pinned_settings=name=='settings.gradle.kts')
    return result


def keystore_metadata():
    # Metadata only; never hash/read/export private key bytes. Existing default
    # debug key must preexist; missing key refuses before Gradle can generate one.
    text = docker('/usr/bin/python3','-B','-c',
        'import pathlib,json,stat; p=pathlib.Path("/root/.android/debug.keystore"); '
        's=p.lstat(); assert stat.S_ISREG(s.st_mode) and not p.is_symlink(); '
        'assert s.st_size>0 and s.st_uid==0 and s.st_gid==0; '
        'print(json.dumps({k:getattr(s,k) for k in '
        '("st_dev","st_ino","st_mode","st_uid","st_gid","st_size","st_mtime_ns","st_ctime_ns")}))')
    return json.loads(text)


def public_predecessor_signer():
    remote='/work/native-fixture5-root/fixture/build/outputs/apk/debug/fixture-debug.apk'
    row=docker('sha256sum',remote)
    require(row == sha(OLD/'fixture.apk')+'  '+remote,
            'Public preserved predecessor APK differs inside tools container')
    text=docker(SDK+'apksigner','verify','--verbose','--print-certs',remote)
    require(re.findall(r'^Signer #\d+ certificate SHA-256 digest: (\w+)$',text,re.M)==[SIGNER],
            'Actual public predecessor ordinary signer changed')
    return dict(apk=ref(OLD/'fixture.apk'),remote=remote,verification_stdout=text,
                signer_sha256=SIGNER,private_keystore_bytes_not_read=True)


def host_resources():
    text=Path('/proc/meminfo').read_text()
    values={}
    for name in ('MemTotal','MemAvailable'):
        rows=re.findall(r'^'+name+r':\s+([0-9]+)\s+kB$',text,re.M)
        require(len(rows)==1,'Unique host memory observation required')
        values[name]=int(rows[0])*1024
    return dict(memory=values,free_bytes={str(p):os.statvfs(p).f_bavail*os.statvfs(p).f_frsize
                                         for p in (ROOT,Path('/var/tmp'))},
                planning_fixture_budget_bytes=3*1024**3,host_reserve_bytes=8*1024**3,
                vendor_cap_bytes=48*1024**3,
                existing_tools_cgroup_has_no_hard_memory_cap=True,
                concurrency_adequacy_proven=False,build_admission_deferred_while_vendor_live=True)


def require_no_vendor():
    # Only future BUILD admission uses this bounded read-only process census;
    # proposing a plan while the root-owned vendor is live remains permitted.
    matches=[]
    for row in sorted(Path('/proc').iterdir()):
        if not row.name.isdecimal() or int(row.name)==os.getpid():continue
        try:
            with (row/'cmdline').open('rb') as stream:payload=stream.read(65537)
        except (FileNotFoundError,ProcessLookupError):continue
        require(len(payload)<=65536,'Oversize process argv refuses fixture build')
        if not payload:continue
        require(payload.endswith(b'\0'),'Malformed process argv refuses fixture build')
        argv=[arg.decode('utf-8',errors='strict') for arg in payload[:-1].split(b'\0')]
        names=[Path(arg).name for arg in argv]
        if any(name in ('run_frankel_vendor.py', 'generate-frankel-vendor.sh') or
               re.fullmatch(r'phase1_frankel_vendor(?:_cache)?_driver_[0-9_]+\.py',name) or
               re.fullmatch(r'prepare-phase1-frankel-vendor(?:-cache)?-[0-9-]+\.sh',name)
               for name in names):
            matches.append(dict(pid=int(row.name),argv=argv))
    require(not matches,'Vendor lane present; fixture compile is deliberately deferred')
    top=command([*DOCKER,'top',CID,'-eo','pid,ppid,args']).splitlines()
    require(len(top)==2 and re.fullmatch(r'\s*[0-9]+\s+[0-9]+\s+sleep infinity\s*',top[1]),
            'Tools container has other live work; refuse fixture build')

def create_plan():
    require(not OUT.exists() and not OUT.is_symlink() and not PLAN.exists(), 'NEW output/plan must be absent')
    identity = tools_identity()
    docker('test', '!', '-e', REMOTE)
    sources = source_inventory()
    settings = fixture_settings((ROOT / 'android/settings.gradle.kts').read_text())
    staged = staged_plan(sources)
    manifest = ET.parse(ROOT / 'android/fixture/src/main/AndroidManifest.xml').getroot()
    attr = '{http://schemas.android.com/apk/res/android}name'
    activities = sorted('org.wonad.fixture' + p.attrib[attr] for p in manifest.findall('./application/activity'))
    launchers = sorted('org.wonad.fixture' + p.attrib[attr] for p in manifest.findall('./application/activity')
        if any(c.attrib.get(attr) == 'android.intent.category.LAUNCHER' for c in p.findall('./intent-filter/category')))
    require(len(activities) == 16 and len(launchers) == 14, 'Exact16 activities/14 real launchers including capture tasks required')
    value = dict(scope='isolated_coherent_fixture7_compile_plan_no_runtime_qualification', qualification='NOT_RUNTIME_QUALIFIED',
        helper=ref(__file__), host_test=ref(HOST_TEST), sources=sources,
        actual_tools=identity, tools_sha256=tool_hashes(), old_fixture5_complete_tree=tree_records(OLD),
        remote=REMOTE, output=str(OUT), staged_copy_hash_plan=staged,
        settings_adaptation='Exact original repository/plugin/root-name prefix, only :fixture included; original settings pinned but not compiled',
        expected_actual_jvm_cases=expected_tests(sources), expected_actual_jvm_count=41, expected_actual_jvm_suites=8,
        gradle_argv=gradle_argv(), environment=build_environment(), existing_keystore_metadata=keystore_metadata(),
        public_predecessor_signer=public_predecessor_signer(), host_resource_observation=host_resources(),
        capture_escape_semantics='claimed external Escape delivered to ordinary app; no Android delayed task-close/Toast/QUIT; phone/unclaimed stock unchanged',
        apk_remote=REMOTE + '/fixture/build/outputs/apk/debug/fixture-debug.apk', signer_sha256=SIGNER,
        exact_activities=activities, exact_launchers=launchers, lint_errors_required=0, lint_warnings_must_be_recorded=True,
        sdk=35, min_sdk=30, target_sdk=35, version_code=1, application_id='org.wonad.fixture',
        compile_adequacy_measured=False, vendor_overlap_authorized=False,
        gradle_worker_count=1, gradle_jvm_heap_mib=512, gradle_launcher_heap_mib=128,
        test_jvm_heap_mib=128, kotlin_compiler_in_process=True,
        existing_tools_cgroup_memory_cap=None, heap_is_not_whole_descendant_rss_cap=True,
        dex_preserves_all_original_classes=True, fresh_band_init_and_journal_dex_required=True,
        var_floor_bytes=8*1024**3, u_floor_bytes=512*1024**2, expected_small_private_build_budget_bytes=512*1024**2,
        no_shared_work_android_access=True, no_downloads=True, no_guest_promotion_registration=True,
        remaining_prerequisite='Parent full helper/plan review and explicit build authorization')
    print(json.dumps(value, indent=2, sort_keys=True), flush=True)


def load_plan(expected):
    require(expected and re.fullmatch('[0-9a-f]{64}',expected) and sha(PLAN) == expected, 'Exact reviewed fixture7 plan SHA required')
    value = json.loads(PLAN.read_text())
    require(value['scope'] == 'isolated_coherent_fixture7_compile_plan_no_runtime_qualification' and value['helper'] == ref(__file__) and
            value['host_test'] == ref(HOST_TEST) and value['remote'] == REMOTE and
            value['output'] == str(OUT) and value['sources'] == source_inventory() and value['actual_tools'] == tools_identity() and
            value['tools_sha256'] == tool_hashes() and value['gradle_argv'] == gradle_argv() and
            value['expected_actual_jvm_cases'] == expected_tests(value['sources']) and
            value['environment'] == build_environment() and
            value['existing_keystore_metadata'] == keystore_metadata() and
            value['public_predecessor_signer'] == public_predecessor_signer() and
            value['expected_actual_jvm_count'] == 41 and value['expected_actual_jvm_suites'] == 8 and
            tree_records(OLD) == value['old_fixture5_complete_tree'],
            'Reviewed tools/source/test/old-artifact plan changed')
    expected_staged = staged_plan(value['sources'])
    require(value['staged_copy_hash_plan'] == expected_staged, 'Exact fixture-only config/source mapping changed')

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
    require(len(paths) == 8, 'All8 actual JVM suites required')
    for path in paths:
        root = ET.parse(path).getroot()
        cases = list(root.iter('testcase'))
        require(root.get('tests') == str(len(cases)) and all(root.get(k) == '0' for k in ('failures', 'errors', 'skipped')),
                'Actual JVM suite failed/skipped/count mismatch')
        for case in cases:
            require(not any(case.find(k) is not None for k in ('failure', 'error', 'skipped')), 'Actual JVM case not passed')
            actual.append(case.attrib['classname'] + '.' + case.attrib['name'])
    require(sorted(actual) == expected and len(actual) == len(set(actual)) == 41, 'Actual JVM identities are not exact41')
    return dict(tests=41, actual_cases=sorted(actual), failures=0, errors=0, skipped=0)


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




def keystore_metadata_local():
    p=Path('/root/.android/debug.keystore')
    s=p.lstat()
    require(stat.S_ISREG(s.st_mode) and not p.is_symlink() and s.st_uid==s.st_gid==0 and s.st_size>0,
            'Existing ordinary debug key metadata required; no key generation permitted')
    return {k:getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')}


def parse_compiled_xml(text):
    """Exact plain aapt2 xmltree node/attribute stream; no matching-only ambiguity."""
    roots=[];stack=[]
    for line in text.splitlines():
        if not line.strip():continue
        if re.fullmatch(r'N: android=http://schemas.android.com/apk/res/android \(line=[0-9]+\)',line):continue
        element=re.fullmatch(r'( *)E: ([A-Za-z][A-Za-z0-9_-]*) \(line=[0-9]+\)',line)
        attribute=re.fullmatch(r'( *)A: (.+?)=(.+)',line)
        if element:
            indent=len(element[1]);node={'tag':element[2],'attrs':{},'children':[]}
            while stack and stack[-1][0]>=indent:stack.pop()
            if stack:stack[-1][1]['children'].append(node)
            else:roots.append(node)
            stack.append((indent,node))
        elif attribute:
            require(stack and len(attribute[1])>stack[-1][0],'Orphan compiled attribute')
            key=re.sub(r'\(0x[0-9a-f]+\)$','',attribute[2])
            key=key.removeprefix('http://schemas.android.com/apk/res/android:')
            require(key not in stack[-1][1]['attrs'],'Duplicate compiled attribute')
            value=attribute[3]
            string=re.fullmatch(r'"([^"]*)" \(Raw: "([^"]*)"\)',value)
            if string:
                require(string[1]==string[2],'Compiled/raw attribute ambiguity')
                value=string[1]
            else:require(re.fullmatch(r'(?:true|false|[0-9]+|0x[0-9a-f]+|@0x[0-9a-f]+)',value),
                         'Unknown compiled attribute value')
            stack[-1][1]['attrs'][key]=value
        else:raise ValueError('Unknown aapt2 compiled XML line')
    require(len(roots)==1 and roots[0]['tag']=='manifest','One real compiled manifest required')
    return roots[0]


def audit_compiled_manifest(plan, text):
    root=parse_compiled_xml(text);attrs=root['attrs']
    require(attrs.get('package')=='org.wonad.fixture' and attrs.get('versionCode')=='1' and
            'sharedUserId' not in attrs,'Compiled package/version/shared UID differs')
    apps=[p for p in root['children'] if p['tag']=='application']
    require(len(apps)==1 and apps[0]['attrs'].get('debuggable')=='true' and
            apps[0]['attrs'].get('testOnly','false')=='false','Compiled ordinary debug app shape differs')
    rows=[p for p in apps[0]['children'] if p['tag']=='activity']
    names=[p['attrs'].get('name') for p in rows]
    require(sorted(names)==plan['exact_activities'] and len(names)==len(set(names))==16,
            'All16 real compiled activity names required')
    launchers=[]
    for row in rows:
        for intent in [p for p in row['children'] if p['tag']=='intent-filter']:
            actions=[p['attrs'].get('name') for p in intent['children'] if p['tag']=='action']
            categories=[p['attrs'].get('name') for p in intent['children'] if p['tag']=='category']
            if 'android.intent.category.LAUNCHER' in categories:
                require(actions==['android.intent.action.MAIN'] and categories==['android.intent.category.LAUNCHER'],
                        'Actual launcher filter changed')
                launchers.append(row['attrs']['name'])
    require(sorted(launchers)==plan['exact_launchers'] and len(launchers)==len(set(launchers))==14,
            'All14 real compiled launcher names required')
    permissions=[p['attrs'].get('name') for p in root['children'] if p['tag']=='uses-permission']
    source=ET.parse(ROOT/'android/fixture/src/main/AndroidManifest.xml').getroot()
    android='{http://schemas.android.com/apk/res/android}'
    require(sorted(permissions)==sorted(p.get(android+'name') for p in source.findall('uses-permission')) and
            len(permissions)==len(set(permissions)) and permissions.count('android.permission.CAPTURE_KEYBOARD')==1,
            'Compiled permission inventory differs')
    expected={}
    for p in source.findall('./application/activity'):
        name='org.wonad.fixture'+p.get(android+'name')
        if 'KeyboardCapture' in name:
            expected[name]={'label':p.get(android+'label'),'taskAffinity':p.get(android+'taskAffinity'),
                'exported':'true','launchMode':'0','documentLaunchMode':'2',
                'excludeFromRecents':'false','resizeableActivity':'true'}
    require(len(expected)==3,'Exact capture source component inventory required')
    for row in rows:
        if row['attrs']['name'] in expected:
            require(all(row['attrs'].get(k)==v for k,v in expected[row['attrs']['name']].items()),
                    'Compiled capture document flags/label/affinity differ')
    return dict(activities=names,launchers=launchers,permissions=permissions,
                exact_capture_components=expected,ordinary_compiled_manifest_verified=True)


def audit_capture_dex(dump, classes):
    targets={'KeyboardCaptureActivity':['dispatchKeyEvent','requestCapture','dump'],
             'KeyboardCaptureCounters':['observe','snapshot','clear'],
             'PublicKeyboardCaptureRequest':['request','setKeyboardCaptureEnabled','hasKeyboardCapture']}
    chunks=re.split(r'(?m)^Class #[0-9]+[^\n]*\n',dump)
    for name,methods in targets.items():
        descriptor='Lorg/wonad/fixture/'+name+';'
        require(descriptor in classes,'Compiled capture DEX class missing')
        found=[chunk for chunk in chunks if re.search(r"Class descriptor\s*:\s*'"+re.escape(descriptor)+"'",chunk)]
        require(len(found)==1 and all(method in found[0] for method in methods),
                'Real capture DEX methods/public reflection strings absent')
    return dict(capture_classes=sorted(targets),real_methods_and_public_reflection_strings_observed=True)



def capsule():
    require(Path.cwd() == Path(REMOTE) and Path('/.dockerenv').exists(), 'Build capsule only in exact private tools project')
    task = json.loads(Path('fixture7-task.json').read_text())
    require(task['gradle_argv'] == gradle_argv() and task['environment'] == build_environment(),
            'Private capsule exact offline command/environment changed')
    before = time.time(); child = None; error = None; code = None
    try:
        require(keystore_metadata_local() == task['existing_keystore_metadata'], 'Existing default key metadata changed/missing')
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
    require(keystore_metadata_local() == task['existing_keystore_metadata'], 'Default key metadata changed during build')


def build(reviewed):
    require_no_vendor()
    plan = load_plan(reviewed)
    require(host_resources()['memory']['MemAvailable'] >= 6*1024**3, 'Fresh6GiB available-memory planning reserve not met')
    require(not OUT.exists() and not OUT.is_symlink(), 'New fixture7 output must be absent; never restart/overwrite')
    docker('test', '!', '-e', REMOTE)
    for directory, floor in ((ROOT, plan['u_floor_bytes']), (Path('/var/tmp'), plan['var_floor_bytes'] + plan['expected_small_private_build_budget_bytes'])):
        s = os.statvfs(directory); require(s.f_bavail*s.f_frsize >= floor, 'Actual fixture build filesystem floor not met')
    OUT.mkdir(mode=0o700)
    receipt = dict(scope='actual_coherent_fixture7_compile_only', qualification='NOT_RUNTIME_QUALIFIED',
                   plan=ref(PLAN), helper=ref(__file__), started=time.time(), actual_tools=plan['actual_tools'])
    try:
        snapshot = OUT / 'source'
        for name, value in plan['sources'].items():
            target = snapshot / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
            require(sha(target) == value['sha256'], 'New host source snapshot differed')
        generated = {}
        for name,text in generated_inputs().items():
            generated[name]=OUT / ('generated-'+name)
            with generated[name].open('x') as stream: stream.write(text)
        docker('mkdir', REMOTE)
        for name, value in plan['staged_copy_hash_plan'].items():
            parent = str(Path(REMOTE + '/' + name).parent)
            docker('mkdir', '-p', parent)
            source = snapshot / value['host_source'] if 'host_source' in value else generated[name]
            command([*DOCKER, 'cp', source, CID + ':' + REMOTE + '/' + name])
        receipt['compiled_sources_before'] = compiled_inventory(plan)
        task = OUT / 'fixture7-task.json'
        write_new(task, {key: plan[key] for key in ('gradle_argv', 'environment', 'var_floor_bytes', 'existing_keystore_metadata')})
        command([*DOCKER, 'cp', task, CID + ':' + REMOTE + '/fixture7-task.json'])
        command([*DOCKER, 'cp', Path(__file__), CID + ':' + REMOTE + '/fixture7-build.py'])
        execution_inputs = {'fixture7-task.json': ref(task), 'fixture7-build.py': ref(__file__)}
        actual_exec_hashes = docker('sha256sum', *[REMOTE + '/' + name for name in sorted(execution_inputs)]).splitlines()
        require(actual_exec_hashes == [execution_inputs[name]['sha256'] + '  ' + REMOTE + '/' + name for name in sorted(execution_inputs)],
                'Actual private build capsule/task copy changed')
        receipt['actual_staged_execution_inputs'] = execution_inputs
        argv = [*DOCKER, 'exec', '--workdir', REMOTE, CID, '/usr/bin/python3', '-B', REMOTE + '/fixture7-build.py', 'capsule']
        with (OUT / 'capsule.stdout').open('xb') as stdout, (OUT / 'capsule.stderr').open('xb') as stderr:
            child = subprocess.Popen(argv, stdout=stdout, stderr=stderr)
            print('Actual fixture7 Docker exec client PID', child.pid, 'CID', CID, flush=True)
            result = child.wait()
        receipt['actual_exec'] = dict(argv=argv, client_pid=child.pid, exit_code=result)
        for name in ('gradle.log', 'gradle-owned.json', 'gradle-terminal.json'):
            command([*DOCKER, 'cp', CID + ':' + REMOTE + '/' + name, OUT / name])
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
            command([*DOCKER, 'cp', CID + ':' + REMOTE + '/' + remote, OUT / local])
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
                command([*DOCKER, 'cp', target, CID + ':' + REMOTE + '/' + name])
                dex_dump.append(docker(SDK + 'dexdump', '-d', REMOTE + '/' + name))
        (OUT / 'dexdump.txt').write_text('\n'.join(dex_dump))
        actual = dex_classes(OUT / 'fixture.apk'); old = dex_classes(OLD / 'fixture.apk')
        receipt['apk_audit'] = audit_apk(plan, cert, badging, '\n'.join(dex_dump), actual, old)
        receipt['compiled_manifest_audit'] = audit_compiled_manifest(plan, manifest)
        receipt['capture_dex_audit'] = audit_capture_dex('\n'.join(dex_dump), actual)
        receipt['artifact'] = ref(OUT / 'fixture.apk')
        load_plan(reviewed)
        require(all(sha(snapshot / name) == value['sha256'] for name, value in plan['sources'].items()), 'Preserved host snapshot changed')
        receipt.update(status='compile_tests_artifact_verified_no_runtime_qualification', guests_started=False,
                       old_fixture5_complete_tree_unchanged=True, promotion_or_registration=False)
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
    parser.add_argument('phase', choices=('propose', 'verify-plan', 'build', 'capsule'))
    parser.add_argument('--build-after-root-authorization', action='store_true')
    parser.add_argument('--reviewed-plan-sha256')
    args = parser.parse_args()
    if args.phase == 'propose': create_plan()
    elif args.phase == 'verify-plan': load_plan(args.reviewed_plan_sha256); print('Plan/source/tools conserved; no build executed')
    elif args.phase == 'capsule': capsule()
    else:
        require(args.build_after_root_authorization, 'Explicit root build authorization flag required')
        build(args.reviewed_plan_sha256)


if __name__ == '__main__': main()
