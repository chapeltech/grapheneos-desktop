#!/usr/bin/env python3
"""Stdlib source-authority PROPOSAL only. No Docker/Gradle/build/sign/install/VM operation.
Print a source-bound proposal to stdout; it is not a reviewed executable build plan."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import xml.etree.ElementTree as ET

ROOT = Path('/u/elric/tree/wonad')
HERE = Path(__file__).resolve().parent
CANDIDATE = Path('/u/elric/tree/wonad-phase1-build-evidence/phase1-ordinary-keyboard-capture-fixture-proposal-20261012-1')
FREEZE_SHA = '8bbb699c77d822c6a448381a416aa10d06f9fe769ec6a385835c5e5bf32d09b4'
FIXTURE5_BUILDER_SHA = '8bb8902433d20b420750a40ea58d2d55079f384dd30174f07523df554dce6640'
BASE = json.loads(r'''{
  "android/build.gradle.kts": {
    "bytes": 200,
    "sha256": "33303e785b76d23da1a13b4be61842f52731ccf39ae6e89eeab89539b3916623"
  },
  "android/fixture/build.gradle.kts": {
    "bytes": 605,
    "sha256": "58a8cabe52ccc0a29f8e194be76ef645ff47d49f663bf0411a3d5b93759d950e"
  },
  "android/fixture/src/main/AndroidManifest.xml": {
    "bytes": 6690,
    "sha256": "f65373bc8325c0539cdf6e177d193e0df4b9a52d5689bd8bc90c0b2bbadcf3a8"
  },
  "android/fixture/src/main/java/org/wonad/fixture/FixedActivity.java": {
    "bytes": 148,
    "sha256": "04ee31908898fda54ec03a8624aaacbe37678a7c842e80eeb8219cdf41f84e28"
  },
  "android/fixture/src/main/java/org/wonad/fixture/FixtureActivity.java": {
    "bytes": 9313,
    "sha256": "873cabb0202995e3ae75d13e7177fee95efc108c7987c7a8fa06541e290ee562"
  },
  "android/fixture/src/main/java/org/wonad/fixture/LaunchActivity.kt": {
    "bytes": 844,
    "sha256": "33c77933c78dbeee2e412b0c2307e8c764f41c5570c710e51d11a902c41c94fb"
  },
  "android/fixture/src/main/java/org/wonad/fixture/OneActivity.java": {
    "bytes": 146,
    "sha256": "e43a6bb1fc7cc8e3506b1eda3354ae72b72ce241e3ec0268572be21ab88b8a36"
  },
  "android/fixture/src/main/java/org/wonad/fixture/TwoActivity.java": {
    "bytes": 146,
    "sha256": "447e7dc4a1a48dcb14a076e858679417ca83bf9c9c71fa8e32f730750bbde71c"
  },
  "android/fixture/src/main/kotlin/org/wonad/fixture/BandedPaletteActivity.kt": {
    "bytes": 6069,
    "sha256": "cd4ba5f9355c3858f03e1faf51c368e2042bf564cc6823f9115aa623cdf730a1"
  },
  "android/fixture/src/main/kotlin/org/wonad/fixture/CompositionEditText.kt": {
    "bytes": 2369,
    "sha256": "ffc942f359b7c1b4b4738ef1b708c38200465beb0644b64dca09dc0d3a75c0d9"
  },
  "android/fixture/src/main/kotlin/org/wonad/fixture/FixtureKeyJournal.kt": {
    "bytes": 1240,
    "sha256": "4ff2f3b3c1b572618807f93c3068e8f992c63f2ea7f7a3a2e166338f48fb457a"
  },
  "android/fixture/src/main/kotlin/org/wonad/fixture/PaletteActivity.kt": {
    "bytes": 4847,
    "sha256": "fed6cbd92be929b7877a5e920c96a70d536fb49cfd0ca33d37d02dea40e7e20f"
  },
  "android/fixture/src/main/kotlin/org/wonad/fixture/PaletteProbeLedger.kt": {
    "bytes": 1887,
    "sha256": "c0cddc11a4c54999ce4a81f2abea772da61e7900aee6b969ea18e72971db4b72"
  },
  "android/fixture/src/main/kotlin/org/wonad/fixture/PermissionActivity.kt": {
    "bytes": 6974,
    "sha256": "10d563313cb9ad9862f1361b6fde944807f460dcfc7bcb6dbea4a91fab9e5c4f"
  },
  "android/fixture/src/main/kotlin/org/wonad/fixture/PermissionRequestLedger.kt": {
    "bytes": 3073,
    "sha256": "bc0645a77adb9f0b47fbf08fe64e6183ccf9c04c3f84c65b7c325223561a291e"
  },
  "android/fixture/src/main/kotlin/org/wonad/fixture/ResetActivity.kt": {
    "bytes": 1480,
    "sha256": "68f19e4ac8daa3b4815aa095c4e4177bb064f25f47ba6d06c4ab37e86d589f3c"
  },
  "android/fixture/src/test/kotlin/org/wonad/fixture/BandedPaletteFixtureContractTest.kt": {
    "bytes": 4770,
    "sha256": "db46eee417e1fc42b34b75199118c7fd048a98433f97f4a2ccd09873ef6db5bf"
  },
  "android/fixture/src/test/kotlin/org/wonad/fixture/FixtureKeyJournalTest.kt": {
    "bytes": 2226,
    "sha256": "e4d21ef879d0e1d49b0ed05dda82c2503ee137d8a2c5c806b0833e739a3b99fa"
  },
  "android/fixture/src/test/kotlin/org/wonad/fixture/PaletteFixtureContractTest.kt": {
    "bytes": 5217,
    "sha256": "1c42718df3963aca13567d49e1c090259ad81d2c2fd58974c1b4b2be94a57009"
  },
  "android/fixture/src/test/kotlin/org/wonad/fixture/PaletteProbeLedgerTest.kt": {
    "bytes": 2504,
    "sha256": "3a7500f6c71d5e24b2b48b5feeb6020ce4a84bda16a352f2c74d14b22fffe596"
  },
  "android/fixture/src/test/kotlin/org/wonad/fixture/PermissionFixtureContractTest.kt": {
    "bytes": 6115,
    "sha256": "cefde877fb0815fb3f2c24a6b348b504ba6914158e55ec43e1115d86f7b95bc6"
  },
  "android/fixture/src/test/kotlin/org/wonad/fixture/PermissionRequestLedgerTest.kt": {
    "bytes": 6598,
    "sha256": "bc536cd98d389a7d24f3609a928e3f6afb936969d659ebce443c1b5690b26126"
  },
  "android/settings.gradle.kts": {
    "bytes": 831,
    "sha256": "69301de73f1b81924b40b03b439858361e67064db2457dc944172fd1d2f3babe"
  }
}''')
OVERLAY = {
 'android/fixture/src/main/AndroidManifest.xml': {'bytes':8646,'sha256':'06aaa2c31d3a86bbca8b0b9fd893a23bd8e1ebb90f982ac7a1a089df110d0c4d'},
 'android/fixture/src/main/kotlin/org/wonad/fixture/KeyboardCaptureActivity.kt': {'bytes':7128,'sha256':'06008e051a58a0855b927327ecdc838fb8709a8d253882513ac02b1e5e95702b'},
 'android/fixture/src/main/kotlin/org/wonad/fixture/KeyboardCaptureCounters.kt': {'bytes':1836,'sha256':'220ce93d74624b4b4cf9fcb86657bee2b9e94a1d176c7be36b3ab7ad00c29000'},
 'android/fixture/src/main/kotlin/org/wonad/fixture/PublicKeyboardCaptureRequest.kt': {'bytes':3880,'sha256':'d991a4fb254cd992d93d052faeebdda84db7e5f1919ba9b69297a66c398966be'},
 'android/fixture/src/test/kotlin/org/wonad/fixture/KeyboardCaptureCountersTest.kt': {'bytes':2163,'sha256':'c805a243bb9131c3370e41d67c918d21c78358dcb5e8cdd37ff3f5c958916dca'},
 'android/fixture/src/test/kotlin/org/wonad/fixture/PublicKeyboardCaptureRequestTest.kt': {'bytes':3460,'sha256':'0639417b6c001f5fabdde8907408142eefb0d1c9e50e15a09c6b2007b25d56db'},
}
SIGNER = 'fdbf6a6940f8a1059fea942db2272abfb19e39716f544c92962a6e98103c4e88'
REMOTE = '/work/native-keyboard-capture-fixture6-root'
OUTPUT = ROOT/'android/out/native-keyboard-capture-fixture-6'
PLAN = ROOT/'android/out/native-fixture6-build-plan-1.json'
PREDECESSOR = ROOT/'android/out/native-banded-fixture-5'
ATTR = '{http://schemas.android.com/apk/res/android}'
LIMIT = 2*1024**2

def require(value, message):
    if not value:
        raise ValueError(message)

def regular_bytes(path):
    path=Path(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= LIMIT,'Bounded regular source required')
        with os.fdopen(fd,'rb',closefd=False) as stream:
            value=stream.read(LIMIT+1)
        after=os.fstat(fd)
        require(len(value)==before.st_size and
                (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),
                'Source changed during bounded regular read')
        return value
    finally:
        os.close(fd)

def ref(path):
    value=regular_bytes(path)
    return {'path':str(path),'sha256':hashlib.sha256(value).hexdigest(),'bytes':len(value)}

def pinned(path, expected):
    result=ref(path)
    require({k:result[k] for k in ('bytes','sha256')}==expected,'Source pin changed: '+str(path))
    return result

def unique_json(data):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'Duplicate JSON member')
            result[key]=value
        return result
    return json.loads(data,object_pairs_hook=pairs)

def source_inventory():
    pinned(CANDIDATE/'freeze-review.json',{'bytes':len(regular_bytes(CANDIDATE/'freeze-review.json')),'sha256':FREEZE_SHA})
    require(ref(ROOT/'android/fixture/build-fixture5.py')['sha256']==FIXTURE5_BUILDER_SHA,
            'Reviewed old fixture5 builder changed')
    actual=['android/build.gradle.kts','android/settings.gradle.kts','android/fixture/build.gradle.kts']
    for path in sorted((ROOT/'android/fixture/src').rglob('*')):
        require(not path.is_symlink(),'Original fixture source symlink rejected')
        if path.is_file():
            actual.append(str(path.relative_to(ROOT)))
        else:
            require(path.is_dir(),'Unexpected original fixture special file')
    require(len(actual)==23 and set(actual)==set(BASE),'Original23 source inventory changed')
    result={name:pinned(ROOT/name,value) for name,value in sorted(BASE.items())}
    for name,value in sorted(OVERLAY.items()):
        if name not in BASE:
            require(not (ROOT/name).exists() and not (ROOT/name).is_symlink(),'Candidate addition target already exists')
        result[name]=pinned(CANDIDATE/'candidate'/name,value)
    require(len(result)==28,'Proposed exact28 source inputs required')
    return dict(sorted(result.items()))

def settings_adaptation(data):
    require(hashlib.sha256(data).hexdigest()==BASE['android/settings.gradle.kts']['sha256'],
            'Current full settings source changed')
    text=data.decode('utf-8')
    require(text.count('include(":probe")')==1,'Pinned settings anchor ambiguous')
    # Same reviewed fixture-only isolation as fixture5; bind full newer original,
    # including conformance and opt-in StyX modules, but do not compile those modules.
    return (text.split('include(":probe")',1)[0]+'include(":fixture")\n').encode()

def expected_tests(sources):
    result=[]
    suites=[]
    for name,record in sorted(sources.items()):
        if '/src/test/' not in name:
            continue
        text=regular_bytes(record['path']).decode()
        package=re.findall(r'^package (\S+)$',text,re.M)
        classes=re.findall(r'^class (\w+)\s*\{',text,re.M)
        methods=re.findall(r'@Test\s+fun (\w+)\(',text)
        require(package==['org.wonad.fixture'] and len(classes)==1 and methods and
                len(methods)==len(set(methods)),'Ordinary exact nonparameterized JVM declaration required')
        suite=package[0]+'.'+classes[0]
        suites.append(suite)
        result.extend(suite+'.'+method for method in methods)
    require(len(suites)==len(set(suites))==8 and len(result)==len(set(result))==41,
            'Exactly observed8 source suites/41 methods required')
    return sorted(result)

def manifest_inventory(data):
    root=ET.fromstring(data)
    # Source manifest has no package attribute; exact pinned module Gradle
    # namespace/applicationId supplies org.wonad.fixture before compilation.
    require(root.get('package') is None and
            ATTR+'sharedUserId' not in root.attrib,'Ordinary fixture manifest package/UID shape changed')
    rows=root.findall('./application/activity')
    names=[row.get(ATTR+'name') for row in rows]
    require(len(names)==len(set(names))==16 and all(name and name.startswith('.') for name in names),
            'Exactly16 distinct fixture activities required')
    activities=sorted('org.wonad.fixture'+name for name in names)
    launchers=sorted('org.wonad.fixture'+row.get(ATTR+'name') for row in rows
                    if any(c.get(ATTR+'name')=='android.intent.category.LAUNCHER'
                           for c in row.findall('./intent-filter/category')))
    require(len(launchers)==len(set(launchers))==14,'Exactly14 distinct real launcher components required')
    permission=root.findall('uses-permission')
    require([p.get(ATTR+'name') for p in permission].count('android.permission.CAPTURE_KEYBOARD')==1,
            'Exactly one normal capture declaration required')
    captures=[]
    for row in rows:
        if row.get(ATTR+'name') not in ('.KeyboardCaptureOneActivity','.KeyboardCaptureTwoActivity','.KeyboardCapturePhoneActivity'):
            continue
        require(all(row.get(ATTR+key)==value for key,value in
                    (('exported','true'),('launchMode','standard'),('documentLaunchMode','always'),
                     ('excludeFromRecents','false'),('resizeableActivity','true'))),
                'Capture document task flags changed')
        captures.append(dict(component='org.wonad.fixture'+row.get(ATTR+'name'),
                             label=row.get(ATTR+'label'),task_affinity=row.get(ATTR+'taskAffinity'),
                             exported=True,launch_mode='standard',document_launch_mode='always',
                             exclude_from_recents=False,resizeable=True))
    require(len(captures)==3 and len({row['task_affinity'] for row in captures})==3,
            'Three distinct same-package capture document task affinities required')
    return {'activities':activities,'launchers':launchers,'capture_components':sorted(captures,key=lambda r:r['component'])}

def audit_future_jvm(directory, expected):
    """Proposed future real report audit; host tests use SYNTHETIC XML only."""
    directory=Path(directory)
    paths=sorted(directory.glob('TEST-*.xml'))
    require(len(paths)==8,'All eight real JVM reports required')
    actual=[]
    for path in paths:
        root=ET.fromstring(regular_bytes(path))
        require(root.tag=='testsuite','Exact testsuite report root required')
        cases=list(root.iter('testcase'))
        require(root.get('tests')==str(len(cases)) and
                all(root.get(key)=='0' for key in ('failures','errors','skipped')),
                'Real JVM suite failed/skipped/count mismatch')
        for case in cases:
            require(not any(case.find(key) is not None for key in ('failure','error','skipped')),
                    'Real JVM case failed/skipped')
            actual.append(case.attrib['classname']+'.'+case.attrib['name'])
    require(len(actual)==len(set(actual))==41 and sorted(actual)==expected,'Exact41 actual JVM identities required')
    return {'actual_cases':sorted(actual),'tests':41,'failures':0,'errors':0,'skipped':0}

def proposal():
    sources=source_inventory()
    settings=settings_adaptation(regular_bytes(ROOT/'android/settings.gradle.kts'))
    manifest=manifest_inventory(regular_bytes(sources['android/fixture/src/main/AndroidManifest.xml']['path']))
    staged={name.removeprefix('android/'):{'host_source':record['path'],
            'sha256':record['sha256'],'bytes':record['bytes']}
            for name,record in sources.items() if name!='android/settings.gradle.kts'}
    staged['settings.gradle.kts']={'generated_from':sources['android/settings.gradle.kts'],
        'text':settings.decode(),'sha256':hashlib.sha256(settings).hexdigest(),'bytes':len(settings)}
    return {'schema':1,'scope':'source_only_fixture6_authority_proposal_not_executable_build_plan',
        'status':'PREPARED_NOT_BUILT_NOT_RUNTIME_QUALIFIED','helper':ref(__file__),
        'source_proposal_receipt':ref(CANDIDATE/'freeze-review.json'),
        'reviewed_old_builder':ref(ROOT/'android/fixture/build-fixture5.py'),
        'sources':sources,'source_count':28,'staged_source_plan':dict(sorted(staged.items())),
        'manifest':manifest,'expected_jvm_cases':expected_tests(sources),'expected_jvm_count':41,
        'expected_jvm_suites':8,'actual_compile_reports_observed':False,
        'build_helper':{'path':'PENDING_NEW_REVIEWED_FIXTURE6_BUILDER','sha256':'PENDING'},
        'actual_tools':{'container_identity':'PENDING_FRESH_INSPECTION','tool_hashes':'PENDING_ACTUAL_OFFLINE_TOOLS'},
        'paths':{'proposed_plan':str(PLAN),'proposed_output':str(OUTPUT),'proposed_remote':REMOTE,
                 'predecessor_fixture5':str(PREDECESSOR)},
        'future_gradle_argv':['/opt/gradle-8.11.1/bin/gradle','--offline','--no-daemon','--rerun-tasks',
             '--max-workers=4','-p',REMOTE,':fixture:testDebugUnitTest',':fixture:lintDebug',':fixture:assembleDebug'],
        'sdk':{'compile':35,'min':30,'target':35,'version_code':1,'package':'org.wonad.fixture'},
        'expected_existing_ordinary_signer_sha256':SIGNER,
        'old_fixture5_output_preservation':'PENDING_FULL_AUTHENTICATED_TREE_BEFORE_BUILD_NO_REUSE_OVERWRITE',
        'resources':{'proposed_original_var_floor_bytes':8*1024**3,'proposed_original_u_floor_bytes':512*1024**2,
                     'actual_memory_and_heavy_lane_admission':'PENDING_SEPARATE_REVIEW'},
        'apk_checks_required':['Official pinned apksigner one exact existing ordinary signer.',
            'Actual aapt2 package/version/min30/target35/debug/notTestOnly and exact14 launcher names.',
            'Compiled XML16activities, exact three document flags/affinities and normal permission declaration; no shared UID.',
            'Original DEX checksum/class inventory preserved plus exact three activities/counters/public-reflection methods.',
            'Eight actual JUnit XML reports exact41 source-derived identities, no failures/errors/skips.',
            'Actual lint zero Error/Fatal; retain all warnings.',
            'Staged inputs/capsule/task/tool hashes before and after actual Gradle; preserve complete predecessor fixture5.',
            'Actual installed ordinary UID/signer/normal permission, capture feature/API support and real keys require future guest, not build receipt.'],
        'build_started':False,'keys_generated':False,'guest_started':False,'runtime_qualified':False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-proposal',action='store_true')
    args=parser.parse_args()
    require(args.source_proposal,'Explicit stdout-only --source-proposal required; no build mode exists')
    print(json.dumps(proposal(),indent=2,sort_keys=True))

if __name__=='__main__':
    main()
