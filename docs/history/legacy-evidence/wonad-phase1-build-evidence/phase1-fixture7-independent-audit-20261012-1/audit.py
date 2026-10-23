#!/usr/bin/python3
"""Read-only authentication/rederivation of the completed fixture7 host evidence."""
from pathlib import Path
import collections
import hashlib
import importlib.util
import json
import re
import sys
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path('/u/elric/tree/wonad')
OUT = ROOT/'android/out/native-keyboard-capture-fixture-7'
OLDER = ROOT/'android/out/native-keyboard-capture-fixture-6'
DRIVER = Path('/u/elric/tree/wonad-phase1-build-evidence/phase1-keyboard-capture-fixture7-build-driver-20261012-1')
RECEIPT_SHA = '003d0138bc9eade9e948eadd6806eee812160d7a962e939d559f827f2c4f272e'

def unique(pairs):
    value = {}
    for key, item in pairs:
        assert key not in value, ('duplicate JSON key',key)
        value[key] = item
    return value

def load(path):
    return json.loads(path.read_bytes(),object_pairs_hook=unique)

def digest(path):
    assert path.is_file() and not path.is_symlink(), path
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()

def check(ref):
    path = Path(ref['path'])
    assert digest(path) == ref['sha256'] and path.stat().st_size == ref['bytes'], path

def reference(path):
    return {'path':str(path),'bytes':path.stat().st_size,'sha256':digest(path)}

spec=importlib.util.spec_from_file_location('fixture7_reviewed_driver',DRIVER/'build_fixture7.py')
V=importlib.util.module_from_spec(spec);sys.modules[spec.name]=V;spec.loader.exec_module(V)
receipt = load(OUT/'build-receipt.json')
assert digest(OUT/'build-receipt.json') == RECEIPT_SHA
assert receipt['status']=='compile_tests_artifact_verified_no_runtime_qualification'
assert receipt['scope']=='actual_coherent_fixture7_compile_only'
assert receipt['qualification']=='NOT_RUNTIME_QUALIFIED' and receipt['guests_started'] is False
assert receipt['promotion_or_registration'] is False
check(receipt['helper']);check(receipt['plan']);check(receipt['artifact'])
plan = load(Path(receipt['plan']['path']))
check(plan['helper']);check(plan['host_test'])
assert plan['sources']==V.source_inventory()
for ref in plan['sources'].values():check(ref)
assert len(plan['sources'])==28 and plan['expected_actual_jvm_cases']==V.expected_tests(plan['sources'])
assert plan['gradle_argv']==V.gradle_argv() and plan['environment']==V.build_environment()
assert plan['staged_copy_hash_plan']==V.staged_plan(plan['sources'])
assert receipt['compiled_sources_before']==receipt['compiled_sources_after']=={
    name:ref['sha256'] for name,ref in plan['staged_copy_hash_plan'].items()}
changed = []
for name, ref in plan['sources'].items():
    snapshot=OUT/'source'/name
    assert digest(snapshot)==ref['sha256'] and snapshot.stat().st_size==ref['bytes']
    if digest(OLDER/'source'/name)!=ref['sha256']:changed.append(name)
assert changed==[
    'android/fixture/src/test/kotlin/org/wonad/fixture/PaletteFixtureContractTest.kt',
    'android/fixture/src/test/kotlin/org/wonad/fixture/PermissionFixtureContractTest.kt']
expected_files=set(receipt['evidence_files'])
actual_files={str(p.relative_to(OUT)) for p in OUT.rglob('*') if p.is_file()}
assert actual_files==expected_files|{'build-receipt.json'}
for name,ref in receipt['evidence_files'].items():
    assert Path(ref['path'])==OUT/name
    check(ref)
for name,ref in receipt['actual_staged_execution_inputs'].items():check(ref)
assert receipt['actual_exec']['exit_code']==0 and type(receipt['actual_exec']['exit_code']) is int
terminal=load(OUT/'gradle-terminal.json')
assert terminal['argv']==plan['gradle_argv'] and type(terminal['exit_code']) is int and terminal['exit_code']==0
assert terminal['error'] is None
assert re.search(r'^BUILD SUCCESSFUL in ',(OUT/'gradle.log').read_text(),re.M)
# Independent XML census (not producer summary), then exact producer audit replay.
cases=[];suites=[]
for path in sorted((OUT/'jvm-results').glob('TEST-*.xml')):
    xml=ET.parse(path).getroot();suites.append(xml.get('name'))
    rows=list(xml.findall('testcase'))
    assert xml.get('tests')==str(len(rows)) and all(xml.get(k)=='0' for k in ('failures','errors','skipped'))
    for row in rows:
        assert not any(row.find(k) is not None for k in ('failure','error','skipped'))
        cases.append(row.get('classname')+'.'+row.get('name'))
assert len(suites)==len(set(suites))==8 and len(cases)==len(set(cases))==41
assert sorted(cases)==plan['expected_actual_jvm_cases']==receipt['jvm']['actual_cases']
assert V.audit_jvm(OUT/'jvm-results',plan['expected_actual_jvm_cases'])==receipt['jvm']
lint=ET.parse(OUT/'lint.xml').getroot()
severities=collections.Counter(row.get('severity') for row in lint)
assert not severities['Error'] and not severities['Fatal'] and severities['Warning']==33
assert receipt['lint']=={'errors':0,'warnings':33}
actual=V.dex_classes(OUT/'fixture.apk');old=V.dex_classes(V.OLD/'fixture.apk')
assert len(actual)==1121 and len(old)==1104 and set(old)<=set(actual)
with zipfile.ZipFile(OUT/'fixture.apk') as apk:
    assert len(apk.namelist())==len(set(apk.namelist()))
    for name in ('classes.dex','classes2.dex','classes3.dex'):
        assert apk.read(name)==(OUT/name).read_bytes()
cert=(OUT/'apksigner.txt').read_text();badging=(OUT/'badging.txt').read_text()
dump=(OUT/'dexdump.txt').read_text();manifest=(OUT/'compiled-manifest.txt').read_text()
assert V.audit_apk(plan,cert,badging,dump,actual,old)==receipt['apk_audit']
assert V.audit_compiled_manifest(plan,manifest)==receipt['compiled_manifest_audit']
assert V.audit_capture_dex(dump,actual)==receipt['capture_dex_audit']
assert re.findall(r'^Number of signers: (\d+)$',cert,re.M)==['1']
assert 'Verified using v2 scheme (APK Signature Scheme v2): true' in cert
assert V.tree_records(V.OLD)==plan['old_fixture5_complete_tree']
failed6=load(OLDER/'build-receipt.json')
assert failed6['status']=='failed' and failed6['partial_failure_preserved'] is True
result={'schema':1,'kind':'fixture7_independent_readonly_evidence_rederivation_v1','result':'PASS',
    'receipt':reference(OUT/'build-receipt.json'),'plan':reference(DRIVER/'plan.json'),
    'driver':reference(DRIVER/'build_fixture7.py'),'host_test':reference(DRIVER/'test_build_fixture7.py'),
    'apk':reference(OUT/'fixture.apk'),'actual_evidence_refs_verified':len(expected_files),
    'current_and_snapshot_source_refs_verified':len(plan['sources']),
    'only_fixture6_source_deltas':changed,'actual_jvm_cases':len(cases),'actual_jvm_suites':len(suites),
    'lint_severity_counts':dict(severities),'lint_warning_ids':dict(collections.Counter(
        row.get('id') for row in lint if row.get('severity')=='Warning')),
    'actual_dex_classes':len(actual),'preserved_predecessor_dex_classes':len(old),
    'actual_capture_classes_and_reflection_strings_present':True,
    'actual_compiled_manifest':receipt['compiled_manifest_audit'],
    'retained_official_apksigner_transcript_matches':True,
    'ordinary_signer_sha256':V.SIGNER,
    'failed_fixture6_preserved':reference(OLDER/'build-receipt.json'),
    'negative_claims':{'runtime_qualification':False,'android_keyboard_capture_delivery_proven':False,
      'tools_container_mutated':False,'key_read_or_created':False,'build_or_signing':False,
      'official_apksigner_reexecuted_by_this_host_only_replay':False}}
print(json.dumps(result,sort_keys=True,indent=2))
