"""Source and mocked build-plan/synthetic compiler transcript guards; no Docker build/Gradle."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile

import build_fixture7 as V


def manifests():
    source=ET.parse(V.ROOT/'android/fixture/src/main/AndroidManifest.xml').getroot()
    android='{http://schemas.android.com/apk/res/android}'
    names=sorted('org.wonad.fixture'+p.get(android+'name') for p in source.findall('./application/activity'))
    launchers=sorted('org.wonad.fixture'+p.get(android+'name') for p in source.findall('./application/activity')
        if p.find('./intent-filter/category') is not None)
    return {'exact_activities':names,'exact_launchers':launchers}


def synthetic_compiled_xml():
    # The13 old real nodes/format are preserved. Only new nodes are synthetic;
    # this is NOT a real fixture7 compiled manifest.
    tree=V.parse_compiled_xml((V.OLD/'compiled-manifest.txt').read_text())
    tree['children'].append({'tag':'uses-permission',
        'attrs':{'name':'android.permission.CAPTURE_KEYBOARD'},'children':[]})
    source=ET.parse(V.ROOT/'android/fixture/src/main/AndroidManifest.xml').getroot()
    android='{http://schemas.android.com/apk/res/android}'
    app=next(p for p in tree['children'] if p['tag']=='application')
    for p in source.findall('./application/activity'):
        if 'KeyboardCapture' not in p.get(android+'name'):continue
        attrs={'name':'org.wonad.fixture'+p.get(android+'name'),'label':p.get(android+'label'),
            'taskAffinity':p.get(android+'taskAffinity'),'exported':'true','launchMode':'0',
            'documentLaunchMode':'2','excludeFromRecents':'false','resizeableActivity':'true'}
        app['children'].append({'tag':'activity','attrs':attrs,'children':[
            {'tag':'intent-filter','attrs':{},'children':[
                {'tag':'action','attrs':{'name':'android.intent.action.MAIN'},'children':[]},
                {'tag':'category','attrs':{'name':'android.intent.category.LAUNCHER'},'children':[]}]}]})
    result=['N: android=http://schemas.android.com/apk/res/android (line=2)']
    def render(p,indent):
        result.append(' '*indent+'E: '+p['tag']+' (line=2)')
        for key,value in p['attrs'].items():
            raw=value if value in ('true','false') or value.isdecimal() or value.startswith(('0x','@0x')) else '"'+value+'" (Raw: "'+value+'")'
            result.append(' '*(indent+2)+'A: '+key+'='+raw)
        for child in p['children']:render(child,indent+4)
    render(tree,2)
    return '\n'.join(result)+'\n'


class Fixture7Tests(unittest.TestCase):
    def test_current_exact28_repo_sources_all_hash_pins_and_held_fixes(self):
        value=V.source_inventory()
        self.assertEqual(28,len(value));self.assertEqual(V.SOURCE_PINS,{k:r['sha256'] for k,r in value.items()})
        self.assertEqual(V.HELD,{k:value[k]['sha256'] for k in V.HELD})
        self.assertTrue(all(r['path']==str(V.ROOT/k) for k,r in value.items()))

    def test_current_settings_exact_full_pin_prefix_and_fixture_only(self):
        source=(V.ROOT/'android/settings.gradle.kts').read_text()
        self.assertEqual(source.split('include(":probe")',1)[0]+'include(":fixture")\n',V.fixture_settings(source))
        self.assertIn('include(":conformance")',source);self.assertIn('include(":styx-auth")',source)
        for hostile in (source+'\nforeign()\n',source.replace('include(":conformance")',''),source.replace('google()','mavenLocal()')):
            with self.assertRaises(ValueError):V.fixture_settings(hostile)

    def test_exact41_source_declared_cases8suites_preserve28_and_new13(self):
        rows=V.expected_tests(V.source_inventory())
        self.assertEqual(41,len(rows));self.assertEqual(8,len({r.rsplit('.',1)[0] for r in rows}))
        self.assertEqual(6,sum('.KeyboardCaptureCountersTest.' in r for r in rows))
        self.assertEqual(7,sum('.PublicKeyboardCaptureRequestTest.' in r for r in rows))

    def test_source_hash_or_symlink_changes_refuse(self):
        pins=copy.deepcopy(V.SOURCE_PINS);pins[next(iter(pins))]='0'*64
        with mock.patch.object(V,'SOURCE_PINS',pins),self.assertRaises(ValueError):V.source_inventory()
        with tempfile.TemporaryDirectory() as root:
            p=Path(root);source=p/'source';source.write_text('public');link=p/'link';link.symlink_to(source)
            with self.assertRaises(ValueError):V.ref(link)

    def test_generated_settings_properties_init_are_content_bound_not_repo_mutations(self):
        value=V.staged_plan(V.source_inventory())
        self.assertEqual(30,len(value))  #27ordinary +3generated; originalsettings source remains bound separately
        self.assertIn('-Xmx512m',value['gradle.properties']['generated_text'])
        self.assertIn('kotlin.compiler.execution.strategy=in-process',value['gradle.properties']['generated_text'])
        self.assertIn('maxHeapSize = "128m"',value['fixture7-test-memory.init.gradle']['generated_text'])
        self.assertNotIn('/work/android',str(value))

    def test_offline_one_worker_explicit_generated_init_and_private_project(self):
        args=V.gradle_argv()
        self.assertIn('--offline',args);self.assertIn('--no-daemon',args);self.assertIn('--rerun-tasks',args)
        self.assertIn('--max-workers=1',args);self.assertNotIn('--max-workers=4',args)
        self.assertEqual(V.REMOTE,args[args.index('-p')+1])
        self.assertEqual(V.REMOTE+'/fixture7-test-memory.init.gradle',args[args.index('--init-script')+1])
        self.assertEqual([':fixture:testDebugUnitTest',':fixture:lintDebug',':fixture:assembleDebug'],args[-3:])

    def test_original_actual_tools_profile_is_bound_without_mutating_it(self):
        value={'Id':V.CID,'Image':V.IMAGE,'Name':'/wonad-android-gate-tools','Mounts':[],
            'Path':'sleep','Args':['infinity'],'Config':{'User':''},
            'HostConfig':{'Privileged':False,'Memory':0,'NanoCpus':0},
            'State':{'Running':True,'OOMKilled':False,'Pid':123,'StartedAt':'same'}}
        with mock.patch.object(V,'command',return_value=json.dumps([value])):
            self.assertTrue(V.tools_identity()['existing_profile']['whole_memory_unbounded'])
        for key,change in (('Image','foreign'),('Mounts',[{}]),('Args',['other']),('Path','foreign')):
            hostile=copy.deepcopy(value);hostile[key]=change
            with mock.patch.object(V,'command',return_value=json.dumps([hostile])),self.assertRaises(ValueError):V.tools_identity()

    def test_tool_sha_inventory_requires_exact_count_paths_hex(self):
        text='\n'.join('a'*64+'  '+p for p in V.TOOLS)
        with mock.patch.object(V,'docker',return_value=text):
            self.assertEqual(len(V.TOOLS),len(V.tool_hashes()))
        for bad in (text+'\nextra',text.replace('a'*64,'z'*64),text.replace(V.TOOLS[0],'/foreign')):
            with mock.patch.object(V,'docker',return_value=bad),self.assertRaises(ValueError):V.tool_hashes()

    def test_public_signer_recheck_reads_existing_apk_not_private_key(self):
        expected=V.sha(V.OLD/'fixture.apk')+'  /work/native-fixture5-root/fixture/build/outputs/apk/debug/fixture-debug.apk'
        with mock.patch.object(V,'docker',side_effect=[expected,'Signer #1 certificate SHA-256 digest: '+V.SIGNER]):
            row=V.public_predecessor_signer();self.assertEqual(V.SIGNER,row['signer_sha256'])
        with mock.patch.object(V,'docker',return_value='wrong'),self.assertRaises(ValueError):V.public_predecessor_signer()
        text=Path(V.__file__).read_text()
        self.assertNotIn('keytool',text);self.assertNotIn('debug.keystore").read',text)

    def test_stdout_only_plan_proposal_does_not_create_plan_output_or_staged_source(self):
        before=[p.exists() for p in (V.PLAN,V.OUT)]
        with tempfile.TemporaryDirectory() as temporary,\
             mock.patch.object(V,'PLAN',Path(temporary)/'fresh-plan.json'),\
             mock.patch.object(V,'tools_identity',return_value={'mocked':True}),\
             mock.patch.object(V,'docker',return_value=''),\
             mock.patch.object(V,'tool_hashes',return_value={'mocked':'a'*64}),\
             mock.patch.object(V,'keystore_metadata',return_value={'mocked':True}),\
             mock.patch.object(V,'public_predecessor_signer',return_value={'mocked':True}),\
             mock.patch.object(V,'host_resources',return_value={'mocked':True}),\
             mock.patch.object(V,'tree_records',return_value={'mocked':True}),\
             mock.patch('sys.stdout',new_callable=io.StringIO) as stdout:
            V.create_plan();value=json.loads(stdout.getvalue())
        self.assertEqual(41,value['expected_actual_jvm_count']);self.assertEqual(8,value['expected_actual_jvm_suites'])
        self.assertEqual(16,len(value['exact_activities']));self.assertEqual(14,len(value['exact_launchers']))
        self.assertIn('no Android delayed task-close',value['capture_escape_semantics'])
        self.assertEqual(before,[p.exists() for p in (V.PLAN,V.OUT)])

    def test_no_unreviewed_build_without_explicit_flag_or_plan_hash(self):
        with mock.patch('sys.argv',['helper','build']),mock.patch.object(V,'build') as build:
            with self.assertRaises(ValueError):V.main()
            build.assert_not_called()
        with self.assertRaises(ValueError):V.load_plan(None)

    def test_real_prior_compiled_xml_format_parses_but_cannot_qualify_new16(self):
        text=(V.OLD/'compiled-manifest.txt').read_text()
        root=V.parse_compiled_xml(text)
        self.assertEqual('org.wonad.fixture',root['attrs']['package'])
        with self.assertRaises(ValueError):V.audit_compiled_manifest(manifests(),text)

    def test_synthetic_new16_manifest14launchers_exact_flags_permissions_pass(self):
        actual=V.audit_compiled_manifest(manifests(),synthetic_compiled_xml())
        self.assertEqual(3,len(actual['exact_capture_components']))
        self.assertEqual(4,len(actual['permissions']))

    def test_hostile_compiled_xml_duplicate_shared_uid_wrong_flag_permission_fail(self):
        text=synthetic_compiled_xml()
        changes=[text.replace('A: package="org.wonad.fixture" (Raw: "org.wonad.fixture")',
            'A: package="org.wonad.fixture" (Raw: "org.wonad.fixture")\n    A: package="foreign" (Raw: "foreign")'),
            text.replace('A: versionCode=1','A: versionCode=1\n    A: sharedUserId="android.uid.system" (Raw: "android.uid.system")'),
            text.replace('A: documentLaunchMode=2','A: documentLaunchMode=1',1),
            text.replace('android.permission.CAPTURE_KEYBOARD','android.permission.INJECT_EVENTS'),
            text+'  E: manifest (line=2)\n']
        for bad in changes:
            with self.assertRaises(ValueError):V.audit_compiled_manifest(manifests(),bad)

    def test_real_prior_dex_checksum_class_inventory_preserved(self):
        classes=V.dex_classes(V.OLD/'fixture.apk')
        self.assertEqual(1104,len(classes));self.assertIn('Lorg/wonad/fixture/FixtureKeyJournal;',classes)
        self.assertIn('Lorg/wonad/fixture/BandedPaletteActivity$onCreate$1;',classes)

    def test_capture_dex_real_class_chunk_and_public_method_strings_required(self):
        rows={'KeyboardCaptureActivity':['dispatchKeyEvent','requestCapture','dump'],
            'KeyboardCaptureCounters':['observe','snapshot','clear'],
            'PublicKeyboardCaptureRequest':['request','setKeyboardCaptureEnabled','hasKeyboardCapture']}
        classes=[];chunks=[]
        for i,(name,methods) in enumerate(rows.items()):
            descriptor='Lorg/wonad/fixture/'+name+';';classes.append(descriptor)
            chunks.append("Class #"+str(i)+" -\nClass descriptor : '"+descriptor+"'\n"+'\n'.join(methods))
        dump='\n'.join(chunks)
        self.assertTrue(V.audit_capture_dex(dump,classes)['real_methods_and_public_reflection_strings_observed'])
        for bad in (dump.replace('hasKeyboardCapture','foreign'),dump.replace('dispatchKeyEvent','foreign')):
            with self.assertRaises(ValueError):V.audit_capture_dex(bad,classes)

    def test_synthetic_exact41_eight_real_report_shape_fails_skips_changed_names(self):
        expected=V.expected_tests(V.source_inventory())
        with tempfile.TemporaryDirectory() as root:
            p=Path(root);suites={}
            for row in expected:
                suite,name=row.rsplit('.',1);suites.setdefault(suite,[]).append(name)
            for suite,names in suites.items():
                node=ET.Element('testsuite',tests=str(len(names)),failures='0',errors='0',skipped='0')
                for name in names:ET.SubElement(node,'testcase',classname=suite,name=name)
                ET.ElementTree(node).write(p/('TEST-'+suite+'.xml'))
            self.assertEqual(41,V.audit_jvm(p,expected)['tests'])
            f=next(p.glob('TEST-*.xml'));node=ET.parse(f).getroot()
            ET.SubElement(node.find('testcase'),'skipped');ET.ElementTree(node).write(f)
            with self.assertRaises(ValueError):V.audit_jvm(p,expected)

    def test_future_build_vendor_guard_fail_closed_not_key_generation(self):
        with mock.patch.object(V,'require_no_vendor',side_effect=ValueError('vendorlive')),\
             mock.patch.object(V,'load_plan') as load:
            with self.assertRaises(ValueError):V.build('a'*64)
            load.assert_not_called()
        text=Path(V.__file__).read_text()
        self.assertIn('keystore_metadata_local() == task',text)
        self.assertIn('whole_memory_unbounded=True',text)
        self.assertNotIn("['docker', 'stop'",text)
        self.assertIn('os.killpg(child.pid, signal.SIGTERM)',text)

    def test_actual_vendor_helper_generator_bridge_process_names_fail_before_tools_access(self):
        commands=[b'/usr/bin/python3\0/u/elric/tree/wonad/android/tools/run_frankel_vendor.py\0--run\0',
            b'/bin/bash\0/wonad/android/platform/generate-frankel-vendor.sh\0',
            b'/bin/bash\0/u/elric/tree/prepare-phase1-frankel-vendor-cache-20261012-10.sh\0--run\0']
        for raw in commands:
            with tempfile.TemporaryDirectory() as root:
                p=Path(root)/'987654';p.mkdir();(p/'cmdline').write_bytes(raw)
                with mock.patch.object(Path,'iterdir',return_value=[p]),\
                     mock.patch.object(V,'command') as command:
                    with self.assertRaisesRegex(ValueError,'Vendor lane'):V.require_no_vendor()
                    command.assert_not_called()

    def test_oversized_malformed_process_refuses_but_empty_kernel_and_normal_sleep_are_allowed(self):
        for raw in (b'x'*65537,b'/usr/bin/python3'):
            with tempfile.TemporaryDirectory() as root:
                p=Path(root)/'987654';p.mkdir();(p/'cmdline').write_bytes(raw)
                with mock.patch.object(Path,'iterdir',return_value=[p]),\
                     mock.patch.object(V,'command') as command:
                    with self.assertRaises(ValueError):V.require_no_vendor()
                    command.assert_not_called()
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'987654';p.mkdir();(p/'cmdline').write_bytes(b'')
            with mock.patch.object(Path,'iterdir',return_value=[p]),\
                 mock.patch.object(V,'command',return_value='PID PPID COMMAND\n123 12 sleep infinity'):
                V.require_no_vendor()

    def test_previous_signer_badging_and_band_journal_audit_is_preserved(self):
        plan={'exact_activities':['org.wonad.fixture.BandedOneActivity'],
              'exact_launchers':['org.wonad.fixture.BandedOneActivity']}
        cert='Signer #1 certificate SHA-256 digest: '+V.SIGNER
        badging=("package: name='org.wonad.fixture' versionCode='1'\nminSdkVersion:'30'\n"
                 "targetSdkVersion:'35'\napplication-debuggable\n"
                 "launchable-activity: name='org.wonad.fixture.BandedOneActivity'\n")
        dump=("Class #0 -\nClass descriptor : 'Lorg/wonad/fixture/BandedPaletteActivity$onCreate$1;'\n"
              "setDefaultFocusHighlightEnabled:(Z)V\nsetFocusableInTouchMode:(Z)V\n"
              "Class #1 -\nClass descriptor : 'Lorg/wonad/fixture/FixtureKeyJournal;'\nobserve\nsnapshot\n")
        classes=['Lorg/wonad/fixture/BandedOneActivity;','Lorg/wonad/fixture/FixtureKeyJournal;','Loriginal/Keep;']
        self.assertTrue(V.audit_apk(plan,cert,badging,dump,classes,['Loriginal/Keep;'])['compiled_journal_present'])
        for index,value in ((1,cert.replace(V.SIGNER,'0'*64)),
                           (2,badging.replace("versionCode='1'","versionCode='2'")),
                           (3,dump.replace('setDefaultFocusHighlightEnabled','foreign')),
                           (4,classes[:-1])):
            args=[plan,cert,badging,dump,classes,['Loriginal/Keep;']];args[index]=value
            with self.assertRaises(ValueError):V.audit_apk(*args)

    def test_bad_original_dex_checksum_or_shape_still_fails(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'bad.apk'
            with zipfile.ZipFile(p,'w') as z:z.writestr('classes.dex',b'not dex')
            with self.assertRaisesRegex(ValueError,'DEX header'):V.dex_classes(p)
            with zipfile.ZipFile(p,'w') as z:z.writestr('classes1.dex',b'not dex')
            with self.assertRaisesRegex(ValueError,'DEX member'):V.dex_classes(p)

    def test_unreadable_process_is_not_silently_skipped(self):
        row=Path('/proc/987654')
        with mock.patch.object(Path,'iterdir',return_value=[row]),\
             mock.patch.object(Path,'open',side_effect=PermissionError('unreadable')),\
             mock.patch.object(V,'command') as command:
            with self.assertRaises(PermissionError):V.require_no_vendor()
            command.assert_not_called()

    def test_readonly_resource_proposal_does_not_claim512m_heap_is_container_cap(self):
        source=Path(V.__file__).read_text()
        self.assertIn('concurrency_adequacy_proven=False',source)
        self.assertIn('existing_tools_cgroup_memory_cap=None',source)
        self.assertIn('vendor_overlap_authorized=False',source)
        self.assertIn('compile_adequacy_measured=False',source)
        self.assertNotIn('docker update',source)


if __name__=='__main__':unittest.main(verbosity=2)
