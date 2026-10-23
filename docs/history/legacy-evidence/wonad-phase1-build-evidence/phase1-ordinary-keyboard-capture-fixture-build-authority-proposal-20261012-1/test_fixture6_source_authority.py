"""Bounded source proposal / synthetic XML tests only, never compile/inspect Docker."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

import fixture6_source_authority as V


class Fixture6AuthorityTests(unittest.TestCase):
    def test_actual_exact28_sources_retain22_originals_modify_one_add_five(self):
        sources=V.source_inventory()
        self.assertEqual(28,len(sources))
        self.assertEqual(5,len(set(V.OVERLAY)-set(V.BASE)))
        self.assertEqual({'android/fixture/src/main/AndroidManifest.xml'},set(V.OVERLAY)&set(V.BASE))
        for name,record in sources.items():
            parent=V.CANDIDATE/'candidate' if name in V.OVERLAY else V.ROOT
            self.assertEqual(str(parent/name),record['path'])
            self.assertEqual((V.OVERLAY if name in V.OVERLAY else V.BASE)[name]['sha256'],record['sha256'])

    def test_current_settings_actual_old_fixture5_rejects_new_private_isolation_is_exact(self):
        source=V.regular_bytes(V.ROOT/'android/settings.gradle.kts')
        spec=importlib.util.spec_from_file_location('fixture5_read_only',V.ROOT/'android/fixture/build-fixture5.py')
        old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
        with self.assertRaisesRegex(ValueError,'Original settings module inventory changed'):
            old.fixture_settings(source.decode())
        actual=V.settings_adaptation(source).decode()
        self.assertEqual(source.decode().split('include(":probe")',1)[0]+'include(":fixture")\n',actual)
        self.assertNotIn('include(":conformance")',actual)
        self.assertNotIn('include(":styx-',actual)
        self.assertIn('repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)',actual)

    def test_settings_hash_rejects_extra_config_or_repository_change(self):
        source=V.regular_bytes(V.ROOT/'android/settings.gradle.kts')
        for changed in (source+b'\napply(from="foreign")\n',source.replace(b'google()',b'mavenLocal()')):
            with self.subTest(changed=changed[-24:]),self.assertRaises(ValueError):
                V.settings_adaptation(changed)

    def test_observed41_exact_test_methods_in8_source_suites(self):
        cases=V.expected_tests(V.source_inventory())
        self.assertEqual(41,len(cases));self.assertEqual(8,len({name.rsplit('.',1)[0] for name in cases}))
        self.assertEqual(6,sum('.KeyboardCaptureCountersTest.' in name for name in cases))
        self.assertEqual(7,sum('.PublicKeyboardCaptureRequestTest.' in name for name in cases))
        self.assertEqual(3,sum('.FixtureKeyJournalTest.' in name for name in cases))
        self.assertEqual(3,sum('.BandedPaletteFixtureContractTest.' in name for name in cases))

    def test_sixteen_activities_fourteen_launchers_three_distinct_document_tasks(self):
        data=V.regular_bytes(V.CANDIDATE/'candidate/android/fixture/src/main/AndroidManifest.xml')
        manifest=V.manifest_inventory(data)
        self.assertEqual(16,len(manifest['activities']));self.assertEqual(14,len(manifest['launchers']))
        self.assertEqual(3,len(manifest['capture_components']))
        self.assertEqual(3,len({row['task_affinity'] for row in manifest['capture_components']}))

    def test_manifest_missing_duplicate_or_nonordinary_capture_shape_rejected(self):
        data=V.regular_bytes(V.CANDIDATE/'candidate/android/fixture/src/main/AndroidManifest.xml')
        changes=[]
        root=ET.fromstring(data);row=root.find('./application/activity')
        root.find('application').append(copy.deepcopy(row));changes.append(ET.tostring(root))
        root=ET.fromstring(data);root.set(V.ATTR+'sharedUserId','android.uid.system');changes.append(ET.tostring(root))
        root=ET.fromstring(data);root.set('package','foreign');changes.append(ET.tostring(root))
        root=ET.fromstring(data)
        row=next(p for p in root.findall('./application/activity') if p.get(V.ATTR+'name')=='.KeyboardCaptureOneActivity')
        row.set(V.ATTR+'documentLaunchMode','never');changes.append(ET.tostring(root))
        for changed in changes:
            with self.subTest(changed=changed[:32]),self.assertRaises(ValueError):V.manifest_inventory(changed)

    def test_candidate_pin_mismatch_refuses_source_proposal(self):
        changed=copy.deepcopy(V.OVERLAY);changed[next(iter(changed))]['sha256']='0'*64
        with mock.patch.object(V,'OVERLAY',changed),self.assertRaises(ValueError):V.source_inventory()

    def test_original_pin_or_inventory_mismatch_refuses_source_proposal(self):
        changed=copy.deepcopy(V.BASE);changed['android/build.gradle.kts']['sha256']='0'*64
        with mock.patch.object(V,'BASE',changed),self.assertRaises(ValueError):V.source_inventory()
        changed=copy.deepcopy(V.BASE);changed['foreign.kt']={'bytes':1,'sha256':'0'*64}
        with mock.patch.object(V,'BASE',changed),self.assertRaises(ValueError):V.source_inventory()

    def test_bounded_regular_reader_rejects_symlink_fifo_empty_oversize(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);normal=root/'normal';normal.write_bytes(b'public')
            link=root/'link';link.symlink_to(normal)
            empty=root/'empty';empty.write_bytes(b'')
            huge=root/'huge';huge.write_bytes(b'x'*(V.LIMIT+1))
            fifo=root/'fifo';V.os.mkfifo(fifo)
            self.assertEqual(b'public',V.regular_bytes(normal))
            for path in (link,empty,huge,fifo):
                with self.subTest(path=path.name),self.assertRaises((ValueError,OSError)):
                    V.regular_bytes(path)

    def xml_reports(self,root,expected):
        grouped={}
        for row in expected:
            suite,method=row.rsplit('.',1);grouped.setdefault(suite,[]).append(method)
        for suite,names in grouped.items():
            node=ET.Element('testsuite',tests=str(len(names)),failures='0',errors='0',skipped='0')
            for name in names:ET.SubElement(node,'testcase',classname=suite,name=name)
            ET.ElementTree(node).write(root/('TEST-'+suite+'.xml'))

    def test_synthetic_reports_all41_exact_identities_pass_but_are_not_real_compile(self):
        expected=V.expected_tests(V.source_inventory())
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.xml_reports(root,expected)
            actual=V.audit_future_jvm(root,expected)
            self.assertEqual(expected,actual['actual_cases']);self.assertEqual(41,actual['tests'])

    def test_synthetic_report_skip_duplicate_case_or_missing_suite_refused(self):
        expected=V.expected_tests(V.source_inventory())
        for hostile in ('skip','duplicate','missing'):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);self.xml_reports(root,expected);path=next(root.glob('TEST-*.xml'))
                if hostile=='missing':path.unlink()
                else:
                    node=ET.parse(path).getroot()
                    if hostile=='skip':ET.SubElement(node.find('testcase'),'skipped')
                    else:
                        node.append(copy.deepcopy(node.find('testcase')))
                        node.set('tests',str(len(node.findall('testcase'))))
                    ET.ElementTree(node).write(path)
                with self.subTest(hostile=hostile),self.assertRaises(ValueError):V.audit_future_jvm(root,expected)

    def test_proposal_does_not_fake_tools_build_image_runtime_authority(self):
        actual=V.proposal()
        self.assertFalse(actual['actual_compile_reports_observed'])
        self.assertFalse(actual['build_started']);self.assertFalse(actual['guest_started'])
        self.assertFalse(actual['keys_generated']);self.assertFalse(actual['runtime_qualified'])
        self.assertEqual('PENDING',actual['build_helper']['sha256'])
        self.assertTrue(all(value.startswith('PENDING') for value in actual['actual_tools'].values()))
        self.assertEqual('/work/native-keyboard-capture-fixture6-root',actual['paths']['proposed_remote'])
        self.assertNotIn('/work/android',actual['future_gradle_argv'])
        self.assertIn('--offline',actual['future_gradle_argv'])

    def test_only_stdout_source_proposal_has_no_execution_or_write_code(self):
        text=Path(V.__file__).read_text()
        for forbidden in ('import subprocess','import shutil','Popen(','check_output(','write_text(','write_bytes(',
                          'docker exec','docker cp','docker run','docker build','killpg('):
            self.assertNotIn(forbidden,text)
        self.assertIn("args.source_proposal",text)
        self.assertIn("'build_started':False",text)

    def test_unique_json_rejects_duplicate_authority_members(self):
        with self.assertRaises(ValueError):V.unique_json(b'{"source":1,"source":2}')


if __name__=='__main__':
    unittest.main(verbosity=2)
