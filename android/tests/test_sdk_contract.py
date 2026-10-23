import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ANDROID = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANDROID / 'tools'))
from sdk_contract import aidl_contract, audit, audit_additive, normalize, snapshot, without_comments, BASELINE


class SdkContract(unittest.TestCase):
    def setUp(self):
        self.baseline = json.loads((ANDROID / 'tests/fixtures/desktop-sdk-contract-v3.json').read_text())

    def changed_source(self, filename, transform):
        original = Path.read_text

        def changed(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            return transform(value) if path.name == filename else value

        with patch.object(Path, 'read_text', changed):
            return snapshot(ANDROID / 'desktop-sdk')

    def test_current_sdk_matches_review_candidate(self):
        candidate = json.loads(BASELINE.read_text())
        self.assertEqual([], audit(snapshot(ANDROID / 'desktop-sdk'), candidate))
        self.assertEqual([], audit_additive(candidate, self.baseline))

    def test_additive_gate_rejects_old_wire_constant_or_jvm_member_changes(self):
        candidate = json.loads(BASELINE.read_text())
        for mutate in (
            lambda c: c['constants'].__setitem__('COMMAND_TRANSFER', '17'),
            lambda c: c['aidl']['IDesktopSession.aidl']['declarations'].reverse(),
            lambda c: c['jvm_abi']['classes']['org/wonad/desktop/api/DesktopProtocol']['fields'].pop(0)):
            with self.subTest(mutate=mutate):
                changed = copy.deepcopy(candidate); mutate(changed)
                self.assertTrue(audit_additive(changed, self.baseline))

    def test_reordered_binder_methods_are_incompatible(self):
        changed = copy.deepcopy(self.baseline)
        methods = changed['aidl']['IDesktopSession.aidl']['declarations']
        methods[0], methods[1] = methods[1], methods[0]
        self.assertTrue(audit(changed, self.baseline))

    def test_generated_binder_transaction_map_is_frozen(self):
        self.assertEqual(
            ['getApiVersion', 'getCapabilities', 'openSession'],
            [row['method'] for row in self.baseline['binder_transactions'][
                'org.wonad.desktop.api.IDesktopBroker']])
        self.assertEqual(
            ['applyFrame', 'focusTask', 'closeTask', 'enableShortcuts', 'heartbeat',
             'release', 'enableExternalUi', 'showShell', 'launcherPage', 'showLauncher',
             'selectLauncher', 'showTransferPicker', 'applySignedFrame'],
            [row['method'] for row in self.baseline['binder_transactions'][
                'org.wonad.desktop.api.IDesktopSession']])
        for rows in self.baseline['binder_transactions'].values():
            self.assertEqual(list(range(len(rows))), [row['offset'] for row in rows])

    def test_signature_hash_covers_wire_constants_and_transactions(self):
        signed = {name: self.baseline[name] for name in
                  ('aidl', 'constants', 'binder_transactions', 'kotlin_api', 'jvm_abi')}
        digest = hashlib.sha256(json.dumps(signed, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(digest, self.baseline['signature_sha256'])

    def test_complete_public_jvm_abi_is_frozen(self):
        ledger = self.baseline['jvm_abi']
        self.assertEqual(1, ledger['schema'])
        self.assertEqual(38, len(ledger['class_files']))
        self.assertEqual(22, len(ledger['classes']))
        failure = ledger['classes']['org/wonad/desktop/api/DesktopFailure']
        self.assertIn(
            {'access': 17, 'name': 'describe',
             'descriptor': '(Ljava/lang/Throwable;)Ljava/lang/String;'},
            failure['methods'])
        for row in ledger['classes'].values():
            self.assertIn('fields', row)
            self.assertIn('methods', row)

    def test_desktop_failure_public_signature_change_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'Kotlin declaration missing from JVM ABI'):
            self.changed_source('DesktopFailure.kt', lambda source: source.replace(
                'fun describe(error: Throwable): String',
                'fun describe(error: Any): String'))

    def test_foreign_import_cannot_change_an_unqualified_wire_type(self):
        changed = copy.deepcopy(self.baseline)
        changed['aidl']['IDesktopSession.aidl']['imports'][0] = 'foreign.DesktopFrame'
        self.assertTrue(audit(changed, self.baseline))

    def test_parcel_field_type_order_and_removal_are_incompatible(self):
        for mutate in (lambda rows: rows.reverse(), lambda rows: rows.pop(),
                       lambda rows: rows.__setitem__(0, 'int topologyRevision')):
            changed = copy.deepcopy(self.baseline)
            mutate(changed['aidl']['DesktopFrame.aidl']['declarations'])
            self.assertTrue(audit(changed, self.baseline))

    def test_oneway_direction_nullability_and_new_rpc_require_review(self):
        for replacement in ('void heartbeat(long generation, long sequence)',
                            'oneway void applyFrame(long generation, long requestId, long baseRevision, out DesktopFrame frame)',
                            'DesktopLaunchPage launcherPage(long generation, long catalogId, long displayToken, int offset)'):
            changed = copy.deepcopy(self.baseline)
            changed['aidl']['IDesktopSession.aidl']['declarations'][0] = replacement
            self.assertTrue(audit(changed, self.baseline))
        changed = copy.deepcopy(self.baseline)
        changed['aidl']['IDesktopSession.aidl']['declarations'].append('oneway void newAuthority(long generation)')
        self.assertTrue(audit(changed, self.baseline))

    def test_capability_and_result_numbers_cannot_be_reused(self):
        for name in ('API_VERSION', 'CAP_SIGNED_PLACEMENT', 'RESULT_REVOKED',
                     'CLIENT_TIMEOUT_MILLIS', 'COMMAND_LAUNCH'):
            changed = copy.deepcopy(self.baseline)
            changed['constants'][name] = '999'
            self.assertTrue(audit(changed, self.baseline))

    def test_descriptor_sensitive_data_and_other_leading_annotations_require_review(self):
        for filename, declaration, annotation in (
                ('IDesktopSession.aidl', 'interface IDesktopSession',
                 '@Descriptor(value="foreign.wire.Identity")'),
                ('IDesktopSession.aidl', 'interface IDesktopSession', '@SensitiveData'),
                ('IDesktopSession.aidl', 'interface IDesktopSession', '@VintfStability'),
                ('DesktopRect.aidl', 'parcelable DesktopRect', '@FixedSize'),
                ('DesktopRect.aidl', 'parcelable DesktopRect', '@RustDerive(Clone=true, Eq=true)')):
            with self.subTest(annotation=annotation):
                actual = self.changed_source(filename,
                    lambda source: source.replace(declaration, annotation + '\n' + declaration))
                self.assertEqual([annotation], actual['aidl'][filename]['annotations'])
                self.assertTrue(audit(actual, self.baseline))

    def test_annotations_preserve_order_values_and_quoted_whitespace(self):
        source = ('package org.wonad.desktop.api;\n'
                  '@Descriptor(value="identity one")\n@SensitiveData\n'
                  'interface ITest { void heartbeat(); }')
        baseline = aidl_contract(source, 'ITest')
        for changed in (source.replace('identity one', 'identity  one'),
                        source.replace('identity one', 'identity two'),
                        source.replace('@Descriptor(value="identity one")\n@SensitiveData',
                                       '@SensitiveData\n@Descriptor(value="identity one")')):
            self.assertNotEqual(baseline, aidl_contract(changed, 'ITest'))
        self.assertNotEqual(normalize('"one two"'), normalize('"one  two"'))

    def test_quoted_comment_markers_braces_and_semicolons_are_not_syntax(self):
        annotation = '@Descriptor(value="https://host/a/*literal*/?x={one;two}")'
        source = ('package org.wonad.desktop.api;\n/* leading comment */\n' +
                  annotation + '\ninterface ITest {\n'
                  '  @JavaPassthrough(annotation="@Foo(value=\\"}; // data\\")") void heartbeat();\n'
                  '} // trailing comment\n')
        contract = aidl_contract(without_comments(source), 'ITest')
        self.assertEqual([annotation], contract['annotations'])
        self.assertEqual(1, len(contract['declarations']))
        self.assertIn('}; // data', contract['declarations'][0])
        self.assertEqual('in DesktopTask', normalize(without_comments('in/*comment*/DesktopTask')))

    def test_unexpected_prefix_trailing_content_and_nested_declarations_fail_closed(self):
        for transform in (
                lambda source: 'unexpected_token\n' + source,
                lambda source: source + '\ninterface Hidden { void surprise(); }',
                lambda source: source + '\nparcelable Hidden { int authority; }',
                lambda source: source + '\nimport foreign.Identity;',
                lambda source: source + '\n}',
                lambda source: source.replace('interface IDesktopSession',
                                             'package foreign;\ninterface IDesktopSession'),
                lambda source: source.replace('interface IDesktopSession',
                                             'unmodeled_modifier interface IDesktopSession'),
                lambda source: source.replace('interface IDesktopSession {',
                                             'interface IDesktopSession { parcelable Hidden { int x; }')):
            with self.subTest(transform=transform):
                with self.assertRaises(ValueError):
                    self.changed_source('IDesktopSession.aidl', transform)

    def test_unterminated_strings_comments_annotations_and_statement_groups_fail_closed(self):
        for annotation in ('@Descriptor(value="unfinished)', '@Descriptor(value="ok"',
                           '@Descriptor(value=["ok")', '@Descriptor(value={})'):
            with self.subTest(annotation=annotation):
                with self.assertRaises(ValueError):
                    self.changed_source('IDesktopSession.aidl',
                        lambda source: source.replace('interface IDesktopSession',
                                                     annotation + '\ninterface IDesktopSession'))
        with self.assertRaises(ValueError):
            self.changed_source('IDesktopSession.aidl', lambda source: source + '/* unfinished')
        for body in ('void call(long generation;', 'void call(long generation];',
                     'void call();;', 'void call()'):
            with self.subTest(body=body):
                with self.assertRaises(ValueError):
                    aidl_contract('package org.wonad.desktop.api; interface ITest { ' + body + ' }', 'ITest')

    def test_hidden_multiline_protocol_expressions_and_extra_objects_fail_closed(self):
        for transform in (
                lambda source: source.replace('const val API_VERSION = 3',
                                             'const val API_VERSION = 3\n        + 100'),
                lambda source: source + '\nobject Hidden { const val AUTHORITY = 1 }',
                lambda source: source.replace('const val API_VERSION = 3',
                                             'const val API_VERSION = 3\n    val unreviewedAuthority = 1')):
            with self.subTest(transform=transform):
                with self.assertRaises(ValueError):
                    self.changed_source('DesktopProtocol.kt', transform)

    def test_protocol_string_values_do_not_lose_comment_markers_or_whitespace(self):
        changed = self.changed_source('DesktopProtocol.kt',
            lambda source: source.replace('".ExternalShellActivity"', '"https://host/a/*literal*/ one  two"'))
        self.assertEqual('"https://host/a/*literal*/ one  two"', changed['constants']['SHELL_ACTIVITY'])
        self.assertTrue(audit(changed, self.baseline))

    def test_only_neutral_v3_public_names_remain(self):
        current = snapshot(ANDROID / 'desktop-sdk')
        self.assertEqual('3', current['constants']['API_VERSION'])
        forbidden = ('Native', 'DesktopLayout', 'DesktopWorkspace', 'NATIVE_API_VERSION')
        rendered = repr(current)
        for name in forbidden:
            self.assertNotIn(name, rendered)


if __name__ == '__main__':
    unittest.main()
