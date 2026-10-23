"""Literal bridge/parser/freshness/pin tests only; no producer execute/admission."""
import copy
import hashlib
import importlib.util
import io
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr

EVIDENCE = Path('/u/elric/tree/wonad-phase1-build-evidence')
OLD = EVIDENCE / 'prepare-phase1-frankel-vendor-cache-20261012-8.sh'
BRIDGE = EVIDENCE / 'prepare-phase1-frankel-vendor-cache-20261012-9.sh'
REPO = Path('/u/elric/tree/wonad')
HELPER_SHA = 'bf2e9ff0a1f71a0586038245e646865f3ea4fc25bbc0fdebb1cf54e6eb721d4b'
OLD_SHA = '9e2c4fac586f4abe76946d90e7b348bb0c6f7ec2f11c61c983a2607890aafe2a'
RENDERER = EVIDENCE / 'phase1-frankel-vendor-resource48-proposal-20261012-1/render_resource_proposal.py'

spec = importlib.util.spec_from_file_location('g9_planned_resource_renderer', RENDERER)
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)
planned = renderer.candidate_bytes()
if hashlib.sha256(planned).hexdigest() != HELPER_SHA:
    raise AssertionError('Reviewed planned48 helper identity changed')
vendor = types.ModuleType('g9_reviewed_planned_vendor')
vendor.__file__ = str(REPO / 'android/tools/run_frankel_vendor.py')
sys.modules[vendor.__name__] = vendor
exec(compile(planned, vendor.__file__, 'exec'), vendor.__dict__)

def tokens(path=BRIDGE):
    source = path.read_text()
    if source.count('\nexec ') != 1:
        raise ValueError('Expected one literal exec line')
    return shlex.split(source.split('\nexec ',1)[1].replace('\\\n',''))

def args(action='--check-only', path=BRIDGE):
    invocation = tokens(path)
    if invocation[:4] != ['/usr/bin/python3.14','-B',str(REPO/'android/tools/run_frankel_vendor.py'),'$1']:
        raise ValueError('Interpreter/helper/action scope differs')
    return vendor.build_parser().parse_args([action,*invocation[4:]])

class Generation9BridgeTests(unittest.TestCase):
    def test_original_bridge_preserved_and_exact_allowed_literal_delta(self):
        self.assertEqual(OLD_SHA, hashlib.sha256(OLD.read_bytes()).hexdigest())
        expected = OLD.read_text()
        replacements = (
            ('# Generation-8 bridge','# Generation-9 bridge'),
            ('prepare-phase1-frankel-vendor-cache-20261012-8.sh','prepare-phase1-frankel-vendor-cache-20261012-9.sh'),
            ('phase1-frankel-vendor-cache-work-20261012-7','phase1-frankel-vendor-cache-work-20261012-8'),
            ('phase1-frankel-baseline-vendor-cache-20261012-8','phase1-frankel-baseline-vendor-cache-20261012-9'),
            ('wonad-phase1-frankel-vendor-2026100600-008','wonad-phase1-frankel-vendor-2026100600-009'),
            ('android/tools/run_frankel_vendor.py=fa249edee74eb0c48e1a340cebad1496c25df659f69af0f6d237d8147a7bbe0b',
             'android/tools/run_frankel_vendor.py='+HELPER_SHA))
        for old,new in replacements:
            self.assertIn(old,expected)
            expected=expected.replace(old,new)
        self.assertEqual(expected,BRIDGE.read_text())

    def test_bash_syntax_only(self):
        result=subprocess.run(['/usr/bin/bash','-n',str(BRIDGE)],capture_output=True,timeout=5)
        self.assertEqual(0,result.returncode,result.stderr)

    def test_shell_rejects_unknown_or_multiple_actions_before_helper(self):
        for extra in (['--unknown'],['--run','--check-only'],['--run','arbitrary-command']):
            result=subprocess.run(['/usr/bin/bash',str(BRIDGE),*extra],capture_output=True,timeout=5)
            self.assertEqual(2,result.returncode)
            self.assertEqual(b'',result.stdout)
            self.assertTrue(b'refusing' in result.stderr or b'usage:' in result.stderr)

    def test_default_action_stays_check_only_no_arbitrary_forwarding(self):
        source=BRIDGE.read_text()
        self.assertIn('if (($# == 0)); then\n  set -- --check-only\nfi',source)
        self.assertIn('if (($# != 1)); then',source)
        self.assertNotIn('"$@"',source)
        self.assertNotIn('eval ',source)
        self.assertNotIn('$(',source)
        for action in ('--check-only','--run'):
            config=vendor.config_from_args(args(action))
            self.assertEqual(action=='--run',config.run)
            self.assertEqual(action=='--check-only',config.check_only)

    def test_exact_source_builder_cache_and_debug_identities_preserved(self):
        old,new=args(path=OLD),args()
        unchanged=('source','repo','builder_image','adevtool_commit','cache','cache_receipt',
                   'cache_receipt_sha256','archive_name','factory_build_id','archive_sha256',
                   'archive_bytes','debug_id','debug_proof','debug_proof_sha256','source_input')
        for name in unchanged:
            self.assertEqual(getattr(old,name),getattr(new,name),name)
        self.assertEqual('sha256:f719a4a56095b613790ef9afcba2aabda795217ac98e08c24ba5cec65bd4ee33',new.builder_image)
        self.assertEqual(Path('/u/elric/tree/wonad-grapheneos-2026100600-frankel-baseline-1'),new.source)
        self.assertEqual(11378664978,new.archive_bytes)

    def test_parser_exact_required_pin_sets_and_planned_helper(self):
        config=vendor.config_from_args(args())
        self.assertEqual(set(vendor.REQUIRED_REPO_INPUTS),set(config.repo_inputs))
        self.assertEqual(set(vendor.REQUIRED_SOURCE_INPUTS),set(config.source_inputs))
        self.assertEqual(HELPER_SHA,config.repo_inputs['android/tools/run_frankel_vendor.py'])
        self.assertEqual(48*1024**3,vendor.MEMORY)
        self.assertEqual(42*1024**3,vendor.MIN_MEM_AVAILABLE)
        self.assertEqual(14,len(vendor.EXPECTED_ADEVTOOL_TARGETS))
        self.assertNotIn('ADEVTOOL_SKIP_DEP_BUILD=1',vendor.builder_environment(config))
        self.assertFalse(any(item.startswith(('GOMEMLIMIT=','GOGC=','SOONG_PARTIAL_ANALYSIS='))
                             for item in vendor.builder_environment(config)))

    def test_all_other_current_live_pins_match_bounded_named_files(self):
        config=vendor.config_from_args(args())
        for root,inputs in ((config.repo,config.repo_inputs),(config.source,config.source_inputs)):
            for relative,digest in inputs.items():
                if relative=='android/tools/run_frankel_vendor.py':
                    continue  # Planned helper intentionally awaits actual integration; separate test below.
                with self.subTest(relative=relative):
                    self.assertEqual(digest,hashlib.sha256((root/relative).read_bytes()).hexdigest())
        for path,digest in ((config.cache_receipt,config.cache_receipt_sha256),
                            (config.debug_proof,config.debug_proof_sha256)):
            self.assertEqual(digest,hashlib.sha256(path.read_bytes()).hexdigest())

    def test_actual_repository_helper_pin_gate_is_not_waived(self):
        config=vendor.config_from_args(args())
        actual=hashlib.sha256((config.repo/'android/tools/run_frankel_vendor.py').read_bytes()).hexdigest()
        expected=config.repo_inputs['android/tools/run_frankel_vendor.py']
        # If48 is not integrated yet, the real capture gate MUST reject it; this is NOT a ready claim.
        if actual!=expected:
            with self.assertRaisesRegex(vendor.Refusal,'repository input differs'):
                vendor.captured_inventory(config.repo,config.repo_inputs,'repository')
        else:
            references,_=vendor.captured_inventory(config.repo,config.repo_inputs,'repository')
            self.assertEqual(expected,references['android/tools/run_frankel_vendor.py']['sha256'])
        for digest in ('fa249edee74eb0c48e1a340cebad1496c25df659f69af0f6d237d8147a7bbe0b',
                       '3c26be80b3f5bb0bbc747811e9d4f40780800897211ad559632193e96bbb5d05'):
            self.assertNotEqual(expected,digest)

    def test_fresh_exact_outputs_and_namespace(self):
        config=vendor.config_from_args(args())
        expected={
            'work':'phase1-frankel-vendor-cache-work-20261012-8',
            'log':'phase1-frankel-baseline-vendor-cache-20261012-9.log',
            'preflight':'phase1-frankel-baseline-vendor-cache-20261012-9.preflight.json',
            'result':'phase1-frankel-baseline-vendor-cache-20261012-9.result.json',
            'attempt_lock':'phase1-frankel-baseline-vendor-cache-20261012-9.lock.json'}
        for name,basename in expected.items():
            path=getattr(config,name)
            self.assertEqual(EVIDENCE/basename,path)
            vendor.fresh(path)  # Read-only lstat/fresh-path validation, not execute().
        self.assertEqual('wonad-phase1-frankel-vendor-2026100600-009',config.container)
        self.assertEqual(len(expected),len({getattr(config,name) for name in expected}))

    def test_any_existing_file_directory_or_symlink_is_not_fresh(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for name,kind in (('file','file'),('dir','dir'),('link','link')):
                path=root/name
                if kind=='file': path.write_text('fixture')
                elif kind=='dir': path.mkdir()
                else: path.symlink_to(root/'missing')
                with self.subTest(kind=kind),self.assertRaises(vendor.Refusal):
                    vendor.fresh(path)

    def test_parser_rejects_conflicting_duplicate_or_inside_source_outputs(self):
        invocation=tokens()[4:]
        with redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
            vendor.build_parser().parse_args(['--run','--check-only',*invocation])
        config=args(); config.log=config.work
        with self.assertRaisesRegex(vendor.Refusal,'distinct'):
            vendor.config_from_args(config)
        config=args(); config.work=config.source/'must-not-be-created'
        with self.assertRaisesRegex(vendor.Refusal,'outside'):
            vendor.config_from_args(config)

    def test_historical_work_and_results_remain_excluded(self):
        old,new=vendor.config_from_args(args(path=OLD)),vendor.config_from_args(args())
        for field in ('work','log','preflight','result','attempt_lock'):
            self.assertNotEqual(getattr(old,field),getattr(new,field))
        # Names/paths are distinct; neither the test nor bridge grants historical cleanup authority.
        self.assertNotEqual(old.container,new.container)
        self.assertIn('original40GiB', (Path(__file__).parent/'G8-CACHE-CUSTODY.md').read_text())

if __name__=='__main__':
    unittest.main(verbosity=2)
