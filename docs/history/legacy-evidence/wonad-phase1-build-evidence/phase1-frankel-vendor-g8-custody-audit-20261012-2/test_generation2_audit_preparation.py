"""Read-only preparation controls; never execute audit main/Docker/cache actions."""
import ast
import hashlib
from pathlib import Path
import unittest

BASE = Path('/u/elric/tree/wonad-phase1-build-evidence')
OLD = BASE/'phase1-frankel-vendor-g8-custody-audit-20261012-1'
NEW = BASE/'phase1-frankel-vendor-g8-custody-audit-20261012-2'
SHA = '7c36b6defd19f792eafdaee9f0e5fd9638eeb185395a7105a6574d6a0ea63179'
OUTPUTS = ('actual-custody-observation.json','docker-inspect-exact-g8.json','custody-seal.json')

class FreshAuditPreparationTests(unittest.TestCase):
    def test_source_is_exact_original_behavior_with_only_new_path(self):
        old=(OLD/'audit_g8_custody.py').read_bytes()
        new=(NEW/'audit_g8_custody.py').read_bytes()
        self.assertEqual(SHA,hashlib.sha256(old).hexdigest())
        self.assertEqual(SHA,hashlib.sha256(new).hexdigest())
        self.assertEqual(old,new)
        ast.parse(new)

    def test_actual_evidence_output_paths_are_fresh_and_original_preserved(self):
        for name in OUTPUTS:
            with self.subTest(name=name):
                self.assertFalse((NEW/name).exists())
                self.assertFalse((NEW/name).is_symlink())
                self.assertTrue((OLD/name).is_file())
        self.assertEqual('2e224e2d9f099efaae167141abf6df1a60048e910083ed91a7793338f10d24be',
                         hashlib.sha256((OLD/'custody-seal.json').read_bytes()).hexdigest())

    def test_exact_historical_inputs_and_read_only_command_unchanged(self):
        text=(NEW/'audit_g8_custody.py').read_text()
        self.assertIn("CANDIDATE_SHA = '3c26be80b3f5bb0bbc747811e9d4f40780800897211ad559632193e96bbb5d05'",text)
        self.assertIn("CID = '79dbd12fcdd9371bb1616bbc1d87c07d788eddf11f8a6e56a3d613ab8d30260b'",text)
        self.assertIn("NONCE = 'e1569c2277e85705b31b81829a71c89cc24a8e57b46028a72693cd0a6e193c06'",text)
        self.assertIn("'container','inspect',CID]",text)
        self.assertIn('vendor.validate_container(info,config,CID,NONCE,stopped=True)',text)
        self.assertIn('fcntl.LOCK_SH|fcntl.LOCK_NB',text)
        self.assertIn('vendor.MEMORY!=40*1024**3',text)
        tree=ast.parse(text)
        dangerous={'execute','initial_inputs','resources','clean_vendor_cache','rmtree','unlink','rmdir'}
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute):
                self.assertNotIn(node.func.attr,dangerous)

if __name__=='__main__':
    unittest.main(verbosity=2)
