"""G10 literal bridge/profile/pin checks only; never execute its producer."""
import ast
import hashlib
import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import unittest

ROOT = Path('/u/elric/tree/wonad')
EVIDENCE = Path('/u/elric/tree/wonad-phase1-build-evidence')
REVIEW = Path(__file__).resolve().parent
BRIDGE = EVIDENCE / 'prepare-phase1-frankel-vendor-cache-20261012-10.sh'
OLD_BRIDGE = EVIDENCE / 'prepare-phase1-frankel-vendor-cache-20261012-9.sh'
SPEC = importlib.util.spec_from_file_location('g10_literal_vendor', ROOT / 'android/tools/run_frankel_vendor.py')
vendor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vendor)


def configuration(action='--check-only'):
    source = BRIDGE.read_text()
    words = shlex.split(source.split('\nexec ', 1)[1].replace('\\\n', ''))
    if words[:4] != ['/usr/bin/python3.14', '-B', str(ROOT / 'android/tools/run_frankel_vendor.py'), '$1']:
        raise ValueError('Unexpected helper invocation')
    return vendor.config_from_args(vendor.build_parser().parse_args([action, *words[4:]]))


class BridgeTests(unittest.TestCase):
    def test_exact_reviewed_bridge_and_original_retained(self):
        self.assertEqual('3dbea9385949b39e34e3078487ff171c4b08393d491953f78c3a0f7cfda716c2',
                         hashlib.sha256(OLD_BRIDGE.read_bytes()).hexdigest())
        self.assertEqual('fe8b40a2f1e466fe4935dd4a3391accee19a59024acafe7f3c9d1392b14b468c',
                         hashlib.sha256(BRIDGE.read_bytes()).hexdigest())

    def test_fresh_outputs_and_only_new_attempt_namespace(self):
        config = configuration()
        for field, name in (
            ('work', 'phase1-frankel-vendor-cache-work-20261012-9'),
            ('log', 'phase1-frankel-baseline-vendor-cache-20261012-10.log'),
            ('preflight', 'phase1-frankel-baseline-vendor-cache-20261012-10.preflight.json'),
            ('result', 'phase1-frankel-baseline-vendor-cache-20261012-10.result.json'),
            ('attempt_lock', 'phase1-frankel-baseline-vendor-cache-20261012-10.lock.json')):
            self.assertEqual(EVIDENCE / name, getattr(config, field))
            self.assertFalse(os.path.lexists(getattr(config, field)))
        self.assertEqual('wonad-phase1-frankel-vendor-2026100600-010', config.container)

    def test_all_nine_repository_and_twelve_source_inputs_match(self):
        config = configuration()
        self.assertEqual(9, len(config.repo_inputs))
        self.assertEqual(12, len(config.source_inputs))
        for root, inventory in ((config.repo, config.repo_inputs), (config.source, config.source_inputs)):
            for relative, digest in inventory.items():
                self.assertEqual(digest, hashlib.sha256((root / relative).read_bytes()).hexdigest(), relative)

    def test_frozen_after_files_match_actual_generator_and_runner(self):
        for relative, name in (
            ('android/platform/generate-frankel-vendor.sh', 'generate-frankel-vendor-after.sh'),
            ('android/tools/run_frankel_vendor.py', 'run-frankel-vendor-after.py'),
            ('android/tests/test_adevtool_dependency_handoff.py', 'test-adevtool-dependency-handoff.py'),
            ('android/tests/test_run_frankel_vendor.py', 'test-run-frankel-vendor-after.py')):
            self.assertEqual((ROOT / relative).read_bytes(), (REVIEW / name).read_bytes())

    def test_container_profile_and_payload_functions_are_byte_equivalent_ast(self):
        before = ast.parse((REVIEW / 'run-frankel-vendor-before.py').read_text())
        after = ast.parse((ROOT / 'android/tools/run_frankel_vendor.py').read_text())
        names = {'builder_environment', 'payload', 'create_command', '_expected_mounts',
                 'validate_container', 'resources', 'require_successful_stopped_build'}
        def selected(tree):
            return {node.name: ast.dump(node, include_attributes=False) for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name in names}
        self.assertEqual(names, set(selected(before)))
        self.assertEqual(selected(before), selected(after))
        config = configuration()
        self.assertEqual(48 * 1024**3, vendor.MEMORY)
        self.assertEqual(42 * 1024**3, vendor.MIN_MEM_AVAILABLE)
        self.assertFalse(any(value.startswith('ADEVTOOL_SKIP_DEP_BUILD=')
                             for value in vendor.builder_environment(config)))

    def test_bash_syntax_and_unsupported_arguments_fail_before_helper(self):
        self.assertEqual(0, subprocess.run(['/usr/bin/bash', '-n', str(BRIDGE)],
                                          capture_output=True, timeout=5).returncode)
        for arguments in (['--unknown'], ['--run', '--check-only']):
            result = subprocess.run(['/usr/bin/bash', str(BRIDGE), *arguments],
                                    capture_output=True, timeout=5)
            self.assertEqual(2, result.returncode)
            self.assertEqual(b'', result.stdout)

    def test_parser_remains_read_only_by_default_and_no_arbitrary_command(self):
        source = BRIDGE.read_text()
        self.assertIn('set -- --check-only', source)
        self.assertNotIn('eval ', source)
        self.assertNotIn('"$@"', source)
        self.assertFalse(configuration().run)
        self.assertTrue(configuration('--run').run)

    def test_factory_cache_and_preserved_debug_proof_pins_match_without_archive_rehash(self):
        config = configuration()
        for path, digest in ((config.cache_receipt, config.cache_receipt_sha256),
                            (config.debug_proof, config.debug_proof_sha256)):
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(11378664978, config.archive_bytes)
        self.assertEqual('3721e6accc2e87d851ee7966d794318078ec74c7cc32343daa10968264d6bb62',
                         config.archive_sha256)


if __name__ == '__main__':
    unittest.main(verbosity=2)
