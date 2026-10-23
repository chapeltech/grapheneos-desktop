"""Bound derived7 recipe checks only. No Docker, copy, build, or conversion.

The original13-test preparation is preserved as historical: native5 and wrong8
now exist. Shell probes always alter an early pin in memory or provide a wrong
image argument, so the resolved actual recipe is never executed by these tests.
"""
import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = Path('/u/elric/tree/wonad')
RECIPE = HERE / 'run-phase1-conformance-candidate-custom7-5-7.sh'
PENDING = HERE / 'phase1-packet8-derived7-native5-prebinding-20261012-1.sh'
ORIGINAL_TESTS = HERE / 'test_phase1_packet8_candidate_preparation_20261012_1.py'
PRESERVED_TESTS = HERE / 'phase1-packet8-candidate-tests-native5-prebinding-20261012-1.py'
IMAGE = 'sha256:0e425e724cb6f53cb1ef6ae080c39dfdfcf810b5e6fe7c262e419e2b750a01b4'


def constants(text):
    return dict(re.findall(r'^readonly ([a-z0-9_]+)=(.*)$', text, re.M))


class BoundDerived7PreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = RECIPE.read_text()
        cls.values = constants(cls.text)

    def probe(self, source, image=IMAGE):
        return subprocess.run(['/usr/bin/bash', '-s', '--', image], input=source,
            text=True, capture_output=True, timeout=10)

    def test_shell_syntax_only(self):
        result = subprocess.run(['/usr/bin/bash', '-n', str(RECIPE)], capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_only_actual_native_image_pin_differs_from_exact_preserved_recipe(self):
        self.assertEqual('4653e03cd993fc48b6a5bfae2075d4091a2f1587201240f33e29ea2987480056',
                         hashlib.sha256(PENDING.read_bytes()).hexdigest())
        restored = self.text.replace('readonly native_image=' + IMAGE, 'readonly native_image=PENDING')
        self.assertEqual(PENDING.read_text(), restored)
        self.assertEqual(IMAGE, self.values['native_image'])

    def test_original13_tests_are_preserved_unchanged_not_rerun_as_current_admission(self):
        original = ORIGINAL_TESTS.read_bytes()
        self.assertEqual(original, PRESERVED_TESTS.read_bytes())
        self.assertEqual('5a4801fda4dea176789454a693f5f42dca739e59cd245154b8e0f0074f6e5e48',
                         hashlib.sha256(original).hexdigest())

    def test_pending_native_and_each_packet_or_current_source_pin_stop_before_work(self):
        for name in ('native_image', 'packet_sha', 'packet_wonad_sha', 'packet_update_sha',
                     'packet_conformance_update_sha', 'packet_wonad_cert_sha', 'packet_platform_cert_sha',
                     'smoke_source_sha', 'common_source_sha', 'guest_source_sha', 'api_auditor_sha'):
            pending = self.text.replace(f'readonly {name}={self.values[name]}', f'readonly {name}=PENDING')
            self.assertNotEqual(self.text, pending)
            result = self.probe(pending)
            with self.subTest(pin=name):
                self.assertEqual(78, result.returncode, result.stderr)
                self.assertIn('PENDING', result.stderr)
                self.assertEqual('', result.stdout)

    def test_wrong_or_malformed_image_arguments_stop_before_lock_or_files(self):
        for image, status in [('sha256:' + 'b' * 64, 65), ('PENDING', 64), ('sha256:' + 'g' * 64, 64)]:
            result = self.probe(self.text, image)
            with self.subTest(image=image):
                self.assertEqual(status, result.returncode)
                self.assertEqual('', result.stdout)

    def test_original_product_and_actual_packet_but_fresh_derived_output(self):
        self.assertEqual('/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-5/target/product/emu64x',
                         self.values['product'])
        self.assertEqual('$repo/android/out/phase1-emulator-client-packet-20261012-8', self.values['packet'])
        self.assertEqual('b30fbb787eb8f39cb573db076a2ac0954cf98f61d375b49d465cc42b355ef3ee',
                         self.values['packet_sha'])
        self.assertEqual('$repo/android/out/phase1-native-candidate-custom7-5-5', self.values['native_output'])
        self.assertEqual('wonad:native-v3-candidate-phase1-custom7-5-5', self.values['native_tag'])
        self.assertEqual('$repo/android/out/phase1-conformance-candidate-custom7-5-7', self.values['output'])
        self.assertFalse((ROOT / 'android/out/phase1-conformance-candidate-custom7-5-7').exists())
        self.assertEqual(IMAGE, (ROOT / 'android/out/phase1-native-candidate-custom7-5-5/built-image.id').read_text().strip())

    def test_current_source_hashes_and_final_restaging_rechecks_remain_exact(self):
        for name in ('builder', 'native_builder', 'packet_tool', 'smoke_source', 'common_source', 'guest_source', 'api_auditor'):
            path = Path(self.values[name].replace('$repo', str(ROOT)))
            self.assertEqual(self.values[name + '_sha'], hashlib.sha256(path.read_bytes()).hexdigest(), name)
        for name in ('smoke_source', 'common_source', 'guest_source', 'api_auditor'):
            self.assertEqual(2, self.text.count(f'exact_sha "${name}" "${name}_sha"'))

    def test_original_resource_ancestry_and_product_absence_checks_not_weakened(self):
        for statement in ('(( mem_kib >= 8 * 1024 * 1024 ))', '(( u_free >= 12 * gib ))',
                          '(( tmp_free >= 4 * gib ))', '(( docker_free >= 12 * gib ))'):
            self.assertIn(statement, self.text)
        builder = (ROOT / 'android/container/build-phase1-conformance-candidate.py').read_text()
        self.assertIn('validate_derived_image(parent, actual)', builder)
        self.assertIn('json.loads(document) == manifest', builder)
        self.assertIn('test ! -e /opt/wonad/wonad.apk', builder)
        self.assertIn('native.publish_candidate(candidate, tag)', builder)

    def test_executed_wrong8_launcher_seam_is_mocked_not_reused_or_converted(self):
        path = HERE / 'run-phase1-wrong-signer-bundle8-20261012-1.py'
        spec = importlib.util.spec_from_file_location('executed_wrong8_mocked_only', path)
        wrong = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wrong)
        with mock.patch.object(wrong, 'preflight', return_value={'status': 'mocked_historical_seam_only'}), \
                mock.patch.object(wrong.os, 'execve') as execute:
            self.assertEqual(0, wrong.main([]))
        execute.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
