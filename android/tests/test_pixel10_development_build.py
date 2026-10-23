"""The development compile lane is bounded and cannot masquerade as release."""
from pathlib import Path
import json
import tempfile
import unittest
from android.tools import run_pixel10_development_build as build
from android.tools import run_frankel_build as release


class Pixel10DevelopmentBuildTests(unittest.TestCase):
    def command(self):
        return build.command(Path('/source'), Path('/output'),
            'wonad-frankel-development-unit', [0, 1, 2, 3], 1792500000)

    def test_is_offline_nonroot_no_extra_swap_and_affinity_bounded(self):
        argv = self.command()
        for option, expected in (("--network", "none"), ("--user", "1000:1000"),
                ("--cpuset-cpus", "0,1,2,3"), ("--cpus", "4"), ("--cap-drop", "ALL"),
                ("--memory", str(28 * build.GIB)), ("--memory-swap", str(28 * build.GIB))):
            self.assertEqual(expected, argv[argv.index(option) + 1])
        self.assertNotIn("--rm", argv)
        self.assertNotIn("--privileged", argv)
        self.assertEqual(2, argv.count("--volume"))

    def test_environment_is_empty_then_explicit_and_never_official(self):
        argv = self.command()
        image = argv.index(build.IMAGE)
        self.assertEqual("-i", argv[image + 1])
        environment = argv[image + 2:-5]
        self.assertTrue(environment)
        self.assertFalse(any(value.startswith(("OFFICIAL_BUILD=", "WONAD_UPDATE_URL=")) for value in environment))
        self.assertIn('lunch frankel-cur-user', build.INNER)
        self.assertIn('m -j2', build.INNER)

    def test_name_and_cpu_profiles_cannot_select_release_or_unbounded_slots(self):
        for name, cpus in (("wonad-phase1-frankel-release-unit", [0, 1, 2, 3]),
                           ("wonad-frankel-development-unit", [0, 0, 1, 2]),
                           ("wonad-frankel-development-unit", list(range(72)))):
            with self.subTest(name=name, cpus=cpus), self.assertRaises(ValueError):
                build.command(Path('/source'), Path('/output'), name, cpus, 1792500000)

    def test_the_qualified_release_profile_remains_unchanged(self):
        self.assertEqual(48 * build.GIB, release.PIN['container_resources']['memory_bytes'])
        self.assertEqual(42 * build.GIB, release.PIN['host_admission']['memory_available_bytes'])
        self.assertEqual(96 * build.GIB, release.PIN['host_admission']['out_free_bytes'])

    def test_resume_cannot_relabel_a_successful_or_different_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preflight = dict(kind='unsigned-pixel10-development-build-not-release',
                             source='/source', out='/output')
            execution = dict(kind=preflight['kind'], container='1'*64,
                             passed=False, build_completed=False)
            (root/'preflight.json').write_text(json.dumps(preflight))
            (root/'execution.json').write_text(json.dumps(execution))
            result = build.previous_attempt(root, Path('/source'), Path('/output'))
            self.assertEqual('1'*64, result['container'])
            with self.assertRaisesRegex(ValueError, 'explicitly failed'):
                build.previous_attempt(root, Path('/other'), Path('/output'))
            execution.update(passed=True, build_completed=True)
            (root/'execution.json').write_text(json.dumps(execution))
            with self.assertRaisesRegex(ValueError, 'explicitly failed'):
                build.previous_attempt(root, Path('/source'), Path('/output'))


if __name__ == '__main__':
    unittest.main()
