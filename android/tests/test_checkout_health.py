import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "checkout_health", Path(__file__).resolve().parents[1] / "tools/checkout_health.py")
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)


class CheckoutHealth(unittest.TestCase):
    def setup_tree(self, source):
        (source / ".repo").mkdir()
        (source / ".repo/project.list").write_text("external/example\n")
        git = source / "external/example/.git"
        git.mkdir(parents=True)
        return git

    def test_missing_index_detects_interrupted_initial_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            self.setup_tree(source)
            self.assertIn("missing Git index", health.check(source)[0])

    def test_stale_lock_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            git = self.setup_tree(source)
            lock = git / "index.lock"
            lock.touch()
            self.assertEqual(2, len(health.check(source)))
            self.assertTrue(lock.exists())

    def test_missing_git_directory_does_not_use_a_parent_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            git = self.setup_tree(source)
            git.rmdir()
            self.assertIn("missing project Git directory", health.check(source)[0])

    def test_initialization_check_is_not_worktree_attestation(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            git = self.setup_tree(source)
            (git / "index").write_bytes(b"index presence only")
            self.assertEqual([], health.check(source))

    def test_project_list_cannot_escape_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            self.setup_tree(source)
            for value in ("../outside", "/outside", ""):
                (source / ".repo/project.list").write_text(value)
                with self.subTest(value=value), self.assertRaises(ValueError):
                    health.check(source)


if __name__ == "__main__":
    unittest.main()
