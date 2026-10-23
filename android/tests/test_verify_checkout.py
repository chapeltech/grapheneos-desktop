import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ANDROID = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("verify_checkout", ANDROID / "tools/verify_checkout.py")
verify_checkout = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_checkout)


class CheckoutVerification(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)
        manifests = self.source / ".repo/manifests"
        manifests.mkdir(parents=True)
        self.projects = {}
        for name in ("frameworks/base", "packages/apps/Updater"):
            project = self.source / name
            project.mkdir(parents=True)
            subprocess.run(["git", "init", "-q", str(project)], check=True)
            (project / "tracked").write_text(name + "\n")
            subprocess.run(["git", "-C", str(project), "add", "tracked"], check=True)
            subprocess.run(["git", "-C", str(project), "-c", "user.name=Test",
                            "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
                            "commit", "-qm", "baseline"], check=True)
            self.projects[name] = subprocess.check_output(
                ["git", "-C", str(project), "rev-parse", "HEAD"], text=True).strip()
        (self.source / ".repo/project.list").write_text("\n".join(self.projects) + "\n")
        self.write_manifest(self.projects)

    def write_manifest(self, projects):
        rows = [f'<project name="{path.replace("/", "_")}" path="{path}" revision="{revision}"/>'
                for path, revision in projects.items()]
        (self.source / ".repo/manifests/default.xml").write_text("<manifest>" + "".join(rows) + "</manifest>")

    def test_exact_clean_checkout_passes_and_untracked_files_are_out_of_scope(self):
        (self.source / "frameworks/base/untracked").write_text("allowed but not attested")
        result = verify_checkout.verify(self.source, jobs=2)
        self.assertEqual(2, result["projects"])
        self.assertEqual("not_attested", result["untracked_files"])

    def test_tracked_edit_is_rejected(self):
        (self.source / "frameworks/base/tracked").write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "tracked worktree changes"):
            verify_checkout.verify(self.source)

    def test_tracked_diff_uses_long_deadline_while_head_remains_cheap(self):
        original = subprocess.check_output
        observations = []

        def observed(argv, **kwargs):
            if argv[0:3] == ["git", "-C", str(self.source / "frameworks/base")] or \
                    argv[0:3] == ["git", "-C", str(self.source / "packages/apps/Updater")]:
                observations.append((argv[3:], kwargs.get("timeout")))
            return original(argv, **kwargs)

        with mock.patch.object(verify_checkout.subprocess, "check_output",
                               side_effect=observed):
            result = verify_checkout.verify(self.source, jobs=1)
        self.assertEqual("clean", result["tracked_worktrees"])
        self.assertEqual([
            (["rev-parse", "HEAD"], 60),
            (["diff", "--name-only", "-z", "HEAD", "--"], 600),
            (["rev-parse", "HEAD"], 60),
            (["diff", "--name-only", "-z", "HEAD", "--"], 600),
        ], observations)

    def test_tracked_diff_timeout_is_rejected_not_skipped(self):
        original = subprocess.check_output
        timed_out = []

        def timeout_framework_diff(argv, **kwargs):
            if argv == ["git", "-C", str(self.source / "frameworks/base"),
                        "diff", "--name-only", "-z", "HEAD", "--"]:
                timed_out.append(kwargs.get("timeout"))
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
            return original(argv, **kwargs)

        with mock.patch.object(verify_checkout.subprocess, "check_output",
                               side_effect=timeout_framework_diff):
            with self.assertRaisesRegex(ValueError,
                                        "frameworks/base: Git verification failed.*timed out"):
                verify_checkout.verify(self.source, jobs=1)
        self.assertEqual([600], timed_out)

    def test_exact_owned_edit_is_allowed_but_never_an_unrelated_tracked_edit(self):
        framework = self.source / "frameworks/base/tracked"
        framework.write_text("owned staged bytes\n")
        result = verify_checkout.verify(
            self.source, allowed_changes={"frameworks/base": {"tracked"}})
        self.assertEqual("clean", result["tracked_worktrees"])
        updater = self.source / "packages/apps/Updater/tracked"
        updater.write_text("unowned change\n")
        with self.assertRaisesRegex(ValueError, "unexpected tracked worktree changes"):
            verify_checkout.verify(
                self.source, allowed_changes={"frameworks/base": {"tracked"}})

    def test_wrong_head_is_rejected(self):
        project = self.source / "frameworks/base"
        (project / "second").write_text("new\n")
        subprocess.run(["git", "-C", str(project), "add", "second"], check=True)
        subprocess.run(["git", "-C", str(project), "-c", "user.name=Test",
                        "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
                        "commit", "-qm", "other"], check=True)
        with self.assertRaisesRegex(ValueError, "HEAD differs"):
            verify_checkout.verify(self.source)

    def test_project_list_must_exactly_match_manifest(self):
        (self.source / ".repo/project.list").write_text("frameworks/base\n")
        with self.assertRaisesRegex(ValueError, "differs from signed manifest"):
            verify_checkout.verify(self.source)

    def test_local_manifest_override_is_rejected(self):
        (self.source / ".repo/local_manifests").mkdir()
        with self.assertRaisesRegex(ValueError, "local manifest"):
            verify_checkout.verify(self.source)

    def test_symbolic_revision_is_not_a_stable_pin(self):
        projects = dict(self.projects)
        projects["frameworks/base"] = "refs/heads/main"
        self.write_manifest(projects)
        with self.assertRaisesRegex(ValueError, "unpinned"):
            verify_checkout.verify(self.source)


if __name__ == "__main__":
    unittest.main()
