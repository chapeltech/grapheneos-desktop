#!/usr/bin/env python3
"""Bounded RED design regressions, NOT an executable release gate.

These tests execute only the actual pinned checker APK/TargetFiles class bodies
over synthetic in-memory records. No imports of upstream common, tool calls,
ZIP extraction, signing, containers, or actual release artifacts are used.
The desired package/shared-UID guarantees intentionally fail on the pinned
primary source. Kept outside the product test matrix and frozen inputs.
"""

import ast
import contextlib
import hashlib
import io
from pathlib import Path
import types
import unittest


CHECKER = Path(
    "/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7/"
    "build/make/tools/releasetools/check_target_files_signatures.py"
)
CHECKER_SHA256 = "c58b011df51c70db0d9a5ffc394fc40bab1d0113e2a0fabb6f9fec09640ec8e9"


class PinnedOfficialCheckerDesignTests(unittest.TestCase):
    def setUp(self):
        data = CHECKER.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), CHECKER_SHA256)
        tree = ast.parse(data, filename=str(CHECKER))
        selected = [node for node in tree.body if isinstance(node, ast.ClassDef)
                    and node.name in {"APK", "TargetFiles"}]
        self.assertEqual([node.name for node in selected], ["APK", "TargetFiles"])
        self.problems = []
        namespace = {
            "AddProblem": self.problems.append,
            "ALL_CERTS": types.SimpleNamespace(Get=lambda digest: digest),
            "Banner": lambda title: None,
        }
        exec(compile(ast.Module(body=selected, type_ignores=[]), str(CHECKER), "exec"),
             namespace)
        self.APK, self.TargetFiles = namespace["APK"], namespace["TargetFiles"]

    def apk(self, path, signer, package, shared_uid=None):
        # Match the real APK constructor's state, without invoking external
        # signature/manifest parsers. All compared methods remain source-exact.
        apk = self.APK.__new__(self.APK)
        apk.filename = path
        apk.cert_digests = frozenset({signer})
        apk.shared_uid = shared_uid
        apk.package = package
        self.assertFalse(hasattr(apk, "certs"))
        return apk

    def target(self, *apks):
        target = self.TargetFiles()
        target.apks = {apk.filename: apk for apk in apks}
        return target

    def compare(self, predecessor, successor):
        with contextlib.redirect_stdout(io.StringIO()):
            successor.CompareWith(predecessor)

    def test_control_same_archive_path_changed_signer_is_rejected(self):
        old = self.target(self.apk("SYSTEM/app/Same/Same.apk", "old", "org.example.same"))
        new = self.target(self.apk("SYSTEM/app/Same/Same.apk", "new", "org.example.same"))
        self.compare(old, new)
        self.assertIn("some APKs changed certs", self.problems)

    def test_same_android_package_moved_path_changed_signer_must_be_rejected(self):
        old = self.target(self.apk("SYSTEM/app/Old/Old.apk", "old", "org.example.same"))
        new = self.target(self.apk("SYSTEM_EXT/app/New/New.apk", "new", "org.example.same"))
        self.compare(old, new)
        self.assertIn("some APKs changed certs", self.problems,
                      "Archive-path identity must not bypass Android package continuity")

    def test_matching_signers_in_real_shared_uid_group_must_be_accepted(self):
        target = self.target(
            self.apk("SYSTEM/app/A/A.apk", "same", "org.example.a", "android.uid.system"),
            self.apk("SYSTEM/app/B/B.apk", "same", "org.example.b", "android.uid.system"),
        )
        target.CheckSharedUids()
        self.assertEqual(self.problems, [])

    def test_different_signers_in_real_shared_uid_group_must_be_rejected(self):
        target = self.target(
            self.apk("SYSTEM/app/A/A.apk", "old", "org.example.a", "android.uid.system"),
            self.apk("SYSTEM/app/B/B.apk", "new", "org.example.b", "android.uid.system"),
        )
        with contextlib.redirect_stdout(io.StringIO()):
            target.CheckSharedUids()
        self.assertIn("different cert sets for packages with uid android.uid.system",
                      self.problems)

    def test_control_genuinely_new_and_removed_packages_are_informational(self):
        old = self.target(self.apk("SYSTEM/app/Old/Old.apk", "old", "org.example.old"))
        new = self.target(self.apk("SYSTEM/app/New/New.apk", "new", "org.example.new"))
        self.compare(old, new)
        self.assertEqual(self.problems, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
