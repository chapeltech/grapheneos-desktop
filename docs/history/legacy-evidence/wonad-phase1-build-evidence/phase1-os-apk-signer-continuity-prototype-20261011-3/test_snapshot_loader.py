#!/usr/bin/env python3
from __future__ import annotations

import builtins
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import authenticated_source as source_loader  # noqa: E402
import signer_continuity_policy as policy  # noqa: E402
import fixture_support as support  # noqa: E402


SAFE_SOURCE = b'MARKER = "authenticated"\n\ndef expected_function():\n    return 41\n'
FOREIGN_SOURCE = b'MARKER = "post_hash_path"\n\ndef expected_function():\n    return 99\n'


class SnapshotLoaderTests(unittest.TestCase):
    def test_changed_post_hash_path_cannot_change_executed_bytes(self):
        with tempfile.TemporaryDirectory(prefix="wonad-v3-loader-green-") as directory:
            path = Path(directory) / "controlled.py"
            path.write_bytes(SAFE_SOURCE)
            expected = hashlib.sha256(SAFE_SOURCE).hexdigest()
            real_compile = builtins.compile

            def replace_path_then_compile(source, filename, mode, **kwargs):
                self.assertEqual(SAFE_SOURCE, source)
                path.write_bytes(FOREIGN_SOURCE)
                return real_compile(source, filename, mode, **kwargs)

            with mock.patch.object(
                source_loader,
                "compile",
                side_effect=replace_path_then_compile,
                create=True,
            ):
                loaded = source_loader.load_authenticated_module(
                    path, expected, "_controlled_snapshot_green"
                )

            self.assertEqual(FOREIGN_SOURCE, path.read_bytes())
            self.assertEqual("authenticated", loaded.MARKER)
            self.assertEqual(41, loaded.expected_function())
            self.assertNotIn("_controlled_snapshot_green", sys.modules)
            self.assertEqual(str(path), loaded.__file__)
            self.assertEqual("", loaded.__package__)

    def test_hash_mismatch_rejects_without_compiling(self):
        with tempfile.TemporaryDirectory(prefix="wonad-v3-loader-mismatch-") as directory:
            path = Path(directory) / "controlled.py"
            path.write_bytes(SAFE_SOURCE)
            with mock.patch.object(source_loader, "compile", create=True) as compile_mock:
                with self.assertRaisesRegex(
                    source_loader.AuthenticatedSourceError,
                    "authenticated source identity changed",
                ):
                    source_loader.load_authenticated_module(
                        path, "0" * 64, "_controlled_snapshot_mismatch"
                    )
            compile_mock.assert_not_called()

    def test_policy_loader_routes_exact_identity_through_snapshot_helper(self):
        sentinel = SimpleNamespace()
        with mock.patch.object(
            policy, "load_authenticated_module", return_value=sentinel
        ) as loader:
            self.assertIs(sentinel, policy._load_frozen_v1())
        loader.assert_called_once_with(
            policy.V1_PATH,
            policy.V1_SHA256,
            "_wonad_signer_continuity_policy_v1",
        )

    def test_support_loaders_route_exact_identities_through_snapshot_helper(self):
        policy_sentinel = SimpleNamespace()
        tests_sentinel = SimpleNamespace()
        with mock.patch.object(
            support,
            "load_authenticated_module",
            side_effect=(policy_sentinel, tests_sentinel),
        ) as loader:
            self.assertIs(policy_sentinel, support._load_v1_policy())
            self.assertIs(tests_sentinel, support._load_v1_tests())
        self.assertEqual(
            [
                mock.call(
                    support.V1_POLICY_PATH,
                    support.V1_POLICY_SHA256,
                    "_wonad_signer_continuity_fixture_policy_v1",
                ),
                mock.call(
                    support.V1_TEST_PATH,
                    support.V1_TEST_SHA256,
                    "_wonad_signer_continuity_tests_v1",
                ),
            ],
            loader.call_args_list,
        )

    def test_real_snapshot_modules_preserve_expected_functions(self):
        self.assertTrue(callable(policy._V1.verify_pair))
        self.assertTrue(callable(support.V1_POLICY.verify_pair))
        self.assertTrue(callable(support.V1_TESTS.fixture))
        self.assertTrue(callable(support.fixture))
        policy_record, predecessor, successor = support.fixture()
        report = policy.verify_pair(policy_record, predecessor, successor)
        self.assertTrue(report["valid"])
        self.assertEqual(
            "phase1_fixed_seed_os_signer_continuity_semantic_report_v3",
            report["kind"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
