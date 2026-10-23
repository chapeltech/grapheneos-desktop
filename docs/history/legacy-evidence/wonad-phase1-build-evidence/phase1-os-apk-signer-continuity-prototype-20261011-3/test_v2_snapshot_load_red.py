#!/usr/bin/env python3
"""Desired snapshot assertions deliberately RED against frozen v2 loaders.

Only controlled synthetic temporary source is used. The frozen v2 directory is
never modified.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from authenticated_source import load_authenticated_module  # noqa: E402


V2 = Path(__file__).resolve().parent.parent / (
    "phase1-os-apk-signer-continuity-prototype-20261011-2"
)
V2_POLICY_SHA256 = "fabf2a059337368a008b114a7dba43090a3350f05984726430c32c6b1ecb5995"
V2_SUPPORT_SHA256 = "52f1f3804a3f2f46420b93ccf98fa99dc47ac6e4f3eaf4bf0ad55e09381206ff"
SAFE_SOURCE = b'MARKER = "authenticated"\n\ndef expected_function():\n    return 41\n'
FOREIGN_SOURCE = b'MARKER = "post_hash_path"\n\ndef expected_function():\n    return 99\n'


class FrozenV2SnapshotLoadRedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_authenticated_module(
            V2 / "signer_continuity_policy.py",
            V2_POLICY_SHA256,
            "_frozen_v2_policy_for_red",
        )
        cls.support = load_authenticated_module(
            V2 / "fixture_support.py",
            V2_SUPPORT_SHA256,
            "_frozen_v2_support_for_red",
        )

    def desired_snapshot(self, module, path_attr, sha_attr, loader_name):
        with tempfile.TemporaryDirectory(prefix="wonad-v2-loader-red-") as directory:
            path = Path(directory) / "controlled.py"
            path.write_bytes(SAFE_SOURCE)
            setattr(module, path_attr, path)
            setattr(module, sha_attr, hashlib.sha256(SAFE_SOURCE).hexdigest())

            original = importlib.util.spec_from_file_location

            def replace_after_hash(name, requested_path, *args, **kwargs):
                path.write_bytes(FOREIGN_SOURCE)
                return original(name, requested_path, *args, **kwargs)

            with mock.patch.object(
                module.importlib.util,
                "spec_from_file_location",
                side_effect=replace_after_hash,
            ):
                loaded = getattr(module, loader_name)()

            # These are desired snapshot semantics. Every frozen-v2 loader
            # instead reopens the changed path, so each assertion is RED.
            self.assertEqual("authenticated", loaded.MARKER)
            self.assertEqual(41, loaded.expected_function())

    def test_v2_policy_loader_must_execute_authenticated_snapshot(self):
        self.desired_snapshot(self.policy, "V1_PATH", "V1_SHA256", "_load_frozen_v1")

    def test_v2_support_policy_loader_must_execute_authenticated_snapshot(self):
        self.desired_snapshot(
            self.support,
            "V1_POLICY_PATH",
            "V1_POLICY_SHA256",
            "_load_v1_policy",
        )

    def test_v2_support_test_loader_must_execute_authenticated_snapshot(self):
        self.desired_snapshot(
            self.support,
            "V1_TEST_PATH",
            "V1_TEST_SHA256",
            "_load_v1_tests",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
