#!/usr/bin/env python3
"""Desired hardening assertions deliberately RED against frozen v1."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixture_support as support  # noqa: E402


class FrozenV1HardeningRedTests(unittest.TestCase):
    def setUp(self):
        self.policy, self.before, self.after = support.fixture()

    def desired_rejection(self):
        with self.assertRaises(support.V1_ERROR):
            support.V1_VERIFY(self.policy, self.before, self.after)

    def test_policy_bool_schema_must_be_rejected(self):
        self.policy["schema"] = True
        self.desired_rejection()

    def test_endpoint_bool_schema_must_be_rejected(self):
        self.after["schema"] = True
        self.desired_rejection()

    def test_partition_member_alias_must_be_rejected(self):
        self.after["packages"][1]["archive_member"] = self.after["packages"][0]["archive_member"]
        self.desired_rejection()

    def test_same_apex_embedded_member_alias_must_be_rejected(self):
        support.add_embedded_package(
            self.policy,
            (self.before, self.after),
            apex_name="com.android.runtime",
            package_name="com.example.embeddedalias",
            archive_member="app/com_example_embedded.apk",
            seed=8200,
        )
        self.desired_rejection()

    def test_apex_outer_member_alias_must_be_rejected(self):
        support.add_second_apex(self.policy, self.before, self.after)
        self.after["apexes"][1]["archive_member"] = self.after["apexes"][0]["archive_member"]
        self.desired_rejection()


if __name__ == "__main__":
    unittest.main(verbosity=2)

