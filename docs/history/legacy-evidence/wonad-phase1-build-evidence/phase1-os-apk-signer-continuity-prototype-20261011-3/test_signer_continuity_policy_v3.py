#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from signer_continuity_policy import PolicyError, verify_pair  # noqa: E402
import fixture_support as support  # noqa: E402


# Replay every frozen v1 semantic test against the v3 entry point. Preserve
# the original callable separately for explicit before/after regressions.
support.V1_TESTS.verify_pair = verify_pair
support.V1_TESTS.PolicyError = PolicyError


class InheritedV1Semantics(support.V1_TESTS.SignerContinuityPolicyTests):
    pass


class V3HardeningTests(unittest.TestCase):
    def setUp(self):
        self.policy, self.before, self.after = support.fixture()

    def reject_v3(self, fragment: str):
        with self.assertRaisesRegex(PolicyError, fragment):
            verify_pair(self.policy, self.before, self.after)

    def v1_accepts(self):
        self.assertTrue(support.V1_VERIFY(self.policy, self.before, self.after)["valid"])

    def test_report_identifies_v3_semantic_entry_point(self):
        report = verify_pair(self.policy, self.before, self.after)
        self.assertEqual(1, report["schema"])
        self.assertIs(type(report["schema"]), int)
        self.assertEqual(
            "phase1_fixed_seed_os_signer_continuity_semantic_report_v3", report["kind"]
        )

    def test_policy_schema_bool_was_accepted_by_v1_and_is_rejected_by_v3(self):
        self.policy["schema"] = True
        self.v1_accepts()
        self.reject_v3("policy: schema must be the exact integer 1")

    def test_endpoint_schema_bools_were_accepted_by_v1_and_are_rejected_by_v3(self):
        for _endpoint, label in ((self.before, "predecessor"), (self.after, "successor")):
            with self.subTest(label=label):
                policy, before, after = support.fixture()
                selected = before if label == "predecessor" else after
                selected["schema"] = True
                self.assertTrue(support.V1_VERIFY(policy, before, after)["valid"])
                with self.assertRaisesRegex(
                    PolicyError, label + ": schema must be the exact integer 1"
                ):
                    verify_pair(policy, before, after)

    def test_partition_archive_member_alias_was_accepted_by_v1_and_is_rejected(self):
        first, second = self.after["packages"][:2]
        second["archive_member"] = first["archive_member"]
        self.v1_accepts()
        self.reject_v3("archive member.*target-files.*aliased")

    def test_split_archive_member_alias_was_accepted_by_v1_and_is_rejected(self):
        base = support.find_package(self.after, "com.example.platform")
        split = support.find_package(self.after, "com.example.platform", "feature")
        split["archive_member"] = base["archive_member"]
        self.v1_accepts()
        self.reject_v3("archive member.*target-files.*aliased")

    def test_same_apex_embedded_alias_was_accepted_by_v1_and_is_rejected(self):
        support.add_embedded_package(
            self.policy,
            (self.before, self.after),
            apex_name="com.android.runtime",
            package_name="com.example.embeddedalias",
            archive_member="app/com_example_embedded.apk",
            seed=8200,
        )
        self.v1_accepts()
        self.reject_v3("archive member.*apex:com.android.runtime.*aliased")

    def test_apex_outer_member_alias_was_accepted_by_v1_and_is_rejected(self):
        support.add_second_apex(self.policy, self.before, self.after)
        self.after["apexes"][1]["archive_member"] = self.after["apexes"][0]["archive_member"]
        self.v1_accepts()
        self.reject_v3("archive member.*target-files.*aliased")

    def test_apex_outer_and_partition_member_collision_fails_closed(self):
        self.after["apexes"][0]["archive_member"] = self.after["packages"][0][
            "archive_member"
        ]
        self.reject_v3("archive member.*target-files.*aliased")

    def test_equal_embedded_relative_path_in_distinct_apex_namespaces_is_allowed(self):
        support.add_second_apex(self.policy, self.before, self.after)
        support.add_embedded_package(
            self.policy,
            (self.before, self.after),
            apex_name="com.android.second",
            package_name="com.example.embeddedsecond",
            archive_member="app/com_example_embedded.apk",
            seed=8300,
        )
        report = verify_pair(self.policy, self.before, self.after)
        self.assertTrue(report["valid"])
        self.assertEqual(2, report["counts"]["apexes"])

    def test_equal_member_text_in_partition_and_apex_namespaces_is_allowed(self):
        for endpoint in (self.before, self.after):
            partition = support.find_package(endpoint, "com.example.bluetooth")
            embedded = support.find_package(endpoint, "com.example.embedded")
            embedded["archive_member"] = partition["archive_member"]
        self.assertTrue(verify_pair(self.policy, self.before, self.after)["valid"])

    def test_archive_ownership_is_scoped_per_endpoint(self):
        member = "APP/cross_endpoint_only.apk"
        support.find_package(self.before, "com.example.bluetooth")["archive_member"] = member
        support.find_package(self.after, "com.example.media")["archive_member"] = member
        # The same string in opposite endpoints is not an intra-archive alias.
        self.assertTrue(verify_pair(self.policy, self.before, self.after)["valid"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
