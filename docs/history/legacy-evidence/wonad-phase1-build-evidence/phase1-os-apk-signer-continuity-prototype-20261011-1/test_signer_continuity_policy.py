#!/usr/bin/env python3
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from signer_continuity_policy import OS_ROLES, PolicyError, verify_pair  # noqa: E402


def h(value: int) -> str:
    return f"{value:064x}"


def signing_assignment(spec: dict) -> dict:
    if spec["kind"] == "role":
        return {
            "kind": "role",
            "role": spec["role"],
            "source_binding_sha256": spec["source_binding_sha256"],
        }
    return {
        "kind": "external",
        "exception_kind": spec["exception_kind"],
        "source_binding_sha256": spec["source_binding_sha256"],
    }


def fixture() -> tuple[dict, dict, dict]:
    role_signers = {role: h(index + 1) for index, role in enumerate(OS_ROLES)}
    artifact_signing: dict[str, dict] = {}
    role_packages = {
        "bluetooth": "com.example.bluetooth",
        "gmscompat_lib": "com.example.gmscompat",
        "media": "com.example.media",
        "networkstack": "com.example.networkstack",
        "nfc": "com.example.nfc",
        "platform": "com.example.platform",
        "releasekey": "com.example.release",
        "sdk_sandbox": "com.example.sdksandbox",
        "shared": "com.example.shared",
    }
    for index, (role, package) in enumerate(role_packages.items(), 1):
        artifact_signing[f"package:{package}"] = {
            "kind": "role",
            "role": role,
            "source_binding_sha256": h(1000 + index),
            "container": "partition",
            "splits": ["base", "feature"] if role == "platform" else ["base"],
        }
    artifact_signing["package:com.example.platformhelper"] = {
        "kind": "role", "role": "platform", "source_binding_sha256": h(1010),
        "container": "partition", "splits": ["base"],
    }
    artifact_signing["package:com.vendor.camera"] = {
        "kind": "external", "exception_kind": "vendor_external",
        "source_binding_sha256": h(1100), "signer_der_sha256": [h(1101), h(1102)],
        "container": "partition", "splits": ["base"],
    }
    artifact_signing["package:com.vendor.presigned"] = {
        "kind": "external", "exception_kind": "presigned",
        "source_binding_sha256": h(1110), "signer_der_sha256": [h(1111)],
        "container": "partition", "splits": ["base"],
    }
    artifact_signing["package:com.example.embedded"] = {
        "kind": "role", "role": "releasekey", "source_binding_sha256": h(1200),
        "container": "apex:com.android.runtime", "splits": ["base"],
    }
    artifact_signing["apex:com.android.runtime"] = {
        "kind": "role", "role": "releasekey", "source_binding_sha256": h(1300),
        "container_type": "apex",
    }
    policy = {
        "schema": 1,
        "scope": "phase1-fixed-seed-pair",
        "required_roles": list(OS_ROLES),
        "role_signers": role_signers,
        "trusted_tools": {
            "aapt2": h(2000), "apksigner": h(2001), "apksigner.jar": h(2002),
            "avbtool": h(2003), "deapexer": h(2004), "debugfs_static": h(2005),
            "fsck.erofs": h(2006),
        },
        "artifact_signing": artifact_signing,
        "apex_payload_keys": {
            "com.android.runtime": {
                "public_key_sha256": h(2100), "source_binding_sha256": h(2101),
            }
        },
    }

    def endpoint(label: str, epoch: int) -> dict:
        evidence_counter = 0

        def evidence(purpose: str) -> dict:
            nonlocal evidence_counter
            evidence_counter += 1
            return {
                "path": f"raw/{label}/{evidence_counter:03d}-{purpose}.txt",
                "sha256": h(epoch * 10000 + evidence_counter),
                "bytes": 100 + evidence_counter,
            }

        def package_record(package: str, split: str, container: str) -> dict:
            spec = artifact_signing[f"package:{package}"]
            if spec["kind"] == "role":
                signers = [role_signers[spec["role"]]]
            else:
                signers = list(spec["signer_der_sha256"])
            leaf = package.replace(".", "_") + (".apk" if split == "base" else f"-{split}.apk")
            shared_uid = "android.uid.example.platform" if package in {
                "com.example.platform", "com.example.platformhelper"
            } else None
            return {
                "package_name": package,
                "split_name": None if split == "base" else split,
                "container": container,
                "archive_member": f"APP/{leaf}" if container == "partition" else f"app/{leaf}",
                "file_sha256": h(epoch * 1000 + evidence_counter + 3000),
                "bytes": 10000 + evidence_counter,
                "signer_der_sha256": signers,
                "shared_uid": shared_uid,
                "assignment": signing_assignment(spec),
                "verification": {
                    "method": "apksigner-strict", "verified": True, "fallback_used": False,
                },
                "evidence": evidence("apk"),
            }

        packages = []
        embedded = []
        for artifact_id, spec in artifact_signing.items():
            if not artifact_id.startswith("package:"):
                continue
            package = artifact_id.removeprefix("package:")
            for split in spec["splits"]:
                record = package_record(package, split, spec["container"])
                (embedded if spec["container"].startswith("apex:") else packages).append(record)

        apex_spec = artifact_signing["apex:com.android.runtime"]
        apex_file_sha = h(epoch * 1000 + 4000)
        apex = {
            "apex_name": "com.android.runtime",
            "container_type": "apex",
            "archive_member": "APEX/com.android.runtime.apex",
            "file_sha256": apex_file_sha,
            "bytes": 500000,
            "outer_apk_sha256": apex_file_sha,
            "outer_signer_der_sha256": [role_signers["releasekey"]],
            "outer_assignment": signing_assignment(apex_spec),
            "outer_verification": {
                "method": "apksigner-strict", "verified": True, "fallback_used": False,
            },
            "outer_evidence": evidence("apex-outer"),
            "payload": {
                "public_key_sha256": h(2100),
                "verification_key_sha256": h(2100),
                "source_binding_sha256": h(2101),
                "method": "avbtool-verify-image",
                "verified": True,
                "pubkey_evidence": evidence("apex-pubkey"),
                "verification_evidence": evidence("apex-payload-verify"),
            },
            "embedded_packages": embedded,
        }
        return {
            "schema": 1,
            "label": label,
            "receipt_sha256": h(5000 + epoch),
            "signed_target_files_sha256": h(5100 + epoch),
            "inventory_evidence_sha256": h(5200 + epoch),
            "tool_identities": dict(policy["trusted_tools"]),
            "packages": packages,
            "apexes": [apex],
        }

    return policy, endpoint("predecessor", 1), endpoint("successor", 2)


def find_package(endpoint: dict, package: str, split=None) -> dict:
    candidates = list(endpoint["packages"])
    for apex in endpoint["apexes"]:
        candidates.extend(apex["embedded_packages"])
    return next(item for item in candidates if item["package_name"] == package and item["split_name"] == split)


class SignerContinuityPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy, self.before, self.after = fixture()

    def reject(self, fragment: str):
        with self.assertRaisesRegex(PolicyError, fragment):
            verify_pair(self.policy, self.before, self.after)

    def test_healthy_fixed_seed_pair_passes(self):
        report = verify_pair(self.policy, self.before, self.after)
        self.assertTrue(report["valid"])
        self.assertFalse(report["cryptography_or_archive_extraction_performed"])
        self.assertEqual(13, report["counts"]["packages"])
        self.assertEqual(14, report["counts"]["package_splits"])
        self.assertEqual(1, report["counts"]["apexes"])
        self.assertEqual(1, report["counts"]["shared_uids"])

    def test_path_moves_use_actual_package_and_apex_identity(self):
        find_package(self.after, "com.example.bluetooth")["archive_member"] = "SYSTEM_EXT/app/BluetoothMoved.apk"
        self.after["apexes"][0]["archive_member"] = "SYSTEM_EXT/apex/runtime-moved.apex"
        report = verify_pair(self.policy, self.before, self.after)
        self.assertEqual("com.example.bluetooth", report["package_path_moves"][0]["package"])
        self.assertEqual("com.android.runtime", report["apex_path_moves"][0]["apex"])

    def test_changed_role_signer_rejected(self):
        find_package(self.after, "com.example.bluetooth")["signer_der_sha256"] = [h(9999)]
        self.reject("actual DER signer set")

    def test_added_or_removed_package_rejected(self):
        self.after["packages"] = self.after["packages"][:-1]
        self.reject("inventory differs")

    def test_both_endpoints_cannot_omit_expected_external_package(self):
        for endpoint in (self.before, self.after):
            endpoint["packages"] = [p for p in endpoint["packages"] if p["package_name"] != "com.vendor.camera"]
        self.reject("inventory differs")

    def test_duplicate_actual_package_split_rejected(self):
        self.after["packages"].append(copy.deepcopy(self.after["packages"][0]))
        self.after["packages"][-1]["evidence"]["path"] = "raw/successor/duplicate.txt"
        self.reject("duplicate actual package/split")

    def test_same_package_cannot_alias_partition_and_apex(self):
        duplicate = copy.deepcopy(find_package(self.after, "com.example.bluetooth"))
        duplicate["container"] = "apex:com.android.runtime"
        duplicate["archive_member"] = "app/alias.apk"
        duplicate["evidence"]["path"] = "raw/successor/alias.txt"
        self.after["apexes"][0]["embedded_packages"].append(duplicate)
        self.reject("container.*does not match|duplicate actual package/split")

    def test_role_assignment_label_mismatch_rejected(self):
        find_package(self.after, "com.example.bluetooth")["assignment"]["role"] = "platform"
        self.reject("source-bound policy assignment")

    def test_role_assignment_source_binding_mismatch_rejected(self):
        find_package(self.after, "com.example.bluetooth")["assignment"]["source_binding_sha256"] = h(9998)
        self.reject("source-bound policy assignment")

    def test_all_nine_role_certificate_identities_must_be_distinct(self):
        self.policy["role_signers"]["bluetooth"] = self.policy["role_signers"]["platform"]
        self.reject("must be distinct")

    def test_each_required_role_needs_actual_package_coverage(self):
        self.policy["artifact_signing"]["package:com.example.bluetooth"]["role"] = "platform"
        self.reject("actual package assignments must cover")

    def test_apex_outer_role_does_not_replace_package_role_coverage(self):
        self.policy["artifact_signing"]["package:com.example.release"]["role"] = "platform"
        self.policy["artifact_signing"]["package:com.example.embedded"]["role"] = "platform"
        self.reject("actual package assignments must cover")

    def test_external_exception_signer_is_exact(self):
        find_package(self.after, "com.vendor.camera")["signer_der_sha256"] = [h(1101)]
        self.reject("actual DER signer set")

    def test_external_exception_kind_is_source_bound(self):
        find_package(self.after, "com.vendor.camera")["assignment"]["exception_kind"] = "presigned"
        self.reject("source-bound policy assignment")

    def test_external_exception_source_is_source_bound(self):
        find_package(self.after, "com.vendor.camera")["assignment"]["source_binding_sha256"] = h(9997)
        self.reject("source-bound policy assignment")

    def test_source_bound_presigned_exception_passes(self):
        report = verify_pair(self.policy, self.before, self.after)
        self.assertTrue(report["valid"])
        self.assertEqual([h(1111)], find_package(self.after, "com.vendor.presigned")["signer_der_sha256"])

    def test_presigned_exception_unknown_signer_rejected(self):
        find_package(self.after, "com.vendor.presigned")["signer_der_sha256"] = [h(9991)]
        self.reject("actual DER signer set")

    def test_external_signers_must_be_sorted_and_unique(self):
        self.policy["artifact_signing"]["package:com.vendor.camera"]["signer_der_sha256"] = [h(1102), h(1101)]
        self.reject("sorted and duplicate-free")

    def test_matching_shared_uid_signer_sets_pass(self):
        report = verify_pair(self.policy, self.before, self.after)
        self.assertEqual(
            ["com.example.platform", "com.example.platformhelper"],
            report["shared_uid_membership"]["android.uid.example.platform"],
        )

    def test_shared_uid_different_signers_rejected(self):
        find_package(self.after, "com.example.bluetooth")["shared_uid"] = "android.uid.example.platform"
        self.reject("contains different actual DER signer sets")

    def test_shared_uid_membership_change_rejected_across_pair(self):
        find_package(self.after, "com.example.platformhelper")["shared_uid"] = None
        self.reject("changed shared_uid|sharedUserId membership sets changed")

    def test_split_shared_uid_disagreement_rejected(self):
        find_package(self.after, "com.example.platform", "feature")["shared_uid"] = None
        self.reject("split records disagree")

    def test_trusted_tool_identity_drift_rejected(self):
        self.after["tool_identities"]["apksigner"] = h(9996)
        self.reject("tool identities")

    def test_malformed_hash_rejected(self):
        self.after["receipt_sha256"] = "abc"
        self.reject("lowercase SHA-256")

    def test_deprecated_apk_certificate_fallback_rejected(self):
        find_package(self.after, "com.example.bluetooth")["verification"]["fallback_used"] = True
        self.reject("fallback certificate extraction")

    def test_failed_apksigner_rejected(self):
        find_package(self.after, "com.example.bluetooth")["verification"]["verified"] = False
        self.reject("verification did not succeed")

    def test_unknown_lineage_or_unreviewed_field_rejected(self):
        find_package(self.after, "com.example.bluetooth")["signing_lineage"] = [h(1), h(2)]
        self.reject("fields must be exactly")

    def test_raw_evidence_path_alias_rejected(self):
        a = find_package(self.after, "com.example.bluetooth")
        b = find_package(self.after, "com.example.media")
        b["evidence"]["path"] = a["evidence"]["path"]
        self.reject("raw evidence path.*aliased")

    def test_raw_evidence_path_traversal_rejected(self):
        find_package(self.after, "com.example.bluetooth")["evidence"]["path"] = "../forged.txt"
        self.reject("traversal component")

    def test_apex_outer_signer_join_rejected(self):
        self.after["apexes"][0]["outer_signer_der_sha256"] = [h(9995)]
        self.reject("outer APEX DER signer")

    def test_apex_outer_fallback_rejected(self):
        self.after["apexes"][0]["outer_verification"]["fallback_used"] = True
        self.reject("fallback certificate extraction")

    def test_apex_payload_public_key_join_rejected(self):
        self.after["apexes"][0]["payload"]["public_key_sha256"] = h(9994)
        self.reject("bundled APEX public key")

    def test_apex_payload_source_binding_rejected(self):
        self.after["apexes"][0]["payload"]["source_binding_sha256"] = h(9993)
        self.reject("payload assignment source binding")

    def test_apex_payload_verification_failure_rejected(self):
        self.after["apexes"][0]["payload"]["verified"] = False
        self.reject("must pass pinned avbtool")

    def test_embedded_apk_is_required_and_verified(self):
        self.after["apexes"][0]["embedded_packages"] = []
        self.reject("inventory differs")

    def test_embedded_apk_wrong_signer_rejected(self):
        find_package(self.after, "com.example.embedded")["signer_der_sha256"] = [h(9992)]
        self.reject("actual DER signer set")

    def test_duplicate_apex_identity_rejected(self):
        clone = copy.deepcopy(self.after["apexes"][0])
        clone["outer_evidence"]["path"] = "raw/successor/duplicate-apex.txt"
        self.after["apexes"].append(clone)
        self.reject("raw evidence path.*aliased|duplicate actual APEX")

    def test_apex_extension_boundary_rejected(self):
        self.after["apexes"][0]["archive_member"] = "APEX/com.android.runtime.capex"
        self.reject("must end with")

    def test_complete_capex_boundary_can_pass(self):
        self.policy["artifact_signing"]["apex:com.android.runtime"]["container_type"] = "capex"
        for endpoint, suffix in ((self.before, "predecessor"), (self.after, "successor")):
            apex = endpoint["apexes"][0]
            apex["container_type"] = "capex"
            apex["archive_member"] = "APEX/com.android.runtime.capex"
            apex["outer_apk_sha256"] = h(7000 if suffix == "predecessor" else 7001)
            apex["payload"]["decompressed_apex_sha256"] = apex["outer_apk_sha256"]
            apex["payload"]["decompression_evidence"] = {
                "path": f"raw/{suffix}/capex-decompress.txt", "sha256": h(7100 if suffix == "predecessor" else 7101),
                "bytes": 321,
            }
        self.assertTrue(verify_pair(self.policy, self.before, self.after)["valid"])

    def test_capex_without_decompression_proof_rejected(self):
        self.policy["artifact_signing"]["apex:com.android.runtime"]["container_type"] = "capex"
        for index, endpoint in enumerate((self.before, self.after)):
            endpoint["apexes"][0]["container_type"] = "capex"
            endpoint["apexes"][0]["archive_member"] = "APEX/com.android.runtime.capex"
            endpoint["apexes"][0]["outer_apk_sha256"] = h(7200 + index)
        self.reject("fields must be exactly")

    def test_capex_cannot_alias_compressed_and_decompressed_identity(self):
        self.policy["artifact_signing"]["apex:com.android.runtime"]["container_type"] = "capex"
        for endpoint in (self.before, self.after):
            apex = endpoint["apexes"][0]
            apex["container_type"] = "capex"
            apex["archive_member"] = "APEX/com.android.runtime.capex"
            apex["payload"]["decompressed_apex_sha256"] = apex["outer_apk_sha256"]
            apex["payload"]["decompression_evidence"] = {
                "path": f"raw/{endpoint['label']}/capex-decompress.txt",
                "sha256": h(7300 if endpoint["label"] == "predecessor" else 7301), "bytes": 123,
            }
        self.reject("must have distinct identities")

    def test_same_endpoint_receipt_substitution_rejected(self):
        self.after["receipt_sha256"] = self.before["receipt_sha256"]
        self.reject("receipt identities must differ")

    def test_same_target_files_substitution_rejected(self):
        self.after["signed_target_files_sha256"] = self.before["signed_target_files_sha256"]
        self.reject("target-files identities must differ")

    def test_extra_endpoint_field_rejected(self):
        self.after["passed"] = True
        self.reject("fields must be exactly")

    def test_non_string_schema_field_name_rejected_deterministically(self):
        self.after[7] = "forged"
        self.reject("field names must be strings")


if __name__ == "__main__":
    unittest.main(verbosity=2)

