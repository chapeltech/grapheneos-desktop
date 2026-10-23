#!/usr/bin/env python3
"""Snapshot-load the exact v1 fixture and extend it for v3 controls."""

from __future__ import annotations

import copy
from pathlib import Path

from authenticated_source import load_authenticated_module


V1_TEST_SHA256 = "be948981966804e26bf1487da26bb438a968f2602ee2f86c7bf3ef782a6600c0"
V1_POLICY_SHA256 = "4570e425bec60944de4e1d181d1a43d8a5cf224fae930736bdf1ab682534f788"
V1_TEST_PATH = (
    Path(__file__).resolve().parent.parent
    / "phase1-os-apk-signer-continuity-prototype-20261011-1"
    / "test_signer_continuity_policy.py"
)
V1_POLICY_PATH = V1_TEST_PATH.with_name("signer_continuity_policy.py")


def _load_v1_policy():
    return load_authenticated_module(
        V1_POLICY_PATH,
        V1_POLICY_SHA256,
        "_wonad_signer_continuity_fixture_policy_v1",
    )


def _load_v1_tests():
    return load_authenticated_module(
        V1_TEST_PATH,
        V1_TEST_SHA256,
        "_wonad_signer_continuity_tests_v1",
    )


V1_POLICY = _load_v1_policy()
V1_TESTS = _load_v1_tests()
# The frozen v1 test source uses an unqualified import. Explicitly restore its
# globals to the independently snapshot-loaded v1 policy even when v3 is
# already present under the conventional module name.
V1_TESTS.verify_pair = V1_POLICY.verify_pair
V1_TESTS.PolicyError = V1_POLICY.PolicyError
V1_VERIFY = V1_POLICY.verify_pair
V1_ERROR = V1_POLICY.PolicyError
fixture = V1_TESTS.fixture
find_package = V1_TESTS.find_package
h = V1_TESTS.h


def add_second_apex(policy: dict, *endpoints: dict) -> None:
    name = "com.android.second"
    policy["artifact_signing"][f"apex:{name}"] = {
        "kind": "role",
        "role": "releasekey",
        "source_binding_sha256": h(8100),
        "container_type": "apex",
    }
    policy["apex_payload_keys"][name] = {
        "public_key_sha256": h(8101),
        "source_binding_sha256": h(8102),
    }
    for index, endpoint in enumerate(endpoints):
        clone = copy.deepcopy(endpoint["apexes"][0])
        clone["apex_name"] = name
        clone["archive_member"] = "APEX/com.android.second.apex"
        clone["file_sha256"] = h(8110 + index)
        clone["outer_apk_sha256"] = clone["file_sha256"]
        clone["outer_assignment"]["source_binding_sha256"] = h(8100)
        clone["outer_evidence"] = {
            "path": f"raw/{endpoint['label']}/second-apex-outer.txt",
            "sha256": h(8120 + index),
            "bytes": 401,
        }
        clone["payload"]["public_key_sha256"] = h(8101)
        clone["payload"]["verification_key_sha256"] = h(8101)
        clone["payload"]["source_binding_sha256"] = h(8102)
        clone["payload"]["pubkey_evidence"] = {
            "path": f"raw/{endpoint['label']}/second-apex-pubkey.txt",
            "sha256": h(8130 + index),
            "bytes": 402,
        }
        clone["payload"]["verification_evidence"] = {
            "path": f"raw/{endpoint['label']}/second-apex-verify.txt",
            "sha256": h(8140 + index),
            "bytes": 403,
        }
        clone["embedded_packages"] = []
        endpoint["apexes"].append(clone)


def add_embedded_package(
    policy: dict,
    endpoints: tuple[dict, ...],
    *,
    apex_name: str,
    package_name: str,
    archive_member: str,
    seed: int,
) -> None:
    policy["artifact_signing"][f"package:{package_name}"] = {
        "kind": "role",
        "role": "releasekey",
        "source_binding_sha256": h(seed),
        "container": f"apex:{apex_name}",
        "splits": ["base"],
    }
    for index, endpoint in enumerate(endpoints):
        source = endpoint["apexes"][0]["embedded_packages"][0]
        record = copy.deepcopy(source)
        record["package_name"] = package_name
        record["container"] = f"apex:{apex_name}"
        record["archive_member"] = archive_member
        record["file_sha256"] = h(seed + 10 + index)
        record["assignment"]["source_binding_sha256"] = h(seed)
        record["evidence"] = {
            "path": f"raw/{endpoint['label']}/{package_name}-apk.txt",
            "sha256": h(seed + 20 + index),
            "bytes": 404,
        }
        apex = next(row for row in endpoint["apexes"] if row["apex_name"] == apex_name)
        apex["embedded_packages"].append(record)
