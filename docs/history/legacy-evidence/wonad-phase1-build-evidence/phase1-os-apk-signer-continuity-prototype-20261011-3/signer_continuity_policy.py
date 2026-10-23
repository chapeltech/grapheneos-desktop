#!/usr/bin/env python3
"""Hardened v3 wrapper for the frozen Phase-1 signer policy prototype.

This remains a pure semantic checker over synthetic/pre-authenticated records.
It performs no archive extraction and no cryptographic verification. V3 loads
the exact frozen v1 implementation from one authenticated raw-byte snapshot,
adds the two independently reviewed v2 invariants, and delegates every
existing semantic check to v1.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from authenticated_source import load_authenticated_module


V1_SHA256 = "4570e425bec60944de4e1d181d1a43d8a5cf224fae930736bdf1ab682534f788"
V1_PATH = (
    Path(__file__).resolve().parent.parent
    / "phase1-os-apk-signer-continuity-prototype-20261011-1"
    / "signer_continuity_policy.py"
)


def _load_frozen_v1():
    return load_authenticated_module(
        V1_PATH, V1_SHA256, "_wonad_signer_continuity_policy_v1"
    )


_V1 = _load_frozen_v1()
OS_ROLES = _V1.OS_ROLES
PolicyError = _V1.PolicyError


def _exact_schema_one(value: Any, context: str) -> None:
    """Reject Python's bool/int alias before v1's equality-only check."""
    if type(value) is not dict:
        return  # The frozen strict-object validator reports the shape error.
    if "schema" in value and (type(value["schema"]) is not int or value["schema"] != 1):
        raise PolicyError(f"{context}: schema must be the exact integer 1")


def _claim(
    claims: dict[tuple[str, str], str], namespace: str, member: Any, owner: str, context: str
) -> None:
    """Claim one physical archive member within one extraction namespace.

    Malformed member values are left to v1's canonical relative-path parser.
    Only well-typed candidate strings participate in the alias preflight.
    """
    if type(member) is not str:
        return
    key = (namespace, member)
    previous = claims.get(key)
    if previous is not None:
        # A repeated record for the same logical owner is still invalid, but
        # the frozen v1 identity checks diagnose it more precisely. V3's
        # preflight is specifically the cross-owner member-alias guard.
        if previous == owner:
            return
        raise PolicyError(
            f"{context}: archive member {member!r} in namespace {namespace!r} "
            f"is aliased by {previous} and {owner}"
        )
    claims[key] = owner


def _package_owner(value: Any, fallback: str) -> str:
    if type(value) is not dict:
        return fallback
    package = value.get("package_name")
    split = value.get("split_name")
    if type(package) is str:
        return f"package:{package}/{split if type(split) is str else 'base'}"
    return fallback


def _archive_member_ownership(endpoint: Any, context: str) -> None:
    """Require a 1:1 physical member map inside each endpoint.

    Partition APKs and APEX/CAPEX containers share the target-files namespace.
    Embedded APK paths are scoped to the enclosing actual APEX identity, so an
    equal relative path in two distinct APEX payloads is intentionally valid.
    """
    if type(endpoint) is not dict:
        return
    claims: dict[tuple[str, str], str] = {}

    packages = endpoint.get("packages")
    if type(packages) is list:
        for index, package in enumerate(packages):
            if type(package) is not dict:
                continue
            _claim(
                claims,
                "target-files",
                package.get("archive_member"),
                _package_owner(package, f"partition-package[{index}]"),
                context,
            )

    apexes = endpoint.get("apexes")
    if type(apexes) is not list:
        return
    for apex_index, apex in enumerate(apexes):
        if type(apex) is not dict:
            continue
        apex_name = apex.get("apex_name")
        apex_owner = f"apex:{apex_name}" if type(apex_name) is str else f"apex[{apex_index}]"
        _claim(
            claims,
            "target-files",
            apex.get("archive_member"),
            apex_owner,
            context,
        )
        embedded = apex.get("embedded_packages")
        if type(embedded) is not list:
            continue
        namespace = f"apex:{apex_name}" if type(apex_name) is str else f"apex-index:{apex_index}"
        for package_index, package in enumerate(embedded):
            if type(package) is not dict:
                continue
            _claim(
                claims,
                namespace,
                package.get("archive_member"),
                _package_owner(package, f"embedded-package[{package_index}]"),
                context,
            )


def verify_pair(policy: Any, predecessor: Any, successor: Any) -> dict[str, Any]:
    """Apply v3 loader/input hardening and all frozen v1 semantic checks."""
    _exact_schema_one(policy, "policy")
    _exact_schema_one(predecessor, "predecessor")
    _exact_schema_one(successor, "successor")
    _archive_member_ownership(predecessor, "predecessor")
    _archive_member_ownership(successor, "successor")
    report = _V1.verify_pair(policy, predecessor, successor)
    return {
        **report,
        "kind": "phase1_fixed_seed_os_signer_continuity_semantic_report_v3",
    }
