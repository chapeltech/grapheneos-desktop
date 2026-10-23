#!/usr/bin/env python3
"""Pure Phase-1 signer-continuity policy over pre-authenticated inventories.

This prototype deliberately performs no archive parsing and no cryptography.
Its inputs model observations that a future producer must obtain with pinned
official tools and bind to raw evidence.  It exists to make the semantic
acceptance rules deterministic and adversarially testable without claiming a
release-verification gate.
"""

from __future__ import annotations

import re
from typing import Any


OS_ROLES = (
    "bluetooth",
    "gmscompat_lib",
    "media",
    "networkstack",
    "nfc",
    "platform",
    "releasekey",
    "sdk_sandbox",
    "shared",
)

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
IDENTITY_RE = re.compile(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+\Z")
SPLIT_RE = re.compile(r"[A-Za-z0-9_.-]+\Z")
SHARED_UID_RE = re.compile(r"[A-Za-z0-9_.]+\Z")


class PolicyError(ValueError):
    """The supplied policy or inventory fails closed."""


def _fail(context: str, message: str) -> None:
    raise PolicyError(f"{context}: {message}")


def _object(value: Any, required: set[str], context: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(context, "must be an object")
    if any(type(key) is not str for key in value):
        _fail(context, "field names must be strings")
    keys = set(value)
    if keys != required:
        _fail(context, f"fields must be exactly {sorted(required)!r}, got {sorted(keys)!r}")
    return value


def _list(value: Any, context: str) -> list[Any]:
    if type(value) is not list:
        _fail(context, "must be an array")
    return value


def _text(value: Any, context: str) -> str:
    if type(value) is not str or not value:
        _fail(context, "must be a non-empty string")
    return value


def _sha256(value: Any, context: str) -> str:
    value = _text(value, context)
    if SHA256_RE.fullmatch(value) is None:
        _fail(context, "must be one lowercase SHA-256 hex digest")
    return value


def _positive_int(value: Any, context: str) -> int:
    if type(value) is not int or value <= 0:
        _fail(context, "must be a positive integer")
    return value


def _identity(value: Any, context: str) -> str:
    value = _text(value, context)
    if IDENTITY_RE.fullmatch(value) is None:
        _fail(context, "must be a dotted package identity")
    return value


def _relative_path(value: Any, context: str, suffix: str | tuple[str, ...] | None = None) -> str:
    value = _text(value, context)
    parts = value.split("/")
    if value.startswith("/") or "\\" in value or "\x00" in value:
        _fail(context, "must be a safe relative POSIX path")
    if any(part in {"", ".", ".."} for part in parts):
        _fail(context, "contains an empty or traversal component")
    if suffix is not None and not value.endswith(suffix):
        _fail(context, f"must end with {suffix!r}")
    return value


def _sorted_unique_strings(value: Any, context: str, *, hashes: bool = False) -> tuple[str, ...]:
    raw = _list(value, context)
    converted = tuple(
        _sha256(item, f"{context}[{index}]") if hashes else _text(item, f"{context}[{index}]")
        for index, item in enumerate(raw)
    )
    if not converted:
        _fail(context, "must not be empty")
    if list(converted) != sorted(set(converted)):
        _fail(context, "must be sorted and duplicate-free")
    return converted


def _evidence(value: Any, context: str, observed_paths: set[str]) -> dict[str, Any]:
    value = _object(value, {"path", "sha256", "bytes"}, context)
    path = _relative_path(value["path"], f"{context}.path")
    if path in observed_paths:
        _fail(context, f"raw evidence path {path!r} is aliased")
    observed_paths.add(path)
    return {
        "path": path,
        "sha256": _sha256(value["sha256"], f"{context}.sha256"),
        "bytes": _positive_int(value["bytes"], f"{context}.bytes"),
    }


def _strict_apk_verification(value: Any, context: str) -> None:
    value = _object(value, {"method", "verified", "fallback_used"}, context)
    if value["method"] != "apksigner-strict":
        _fail(context, "method must be apksigner-strict")
    if value["verified"] is not True:
        _fail(context, "verification did not succeed")
    if value["fallback_used"] is not False:
        _fail(context, "deprecated/fallback certificate extraction is forbidden")


def _validate_signing_spec(identity: str, spec: Any, context: str, *, package: bool) -> dict[str, Any]:
    common = {"kind", "source_binding_sha256"}
    package_fields = {"container", "splits"} if package else {"container_type"}
    if type(spec) is not dict:
        _fail(context, "must be an object")
    kind = spec.get("kind")
    if kind == "role":
        expected = common | package_fields | {"role"}
    elif kind == "external":
        expected = common | package_fields | {"exception_kind", "signer_der_sha256"}
    else:
        _fail(context, "kind must be role or external")
    _object(spec, expected, context)

    result: dict[str, Any] = {
        "kind": kind,
        "source_binding_sha256": _sha256(spec["source_binding_sha256"], f"{context}.source_binding_sha256"),
    }
    if package:
        container = _text(spec["container"], f"{context}.container")
        if container != "partition" and not container.startswith("apex:"):
            _fail(context, "package container must be partition or apex:<actual-name>")
        if container.startswith("apex:"):
            _identity(container.removeprefix("apex:"), f"{context}.container")
        splits = _sorted_unique_strings(spec["splits"], f"{context}.splits")
        if "base" not in splits:
            _fail(context, "package split inventory must contain base")
        for split in splits:
            if split != "base" and SPLIT_RE.fullmatch(split) is None:
                _fail(context, f"invalid split identity {split!r}")
        result.update(container=container, splits=splits)
    else:
        container_type = _text(spec["container_type"], f"{context}.container_type")
        if container_type not in {"apex", "capex"}:
            _fail(context, "container_type must be apex or capex")
        result["container_type"] = container_type

    if kind == "role":
        role = _text(spec["role"], f"{context}.role")
        if role not in OS_ROLES:
            _fail(context, f"unknown OS role {role!r}")
        result["role"] = role
    else:
        exception_kind = _text(spec["exception_kind"], f"{context}.exception_kind")
        if exception_kind not in {"presigned", "vendor_external"}:
            _fail(context, "external exception must be source-bound presigned or vendor_external")
        result["exception_kind"] = exception_kind
        result["signers"] = _sorted_unique_strings(
            spec["signer_der_sha256"], f"{context}.signer_der_sha256", hashes=True
        )
    return result


def _validate_policy(policy: Any) -> dict[str, Any]:
    context = "policy"
    policy = _object(
        policy,
        {
            "schema",
            "scope",
            "required_roles",
            "role_signers",
            "trusted_tools",
            "artifact_signing",
            "apex_payload_keys",
        },
        context,
    )
    if policy["schema"] != 1:
        _fail(context, "schema must be 1")
    if policy["scope"] != "phase1-fixed-seed-pair":
        _fail(context, "scope must be phase1-fixed-seed-pair")
    if policy["required_roles"] != list(OS_ROLES):
        _fail(context, "required_roles must be the exact ordered nine-role Phase-1 set")

    role_signers = _object(policy["role_signers"], set(OS_ROLES), "policy.role_signers")
    role_signers = {role: _sha256(role_signers[role], f"policy.role_signers.{role}") for role in OS_ROLES}
    if len(set(role_signers.values())) != len(OS_ROLES):
        _fail("policy.role_signers", "all nine independent role certificates must be distinct")

    if type(policy["trusted_tools"]) is not dict or not policy["trusted_tools"]:
        _fail("policy.trusted_tools", "must be a non-empty object")
    if any(type(name) is not str for name in policy["trusted_tools"]):
        _fail("policy.trusted_tools", "tool names must be strings")
    trusted_tools: dict[str, str] = {}
    for name in sorted(policy["trusted_tools"]):
        if not SPLIT_RE.fullmatch(_text(name, "policy.trusted_tools key")):
            _fail("policy.trusted_tools", f"invalid tool name {name!r}")
        trusted_tools[name] = _sha256(policy["trusted_tools"][name], f"policy.trusted_tools.{name}")

    if type(policy["artifact_signing"]) is not dict or not policy["artifact_signing"]:
        _fail("policy.artifact_signing", "must be a non-empty object")
    if any(type(name) is not str for name in policy["artifact_signing"]):
        _fail("policy.artifact_signing", "artifact identities must be strings")
    signing: dict[str, dict[str, Any]] = {}
    for artifact_id in sorted(policy["artifact_signing"]):
        if artifact_id.startswith("package:"):
            name = _identity(artifact_id.removeprefix("package:"), "policy.artifact_signing package key")
            canonical_id = f"package:{name}"
            package = True
        elif artifact_id.startswith("apex:"):
            name = _identity(artifact_id.removeprefix("apex:"), "policy.artifact_signing apex key")
            canonical_id = f"apex:{name}"
            package = False
        else:
            _fail("policy.artifact_signing", f"invalid actual artifact identity {artifact_id!r}")
        if canonical_id != artifact_id:
            _fail("policy.artifact_signing", f"non-canonical identity {artifact_id!r}")
        signing[artifact_id] = _validate_signing_spec(
            artifact_id, policy["artifact_signing"][artifact_id],
            f"policy.artifact_signing[{artifact_id!r}]", package=package,
        )

    package_role_coverage = {
        spec["role"] for artifact_id, spec in signing.items()
        if artifact_id.startswith("package:") and spec["kind"] == "role"
    }
    if package_role_coverage != set(OS_ROLES):
        _fail(
            "policy.artifact_signing",
            "actual package assignments must cover every required role; APEX outer roles do not substitute",
        )

    apex_names = {item.removeprefix("apex:") for item in signing if item.startswith("apex:")}
    if type(policy["apex_payload_keys"]) is not dict:
        _fail("policy.apex_payload_keys", "must be an object")
    if any(type(name) is not str for name in policy["apex_payload_keys"]):
        _fail("policy.apex_payload_keys", "APEX identities must be strings")
    if set(policy["apex_payload_keys"]) != apex_names:
        _fail("policy.apex_payload_keys", "keys must exactly match the expected actual APEX identities")
    payload_keys: dict[str, dict[str, str]] = {}
    for name in sorted(apex_names):
        value = _object(
            policy["apex_payload_keys"][name],
            {"public_key_sha256", "source_binding_sha256"},
            f"policy.apex_payload_keys[{name!r}]",
        )
        payload_keys[name] = {
            "public_key_sha256": _sha256(value["public_key_sha256"], f"policy.apex_payload_keys.{name}.public_key_sha256"),
            "source_binding_sha256": _sha256(value["source_binding_sha256"], f"policy.apex_payload_keys.{name}.source_binding_sha256"),
        }

    for artifact_id, spec in signing.items():
        if artifact_id.startswith("package:") and spec["container"].startswith("apex:"):
            apex_name = spec["container"].removeprefix("apex:")
            if apex_name not in apex_names:
                _fail("policy.artifact_signing", f"embedded package refers to unknown APEX {apex_name!r}")

    return {
        "role_signers": role_signers,
        "trusted_tools": trusted_tools,
        "signing": signing,
        "payload_keys": payload_keys,
    }


def _expected_signers(spec: dict[str, Any], normalized_policy: dict[str, Any]) -> tuple[str, ...]:
    if spec["kind"] == "role":
        return (normalized_policy["role_signers"][spec["role"]],)
    return spec["signers"]


def _assignment(value: Any, spec: dict[str, Any], context: str) -> dict[str, str]:
    if spec["kind"] == "role":
        value = _object(value, {"kind", "role", "source_binding_sha256"}, context)
        expected = {
            "kind": "role",
            "role": spec["role"],
            "source_binding_sha256": spec["source_binding_sha256"],
        }
    else:
        value = _object(value, {"kind", "exception_kind", "source_binding_sha256"}, context)
        expected = {
            "kind": "external",
            "exception_kind": spec["exception_kind"],
            "source_binding_sha256": spec["source_binding_sha256"],
        }
    if value != expected:
        _fail(context, f"does not equal source-bound policy assignment {expected!r}")
    return expected


def _package_record(
    value: Any,
    context: str,
    normalized_policy: dict[str, Any],
    observed_evidence: set[str],
    expected_container: str,
) -> dict[str, Any]:
    value = _object(
        value,
        {
            "package_name", "split_name", "container", "archive_member", "file_sha256", "bytes",
            "signer_der_sha256", "shared_uid", "assignment", "verification", "evidence",
        },
        context,
    )
    name = _identity(value["package_name"], f"{context}.package_name")
    artifact_id = f"package:{name}"
    spec = normalized_policy["signing"].get(artifact_id)
    if spec is None or "splits" not in spec:
        _fail(context, f"unexpected actual package identity {name!r}")
    container = _text(value["container"], f"{context}.container")
    if container != expected_container or container != spec["container"]:
        _fail(context, f"container {container!r} does not match source-bound boundary")
    split = value["split_name"]
    if split is None:
        split_key = "base"
    else:
        split_key = _text(split, f"{context}.split_name")
        if split_key == "base" or SPLIT_RE.fullmatch(split_key) is None:
            _fail(context, "split_name must be null for base or a valid non-base split")
    if split_key not in spec["splits"]:
        _fail(context, f"unexpected split identity {split_key!r}")
    archive_member = _relative_path(value["archive_member"], f"{context}.archive_member", ".apk")
    signers = _sorted_unique_strings(value["signer_der_sha256"], f"{context}.signer_der_sha256", hashes=True)
    expected_signers = _expected_signers(spec, normalized_policy)
    if signers != expected_signers:
        _fail(context, f"actual DER signer set does not equal independently bound set {expected_signers!r}")
    shared_uid = value["shared_uid"]
    if shared_uid is not None:
        shared_uid = _text(shared_uid, f"{context}.shared_uid")
        if SHARED_UID_RE.fullmatch(shared_uid) is None:
            _fail(context, "invalid sharedUserId")
    assignment = _assignment(value["assignment"], spec, f"{context}.assignment")
    _strict_apk_verification(value["verification"], f"{context}.verification")
    evidence = _evidence(value["evidence"], f"{context}.evidence", observed_evidence)
    return {
        "key": (name, split_key),
        "package_name": name,
        "split": split_key,
        "container": container,
        "archive_member": archive_member,
        "file_sha256": _sha256(value["file_sha256"], f"{context}.file_sha256"),
        "bytes": _positive_int(value["bytes"], f"{context}.bytes"),
        "signers": signers,
        "shared_uid": shared_uid,
        "assignment": assignment,
        "evidence": evidence,
    }


def _apex_record(
    value: Any,
    context: str,
    normalized_policy: dict[str, Any],
    observed_evidence: set[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    value = _object(
        value,
        {
            "apex_name", "container_type", "archive_member", "file_sha256", "bytes", "outer_apk_sha256",
            "outer_signer_der_sha256", "outer_assignment", "outer_verification", "outer_evidence",
            "payload", "embedded_packages",
        },
        context,
    )
    name = _identity(value["apex_name"], f"{context}.apex_name")
    artifact_id = f"apex:{name}"
    spec = normalized_policy["signing"].get(artifact_id)
    if spec is None or "container_type" not in spec:
        _fail(context, f"unexpected actual APEX identity {name!r}")
    container_type = _text(value["container_type"], f"{context}.container_type")
    if container_type != spec["container_type"]:
        _fail(context, "APEX/.capex boundary does not equal source-bound policy")
    suffix = ".apex" if container_type == "apex" else ".capex"
    archive_member = _relative_path(value["archive_member"], f"{context}.archive_member", suffix)
    file_sha = _sha256(value["file_sha256"], f"{context}.file_sha256")
    outer_sha = _sha256(value["outer_apk_sha256"], f"{context}.outer_apk_sha256")
    if container_type == "apex" and outer_sha != file_sha:
        _fail(context, "uncompressed APEX outer APK must be the archive member")
    if container_type == "capex" and outer_sha == file_sha:
        _fail(context, "compressed .capex and decompressed outer APEX must have distinct identities")
    signers = _sorted_unique_strings(value["outer_signer_der_sha256"], f"{context}.outer_signer_der_sha256", hashes=True)
    expected_signers = _expected_signers(spec, normalized_policy)
    if signers != expected_signers:
        _fail(context, f"outer APEX DER signer set does not equal {expected_signers!r}")
    assignment = _assignment(value["outer_assignment"], spec, f"{context}.outer_assignment")
    _strict_apk_verification(value["outer_verification"], f"{context}.outer_verification")
    outer_evidence = _evidence(value["outer_evidence"], f"{context}.outer_evidence", observed_evidence)

    payload_required = {
        "public_key_sha256", "verification_key_sha256", "source_binding_sha256", "method", "verified",
        "pubkey_evidence", "verification_evidence",
    }
    if container_type == "capex":
        payload_required |= {"decompressed_apex_sha256", "decompression_evidence"}
    payload = _object(value["payload"], payload_required, f"{context}.payload")
    payload_policy = normalized_policy["payload_keys"][name]
    public_key = _sha256(payload["public_key_sha256"], f"{context}.payload.public_key_sha256")
    verification_key = _sha256(payload["verification_key_sha256"], f"{context}.payload.verification_key_sha256")
    if public_key != payload_policy["public_key_sha256"] or verification_key != public_key:
        _fail(context, "actual bundled APEX public key and verification key must equal independent payload policy")
    if _sha256(payload["source_binding_sha256"], f"{context}.payload.source_binding_sha256") != payload_policy["source_binding_sha256"]:
        _fail(context, "APEX payload assignment source binding differs")
    if payload["method"] != "avbtool-verify-image" or payload["verified"] is not True:
        _fail(context, "APEX payload must pass pinned avbtool verify_image")
    pubkey_evidence = _evidence(payload["pubkey_evidence"], f"{context}.payload.pubkey_evidence", observed_evidence)
    verification_evidence = _evidence(
        payload["verification_evidence"], f"{context}.payload.verification_evidence", observed_evidence
    )
    decompression_evidence = None
    if container_type == "capex":
        decompressed = _sha256(payload["decompressed_apex_sha256"], f"{context}.payload.decompressed_apex_sha256")
        if decompressed != outer_sha:
            _fail(context, "decompressed .capex identity does not equal verified outer APEX")
        decompression_evidence = _evidence(
            payload["decompression_evidence"], f"{context}.payload.decompression_evidence", observed_evidence
        )

    embedded: list[dict[str, Any]] = []
    for index, package in enumerate(_list(value["embedded_packages"], f"{context}.embedded_packages")):
        embedded.append(
            _package_record(
                package,
                f"{context}.embedded_packages[{index}]",
                normalized_policy,
                observed_evidence,
                f"apex:{name}",
            )
        )
    return ({
        "name": name,
        "container_type": container_type,
        "archive_member": archive_member,
        "file_sha256": file_sha,
        "bytes": _positive_int(value["bytes"], f"{context}.bytes"),
        "outer_apk_sha256": outer_sha,
        "outer_signers": signers,
        "outer_assignment": assignment,
        "outer_evidence": outer_evidence,
        "payload_public_key_sha256": public_key,
        "payload_pubkey_evidence": pubkey_evidence,
        "payload_verification_evidence": verification_evidence,
        "decompression_evidence": decompression_evidence,
    }, embedded)


def _endpoint(value: Any, expected_label: str, normalized_policy: dict[str, Any]) -> dict[str, Any]:
    context = expected_label
    value = _object(
        value,
        {
            "schema", "label", "receipt_sha256", "signed_target_files_sha256", "inventory_evidence_sha256",
            "tool_identities", "packages", "apexes",
        },
        context,
    )
    if value["schema"] != 1 or value["label"] != expected_label:
        _fail(context, "schema/label mismatch")
    if value["tool_identities"] != normalized_policy["trusted_tools"]:
        _fail(context, "observed tool identities do not exactly equal trusted policy")
    observed_evidence: set[str] = set()
    packages: dict[tuple[str, str], dict[str, Any]] = {}
    for index, package in enumerate(_list(value["packages"], f"{context}.packages")):
        record = _package_record(
            package, f"{context}.packages[{index}]", normalized_policy, observed_evidence, "partition"
        )
        if record["key"] in packages:
            _fail(context, f"duplicate actual package/split identity {record['key']!r}")
        packages[record["key"]] = record

    apexes: dict[str, dict[str, Any]] = {}
    for index, apex in enumerate(_list(value["apexes"], f"{context}.apexes")):
        record, embedded = _apex_record(
            apex, f"{context}.apexes[{index}]", normalized_policy, observed_evidence
        )
        if record["name"] in apexes:
            _fail(context, f"duplicate actual APEX identity {record['name']!r}")
        apexes[record["name"]] = record
        for package in embedded:
            if package["key"] in packages:
                _fail(context, f"duplicate actual package/split identity {package['key']!r}")
            packages[package["key"]] = package

    expected_package_keys = {
        (artifact_id.removeprefix("package:"), split)
        for artifact_id, spec in normalized_policy["signing"].items()
        if artifact_id.startswith("package:")
        for split in spec["splits"]
    }
    if set(packages) != expected_package_keys:
        missing = sorted(expected_package_keys - set(packages))
        extra = sorted(set(packages) - expected_package_keys)
        _fail(context, f"package/split inventory differs from fixed seed policy; missing={missing!r} extra={extra!r}")
    expected_apexes = {
        artifact_id.removeprefix("apex:") for artifact_id in normalized_policy["signing"]
        if artifact_id.startswith("apex:")
    }
    if set(apexes) != expected_apexes:
        _fail(context, f"APEX inventory differs from fixed seed policy")

    package_groups: dict[str, dict[str, Any]] = {}
    for key in sorted(packages):
        record = packages[key]
        group = package_groups.setdefault(record["package_name"], {
            "signers": record["signers"],
            "shared_uid": record["shared_uid"],
            "assignment": record["assignment"],
            "container": record["container"],
            "splits": [],
        })
        for field in ("signers", "shared_uid", "assignment", "container"):
            if group[field] != record[field]:
                _fail(context, f"split records disagree for package {record['package_name']!r} field {field}")
        group["splits"].append(record["split"])

    shared_uids: dict[str, tuple[str, ...]] = {}
    for package_name, group in sorted(package_groups.items()):
        uid = group["shared_uid"]
        if uid is not None:
            shared_uids.setdefault(uid, tuple())
            shared_uids[uid] = tuple(sorted(shared_uids[uid] + (package_name,)))
    for uid, names in shared_uids.items():
        signer_sets = {package_groups[name]["signers"] for name in names}
        if len(signer_sets) != 1:
            _fail(context, f"sharedUserId {uid!r} contains different actual DER signer sets")

    return {
        "label": expected_label,
        "receipt_sha256": _sha256(value["receipt_sha256"], f"{context}.receipt_sha256"),
        "signed_target_files_sha256": _sha256(
            value["signed_target_files_sha256"], f"{context}.signed_target_files_sha256"
        ),
        "inventory_evidence_sha256": _sha256(
            value["inventory_evidence_sha256"], f"{context}.inventory_evidence_sha256"
        ),
        "packages": packages,
        "package_groups": package_groups,
        "shared_uids": shared_uids,
        "apexes": apexes,
        "evidence_count": len(observed_evidence),
    }


def verify_pair(policy: Any, predecessor: Any, successor: Any) -> dict[str, Any]:
    """Validate and compare two complete synthetic authenticated inventories."""
    normalized_policy = _validate_policy(policy)
    before = _endpoint(predecessor, "predecessor", normalized_policy)
    after = _endpoint(successor, "successor", normalized_policy)
    if before["receipt_sha256"] == after["receipt_sha256"]:
        _fail("pair", "predecessor and successor receipt identities must differ")
    if before["signed_target_files_sha256"] == after["signed_target_files_sha256"]:
        _fail("pair", "predecessor and successor signed target-files identities must differ")

    package_moves: list[dict[str, str]] = []
    package_content_changes = 0
    for key in sorted(before["packages"]):
        old = before["packages"][key]
        new = after["packages"][key]
        for field in ("signers", "shared_uid", "assignment", "container"):
            if old[field] != new[field]:
                _fail("pair", f"package {key!r} changed {field}")
        if old["archive_member"] != new["archive_member"]:
            package_moves.append({
                "package": key[0], "split": key[1],
                "predecessor": old["archive_member"], "successor": new["archive_member"],
            })
        if old["file_sha256"] != new["file_sha256"]:
            package_content_changes += 1
    if before["shared_uids"] != after["shared_uids"]:
        _fail("pair", "sharedUserId membership sets changed")

    apex_moves: list[dict[str, str]] = []
    apex_content_changes = 0
    for name in sorted(before["apexes"]):
        old = before["apexes"][name]
        new = after["apexes"][name]
        for field in (
            "container_type", "outer_signers", "outer_assignment", "payload_public_key_sha256"
        ):
            if old[field] != new[field]:
                _fail("pair", f"APEX {name!r} changed {field}")
        if old["archive_member"] != new["archive_member"]:
            apex_moves.append({
                "apex": name, "predecessor": old["archive_member"], "successor": new["archive_member"]
            })
        if old["file_sha256"] != new["file_sha256"]:
            apex_content_changes += 1

    return {
        "schema": 1,
        "kind": "phase1_fixed_seed_os_signer_continuity_semantic_report_v1",
        "valid": True,
        "input_records_are_pre_authenticated_observations": True,
        "cryptography_or_archive_extraction_performed": False,
        "predecessor": {
            "receipt_sha256": before["receipt_sha256"],
            "signed_target_files_sha256": before["signed_target_files_sha256"],
            "inventory_evidence_sha256": before["inventory_evidence_sha256"],
        },
        "successor": {
            "receipt_sha256": after["receipt_sha256"],
            "signed_target_files_sha256": after["signed_target_files_sha256"],
            "inventory_evidence_sha256": after["inventory_evidence_sha256"],
        },
        "counts": {
            "packages": len(before["package_groups"]),
            "package_splits": len(before["packages"]),
            "apexes": len(before["apexes"]),
            "shared_uids": len(before["shared_uids"]),
            "package_content_changes": package_content_changes,
            "apex_content_changes": apex_content_changes,
            "predecessor_raw_evidence": before["evidence_count"],
            "successor_raw_evidence": after["evidence_count"],
        },
        "package_path_moves": package_moves,
        "apex_path_moves": apex_moves,
        "shared_uid_membership": {
            uid: list(names) for uid, names in sorted(before["shared_uids"].items())
        },
    }

