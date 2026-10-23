#!/usr/bin/env python3
"""Create and verify the aggregate Phase-1 release-evidence freeze.

This is the final *index* over the independently produced evidence.  It does
not turn hashes into test results: creation and verification replay the x86,
Frankel, release-signature, client/SDK and runtime semantic verifiers before
cross-binding their identities.  The returned SHA-256 is the one out-of-band
trust anchor for the complete Phase-1 evidence set.

The evidence tree is deliberately supplied separately from the index.  Every
path in the assembly is a canonical relative path below that tree; links,
special files, duplicate JSON keys and private-key material fail closed.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit


TOOLS = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[2]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import frankel_build_comparison as frankel  # noqa: E402
import phase1_conformance_acceptance as conformance_acceptance  # noqa: E402
import phase1_conformance_recents_guest_acceptance as recents_guest_acceptance  # noqa: E402
import phase1_provenance as provenance  # noqa: E402
import phase1_generic_upstream_evidence as generic_upstream  # noqa: E402
import phase1_upstream_test_comparison as upstream_tests  # noqa: E402
import release_pair_receipt  # noqa: E402
# Historical product DesktopService/Haskell campaign, NOT the policy-free
# ConformanceService runtime. Its existing strict checks remain diagnostic
# inputs while final publication is blocked below, pending the real adapter.
import run_phase1_runtime_qualification as runtime  # noqa: E402
import verify_release_pair  # noqa: E402
import x86_build_comparison as x86  # noqa: E402


SCHEMA = 1
KIND = "wonad-phase1-release-evidence-index"
ASSEMBLY_KIND = "wonad-phase1-release-evidence-assembly"
SOURCE_PROOF_KIND = "wonad-phase1-x86-arm-source-difference-proof"
UPSTREAM_KIND = "wonad-phase1-upstream-regression-evidence"
UPSTREAM_SCHEMA = 2
UPSTREAM_INPUTS_KIND = "wonad-phase1-native-upstream-selection"
REVIEW_KIND = "wonad-phase1-final-os-glue-review"
DEFECT_KIND = "wonad-phase1-defect-register"
OPERATIONS_KIND = "wonad-phase1-candidate-operations"
CEREMONY_KIND = "wonad-phase1-signing-ceremony-record"
CUSTODY_OBSERVATION_KIND = "wonad-phase1-signing-custody-observation"
QUALIFICATION = "production"
API = 3
SDK_COORDINATE = "org.wonad:desktop-sdk:3.0.1"
PRODUCT = "frankel"
RELEASE = "2026100600"
SHA256 = re.compile(r"[0-9a-f]{64}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
MAX_JSON = 64 * 1024 * 1024
PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
)
PRIVATE_SUFFIXES = {
    ".key", ".keytab", ".p8", ".pk8", ".pkcs8", ".p12", ".pfx", ".jks", ".keystore",
}

REQUIRED_UPSTREAM_CLASSES = {
    "grapheneos_host",
    "aosp_host",
    "aosp_emulator",
}
REQUIRED_REVIEW_SCOPES = {
    "privileged_interface_inventory",
    "identity_and_signer_admission",
    "binder_lifecycle_and_cancellation",
    "display_containment_and_input",
    "phone_ui_regression",
    "release_configuration",
    "signing_ceremony_and_key_custody",
    "channel_operations_and_maintenance",
    "language_and_unsafe_code",
    "selinux_and_permissions",
    "update_and_recovery",
    "source_and_toolchain_provenance",
}
REVIEW_BINDING_KEYS = {
    "grapheneos_lock", "api_contract",
    "x86_baseline_receipt", "x86_custom_receipt", "x86_comparison", "runtime_result",
    "arm_baseline_receipt", "arm_custom_receipt", "arm_comparison", "release_pair",
    "avb_public_key", "ota_certificate", "factory_public_key", "trusted_otatools_manifest",
    "client_record", "client_source_receipt", "conformance_apk", "signer_certificate",
    "apksigner", "sdk_publication", "source_difference_proof",
    "upstream_regression", "upstream_atest_comparison", "upstream_test_plan",
    "upstream_baseline_run", "upstream_custom_run", "production_operations", "operations_runbook",
    "signing_ceremony", "signing_policy", "runtime_admission", "runtime_inputs",
    "runtime_qualification", "runtime_evidence_index", "defects",
    "conformance_packet_receipt", "conformance_api_report",
    "conformance_recents_report", "conformance_recents_child_report",
    "conformance_packet_tree", "conformance_product_identity",
    "conformance_api_evidence_set", "conformance_recents_guest_evidence_set",
    "conformance_recents_child_evidence_set",
}
SIGNER_GENERATED_FILES = {
    "WonadReleaseCertificate.der",
    "WonadSigning.kt",
    "generated-res/values/wonad_signer.xml",
}

HELPERS = {
    "phase1_release_index": Path(__file__).resolve(),
    "x86_build_comparison": TOOLS / "x86_build_comparison.py",
    "frankel_build_comparison": TOOLS / "frankel_build_comparison.py",
    "phase1_provenance": TOOLS / "phase1_provenance.py",
    "runtime_qualification": TOOLS / "run_phase1_runtime_qualification.py",
    "upstream_test_comparison": TOOLS / "phase1_upstream_test_comparison.py",
    "isolated_upstream_runner": TOOLS / "run_phase1_upstream_tests.py",
    "generic_upstream_evidence": TOOLS / "phase1_generic_upstream_evidence.py",
    "grapheneos_host_applicability": TOOLS / "phase1_grapheneos_host_applicability.py",
    "release_receipt": TOOLS / "release_receipt.py",
    "release_pair_receipt": TOOLS / "release_pair_receipt.py",
    "verify_release_artifacts": TOOLS / "verify_release_artifacts.py",
    "verify_release_pair": TOOLS / "verify_release_pair.py",
    "sdk_verifier": TOOLS / "verify_sdk_publication.py",
    "fresh_conformance_common": TOOLS / "phase1_conformance_common.py",
    "fresh_conformance_guest": TOOLS / "phase1_conformance_guest.py",
    "fresh_conformance_acceptance": TOOLS / "phase1_conformance_acceptance.py",
    "fresh_conformance_candidate_builder": ROOT / "android/container/build-phase1-conformance-candidate.py",
    "emulator_client_packet": TOOLS / "phase1_emulator_client_packet.py",
    "fresh_recents_producer": TOOLS / "phase1_conformance_recents.py",
    "fresh_recents_acceptance": TOOLS / "phase1_conformance_recents_acceptance.py",
    "fresh_recents_guest_runner": TOOLS / "run_phase1_conformance_recents_guest.py",
    "fresh_recents_guest_acceptance": TOOLS / "phase1_conformance_recents_guest_acceptance.py",
}

UPSTREAM_PLAN = ROOT / "android/platform/phase1-upstream-tests-2026100600.json"
OPERATIONS_RUNBOOK = ROOT / "android/platform/PHASE1-INSTALL-UPDATE-RECOVERY.md"
SIGNING_POLICY = ROOT / "android/platform/PHASE1-SIGNING-CEREMONY.md"
OS_SIGNER_ROLES = {
    "bluetooth", "gmscompat_lib", "media", "networkstack", "nfc", "platform",
    "releasekey", "sdk_sandbox", "shared",
}
OWNER_ROLES = {
    "release", "channel", "security_updates", "grapheneos_rebase", "withdrawal",
}
CEREMONY_TOOLS = {
    "android/platform/release-build.sh": ROOT / "android/platform/release-build.sh",
    "android/tools/phase1_provenance.py": TOOLS / "phase1_provenance.py",
    "android/tools/verify_release_artifacts.py": TOOLS / "verify_release_artifacts.py",
    "android/tools/verify_release_pair.py": TOOLS / "verify_release_pair.py",
}
CUSTODY_CONTROLS = {
    "preflight": sorted({
        "offline_host", "networking_disabled", "swap_disabled", "hibernation_disabled",
        "core_dumps_disabled", "private_material_outside_source_build_and_evidence",
        "build_container_removed_before_signing",
    }),
    "postflight": sorted({
        "locked_ram_temporary_material_removed", "independent_verification_host",
        "public_release_pair_verified",
    }),
    "backup_restore": sorted({
        "two_geographic_encrypted_backups", "restore_test_completed",
    }),
}


class IndexError(ValueError):
    """An evidence input or cross-binding failed closed."""


def require(condition, message):
    if not condition:
        raise IndexError(message)


def exact_keys(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys),
            f"Unexpected {label} fields")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def safe_relative(value):
    require(isinstance(value, str) and value and "\x00" not in value and "\\" not in value,
            "Evidence path must be a non-empty canonical relative path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value and
            all(part not in {"", ".", ".."} for part in path.parts),
            f"Unsafe or non-canonical evidence path: {value!r}")
    return path


def canonical_root(value: Path):
    require(value.is_absolute() and not value.is_symlink(),
            "Evidence root must be a literal absolute non-symlink directory")
    try:
        resolved = value.resolve(strict=True)
    except OSError as error:
        raise IndexError(f"Cannot resolve evidence root: {error}") from error
    require(resolved == value and value.is_dir(),
            "Evidence root must be a canonical existing directory")
    return value


def confined(root: Path, relative_value: str, label: str, *, directory=False):
    relative = safe_relative(relative_value)
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            mode = current.lstat().st_mode
        except OSError as error:
            raise IndexError(f"Missing {label}: {relative_value}: {error}") from error
        require(not stat.S_ISLNK(mode), f"{label} contains a symlink: {relative_value}")
        if index < len(relative.parts) - 1:
            require(stat.S_ISDIR(mode), f"{label} parent is not a directory: {relative_value}")
    require(stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode),
            f"{label} is not an ordinary {'directory' if directory else 'file'}: {relative_value}")
    return current


def stat_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def private_key_name(path: Path):
    return any(suffix.lower() in PRIVATE_SUFFIXES for suffix in path.suffixes)


def stable_bytes(path: Path, *, maximum=MAX_JSON):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise IndexError(f"Cannot safely open evidence: {path}: {error}") from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), f"Evidence is not an ordinary file: {path}")
        require(0 < before.st_size <= maximum, f"Evidence has an invalid size: {path}")
        chunks = []
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
            digest.update(block)
            size += len(block)
        after = os.fstat(descriptor)
        current = os.lstat(path)
        require(stat.S_ISREG(current.st_mode) and
                stat_identity(before) == stat_identity(after) == stat_identity(current) and
                size == before.st_size,
                f"Evidence changed while being read: {path}")
        return b"".join(chunks), {"sha256": digest.hexdigest(), "size": size}
    finally:
        os.close(descriptor)


def stable_ref(path: Path, relative: str, *, reject_private=True):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise IndexError(f"Cannot safely open evidence: {path}: {error}") from error
    digest = hashlib.sha256()
    size = 0
    private = False
    overlap = b""
    marker_overlap = max(map(len, PRIVATE_MARKERS)) - 1
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size > 0,
                f"Evidence is not a non-empty ordinary file: {path}")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
            if reject_private:
                window = overlap + block
                private = private or any(marker in window for marker in PRIVATE_MARKERS)
                overlap = window[-marker_overlap:]
        after = os.fstat(descriptor)
        current = os.lstat(path)
        require(stat.S_ISREG(current.st_mode) and
                stat_identity(before) == stat_identity(after) == stat_identity(current) and
                size == before.st_size,
                f"Evidence changed while being hashed: {path}")
    finally:
        os.close(descriptor)
    if reject_private:
        require(not private_key_name(path) and not private,
                f"Private-key material is forbidden in Phase-1 evidence: {relative}")
    return {"path": relative, "sha256": digest.hexdigest(), "size": size}


def file_ref(root: Path, relative: str, label="evidence"):
    return stable_ref(confined(root, relative, label), relative)


def tree_ref(root: Path, relative: str, label="evidence tree"):
    base = confined(root, relative, label, directory=True)
    files = {}
    def walk_error(error):
        raise IndexError(f"Cannot inventory {label}: {error}") from error

    for directory, directory_names, file_names in os.walk(
            base, followlinks=False, onerror=walk_error):
        directory_path = Path(directory)
        for name in directory_names:
            child = directory_path / name
            require(not child.is_symlink() and child.is_dir(),
                    f"{label} contains a link or special directory: {child}")
        for name in file_names:
            child = directory_path / name
            child_relative = child.relative_to(base).as_posix()
            safe_relative(child_relative)
            require(not child.is_symlink() and child.is_file() and
                    not private_key_name(child),
                    f"{label} contains a link, special file or private key: {child}")
            row = stable_ref(child, child_relative)
            files[child_relative] = {"sha256": row["sha256"], "size": row["size"]}
    require(files, f"{label} is empty")
    files = dict(sorted(files.items()))
    return {"path": relative, "files": files,
            "files_sha256": canonical_digest(files), "file_count": len(files)}


def declared_evidence_set(root: Path, base: Path, records, label: str):
    """Rehash every raw file committed by an already-audited report.

    The semantic auditor proves which files are required.  This publication
    identity closes the interval between that replay and aggregate sealing,
    and lets a later full index verification recheck the same raw bytes.
    """
    try:
        base_relative = base.relative_to(root).as_posix()
    except ValueError as error:
        raise IndexError(f"{label} directory is outside the evidence root") from error
    require(isinstance(records, dict) and records,
            f"{label} lacks a declared raw-evidence inventory")
    observed = {}
    for name, expected in sorted(records.items()):
        relative_name = safe_relative(name).as_posix()
        require(relative_name == name and isinstance(expected, dict) and
                set(expected) == {"sha256", "bytes"} and
                SHA256.fullmatch(str(expected.get("sha256", ""))) and
                type(expected.get("bytes")) is int and expected["bytes"] > 0,
                f"Malformed {label} file identity: {name}")
        relative = (PurePosixPath(base_relative) / relative_name).as_posix()
        actual = file_ref(root, relative, label + " file")
        require((actual["sha256"], actual["size"]) ==
                (expected["sha256"], expected["bytes"]),
                f"{label} raw file changed after independent replay: {name}")
        observed[name] = {"sha256": actual["sha256"], "size": actual["size"]}
    return {"path": base_relative, "sha256": canonical_digest(observed),
            "file_count": len(observed), "files": observed}


def packet_tree_binding(root: Path, relative: str):
    value = tree_ref(root, relative, "fresh conformance packet tree")
    return {"path": value["path"], "sha256": value["files_sha256"],
            "file_count": value["file_count"], "files": value["files"]}


def product_identity(root: Path, product_relative: str, manifest, products, os_artifacts):
    """Bind stable bytes for every product file checked by verify_product()."""
    expected = {name: digest for name, digest in products.items()}
    expected.update({conformance_acceptance.builder.OS_PATHS[role]: digest
                     for role, digest in os_artifacts.items()})
    files = {}
    for relative_name, digest in sorted(expected.items()):
        relative = (PurePosixPath(product_relative) / relative_name).as_posix()
        row = file_ref(root, relative, "fresh conformance product file")
        require(row["sha256"] == digest,
                "Fresh conformance selected product changed after independent replay: " +
                relative_name)
        files[relative_name] = {"sha256": row["sha256"], "size": row["size"]}
    value = {"manifest_sha256": canonical_digest(manifest), "files": files,
             "product_images": dict(sorted(products.items())),
             "os_artifacts": dict(sorted(os_artifacts.items()))}
    return {"path": product_relative, "sha256": canonical_digest(value),
            "file_count": len(files), **value}


def load_json_path(path: Path, label: str):
    payload, reference = stable_bytes(path)
    try:
        value = json.loads(payload, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IndexError(f"Invalid JSON in {label}: {error}") from error
    return value, reference


def load_json_ref(root: Path, relative: str, label: str):
    path = confined(root, relative, label)
    value, reference = load_json_path(path, label)
    private_checked = stable_ref(path, relative)
    require(reference == {key: private_checked[key] for key in ("sha256", "size")},
            f"{label} changed between parsing and private-material inspection")
    return value, private_checked, path


def confined_absolute(root: Path, value, label: str):
    require(isinstance(value, str), f"{label} path must be a string")
    path = Path(value)
    require(path.is_absolute(), f"{label} path must be absolute")
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as error:
        raise IndexError(f"{label} is outside the aggregate evidence root") from error
    selected = confined(root, relative, label)
    require(selected == path and path.resolve(strict=True) == path,
            f"{label} path is not canonical inside the aggregate evidence root")
    return selected, relative


def load_bound_runtime_json(root: Path, reference, label: str):
    exact_keys(reference, {"path", "sha256"}, label + " reference")
    require(SHA256.fullmatch(str(reference.get("sha256", ""))),
            f"Malformed {label} digest")
    path, relative = confined_absolute(root, reference.get("path"), label)
    value, raw = load_json_path(path, label)
    require(raw["sha256"] == reference["sha256"], f"Authenticated {label} changed")
    checked = stable_ref(path, relative)
    require(checked["sha256"] == reference["sha256"] and checked["size"] == raw["size"],
            f"{label} changed during aggregate binding")
    return value, checked, path


def concrete_https(value, label: str, *, allow_grapheneos=False):
    require(isinstance(value, str) and value == value.strip() and value.endswith("/"),
            f"{label} must be a canonical HTTPS base URL ending in /")
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").rstrip(".").lower()
        _port = parsed.port
    except ValueError as error:
        raise IndexError(f"{label} is a malformed HTTPS URL") from error
    require(parsed.scheme == "https" and host and "." in host and
            not parsed.username and not parsed.password and not parsed.query and
            not parsed.fragment and not any(ord(character) < 0x20 for character in value) and
            "\\" not in value,
            f"{label} must be an HTTPS URL without credentials, query or fragment")
    placeholder = (host in {"example", "example.com", "example.net", "example.org",
                            "invalid", "test", "localhost"} or
                   host.endswith((".example", ".invalid", ".test", ".localhost", ".local")) or
                   "example" in host)
    grapheneos = host == "grapheneos.org" or host.endswith(".grapheneos.org")
    require(not placeholder and (allow_grapheneos or not grapheneos),
            f"{label} is an example, reserved or GrapheneOS-owned endpoint")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    require(address is None or address.is_global,
            f"{label} must not use a non-public IP address")
    return value


def non_placeholder(value, label: str):
    require(isinstance(value, str) and value == value.strip() and value and
            value.lower() not in {"tbd", "todo", "none", "unknown", "n/a"} and
            "example" not in value.lower(), f"{label} is missing or a placeholder")
    return value


def validate_owner(value, label: str):
    exact_keys(value, {"name", "contact"}, label)
    non_placeholder(value.get("name"), label + " name")
    contact = non_placeholder(value.get("contact"), label + " contact")
    if contact.startswith("mailto:"):
        require(re.fullmatch(r"mailto:[^@\s]+@[^@\s]+", contact) is not None,
                f"{label} contact is malformed")
    else:
        concrete_https(contact, label + " contact", allow_grapheneos=False)
    return value


def utc_timestamp(value, label: str):
    require(isinstance(value, str) and value.endswith("Z"),
            f"{label} must be an explicit UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise IndexError(f"Malformed {label}") from error
    require(parsed.tzinfo == timezone.utc, f"{label} is not UTC")
    return parsed


def validate_embedded_ref(root: Path, value, label: str):
    exact_keys(value, {"path", "sha256", "size"}, label)
    require(SHA256.fullmatch(str(value.get("sha256", ""))) and
            type(value.get("size")) is int and value["size"] > 0,
            f"Malformed {label} reference")
    observed = file_ref(root, value["path"], label)
    require(observed == value, f"{label} bytes differ from their reference")
    return observed


def tool_ledger():
    imported = {
        "x86_build_comparison": Path(x86.__file__).resolve(),
        "frankel_build_comparison": Path(frankel.__file__).resolve(),
        "phase1_provenance": Path(provenance.__file__).resolve(),
        "runtime_qualification": Path(runtime.__file__).resolve(),
        "upstream_test_comparison": Path(upstream_tests.__file__).resolve(),
        "generic_upstream_evidence": Path(generic_upstream.__file__).resolve(),
        "isolated_upstream_runner": Path(generic_upstream.isolated_atest.__file__).resolve(),
        "grapheneos_host_applicability": Path(generic_upstream.grapheneos_applicability.__file__).resolve(),
        "release_pair_receipt": Path(release_pair_receipt.__file__).resolve(),
        "verify_release_pair": Path(verify_release_pair.__file__).resolve(),
        "fresh_conformance_acceptance": Path(conformance_acceptance.__file__).resolve(),
        "fresh_recents_guest_acceptance": Path(recents_guest_acceptance.__file__).resolve(),
        "fresh_conformance_candidate_builder":
            Path(conformance_acceptance.builder.__file__).resolve(),
        "emulator_client_packet": Path(conformance_acceptance.packet_tool.__file__).resolve(),
        "fresh_recents_acceptance":
            Path(recents_guest_acceptance.recents_acceptance.__file__).resolve(),
    }
    for name, actual in imported.items():
        require(actual == HELPERS[name].resolve(),
                f"Imported Phase-1 helper resolved outside reviewed path: {name}")
    result = {}
    for name, path in sorted(HELPERS.items()):
        relative = path.relative_to(ROOT).as_posix()
        result[name] = stable_ref(path, relative, reject_private=False)
    return result


def validate_assembly(value):
    exact_keys(value, {
        "schema", "kind", "qualification", "grapheneos_lock", "api_contract",
        "x86", "arm", "clients", "conformance_acceptance", "source_difference_proof",
        "upstream_regression", "upstream_atest_comparison", "upstream_test_plan", "upstream_baseline_run",
        "upstream_custom_run", "production_operations", "signing_ceremony",
        "review", "defects",
    }, "assembly")
    require(value.get("schema") == SCHEMA and value.get("kind") == ASSEMBLY_KIND and
            value.get("qualification") == QUALIFICATION,
            "Only the production Phase-1 assembly schema is accepted")
    for name in ("grapheneos_lock", "api_contract", "source_difference_proof",
                 "upstream_regression", "upstream_atest_comparison", "upstream_test_plan", "upstream_baseline_run",
                 "upstream_custom_run", "production_operations", "signing_ceremony",
                 "review", "defects"):
        if name == "source_difference_proof" and value[name] is None:
            continue
        safe_relative(value[name])
    exact_keys(value["x86"], {"baseline_receipt", "custom_receipt", "comparison",
                               "runtime_result"}, "x86 assembly")
    exact_keys(value["arm"], {"baseline_receipt", "custom_receipt", "comparison",
                               "release_pair_receipt", "avb_public_key", "ota_certificate",
                               "factory_public_key", "trusted_otatools_manifest",
                               "trusted_otatools_manifest_sha256"}, "ARM assembly")
    exact_keys(value["clients"], {"record", "sdk_publication", "conformance_apk",
                                  "source_receipt", "signer_certificate", "apksigner"},
               "client assembly")
    exact_keys(value["conformance_acceptance"], {
        "product", "client_packet", "api_report", "recents_report"},
        "fresh conformance assembly")
    for group in (value["x86"], value["clients"], value["conformance_acceptance"]):
        for relative in group.values():
            safe_relative(relative)
    for name, relative in value["arm"].items():
        if name == "trusted_otatools_manifest_sha256":
            require(SHA256.fullmatch(str(relative)), "Invalid trusted otatools manifest SHA-256")
        else:
            safe_relative(relative)
    return value


def load_lock(path: Path):
    value, _reference = load_json_path(path, "GrapheneOS lock")
    try:
        value = provenance.validate_lock(value)
    except provenance.ProvenanceError as error:
        raise IndexError(f"Invalid GrapheneOS lock: {error}") from error
    require(value.get("release") == RELEASE and value.get("device") == PRODUCT and
            value.get("production_target", {}).get("product") == PRODUCT,
            "GrapheneOS lock does not select the Phase-1 Pixel 10 release")
    return value


def verifier_call(label, function, *arguments, **keywords):
    try:
        return function(*arguments, **keywords)
    except Exception as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise IndexError(f"{label} verification failed: {error}") from error


def source_identity(receipt):
    source = receipt.get("source")
    pin = source.get("pin") if isinstance(source, dict) else None
    require(isinstance(pin, dict) and isinstance(source, dict),
            "Build receipt lacks authenticated source identity")
    return {
        "lock_sha256": pin.get("lock", {}).get("sha256"),
        "manifest_commit": pin.get("manifest_commit"),
        "manifest_tag_object": pin.get("manifest_tag_object"),
        "default_xml_sha256": pin.get("default_xml", {}).get("sha256"),
        "project_count": pin.get("project_count"),
        "project_ledger_sha256": pin.get("project_ledger_sha256"),
        "worktree_materializations_sha256": source.get("worktree_materializations_sha256"),
    }


def x86_stage(receipt):
    stage = receipt.get("source", {}).get("stage", {})
    require(stage.get("state") == f"schema-{x86.stage_contract.stage_schema()}-owned-stage" and
            stage.get("qualification") == "emulator-development-only" and
            isinstance(stage.get("marker"), dict),
            "x86 custom receipt lacks development-only active-schema staging")
    signer = stage.get("development_certificate", {}).get("der_sha256")
    x86.marker_owned_targets(stage["marker"])
    require(SHA256.fullmatch(str(signer or "")) and
            stage["marker"].get("signer_sha256") == signer,
            "x86 staged signer identity is inconsistent")
    return stage, signer


def arm_stage(receipt):
    stage = receipt.get("source", {}).get("stage", {})
    require(stage.get("state") == f"schema-{frankel.stage_contract.stage_schema()}-with-project-updater" and
            isinstance(stage.get("marker"), dict),
            "ARM custom receipt lacks production active-schema/Updater staging")
    signer = stage.get("signer", {}).get("der_sha256")
    x86.marker_owned_targets(stage["marker"])
    require(SHA256.fullmatch(str(signer or "")) and
            stage["marker"].get("signer_sha256") == signer,
            "ARM staged signer identity is inconsistent")
    return stage, signer


def normalized_signer_marker(marker):
    value = copy.deepcopy(marker)
    require(isinstance(value.get("files"), dict), "Stage marker lacks a file ledger")
    require(SIGNER_GENERATED_FILES <= set(value["files"]),
            "Stage marker lacks all signer-generated files")
    value["signer_certificate"] = "<target-signer>"
    value["signer_sha256"] = "<target-signer>"
    for name in SIGNER_GENERATED_FILES:
        value["files"][name] = "<target-signer-generated>"
    return value


def expected_source_proof(x86_receipt, x86_ref, arm_receipt, arm_ref):
    x_stage, x_signer = x86_stage(x86_receipt)
    a_stage, a_signer = arm_stage(arm_receipt)
    x_identity, a_identity = source_identity(x86_receipt), source_identity(arm_receipt)
    require(x_identity == a_identity,
            "x86 and ARM builds do not share one source/project/materialization freeze")
    normalized_x = normalized_signer_marker(x_stage["marker"])
    normalized_a = normalized_signer_marker(a_stage["marker"])
    require(normalized_x == normalized_a,
            "x86/ARM stage source differs outside signer-generated fields")
    require(x_signer != a_signer,
            "A source-difference proof is forbidden when x86 and ARM use the same signer")
    def identity(reference):
        return {"sha256": reference["sha256"], "size": reference["size"]}
    return {
        "schema": SCHEMA,
        "kind": SOURCE_PROOF_KIND,
        "scope": "same-source-freeze-with-target-specific-signer-only",
        "x86_custom_receipt": identity(x86_ref),
        "arm_custom_receipt": identity(arm_ref),
        "shared_source": x_identity,
        "x86_development_signer_sha256": x_signer,
        "arm_production_signer_sha256": a_signer,
        "normalized_stage_marker_sha256": canonical_digest(normalized_x),
        "permitted_stage_differences": {
            "scalar_fields": ["signer_certificate", "signer_sha256"],
            "generated_files": sorted(SIGNER_GENERATED_FILES),
            "arm_only_updater_stage": True,
        },
        "result": "passed_exhaustive_signer_only_source_difference",
    }


def native_upstream_run(test_class, path, digest):
    if test_class == "aosp_host":
        return generic_upstream.verify_host(path, digest, rehash_build=True)
    if test_class == "aosp_emulator":
        return generic_upstream.normalize_emulator(path, digest)
    if test_class == "grapheneos_host":
        return generic_upstream.grapheneos_applicability.verify(path, digest, rehash_build=True)
    raise IndexError("No reviewed upstream native producer for this coverage class")


def validate_upstream(root: Path, value, shared_source, *, expected_builds,
                      expected_source_pin_sha256):
    """Replay native producers, never operator-written command/JUnit summaries."""
    exact_keys(value, {"schema", "kind", "qualification", "source", "plan", "runs", "result"},
               "upstream regression record")
    require(value.get("schema") == UPSTREAM_SCHEMA and value.get("kind") == UPSTREAM_KIND and
            value.get("qualification") == QUALIFICATION and value.get("source") == shared_source and
            value.get("result") == "passed_no_new_or_worsened_native_failures",
            "Upstream regression evidence has the wrong identity or result")
    plan_ref = validate_embedded_ref(root, value["plan"], "generic upstream plan")
    plan_path = confined(root, plan_ref["path"], "generic upstream plan")
    current_plan = verifier_call("generic upstream plan", generic_upstream.reviewed_plan)
    plan, _ = load_json_path(plan_path, "generic upstream plan")
    require(plan == current_plan and plan_ref["sha256"] == generic_upstream.PLAN_SHA256,
            "Generic upstream plan differs from the repository-reviewed bytes")
    unresolved = sorted(row["class"] for row in plan["classes"] if row["state"] == "unresolved")
    require(not unresolved, "Generic upstream applicability is unresolved: " +
            ", ".join(unresolved))
    require(isinstance(expected_builds, dict) and
            set(expected_builds) == {"baseline", "custom"} and
            isinstance(expected_source_pin_sha256, str) and
            SHA256.fullmatch(expected_source_pin_sha256),
            "Generic upstream validation lacks selected build/source identities")
    runs = value.get("runs")
    require(isinstance(runs, list) and len(runs) == len(REQUIRED_UPSTREAM_CLASSES),
            "Upstream regression lacks one exact pair per required coverage class")
    classes, native_sides = set(), {}
    for row in runs:
        exact_keys(row, {"class", "baseline", "custom"},
                   "upstream regression run")
        test_class = row.get("class")
        require(test_class in REQUIRED_UPSTREAM_CLASSES and test_class not in classes,
                "Malformed, duplicate or unknown upstream regression run")
        classes.add(test_class)
        sides = {}
        for side in ("baseline", "custom"):
            reference = validate_embedded_ref(root, row[side],
                                              f"upstream {test_class} {side} native run")
            path = confined(root, reference["path"], f"upstream {test_class} {side} native run")
            native = verifier_call(f"upstream {test_class} {side}", native_upstream_run,
                                   test_class, path, reference["sha256"])
            expected = {key: expected_builds[side][key] for key in ("sha256", "size")}
            require(native.get("class") == test_class and native.get("role") == side and
                    native.get("build_receipt") == expected and
                    native.get("source_pin_sha256") == expected_source_pin_sha256 and
                    native.get("receipt_sha256") == reference["sha256"],
                    "Upstream native run is not bound to the selected class/role/build/source")
            sides[side] = native
        native_sides[test_class] = sides
    require(classes == REQUIRED_UPSTREAM_CLASSES,
            "Upstream evidence lacks GrapheneOS host, AOSP host or AOSP emulator coverage")
    comparison = verifier_call("generic upstream comparison",
                               generic_upstream.compare_native_sides, plan, native_sides)
    require(comparison["result"] == value["result"], "Generic upstream result differs")
    return {"runs": len(runs), "cases": sum(row["case_count"] for row in
                                              comparison["classes"].values()),
            "classes": sorted(classes), "plan": plan_ref,
            "native_comparison": comparison, "result": value["result"]}


def validate_defects(root: Path, value):
    exact_keys(value, {"schema", "kind", "qualification", "items", "result"},
               "defect register")
    require(value.get("schema") == SCHEMA and value.get("kind") == DEFECT_KIND and
            value.get("qualification") == QUALIFICATION and
            value.get("result") == "zero_known_critical_high_and_no_untriaged_defects",
            "Defect register has the wrong identity or exit result")
    items = value.get("items")
    require(isinstance(items, list), "Defect register items must be a list")
    identifiers = set()
    accepted = []
    for row in items:
        exact_keys(row, {"id", "severity", "status", "summary", "owner", "workaround",
                         "closure_evidence"}, "defect")
        identifier = row.get("id")
        severity, status = row.get("severity"), row.get("status")
        require(isinstance(identifier, str) and re.fullmatch(r"[A-Z][A-Z0-9_-]{2,63}", identifier) and
                identifier not in identifiers and severity in {"critical", "high", "medium", "low"} and
                status in {"accepted", "resolved"} and isinstance(row.get("summary"), str) and
                row["summary"].strip() == row["summary"] and row["summary"],
                "Malformed, duplicate or untriaged defect")
        identifiers.add(identifier)
        closure = row.get("closure_evidence")
        require(isinstance(closure, list), "Defect closure evidence must be a list")
        for ordinal, reference in enumerate(closure):
            validate_embedded_ref(root, reference, f"defect {identifier} closure {ordinal}")
        if status == "accepted":
            require(severity in {"medium", "low"} and not closure,
                    "Only owned medium/low defects with workarounds may be accepted")
            non_placeholder(row.get("owner"), "accepted defect owner")
            non_placeholder(row.get("workaround"), "accepted defect workaround")
            accepted.append(identifier)
        else:
            require(row.get("owner") is None and row.get("workaround") is None and closure,
                    "Resolved defects require closure evidence and no active workaround/owner")
    return {"count": len(items), "accepted": sorted(accepted), "ids": sorted(identifiers),
            "result": value["result"]}


def public_certificate_snapshot(path: Path, expected_file, label: str):
    """Inspect the identity and key from one authenticated certificate snapshot.

    OpenSSL parses one stable stdin snapshot.  Its pinned, locale-independent
    rendering supplies the key family, size and EC curve; certificate signature
    algorithms are deliberately not used to identify the subject's key.
    """
    payload, reference = stable_bytes(path)
    require(reference == expected_file,
            f"{label} certificate changed before algorithm inspection")
    try:
        openssl = provenance.host_tool("openssl")
        command = provenance.HOST_TOOL_PINS["openssl"]["path"]
        environment = provenance.hermetic_environment(openssl=True)
        der = subprocess.run([command, "x509", "-outform", "DER"], input=payload,
                             check=True, capture_output=True, timeout=30,
                             env=environment).stdout
        subject = subprocess.run([command, "x509", "-noout", "-subject"], input=payload,
                                 check=True, capture_output=True, timeout=30,
                                 env=environment).stdout.decode("utf-8").strip()
        rendered = subprocess.run(
            [command, "x509", "-noout", "-text"],
            input=payload, check=True, capture_output=True, timeout=30,
            env=environment).stdout.decode("ascii", "replace")
        require(provenance._host_tool_uncached("openssl") == openssl,
                "Pinned OpenSSL changed during certificate algorithm inspection")
    except (provenance.ProvenanceError, OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, UnicodeError) as error:
        raise IndexError(f"Cannot inspect {label} certificate identity/algorithm") from error
    families = re.findall(r"^[ \t]+Public Key Algorithm: ([^\r\n]+)$", rendered, re.MULTILINE)
    sizes = re.findall(r"^[ \t]+Public-Key: \(([0-9]+) bit\)$", rendered, re.MULTILINE)
    curves = re.findall(r"^[ \t]+ASN1 OID: ([^\r\n]+)$", rendered, re.MULTILINE)
    require(len(families) == len(sizes) == 1,
            f"Unsupported or ambiguous {label} certificate algorithm")
    algorithm = None
    if families[0] == "rsaEncryption" and not curves and sizes[0] in {"3072", "4096"}:
        algorithm = "RSA-" + sizes[0]
    elif families[0] == "id-ecPublicKey" and len(curves) == 1:
        algorithm = {("256", "prime256v1"): "ECDSA-P256",
                     ("384", "secp384r1"): "ECDSA-P384"}.get((sizes[0], curves[0]))
    require(algorithm is not None, f"Unsupported {label} certificate algorithm")
    require(128 <= len(der) <= 65536, f"{label} certificate DER size differs")
    return {"file": reference, "der_sha256": hashlib.sha256(der).hexdigest(),
            "der_size": len(der), "subject": subject, "algorithm": algorithm}


def public_certificate_algorithm(path: Path, expected_file, label: str):
    return public_certificate_snapshot(path, expected_file, label)["algorithm"]


def validate_public_certificate(root: Path, value, label: str):
    exact_keys(value, {"algorithm", "certificate", "der_sha256", "der_size", "subject"}, label)
    require(value.get("algorithm") in {"RSA-4096", "RSA-3072", "ECDSA-P256", "ECDSA-P384"},
            f"Unsupported {label} algorithm")
    reference = validate_embedded_ref(root, value.get("certificate"), label + " certificate")
    path = confined(root, reference["path"], label + " certificate")
    observed = public_certificate_snapshot(
        path, {key: reference[key] for key in ("sha256", "size")}, label)
    require(observed["file"] == {"sha256": reference["sha256"], "size": reference["size"]} and
            value.get("der_sha256") == observed["der_sha256"] and
            value.get("der_size") == observed["der_size"] and
            value.get("subject") == observed["subject"],
            f"{label} identity differs from its public certificate")
    require(value["algorithm"] == observed["algorithm"],
            f"{label} algorithm differs from its public certificate")
    return {key: observed[key] for key in ("file", "der_sha256", "der_size", "subject")}


def validate_custody_observation(root: Path, reference, category: str, expected_owner,
                                 began, ended, pair, pair_ref, production_signer):
    observed_ref = validate_embedded_ref(root, reference, f"{category} custody observation")
    observation, parsed_ref, _ = load_json_ref(
        root, reference["path"], f"{category} custody observation")
    require(parsed_ref == observed_ref,
            f"{category} custody observation changed while being interpreted")
    exact_keys(observation, {
        "schema", "kind", "qualification", "release", "product", "category",
        "observed_utc", "observer", "predecessor_build", "successor_build",
        "release_pair_sha256", "wonad_signer_sha256", "controls", "result",
    }, f"{category} custody observation")
    observed_at = utc_timestamp(observation.get("observed_utc"), category + " observation time")
    require(observation.get("schema") == SCHEMA and
            observation.get("kind") == CUSTODY_OBSERVATION_KIND and
            observation.get("qualification") == QUALIFICATION and
            observation.get("release") == RELEASE and observation.get("product") == PRODUCT and
            observation.get("category") == category and began <= observed_at <= ended and
            observation.get("observer") == expected_owner and
            observation.get("predecessor_build") == pair["predecessor"]["number"] and
            observation.get("successor_build") == pair["successor"]["number"] and
            observation.get("release_pair_sha256") == pair_ref["sha256"] and
            observation.get("wonad_signer_sha256") == production_signer and
            observation.get("controls") == CUSTODY_CONTROLS[category] and
            observation.get("result") == "passed_observed_signing_custody_controls",
            f"{category} custody observation is not an exact public observation of this ceremony")
    return observed_ref


def validate_signing_ceremony(root: Path, value, shared_source, pair_result,
                              production_signer, release_refs, signer_ref):
    exact_keys(value, {"schema", "kind", "qualification", "release", "product", "source",
                       "predecessor_build", "successor_build", "started_utc", "ended_utc",
                       "release_operator", "key_custodian", "independent_verifier", "policy",
                       "custody", "identities", "tools", "result"},
               "signing ceremony")
    pair = pair_result["pair"]
    require(value.get("schema") == SCHEMA and value.get("kind") == CEREMONY_KIND and
            value.get("qualification") == QUALIFICATION and value.get("release") == RELEASE and
            value.get("product") == PRODUCT and value.get("source") == shared_source and
            value.get("predecessor_build") == pair["predecessor"]["number"] and
            value.get("successor_build") == pair["successor"]["number"] and
            value.get("result") == "passed_protected_key_ceremony_and_public_verification",
            "Signing ceremony does not select the authenticated production release pair")
    began = utc_timestamp(value.get("started_utc"), "ceremony start")
    ended = utc_timestamp(value.get("ended_utc"), "ceremony end")
    require(began < ended and (ended - began).total_seconds() <= 72 * 60 * 60,
            "Signing ceremony time interval is invalid")
    operator = validate_owner(value.get("release_operator"), "release operator")
    custodian = validate_owner(value.get("key_custodian"), "key custodian")
    independent = validate_owner(value.get("independent_verifier"), "independent verifier")
    require(len({owner["name"].casefold() for owner in (operator, custodian, independent)}) == 3,
            "Release operator, key custodian and verifier must be accountable distinct people/roles")

    policy = validate_embedded_ref(root, value.get("policy"), "signing ceremony policy")
    current_policy = stable_ref(SIGNING_POLICY,
                                "android/platform/PHASE1-SIGNING-CEREMONY.md",
                                reject_private=False)
    require({key: policy[key] for key in ("sha256", "size")} ==
            {key: current_policy[key] for key in ("sha256", "size")},
            "Signing ceremony policy differs from the reviewed repository policy")
    custody = value.get("custody")
    exact_keys(custody, {"offline_host", "networking_disabled", "swap_disabled",
                         "hibernation_disabled", "core_dumps_disabled",
                         "private_material_outside_source_build_and_evidence",
                         "locked_ram_temporary_material_removed", "two_geographic_encrypted_backups",
                         "build_container_removed_before_signing", "independent_verification_host",
                         "preflight_evidence", "postflight_evidence", "backup_restore_evidence"},
               "signing custody")
    boolean_controls = set(custody) - {
        "preflight_evidence", "postflight_evidence", "backup_restore_evidence"}
    require(all(custody.get(name) is True for name in boolean_controls),
            "Signing custody controls were not all positively attested")
    custody_refs = []
    observation_owners = {
        "preflight_evidence": operator,
        "postflight_evidence": independent,
        "backup_restore_evidence": custodian,
    }
    for name, expected_owner in observation_owners.items():
        rows = custody.get(name)
        require(isinstance(rows, list) and rows,
                f"Signing custody lacks {name.replace('_', ' ')}")
        for ordinal, reference in enumerate(rows):
            category = name.removesuffix("_evidence")
            custody_refs.append(validate_custody_observation(
                root, reference, category, expected_owner, began, ended, pair,
                release_refs["release_pair_receipt"], production_signer))
    require(len({row["sha256"] for row in custody_refs}) == len(custody_refs),
            "Signing custody reuses one report as multiple independent observations")

    identities = value.get("identities")
    exact_keys(identities, {"os_certificates", "wonad", "avb", "factory"},
               "ceremony public identities")
    os_certificates = identities.get("os_certificates")
    require(isinstance(os_certificates, dict) and set(os_certificates) == OS_SIGNER_ROLES,
            "Ceremony lacks the exact nine GrapheneOS public signing roles")
    os_identities = {role: validate_public_certificate(
        root, row, "OS signer " + role) for role, row in os_certificates.items()}
    wonad_identity = validate_public_certificate(root, identities.get("wonad"), "Wonad signer")
    all_os = [row["der_sha256"] for row in os_identities.values()]
    require(len(set(all_os)) == len(OS_SIGNER_ROLES) and
            wonad_identity["der_sha256"] == production_signer and
            production_signer not in set(all_os),
            "Ceremony public OS/Wonad identities are aliased or differ from the release")
    wonad_ref = identities["wonad"]["certificate"]
    require((wonad_ref["sha256"], wonad_ref["size"]) ==
            (signer_ref["sha256"], signer_ref["size"]),
            "Ceremony Wonad certificate differs from production client evidence")
    ota = os_certificates["releasekey"]["certificate"]
    require((ota["sha256"], ota["size"]) ==
            (release_refs["ota_certificate"]["sha256"], release_refs["ota_certificate"]["size"]),
            "Ceremony releasekey certificate differs from the verified OTA trust anchor")
    for name, algorithm in (("avb", "RSA-4096"), ("factory", "Ed25519")):
        row = identities.get(name)
        exact_keys(row, {"algorithm", "public"}, "ceremony " + name + " identity")
        reference = validate_embedded_ref(root, row.get("public"), "ceremony " + name + " public key")
        expected = release_refs[name + "_public_key"]
        require(row.get("algorithm") == algorithm and
                (reference["sha256"], reference["size"]) ==
                (expected["sha256"], expected["size"]),
                f"Ceremony {name} identity differs from the verified release trust anchor")

    expected_tools = {
        name: stable_ref(path, name, reject_private=False)["sha256"]
        for name, path in sorted(CEREMONY_TOOLS.items())
    }
    require(value.get("tools") == expected_tools,
            "Ceremony tool identities differ from the reviewed release/verification tools")
    return {
        "result": value["result"], "started_utc": value["started_utc"],
        "ended_utc": value["ended_utc"],
        "policy": policy, "custody_reports": custody_refs,
        "wonad_signer_sha256": production_signer,
        "os_signer_count": len(OS_SIGNER_ROLES),
    }


def validate_operations(root: Path, value, shared_source, pair_result, updater,
                        ceremony_ref):
    exact_keys(value, {"schema", "kind", "qualification", "release", "product", "source",
                       "candidate", "ownership", "publication", "rollout", "maintenance",
                       "change_control", "runbook", "signing_ceremony", "physical_rollback",
                       "result"}, "production operations")
    pair = pair_result["pair"]
    require(value.get("schema") == SCHEMA and value.get("kind") == OPERATIONS_KIND and
            value.get("qualification") == QUALIFICATION and value.get("release") == RELEASE and
            value.get("product") == PRODUCT and value.get("source") == shared_source and
            value.get("result") == "complete_private_candidate_channel_and_handoff_operations",
            "Production operations record has the wrong release identity or result")
    candidate = value.get("candidate")
    exact_keys(candidate, {"channel", "status", "update_url", "predecessor_build",
                           "successor_build"}, "candidate channel")
    require(isinstance(candidate.get("channel"), str) and
            re.fullmatch(r"[a-z][a-z0-9-]{1,31}", candidate["channel"]) and
            candidate.get("status") == "private_flashable_candidate_not_production_or_hardware_qualified" and
            candidate.get("predecessor_build") == pair["predecessor"]["number"] and
            candidate.get("successor_build") == pair["successor"]["number"] and
            candidate.get("update_url") == updater.get("update_url"),
            "Candidate channel does not select the authenticated release pair and Updater")
    concrete_https(candidate["update_url"], "candidate update URL")

    owners = value.get("ownership")
    require(isinstance(owners, dict) and set(owners) == OWNER_ROLES,
            "Production operations lacks every accountable owner")
    for role, owner in owners.items():
        validate_owner(owner, role.replace("_", " ") + " owner")

    publication = value.get("publication")
    exact_keys(publication, {"artifact_base_url", "metadata_base_url",
                             "release_index_digest_url", "failure_communication_url",
                             "signed_ota_metadata", "release_pair_and_endpoint_receipts",
                             "public_trust_anchors_separately_published",
                             "out_of_band_index_sha256_required",
                             "offline_verification_before_publication"},
               "candidate publication")
    for name in ("artifact_base_url", "metadata_base_url", "release_index_digest_url",
                 "failure_communication_url"):
        concrete_https(publication.get(name), name.replace("_", " "))
    require(publication.get("metadata_base_url") == candidate["update_url"] and
            all(publication.get(name) is True for name in {
        "signed_ota_metadata", "release_pair_and_endpoint_receipts",
        "public_trust_anchors_separately_published", "out_of_band_index_sha256_required",
        "offline_verification_before_publication"}),
        "Candidate publication endpoint/authenticity controls are incomplete")

    rollout = value.get("rollout")
    require(rollout == {
        "mode": "private_allowlisted_candidate",
        "production_enabled": False,
        "approval_gate": "phase2_exact_hash_physical_pixel8_qualification",
        "promotion_owner": "release",
        "withdrawal_owner": "withdrawal",
        "withdrawal_action": "remove_signed_metadata_and_artifacts_then_publish_signed_notice",
    }, "Candidate rollout/withdrawal policy is incomplete or production-enabled")

    maintenance = value.get("maintenance")
    exact_keys(maintenance, {"security_monitoring_urls", "security_review_cadence_days",
                             "rebase_decision_cadence_days", "rebase_policy"},
               "candidate maintenance")
    urls = maintenance.get("security_monitoring_urls")
    require(isinstance(urls, list) and urls == sorted(set(urls)) and urls,
            "Security monitoring URLs must be a non-empty sorted unique list")
    for ordinal, url in enumerate(urls):
        concrete_https(url, f"security monitoring URL {ordinal}", allow_grapheneos=True)
    require(any((urlsplit(url).hostname or "").rstrip(".").lower() in
                {"grapheneos.org", "releases.grapheneos.org"} or
                (urlsplit(url).hostname or "").rstrip(".").lower().endswith(".grapheneos.org")
                for url in urls), "Maintenance must monitor an official GrapheneOS source")
    require(type(maintenance.get("security_review_cadence_days")) is int and
            1 <= maintenance["security_review_cadence_days"] <= 7 and
            type(maintenance.get("rebase_decision_cadence_days")) is int and
            1 <= maintenance["rebase_decision_cadence_days"] <= 31 and
            maintenance.get("rebase_policy") ==
            "each_grapheneos_security_release_is_triaged_and_required_os_changes_reenter_phase1",
            "Security monitoring/rebase cadence or policy is incomplete")

    require(value.get("change_control") == {
        "os_privileged_interface_or_signer_change": "requires_new_phase1_and_phase2_qualification",
        "ordinary_apk_only_change":
            "may_ship_independently_only_when_api_os_trust_policy_and_signer_are_unchanged",
    }, "OS/API-versus-APK change-control rule is incomplete")
    runbook = validate_embedded_ref(root, value.get("runbook"), "operations runbook")
    current_runbook = stable_ref(OPERATIONS_RUNBOOK,
        "android/platform/PHASE1-INSTALL-UPDATE-RECOVERY.md", reject_private=False)
    require((runbook["sha256"], runbook["size"]) ==
            (current_runbook["sha256"], current_runbook["size"]),
            "Operations runbook differs from the reviewed repository runbook")
    ceremony = validate_embedded_ref(root, value.get("signing_ceremony"),
                                     "operations signing ceremony")
    require(ceremony == ceremony_ref,
            "Production operations selects a different signing ceremony record")
    require(value.get("physical_rollback") == {
        "tested": False, "qualification_phase": "Phase 2",
        "claim": "procedural_guidance_only_untested_until_phase2",
    }, "Operations record overclaims physical rollback testing")
    return {"channel": candidate["channel"], "update_url": candidate["update_url"],
            "production_enabled": False, "runbook": runbook,
            "result": value["result"]}


def review_bindings(refs, sdk_identity, source_proof_ref):
    result = {name: refs[name]["sha256"] for name in REVIEW_BINDING_KEYS
              if name not in {"sdk_publication", "source_difference_proof"}}
    result["sdk_publication"] = sdk_identity
    result["source_difference_proof"] = (
        None if source_proof_ref is None else source_proof_ref["sha256"])
    require(set(result) == REVIEW_BINDING_KEYS, "Internal final-review binding set changed")
    return result


def validate_review(root: Path, value, expected_bindings, defect_ids):
    exact_keys(value, {"schema", "kind", "qualification", "decision", "reviewers",
                       "scopes", "evidence_sha256", "defect_ids", "report"},
               "final OS-glue review")
    require(value.get("schema") == SCHEMA and value.get("kind") == REVIEW_KIND and
            value.get("qualification") == QUALIFICATION and value.get("decision") == "approved" and
            value.get("scopes") == sorted(REQUIRED_REVIEW_SCOPES) and
            value.get("evidence_sha256") == expected_bindings and
            value.get("defect_ids") == defect_ids,
            "Final review does not cover the exact complete Phase-1 evidence")
    reviewers = value.get("reviewers")
    require(isinstance(reviewers, list) and reviewers and all(
        isinstance(row, dict) and set(row) == {"name", "role"} and
        isinstance(row["name"], str) and row["name"].strip() == row["name"] and row["name"] and
        isinstance(row["role"], str) and row["role"].strip() == row["role"] and row["role"]
        for row in reviewers), "Final review lacks identified reviewers")
    for ordinal, reviewer in enumerate(reviewers):
        non_placeholder(reviewer["name"], f"reviewer {ordinal} name")
        non_placeholder(reviewer["role"], f"reviewer {ordinal} role")
    validate_embedded_ref(root, value.get("report"), "final review report")
    return {"decision": "approved", "reviewers": len(reviewers),
            "scopes": sorted(REQUIRED_REVIEW_SCOPES)}


def runtime_embedded_binding(root: Path, result_path: Path, x86_refs, x86_receipt, x86_signer):
    result, _ = load_json_path(result_path, "runtime result")
    admission, admission_ref, admission_path = load_bound_runtime_json(
        root, result.get("admission"), "runtime admission")
    plan, inputs_ref, _inputs_path = load_bound_runtime_json(
        root, admission.get("inputs"), "runtime frozen inputs")
    _qualification, qualification_ref, _qualification_path = load_bound_runtime_json(
        root, admission.get("qualification"), "runtime qualification")
    evidence_index, evidence_index_ref, _evidence_index_path = load_bound_runtime_json(
        root, result.get("evidence_index"), "runtime evidence index")
    evidence = plan.get("image", {}).get("manifest", {}).get("value", {}).get("phase1_build_evidence")
    require(isinstance(evidence, dict), "Runtime image lacks authenticated Phase-1 build evidence")
    mapping = {
        "baseline_receipt": x86_refs["baseline_receipt"],
        "custom_receipt": x86_refs["custom_receipt"],
        "comparison": x86_refs["comparison"],
    }
    for name, reference in mapping.items():
        row = evidence.get(name, {})
        require(row.get("expected_sha256") == reference["sha256"] and
                row.get("file") == {"sha256": reference["sha256"],
                                    "size": reference["size"]},
                f"Runtime image embeds a different x86 {name}")
    packet = evidence.get("client_packet", {})
    require(packet.get("development_only") is True and packet.get("runtime_qualified") is False and
            packet.get("staged_signer_der_sha256") == x86_signer,
            "Runtime image client/staged development signer differs from x86 source")
    require(evidence.get("source_pin_sha256") ==
            canonical_digest(x86_receipt.get("source", {}).get("pin")) and
            evidence.get("shared_fingerprint") == x86_receipt.get("fingerprint") and
            evidence.get("qualification_claimed") is False,
            "Runtime image source pin, fingerprint or qualification differs from x86 build")
    records = evidence_index.get("records") if isinstance(evidence_index, dict) else None
    require(isinstance(records, list) and len(records) == 4,
            "Runtime evidence index lacks the exact four authenticated guests")
    guests = []
    for ordinal, record in enumerate(records):
        identity = record.get("identity") if isinstance(record, dict) else None
        require(isinstance(identity, dict) and set(identity) == {"run", "boot_id", "container"} and
                re.fullmatch(r"[0-9a-f]{32}", str(identity["run"])) and
                re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                             str(identity["boot_id"])) and
                re.fullmatch(r"[0-9a-f]{64}", str(identity["container"])),
                f"Runtime guest {ordinal} has a malformed authenticated identity")
        guests.append(dict(identity))
    require(all(len({row[field] for row in guests}) == len(guests)
                for field in ("run", "boot_id", "container")),
            "Runtime campaign reused a guest run/boot/container identity")
    return {
        "candidate_image": admission.get("image_id"),
        "x86_evidence_embedded": True,
        "development_signer_sha256": x86_signer,
        "admission": admission_ref,
        "inputs": inputs_ref,
        "qualification": qualification_ref,
        "evidence_index": evidence_index_ref,
        "guests": guests,
    }


def _same_file_identity(left, right):
    """Compare size-vs-bytes references without accepting partial identities."""
    if not isinstance(left, dict) or not isinstance(right, dict):
        return False
    left_size = left.get("size", left.get("bytes"))
    right_size = right.get("size", right.get("bytes"))
    return (set(left) in ({"sha256", "size"}, {"sha256", "bytes"}) and
            set(right) in ({"sha256", "size"}, {"sha256", "bytes"}) and
            left.get("sha256") == right.get("sha256") and
            type(left_size) is int and left_size > 0 and left_size == right_size)


def validate_development_packet_binding(receipt, packet_ref, client, x86_signer):
    """Bind the development emulator packet to the production SDK compile.

    Signing differs intentionally: the packet is development-signed while the
    production client is release-signed.  Their authenticated unsigned APK and
    compile/source-freeze inputs must nevertheless be byte-identical.
    """
    require(isinstance(receipt, dict) and receipt.get("schema") == 2 and
            receipt.get("kind") == "phase1_source_matched_x86_development_client_packet_v1" and
            receipt.get("status") == "compile_qualified_development_packet_not_runtime_qualified" and
            receipt.get("development_only") is True and receipt.get("runtime_qualified") is False,
            "Fresh conformance did not select the source-matched development packet")
    successor = receipt.get("successor", {})
    artifacts = receipt.get("artifacts", {})
    require(_same_file_identity(successor.get("build_receipt"), client.get("source_receipt")) and
            _same_file_identity(successor.get("source_freeze"),
                                client.get("source_freeze", {}).get("identity")) and
            _same_file_identity(successor.get("input_conformance"),
                                client.get("conformance", {}).get("unsigned_apk")),
            "Development packet does not come from the production SDK/client compile freeze")
    packet_conformance = artifacts.get("conformance", {})
    packet_wonad = artifacts.get("wonad", {})
    # The packet and production provenance tools intentionally use different
    # normalized *signed* payload schemas.  Do not compare those incomparable
    # digests.  Their exact common unsigned APK is cross-bound above; each
    # producer independently proves its signed derivative preserves it.
    require(SHA256.fullmatch(str(packet_conformance.get("payload_sha256", ""))) and
            SHA256.fullmatch(str(client.get("conformance", {}).get("payload_sha256", ""))) and
            packet_conformance.get("certificate_der_sha256") == x86_signer and
            packet_wonad.get("certificate_der_sha256") == x86_signer and
            SHA256.fullmatch(str(packet_ref.get("sha256", ""))) and
            type(packet_ref.get("size")) is int and packet_ref["size"] > 0,
            "Development packet APK payload/signer differs from the x86/client freeze")
    return {
        "receipt": packet_ref,
        "compile_receipt_sha256": successor["build_receipt"]["sha256"],
        "source_freeze_sha256": successor["source_freeze"]["sha256"],
        "unsigned_conformance_sha256": successor["input_conformance"]["sha256"],
        "development_conformance_payload_sha256": packet_conformance["payload_sha256"],
        "production_conformance_payload_sha256": client["conformance"]["payload_sha256"],
        "development_signer_sha256": x86_signer,
    }


def validate_fresh_identity_separation(api_report, recents_report, recents_summary, campaign):
    """Reject seeded/reused guests across API, Recents and runtime lanes."""
    api_container = api_report.get("container")
    api_boot = api_report.get("boot_id")
    api_runs = [api_report.get("container_run"), api_report.get("run")]
    recents_container = recents_summary.get("container_id")
    recents_boot = recents_summary.get("boot_id")
    recents_runs = [recents_summary.get("run"), recents_summary.get("recents_run"),
                    recents_summary.get("conformance_run")]
    require(isinstance(campaign, list) and len(campaign) == 4 and
            all(isinstance(row, dict) and set(row) == {"run", "boot_id", "container"}
                for row in campaign),
            "Runtime guest identities are missing from authenticated campaign evidence")
    all_runs = api_runs + recents_runs + [row["run"] for row in campaign]
    all_boots = [api_boot, recents_boot, *[row["boot_id"] for row in campaign]]
    all_containers = [api_container, recents_container,
                      *[row["container"] for row in campaign]]
    require(all(re.fullmatch(r"[0-9a-f]{32}", str(value)) for value in all_runs) and
            all(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                             str(value)) for value in all_boots) and
            all(re.fullmatch(r"[0-9a-f]{64}", str(value)) for value in all_containers) and
            len(set(all_runs)) == len(all_runs) and len(set(all_boots)) == len(all_boots) and
            len(set(all_containers)) == len(all_containers) and
            isinstance(api_report.get("userdata_retained_path"), str) and
            isinstance(recents_report.get("userdata_retained_path"), str) and
            api_report["userdata_retained_path"] != recents_report["userdata_retained_path"],
            "Fresh API, Recents and runtime campaign reused a run/boot/container/userdata identity")
    return {"runs": len(all_runs), "boots": len(all_boots),
            "containers": len(all_containers), "userdata": "distinct"}


def validate_conformance_acceptance(root: Path, selection, x86_refs, x86_receipt,
                                    x86_signer, runtime_binding, client):
    """Replay and cross-bind the mandatory fresh API and Recents guests."""
    exact_keys(selection, {"product", "client_packet", "api_report", "recents_report"},
               "fresh conformance selection")
    product = confined(root, selection["product"], "fresh conformance product", directory=True)
    packet = confined(root, selection["client_packet"], "fresh conformance packet", directory=True)
    api_path = confined(root, selection["api_report"], "fresh API report")
    recents_path = confined(root, selection["recents_report"], "fresh Recents report")
    packet_relative = (PurePosixPath(selection["client_packet"]) / "receipt.json").as_posix()
    packet_path = confined(root, packet_relative, "fresh conformance packet receipt")
    packet_ref = file_ref(root, packet_relative, "fresh conformance packet receipt")
    api_ref = file_ref(root, selection["api_report"], "fresh API report")
    recents_ref = file_ref(root, selection["recents_report"], "fresh Recents report")

    api_summary = verifier_call(
        "fresh API conformance", conformance_acceptance.audit_report,
        api_path, product, packet, packet_ref["sha256"])
    recents_summary = verifier_call(
        "fresh Recents conformance", recents_guest_acceptance.audit_report,
        recents_path, product, packet, packet_ref["sha256"])
    require(api_summary.get("status") ==
                "accepted_fresh_guest_conformance_not_runtime_qualification" and
            recents_summary.get("status") ==
                "accepted_fresh_recents_guest_not_runtime_or_hardware_qualification",
            "Fresh API/Recents evidence was not independently accepted")

    api_report, _ = load_json_path(api_path, "fresh API report")
    recents_report, _ = load_json_path(recents_path, "fresh Recents report")
    api_manifest, _ = load_json_path(api_path.parent / "image-manifest.json",
                                     "fresh API candidate manifest")
    recents_manifest, _ = load_json_path(recents_path.parent / "guest/image-manifest.json",
                                         "fresh Recents candidate manifest")
    api_product, _ = load_json_path(api_path.parent / "product-candidate-manifest.json",
                                    "fresh API product manifest")
    recents_product, _ = load_json_path(
        recents_path.parent / "guest/product-candidate-manifest.json",
        "fresh Recents product manifest")
    receipt, _ = load_json_path(packet_path, "fresh conformance packet receipt")
    require(api_manifest == recents_manifest and api_product == recents_product,
            "Fresh API and Recents guests used different candidate/product manifests")
    base_evidence = verifier_call(
        "fresh conformance base build evidence",
        conformance_acceptance.builder.validate_phase1_base_evidence, api_product, product)
    mapping = {"baseline_receipt": x86_refs["baseline_receipt"],
               "custom_receipt": x86_refs["custom_receipt"],
               "comparison": x86_refs["comparison"]}
    for name, reference in mapping.items():
        row = base_evidence.get(name, {})
        require(row.get("expected_sha256") == reference["sha256"] and
                row.get("file") == {"sha256": reference["sha256"],
                                    "size": reference["size"]},
                "Fresh conformance candidate embeds a different x86 " + name)
    packet_row = base_evidence.get("client_packet", {})
    require(packet_row.get("expected_sha256") == packet_ref["sha256"] and
            packet_row.get("file") == {"sha256": packet_ref["sha256"],
                                       "size": packet_ref["size"]} and
            packet_row.get("staged_signer_der_sha256") == x86_signer and
            packet_row.get("wonad_apk", {}).get("certificate_der_sha256") == x86_signer and
            base_evidence.get("source_pin_sha256") ==
                canonical_digest(x86_receipt.get("source", {}).get("pin")) and
            base_evidence.get("shared_fingerprint") == x86_receipt.get("fingerprint") and
            base_evidence.get("selected_custom_build", {}).get("product") == str(product) and
            base_evidence.get("qualification_claimed") is False,
            "Fresh conformance product/packet/source identity differs from x86 custom build")
    packet_binding = validate_development_packet_binding(
        receipt, packet_ref, client, x86_signer)

    base_image = api_manifest.get("base_product_candidate", {}).get("image_id")
    require(api_report.get("image_id") == recents_report.get("image_id") ==
                api_summary.get("image_id") == recents_summary.get("image_id") and
            base_image == recents_summary.get("base_image_id") ==
                runtime_binding.get("candidate_image") and
            api_report.get("fingerprint") == recents_report.get("fingerprint") ==
                x86_receipt.get("fingerprint"),
            "Fresh guests do not share the exact runtime-qualified x86 candidate ancestry")

    child_path = recents_path.parent / "recents/report.json"
    try:
        child_relative = child_path.relative_to(root).as_posix()
    except ValueError as error:
        raise IndexError("Fresh Recents child report is outside the evidence root") from error
    require(confined(root, child_relative, "fresh Recents child report") == child_path,
            "Fresh Recents child report traverses an unsafe path")
    child_ref = file_ref(root, child_relative, "fresh Recents child report")
    require(recents_report.get("recents_report") == {
                "path": "recents/report.json", "sha256": child_ref["sha256"],
                "bytes": child_ref["size"]} and
            recents_summary.get("recents_report_sha256") == child_ref["sha256"],
            "Fresh Recents wrapper selects another child report")

    campaign = runtime_binding.get("guests")
    identity_summary = validate_fresh_identity_separation(
        api_report, recents_report, recents_summary, campaign)
    api_container, api_boot = api_report["container"], api_report["boot_id"]
    recents_container, recents_boot = (recents_summary["container_id"],
                                      recents_summary["boot_id"])

    # Close the semantic-replay/publication interval over every transitive raw
    # input, not only the four top-level JSON reports.  These deterministic
    # identities are also bound into final review and replayed by verify().
    packet_tree_before = packet_tree_binding(root, selection["client_packet"])
    conformance_acceptance.packet_tool.validate_receipt(
        packet, receipt, packet_ref["sha256"], live_tools=False)
    packet_binding_tree = packet_tree_binding(root, selection["client_packet"])
    require(packet_binding_tree == packet_tree_before,
            "Fresh conformance packet tree changed during terminal validation")
    final_products = api_manifest["product_images"]
    final_os_artifacts = api_manifest["os_artifacts"]
    product_binding = product_identity(
        root, selection["product"], api_product, final_products, final_os_artifacts)
    api_evidence = declared_evidence_set(
        root, api_path.parent, api_report.get("evidence_files"),
        "fresh API evidence set")
    recents_guest_evidence = declared_evidence_set(
        root, recents_path.parent / "guest", recents_report.get("guest_setup_evidence"),
        "fresh Recents guest evidence set")
    recents_child_evidence = declared_evidence_set(
        root, child_path.parent, child.get("evidence_files"),
        "fresh Recents child evidence set")

    # Detect mutation of the selected top-level records during aggregate replay.
    require(file_ref(root, packet_relative, "fresh conformance packet receipt") == packet_ref and
            file_ref(root, selection["api_report"], "fresh API report") == api_ref and
            file_ref(root, selection["recents_report"], "fresh Recents report") == recents_ref and
            file_ref(root, child_relative, "fresh Recents child report") == child_ref,
            "Fresh conformance evidence changed during aggregate replay")
    conformance_acceptance.packet_tool.validate_receipt(
        packet, receipt, packet_ref["sha256"], live_tools=False)
    require(packet_tree_binding(root, selection["client_packet"]) == packet_binding_tree and
            product_identity(root, selection["product"], api_product,
                             final_products, final_os_artifacts) == product_binding and
            declared_evidence_set(root, api_path.parent, api_report["evidence_files"],
                                  "fresh API evidence set") == api_evidence and
            declared_evidence_set(root, recents_path.parent / "guest",
                                  recents_report["guest_setup_evidence"],
                                  "fresh Recents guest evidence set") ==
                recents_guest_evidence and
            declared_evidence_set(root, child_path.parent, child["evidence_files"],
                                  "fresh Recents child evidence set") ==
                recents_child_evidence,
            "Fresh conformance transitive evidence changed at publication edge")
    references = {
        "conformance_packet_receipt": packet_ref,
        "conformance_api_report": api_ref,
        "conformance_recents_report": recents_ref,
        "conformance_recents_child_report": child_ref,
        "conformance_packet_tree": packet_binding_tree,
        "conformance_product_identity": product_binding,
        "conformance_api_evidence_set": api_evidence,
        "conformance_recents_guest_evidence_set": recents_guest_evidence,
        "conformance_recents_child_evidence_set": recents_child_evidence,
    }
    return {
        "candidate_image": api_report["image_id"], "base_image": base_image,
        "fingerprint": api_report["fingerprint"], "packet": packet_binding,
        "phase1_build_evidence_sha256": canonical_digest(base_evidence),
        "publication_bindings": {
            "product": product_binding, "packet": packet_binding_tree,
            "api_evidence": api_evidence,
            "recents_guest_evidence": recents_guest_evidence,
            "recents_child_evidence": recents_child_evidence,
        },
        "identity_separation": identity_summary,
        "api": {"report": api_ref, "status": api_summary["status"],
                "container": api_container, "boot_id": api_boot,
                "run": api_report["run"], "container_run": api_report["container_run"]},
        "recents": {"report": recents_ref, "child_report": child_ref,
                    "status": recents_summary["status"],
                    "container": recents_container, "boot_id": recents_boot,
                    "run": recents_summary["run"],
                    "recents_run": recents_summary["recents_run"],
                    "conformance_run": recents_summary["conformance_run"]},
    }, references


def validate_ota_build_dates(pair_result):
    """Bind real endpoint dates and require an update the pinned Updater sees.

    Its eligibility check uses a strictly newer build timestamp, not merely a
    greater incremental build number. Keep this aggregate guard independent of
    the frozen pair producer, which currently also accepts equal timestamps.
    """
    require(isinstance(pair_result, dict) and isinstance(pair_result.get("pair"), dict),
            "OTA build timestamps lack the authenticated release pair")
    timestamps = {}
    for role in ("predecessor", "successor"):
        receipt = pair_result.get(role)
        endpoint = pair_result["pair"].get(role)
        require(isinstance(receipt, dict) and isinstance(receipt.get("build"), dict) and
                isinstance(endpoint, dict) and isinstance(endpoint.get("build"), dict),
                f"OTA {role} build timestamp lacks its full receipt or embedded endpoint")
        build, embedded = receipt["build"], endpoint["build"]
        timestamp, embedded_timestamp = build.get("timestamp"), embedded.get("timestamp")
        require(type(timestamp) is int and timestamp > 0 and
                type(embedded_timestamp) is int and embedded_timestamp > 0,
                f"OTA {role} build timestamps must be positive exact integers")
        number = build.get("number")
        require(isinstance(number, str) and re.fullmatch(r"[0-9]{10}", number) and
                endpoint.get("number") == number and embedded.get("number") == number and
                embedded_timestamp == timestamp,
                f"OTA {role} endpoint label/timestamp differs from its full release receipt")
        timestamps[role] = timestamp
    require(timestamps["successor"] > timestamps["predecessor"],
            "OTA successor build timestamp must be strictly newer than predecessor for the pinned Updater")


def validate_release_cross_bindings(pair_result, arm_custom, client_record, lock_ref):
    validate_ota_build_dates(pair_result)
    pair = pair_result["pair"]
    successor = pair_result["successor"]
    stage, production_signer = arm_stage(arm_custom)
    require(successor.get("grapheneos_lock", {}).get("sha256") == lock_ref["sha256"] and
            successor.get("wonad_stage") == stage["marker"] and
            successor.get("updater_stage") == stage["updater"] and
            successor.get("apk_signer_sha256") == production_signer,
            "Signed ARM successor differs from the source-matched custom build")
    client_summary = successor.get("phase1_provenance", {}).get("client_record", {})
    require(client_summary.get("sha256") == client_record["_reference"]["sha256"] and
            client_summary.get("size") == client_record["_reference"]["size"] and
            client_summary.get("signer_sha256") == production_signer and
            client_summary.get("conformance_apk_sha256") ==
                client_record["conformance"]["apk"]["sha256"] and
            client_summary.get("sdk_publication_sha256") ==
                canonical_digest(client_record["sdk_publication"]["files"]) and
            client_summary.get("source_freeze_sha256") ==
                client_record["source_freeze"]["files_sha256"],
            "Signed ARM successor does not bundle the selected production client/SDK evidence")
    require(pair["successor"]["number"] == successor["build"]["number"],
            "Release-pair successor identity is inconsistent")
    return production_signer


def validate_signed_source_binding(root: Path, pair_result, arm_custom):
    """Bind the signed successor's complete source record to the ARM comparison.

    The release receipt already authenticates this bundled record.  This check
    closes the remaining semantic edge: the build compared with the clean ARM
    baseline and the build later signed as the successor must have the same
    complete project and build-visible source state, not merely the same stage
    marker or release tag.
    """
    successor_receipt_path = Path(pair_result.get("paths", {}).get("successor", ""))
    require(successor_receipt_path.is_absolute() and successor_receipt_path.is_file() and
            not successor_receipt_path.is_symlink() and
            successor_receipt_path.resolve(strict=True) == successor_receipt_path,
            "Signed release pair lacks its canonical successor receipt path")
    try:
        successor_relative = successor_receipt_path.relative_to(root).as_posix()
    except ValueError as error:
        raise IndexError("Signed successor receipt is outside the aggregate evidence root") from error
    require(confined(root, successor_relative, "signed successor receipt") == successor_receipt_path,
            "Signed successor receipt traverses an unsafe path")
    source_path = successor_receipt_path.parent / "wonad-provenance/source-provenance.json"
    try:
        relative = source_path.relative_to(root).as_posix()
    except ValueError as error:
        raise IndexError("Signed successor source provenance is outside the aggregate evidence root") from error
    source_path = confined(root, relative, "signed successor source provenance")
    source_record, reference, _ = load_json_ref(
        root, relative, "signed successor source provenance")
    try:
        source_record = provenance.validate_source_record_shape(source_record)
    except provenance.ProvenanceError as error:
        raise IndexError(f"Signed successor source provenance is invalid: {error}") from error
    raw_reference = {key: reference[key] for key in ("sha256", "size")}
    arm_source = arm_custom.get("source", {})
    pin = arm_source.get("pin", {})
    manifest = source_record.get("manifest", {})
    summary = pair_result.get("successor", {}).get("phase1_provenance", {}).get("source_record", {})
    require(summary.get("sha256") == raw_reference["sha256"] and
            summary.get("size") == raw_reference["size"] and
            source_record.get("lock") == pin.get("lock") and
            manifest.get("commit") == pin.get("manifest_commit") and
            manifest.get("tag_object") == pin.get("manifest_tag_object") and
            manifest.get("default_xml") == pin.get("default_xml") and
            manifest.get("projects") == pin.get("projects") and
            manifest.get("project_count") == pin.get("project_count") and
            manifest.get("project_ledger_sha256") == pin.get("project_ledger_sha256") and
            source_record.get("owned_tracked_changes") == arm_source.get("owned_tracked_changes") and
            source_record.get("generated_inputs") == arm_source.get("generated_inputs") and
            source_record.get("builder") == arm_custom.get("builder") and
            source_record.get("repo_tool", {}).get("commit") == pin.get("repo_tool_commit") and
            summary.get("manifest_commit") == pin.get("manifest_commit") and
            summary.get("project_count") == pin.get("project_count") and
            summary.get("project_ledger_sha256") == pin.get("project_ledger_sha256"),
            "Signed successor source/project/generated-input state differs from ARM comparison")
    audited_projects = source_record.get("source_audit", {}).get("projects", {})
    materializations = {}
    require(isinstance(audited_projects, dict),
            "Signed successor source audit lacks project materializations")
    for project, audit in audited_projects.items():
        require(isinstance(audit, dict),
                "Signed successor source audit contains a malformed project")
        materializations[project] = {
            "gitlinks": audit.get("gitlinks"),
            "materialized_eol": audit.get("materialized_eol"),
            "materialized_lfs": audit.get("materialized_lfs"),
        }
    materializations = dict(sorted(materializations.items()))
    require(materializations == arm_source.get("worktree_materializations") and
            canonical_digest(materializations) ==
                arm_source.get("worktree_materializations_sha256"),
            "Signed successor worktree materializations differ from ARM comparison")
    return {
        "source_provenance": reference,
        "project_ledger_sha256": pin["project_ledger_sha256"],
        "worktree_materializations_sha256": arm_source["worktree_materializations_sha256"],
        "generated_inputs_sha256": source_record["generated_inputs_sha256"],
    }


def require_policy_free_runtime_exit_admission():
    """Do not upgrade product/partial evidence to genuine Phase-1 conformance.

    There is presently no reviewed complete policy-free campaign kind or raw
    auditor. The three-clean-boot producer/auditor is implemented separately;
    no actual current conformance campaign is qualified. The full
    86400-second/minimum-three-round nine-disturbance soak is not implemented. This guard
    has no CLI/environment waiver and no invented positive report schema.
    Remove it only through reviewed source changes integrating the complete
    independent raw auditors/bindings; never by relabelling historical reports.
    """
    raise IndexError(
        "Policy-free ConformanceService final runtime admission is unavailable: "
        "product DesktopService/Haskell reports, three-clean-boot aggregates "
        "and bounded hotplug/health slices cannot establish the complete "
        "23-gate, three mixed-monitor 20-cycle boots plus uninterrupted "
        "86400-second/minimum-three-round nine-disturbance conformance campaign. "
        "No Phase-1 release index may be published or requalified until its "
        "complete producer and independent raw admission are implemented.")


def collect(root: Path, assembly_path: Path):
    root = canonical_root(root)
    tools = tool_ledger()
    require(assembly_path.is_absolute() and assembly_path.parent == root and
            assembly_path.resolve(strict=True) == assembly_path and not assembly_path.is_symlink(),
            "Assembly must be a literal ordinary direct child of the evidence root")
    assembly, assembly_raw_ref = load_json_path(assembly_path, "Phase-1 assembly")
    validate_assembly(assembly)
    assembly_ref = {"path": assembly_path.name, **assembly_raw_ref}

    refs = {
        "grapheneos_lock": file_ref(root, assembly["grapheneos_lock"], "GrapheneOS lock"),
        "api_contract": file_ref(root, assembly["api_contract"], "API contract"),
    }
    lock_path = confined(root, assembly["grapheneos_lock"], "GrapheneOS lock")
    load_lock(lock_path)
    current_lock = stable_ref(ROOT / "android/grapheneos.lock.json",
                              "android/grapheneos.lock.json", reject_private=False)
    require(refs["grapheneos_lock"]["sha256"] == current_lock["sha256"] and
            refs["grapheneos_lock"]["size"] == current_lock["size"],
            "Evidence lock differs from the reviewed repository lock")
    current_contract = stable_ref(ROOT / "android/EXTERNAL-SHELL.md",
                                  "android/EXTERNAL-SHELL.md", reject_private=False)
    require(refs["api_contract"]["sha256"] == current_contract["sha256"] and
            refs["api_contract"]["size"] == current_contract["size"],
            "Evidence API contract differs from the reviewed repository contract")

    # x86 baseline/custom comparison and exact-image runtime campaign.
    xpaths, xrefs = {}, {}
    for name in ("baseline_receipt", "custom_receipt", "comparison", "runtime_result"):
        relative = assembly["x86"][name]
        xpaths[name] = confined(root, relative, "x86 " + name)
        xrefs[name] = file_ref(root, relative, "x86 " + name)
    verifier_call("x86 comparison", x86.verify_comparison,
                  xpaths["comparison"], xrefs["comparison"]["sha256"],
                  xpaths["baseline_receipt"], xrefs["baseline_receipt"]["sha256"],
                  xpaths["custom_receipt"], xrefs["custom_receipt"]["sha256"])
    xbaseline, _ = load_json_path(xpaths["baseline_receipt"], "x86 baseline receipt")
    xcustom, _ = load_json_path(xpaths["custom_receipt"], "x86 custom receipt")
    x_stage, x_signer = x86_stage(xcustom)
    runtime_summary = verifier_call("runtime campaign", runtime.verify_result,
                                    xpaths["runtime_result"])
    require(runtime_summary.get("runtime_qualification") == "passed" and
            runtime_summary.get("production_acceptance") == "passed" and
            runtime_summary.get("boots") == 4 and runtime_summary.get("soak_rounds", 0) >= 3 and
            IMAGE_ID.fullmatch(str(runtime_summary.get("candidate_image", ""))),
            "Runtime evidence is not the production three-boot plus 24-hour soak campaign")
    runtime_binding = runtime_embedded_binding(
        root, xpaths["runtime_result"], xrefs, xcustom, x_signer)
    require(runtime_binding["candidate_image"] == runtime_summary["candidate_image"],
            "Runtime candidate image identity changed across its evidence")

    # ARM clean/custom comparison and signed predecessor/successor release pair.
    apaths, arefs = {}, {}
    for name in ("baseline_receipt", "custom_receipt", "comparison"):
        relative = assembly["arm"][name]
        apaths[name] = confined(root, relative, "ARM " + name)
        arefs[name] = file_ref(root, relative, "ARM " + name)
    verifier_call("ARM comparison", frankel.verify_comparison,
                  apaths["comparison"], arefs["comparison"]["sha256"],
                  apaths["baseline_receipt"], arefs["baseline_receipt"]["sha256"],
                  apaths["custom_receipt"], arefs["custom_receipt"]["sha256"])
    abaseline, _ = load_json_path(apaths["baseline_receipt"], "ARM baseline receipt")
    acustom, _ = load_json_path(apaths["custom_receipt"], "ARM custom receipt")

    release_names = ("release_pair_receipt", "avb_public_key", "ota_certificate",
                     "factory_public_key", "trusted_otatools_manifest")
    release_paths, release_refs = {}, {}
    for name in release_names:
        relative = assembly["arm"][name]
        release_paths[name] = confined(root, relative, "ARM " + name)
        release_refs[name] = file_ref(root, relative, "ARM " + name)
    require(release_refs["trusted_otatools_manifest"]["sha256"] ==
            assembly["arm"]["trusted_otatools_manifest_sha256"],
            "Trusted otatools manifest differs from its assembly anchor")
    pair_evidence = verifier_call(
        "signed ARM release pair", verify_release_pair.verify,
        release_paths["release_pair_receipt"], release_paths["avb_public_key"],
        release_paths["ota_certificate"], release_paths["factory_public_key"],
        release_refs["release_pair_receipt"]["sha256"],
        release_paths["trusted_otatools_manifest"],
        assembly["arm"]["trusted_otatools_manifest_sha256"])
    # verify_release_pair returns a public summary.  The semantic pair binding
    # is loaded again without executing tools to expose the exact endpoint
    # receipts used for cross-target/client checks.
    pair_bound = verifier_call("ARM pair layout", release_pair_receipt.verify_pair_receipt,
                               release_paths["release_pair_receipt"])
    validate_ota_build_dates(pair_bound)
    signed_source_binding = validate_signed_source_binding(root, pair_bound, acustom)

    # Production client and SDK publication.
    cpaths, crefs = {}, {}
    for name, relative in assembly["clients"].items():
        if name == "sdk_publication":
            cpaths[name] = confined(root, relative, "SDK publication", directory=True)
        else:
            cpaths[name] = confined(root, relative, "client " + name)
            crefs[name] = file_ref(root, relative, "client " + name)
    sdk_ref = tree_ref(root, assembly["clients"]["sdk_publication"], "SDK publication")
    client_value, _ = load_json_path(cpaths["record"], "production client record")
    try:
        client_value = provenance.validate_clients_shape(client_value)
        actual_client = provenance.collect_clients(
            cpaths["sdk_publication"], cpaths["conformance_apk"], cpaths["source_receipt"],
            cpaths["signer_certificate"], cpaths["apksigner"], QUALIFICATION)
    except provenance.ProvenanceError as error:
        raise IndexError(f"Production client/SDK verification failed: {error}") from error
    require(client_value == actual_client and client_value["qualification"] == QUALIFICATION,
            "Production client/SDK differs from its immutable record")
    require(sdk_ref["files"] == {name: {"sha256": row["sha256"], "size": row["size"]}
                                      for name, row in client_value["sdk_publication"]["files"].items()},
            "Explicit SDK tree differs from production client provenance")
    client_value = copy.deepcopy(client_value)
    client_value["_reference"] = crefs["record"]
    production_signer = validate_release_cross_bindings(
        pair_bound, acustom, client_value, refs["grapheneos_lock"])
    require(client_value["public_signer"]["der_sha256"] == production_signer,
            "Selected production client signer differs from ARM source/release signer")

    # One common source freeze, with an explicit proof exactly when the x86
    # development signer makes the stage bytes differ from production ARM.
    shared_source = source_identity(xcustom)
    require(shared_source == source_identity(acustom) and
            shared_source["lock_sha256"] == refs["grapheneos_lock"]["sha256"],
            "x86/ARM source identity does not bind the selected GrapheneOS lock")
    proof_ref = None
    if x_signer == production_signer:
        require(assembly["source_difference_proof"] is None and
                x_stage["marker"] == arm_stage(acustom)[0]["marker"],
                "Same-signer targets must not carry a source-difference proof")
        source_policy = "same-production-signer-and-stage"
    else:
        require(assembly["source_difference_proof"] is not None,
                "Different x86/ARM signers require an exhaustive source-difference proof")
        proof, proof_ref, _proof_path = load_json_ref(
            root, assembly["source_difference_proof"], "source-difference proof")
        expected_proof = expected_source_proof(
            xcustom, xrefs["custom_receipt"], acustom, arefs["custom_receipt"])
        require(proof == expected_proof,
                "Source-difference proof is not exact for the authenticated x86/ARM receipts")
        source_policy = "x86-development-signer-only-difference-proved"

    refs.update({
        "x86_baseline_receipt": xrefs["baseline_receipt"],
        "x86_custom_receipt": xrefs["custom_receipt"],
        "x86_comparison": xrefs["comparison"], "runtime_result": xrefs["runtime_result"],
        "runtime_admission": runtime_binding["admission"],
        "runtime_inputs": runtime_binding["inputs"],
        "runtime_qualification": runtime_binding["qualification"],
        "runtime_evidence_index": runtime_binding["evidence_index"],
        "arm_baseline_receipt": arefs["baseline_receipt"],
        "arm_custom_receipt": arefs["custom_receipt"],
        "arm_comparison": arefs["comparison"],
        "release_pair": release_refs["release_pair_receipt"],
        "avb_public_key": release_refs["avb_public_key"],
        "ota_certificate": release_refs["ota_certificate"],
        "factory_public_key": release_refs["factory_public_key"],
        "trusted_otatools_manifest": release_refs["trusted_otatools_manifest"],
        "client_record": crefs["record"],
        "client_source_receipt": crefs["source_receipt"],
        "conformance_apk": crefs["conformance_apk"],
        "signer_certificate": crefs["signer_certificate"],
        "apksigner": crefs["apksigner"],
    })

    # Fresh API and Recents requirements are separate, non-runtime-qualified
    # guests on the exact runtime candidate ancestry.  Their independent
    # auditors replay raw guest/consent/container evidence and this aggregate
    # additionally prevents reuse of any API, Recents or campaign identity.
    conformance_summary, conformance_refs = validate_conformance_acceptance(
        root, assembly["conformance_acceptance"], xrefs, xcustom, x_signer,
        runtime_binding, client_value)
    refs.update(conformance_refs)

    # Broader coverage must replay reviewed isolated native producers, not
    # arbitrary commands or hand-written JUnit claims. The concrete Android
    # suites additionally replay their exact reviewed Atest comparison.
    upstream, upstream_ref, _ = load_json_ref(
        root, assembly["upstream_regression"], "upstream regression record")
    refs["upstream_regression"] = upstream_ref
    upstream_summary = validate_upstream(
        root, upstream, shared_source,
        expected_builds={role: xrefs[role + "_receipt"] for role in ("baseline", "custom")},
        expected_source_pin_sha256=canonical_digest(xcustom["source"]["pin"]))

    upstream_paths, upstream_refs = {}, {}
    for name, assembly_name in (("plan", "upstream_test_plan"),
                                ("baseline", "upstream_baseline_run"),
                                ("custom", "upstream_custom_run")):
        relative = assembly[assembly_name]
        upstream_paths[name] = confined(root, relative, "upstream " + name)
        upstream_refs[name] = file_ref(root, relative, "upstream " + name)
    # Generic host evidence and the exact Android Atest comparison are
    # independent inputs; neither can stand in for the other.
    atest_relative = assembly["upstream_atest_comparison"]
    upstream_paths["comparison"] = confined(root, atest_relative,
                                              "upstream Atest comparison")
    upstream_refs["comparison"] = file_ref(root, atest_relative,
                                            "upstream Atest comparison")
    plan_value, _ = load_json_path(upstream_paths["plan"], "reviewed upstream test plan")
    current_plan_value, current_plan_raw = load_json_path(UPSTREAM_PLAN, "repository upstream test plan")
    verifier_call("upstream test plan", upstream_tests.validate_plan, plan_value)
    require(plan_value == current_plan_value and
            upstream_refs["plan"]["sha256"] == current_plan_raw["sha256"] and
            plan_value.get("release") == RELEASE,
            "Selected upstream test plan differs from the reviewed release plan")
    atest_comparison = verifier_call(
        "upstream Atest comparison", upstream_tests.verify_comparison,
        upstream_paths["comparison"], upstream_refs["comparison"]["sha256"],
        upstream_paths["baseline"], upstream_refs["baseline"]["sha256"],
        upstream_paths["custom"], upstream_refs["custom"]["sha256"],
        xpaths["comparison"], xrefs["comparison"]["sha256"])
    atest_baseline = verifier_call(
        "upstream baseline run", upstream_tests.authenticated_run,
        upstream_paths["baseline"], upstream_refs["baseline"]["sha256"])
    atest_custom = verifier_call(
        "upstream custom run", upstream_tests.authenticated_run,
        upstream_paths["custom"], upstream_refs["custom"]["sha256"])
    for name, run, expected in (("baseline", atest_baseline, xrefs["baseline_receipt"]),
                                ("custom", atest_custom, xrefs["custom_receipt"])):
        build_ref = run.get("build", {}).get("receipt", {})
        require((build_ref.get("sha256"), build_ref.get("size")) ==
                (expected["sha256"], expected["size"]),
                f"Upstream {name} run selects a different x86 build receipt")
        require(run.get("plan") == plan_value and run.get("plan_sha256") == canonical_digest(plan_value),
                f"Upstream {name} run selects a different reviewed test plan")
    require(atest_comparison.get("architecture") == "x86_64" and
            atest_comparison.get("status") == "passed" and
            atest_comparison.get("new_or_worsened_failures") == [] and
            atest_comparison.get("source_pin_sha256") ==
                canonical_digest(xcustom["source"]["pin"]),
            "Upstream Atest evidence is not a same-pin passing x86 comparison")
    refs.update({
        "upstream_atest_comparison": upstream_refs["comparison"],
        "upstream_test_plan": upstream_refs["plan"],
        "upstream_baseline_run": upstream_refs["baseline"],
        "upstream_custom_run": upstream_refs["custom"],
    })

    # A real public signing ceremony and concrete candidate-channel operations
    # are release inputs, not claims inferred from the presence of signatures.
    ceremony, ceremony_ref, _ = load_json_ref(
        root, assembly["signing_ceremony"], "signing ceremony record")
    ceremony_summary = validate_signing_ceremony(
        root, ceremony, shared_source, pair_bound, production_signer,
        release_refs, crefs["signer_certificate"])
    refs["signing_ceremony"] = ceremony_ref
    refs["signing_policy"] = ceremony_summary["policy"]
    operations, operations_ref, _ = load_json_ref(
        root, assembly["production_operations"], "production operations record")
    operations_summary = validate_operations(
        root, operations, shared_source, pair_bound, arm_stage(acustom)[0]["updater"],
        ceremony_ref)
    refs["production_operations"] = operations_ref
    refs["operations_runbook"] = operations_summary["runbook"]

    defects, defects_ref, _ = load_json_ref(root, assembly["defects"], "defect register")
    refs["defects"] = defects_ref
    defect_summary = validate_defects(root, defects)

    expected_review_bindings = review_bindings(
        refs, sdk_ref["files_sha256"], proof_ref)
    review, review_ref, _ = load_json_ref(root, assembly["review"], "final OS-glue review")
    review_summary = validate_review(
        root, review, expected_review_bindings, defect_summary["ids"])

    # Cross-check clean/custom roles, targets and the signed-release verifier
    # summary only after all semantic verifiers have succeeded.
    require(xbaseline.get("role") == "baseline" and xcustom.get("role") == "custom" and
            abaseline.get("role") == "baseline" and acustom.get("role") == "custom" and
            xcustom.get("build_contract", {}).get("target_arch") == "x86_64" and
            acustom.get("contract", {}).get("abi") == "arm64-v8a" and
            pair_evidence.get("status") == "verified" and pair_evidence.get("target") == "frankel-user",
            "Build roles, target architectures or signed-release result changed")
    require(tool_ledger() == tools,
            "Aggregate semantic-verifier bytes changed during evidence collection")
    require(stable_ref(ROOT / "android/grapheneos.lock.json",
                       "android/grapheneos.lock.json", reject_private=False) == current_lock and
            stable_ref(ROOT / "android/EXTERNAL-SHELL.md",
                       "android/EXTERNAL-SHELL.md", reject_private=False) == current_contract,
            "Reviewed lock or API contract changed during evidence collection")

    # Preserve every original 23-gate/product-campaign, API/Recents, signing,
    # source, review and publication-edge check above. Even an entirely passing
    # historical product fixture must not reach the Phase-1 PASS below. verify
    # also calls collect, so an old/relabelled authenticated index cannot bypass
    # this transition. This is an explicit blocker, not a scope reduction.
    require_policy_free_runtime_exit_admission()

    evidence = {
        "grapheneos_lock": refs["grapheneos_lock"],
        "api_contract": refs["api_contract"],
        "x86": {
            "baseline_receipt": xrefs["baseline_receipt"],
            "custom_receipt": xrefs["custom_receipt"],
            "comparison": xrefs["comparison"],
            "runtime_result": xrefs["runtime_result"],
            "runtime": {**runtime_summary, **runtime_binding},
        },
        "arm": {
            "baseline_receipt": arefs["baseline_receipt"],
            "custom_receipt": arefs["custom_receipt"],
            "comparison": arefs["comparison"],
            "release_pair_receipt": release_refs["release_pair_receipt"],
            "public_verification_inputs": {
                name: release_refs[name] for name in
                ("avb_public_key", "ota_certificate", "factory_public_key",
                 "trusted_otatools_manifest")
            },
            "release_verification": pair_evidence,
            "signed_source_binding": signed_source_binding,
        },
        "clients": {
            "record": crefs["record"],
            "source_receipt": crefs["source_receipt"],
            "conformance_apk": crefs["conformance_apk"],
            "signer_certificate": crefs["signer_certificate"],
            "apksigner": crefs["apksigner"],
            "sdk_publication": sdk_ref,
            "coordinate": SDK_COORDINATE,
            "production_signer_sha256": production_signer,
        },
        "source_difference_proof": proof_ref,
        "conformance_acceptance": conformance_summary,
        "upstream_regression": {"record": upstream_ref, **upstream_summary},
        "upstream_atest": {
            "plan": upstream_refs["plan"],
            "baseline_run": upstream_refs["baseline"],
            "custom_run": upstream_refs["custom"],
            "comparison": upstream_refs["comparison"],
            "architecture": atest_comparison["architecture"],
            "suite_count": len(atest_comparison["suites"]),
            "status": atest_comparison["status"],
        },
        "signing_ceremony": {"record": ceremony_ref, **ceremony_summary},
        "production_operations": {"record": operations_ref, **operations_summary},
        "review": {"record": review_ref, **review_summary},
        "defects": {"record": defects_ref, **defect_summary},
    }
    return {
        "schema": SCHEMA,
        "kind": KIND,
        "qualification": QUALIFICATION,
        "assembly": assembly_ref,
        "tools": tools,
        "freeze": {
            "release": RELEASE,
            "product": PRODUCT,
            "api_version": API,
            "sdk_coordinate": SDK_COORDINATE,
            "shared_source": shared_source,
            "source_policy": source_policy,
            "x86_development_signer_sha256": x_signer,
            "arm_production_signer_sha256": production_signer,
            "candidate_image": runtime_summary["candidate_image"],
        },
        "evidence": evidence,
        "exit_gate": {
            "all_semantic_verifiers_replayed": True,
            "zero_known_critical_high_defects": True,
            "accepted_defects": defect_summary["accepted"],
            "result": "passed_phase1_flashable_candidate_evidence_freeze",
        },
    }


def atomic_new(path: Path, value):
    require(path.is_absolute() and path.parent.is_dir() and not path.parent.is_symlink() and
            path.parent.resolve(strict=True) == path.parent and
            not os.path.lexists(path), "Index output must be a fresh absolute path")
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    require(0 < len(payload) <= MAX_JSON, "Index output has an invalid size")
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                        getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    directory_identity = None
    descriptor = None
    temporary = None
    owned_identity = None

    def verify_parent():
        observed = path.parent.lstat()
        require(stat.S_ISDIR(observed.st_mode) and
                (observed.st_dev, observed.st_ino) ==
                (directory_identity.st_dev, directory_identity.st_ino) and
                path.parent.resolve(strict=True) == path.parent,
                "Index output parent changed during publication")

    try:
        directory_identity = os.fstat(directory)
        verify_parent()
        temporary = f".{path.name}.pending-{secrets.token_hex(16)}"
        flags = (os.O_RDWR | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(temporary, flags, 0o644, dir_fd=directory)
        owned = os.fstat(descriptor)
        owned_identity = (owned.st_dev, owned.st_ino)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            require(stream.write(payload) == len(payload),
                    "Incomplete index write before publication")
            stream.flush()
            os.fsync(stream.fileno())
        written = os.fstat(descriptor)
        require(written.st_size == len(payload), "Incomplete index file before publication")
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        size = 0
        while block := os.read(descriptor, 1024 * 1024):
            size += len(block)
            require(size <= len(payload), "Index temporary grew before publication")
            digest.update(block)
        require(size == len(payload) and digest.hexdigest() == hashlib.sha256(payload).hexdigest() and
                stat_identity(written) == stat_identity(os.fstat(descriptor)) and
                stat_identity(written) == stat_identity(
                    os.stat(temporary, dir_fd=directory, follow_symlinks=False)),
                "Index temporary bytes or identity changed before publication")
        verify_parent()
        # A same-directory hard link publishes the complete, file-fsynced
        # inode atomically without overwriting a concurrently created output.
        # Never stream into the final path or use an overwriting rename.
        os.link(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory,
                follow_symlinks=False)
        os.unlink(temporary, dir_fd=directory)
        temporary = None
        os.fsync(directory)
        verify_parent()
        before = path.lstat()
        require((before.st_dev, before.st_ino) == owned_identity,
                "Published index was replaced during publication")
        observed, _reference = stable_bytes(path)
        require(observed == payload and stat_identity(before) == stat_identity(path.lstat()) and
                stat_identity(before) == stat_identity(os.fstat(descriptor)),
                "Published index bytes or identity changed during publication")
        verify_parent()
    finally:
        if temporary is not None and descriptor is not None:
            try:
                # Retry a transient ownership-observation failure while the
                # exclusively created inode is still held open. If ownership
                # remains unobservable, preserve the temporary rather than
                # guessing about another directory entry.
                if owned_identity is None:
                    owned = os.fstat(descriptor)
                    owned_identity = (owned.st_dev, owned.st_ino)
                remaining = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
                if (remaining.st_dev, remaining.st_ino) == owned_identity:
                    os.unlink(temporary, dir_fd=directory)
            except OSError:
                pass
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)
        # Once linked, the final record is complete. Even a durability or
        # verification failure must not delete it or a competing replacement.
    return hashlib.sha256(payload).hexdigest()


def create(root: Path, assembly: Path, output: Path):
    root = canonical_root(root)
    require(output.parent == root and output.name == "phase1-release-index.json",
            "Aggregate index must be the canonical direct child phase1-release-index.json")
    result = collect(root, assembly)
    # Every semantic verifier closes races over its own inputs.  Reopen the
    # assembly once at the publication edge; later byte changes are rejected by
    # the authenticated index and a full replay during ``verify``.
    _assembly, final_assembly_ref = load_json_path(assembly, "Phase-1 assembly")
    require(result["assembly"] == {"path": assembly.name, **final_assembly_ref},
            "Phase-1 assembly changed during aggregate collection")
    return result, atomic_new(output, result)


def verify(root: Path, index_path: Path, expected_sha256: str):
    root = canonical_root(root)
    require(SHA256.fullmatch(str(expected_sha256 or "")),
            "An exact lowercase out-of-band index SHA-256 is required")
    require(index_path.is_absolute() and index_path.parent == root and
            index_path.name == "phase1-release-index.json" and not index_path.is_symlink(),
            "Index must retain its canonical evidence-root path")
    value, reference = load_json_path(index_path, "Phase-1 release index")
    require(reference["sha256"] == expected_sha256,
            "Phase-1 index differs from its out-of-band SHA-256")
    exact_keys(value, {"schema", "kind", "qualification", "assembly", "tools", "freeze",
                       "evidence", "exit_gate"}, "Phase-1 release index")
    require(value.get("schema") == SCHEMA and value.get("kind") == KIND and
            value.get("qualification") == QUALIFICATION,
            "Unsupported Phase-1 release index")
    assembly_ref = value.get("assembly")
    validate_embedded_ref(root, assembly_ref, "assembly")
    expected = collect(root, confined(root, assembly_ref["path"], "assembly"))
    require(value == expected, "Phase-1 index is not the exact semantic result for its evidence")
    _payload, final_reference = stable_bytes(index_path)
    require(final_reference == reference, "Phase-1 index changed during verification")
    return value


def create_source_proof(x86_path: Path, x86_sha256: str, arm_path: Path,
                        arm_sha256: str, output: Path):
    require(SHA256.fullmatch(str(x86_sha256 or "")) and SHA256.fullmatch(str(arm_sha256 or "")),
            "Both custom receipt SHA-256 anchors are required")
    require(x86_path.is_absolute() and arm_path.is_absolute() and
            x86_path.resolve(strict=True) == x86_path and arm_path.resolve(strict=True) == arm_path and
            not x86_path.is_symlink() and not arm_path.is_symlink(),
            "Source proof receipts must be canonical absolute ordinary files")
    xreceipt = verifier_call("x86 custom receipt", x86.verify, x86_path, x86_sha256)
    areceipt = verifier_call("ARM custom receipt", frankel.verify, arm_path, arm_sha256)
    require(xreceipt.get("role") == areceipt.get("role") == "custom",
            "Source proof requires two custom build receipts")
    xobserved = stable_ref(x86_path, x86_path.name)
    aobserved = stable_ref(arm_path, arm_path.name)
    require(xobserved["sha256"] == x86_sha256 and aobserved["sha256"] == arm_sha256,
            "Source proof receipts changed after semantic verification")
    xref = {"sha256": x86_sha256, "size": xobserved["size"]}
    aref = {"sha256": arm_sha256, "size": aobserved["size"]}
    value = expected_source_proof(xreceipt, xref, areceipt, aref)
    return value, atomic_new(output, value)


def create_upstream_record(root: Path, selection_path: Path, output: Path):
    """Seal only a fully replayed native-evidence selection, not claimed results."""
    root = canonical_root(root)
    require(selection_path.is_absolute() and selection_path.is_relative_to(root) and
            output.is_absolute() and output.is_relative_to(root),
            "Upstream selection and output must be inside the canonical evidence root")
    selection, selection_ref, _ = load_json_ref(
        root, selection_path.relative_to(root).as_posix(), "native upstream selection")
    exact_keys(selection, {"schema", "kind", "plan", "builds", "runs"},
               "native upstream selection")
    require(selection["schema"] == SCHEMA and selection["kind"] == UPSTREAM_INPUTS_KIND,
            "Unsupported native upstream selection")
    exact_keys(selection["builds"], {"baseline", "custom"}, "selected upstream builds")
    builds = {}
    for role in ("baseline", "custom"):
        reference = validate_embedded_ref(root, selection["builds"][role],
                                          "selected upstream " + role + " build")
        path = confined(root, reference["path"], "selected upstream " + role + " build")
        builds[role], _ = verifier_call(
            "selected upstream " + role + " build",
            generic_upstream.isolated_atest.full_build_verify, path, reference["sha256"], role)
    require(builds["baseline"]["source"]["pin"] == builds["custom"]["source"]["pin"],
            "Native upstream selection uses different source pins")
    value = {"schema": UPSTREAM_SCHEMA, "kind": UPSTREAM_KIND,
             "qualification": QUALIFICATION, "source": source_identity(builds["custom"]),
             "plan": selection["plan"], "runs": selection["runs"],
             "result": "passed_no_new_or_worsened_native_failures"}
    validate_upstream(root, value, value["source"], expected_builds=selection["builds"],
                      expected_source_pin_sha256=canonical_digest(builds["custom"]["source"]["pin"]))
    # Reopen every selected anchor after the native verifiers close their own
    # source/result races and before writing the non-overwriting record.
    require(file_ref(root, selection_ref["path"]) == selection_ref,
            "Native upstream selection changed during verification")
    for role, reference in selection["builds"].items():
        validate_embedded_ref(root, reference, "selected upstream " + role + " build")
    validate_embedded_ref(root, value["plan"], "generic upstream plan")
    for row in value["runs"]:
        for role in ("baseline", "custom"):
            validate_embedded_ref(root, row[role], "native upstream " + row["class"] + "/" + role)
    return value, atomic_new(output, value)


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    actions = result.add_subparsers(dest="action", required=True)
    proof = actions.add_parser("create-source-proof",
                               help="seal the exhaustive x86-development/ARM-production source delta")
    proof.add_argument("--x86-custom-receipt", type=Path, required=True)
    proof.add_argument("--x86-custom-sha256", required=True)
    proof.add_argument("--arm-custom-receipt", type=Path, required=True)
    proof.add_argument("--arm-custom-sha256", required=True)
    proof.add_argument("--output", type=Path, required=True)
    upstream_action = actions.add_parser("create-upstream-record",
                                        help="seal an authenticated native upstream selection")
    upstream_action.add_argument("--evidence-root", type=Path, required=True)
    upstream_action.add_argument("--selection", type=Path, required=True)
    upstream_action.add_argument("--output", type=Path, required=True)
    create_action = actions.add_parser("create", help="create the final aggregate index")
    create_action.add_argument("--evidence-root", type=Path, required=True)
    create_action.add_argument("--assembly", type=Path, required=True)
    create_action.add_argument("--output", type=Path, required=True)
    verify_action = actions.add_parser("verify", help="offline-replay and verify the aggregate index")
    verify_action.add_argument("--evidence-root", type=Path, required=True)
    verify_action.add_argument("--index", type=Path, required=True)
    verify_action.add_argument("--expected-sha256", required=True)
    return result


def main(argv=None):
    arguments = parser().parse_args(argv)
    try:
        if arguments.action == "create-source-proof":
            _value, digest = create_source_proof(
                arguments.x86_custom_receipt, arguments.x86_custom_sha256,
                arguments.arm_custom_receipt, arguments.arm_custom_sha256, arguments.output)
            print(digest)
        elif arguments.action == "create-upstream-record":
            _value, digest = create_upstream_record(
                arguments.evidence_root, arguments.selection, arguments.output)
            print(digest)
        elif arguments.action == "create":
            _value, digest = create(arguments.evidence_root, arguments.assembly, arguments.output)
            print(digest)
        else:
            value = verify(arguments.evidence_root, arguments.index, arguments.expected_sha256)
            print(json.dumps({"status": "verified", "kind": value["kind"],
                              "candidate_image": value["freeze"]["candidate_image"]}, sort_keys=True))
        return 0
    except (IndexError, OSError, KeyError, TypeError, AttributeError) as error:
        print("phase1_release_index.py: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
