#!/usr/bin/env python3
"""Strict shared schema for the fresh-guest Phase-1 conformance lane.

This module is deliberately free of Docker and adb calls.  The image builder,
runtime producer and independent auditor all use the same small vocabulary,
while the auditor still reconstructs every result from sealed raw evidence.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re


KIND = "phase1_fresh_guest_conformance_candidate_v1"
SCOPE = "unqualified_phase1_fresh_guest_os_contract_conformance_candidate"
REPORT_KIND = "phase1_fresh_guest_conformance_run_v1"
REPORT_SCOPE = "fresh_guest_exact_custom_x86_full_os_contract_conformance"
SHA256 = re.compile(r"[0-9a-f]{64}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
RUN = re.compile(r"[0-9a-f]{32}")
BOOT_ID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}")

REQUIRED_CAPABILITIES = sum(1 << bit for bit in (3, 5, 6, 7, 8, 9, 10))
OPERATIONS = (
    "getApiVersion", "getCapabilities", "openSession", "applyFrame", "focusTask",
    "closeTask", "enableShortcuts", "heartbeat", "release", "enableExternalUi",
    "showShell", "launcherPage", "showLauncher", "selectLauncher",
    "showTransferPicker", "applySignedFrame",
)
CALLBACKS = ("onSnapshot", "onCommand", "onResult", "onRevoked")
FACADES = ("ExternalHomeActivity:valid", "ExternalShellActivity:valid", "LauncherActivity:valid")
ARTIFACT_ROLES = ("wonad", "conformance", "fixture", "fault")
OS_ARTIFACTS = ("com.android.systemui", "os_broker_native", "os_input_native", "os_services", "os_framework")
PHASE1_BUILD_EVIDENCE_PATHS = frozenset({
    "/opt/wonad/build-evidence/x86-baseline-custom-comparison.json",
    "/opt/wonad/build-evidence/x86-baseline-receipt.json",
    "/opt/wonad/build-evidence/x86-custom-receipt.json",
    "/opt/wonad/build-evidence/client-packet-receipt.json",
})


class ConformanceError(ValueError):
    pass


def require(value, message):
    if not value:
        raise ConformanceError(message)


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def canonical_sha256(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key: " + key)
        result[key] = value
    return result


def load(path: Path):
    require(path.is_file() and not path.is_symlink(), "Missing/symlinked JSON file: " + str(path))
    try:
        return json.loads(path.read_text(), object_pairs_hook=strict_object)
    except json.JSONDecodeError as error:
        raise ConformanceError("Malformed JSON file: " + str(path)) from error


def file_ref(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0,
            "Missing, empty or symlinked file: " + str(path))
    return {"sha256": sha256(path), "bytes": path.stat().st_size}


def exact_int(value, minimum=0):
    return type(value) is int and value >= minimum


def artifact_subset(value, role):
    require(isinstance(value, dict), "Malformed packet artifact: " + role)
    required = {"sha256", "bytes", "package", "version_code", "version_name",
                "certificate_der_sha256", "signers", "schemes", "debuggable",
                "test_only", "instrumentation_targets", "shared_uid", "privileged_manifest"}
    require(required <= set(value), "Incomplete packet artifact: " + role)
    require(SHA256.fullmatch(str(value["sha256"])) is not None and exact_int(value["bytes"], 1) and
            SHA256.fullmatch(str(value["certificate_der_sha256"])) is not None and
            type(value["version_code"]) is int and value["version_code"] > 0 and
            isinstance(value["version_name"], str) and value["version_name"] and
            type(value["signers"]) is int and value["signers"] == 1 and
            isinstance(value["schemes"], dict) and value["schemes"].get("3") is True and
            all(isinstance(name, str) and type(enabled) is bool
                for name, enabled in value["schemes"].items()) and
            type(value["debuggable"]) is bool and type(value["test_only"]) is bool and
            isinstance(value["instrumentation_targets"], list) and
            all(isinstance(item, str) for item in value["instrumentation_targets"]) and
            value["shared_uid"] is False and value["privileged_manifest"] is False,
            "Invalid packet artifact identity: " + role)
    expected = {
        "wonad": ("org.wonad.desktop", False, []),
        "conformance": ("org.wonad.desktop", False, ["org.wonad.desktop"]),
        "fixture": ("org.wonad.fixture", False, []),
        "fault": ("org.wonad.desktop.transitionfault", True, ["com.android.systemui"]),
        "security": ("org.wonad.desktop.test", True, ["org.wonad.desktop"]),
    }[role]
    require((value["package"], value["test_only"], value["instrumentation_targets"]) == expected,
            "Packet artifact role changed: " + role)
    return {key: value[key] for key in sorted(required)}


def validate_manifest(value):
    required = {"schema", "kind", "scope", "architecture", "api", "fingerprint", "files",
        "product_images", "os_artifacts", "base_product_candidate", "packet", "artifacts",
        "conformance_version_update", "update_data_canary",
        "systemui_fault_identity", "planned_runtime_gates", "runtime_qualified", "guests_started",
        "hardware", "unofficial", "production_identity", "product_apk_present"}
    require(isinstance(value, dict) and set(value) == required, "Unexpected conformance candidate manifest fields")
    require(type(value["schema"]) is int and value["schema"] == 1 and value["kind"] == KIND and
            value["scope"] == SCOPE and value["architecture"] == "amd64" and
            type(value["api"]) is int and value["api"] == 3 and isinstance(value["fingerprint"], str) and
            value["fingerprint"].startswith("Android/sdk_phone64_x86_64/emu64x:") and
            value["runtime_qualified"] is False and value["guests_started"] is False and
            value["hardware"] == "emulator_only" and value["unofficial"] is True and
            value["production_identity"] is False and value["product_apk_present"] is False,
            "Conformance candidate qualification disclosure changed")

    files = value["files"]
    require(isinstance(files, dict) and 10 <= len(files) <= 20000 and
            "/opt/wonad/wonad.apk" not in files and
            PHASE1_BUILD_EVIDENCE_PATHS <= set(files),
            "Invalid/current product APK or strict build-evidence inventory")
    for name, digest in files.items():
        path = PurePosixPath(name) if isinstance(name, str) else PurePosixPath(".")
        require(path.is_absolute() and ".." not in path.parts and
                (name.startswith("/product/") or name.startswith("/opt/wonad/")) and
                isinstance(digest, str) and SHA256.fullmatch(digest) is not None,
                "Invalid candidate file inventory")
    products = value["product_images"]
    require(isinstance(products, dict) and products and all(
        isinstance(name, str) and "/" not in name.removeprefix("system/") and
        isinstance(digest, str) and SHA256.fullmatch(digest) is not None
        for name, digest in products.items()), "Invalid candidate product-image identities")
    require(isinstance(value["os_artifacts"], dict) and set(value["os_artifacts"]) == set(OS_ARTIFACTS) and
            all(SHA256.fullmatch(str(item)) for item in value["os_artifacts"].values()),
            "Invalid candidate OS artifact identities")

    base = value["base_product_candidate"]
    require(isinstance(base, dict) and set(base) == {"image_id", "manifest_sha256",
            "phase1_build_evidence_sha256", "scope", "product_apk_sha256"} and
            IMAGE_ID.fullmatch(str(base["image_id"])) and SHA256.fullmatch(str(base["manifest_sha256"])) and
            SHA256.fullmatch(str(base["phase1_build_evidence_sha256"])) and
            base["scope"] == "unqualified_native_v3_exact_bundle_candidate" and
            SHA256.fullmatch(str(base["product_apk_sha256"])), "Invalid base product candidate binding")
    packet = value["packet"]
    require(isinstance(packet, dict) and set(packet) == {"receipt_sha256", "kind", "status"} and
            SHA256.fullmatch(str(packet["receipt_sha256"])) and
            packet["kind"] == "phase1_source_matched_x86_development_client_packet_v1" and
            packet["status"] == "compile_qualified_development_packet_not_runtime_qualified",
            "Invalid client packet binding")
    artifacts = value["artifacts"]
    require(isinstance(artifacts, dict) and set(artifacts) == set(ARTIFACT_ROLES),
            "Wrong candidate APK role set")
    normalized = {role: artifact_subset(artifacts[role], role) for role in ARTIFACT_ROLES}
    require(artifacts == normalized, "Candidate APK records must be exact bounded packet subsets")
    require(artifacts["wonad"]["sha256"] == base["product_apk_sha256"] and
            artifacts["wonad"]["certificate_der_sha256"] == artifacts["conformance"]["certificate_der_sha256"] and
            artifacts["fixture"]["certificate_der_sha256"] != artifacts["conformance"]["certificate_der_sha256"],
            "Product/conformance/fixture signer or byte binding changed")

    update = value["conformance_version_update"]
    require(isinstance(update, dict) and set(update) == {
                "preparation_receipt", "v1", "v2", "unsigned", "version_only"},
            "Malformed conformance version-only candidate binding")
    file_keys = {"bundle_path", "sha256", "bytes"}
    member_keys = file_keys | {"file", "package", "version_code", "version_name",
        "certificate_der_sha256", "normalized_manifest_sha256",
        "non_manifest_payload_sha256"}

    def bundled_file(record, label):
        require(isinstance(record, dict) and file_keys <= set(record) and
                isinstance(record["bundle_path"], str) and
                record["bundle_path"].startswith("/opt/wonad/phase1-conformance/") and
                files.get(record["bundle_path"]) == record["sha256"] and
                SHA256.fullmatch(str(record["sha256"])) is not None and
                exact_int(record["bytes"], 1),
                "Invalid bundled conformance update file: " + label)
        return record

    receipt_record = bundled_file(update["preparation_receipt"], "preparation receipt")
    require(set(receipt_record) == file_keys and receipt_record["bundle_path"] ==
            "/opt/wonad/phase1-conformance/conformance-update/preparation-receipt.json",
            "Conformance update preparation receipt fields changed")
    unsigned = bundled_file(update["unsigned"], "unsigned derivative")
    require(set(unsigned) == file_keys and unsigned["bundle_path"] ==
            "/opt/wonad/phase1-conformance/conformance-update/unsigned-version-only.apk",
            "Conformance update unsigned derivative fields changed")
    for role in ("v1", "v2"):
        member = bundled_file(update[role], role)
        require(set(member) == member_keys and isinstance(member["file"], dict) and
                set(member["file"]) == {"sha256", "bytes"} and
                member["file"] == {"sha256": member["sha256"], "bytes": member["bytes"]} and
                member["package"] == "org.wonad.desktop" and
                member["bundle_path"] == "/opt/wonad/phase1-conformance/conformance-update/" +
                    ("original.apk" if role == "v1" else "candidate.apk") and
                member["certificate_der_sha256"] == artifacts["conformance"]["certificate_der_sha256"] and
                SHA256.fullmatch(str(member["normalized_manifest_sha256"])) is not None and
                SHA256.fullmatch(str(member["non_manifest_payload_sha256"])) is not None,
                "Invalid conformance update APK identity: " + role)
    v1, v2 = update["v1"], update["v2"]
    require(v1["sha256"] == artifacts["conformance"]["sha256"] and
            v1["bytes"] == artifacts["conformance"]["bytes"] and
            v1["version_code"] == artifacts["conformance"]["version_code"] == 1 and
            v1["version_name"] == artifacts["conformance"]["version_name"] and
            v2["version_code"] == 2 and v2["sha256"] != v1["sha256"] and
            all(v1[key] == v2[key] for key in ("package", "version_name",
                "certificate_der_sha256", "normalized_manifest_sha256",
                "non_manifest_payload_sha256")),
            "Candidate does not bind the exact same-package/signer/payload conformance v1/v2 pair")
    require(update["version_only"] == {
        "package": "org.wonad.desktop",
        "version_name": v1["version_name"],
        "certificate_der_sha256": v1["certificate_der_sha256"],
        "original_version_code": 1,
        "candidate_version_code": 2,
        "normalized_manifest_sha256": v1["normalized_manifest_sha256"],
        "non_manifest_payload_sha256": v1["non_manifest_payload_sha256"],
        "permissions_binding": "exact_binary_manifest_equality_except_root_version_code",
    }, "Candidate conformance permission/version-only proof changed")

    canary = value["update_data_canary"]
    require(isinstance(canary, dict) and set(canary) == {
                "runner", "source_sha256", "instrumentation_apk", "compile_receipt",
                "source_freeze", "compiled_files", "tests"} and
            canary["runner"] == ("org.wonad.desktop.test/"
                "org.wonad.desktop.security.UpdateDataInstrumentation") and
            canary["source_sha256"] ==
                "1873f736c689d2fe14e4bd067573b14d8f2c4d09aeeff8303a3d2df7c93243a9" and
            exact_int(canary["compiled_files"], 1) and exact_int(canary["tests"], 1),
            "Malformed compiled update-data canary binding")
    canary_apk = bundled_file(canary["instrumentation_apk"], "update-data instrumentation APK")
    require(set(canary_apk) == set(artifact_subset(canary_apk, "security")) | {"bundle_path"} and
            canary_apk["bundle_path"] ==
                "/opt/wonad/phase1-conformance/update-data-canary/security.apk" and
            {key: canary_apk[key] for key in canary_apk if key != "bundle_path"} ==
                artifact_subset(canary_apk, "security") and
            canary_apk["certificate_der_sha256"] == artifacts["conformance"]["certificate_der_sha256"],
            "Update-data canary APK identity changed")
    for role in ("compile_receipt", "source_freeze"):
        record = bundled_file(canary[role], "update-data " + role)
        require(set(record) == file_keys and record["bundle_path"] ==
                "/opt/wonad/phase1-conformance/update-data-canary/" +
                ("security-build-receipt.json" if role == "compile_receipt" else
                 "security-source-freeze.json"),
                "Update-data evidence fields changed: " + role)
    identity = value["systemui_fault_identity"]
    require(isinstance(identity, dict) and set(identity) == {"systemui_apk_sha256", "systemui_signer_sha256",
            "fault_apk_sha256", "fault_signer_sha256", "signers_match", "runtime_fault_injection"} and
            identity["systemui_apk_sha256"] == value["os_artifacts"]["com.android.systemui"] and
            identity["fault_apk_sha256"] == artifacts["fault"]["sha256"] and
            identity["systemui_signer_sha256"] == identity["fault_signer_sha256"] ==
                artifacts["fault"]["certificate_der_sha256"] and identity["signers_match"] is True and
            identity["runtime_fault_injection"] == "not_run_by_this_lane",
            "Fault harness is not tied to the actual custom SystemUI identity")
    require(value["planned_runtime_gates"] == {
        "fresh_userdata_and_absent_packages": "not_run",
        "ordinary_ui_consent": "not_run",
        "full_v3_operations_callbacks_capabilities_and_facades": "not_run",
        "protected_process_continuity": "not_run",
        "platform_fault_injection": "identity_verified_only_not_run",
    }, "Candidate manifest made an unsupported runtime claim")
    return value


def validate_status(value, run=None, display_id=None):
    required = {"schema", "run", "mode", "state", "phase", "started_elapsed_ms",
                "updated_elapsed_ms", "api_version", "capabilities", "generation", "display_ids",
                "heartbeat_count", "operations", "callbacks", "facades", "failure"}
    require(isinstance(value, dict) and set(value) == required, "Unexpected conformance status fields")
    require(type(value["schema"]) is int and value["schema"] == 1 and RUN.fullmatch(str(value["run"])) and
            (run is None or value["run"] == run) and value["mode"] == "full" and
            value["state"] == "passed" and value["phase"] == "complete" and value["failure"] is None and
            type(value["api_version"]) is int and value["api_version"] == 3 and
            type(value["capabilities"]) is int and value["capabilities"] == REQUIRED_CAPABILITIES and
            exact_int(value["started_elapsed_ms"], 1) and exact_int(value["updated_elapsed_ms"], 1) and
            value["updated_elapsed_ms"] >= value["started_elapsed_ms"] and exact_int(value["generation"], 1) and
            exact_int(value["heartbeat_count"], 1), "Conformance terminal state/API/capability identity failed")
    displays = value["display_ids"]
    require(isinstance(displays, list) and displays and all(type(item) is int and item > 0 for item in displays) and
            displays == sorted(set(displays)) and
            (display_id is None or displays == [display_id]),
            "Conformance display identity failed")
    require(isinstance(value["operations"], list) and len(value["operations"]) == len(set(value["operations"])) and
            set(value["operations"]) == set(OPERATIONS), "Conformance operation coverage is incomplete")
    require(isinstance(value["callbacks"], dict) and set(value["callbacks"]) == set(CALLBACKS) and
            all(type(count) is int and count > 0 for count in value["callbacks"].values()),
            "Conformance callback coverage is incomplete")
    require(isinstance(value["facades"], list) and len(value["facades"]) == len(set(value["facades"])) and
            set(value["facades"]) == set(FACADES), "Conformance facade validation is incomplete")
    return value


def terminal_status_from_log(output: str):
    rows = []
    for line in output.splitlines():
        if not line.startswith("{") or not line.endswith("}"):
            continue
        try:
            value = json.loads(line, object_pairs_hook=strict_object)
        except (json.JSONDecodeError, ConformanceError):
            continue
        if isinstance(value, dict) and value.get("schema") == 1 and "state" in value:
            rows.append(value)
    require(rows, "Conformance log has no complete one-line status observation")
    return rows[-1]
