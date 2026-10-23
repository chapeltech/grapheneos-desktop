#!/usr/bin/python3.14
"""Prepare packet8's public-only signature-pair conversion; do not execute yet.

All packet-specific artifact fields deliberately remain PENDING until packet8
is terminal and independently audited. Execution additionally requires the
separate ``--execute-after-root-authorization`` switch. The reviewed converter
copies already-signed public artifacts and proves trusted/wrong APK pairs differ
only in signature material; it never loads, creates, or receives a private key.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re


ROOT = Path("/u/elric/tree/wonad")
PYTHON = Path("/usr/bin/python3.14")
PYTHON_SHA256 = "0d64bd6d66d68dac91cdadafc46e22d4f09f22bdc997aaae870f42865b024a3e"
CONVERTER = ROOT / "android/tools/convert_packet_wrong_signer.py"
CONVERTER_SHA256 = "7d5c94cc5f8819662db7795b4b0b2735d3786c04aca46b90ceb82f8a655454e6"
AUDITOR = ROOT / "android/tools/native_wrong_signer_acceptance.py"
AUDITOR_SHA256 = "48807fff5ba75b81c8bc55a559cc73909fe0a645b36a88f82fd807dde61c20e1"
PACKET_TOOL = ROOT / "android/tools/phase1_emulator_client_packet.py"
PACKET_TOOL_SHA256 = "defd7f981ee6ff4317c57730bfeeaa0ab84f39aa1585b446ed4db92f250a60d2"
PACKET = ROOT / "android/out/phase1-emulator-client-packet-20261012-8"
PACKET_RECEIPT_SHA256 = "PENDING"
OUTPUT = ROOT / "android/out/phase1-wrong-signer-bundle-20261012-8"
SHA256 = re.compile(r"[0-9a-f]{64}")

EXPECTED_FILES = {
    "wonad.apk": ("PENDING", None),
    "version-update/preparation-receipt.json": ("PENDING", None),
    "version-update/candidate.apk": ("PENDING", None),
    "conformance-version-update/preparation-receipt.json": ("PENDING", None),
    "conformance-version-update/candidate.apk": ("PENDING", None),
    "evidence/certificates/wonad.x509.pem": ("PENDING", None),
    "evidence/certificates/fixture.x509.pem": ("PENDING", None),
    "evidence/certificates/platform.x509.pem": ("PENDING", None),
    "evidence/certificates/wrong.x509.pem": ("PENDING", None),
}
EXPECTED_SIGNERS = {
    "wonad_emulator_development": "3183261f28256159ad5e488d8a34854e77f36e14348720daae7f8cae7a8c26ff",
    "ordinary_fixture_development": "fdbf6a6940f8a1059fea942db2272abfb19e39716f544c92962a6e98103c4e88",
    "systemui_platform_development": "c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8",
    "isolated_wrong_development": "61cabf82496f91892ec157dbf842979ff4fb0bf411e2d40636b5b2b98f3dd1fc",
}
EXPECTED_FILE_NAMES = {
    "wonad.apk", "version-update/preparation-receipt.json",
    "version-update/candidate.apk",
    "conformance-version-update/preparation-receipt.json",
    "conformance-version-update/candidate.apk",
    "evidence/certificates/wonad.x509.pem",
    "evidence/certificates/fixture.x509.pem",
    "evidence/certificates/platform.x509.pem",
    "evidence/certificates/wrong.x509.pem",
}


def require(value, message):
    if not value:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key: " + key)
        result[key] = value
    return result


def digest(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), "Missing/symlinked file: " + str(path))
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def exact_file(path: Path, sha256: str, size: int):
    require(SHA256.fullmatch(sha256) is not None and type(size) is int and size > 0,
            "Invalid expected public artifact record")
    require(path.resolve(strict=True) == path and not path.is_symlink(),
            "File is absent or aliased: " + str(path))
    require(path.stat().st_size == size and digest(path) == sha256,
            "File differs from the reviewed packet8 record: " + str(path))


def publication_pins_resolved() -> bool:
    return (SHA256.fullmatch(PACKET_RECEIPT_SHA256) is not None and
            set(EXPECTED_FILES) == EXPECTED_FILE_NAMES and
            all(type(row) is tuple and len(row) == 2 and
                isinstance(row[0], str) and SHA256.fullmatch(row[0]) is not None and
                type(row[1]) is int and row[1] > 0
                for row in EXPECTED_FILES.values()) and
            set(EXPECTED_SIGNERS) == {
                "wonad_emulator_development", "ordinary_fixture_development",
                "systemui_platform_development", "isolated_wrong_development"} and
            all(SHA256.fullmatch(value) is not None for value in EXPECTED_SIGNERS.values()))


def command():
    return [
        str(PYTHON), "-B", str(CONVERTER),
        "--packet", str(PACKET),
        "--expected-receipt-sha256", PACKET_RECEIPT_SHA256,
        "--output", str(OUTPUT),
    ]


def preflight():
    require(publication_pins_resolved(),
            "NOT READY: packet8 receipt/artifact publication pins remain PENDING")
    require(os.getuid() == os.getgid() == 1000, "Run as the reviewed UID/GID 1000")
    exact_file(PYTHON, PYTHON_SHA256, PYTHON.stat().st_size)
    exact_file(CONVERTER, CONVERTER_SHA256, CONVERTER.stat().st_size)
    exact_file(AUDITOR, AUDITOR_SHA256, AUDITOR.stat().st_size)
    exact_file(PACKET_TOOL, PACKET_TOOL_SHA256, PACKET_TOOL.stat().st_size)
    require(PACKET.resolve(strict=True) == PACKET and PACKET.is_dir() and not PACKET.is_symlink(),
            "Packet8 is absent or aliased")
    require(not OUTPUT.exists() and not OUTPUT.is_symlink() and
            OUTPUT.parent.resolve(strict=True) == ROOT / "android/out",
            "Wrong-signer bundle8 output is not a fresh literal android/out child")
    exact_file(PACKET / "receipt.json", PACKET_RECEIPT_SHA256,
               (PACKET / "receipt.json").stat().st_size)
    receipt = json.loads((PACKET / "receipt.json").read_bytes(), object_pairs_hook=unique)
    require(receipt.get("status") == "compile_qualified_development_packet_not_runtime_qualified" and
            receipt.get("runtime_qualified") is False and receipt.get("guests_started") is False,
            "Packet8 qualification disclosure changed")
    for name, (sha256, size) in EXPECTED_FILES.items():
        exact_file(PACKET / name, sha256, size)
        require(receipt.get("files", {}).get(name) == {"sha256": sha256, "bytes": size},
                "Packet8 inventory no longer binds " + name)
    require(receipt["version_update"]["receipt"] == {
                "sha256": EXPECTED_FILES["version-update/preparation-receipt.json"][0],
                "bytes": EXPECTED_FILES["version-update/preparation-receipt.json"][1]},
            "Wonad version-only preparation receipt changed")
    require(receipt["version_update"]["candidate"]["sha256"] ==
            EXPECTED_FILES["version-update/candidate.apk"][0] and
            receipt["version_update"]["candidate"]["bytes"] ==
            EXPECTED_FILES["version-update/candidate.apk"][1],
            "Wonad version-only candidate changed")
    require(receipt["conformance_version_update"]["receipt"] == {
                "sha256": EXPECTED_FILES["conformance-version-update/preparation-receipt.json"][0],
                "bytes": EXPECTED_FILES["conformance-version-update/preparation-receipt.json"][1]},
            "Conformance version-only preparation receipt changed")
    require(receipt["conformance_version_update"]["v2"]["file"] == {
                "sha256": EXPECTED_FILES["conformance-version-update/candidate.apk"][0],
                "bytes": EXPECTED_FILES["conformance-version-update/candidate.apk"][1]},
            "Conformance version-only candidate changed")
    cert_names = {
        "wonad_emulator_development": "wonad.x509.pem",
        "ordinary_fixture_development": "fixture.x509.pem",
        "systemui_platform_development": "platform.x509.pem",
        "isolated_wrong_development": "wrong.x509.pem",
    }
    require(set(receipt["signers"]) == set(EXPECTED_SIGNERS),
            "Packet8 signer class set changed")
    for role, der_sha256 in EXPECTED_SIGNERS.items():
        file_sha256, size = EXPECTED_FILES["evidence/certificates/" + cert_names[role]]
        row = receipt["signers"][role]
        require(row["certificate_der_sha256"] == der_sha256 and
                row["public_certificate"] == {"sha256": file_sha256, "bytes": size} and
                row.get("production") is False,
                "Packet8 public signer record changed: " + role)
    return {
        "status": "prepared_not_executed",
        "packet_receipt_sha256": PACKET_RECEIPT_SHA256,
        "output": str(OUTPUT),
        "command": command(),
        "conversion_semantics": "public_existing_signature_pairs_non_signature_members_must_match",
        "private_keys_consumed": False,
        "runtime_qualified": False,
        "guests_started": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-after-root-authorization", action="store_true")
    args = parser.parse_args(argv)
    record = preflight()
    if not args.execute_after_root_authorization:
        print(json.dumps(record, sort_keys=True, indent=2))
        return 0
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    os.execve(str(PYTHON), command(), environment)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print("ERROR: " + str(error), file=__import__("sys").stderr)
        raise SystemExit(1)
