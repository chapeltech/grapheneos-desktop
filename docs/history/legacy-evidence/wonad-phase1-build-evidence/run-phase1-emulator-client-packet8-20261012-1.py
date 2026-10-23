#!/usr/bin/env python3
"""Prepared exact packet8 build launch; execution requires separate root GO.

This external launcher contains no signing material. Root independently checked
the actual successful successor19 receipt. Its exact receipt pin is the first
preflight operation before any filesystem, signer, Docker, builder, or output
observation.  Default mode is read-only.  --execute additionally requires a
separate packet-build authorization.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re


ROOT = Path("/u/elric/tree/wonad")
PYTHON = Path("/usr/bin/python3.14")
BUILDER = ROOT / "android/tools/phase1_emulator_client_packet.py"
BUILDER_SHA256 = "defd7f981ee6ff4317c57730bfeeaa0ab84f39aa1585b446ed4db92f250a60d2"
SUCCESSOR = ROOT / "android/out/native-current-successor-12-phase1-v3-runtime-20261012-19"
OUTPUT = ROOT / "android/out/phase1-emulator-client-packet-20261012-8"
SIGNER = Path("/u/elric/.local/state/wonad/phase1-emulator-signer")
PUBLIC_CERT = Path(
    "/u/elric/.local/state/wonad/phase1-emulator-public/"
    "wonad-phase1-emulator.x509.pem"
)
PUBLIC_CERT_SHA256 = "65e326ada8f623cd6e1852d6fefba8262f445bcd5949966e10361c6d770c70a3"
PLATFORM_ROOT = Path("/u/elric/tree/wonad-grapheneos-2026100600")
TOOLS_IMAGE = "sha256:f7ad3758f4913b44b320c252dfb1a6590aa34f6252a671b0db56fda3263889e1"
TOOLS_MANIFEST = ROOT / "android/out/phase1-client-tools-image-20261011-3/manifest.json"
TOOLS_MANIFEST_SHA256 = "3ac8bdf7330f8c0b9d8dbedfc97d9b58d9eaa295a2c91d9ad18f9fbcfa2b1dd6"
PREVIOUS_PACKET_RECEIPT_SHA256 = (
    "5d5737ebe26048152fccfb4881cd89fb4b583ca2df0cfc84fbe8d023799cc459"
)
EXPECTED_SUCCESSOR_RECEIPT_SHA256 = "d17953b598c16a2913bf315980e8626352945630b1343166b181c33d70bb721a"
SHA256 = re.compile(r"[0-9a-f]{64}")
SUCCESSOR_FILES = (
    "build-receipt.json",
    "source-freeze.json",
    "plan.json",
    "wonad.apk",
    "conformance-unsigned.apk",
)


def require(value, message):
    if not value:
        raise ValueError(message)


def resolved_receipt_pin():
    value = EXPECTED_SUCCESSOR_RECEIPT_SHA256
    require(isinstance(value, str) and SHA256.fullmatch(value) is not None,
            "NOT READY: successor19 build-receipt SHA-256 remains PENDING")
    return value


def digest(path):
    require(path.is_file() and not path.is_symlink(), "Missing/symlinked file: " + str(path))
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def literal(path, directory):
    require(path.is_absolute() and path.resolve(strict=True) == path and not path.is_symlink(),
            "Path is absent or aliased: " + str(path))
    require(path.is_dir() if directory else path.is_file(), "Wrong path type: " + str(path))


def command():
    return [
        str(PYTHON), "-B", str(BUILDER), "build",
        "--successor", str(SUCCESSOR),
        "--output", str(OUTPUT),
        "--signer", str(SIGNER),
        "--public-cert", str(PUBLIC_CERT),
        "--platform-root", str(PLATFORM_ROOT),
        "--tools-image", TOOLS_IMAGE,
        "--tools-image-manifest", str(TOOLS_MANIFEST),
        "--tools-image-manifest-sha256", TOOLS_MANIFEST_SHA256,
    ]


def preflight():
    # This must remain the first operation: an unresolved review pin may not
    # observe or mutate build/signing state and cannot be supplied by an operator.
    expected_successor_receipt_sha256 = resolved_receipt_pin()
    require(os.getuid() == os.getgid() == 1000, "Run the packet lane as owned UID/GID 1000")
    literal(PYTHON, False)
    literal(BUILDER, False)
    literal(SUCCESSOR, True)
    literal(SIGNER, True)
    literal(PUBLIC_CERT, False)
    literal(PLATFORM_ROOT, True)
    literal(TOOLS_MANIFEST, False)
    require(not OUTPUT.exists() and not OUTPUT.is_symlink(),
            "Packet8 output is not fresh: " + str(OUTPUT))
    require(digest(BUILDER) == BUILDER_SHA256,
            "Packet builder differs from packet7 provenance")
    require(digest(PUBLIC_CERT) == PUBLIC_CERT_SHA256,
            "Development public certificate differs from packet7 identity")
    require(digest(TOOLS_MANIFEST) == TOOLS_MANIFEST_SHA256,
            "Client-tools manifest differs from packet7 provenance")
    manifest = json.loads(TOOLS_MANIFEST.read_bytes())
    require(manifest.get("image_id") == TOOLS_IMAGE,
            "Client-tools manifest names another immutable image")
    for name in SUCCESSOR_FILES:
        literal(SUCCESSOR / name, False)
    observed = digest(SUCCESSOR / "build-receipt.json")
    require(observed == expected_successor_receipt_sha256,
            "Successor19 build receipt differs from the reviewed digest")
    return {
        "status": "prepared_not_executed",
        "successor_build_receipt_sha256": observed,
        "packet7_provenance": {
            "receipt_sha256": PREVIOUS_PACKET_RECEIPT_SHA256,
            "builder_sha256": BUILDER_SHA256,
            "tools_image": TOOLS_IMAGE,
            "tools_manifest_sha256": TOOLS_MANIFEST_SHA256,
            "development_public_cert_sha256": PUBLIC_CERT_SHA256,
        },
        "command": command(),
        "output": str(OUTPUT),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true",
                        help="Execute only after a separate packet BUILD GO and reviewed pin edit")
    args = parser.parse_args()
    record = preflight()
    if not args.execute:
        print(json.dumps(record, sort_keys=True, indent=2))
        return 0
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    os.execve(str(PYTHON), command(), environment)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print("ERROR: " + str(error), file=__import__("sys").stderr)
        raise SystemExit(1)
