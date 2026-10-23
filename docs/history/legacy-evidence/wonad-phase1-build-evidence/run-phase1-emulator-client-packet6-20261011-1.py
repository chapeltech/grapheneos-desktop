#!/usr/bin/env python3
"""Prepared exact packet6 build launch; execution requires explicit approval.

This external launcher does not contain signing material and does not create an
output in its default mode.  The eventual caller must provide the independently
published successor17 build-receipt digest and must opt in with --execute.
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
SUCCESSOR = ROOT / "android/out/native-current-successor-12-phase1-v3-runtime-20261011-17"
OUTPUT = ROOT / "android/out/phase1-emulator-client-packet-20261011-6"
SIGNER = Path("/u/elric/.local/state/wonad/phase1-emulator-signer")
PUBLIC_CERT = Path(
    "/u/elric/.local/state/wonad/phase1-emulator-public/"
    "wonad-phase1-emulator.x509.pem"
)
PLATFORM_ROOT = Path("/u/elric/tree/wonad-grapheneos-2026100600")
TOOLS_IMAGE = "sha256:f7ad3758f4913b44b320c252dfb1a6590aa34f6252a671b0db56fda3263889e1"
TOOLS_MANIFEST = ROOT / "android/out/phase1-client-tools-image-20261011-3/manifest.json"
TOOLS_MANIFEST_SHA256 = "3ac8bdf7330f8c0b9d8dbedfc97d9b58d9eaa295a2c91d9ad18f9fbcfa2b1dd6"
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


def preflight(expected_successor_receipt_sha256):
    require(SHA256.fullmatch(expected_successor_receipt_sha256) is not None,
            "An out-of-band successor17 build-receipt SHA-256 is required")
    require(os.getuid() == os.getgid() == 1000, "Run the packet lane as owned UID/GID 1000")
    literal(PYTHON, False)
    literal(BUILDER, False)
    literal(SUCCESSOR, True)
    literal(SIGNER, True)
    literal(PUBLIC_CERT, False)
    literal(PLATFORM_ROOT, True)
    literal(TOOLS_MANIFEST, False)
    require(not OUTPUT.exists() and not OUTPUT.is_symlink(),
            "Packet6 output is not fresh: " + str(OUTPUT))
    require(digest(BUILDER) == BUILDER_SHA256, "Packet builder differs from packet5 provenance")
    require(digest(TOOLS_MANIFEST) == TOOLS_MANIFEST_SHA256,
            "Client-tools manifest differs from packet5 provenance")
    manifest = json.loads(TOOLS_MANIFEST.read_bytes())
    require(manifest.get("image_id") == TOOLS_IMAGE,
            "Client-tools manifest names another immutable image")
    for name in SUCCESSOR_FILES:
        literal(SUCCESSOR / name, False)
    observed = digest(SUCCESSOR / "build-receipt.json")
    require(observed == expected_successor_receipt_sha256,
            "Successor17 build receipt differs from the out-of-band digest")
    return {
        "status": "prepared_not_executed",
        "successor_build_receipt_sha256": observed,
        "packet5_provenance": {
            "builder_sha256": BUILDER_SHA256,
            "tools_image": TOOLS_IMAGE,
            "tools_manifest_sha256": TOOLS_MANIFEST_SHA256,
        },
        "command": command(),
        "output": str(OUTPUT),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-successor-receipt-sha256", required=True)
    parser.add_argument("--execute", action="store_true",
                        help="Execute only after explicit packet BUILD GO")
    args = parser.parse_args()
    record = preflight(args.expected_successor_receipt_sha256)
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
