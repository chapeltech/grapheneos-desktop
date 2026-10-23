"""Expected-failing probes for proposed SDK contract-member evidence."""

from __future__ import annotations

import copy
import sys
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
TREE = HERE / "corrected"
sys.path.insert(0, str(TREE / "android/tools"))

import native_current_compile_acceptance as native  # noqa: E402
import phase1_provenance as provenance  # noqa: E402


SIGNATURE = "db6ac649c34d8c25ab0bdd4a46802639deb3972d376070c6c3cdd811d7962fff"


def members(digest="a" * 64):
    return {
        "API-v3.md": {"sha256": digest, "bytes": 17997, "mode": 0o644},
        "desktop-sdk-contract-v3.json": {
            "sha256": "b" * 64, "bytes": 54466, "mode": 0o644},
        "verify-desktop-sdk-contract.py": {
            "sha256": "c" * 64, "bytes": 31287, "mode": 0o755},
    }


def client_record(digest="a" * 64):
    signer = "d" * 64
    reference = {"sha256": "e" * 64, "size": 1}
    return {
        "schema": provenance.CLIENT_SCHEMA,
        "kind": "wonad-phase1-client-provenance",
        "qualification": "production",
        "coordinate": "org.wonad:desktop-sdk:3.0.1",
        "sdk_publication": {
            "verification": {
                "coordinate": "org.wonad:desktop-sdk:3.0.1",
                "contract_signature": SIGNATURE,
                "contract_members": members(digest),
            },
            "files": {"publication.bin": {**reference, "mode": 0o644}},
        },
        "conformance": {
            "package": "org.wonad.desktop",
            "apk": reference,
            "unsigned_apk": reference,
            "signing": {
                "certificate_sha256": signer,
                "lineage_certificate_sha256": [],
                "schemes": {"2": True},
                "signers": 1,
            },
            "payload_sha256": "f" * 64,
        },
        "public_signer": {"file": reference, "der_sha256": signer},
        "source_receipt": reference,
        "source_freeze": {
            "files": {}, "files_sha256": provenance.canonical_digest({})},
        "tools": {
            "generator": {}, "sdk_verifier": {}, "apksigner": {},
            "host_tools": provenance.expected_host_tool_ledger(),
        },
    }


class ContractMemberBindingGaps(unittest.TestCase):
    def test_native_member_digest_must_be_derived_from_sealed_publication(self):
        relative = "org/wonad/desktop-sdk/3.0.1/desktop-sdk-3.0.1-contract.zip"
        row = {"sha256": "0" * 64, "bytes": 1}
        publication = {
            "result": {
                "coordinate": "org.wonad:desktop-sdk:3.0.1",
                "reproducible": None,
                "contract_members": members(),
            },
            "files": {relative: row},
        }
        expected = {"sdk-repository/" + relative: row}
        native.publication_binding(publication, expected)
        forged = copy.deepcopy(publication)
        forged["result"]["contract_members"]["API-v3.md"]["sha256"] = "9" * 64
        with self.assertRaisesRegex(ValueError, "contract-member"):
            native.publication_binding(forged, expected)

    def test_native_member_digest_must_be_a_string(self):
        numeric = int("1" * 64)
        with self.assertRaisesRegex(ValueError, "contract-member"):
            native.sdk_contract_members({"contract_members": members(numeric)})

    def test_client_record_member_digest_must_be_a_string(self):
        numeric = int("1" * 64)
        with self.assertRaisesRegex(provenance.ProvenanceError, "contract-member"):
            provenance.validate_clients_shape(client_record(numeric))


if __name__ == "__main__":
    unittest.main()
