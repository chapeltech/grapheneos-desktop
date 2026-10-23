#!/usr/bin/env python3
"""Verify the external SDK 3.0.1 integration candidate; never publish it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat


HERE = Path(__file__).resolve().parent
WORKSPACE = Path("/u/elric/tree/wonad")
SHA256 = re.compile(r"[0-9a-f]{64}")
SCOPE = "external_preparatory_candidate_not_applied_not_published_not_qualified"
SIGNATURE = "db6ac649c34d8c25ab0bdd4a46802639deb3972d376070c6c3cdd811d7962fff"
MODES = {
    "API-v3.md": 0o644,
    "desktop-sdk-contract-v3.json": 0o644,
    "verify-desktop-sdk-contract.py": 0o755,
}
PROTOTYPE_FILES = {
    "API-v3.0.1-draft.md": "fec4284c91e9c50d84747ebe2d7546c53852529f855ed04db7b790f132e7ae05",
    "known-publications.json": "c3b19b8600f16ffe09254c2c827e7dfaed2efcd7cd060fc791676ff061db4899",
    "versioned_publication.py": "91032ad26ba922b3e7d86e09912c5f0ac497781bd08ea746bbe8483a7a9e06aa",
    "test_versioned_publication.py": "2139a6829b167dadeafa8917d88ad055c8e01a9ef5c4eceb9deb4ce3cb34c78f",
    "native_picker.rs": "b22bb4ffa4f1ecf12bca0a5b745149faff0dc1876707b2c0e6bb97eb317a04d5",
    "native_picker_boundary_test.rs": "b4933909db95b98e7e49f065fbeb8707fbf5c7ae3b948f1491dd8fc1940c03d1",
}


class CandidateError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CandidateError(message)


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load(path: Path) -> dict[str, object]:
    require(path.is_file() and not path.is_symlink(), f"missing/non-regular JSON: {path}")
    try:
        result = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CandidateError(f"invalid JSON {path}: {error}") from error
    require(type(result) is dict, f"JSON root is not an object: {path}")
    return result


def digest(path: Path) -> tuple[str, int]:
    require(path.is_file() and not path.is_symlink(), f"missing/non-regular input: {path}")
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= 128 * 1024 * 1024,
            f"invalid input type/size: {path}")
    value = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            value.update(block)
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            f"input changed while hashing: {path}")
    return value.hexdigest(), before.st_size


def safe_relative(value: object, label: str) -> Path:
    require(type(value) is str and value and "\\" not in value and "\x00" not in value,
            f"{label} is not a safe relative path")
    assert isinstance(value, str)
    pure = PurePosixPath(value)
    require(not pure.is_absolute() and pure.as_posix() == value and
            all(part not in ("", ".", "..") for part in pure.parts),
            f"{label} is not a canonical relative path")
    return Path(*pure.parts)


def file_tree(root: Path) -> dict[str, tuple[str, int]]:
    require(root.is_dir() and not root.is_symlink(), f"invalid tree root: {root}")
    result: dict[str, tuple[str, int]] = {}
    for base, directories, files in os.walk(root, followlinks=False):
        parent = Path(base)
        require(not any((parent / name).is_symlink() for name in directories),
                f"symlink directory in tree: {root}")
        for name in files:
            path = parent / name
            relative = path.relative_to(root).as_posix()
            require(relative not in result, f"duplicate tree path: {relative}")
            result[relative] = digest(path)
    return dict(sorted(result.items()))


def verify(candidate_root: Path = HERE, workspace: Path = WORKSPACE) -> dict[str, object]:
    candidate_root = candidate_root.resolve(strict=True)
    workspace = workspace.resolve(strict=True)
    plan = load(candidate_root / "integration-map.json")
    require(set(plan) == {
        "schema", "kind", "status", "api_version", "coordinate", "machine_contract",
        "prototype", "canonical_historical_3_0_0", "noncanonical_historical_observation",
        "proposed_3_0_1", "source_snapshots", "bootstrapping", "required_future_results",
    }, "integration-map fields differ")
    require(type(plan["schema"]) is int and plan["schema"] == 1 and
            plan["kind"] == "wonad-sdk-3.0.1-production-integration-candidate-v1" and
            plan["status"] == SCOPE and type(plan["api_version"]) is int and
            plan["api_version"] == 3 and plan["coordinate"] == "org.wonad:desktop-sdk:3.0.1",
            "integration-map identity differs")

    machine = plan["machine_contract"]
    require(type(machine) is dict and machine == {
        "signature_sha256": SIGNATURE,
        "baseline_sha256": "519893e53906548144f5f407de0481f21d6b608f32cf53ffa658f28c1f235e8c",
        "wire_or_jvm_or_numeric_change": False,
    }, "machine contract changed")

    for name, wanted in PROTOTYPE_FILES.items():
        require(digest(candidate_root / "prototype" / name)[0] == wanted,
                f"captured prototype changed: {name}")
    prototype = plan["prototype"]
    require(type(prototype) is dict and prototype["draft"]["sha256"] ==
            PROTOTYPE_FILES["API-v3.0.1-draft.md"] and
            prototype["inventory"]["sha256"] == PROTOTYPE_FILES["known-publications.json"] and
            prototype["verifier"]["sha256"] == PROTOTYPE_FILES["versioned_publication.py"],
            "prototype references differ")

    history = plan["canonical_historical_3_0_0"]
    require(type(history) is dict and history["status"] ==
            "immutable_known_publication_not_replaced" and
            history["coordinate"] == "org.wonad:desktop-sdk:3.0.0" and
            set(history["artifacts"]) == {
                "desktop-sdk-3.0.0.aar", "desktop-sdk-3.0.0-sources.jar",
                "desktop-sdk-3.0.0-contract.zip", "desktop-sdk-3.0.0.pom",
                "desktop-sdk-3.0.0.module"} and
            all(type(row) is dict and set(row) == {"sha256", "bytes"} and
                type(row["sha256"]) is str and SHA256.fullmatch(row["sha256"]) and
                type(row["bytes"]) is int and row["bytes"] > 0
                for row in history["artifacts"].values()),
            "canonical 3.0.0 history differs")
    observation = plan["noncanonical_historical_observation"]
    require(type(observation) is dict and observation["canonical_publication"] is False and
            observation["coordinate_label"] == "org.wonad:desktop-sdk:3.0.0" and
            observation["api_document_member_sha256"] !=
                history["api_document_member"]["sha256"],
            "noncanonical historical distinction is missing")

    proposed = plan["proposed_3_0_1"]
    require(type(proposed) is dict and set(proposed) == {
        "normative_document", "contract_members", "artifacts", "state"},
        "proposed publication fields differ")
    document = proposed["normative_document"]
    document_path = candidate_root / safe_relative(document["path"], "normative document")
    require(digest(document_path) == (document["sha256"], document["bytes"]),
            "normative document bytes differ")
    members = proposed["contract_members"]
    require(type(members) is dict and set(members) == set(MODES),
            "contract-member set differs")
    for name, mode in MODES.items():
        row = members[name]
        require(type(row) is dict and set(row) == {"sha256", "bytes", "mode"} and
                type(row["sha256"]) is str and SHA256.fullmatch(row["sha256"]) and
                type(row["bytes"]) is int and row["bytes"] > 0 and
                type(row["mode"]) is int and row["mode"] == mode,
                f"invalid contract-member identity: {name}")
    require(members["API-v3.md"] == {
        "sha256": document["sha256"], "bytes": document["bytes"], "mode": 0o644},
        "normative document is not the exact contract member")
    require(members["desktop-sdk-contract-v3.json"]["sha256"] == machine["baseline_sha256"] and
            members["verify-desktop-sdk-contract.py"]["sha256"] ==
                "d198bd1c265d6f0269026951e534b34997bfe3f3ab9930825baf38da5016c110",
            "machine contract members differ")
    expected_artifacts = {
        "desktop-sdk-3.0.1.aar", "desktop-sdk-3.0.1-sources.jar",
        "desktop-sdk-3.0.1-contract.zip", "desktop-sdk-3.0.1.pom",
        "desktop-sdk-3.0.1.module",
    }
    require(type(proposed["artifacts"]) is dict and set(proposed["artifacts"]) == expected_artifacts and
            all(row == {"sha256": None, "bytes": None}
                for row in proposed["artifacts"].values()),
            "unpublished 3.0.1 artifact identities must remain unknown")
    require(type(proposed["state"]) is dict and proposed["state"] and
            all(type(value) is bool and value is False for value in proposed["state"].values()),
            "unpublished 3.0.1 state must remain false")

    snapshots = plan["source_snapshots"]
    require(type(snapshots) is dict and set(snapshots) == {
        "modified", "unchanged_machine_and_review_tests",
        "unchanged_downstream_consumers_requiring_fresh_evidence"},
        "source snapshot groups differ")
    for name, row in snapshots["modified"].items():
        relative = safe_relative(name, "modified source")
        require(type(row) is dict and set(row) == {"before", "after"} and
                all(type(value) is str and SHA256.fullmatch(value) for value in row.values()),
                f"invalid modified-source record: {name}")
        current = candidate_root / "current" / relative
        next_file = candidate_root / "proposed" / relative
        live = workspace / relative
        require(digest(current)[0] == row["before"] and digest(live)[0] == row["before"] and
                digest(next_file)[0] == row["after"] and row["before"] != row["after"],
                f"modified-source snapshot/pin differs: {name}")
    for group in ("unchanged_machine_and_review_tests",
                  "unchanged_downstream_consumers_requiring_fresh_evidence"):
        for name, wanted in snapshots[group].items():
            relative = safe_relative(name, f"{group} source")
            require(type(wanted) is str and SHA256.fullmatch(wanted) and
                    digest(workspace / relative)[0] == wanted,
                    f"live unchanged dependency differs: {name}")
            if group == "unchanged_machine_and_review_tests":
                require(digest(candidate_root / "current" / relative)[0] == wanted and
                        digest(candidate_root / "proposed" / relative)[0] == wanted,
                        f"unchanged snapshot differs: {name}")

    current_sdk = file_tree(candidate_root / "current/android/desktop-sdk/src")
    proposed_sdk = file_tree(candidate_root / "proposed/android/desktop-sdk/src")
    live_sdk = file_tree(workspace / "android/desktop-sdk/src")
    require(current_sdk == proposed_sdk == live_sdk and len(live_sdk) == 17,
            "AIDL/Kotlin/manifest source changed in documentation-only candidate")

    text = document_path.read_text(encoding="utf-8")
    required_text = (
        "SDK documentation 3.0.1", "one process-global monotonic clock",
        "`T + 1000` milliseconds", "Attempts strictly before that boundary are rejected",
        "`launcherPage` is synchronous and nullable",
        "`showTransferPicker` is a one-way, fire-and-forget request",
        "API v3 has no exact", "`org.wonad:desktop-sdk:3.0.1`",
    )
    require(all(text.count(value) == 1 for value in required_text) and
            text.count(SIGNATURE) == 1 and "`API_VERSION` is exactly 3" in text,
            "normative 3.0.1 document language differs")

    verifier_text = (candidate_root / "proposed/android/tools/verify_sdk_publication.py").read_text()
    require('VERSION = "3.0.1"' in verifier_text and
            '"contract_members": contract_members' in verifier_text and
            "DOCUMENTATION_REQUIREMENTS" in verifier_text,
            "proposed production verifier lacks versioned document-member binding")
    stage_contract = (workspace / "android/tools/stage_contract.py").read_text()
    require(all(f'"{name}"' in stage_contract for name in (
        "android/tools/verify_sdk_publication.py",
        "android/tools/phase1_provenance.py",
        "android/tools/release_receipt.py")),
        "changed release tools are not all in the stage-tool ledger")

    future = plan["required_future_results"]
    require(type(future) is dict and future and all(value is None for value in future.values()),
            "future publication/build/runtime results must remain unresolved")
    bootstrap = plan["bootstrapping"]
    require(type(bootstrap) is dict and set(bootstrap) == {
        "first_publication", "independent_builds", "promotion",
        "fresh_os_stage_and_rebuild"} and
        all(type(value) is str and value for value in bootstrap.values()),
        "publication bootstrap map differs")
    return {
        "schema": 1,
        "status": SCOPE,
        "modified_source_count": len(snapshots["modified"]),
        "unchanged_sdk_source_count": len(live_sdk),
        "unresolved_artifact_count": len(proposed["artifacts"]),
        "normative_document": {"sha256": document["sha256"], "bytes": document["bytes"]},
        "machine_signature": SIGNATURE,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, default=HERE)
    parser.add_argument("--workspace", type=Path, default=WORKSPACE)
    arguments = parser.parse_args(argv)
    try:
        print(json.dumps(verify(arguments.candidate_root, arguments.workspace),
                         indent=2, sort_keys=True))
        return 0
    except (OSError, CandidateError, KeyError, TypeError, UnicodeError) as error:
        print(f"SDK 3.0.1 integration candidate verification failed: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
