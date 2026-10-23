#!/usr/bin/env python3
"""Fail-closed prototype for versioned Wonad SDK documentation/publications.

This external prototype adds no publication authority.  It delegates all
archive/wire/ABI/inventory checks to the exact authenticated production
verifier for a known publication, then adds an immutable version/artifact/doc
join.  A draft with unknown artifact hashes is deliberately unverifiable.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import zipfile


SCOPE = "external_preparatory_versioned_sdk_document_and_publication_prototype_not_release_authority"
SIGNATURE = "db6ac649c34d8c25ab0bdd4a46802639deb3972d376070c6c3cdd811d7962fff"
SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_ZIP_ENTRIES = 32
MAX_ZIP_MEMBER_BYTES = 16 * 1024 * 1024
CONTRACT_MEMBERS = {
    "API-v3.md",
    "desktop-sdk-contract-v3.json",
    "verify-desktop-sdk-contract.py",
}


class VerificationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, object]:
    require(path.is_file() and not path.is_symlink(), f"missing/non-regular inventory: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid inventory JSON: {exc}") from exc
    require(type(value) is dict, "inventory root is not an object")
    return value


def exact_keys(value: object, keys: set[str], label: str) -> dict[str, object]:
    require(type(value) is dict, f"{label} is not an object")
    assert isinstance(value, dict)
    require(set(value) == keys, f"{label} keys differ: {sorted(set(value) ^ keys)}")
    return value


def exact_int(value: object, label: str, minimum: int = 0) -> int:
    require(type(value) is int and value >= minimum, f"{label} is not an exact integer >= {minimum}")
    assert isinstance(value, int)
    return value


def exact_bool(value: object, label: str) -> bool:
    require(type(value) is bool, f"{label} is not a boolean")
    assert isinstance(value, bool)
    return value


def exact_sha(value: object, label: str) -> str:
    require(type(value) is str and SHA256.fullmatch(value) is not None,
            f"{label} is not lowercase SHA-256")
    assert isinstance(value, str)
    return value


def safe_relative(value: object, label: str) -> Path:
    require(type(value) is str and value and "\\" not in value and "\x00" not in value,
            f"{label} is not a safe relative path")
    assert isinstance(value, str)
    pure = PurePosixPath(value)
    require(not pure.is_absolute() and all(part not in ("", ".", "..") for part in pure.parts),
            f"{label} is not a safe relative path")
    return Path(*pure.parts)


def file_digest(path: Path) -> tuple[str, int]:
    require(path.is_file() and not path.is_symlink(), f"missing/non-regular file: {path}")
    size = path.stat().st_size
    require(0 <= size <= MAX_FILE_BYTES, f"unbounded file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest(), size


def authenticated_bytes(path: Path, wanted_sha: str, wanted_bytes: int,
                        label: str) -> bytes:
    require(path.is_file() and not path.is_symlink(), f"missing/non-regular {label}: {path}")
    require(0 < wanted_bytes <= MAX_FILE_BYTES, f"invalid expected size for {label}")
    try:
        value = path.read_bytes()
    except OSError as exc:
        raise VerificationError(f"cannot read {label}: {exc}") from exc
    require(len(value) == wanted_bytes and hashlib.sha256(value).hexdigest() == wanted_sha,
            f"authenticated {label} bytes differ")
    return value


def check_file(row: object, path: Path, label: str) -> tuple[str, int]:
    record = exact_keys(row, {"sha256", "bytes"}, label)
    wanted = (exact_sha(record["sha256"], f"{label}.sha256"),
              exact_int(record["bytes"], f"{label}.bytes", 1))
    actual = file_digest(path)
    require(actual == wanted, f"{label} bytes differ: {actual} != {wanted}")
    return actual


def check_path_file(row: object, workspace: Path, label: str) -> tuple[Path, tuple[str, int]]:
    record = exact_keys(row, {"path", "sha256", "bytes"}, label)
    path = workspace / safe_relative(record["path"], f"{label}.path")
    digest = check_file({"sha256": record["sha256"], "bytes": record["bytes"]}, path, label)
    return path, digest


def _safe_zip_members(path: Path) -> dict[str, bytes]:
    require(path.stat().st_size <= MAX_FILE_BYTES, "contract ZIP is oversized")
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise VerificationError(f"invalid contract ZIP: {exc}") from exc
    with archive:
        require(not archive.comment, "contract ZIP has a comment")
        infos = archive.infolist()
        require(len(infos) <= MAX_ZIP_ENTRIES, "too many contract ZIP entries")
        names = [entry.filename for entry in infos]
        require(len(names) == len(set(names)), "duplicate contract ZIP entry")
        require(set(names) == CONTRACT_MEMBERS, "contract ZIP members differ")
        result: dict[str, bytes] = {}
        for entry in infos:
            name = entry.filename
            pure = PurePosixPath(name)
            require(not pure.is_absolute() and len(pure.parts) == 1 and pure.name == name,
                    f"unsafe contract ZIP member: {name!r}")
            mode = (entry.external_attr >> 16) & 0o177777
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG), f"non-regular contract member: {name}")
            require(not (entry.flag_bits & 1), f"encrypted contract member: {name}")
            require(0 < entry.file_size <= MAX_ZIP_MEMBER_BYTES,
                    f"invalid contract member size: {name}")
            try:
                payload = archive.read(entry)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                raise VerificationError(f"unreadable contract member {name}: {exc}") from exc
            require(len(payload) == entry.file_size, f"short contract member: {name}")
            result[name] = payload
        return result


def _artifact_names(version: str) -> set[str]:
    base = f"desktop-sdk-{version}"
    return {
        f"{base}.aar",
        f"{base}-sources.jar",
        f"{base}-contract.zip",
        f"{base}.pom",
        f"{base}.module",
    }


def _validate_artifacts(value: object, version: str, known: bool, label: str) -> dict[str, object]:
    require(type(value) is dict, f"{label} is not an object")
    assert isinstance(value, dict)
    require(set(value) == _artifact_names(version), f"{label} artifact names differ")
    for name, raw in value.items():
        row = exact_keys(raw, {"sha256", "bytes"}, f"{label}.{name}")
        if known:
            exact_sha(row["sha256"], f"{label}.{name}.sha256")
            exact_int(row["bytes"], f"{label}.{name}.bytes", 1)
        else:
            require(row["sha256"] is None and row["bytes"] is None,
                    f"{label}.{name} draft hashes must remain explicitly unknown")
    return value


def validate_inventory(inventory: dict[str, object], evidence_root: Path,
                       workspace: Path, check_files: bool = True) -> None:
    exact_keys(inventory, {
        "schema", "scope", "api_version", "machine_contract", "frozen_inputs",
        "publications", "noncanonical_historical_compile_observations",
    }, "inventory")
    require(exact_int(inventory["schema"], "inventory.schema", 1) == 1, "schema is not 1")
    require(inventory["scope"] == SCOPE, "inventory scope differs")
    require(exact_int(inventory["api_version"], "inventory.api_version", 1) == 3,
            "API version differs")

    machine = exact_keys(inventory["machine_contract"], {
        "signature_sha256", "baseline_sha256", "wire_or_abi_change_in_3_0_1",
    }, "machine_contract")
    require(exact_sha(machine["signature_sha256"], "machine signature") == SIGNATURE,
            "machine signature differs")
    exact_sha(machine["baseline_sha256"], "machine baseline")
    require(exact_bool(machine["wire_or_abi_change_in_3_0_1"], "machine change") is False,
            "3.0.1 must not claim a wire/ABI change")

    frozen = exact_keys(inventory["frozen_inputs"], {
        "reviewed_api_v3_source", "captured_native_picker", "picker_process_owner",
    }, "frozen_inputs")
    reviewed = exact_keys(frozen["reviewed_api_v3_source"], {"path", "sha256", "bytes"},
                          "reviewed_api_v3_source")
    picker = exact_keys(frozen["captured_native_picker"], {
        "workspace_path", "evidence_path", "sha256", "bytes",
    }, "captured_native_picker")
    owner = exact_keys(frozen["picker_process_owner"], {
        "path", "sha256", "bytes", "required_declaration",
    }, "picker_process_owner")
    exact_sha(reviewed["sha256"], "reviewed API SHA")
    exact_int(reviewed["bytes"], "reviewed API bytes", 1)
    picker_sha = exact_sha(picker["sha256"], "picker SHA")
    picker_bytes = exact_int(picker["bytes"], "picker bytes", 1)
    owner_path_relative = safe_relative(owner["path"], "picker owner path")
    owner_sha = exact_sha(owner["sha256"], "picker owner SHA")
    owner_bytes = exact_int(owner["bytes"], "picker owner bytes", 1)
    require(owner["required_declaration"] ==
            "static PICKER: Mutex<Picker> = Mutex::new(Picker::new());",
            "picker process owner declaration differs")
    if check_files:
        check_file({"sha256": reviewed["sha256"], "bytes": reviewed["bytes"]},
                   workspace / safe_relative(reviewed["path"], "reviewed API path"),
                   "reviewed API source")
        for field, root in (("workspace_path", workspace), ("evidence_path", evidence_root)):
            check_file({"sha256": picker_sha, "bytes": picker_bytes},
                       root / safe_relative(picker[field], f"picker {field}"),
                       f"captured picker {field}")
        owner_path = workspace / owner_path_relative
        check_file({"sha256": owner_sha, "bytes": owner_bytes}, owner_path,
                   "picker process owner")
        owner_text = owner_path.read_text(encoding="utf-8")
        require(owner_text.count(owner["required_declaration"]) == 1,
                "picker process owner is not the exact singleton declaration")

    publications = exact_keys(inventory["publications"], {"3.0.0", "3.0.1"}, "publications")
    known = exact_keys(publications["3.0.0"], {
        "status", "coordinate", "repository_path", "source_root_path", "build_receipt",
        "verifier_inputs", "artifacts", "contract_members",
    }, "publication 3.0.0")
    require(known["status"] == "published_immutable_known", "3.0.0 status differs")
    require(known["coordinate"] == "org.wonad:desktop-sdk:3.0.0", "3.0.0 coordinate differs")
    safe_relative(known["repository_path"], "3.0.0 repository")
    safe_relative(known["source_root_path"], "3.0.0 source root")
    build_path, _ = check_path_file(known["build_receipt"], workspace, "3.0.0 build receipt") \
        if check_files else (workspace, ("", 0))
    if check_files:
        require(build_path.name == "build-receipt.json", "unexpected build receipt name")
    verifier_inputs = exact_keys(known["verifier_inputs"], {
        "verify_sdk_publication.py", "sdk_contract.py", "API-v3.md",
        "desktop-sdk-contract-v3.json", "build.gradle.kts",
    }, "3.0.0 verifier inputs")
    for name, row in verifier_inputs.items():
        if check_files:
            check_path_file(row, workspace, f"3.0.0 verifier input {name}")
        else:
            record = exact_keys(row, {"path", "sha256", "bytes"}, f"verifier input {name}")
            safe_relative(record["path"], f"verifier input {name}.path")
            exact_sha(record["sha256"], f"verifier input {name}.sha256")
            exact_int(record["bytes"], f"verifier input {name}.bytes", 1)
    known_artifacts = _validate_artifacts(known["artifacts"], "3.0.0", True,
                                          "publication 3.0.0")
    members = exact_keys(known["contract_members"], CONTRACT_MEMBERS, "3.0.0 contract members")
    for name, row in members.items():
        exact_keys(row, {"sha256", "bytes"}, f"contract member {name}")
        exact_sha(row["sha256"], f"contract member {name}.sha256")
        exact_int(row["bytes"], f"contract member {name}.bytes", 1)

    draft = exact_keys(publications["3.0.1"], {
        "status", "coordinate", "draft", "artifacts", "publication_state",
    }, "publication 3.0.1")
    require(draft["status"] == "draft_unpublished_unknown_artifacts", "3.0.1 status differs")
    require(draft["coordinate"] == "org.wonad:desktop-sdk:3.0.1", "3.0.1 coordinate differs")
    draft_doc = exact_keys(draft["draft"], {
        "path", "sha256", "bytes", "derived_from_sha256",
    }, "3.0.1 draft")
    exact_sha(draft_doc["derived_from_sha256"], "3.0.1 derived source")
    require(draft_doc["derived_from_sha256"] == reviewed["sha256"],
            "3.0.1 draft is not bound to reviewed API-v3 source")
    if check_files:
        draft_path = evidence_root / safe_relative(draft_doc["path"], "3.0.1 draft path")
        check_file({"sha256": draft_doc["sha256"], "bytes": draft_doc["bytes"]},
                   draft_path, "3.0.1 draft")
        text = draft_path.read_text(encoding="utf-8")
        required = (
            "API-v3 picker admission gate",
            "`T + 1000` milliseconds",
            "boundary may be admitted",
            "Cancellation, successful or invalid selection",
            "`launcherPage` is synchronous and nullable",
            "one-way, fire-and-forget request",
            "callback for picker accepted",
            "unknown until a separate reviewed publication",
        )
        require(all(text.count(phrase) == 1 for phrase in required),
                "3.0.1 draft lacks unique required admission/observability language")
        require(text.count(SIGNATURE) == 1, "3.0.1 draft must state machine signature once")
    else:
        exact_sha(draft_doc["sha256"], "3.0.1 draft SHA")
        exact_int(draft_doc["bytes"], "3.0.1 draft bytes", 1)
    _validate_artifacts(draft["artifacts"], "3.0.1", False, "publication 3.0.1")
    state = exact_keys(draft["publication_state"], {
        "built", "verified", "published", "runtime_qualified",
    }, "3.0.1 publication state")
    require(all(exact_bool(value, f"3.0.1 state {name}") is False for name, value in state.items()),
            "unpublished 3.0.1 state must be entirely false")

    observations = inventory["noncanonical_historical_compile_observations"]
    require(type(observations) is list and len(observations) == 1,
            "historical observations must contain one exact row")
    observation = exact_keys(observations[0], {
        "coordinate_label", "build_receipt", "contract_zip", "canonical_publication", "reason",
    }, "historical observation")
    require(observation["coordinate_label"] == "org.wonad:desktop-sdk:3.0.0",
            "historical coordinate differs")
    require(exact_bool(observation["canonical_publication"], "historical canonical flag") is False,
            "historical observation cannot be canonical")
    require(type(observation["reason"]) is str and "documentation bytes differ" in observation["reason"],
            "historical observation reason differs")
    historical_contract = exact_keys(observation["contract_zip"], {
        "path", "sha256", "bytes", "API-v3.md_sha256",
    }, "historical contract")
    if check_files:
        check_path_file(observation["build_receipt"], workspace, "historical build receipt")
        contract_path = workspace / safe_relative(historical_contract["path"], "historical path")
        check_file({"sha256": historical_contract["sha256"],
                    "bytes": historical_contract["bytes"]}, contract_path,
                   "historical contract ZIP")
        historical_members = _safe_zip_members(contract_path)
        require(hashlib.sha256(historical_members["API-v3.md"]).hexdigest() ==
                exact_sha(historical_contract["API-v3.md_sha256"], "historical API SHA"),
                "historical API member differs")
        canonical_doc = members["API-v3.md"]
        require(historical_contract["API-v3.md_sha256"] != canonical_doc["sha256"],
                "historical observation does not demonstrate distinct documentation")

    if check_files:
        repository = workspace / safe_relative(known["repository_path"], "3.0.0 repository")
        version_dir = repository / "org/wonad/desktop-sdk/3.0.0"
        for name, row in known_artifacts.items():
            check_file(row, version_dir / name, f"3.0.0 artifact {name}")
        contract_name = "desktop-sdk-3.0.0-contract.zip"
        payloads = _safe_zip_members(version_dir / contract_name)
        for name, row in members.items():
            wanted = (row["sha256"], row["bytes"])
            payload = payloads[name]
            actual = (hashlib.sha256(payload).hexdigest(), len(payload))
            require(actual == wanted, f"contract member {name} differs")


def _snapshot_known_files(inventory: dict[str, object], workspace: Path) -> dict[str, tuple[str, int]]:
    known = inventory["publications"]["3.0.0"]
    paths: list[Path] = []
    for row in known["verifier_inputs"].values():
        paths.append(workspace / Path(row["path"]))
    paths.append(workspace / Path(known["build_receipt"]["path"]))
    version_dir = workspace / Path(known["repository_path"]) / "org/wonad/desktop-sdk/3.0.0"
    paths.extend(version_dir / name for name in known["artifacts"])
    return {str(path): file_digest(path) for path in paths}


def verify_known_publication(inventory: dict[str, object], evidence_root: Path,
                             workspace: Path, version: str,
                             run=subprocess.run) -> dict[str, object]:
    validate_inventory(inventory, evidence_root, workspace, check_files=True)
    require(version in inventory["publications"], f"unknown SDK version: {version}")
    publication = inventory["publications"][version]
    require(publication["status"] == "published_immutable_known",
            f"SDK {version} is not an immutable known publication; hashes remain unknown")
    require(version == "3.0.0", "prototype has no verifier binding for this version")

    before = _snapshot_known_files(inventory, workspace)
    repository = workspace / Path(publication["repository_path"])
    source_root = workspace / Path(publication["source_root_path"])
    verifier_row = publication["verifier_inputs"]["verify_sdk_publication.py"]
    contract_row = publication["verifier_inputs"]["sdk_contract.py"]
    verifier_source = workspace / Path(verifier_row["path"])
    contract_source = workspace / Path(contract_row["path"])
    verifier_bytes = authenticated_bytes(
        verifier_source, verifier_row["sha256"], verifier_row["bytes"], "production verifier")
    contract_bytes = authenticated_bytes(
        contract_source, contract_row["sha256"], contract_row["bytes"], "contract verifier")
    display_command = [sys.executable, "-B", "<authenticated-temporary-copy>/verify_sdk_publication.py",
                       str(repository), "--source-root", str(source_root)]
    try:
        with tempfile.TemporaryDirectory(prefix="wonad-sdk-versioned-verifier-") as temporary:
            temp = Path(temporary)
            verifier = temp / "verify_sdk_publication.py"
            contract = temp / "sdk_contract.py"
            with verifier.open("xb") as output:
                output.write(verifier_bytes)
                output.flush()
                os.fsync(output.fileno())
            with contract.open("xb") as output:
                output.write(contract_bytes)
                output.flush()
                os.fsync(output.fileno())
            verifier.chmod(0o500)
            contract.chmod(0o400)
            command = [sys.executable, "-B", str(verifier), str(repository),
                       "--source-root", str(source_root)]
            process = run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=120, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise VerificationError(f"production SDK verifier failed to execute: {exc}") from exc
    require(type(process.returncode) is int and process.returncode == 0,
            "production SDK verifier rejected publication: " +
            (process.stdout + process.stderr)[-4000:])
    require(process.stderr == "", "production SDK verifier emitted stderr")
    try:
        result = json.loads(process.stdout, object_pairs_hook=_object)
    except (TypeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"production SDK verifier output is not unique JSON: {exc}") from exc
    require(type(result) is dict, "production verifier result is not an object")
    require(result.get("coordinate") == publication["coordinate"],
            "production verifier coordinate differs")
    require(result.get("contract_signature") == SIGNATURE,
            "production verifier signature differs")
    expected_hashes = {name: row["sha256"] for name, row in publication["artifacts"].items()}
    require(result.get("artifact_sha256") == expected_hashes,
            "production verifier artifact result differs from immutable inventory")
    after = _snapshot_known_files(inventory, workspace)
    require(after == before, "known publication/verifier inputs changed during verification")
    return {
        "schema": 1,
        "scope": "external_prototype_known_publication_verification_not_release_or_runtime_qualification",
        "version": version,
        "coordinate": publication["coordinate"],
        "contract_signature": SIGNATURE,
        "artifact_sha256": expected_hashes,
        "production_verifier_command": display_command,
        "production_verifier_sha256": verifier_row["sha256"],
        "contract_verifier_sha256": contract_row["sha256"],
        "production_verifier_result": result,
        "runtime_qualified": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).resolve().parent
    parser.add_argument("--inventory", type=Path, default=here / "known-publications.json")
    parser.add_argument("--workspace", type=Path, default=Path("/u/elric/tree/wonad"))
    parser.add_argument("--verify-version")
    arguments = parser.parse_args(argv)
    try:
        inventory = load_json(arguments.inventory)
        evidence_root = arguments.inventory.resolve().parent
        workspace = arguments.workspace.resolve()
        validate_inventory(inventory, evidence_root, workspace, check_files=True)
        if arguments.verify_version is None:
            result = {
                "schema": 1,
                "scope": SCOPE,
                "inventory_valid": True,
                "known_publication_versions": ["3.0.0"],
                "draft_unpublished_versions": ["3.0.1"],
                "runtime_qualified": False,
            }
        else:
            result = verify_known_publication(
                inventory, evidence_root, workspace, arguments.verify_version)
    except VerificationError as exc:
        print(f"versioned SDK publication verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
