#!/usr/bin/env python3
"""Create and verify a frankel predecessor/successor incremental-OTA receipt.

The pair receipt is deliberately separate from either immutable full-release
receipt.  It authenticates the incremental package, both endpoint receipts,
their source/stage identities, and the exact official GrapheneOS delta script
used by the release driver.  Private signing keys are never inputs or receipt
content.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile


TOOLS_DIRECTORY = Path(__file__).resolve().parent
if str(TOOLS_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIRECTORY))
import release_receipt  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "android/grapheneos.lock.json"
SCHEMA = 1
KIND = "wonad-grapheneos-incremental-pair"
PRODUCT = "frankel"
BUILD_NUMBER = re.compile(r"[0-9]{10}")
SHA256 = re.compile(r"[0-9a-f]{64}")
METADATA_NAME = "META-INF/com/android/metadata"
MAX_RECEIPT = 4 * 1024 * 1024
MAX_METADATA = 64 * 1024


class PairReceiptError(ValueError):
    """A fail-closed pair-generation or receipt-validation error."""


def validate_build_pair(predecessor: str, successor: str):
    if (not isinstance(predecessor, str) or BUILD_NUMBER.fullmatch(predecessor) is None or
            not isinstance(successor, str) or BUILD_NUMBER.fullmatch(successor) is None):
        raise PairReceiptError("Both build numbers must be exactly 10 decimal digits")
    if int(successor, 10) <= int(predecessor, 10):
        raise PairReceiptError("Successor build number must be monotonically greater than predecessor")


def delta_name(predecessor: str, successor: str) -> str:
    validate_build_pair(predecessor, successor)
    return f"{PRODUCT}-incremental-{predecessor}-{successor}.zip"


def pair_receipt_name(predecessor: str, successor: str) -> str:
    return delta_name(predecessor, successor)[:-4] + "-receipt.json"


def release_receipt_relative(build_number: str) -> str:
    return f"{build_number}/release-{PRODUCT}-{build_number}/{release_receipt.RECEIPT_NAME}"


def delta_relative(predecessor: str, successor: str) -> str:
    return f"{successor}/{delta_name(predecessor, successor)}"


def pair_relative(predecessor: str, successor: str) -> str:
    return f"{successor}/{pair_receipt_name(predecessor, successor)}"


def require_keys(value, keys: set[str], description: str):
    if not isinstance(value, dict) or set(value) != keys:
        raise PairReceiptError(f"Unexpected {description} fields")


def file_reference(path: Path) -> dict[str, object]:
    try:
        return release_receipt.hash_file(path)
    except (release_receipt.ReceiptError, OSError) as error:
        raise PairReceiptError(str(error)) from error


def named_reference(path: Path, name: str) -> dict[str, object]:
    reference = file_reference(path)
    return {"name": name, **reference}


def load_pair(path: Path):
    if path.is_symlink() or not path.is_file():
        raise PairReceiptError("Pair receipt must be an ordinary file")
    if path.stat().st_size <= 0 or path.stat().st_size > MAX_RECEIPT:
        raise PairReceiptError("Pair receipt has an invalid size")
    try:
        return json.loads(path.read_text(), object_pairs_hook=release_receipt.unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError,
            release_receipt.ReceiptError) as error:
        raise PairReceiptError(f"Invalid pair receipt: {error}") from error


def parse_ota_metadata(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise PairReceiptError("Incremental OTA must be an ordinary file")
    try:
        with zipfile.ZipFile(path) as archive:
            entries = [entry for entry in archive.infolist()
                       if entry.filename == METADATA_NAME]
            if len(entries) != 1:
                raise PairReceiptError("Incremental OTA must contain exactly one metadata entry")
            if entries[0].file_size <= 0 or entries[0].file_size > MAX_METADATA:
                raise PairReceiptError("Incremental OTA metadata has an invalid size")
            raw = archive.read(entries[0])
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise PairReceiptError("Cannot read incremental OTA metadata") from error
    try:
        rows = []
        for line in raw.decode("utf-8").splitlines():
            if not line or "=" not in line:
                raise PairReceiptError("Malformed incremental OTA metadata line")
            key, value = line.split("=", 1)
            if not key or not value:
                raise PairReceiptError("Malformed incremental OTA metadata field")
            rows.append((key, value))
        return release_receipt.unique_object(rows)
    except UnicodeDecodeError as error:
        raise PairReceiptError("Incremental OTA metadata is not UTF-8") from error
    except release_receipt.ReceiptError as error:
        raise PairReceiptError(str(error)) from error


def selected_metadata(metadata: dict[str, str], predecessor_receipt,
                      successor_receipt) -> dict[str, object]:
    predecessor = predecessor_receipt["build"]["number"]
    successor = successor_receipt["build"]["number"]
    expected = {
        "ota-type": "AB",
        "pre-device": PRODUCT,
        "pre-build": predecessor_receipt["build"]["post_build"],
        "pre-build-incremental": predecessor,
        "post-build": successor_receipt["build"]["post_build"],
        "post-build-incremental": successor,
        "post-timestamp": str(successor_receipt["build"]["timestamp"]),
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise PairReceiptError(f"Incremental OTA metadata does not bind {key} to both endpoints")
    if "ota-downgrade" in metadata or "spl-downgrade" in metadata:
        raise PairReceiptError("Incremental OTA unexpectedly permits a downgrade")
    return {
        **expected,
        "post_datetime_utc": datetime.fromtimestamp(
            successor_receipt["build"]["timestamp"], timezone.utc).isoformat(),
    }


def endpoint_identity(receipt, reference: dict[str, object], relative_path: str):
    return {
        "number": receipt["build"]["number"],
        "receipt": {"path": relative_path, **reference},
        "build": receipt["build"],
        "target": receipt["target"],
        "source": receipt["source"],
        "grapheneos_lock": receipt["grapheneos_lock"],
        "wonad_stage": receipt["wonad_stage"],
        "updater_stage": receipt["updater_stage"],
        "phase1_provenance": receipt["phase1_provenance"],
        "apk_signer_sha256": receipt["apk_signer_sha256"],
    }


def endpoint_paths(source: Path, predecessor: str, successor: str):
    releases = source / "releases"
    return {
        "predecessor": releases / release_receipt_relative(predecessor),
        "successor": releases / release_receipt_relative(successor),
        "incremental": releases / delta_relative(predecessor, successor),
        "pair": releases / pair_relative(predecessor, successor),
    }


def verify_endpoints(source_value: Path, predecessor: str, successor: str):
    validate_build_pair(predecessor, successor)
    try:
        source_state = release_receipt.verify_release_source(source_value)
        source = release_receipt.dedicated_source(source_value)
    except (release_receipt.ReceiptError, OSError) as error:
        raise PairReceiptError(str(error)) from error
    paths = endpoint_paths(source, predecessor, successor)
    endpoints = {}
    for role in ("predecessor", "successor"):
        path = paths[role]
        try:
            value = release_receipt.verify_receipt(path)
        except (release_receipt.ReceiptError, OSError) as error:
            raise PairReceiptError(f"Invalid {role} full-release receipt: {error}") from error
        expected_number = predecessor if role == "predecessor" else successor
        if value["build"]["number"] != expected_number:
            raise PairReceiptError(f"{role.capitalize()} receipt has the wrong build number")
        endpoints[role] = value
    before = endpoints["predecessor"]
    after = endpoints["successor"]
    if before["apk_signer_sha256"] != after["apk_signer_sha256"]:
        raise PairReceiptError("Endpoint releases do not share the frozen Wonad signer lineage")
    if before["updater_stage"]["update_url"] != after["updater_stage"]["update_url"]:
        raise PairReceiptError("Endpoint releases do not share the project OTA channel")
    if after["build"]["timestamp"] < before["build"]["timestamp"]:
        raise PairReceiptError("Successor timestamp is older than predecessor")
    if (source_state["source"] != after["source"] or
            source_state["wonad_stage"] != after["wonad_stage"] or
            source_state["updater_stage"] != after["updater_stage"]):
        raise PairReceiptError("Current source/stage lineage differs from the successor receipt")
    return source, source_state, paths, endpoints


def validate_file_row(value, description: str, expected_name: str | None = None):
    keys = {"sha256", "size"} if expected_name is None else {"name", "sha256", "size"}
    require_keys(value, keys, description)
    if expected_name is not None and value["name"] != expected_name:
        raise PairReceiptError(f"Unexpected {description} name")
    if (not isinstance(value["sha256"], str) or SHA256.fullmatch(value["sha256"]) is None or
            type(value["size"]) is not int or value["size"] <= 0):
        raise PairReceiptError(f"Invalid {description} identity")


def locked_delta_generator() -> dict[str, object]:
    try:
        lock = release_receipt.load_json(LOCK_PATH)
        value = lock["release_pipeline"]["delta_generator"]
    except (KeyError, TypeError, release_receipt.ReceiptError, OSError) as error:
        raise PairReceiptError("GrapheneOS lock lacks the reviewed delta generator") from error
    if not isinstance(value, dict) or set(value) != {"path", "project_commit", "sha256", "size"}:
        raise PairReceiptError("GrapheneOS lock has an invalid delta-generator record")
    result = {
        "name": value["path"],
        "repository_commit": value["project_commit"],
        "sha256": value["sha256"],
        "size": value["size"],
    }
    validate_file_row({"name": result["name"], "sha256": result["sha256"],
                       "size": result["size"]}, "locked delta generator",
                      "script/generate-delta.sh")
    if re.fullmatch(r"[0-9a-f]{40}", str(result["repository_commit"])) is None:
        raise PairReceiptError("GrapheneOS lock has an invalid delta-generator commit")
    return result


def validate_endpoint_shape(value, role: str, build_number: str):
    require_keys(value, {"number", "receipt", "build", "target", "source",
                         "grapheneos_lock", "wonad_stage", "updater_stage",
                         "phase1_provenance", "apk_signer_sha256"}, role)
    if value["number"] != build_number:
        raise PairReceiptError(f"{role.capitalize()} number is inconsistent")
    receipt = value["receipt"]
    require_keys(receipt, {"path", "sha256", "size"}, f"{role} receipt reference")
    if receipt["path"] != release_receipt_relative(build_number):
        raise PairReceiptError(f"Unexpected {role} receipt path")
    validate_file_row({"sha256": receipt["sha256"], "size": receipt["size"]},
                      f"{role} receipt")
    build = value["build"]
    if (not isinstance(build, dict) or build.get("number") != build_number or
            not isinstance(build.get("post_build"), str) or
            type(build.get("timestamp")) is not int or build["timestamp"] <= 0):
        raise PairReceiptError(f"Invalid {role} build identity")
    expected_target = {"device": "Pixel 10", "product": PRODUCT, "abi": "arm64-v8a",
                       "variant": "user", "lunch_target": "frankel-cur-user"}
    if value["target"] != expected_target:
        raise PairReceiptError(f"{role.capitalize()} is not a frankel ARM64 user release")
    if (not isinstance(value["apk_signer_sha256"], str) or
            SHA256.fullmatch(value["apk_signer_sha256"]) is None):
        raise PairReceiptError(f"Invalid {role} Wonad signer identity")
    for field in ("source", "grapheneos_lock", "wonad_stage", "updater_stage",
                  "phase1_provenance"):
        if not isinstance(value[field], dict) or not value[field]:
            raise PairReceiptError(f"Invalid {role} {field} identity")


def validate_pair_shape(value):
    require_keys(value, {"schema", "kind", "target", "predecessor", "successor",
                         "incremental_ota", "official_delta_generator",
                         "receipt_generator", "pair_verifier"}, "pair receipt")
    if value["schema"] != SCHEMA or value["kind"] != KIND or value["target"] != PRODUCT:
        raise PairReceiptError("Unsupported incremental pair receipt")
    predecessor = value["predecessor"].get("number") if isinstance(value["predecessor"], dict) else None
    successor = value["successor"].get("number") if isinstance(value["successor"], dict) else None
    validate_build_pair(predecessor, successor)
    validate_endpoint_shape(value["predecessor"], "predecessor", predecessor)
    validate_endpoint_shape(value["successor"], "successor", successor)
    if value["predecessor"]["apk_signer_sha256"] != value["successor"]["apk_signer_sha256"]:
        raise PairReceiptError("Endpoint Wonad signer lineage differs")
    if (value["predecessor"]["updater_stage"].get("update_url") !=
            value["successor"]["updater_stage"].get("update_url")):
        raise PairReceiptError("Endpoint OTA channel lineage differs")
    if value["successor"]["build"]["timestamp"] < value["predecessor"]["build"]["timestamp"]:
        raise PairReceiptError("Successor timestamp is older than predecessor")

    incremental = value["incremental_ota"]
    require_keys(incremental, {"path", "sha256", "size", "metadata"}, "incremental OTA")
    if incremental["path"] != delta_relative(predecessor, successor):
        raise PairReceiptError("Unexpected incremental OTA path")
    validate_file_row({"sha256": incremental["sha256"], "size": incremental["size"]},
                      "incremental OTA")
    metadata = incremental["metadata"]
    expected_metadata_keys = {"ota-type", "pre-device", "pre-build",
                              "pre-build-incremental", "post-build",
                              "post-build-incremental", "post-timestamp",
                              "post_datetime_utc"}
    require_keys(metadata, expected_metadata_keys, "incremental OTA metadata")
    expected_metadata = {
        "ota-type": "AB",
        "pre-device": PRODUCT,
        "pre-build": value["predecessor"]["build"]["post_build"],
        "pre-build-incremental": predecessor,
        "post-build": value["successor"]["build"]["post_build"],
        "post-build-incremental": successor,
        "post-timestamp": str(value["successor"]["build"]["timestamp"]),
        "post_datetime_utc": datetime.fromtimestamp(
            value["successor"]["build"]["timestamp"], timezone.utc).isoformat(),
    }
    if metadata != expected_metadata:
        raise PairReceiptError("Receipted incremental metadata differs from endpoint identities")

    official = value["official_delta_generator"]
    require_keys(official, {"name", "repository_commit", "sha256", "size"},
                 "official delta generator")
    if (official["name"] != "script/generate-delta.sh" or
            re.fullmatch(r"[0-9a-f]{40}", str(official["repository_commit"])) is None):
        raise PairReceiptError("Invalid official GrapheneOS delta-generator identity")
    validate_file_row({"name": official["name"], "sha256": official["sha256"],
                       "size": official["size"]}, "official delta generator",
                      "script/generate-delta.sh")
    if official != locked_delta_generator():
        raise PairReceiptError("Official delta generator differs from the reviewed GrapheneOS lock")
    validate_file_row(value["receipt_generator"], "pair receipt generator",
                      "android/tools/release_pair_receipt.py")
    validate_file_row(value["pair_verifier"], "pair verifier",
                      "android/tools/verify_release_pair.py")
    return predecessor, successor


def atomic_write_new(path: Path, data: bytes):
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise PairReceiptError("Pair receipt parent must be an ordinary directory")
    if path.exists() or path.is_symlink():
        raise PairReceiptError("Pair receipt already exists; refusing overwrite")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".incremental-receipt.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as error:
            raise PairReceiptError("Pair receipt already exists; refusing overwrite") from error
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def create_pair_receipt(source_value: Path, predecessor: str, successor: str) -> Path:
    source, _source_state, paths, endpoints = verify_endpoints(
        source_value, predecessor, successor)
    delta = paths["incremental"]
    if delta.name != delta_name(predecessor, successor):
        raise PairReceiptError("Unexpected incremental OTA filename")
    metadata = selected_metadata(parse_ota_metadata(delta), endpoints["predecessor"],
                                 endpoints["successor"])
    script = source / "script/generate-delta.sh"
    try:
        script_commit = release_receipt.revision(source / "script")
    except (release_receipt.ReceiptError, OSError) as error:
        raise PairReceiptError(str(error)) from error
    verifier = ROOT / "android/tools/verify_release_pair.py"
    if not verifier.is_file():
        raise PairReceiptError("Pair verifier source is missing")
    predecessor_reference = file_reference(paths["predecessor"])
    successor_reference = file_reference(paths["successor"])
    delta_reference = file_reference(delta)
    pair = {
        "schema": SCHEMA,
        "kind": KIND,
        "target": PRODUCT,
        "predecessor": endpoint_identity(
            endpoints["predecessor"], predecessor_reference,
            release_receipt_relative(predecessor)),
        "successor": endpoint_identity(
            endpoints["successor"], successor_reference,
            release_receipt_relative(successor)),
        "incremental_ota": {
            "path": delta_relative(predecessor, successor),
            **delta_reference,
            "metadata": metadata,
        },
        "official_delta_generator": {
            "name": "script/generate-delta.sh",
            "repository_commit": script_commit,
            **file_reference(script),
        },
        "receipt_generator": named_reference(
            Path(__file__), "android/tools/release_pair_receipt.py"),
        "pair_verifier": named_reference(
            verifier, "android/tools/verify_release_pair.py"),
    }
    validate_pair_shape(pair)
    output = paths["pair"]
    encoded = (json.dumps(pair, indent=2, sort_keys=True) + "\n").encode("utf-8")
    atomic_write_new(output, encoded)
    return output


def paths_from_pair(pair_path: Path, predecessor: str, successor: str):
    expected_name = pair_receipt_name(predecessor, successor)
    if pair_path.name != expected_name or pair_path.parent.name != successor:
        raise PairReceiptError("Pair receipt is not in the canonical successor release directory")
    releases = pair_path.parent.parent
    if releases.name != "releases":
        raise PairReceiptError("Pair receipt must retain the canonical releases/build layout")
    paths = {
        "predecessor": releases / release_receipt_relative(predecessor),
        "successor": releases / release_receipt_relative(successor),
        "incremental": releases / delta_relative(predecessor, successor),
        "pair": pair_path,
    }
    directories = {pair_path.parent, releases,
                   paths["predecessor"].parent, paths["predecessor"].parent.parent,
                   paths["successor"].parent, paths["successor"].parent.parent}
    if any(directory.is_symlink() or not directory.is_dir() for directory in directories):
        raise PairReceiptError("Pair release layout contains a symlink or missing directory")
    return paths


def verify_pair_receipt(pair_path: Path):
    pair = load_pair(pair_path)
    predecessor, successor = validate_pair_shape(pair)
    paths = paths_from_pair(pair_path, predecessor, successor)
    current_generator = named_reference(Path(__file__), "android/tools/release_pair_receipt.py")
    current_verifier = named_reference(ROOT / "android/tools/verify_release_pair.py",
                                       "android/tools/verify_release_pair.py")
    if pair["receipt_generator"] != current_generator:
        raise PairReceiptError("Running pair receipt generator differs from the receipt")
    if pair["pair_verifier"] != current_verifier:
        raise PairReceiptError("Running pair verifier differs from the receipt")

    endpoints = {}
    for role in ("predecessor", "successor"):
        expected = pair[role]["receipt"]
        observed = file_reference(paths[role])
        if observed != {"sha256": expected["sha256"], "size": expected["size"]}:
            raise PairReceiptError(f"{role.capitalize()} receipt identity differs from pair")
        try:
            actual = release_receipt.verify_receipt(paths[role])
        except (release_receipt.ReceiptError, OSError) as error:
            raise PairReceiptError(f"Invalid {role} endpoint receipt: {error}") from error
        expected_identity = endpoint_identity(actual, observed, expected["path"])
        if expected_identity != pair[role]:
            raise PairReceiptError(f"{role.capitalize()} source/stage identity differs from pair")
        endpoints[role] = actual

    expected_delta = pair["incremental_ota"]
    observed_delta = file_reference(paths["incremental"])
    if observed_delta != {"sha256": expected_delta["sha256"], "size": expected_delta["size"]}:
        raise PairReceiptError("Incremental OTA identity differs from pair receipt")
    metadata = selected_metadata(parse_ota_metadata(paths["incremental"]),
                                 endpoints["predecessor"], endpoints["successor"])
    if metadata != expected_delta["metadata"]:
        raise PairReceiptError("Incremental OTA metadata differs from pair receipt")
    return {"pair": pair, "paths": paths, "predecessor": endpoints["predecessor"],
            "successor": endpoints["successor"]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    endpoints = commands.add_parser("verify-endpoints",
                                    help="verify both full releases and target source lineage")
    endpoints.add_argument("--source", required=True, type=Path)
    endpoints.add_argument("--predecessor", required=True)
    endpoints.add_argument("--successor", required=True)
    create = commands.add_parser("create", help="create a new pair receipt without overwrite")
    create.add_argument("--source", required=True, type=Path)
    create.add_argument("--predecessor", required=True)
    create.add_argument("--successor", required=True)
    verify = commands.add_parser("verify", help="offline-verify pair receipt and endpoint hashes")
    verify.add_argument("--receipt", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "verify-endpoints":
            _source, _state, _paths, values = verify_endpoints(
                arguments.source, arguments.predecessor, arguments.successor)
            print(json.dumps({"status": "verified", "predecessor":
                              values["predecessor"]["build"]["number"], "successor":
                              values["successor"]["build"]["number"]}, sort_keys=True))
        elif arguments.command == "create":
            output = create_pair_receipt(arguments.source, arguments.predecessor,
                                         arguments.successor)
            print(json.dumps({"status": "created", "receipt": str(output)}, sort_keys=True))
        else:
            result = verify_pair_receipt(arguments.receipt)
            print(json.dumps({"status": "verified", "predecessor":
                              result["pair"]["predecessor"]["number"], "successor":
                              result["pair"]["successor"]["number"]}, sort_keys=True))
        return 0
    except (PairReceiptError, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
