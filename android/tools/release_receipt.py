#!/usr/bin/env python3
"""Create and offline-verify an exact Pixel 10 GrapheneOS release receipt.

Creation deliberately accepts a source checkout and build number, rather than
arbitrary artifact paths.  GrapheneOS' release layout is therefore part of the
contract and a receipt cannot accidentally bless a partial export.  Verification
needs only the receipt and the release directory containing it.

Private release keys are neither inputs nor evidence.  The tool never walks the
checkout's ``keys`` directory and refuses key-like paths in the release output
before opening or hashing them.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
import zipfile

TOOLS_DIRECTORY = Path(__file__).resolve().parent
if str(TOOLS_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIRECTORY))
import stage_contract
import phase1_provenance
import run_release_build
import verify_checkout


ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "android/grapheneos.lock.json"
RECEIPT_NAME = "release-receipt.json"
SCHEMA = 4
PRODUCT = "frankel"
LUNCH_TARGET = "frankel-cur-user"
STAGE_MARKER = Path("external/wonad/.wonad-stage.json")
UPDATER_MARKER = Path(".wonad-updater-stage.json")
UPDATER_CONFIG = Path("packages/apps/Updater/res/values/config.xml")
PROVENANCE_DIRECTORY = Path("wonad-provenance")
SOURCE_PROVENANCE = PROVENANCE_DIRECTORY / "source-provenance.json"
CLIENT_PROVENANCE = PROVENANCE_DIRECTORY / "client-provenance.json"
BUILD_EXECUTION = PROVENANCE_DIRECTORY / "build-execution.json"
BUILD_BIND_PROOF = PROVENANCE_DIRECTORY / "build-bind-proof.json"
BUILD_CONSUMPTION = PROVENANCE_DIRECTORY / "build-container-consumption.json"
BUILD_LOG = PROVENANCE_DIRECTORY / "build.log"
SHA256 = re.compile(r"[0-9a-f]{64}")
BUILD_NUMBER = re.compile(r"[0-9]{10}")

# These names are never legitimate release evidence.  Check the path before
# opening it, so a mistakenly copied secret is not even hashed.
PRIVATE_SUFFIXES = {".jks", ".key", ".keystore", ".p12", ".pfx", ".pem", ".pk8"}
PRIVATE_NAMES = {"id_ed25519", "id_ecdsa", "id_rsa", "avb.pem"}
PRIVATE_COMPONENTS = {"keys", "private-keys", "private_keys"}


class ReceiptError(ValueError):
    """A fail-closed release or receipt validation error."""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def load_json(path: Path):
    try:
        return json.loads(path.read_text(), object_pairs_hook=unique_object)
    except UnicodeDecodeError as error:
        raise ReceiptError(f"JSON is not UTF-8: {path}") from error
    except json.JSONDecodeError as error:
        raise ReceiptError(f"Invalid JSON in {path}: {error}") from error


def private_key_like(relative: PurePosixPath) -> bool:
    parts = {part.lower() for part in relative.parts}
    name = relative.name.lower()
    return (bool(parts & PRIVATE_COMPONENTS) or name in PRIVATE_NAMES or
            relative.suffix.lower() in PRIVATE_SUFFIXES)


def safe_relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ReceiptError("Invalid empty or NUL-containing relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReceiptError(f"Unsafe relative path: {value!r}")
    if path.as_posix() != value:
        raise ReceiptError(f"Non-canonical relative path: {value!r}")
    return path


def hash_file(path: Path) -> dict[str, object]:
    """Hash one stable regular file without following a final symlink."""
    relative = PurePosixPath(path.name)
    if private_key_like(relative):
        raise ReceiptError(f"Refusing to read key-like file: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ReceiptError(f"Not an ordinary file: {path}")
        digest = hashlib.sha256()
        while True:
            data = os.read(descriptor, 1024 * 1024)
            if not data:
                break
            digest.update(data)
        after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode,
                                  value.st_size, value.st_mtime_ns)
        if identity(before) != identity(after):
            raise ReceiptError(f"File changed while it was hashed: {path}")
        return {"sha256": digest.hexdigest(), "size": before.st_size}
    finally:
        os.close(descriptor)


def walk_regular_files(root: Path, excluded: set[str] | None = None) -> dict[str, Path]:
    """Return every ordinary file below root; reject links and special files."""
    excluded = excluded or set()
    result: dict[str, Path] = {}

    def visit(directory: Path, prefix: PurePosixPath | None = None):
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise ReceiptError(f"Cannot inventory release directory {directory}: {error}") from error
        for entry in entries:
            relative = PurePosixPath(entry.name) if prefix is None else prefix / entry.name
            name = relative.as_posix()
            if entry.is_symlink():
                raise ReceiptError(f"Release output contains a symlink: {name}")
            if entry.is_dir(follow_symlinks=False):
                visit(Path(entry.path), relative)
            elif entry.is_file(follow_symlinks=False):
                if name in excluded:
                    continue
                if private_key_like(relative):
                    raise ReceiptError(f"Release output contains a key-like path: {name}")
                result[name] = Path(entry.path)
            else:
                raise ReceiptError(f"Release output contains a non-ordinary file: {name}")

    visit(root)
    return result


def revision(repository: Path) -> str:
    if repository.is_symlink() or not repository.is_dir():
        raise ReceiptError(f"Missing or symlinked source repository: {repository}")
    try:
        value = subprocess.check_output(
            ["git", "-C", str(repository), "rev-parse", "HEAD"],
            stderr=subprocess.STDOUT, timeout=60, text=True).strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise ReceiptError(f"Cannot resolve source revision for {repository}") from error
    if re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise ReceiptError(f"Unexpected Git revision for {repository}: {value!r}")
    return value


def require_keys(value, keys: set[str], description: str):
    if not isinstance(value, dict) or set(value) != keys:
        raise ReceiptError(f"Unexpected {description} fields")


def validate_lock(lock):
    if not isinstance(lock, dict) or lock.get("schema") != 2:
        raise ReceiptError("GrapheneOS lock schema 2 is required")
    production = lock.get("production_target")
    pipeline = lock.get("release_pipeline")
    if (lock.get("device") != PRODUCT or not isinstance(production, dict) or
            production.get("product") != PRODUCT or production.get("variant") != "user" or
            production.get("abi") != "arm64-v8a" or not isinstance(pipeline, dict) or
            pipeline.get("device") != PRODUCT or pipeline.get("lunch_target") != LUNCH_TARGET):
        raise ReceiptError("Lock does not select the frankel ARM64 user release target")
    delta = pipeline.get("delta_generator")
    if (not isinstance(delta, dict) or
            set(delta) != {"path", "project_commit", "sha256", "size"} or
            delta.get("path") != "script/generate-delta.sh" or
            re.fullmatch(r"[0-9a-f]{40}", str(delta.get("project_commit", ""))) is None or
            SHA256.fullmatch(str(delta.get("sha256", ""))) is None or
            type(delta.get("size")) is not int or delta["size"] <= 0):
        raise ReceiptError("Lock does not pin the official GrapheneOS delta generator")
    for field, key in (("manifest", "commit"), ("frameworks_base", "commit"),
                       ("launcher3", "commit"), ("updater", "commit"),
                       ("emulator_goldfish", "commit")):
        row = lock.get(field)
        if not isinstance(row, dict) or SHA256.fullmatch(str(row.get(key, ""))) is not None:
            # A Git SHA-1 is deliberately 40 hex; reject accidentally substituting
            # an artifact hash even if it is syntactically hexadecimal.
            raise ReceiptError(f"Invalid {field} source pin")
        if re.fullmatch(r"[0-9a-f]{40}", str(row.get(key, ""))) is None:
            raise ReceiptError(f"Invalid {field} source pin")


def dedicated_source(value: Path) -> Path:
    if value.is_symlink():
        raise ReceiptError("The GrapheneOS source path must not be a symlink")
    try:
        source = value.resolve(strict=True)
    except OSError as error:
        raise ReceiptError(f"GrapheneOS source path does not exist: {value}") from error
    if source == ROOT or ROOT in source.parents:
        raise ReceiptError("Use a dedicated GrapheneOS checkout outside Wonad")
    repo = source / ".repo"
    if repo.is_symlink() or not repo.is_dir():
        raise ReceiptError("Dedicated GrapheneOS checkout is missing .repo")
    return source


def verify_source_pins(source: Path, lock) -> dict[str, dict[str, str]]:
    repositories = {
        "manifest": source / ".repo/manifests",
        "frameworks_base": source / "frameworks/base",
        "launcher3": source / "packages/apps/Launcher3",
        "updater": source / "packages/apps/Updater",
        "emulator_goldfish": source / "device/generic/goldfish",
    }
    result = {}
    for name, repository in repositories.items():
        actual = revision(repository)
        expected = lock[name]["commit"]
        if actual != expected:
            raise ReceiptError(f"{name} revision {actual} differs from pinned {expected}")
        row = {"commit": actual, "url": lock[name]["url"]}
        if name == "manifest":
            row.update({
                "tag_object": lock[name]["tag_object"],
                "signer": lock[name]["signer"],
                "signing_key_fingerprint": lock[name]["signing_key_fingerprint"],
            })
        result[name] = row
    if stage_contract.NATIVE_PATCH_NAMES:
        expected = stage_contract.authenticated_native_revision(source, lock)
        actual = revision(source / stage_contract.NATIVE_PROJECT)
        if actual != expected:
            raise ReceiptError("Native revision differs from its authenticated manifest pin")
        result["frameworks_native"] = {"commit": actual, "manifest_path": stage_contract.NATIVE_PROJECT}
    return result


def validate_sha_map(value, description: str) -> dict[str, str]:
    if not isinstance(value, dict) or not value:
        raise ReceiptError(f"{description} must be a non-empty object")
    result = {}
    for name, digest in value.items():
        relative = safe_relative(name)
        if private_key_like(relative):
            raise ReceiptError(f"{description} contains a key-like path: {name}")
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise ReceiptError(f"Invalid digest for {description} entry {name}")
        result[name] = digest
    return dict(sorted(result.items()))


def read_stage_marker(source: Path, lock):
    marker_path = source / STAGE_MARKER
    if marker_path.is_symlink() or not marker_path.is_file():
        raise ReceiptError("Staged Wonad source marker is missing or symlinked")
    marker = load_json(marker_path)
    require_keys(marker, stage_contract.marker_fields(), "Wonad stage marker")
    try:
        stage_contract.require_stage_schema(marker)
    except ValueError as error:
        raise ReceiptError(str(error)) from error
    files = validate_sha_map(marker["files"], "Wonad staged files")
    signer = marker["signer_sha256"]
    if (marker["schema"] != stage_contract.stage_schema() or marker["frameworks_revision"] != lock["frameworks_base"]["commit"] or
            marker["launcher3_revision"] != lock["launcher3"]["commit"] or
            marker["emulator_goldfish_revision"] != lock["emulator_goldfish"]["commit"] or
            not isinstance(signer, str) or SHA256.fullmatch(signer) is None):
        raise ReceiptError("Wonad stage marker does not match the pinned source and signer contract")
    expected_patches = {
        "frameworks_base": stage_contract.patch_ledger(stage_contract.FRAMEWORK_PATCH_NAMES),
        "launcher3": stage_contract.patch_ledger(stage_contract.LAUNCHER_PATCH_NAMES),
        "emulator_goldfish": stage_contract.patch_ledger(stage_contract.EMULATOR_PATCH_NAMES),
    }
    if stage_contract.NATIVE_PATCH_NAMES:
        if marker["frameworks_native_revision"] != stage_contract.authenticated_native_revision(source, lock):
            raise ReceiptError("Native stage revision differs from its authenticated manifest")
        expected_patches["frameworks_native"] = stage_contract.patch_ledger(stage_contract.NATIVE_PATCH_NAMES)
    if marker["patches"] != expected_patches:
        raise ReceiptError("Wonad stage patch order or digest differs from the release source")
    if marker["tools"] != stage_contract.tool_ledger():
        raise ReceiptError("Wonad stage tool identity differs from the release source")
    targets = marker["platform_targets"]
    if not isinstance(targets, dict) or set(targets) != set(stage_contract.platform_lanes()):
        raise ReceiptError("Wonad stage platform target inventory is incomplete")
    repositories = {label: source / path for label, (path, names, field) in stage_contract.platform_lanes().items()}
    try:
        stage_contract.marker_owned_targets(marker)
    except ValueError as error:
        raise ReceiptError(str(error)) from error
    normalized_targets = {}
    for repository_name, values in targets.items():
        patch_names = stage_contract.platform_lanes()[repository_name][1]
        if patch_names:
            values = validate_sha_map(values, f"{repository_name} owned platform targets")
        elif values != {}:
            raise ReceiptError("Targets declared under an empty registered patch lane")
        repository = repositories[repository_name]
        for name, expected in values.items():
            path = repository / name
            if any(repository.joinpath(*Path(name).parts[:i]).is_symlink()
                   for i in range(1, len(Path(name).parts) + 1)):
                raise ReceiptError(f"Symlinked owned {repository_name} target: {name}")
            if path.is_symlink() or not path.is_file() or hash_file(path)["sha256"] != expected:
                raise ReceiptError(f"Owned {repository_name} target differs from marker: {name}")
        normalized_targets[repository_name] = values
    certificate = marker["signer_certificate"]
    require_keys(certificate, {"path", "sha256", "size"}, "Wonad signer certificate")
    if (certificate["path"] != "WonadReleaseCertificate.der" or
            certificate["sha256"] != signer or type(certificate["size"]) is not int or
            certificate["size"] < 128 or files.get(certificate["path"]) != signer):
        raise ReceiptError("Wonad signer certificate is not bound to the staged signer")
    staged_root = marker_path.parent
    actual = walk_regular_files(staged_root, {marker_path.name})
    if set(actual) != set(files):
        raise ReceiptError("Staged Wonad source inventory differs from its marker")
    for name, expected in files.items():
        if hash_file(actual[name])["sha256"] != expected:
            raise ReceiptError(f"Staged Wonad source differs from marker: {name}")
    if hash_file(actual[certificate["path"]])["size"] != certificate["size"]:
        raise ReceiptError("Staged Wonad signer certificate size differs from marker")
    reference = hash_file(marker_path)
    result = {
        "path": STAGE_MARKER.as_posix(),
        "sha256": reference["sha256"],
        "size": reference["size"],
        "schema": stage_contract.stage_schema(),
        "frameworks_revision": marker["frameworks_revision"],
        "launcher3_revision": marker["launcher3_revision"],
        "emulator_goldfish_revision": marker["emulator_goldfish_revision"],
        "signer_sha256": signer,
        "signer_certificate": certificate,
        "files": files,
        "patches": expected_patches,
        "platform_targets": normalized_targets,
        "tools": marker["tools"],
    }
    if stage_contract.NATIVE_PATCH_NAMES:
        result["frameworks_native_revision"] = marker["frameworks_native_revision"]
    return result


def verify_release_worktree(source: Path, stage):
    """Recheck every tracked manifest project, allowing only exact owned edits."""
    allowed = {
        "frameworks/base": set(stage["platform_targets"]["frameworks_base"]),
        "packages/apps/Launcher3": set(stage["platform_targets"]["launcher3"]),
        "device/generic/goldfish": set(stage["platform_targets"]["emulator_goldfish"]),
        "packages/apps/Updater": {"res/values/config.xml"},
    }
    if stage_contract.NATIVE_PATCH_NAMES:
        allowed[stage_contract.NATIVE_PROJECT] = set(stage["platform_targets"]["frameworks_native"])
    try:
        result = verify_checkout.verify(source, jobs=32, allowed_changes=allowed)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise ReceiptError(f"Release checkout contains unowned worktree state: {error}") from error
    if result.get("tracked_worktrees") != "clean":
        raise ReceiptError("Release checkout worktree state was not verified")
    return result


def verify_release_source(source_value: Path):
    source = dedicated_source(source_value)
    lock = load_json(LOCK_PATH)
    validate_lock(lock)
    pins = verify_source_pins(source, lock)
    stage = read_stage_marker(source, lock)
    updater = read_updater_marker(source, lock)
    verify_release_worktree(source, stage)
    return {"source": pins, "wonad_stage": stage, "updater_stage": updater}


def custom_update_url(value: str) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    host = (parsed.hostname or "").rstrip(".").lower()
    return (parsed.scheme == "https" and bool(host) and not parsed.username and
            not parsed.password and not parsed.query and not parsed.fragment and
            value.endswith("/") and host != "grapheneos.org" and
            not host.endswith(".grapheneos.org") and host not in {"localhost", "127.0.0.1", "::1"})


def read_updater_marker(source: Path, lock):
    marker_path = source / UPDATER_MARKER
    config_path = source / UPDATER_CONFIG
    if marker_path.is_symlink() or not marker_path.is_file():
        raise ReceiptError("Updater ownership marker is missing or symlinked")
    if config_path.is_symlink() or not config_path.is_file():
        raise ReceiptError("Configured Updater resource is missing or symlinked")
    marker = load_json(marker_path)
    require_keys(marker, {"schema", "updater_revision", "update_url",
                          "baseline_sha256", "configured_sha256"}, "Updater marker")
    if (marker["schema"] != 1 or marker["updater_revision"] != lock["updater"]["commit"] or
            not custom_update_url(marker["update_url"]) or
            any(not isinstance(marker[name], str) or SHA256.fullmatch(marker[name]) is None
                for name in ("baseline_sha256", "configured_sha256"))):
        raise ReceiptError("Updater marker does not describe the pinned project channel")
    config = hash_file(config_path)
    if config["sha256"] != marker["configured_sha256"]:
        raise ReceiptError("Updater configuration differs from its ownership marker")
    reference = hash_file(marker_path)
    return {
        "path": UPDATER_MARKER.as_posix(),
        "sha256": reference["sha256"],
        "size": reference["size"],
        **marker,
        "configured_resource": {
            "path": UPDATER_CONFIG.as_posix(),
            "sha256": config["sha256"],
            "size": config["size"],
        },
    }


def artifact_roles(build_number: str) -> dict[str, str]:
    prefix = f"{PRODUCT}"
    install = f"{prefix}-install-{build_number}.zip"
    return {
        "factory": f"{prefix}-factory-{build_number}.zip",
        "install": install,
        "install_signature": install + ".sig",
        "full_ota": f"{prefix}-ota_update-{build_number}.zip",
        "signed_target_files": f"{prefix}-target_files.zip",
        "images": f"{prefix}-img-{build_number}.zip",
        "channel_alpha": f"{prefix}-alpha",
        "channel_beta": f"{prefix}-beta",
        "channel_stable": f"{prefix}-stable",
        "channel_testing": f"{prefix}-testing",
    }


def release_directory(source: Path, build_number: str) -> Path:
    return source / "releases" / build_number / f"release-{PRODUCT}-{build_number}"


def ota_metadata(path: Path, build_number: str) -> dict[str, object]:
    try:
        with zipfile.ZipFile(path) as archive:
            entries = [entry for entry in archive.infolist()
                       if entry.filename == "META-INF/com/android/metadata"]
            if len(entries) != 1:
                raise ReceiptError("Full OTA must contain exactly one Android metadata entry")
            entry = entries[0]
            if entry.file_size > 64 * 1024:
                raise ReceiptError("Full OTA metadata is unexpectedly large")
            raw = archive.read(entry)
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise ReceiptError(f"Cannot read full OTA metadata: {path}") from error
    try:
        rows = []
        for line in raw.decode("utf-8").splitlines():
            if "=" not in line:
                raise ReceiptError("Malformed full OTA metadata line")
            rows.append(line.split("=", 1))
        metadata = unique_object(rows)
    except UnicodeDecodeError as error:
        raise ReceiptError("Full OTA metadata is not UTF-8") from error
    try:
        post_build = metadata["post-build"]
        parts = post_build.split("/")
        incremental = parts[4].split(":", 1)[0]
        timestamp_text = metadata["post-timestamp"]
        device = metadata["pre-device"]
    except (KeyError, IndexError, AttributeError) as error:
        raise ReceiptError("Full OTA metadata lacks build identity") from error
    if incremental != build_number or device != PRODUCT or not timestamp_text.isdigit():
        raise ReceiptError("Full OTA metadata does not match frankel and the requested build number")
    timestamp = int(timestamp_text)
    if timestamp <= 0:
        raise ReceiptError("Full OTA build timestamp must be positive")
    return {
        "post_build": post_build,
        "post_timestamp": timestamp,
        "post_datetime_utc": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
        "pre_device": device,
    }


def validate_channels(directory: Path, roles: dict[str, str], build_number: str,
                      timestamp: int):
    for channel in ("alpha", "beta", "stable", "testing"):
        path = directory / roles[f"channel_{channel}"]
        try:
            fields = path.read_text().split()
        except (OSError, UnicodeDecodeError) as error:
            raise ReceiptError(f"Cannot read {channel} channel metadata") from error
        if fields != [build_number, str(timestamp), PRODUCT, channel]:
            raise ReceiptError(f"{channel} channel metadata does not match the OTA")


def read_phase1_evidence(directory: Path, source_pins, stage, lock_reference,
                         build_number: str, lock=None):
    """Validate the complete public source/client evidence bundled in a release."""
    try:
        source_path = directory / SOURCE_PROVENANCE
        client_path = directory / CLIENT_PROVENANCE
        execution_path = directory / BUILD_EXECUTION
        bind_path = directory / BUILD_BIND_PROOF
        consumption_path = directory / BUILD_CONSUMPTION
        build_log_path = directory / BUILD_LOG
        source_record = phase1_provenance.validate_source_record_shape(load_json(source_path))
        client_record = phase1_provenance.validate_clients_shape(load_json(client_path))
        execution_record = run_release_build.validate_record_shape(load_json(execution_path))
        bind_record = run_release_build.validate_bind_proof(load_json(bind_path))
        consumption_record = run_release_build.validate_consumption_record(
            load_json(consumption_path))
        run_release_build.bind_proof_matches_execution(bind_record, execution_record)
        if lock is not None:
            phase1_provenance.validate_builder(source_record["builder"], lock)
    except (phase1_provenance.ProvenanceError, run_release_build.ReleaseBuildError,
            KeyError, TypeError, AttributeError, OSError) as error:
        raise ReceiptError(f"Invalid Phase-1 provenance evidence: {error}") from error
    if source_record["lock"] != {"sha256": lock_reference["sha256"],
                                  "size": lock_reference["size"]}:
        raise ReceiptError("Source provenance and GrapheneOS lock identity differ")
    if (source_record["manifest"]["commit"] != source_pins["manifest"]["commit"] or
            source_record["targets"]["production"] != {
                "device": "Pixel 10", "product": PRODUCT, "abi": "arm64-v8a",
                "variant": "user", "lunch_target": LUNCH_TARGET,
                "artifact_scope": "factory_full_incremental_ota_only"} or
            source_record["targets"]["source_matched_emulator"] !=
            phase1_provenance.EMULATOR_TARGET or
            source_record["artifact_claim"] != "source_freeze_only_no_binary_artifacts"):
        raise ReceiptError("Phase-1 source freeze has the wrong target or manifest lineage")
    project_revisions = {row["path"]: row["revision"]
                         for row in source_record["manifest"]["projects"]}
    expected_projects = {
        "frameworks/base": source_pins["frameworks_base"]["commit"],
        "packages/apps/Launcher3": source_pins["launcher3"]["commit"],
        "packages/apps/Updater": source_pins["updater"]["commit"],
        "device/generic/goldfish": source_pins["emulator_goldfish"]["commit"],
    }
    if stage_contract.NATIVE_PATCH_NAMES:
        expected_projects[stage_contract.NATIVE_PROJECT] = source_pins["frameworks_native"]["commit"]
    if any(project_revisions.get(path) != revision for path, revision in expected_projects.items()):
        raise ReceiptError("Phase-1 project ledger differs from receipted source pins")
    if stage_contract.NATIVE_PATCH_NAMES:
        for name, digest in stage["platform_targets"]["frameworks_native"].items():
            qualified = stage_contract.NATIVE_PROJECT + "/" + safe_relative(name).as_posix()
            row = source_record["owned_tracked_changes"].get(qualified) or source_record["generated_inputs"].get(qualified)
            if not isinstance(row, dict) or row.get("sha256") != digest:
                raise ReceiptError("Native target differs from the release source freeze: " + name)
    phase1_tool = stage["tools"].get("android/tools/phase1_provenance.py")
    if (source_record["generator"]["sha256"] != phase1_tool or
            source_record["builder"]["dockerfile"]["sha256"] !=
            stage["tools"].get("android/platform/Dockerfile") or
            client_record["tools"]["generator"]["sha256"] != phase1_tool or
            client_record["tools"]["sdk_verifier"]["sha256"] !=
            stage["tools"].get("android/tools/verify_sdk_publication.py")):
        raise ReceiptError("Phase-1 provenance tools differ from the staged release tools")
    if (client_record["qualification"] != "production" or
            client_record["public_signer"]["der_sha256"] != stage["signer_sha256"]):
        raise ReceiptError("Production client signer differs from the staged OS signer")
    source_reference = hash_file(source_path)
    execution_reference = hash_file(execution_path)
    bind_reference = hash_file(bind_path)
    consumption_reference = hash_file(consumption_path)
    build_log_reference = hash_file(build_log_path)
    execution_tool = stage["tools"].get("android/tools/run_release_build.py")
    locality_tool = stage["tools"].get("android/tools/docker_locality_proof.py")
    if (execution_record["contract"]["build_number"] != build_number or
            execution_record["lock"] != {"sha256": lock_reference["sha256"],
                                         "size": lock_reference["size"]} or
            execution_record["source_record"] != source_reference or
            execution_record["builder"] != source_record["builder"] or
            execution_record["bind_proof"] != bind_reference or
            execution_record["generator"]["sha256"] != execution_tool or
            execution_record["docker_locality"]["generator"]["sha256"] != locality_tool or
            consumption_record["execution"] != execution_reference or
            consumption_record["build_number"] != build_number or
            consumption_record["container"] != {
                "id": execution_record["container"]["id"],
                "name": execution_record["container"]["name"],
            } or consumption_record["docker_locality_sha256"] !=
            execution_record["docker_locality_sha256"] or
            consumption_record["daemon_id"] !=
            execution_record["docker_locality"]["daemon"]["id"] or
            consumption_record["host_boot_id"] !=
            execution_record["docker_locality"]["host_boot_id"] or
            consumption_record["generator"]["sha256"] != execution_tool):
        raise ReceiptError("Build execution does not bind the release source, builder, lock and tools")

    def require_ref(relative: Path, expected):
        path = directory / relative
        if path.is_symlink() or not path.is_file() or hash_file(path) != {
                "sha256": expected["sha256"], "size": expected["size"]}:
            raise ReceiptError(f"Phase-1 evidence differs from its record: {relative.as_posix()}")

    require_ref(SOURCE_PROVENANCE, hash_file(source_path))
    require_ref(CLIENT_PROVENANCE, hash_file(client_path))
    require_ref(BUILD_EXECUTION, hash_file(execution_path))
    require_ref(BUILD_BIND_PROOF, bind_reference)
    require_ref(BUILD_CONSUMPTION, consumption_reference)
    require_ref(BUILD_LOG, execution_record["log"])
    require_ref(PROVENANCE_DIRECTORY / "conformance.apk", client_record["conformance"]["apk"])
    require_ref(PROVENANCE_DIRECTORY / "signer-certificate.x509",
                client_record["public_signer"]["file"])
    require_ref(PROVENANCE_DIRECTORY / "compile/build-receipt.json",
                client_record["source_receipt"])
    require_ref(PROVENANCE_DIRECTORY / "compile/source-freeze.json",
                client_record["source_freeze"]["identity"])
    require_ref(PROVENANCE_DIRECTORY / "compile/conformance-unsigned.apk",
                client_record["conformance"]["unsigned_apk"])
    expected_evidence = {
        "source-provenance.json", "client-provenance.json", "build-execution.json",
        "build-bind-proof.json", "build-container-consumption.json",
        "build.log", "conformance.apk",
        "signer-certificate.x509", "compile/build-receipt.json",
        "compile/source-freeze.json", "compile/conformance-unsigned.apk",
    }
    for name, row in client_record["sdk_publication"]["files"].items():
        require_ref(PROVENANCE_DIRECTORY / "sdk" / safe_relative(name), row)
        expected_evidence.add("sdk/" + name)
    for name, row in client_record["source_freeze"]["files"].items():
        require_ref(PROVENANCE_DIRECTORY / "compile/source" / safe_relative(name),
                    {"sha256": row["sha256"], "size": row["bytes"]})
        expected_evidence.add("compile/source/" + name)
    actual_evidence = walk_regular_files(directory / PROVENANCE_DIRECTORY)
    if set(actual_evidence) != expected_evidence:
        raise ReceiptError("Phase-1 evidence tree has missing or unbound files")

    client_reference = hash_file(client_path)
    return {
        "selected_target": "production",
        "source_record": {
            "path": SOURCE_PROVENANCE.as_posix(), **source_reference,
            "schema": source_record["schema"],
            "manifest_commit": source_record["manifest"]["commit"],
            "project_count": source_record["manifest"]["project_count"],
            "project_ledger_sha256": source_record["manifest"]["project_ledger_sha256"],
            "generated_inputs_sha256": source_record["generated_inputs_sha256"],
            "builder_image_id": source_record["builder"]["image"]["id"],
            "artifact_claim": source_record["artifact_claim"],
        },
        "client_record": {
            "path": CLIENT_PROVENANCE.as_posix(), **client_reference,
            "schema": client_record["schema"], "qualification": "production",
            "coordinate": client_record["coordinate"],
            "signer_sha256": client_record["public_signer"]["der_sha256"],
            "conformance_apk_sha256": client_record["conformance"]["apk"]["sha256"],
            "sdk_publication_sha256": phase1_provenance.canonical_digest(
                client_record["sdk_publication"]["files"]),
            "source_freeze_sha256": client_record["source_freeze"]["files_sha256"],
        },
        "build_execution": {
            "path": BUILD_EXECUTION.as_posix(), **execution_reference,
            "schema": execution_record["schema"], "status": execution_record["status"],
            "build_number": execution_record["contract"]["build_number"],
            "build_datetime": execution_record["contract"]["build_datetime"],
            "builder_image_id": execution_record["contract"]["builder_image_id"],
            "container_id": execution_record["container"]["id"],
            "container_name": execution_record["container"]["name"],
            "docker_daemon_id": execution_record["docker_locality"]["daemon"]["id"],
            "log_path": BUILD_LOG.as_posix(),
            "log_sha256": build_log_reference["sha256"],
            "log_size": build_log_reference["size"],
            "target_files_sha256": execution_record["finalized_inputs"]["target_files"]["sha256"],
            "otatools_sha256": execution_record["finalized_inputs"]["otatools"]["sha256"],
            "launcher_sha256": execution_record["generator"]["sha256"],
        },
        "build_bind_proof": {
            "path": BUILD_BIND_PROOF.as_posix(), **bind_reference,
            "schema": bind_record["schema"],
            "scope": bind_record["scope"],
            "container_id": bind_record["container"]["id"],
            "bindings_sha256": phase1_provenance.canonical_digest(bind_record["bindings"]),
            "generator_sha256": bind_record["generator"]["sha256"],
        },
        "container_consumption": {
            "path": BUILD_CONSUMPTION.as_posix(), **consumption_reference,
            "schema": consumption_record["schema"],
            "status": consumption_record["status"],
            "container_id": consumption_record["container"]["id"],
            "container_name": consumption_record["container"]["name"],
            "execution_sha256": consumption_record["execution"]["sha256"],
            "docker_locality_sha256": consumption_record["docker_locality_sha256"],
            "generator_sha256": consumption_record["generator"]["sha256"],
        },
    }


def validate_receipt_shape(receipt):
    top = {"schema", "kind", "build", "target", "source", "grapheneos_lock",
           "wonad_stage", "updater_stage", "apk_signer_sha256", "artifacts",
           "phase1_provenance", "files", "generator", "artifact_verifier"}
    require_keys(receipt, top, "release receipt")
    if receipt["schema"] != SCHEMA or receipt["kind"] != "wonad-grapheneos-release":
        raise ReceiptError("Unsupported release receipt schema or kind")
    build = receipt["build"]
    require_keys(build, {"number", "post_build", "timestamp", "datetime_utc"}, "build")
    if not isinstance(build["number"], str) or BUILD_NUMBER.fullmatch(build["number"]) is None:
        raise ReceiptError("Invalid receipted build number")
    target = receipt["target"]
    expected_target = {"device": "Pixel 10", "product": PRODUCT,
                       "abi": "arm64-v8a", "variant": "user",
                       "lunch_target": LUNCH_TARGET}
    if target != expected_target:
        raise ReceiptError("Receipt is not for the frozen frankel user target")
    signer = receipt["apk_signer_sha256"]
    if not isinstance(signer, str) or SHA256.fullmatch(signer) is None:
        raise ReceiptError("Invalid public Wonad APK signer digest")
    for field, expected_name in (("generator", "android/tools/release_receipt.py"),
                                 ("artifact_verifier", "android/tools/verify_release_artifacts.py")):
        row = receipt[field]
        require_keys(row, {"name", "sha256", "size"}, field.replace("_", " "))
        if (row["name"] != expected_name or not isinstance(row["sha256"], str) or
                SHA256.fullmatch(row["sha256"]) is None or type(row["size"]) is not int or row["size"] <= 0):
            raise ReceiptError(f"Invalid {field.replace('_', ' ')} identity")
    stage = receipt["wonad_stage"]
    stage_fields = stage_contract.marker_fields() | {"path", "sha256", "size"}
    if (not isinstance(stage, dict) or set(stage) != stage_fields or stage.get("schema") != stage_contract.stage_schema() or
            stage.get("signer_sha256") != signer):
        raise ReceiptError("Wonad stage marker and APK signer identity differ")
    if (not isinstance(stage.get("sha256"), str) or SHA256.fullmatch(stage["sha256"]) is None or
            type(stage.get("size")) is not int or stage["size"] <= 0 or
            stage.get("path") != STAGE_MARKER.as_posix()):
        raise ReceiptError("Invalid Wonad stage marker identity")
    validate_sha_map(stage.get("files"), "receipted Wonad staged files")
    certificate = stage.get("signer_certificate")
    if (not isinstance(certificate, dict) or set(certificate) != {"path", "sha256", "size"} or
            certificate.get("path") != "WonadReleaseCertificate.der" or
            certificate.get("sha256") != signer or type(certificate.get("size")) is not int or
            certificate["size"] < 128 or stage["files"].get(certificate["path"]) != signer):
        raise ReceiptError("Invalid receipted Wonad signer certificate")
    if not isinstance(stage.get("patches"), dict) or set(stage["patches"]) != set(stage_contract.platform_lanes()):
        raise ReceiptError("Invalid receipted patch ledger")
    for name, rows in stage["patches"].items():
        patch_names = stage_contract.platform_lanes()[name][1]
        if (not isinstance(rows, list) or (patch_names and not rows) or
                (not patch_names and rows) or any(
                not isinstance(row, dict) or set(row) != {"name", "sha256"} or
                safe_relative(row["name"]).name != row["name"] or
                not isinstance(row["sha256"], str) or SHA256.fullmatch(row["sha256"]) is None
                for row in rows)):
            raise ReceiptError(f"Invalid receipted {name} patch ledger")
    if (not isinstance(stage.get("platform_targets"), dict) or
            set(stage["platform_targets"]) != set(stage_contract.platform_lanes())):
        raise ReceiptError("Invalid receipted platform target inventory")
    for name, values in stage["platform_targets"].items():
        if stage_contract.platform_lanes()[name][1]:
            validate_sha_map(values, f"receipted {name} target inventory")
        elif values != {}:
            raise ReceiptError("Receipted targets under an empty registered patch lane")
    try:
        stage_contract.marker_owned_targets({name: stage[name] for name in stage_contract.marker_fields()})
    except ValueError as error:
        raise ReceiptError(str(error)) from error
    validate_sha_map(stage.get("tools"), "receipted release tools")
    source = receipt["source"]
    expected_source = {"manifest", "frameworks_base", "launcher3", "updater", "emulator_goldfish"}
    if stage_contract.NATIVE_PATCH_NAMES:
        expected_source.add("frameworks_native")
    if not isinstance(source, dict) or set(source) != expected_source:
        raise ReceiptError("Incomplete pinned source identity")
    for name in source:
        row = source[name]
        if not isinstance(row, dict) or re.fullmatch(r"[0-9a-f]{40}", str(row.get("commit", ""))) is None:
            raise ReceiptError(f"Invalid receipted {name} commit")
    if (stage.get("frameworks_revision") != source["frameworks_base"]["commit"] or
            stage.get("launcher3_revision") != source["launcher3"]["commit"] or
            stage.get("emulator_goldfish_revision") != source["emulator_goldfish"]["commit"] or
            not isinstance(receipt["updater_stage"], dict) or
            receipt["updater_stage"].get("updater_revision") != source["updater"]["commit"]):
        raise ReceiptError("Source pins and ownership markers are inconsistent")
    if stage_contract.NATIVE_PATCH_NAMES:
        native_pin = source["frameworks_native"]
        if (set(native_pin) != {"commit", "manifest_path"} or
                native_pin["manifest_path"] != stage_contract.NATIVE_PROJECT or
                native_pin["commit"] != stage_contract.NATIVE_MANIFEST_REVISION or
                stage["frameworks_native_revision"] != native_pin["commit"]):
            raise ReceiptError("Native stage/source pin differs from its authenticated manifest project")
    provenance = receipt["phase1_provenance"]
    require_keys(provenance, {"selected_target", "source_record", "client_record",
                              "build_execution", "build_bind_proof",
                              "container_consumption"},
                 "Phase-1 provenance")
    if provenance["selected_target"] != "production":
        raise ReceiptError("ARM release must select the production source-freeze target")
    source_record = provenance["source_record"]
    client_record = provenance["client_record"]
    build_execution = provenance["build_execution"]
    build_bind_proof = provenance["build_bind_proof"]
    container_consumption = provenance["container_consumption"]
    require_keys(source_record, {"path", "sha256", "size", "schema", "manifest_commit",
                                 "project_count", "project_ledger_sha256",
                                 "generated_inputs_sha256", "builder_image_id", "artifact_claim"},
                 "source provenance reference")
    require_keys(client_record, {"path", "sha256", "size", "schema", "qualification",
                                 "coordinate", "signer_sha256", "conformance_apk_sha256",
                                 "sdk_publication_sha256", "source_freeze_sha256"},
                 "client provenance reference")
    if (source_record["path"] != SOURCE_PROVENANCE.as_posix() or
            source_record["schema"] != phase1_provenance.SOURCE_SCHEMA or
            source_record["manifest_commit"] != source["manifest"]["commit"] or
            source_record["artifact_claim"] != "source_freeze_only_no_binary_artifacts"):
        raise ReceiptError("Invalid Phase-1 source provenance reference")
    if (not isinstance(source_record["builder_image_id"], str) or
            re.fullmatch(r"sha256:[0-9a-f]{64}", source_record["builder_image_id"]) is None or
            type(source_record["project_count"]) is not int or source_record["project_count"] <= 0):
        raise ReceiptError("Invalid Phase-1 source provenance identity")
    if (client_record["path"] != CLIENT_PROVENANCE.as_posix() or
            client_record["schema"] != phase1_provenance.CLIENT_SCHEMA or
            client_record["qualification"] != "production" or
            client_record["coordinate"] != "org.wonad:desktop-sdk:3.0.1" or
            client_record["signer_sha256"] != signer):
        raise ReceiptError("Invalid Phase-1 client provenance reference")
    for row in (source_record, client_record):
        if (not isinstance(row["sha256"], str) or SHA256.fullmatch(row["sha256"]) is None or
                type(row["size"]) is not int or row["size"] <= 0):
            raise ReceiptError("Invalid Phase-1 record file identity")
    for name in ("project_ledger_sha256", "generated_inputs_sha256"):
        if SHA256.fullmatch(str(source_record[name])) is None:
            raise ReceiptError("Invalid Phase-1 source ledger identity")
    for name in ("conformance_apk_sha256", "sdk_publication_sha256", "source_freeze_sha256"):
        if SHA256.fullmatch(str(client_record[name])) is None:
            raise ReceiptError("Invalid Phase-1 client artifact identity")
    require_keys(build_execution, {
        "path", "sha256", "size", "schema", "status", "build_number",
        "build_datetime", "builder_image_id", "container_id", "container_name",
        "docker_daemon_id", "log_sha256", "target_files_sha256", "otatools_sha256",
        "launcher_sha256", "log_path", "log_size",
    }, "build-execution reference")
    if (build_execution["path"] != BUILD_EXECUTION.as_posix() or
            build_execution["schema"] != run_release_build.SCHEMA or
            build_execution["status"] != "succeeded" or
            build_execution["build_number"] != build["number"] or
            build_execution["log_path"] != BUILD_LOG.as_posix() or
            not isinstance(build_execution["docker_daemon_id"], str) or
            not build_execution["docker_daemon_id"] or
            re.fullmatch(r"sha256:[0-9a-f]{64}",
                         str(build_execution["builder_image_id"])) is None or
            re.fullmatch(r"[0-9a-f]{64}", str(build_execution["container_id"])) is None or
            not isinstance(build_execution["container_name"], str) or
            type(build_execution["log_size"]) is not int or
            build_execution["log_size"] <= 0):
        raise ReceiptError("Invalid production build-execution reference")
    for name in ("sha256", "log_sha256", "target_files_sha256", "otatools_sha256",
                 "launcher_sha256"):
        if SHA256.fullmatch(str(build_execution[name])) is None:
            raise ReceiptError("Invalid build-execution digest")
    if (type(build_execution["size"]) is not int or build_execution["size"] <= 0 or
            re.fullmatch(r"[1-9][0-9]{8,10}", str(build_execution["build_datetime"])) is None):
        raise ReceiptError("Invalid build-execution size or timestamp")
    require_keys(build_bind_proof, {
        "path", "sha256", "size", "schema", "scope", "container_id",
        "bindings_sha256", "generator_sha256",
    }, "live build-bind reference")
    if (build_bind_proof["path"] != BUILD_BIND_PROOF.as_posix() or
            build_bind_proof["schema"] != 1 or
            build_bind_proof["scope"] != "running-gated-container-before-build" or
            build_bind_proof["container_id"] != build_execution["container_id"] or
            type(build_bind_proof["size"]) is not int or build_bind_proof["size"] <= 0):
        raise ReceiptError("Invalid live build-bind proof reference")
    for name in ("sha256", "bindings_sha256", "generator_sha256"):
        if SHA256.fullmatch(str(build_bind_proof[name])) is None:
            raise ReceiptError("Invalid live build-bind proof digest")
    require_keys(container_consumption, {
        "path", "sha256", "size", "schema", "status", "container_id",
        "container_name", "execution_sha256", "docker_locality_sha256",
        "generator_sha256",
    }, "container-consumption reference")
    if (container_consumption["path"] != BUILD_CONSUMPTION.as_posix() or
            container_consumption["schema"] != 1 or
            container_consumption["status"] != "consumed-confirmed-absent" or
            container_consumption["container_id"] != build_execution["container_id"] or
            container_consumption["container_name"] != build_execution["container_name"] or
            type(container_consumption["size"]) is not int or
            container_consumption["size"] <= 0):
        raise ReceiptError("Invalid container-consumption reference")
    for name in ("sha256", "execution_sha256", "docker_locality_sha256",
                 "generator_sha256"):
        if SHA256.fullmatch(str(container_consumption[name])) is None:
            raise ReceiptError("Invalid container-consumption digest")
    files = receipt["files"]
    if not isinstance(files, dict):
        raise ReceiptError("Release file inventory is not an object")
    for name, row in files.items():
        relative = safe_relative(name)
        if private_key_like(relative) or not isinstance(row, dict) or set(row) != {"sha256", "size"}:
            raise ReceiptError(f"Invalid release inventory row: {name}")
        if (not isinstance(row["sha256"], str) or SHA256.fullmatch(row["sha256"]) is None or
                type(row["size"]) is not int or row["size"] < 0):
            raise ReceiptError(f"Invalid release hash or size: {name}")
    roles = artifact_roles(build["number"])
    if receipt["artifacts"] != roles or not set(roles.values()).issubset(files):
        raise ReceiptError("Required release artifacts are incomplete or renamed")
    if (type(build["timestamp"]) is not int or build["timestamp"] <= 0 or
            build["datetime_utc"] != datetime.fromtimestamp(
                build["timestamp"], timezone.utc).isoformat()):
        raise ReceiptError("Invalid receipted build time")
    return roles


def atomic_write(path: Path, data: bytes):
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ReceiptError("Receipt parent must be an existing ordinary directory")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".release-receipt.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def create_receipt(source_value: Path, build_number: str) -> Path:
    if not isinstance(build_number, str) or BUILD_NUMBER.fullmatch(build_number) is None:
        raise ReceiptError("Build number must be exactly 10 decimal digits")
    source_state = verify_release_source(source_value)
    source = dedicated_source(source_value)
    lock = load_json(LOCK_PATH)
    source_pins = source_state["source"]
    stage = source_state["wonad_stage"]
    updater = source_state["updater_stage"]
    directory = release_directory(source, build_number)
    if directory.is_symlink() or not directory.is_dir():
        raise ReceiptError(f"Expected GrapheneOS release directory is missing: {directory}")
    roles = artifact_roles(build_number)
    paths = walk_regular_files(directory, {RECEIPT_NAME})
    missing = sorted(set(roles.values()) - set(paths))
    if missing:
        raise ReceiptError("Missing required release artifacts: " + ", ".join(missing))
    metadata = ota_metadata(paths[roles["full_ota"]], build_number)
    validate_channels(directory, roles, build_number, metadata["post_timestamp"])
    files = {name: hash_file(paths[name]) for name in sorted(paths)}
    lock_ref = hash_file(LOCK_PATH)
    generator_ref = hash_file(Path(__file__))
    verifier_path = ROOT / "android/tools/verify_release_artifacts.py"
    verifier_ref = hash_file(verifier_path)
    provenance = read_phase1_evidence(directory, source_pins, stage,
                                      {"sha256": lock_ref["sha256"], "size": lock_ref["size"]},
                                      build_number, lock)
    receipt = {
        "schema": SCHEMA,
        "kind": "wonad-grapheneos-release",
        "build": {
            "number": build_number,
            "post_build": metadata["post_build"],
            "timestamp": metadata["post_timestamp"],
            "datetime_utc": metadata["post_datetime_utc"],
        },
        "target": {
            "device": lock["production_target"]["device"],
            "product": PRODUCT,
            "abi": "arm64-v8a",
            "variant": "user",
            "lunch_target": LUNCH_TARGET,
        },
        "source": source_pins,
        "grapheneos_lock": {
            "release": lock["release"],
            "sha256": lock_ref["sha256"],
            "size": lock_ref["size"],
        },
        "wonad_stage": stage,
        "updater_stage": updater,
        "apk_signer_sha256": stage["signer_sha256"],
        "phase1_provenance": provenance,
        "artifacts": roles,
        "files": files,
        "generator": {
            "name": "android/tools/release_receipt.py",
            "sha256": generator_ref["sha256"],
            "size": generator_ref["size"],
        },
        "artifact_verifier": {
            "name": "android/tools/verify_release_artifacts.py",
            "sha256": verifier_ref["sha256"],
            "size": verifier_ref["size"],
        },
    }
    validate_receipt_shape(receipt)
    output = directory / RECEIPT_NAME
    encoded = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    atomic_write(output, encoded)
    return output


def verify_receipt(receipt_path: Path):
    if receipt_path.name != RECEIPT_NAME or receipt_path.is_symlink() or not receipt_path.is_file():
        raise ReceiptError(f"Expected an ordinary {RECEIPT_NAME}")
    receipt = load_json(receipt_path)
    roles = validate_receipt_shape(receipt)
    directory = receipt_path.parent
    actual = walk_regular_files(directory, {RECEIPT_NAME})
    expected = receipt["files"]
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    if missing or extra:
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if extra:
            details.append("extra: " + ", ".join(extra))
        raise ReceiptError("Release inventory differs (" + "; ".join(details) + ")")
    for name in sorted(expected):
        observed = hash_file(actual[name])
        if observed != expected[name]:
            raise ReceiptError(f"Release file was tampered with: {name}")
    metadata = ota_metadata(actual[roles["full_ota"]], receipt["build"]["number"])
    if (metadata["post_build"] != receipt["build"]["post_build"] or
            metadata["post_timestamp"] != receipt["build"]["timestamp"]):
        raise ReceiptError("Full OTA identity differs from the receipt")
    validate_channels(directory, roles, receipt["build"]["number"],
                      receipt["build"]["timestamp"])
    provenance = read_phase1_evidence(
        directory, receipt["source"], receipt["wonad_stage"], receipt["grapheneos_lock"],
        receipt["build"]["number"])
    if provenance != receipt["phase1_provenance"]:
        raise ReceiptError("Bundled Phase-1 provenance differs from the release receipt")
    return receipt


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    source = commands.add_parser("verify-source", help="verify exact post-stage release source")
    source.add_argument("--source", type=Path, required=True)
    create = commands.add_parser("create", help="create or atomically replace a release receipt")
    create.add_argument("--source", type=Path, required=True,
                        help="dedicated pinned GrapheneOS source checkout")
    create.add_argument("--build-number", required=True)
    verify = commands.add_parser("verify", help="offline-verify a receipted release directory")
    verify.add_argument("--receipt", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "verify-source":
            result = verify_release_source(arguments.source)
            print(json.dumps({"status": "verified", "source_projects": len(result["source"]),
                              "stage_schema": result["wonad_stage"]["schema"]}, sort_keys=True))
        elif arguments.command == "create":
            output = create_receipt(arguments.source, arguments.build_number)
            print(json.dumps({"status": "created", "receipt": str(output)}))
        else:
            receipt = verify_receipt(arguments.receipt)
            print(json.dumps({"status": "verified", "build": receipt["build"]["number"],
                              "files": len(receipt["files"])}))
        return 0
    except (ReceiptError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
