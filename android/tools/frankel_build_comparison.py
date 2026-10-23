#!/usr/bin/env python3
"""Seal and compare pinned Pixel 10 GrapheneOS baseline/custom builds.

This tool is intentionally limited to unsigned build-comparison evidence.  It
does not sign an image, create release keys, publish an update, or claim that a
build has passed hardware/runtime qualification.  Every receipt is
authenticated by a SHA-256 which must be retained out of band.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[2]
ANDROID = ROOT / "android"
TOOLS = ANDROID / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
import phase1_provenance as provenance  # noqa: E402
import release_receipt  # noqa: E402
import x86_build_comparison as x86  # noqa: E402
import docker_locality_proof as locality  # noqa: E402
import stage_contract  # noqa: E402


LOCK = ANDROID / "grapheneos.lock.json"
LAUNCHER = ANDROID / "tools/run_frankel_build.py"
STAGE_OS = ANDROID / "platform/stage-os.py"
RECEIPT_SCHEMA = 3
COMPARISON_SCHEMA = 3
SHA256 = re.compile(r"[0-9a-f]{64}")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
CONTAINER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
PRODUCT = Path("target/product/frankel")
TARGET_FILES = PRODUCT / "obj/PACKAGING/target_files_intermediates/frankel-target_files.zip"
FIXED_ARTIFACTS = {
    "vendor_boot": PRODUCT / "vendor_boot.img",
    "vendor_kernel_boot": PRODUCT / "vendor_kernel_boot.img",
    "build_fingerprint": PRODUCT / "build_fingerprint-frankel.txt",
    "target_files": TARGET_FILES,
}
OS_ARTIFACTS = dict(x86.OS_PATHS)
NATIVE_ONLY = set(x86.NATIVE_ONLY)
REQUIRED_CHANGED = set(x86.REQUIRED_CHANGED)
TOOLCHAIN_PATHS = {
    "siso": "prebuilts/siso/linux-x86/siso",
    "clang": "prebuilts/clang/host/linux-x86/clang-r584948b/bin/clang",
    "java": "prebuilts/jdk/jdk21/linux-x86/bin/java",
    "soong_ui": "build/soong/soong_ui.bash",
}
VENDOR_ROOT = Path("vendor/google_devices/frankel")
VENDOR_SPEC = Path("vendor/adevtool/vendor-specs/google_devices/frankel.yml")
VENDOR_CONFIG = Path("vendor/adevtool/config/device/common/gen10pixel.yml")
VENDOR_VERSION_FILE = PurePosixPath("adevtool-version-check.mk")
BUILD_ID = "CP3A.261005.005"
BUILD_NUMBER = "2026100600"
BUILDER_DIGEST = "sha256:f719a4a56095b613790ef9afcba2aabda795217ac98e08c24ba5cec65bd4ee33"
BUILDER_REFERENCE = "wonad-grapheneos-builder:2026100600"
SOURCE_AUDIT_JOBS = 4
CONTAINER_RESOURCES = {
    "cpus": 6,
    "memory_bytes": 48 * 1024 ** 3,
    "memory_swap_bytes": 48 * 1024 ** 3,
    "pids_limit": 4096,
}
HELPER_FILES = {
    "frankel_comparison": Path(__file__).resolve(),
    "x86_comparison": ANDROID / "tools/x86_build_comparison.py",
    "phase1_provenance": ANDROID / "tools/phase1_provenance.py",
    "release_receipt": ANDROID / "tools/release_receipt.py",
    "docker_locality_proof": ANDROID / "tools/docker_locality_proof.py",
    "frankel_launcher": LAUNCHER,
    "stage_os": STAGE_OS,
}


class ComparisonError(ValueError):
    """A fail-closed Frankel build-evidence error."""


def require(condition, message):
    if not condition:
        raise ComparisonError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def parse_json(payload: bytes | str, label: str):
    try:
        return json.loads(payload, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ComparisonError(f"Invalid JSON in {label}: {error}") from error


def canonical_digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def safe_relative(value: str) -> PurePosixPath:
    try:
        return provenance.safe_relative(value)
    except (ValueError, provenance.ProvenanceError) as error:
        raise ComparisonError(str(error)) from error


def stat_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def open_regular(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ComparisonError(f"Cannot safely open evidence input {path}: {error}") from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), f"Evidence input is not an ordinary file: {path}")
        return descriptor, before
    except BaseException:
        os.close(descriptor)
        raise


def close_stable(path: Path, descriptor: int, before, size: int):
    after = os.fstat(descriptor)
    try:
        current = os.lstat(path)
    except OSError as error:
        raise ComparisonError(f"Evidence input disappeared while reading: {path}: {error}") from error
    require(stat.S_ISREG(current.st_mode) and stat_identity(before) == stat_identity(after) ==
            stat_identity(current) and size == before.st_size,
            f"Evidence input or pathname changed while reading: {path}")


def stable_file_ref(path: Path, *, allow_empty=False):
    """Stream one stable ordinary file and revalidate its pathname identity."""
    descriptor, before = open_regular(path)
    digest = hashlib.sha256()
    size = 0
    try:
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            size += len(block)
            digest.update(block)
        close_stable(path, descriptor, before, size)
    finally:
        os.close(descriptor)
    require(allow_empty or size > 0, f"Empty evidence file: {path}")
    return {"sha256": digest.hexdigest(), "size": size}


def stable_bytes(path: Path, *, maximum_size=None):
    """Read a bounded parse input through one descriptor and bind that inode."""
    descriptor, before = open_regular(path)
    chunks = []
    size = 0
    digest = hashlib.sha256()
    try:
        require(maximum_size is None or before.st_size <= maximum_size,
                f"Evidence input is unexpectedly large: {path}")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            size += len(block)
            chunks.append(block)
            digest.update(block)
        close_stable(path, descriptor, before, size)
    finally:
        os.close(descriptor)
    return b"".join(chunks), {"sha256": digest.hexdigest(), "size": size}


def ordinary_ref(path: Path, *, allow_empty=False):
    return stable_file_ref(path, allow_empty=allow_empty)


def helper_ledger():
    expected_modules = {
        "x86_comparison": Path(x86.__file__).resolve(),
        "phase1_provenance": Path(provenance.__file__).resolve(),
        "release_receipt": Path(release_receipt.__file__).resolve(),
        "docker_locality_proof": Path(locality.__file__).resolve(),
    }
    for name, actual in expected_modules.items():
        require(actual == HELPER_FILES[name].resolve(),
                f"Imported helper resolved outside the reviewed path: {name}")
    result = {}
    for name, path in sorted(HELPER_FILES.items()):
        require(path.is_absolute(), f"Helper path is not absolute: {name}")
        result[name] = {"path": path.relative_to(ROOT).as_posix(), **ordinary_ref(path)}
    return result


def validate_helper_ledger(value):
    current = helper_ledger()
    require(value == current, "Receipt helper/tool ledger differs from the current verifier")
    return current


def exact_path(value: Path, label: str, *, directory=False) -> Path:
    require(value.is_absolute() and not value.is_symlink(),
            f"{label} must be a literal absolute non-symlink path")
    try:
        resolved = value.resolve(strict=True)
    except OSError as error:
        raise ComparisonError(f"Cannot resolve {label}: {error}") from error
    require(resolved == value and (value.is_dir() if directory else value.is_file()),
            f"{label} must be canonical and {'a directory' if directory else 'an ordinary file'}")
    return value


def confined_path(root: Path, relative_value: str | Path, label: str,
                  *, allow_absent=False) -> Path:
    relative = safe_relative(PurePosixPath(relative_value).as_posix())
    current = root
    require(root.is_dir() and not root.is_symlink(), f"{label} root is not an ordinary directory")
    for index, part in enumerate(relative.parts):
        current = current / part
        final = index == len(relative.parts) - 1
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            require(allow_absent, f"{label} is absent: {relative.as_posix()}")
            return root.joinpath(*relative.parts)
        except OSError as error:
            raise ComparisonError(f"Cannot inspect {label} component {current}: {error}") from error
        require(not stat.S_ISLNK(mode),
                f"{label} contains a symlink component: {relative.as_posix()}")
        if not final:
            require(stat.S_ISDIR(mode),
                    f"{label} parent is not a directory: {relative.as_posix()}")
    return current


def within(path: Path, tree: Path) -> bool:
    try:
        return x86.within_filesystem(path, tree)
    except x86.ComparisonError as error:
        raise ComparisonError(str(error)) from error


def load_stage_module():
    spec = importlib.util.spec_from_file_location("wonad_frankel_stage", STAGE_OS)
    require(spec is not None and spec.loader is not None, "Cannot load stage-os verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def authenticated_manifest(source: Path, lock):
    try:
        return x86.authenticated_manifest(source, lock)
    except (x86.ComparisonError, provenance.ProvenanceError) as error:
        raise ComparisonError(str(error)) from error


def expected_version_check(revision: str) -> bytes:
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None,
            "Invalid pinned adevtool revision")
    return (
        f"ifneq ($(shell git -C vendor/adevtool rev-parse HEAD),{revision})\n"
        "  $(error frankel vendor module is outdated. Run `adevtool generate-all -d frankel` to update it)\n"
        "endif"
    ).encode()


def parse_vendor_spec(path: Path):
    payload, reference = stable_bytes(path, maximum_size=16 * 1024 * 1024)
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ComparisonError("Frankel vendor specification is not UTF-8") from error
    files, directories = {}, set()
    for line in lines:
        require(line and not line[0].isspace() and ": " in line,
                "Malformed Frankel vendor specification")
        name, value = line.split(": ", 1)
        relative = safe_relative(name).as_posix()
        require(relative not in files and relative not in directories,
                f"Duplicate Frankel vendor specification path: {relative}")
        if value == "dir":
            directories.add(relative)
        else:
            require(SHA256.fullmatch(value) is not None,
                    f"Invalid Frankel vendor digest: {relative}")
            files[relative] = value
    require(files and directories and "AndroidProducts.mk" in files and "frankel.mk" in files,
            "Frankel vendor specification is incomplete")
    return files, directories, reference


def collect_vendor(source: Path):
    root = source / VENDOR_ROOT
    spec_path = source / VENDOR_SPEC
    config_path = source / VENDOR_CONFIG
    require(root.is_dir() and not root.is_symlink(), "Generated Frankel vendor tree is absent")
    require(spec_path.is_file() and not spec_path.is_symlink(), "Pinned Frankel vendor spec is absent")
    require(config_path.is_file() and not config_path.is_symlink(), "Pinned Pixel 10 config is absent")
    expected_files, expected_directories, spec_ref = parse_vendor_spec(spec_path)
    try:
        config_payload, config_ref = stable_bytes(config_path, maximum_size=1024 * 1024)
        config = config_payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ComparisonError(f"Cannot read pinned Pixel 10 config: {error}") from error
    require(re.search(r"(?m)^\s*build_id:\s*" + re.escape(BUILD_ID) + r"\s*$", config),
            "Pinned Pixel 10 vendor BUILD_ID differs")
    try:
        adevtool_revision = provenance.git_bytes(source / "vendor/adevtool", "rev-parse", "HEAD").decode().strip()
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error
    version_payload = expected_version_check(adevtool_revision)
    expected_files[VENDOR_VERSION_FILE.as_posix()] = hashlib.sha256(version_payload).hexdigest()

    actual_files, actual_directories = {}, set()
    for directory, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        for name in directory_names:
            path = base / name
            relative = path.relative_to(root).as_posix()
            require(not path.is_symlink() and path.is_dir(),
                    f"Frankel vendor directory is not ordinary: {relative}")
            actual_directories.add(relative)
        for name in file_names:
            path = base / name
            relative = path.relative_to(root).as_posix()
            require(not path.is_symlink() and path.is_file(),
                    f"Frankel vendor file is not ordinary: {relative}")
            actual_files[relative] = path
    require(actual_directories == expected_directories,
            "Frankel vendor directory inventory differs from its pinned spec: "
            f"extra={sorted(actual_directories - expected_directories)[:8]} "
            f"missing={sorted(expected_directories - actual_directories)[:8]}")
    require(set(actual_files) == set(expected_files),
            "Frankel vendor file inventory differs from its pinned spec: "
            f"extra={sorted(set(actual_files) - set(expected_files))[:8]} "
            f"missing={sorted(set(expected_files) - set(actual_files))[:8]}")

    def one(item):
        name, path = item
        row = ordinary_ref(path, allow_empty=True)
        require(row["sha256"] == expected_files[name],
                f"Frankel vendor file differs from pinned spec: {name}")
        return name, row

    with ThreadPoolExecutor(max_workers=min(16, len(actual_files))) as pool:
        ledger = dict(pool.map(one, sorted(actual_files.items())))
    version_actual, version_ref = stable_bytes(
        actual_files[VENDOR_VERSION_FILE.as_posix()], maximum_size=64 * 1024)
    require(version_actual == version_payload and
            version_ref == ledger[VENDOR_VERSION_FILE.as_posix()],
            "Frankel vendor revision guard differs from the pinned adevtool generator")
    result = {
        "root": VENDOR_ROOT.as_posix(),
        "build_id": BUILD_ID,
        "adevtool_revision": adevtool_revision,
        "spec": {"path": VENDOR_SPEC.as_posix(), **spec_ref},
        "config": {"path": VENDOR_CONFIG.as_posix(), **config_ref},
        "directories": sorted(actual_directories),
        "files": dict(sorted(ledger.items())),
    }
    result["identity_sha256"] = canonical_digest({
        "directories": result["directories"], "files": result["files"]})
    return result


def require_vendor_caches_absent(source: Path):
    for relative in (
            "vendor/adevtool/node_modules", "vendor/adevtool/.cache",
            "vendor/adevtool/cache", "vendor/adevtool/.yarn", "vendor/adevtool/lib",
            "vendor/adevtool/dist", "out_adevtool_deps"):
        path = source / relative
        require(not path.exists() and not path.is_symlink(),
                f"Regenerable adevtool cache is present: {relative}")
    return True


def marker_owned_targets(marker):
    try:
        return x86.marker_owned_targets(marker)
    except x86.ComparisonError as error:
        raise ComparisonError(str(error)) from error


def signer_identity(certificate: Path, source: Path, *, allow_staged=False):
    require(certificate.is_absolute() and not certificate.is_symlink() and certificate.is_file(),
            "Custom certificate must be a literal absolute public certificate")
    staged = source / "external/wonad/WonadReleaseCertificate.der"
    require(not within(certificate, source) or
            (allow_staged and certificate == staged),
            "Custom certificate must remain outside the source")
    try:
        value = provenance.public_certificate(certificate)
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error
    # A PEM selected at launch and its canonical staged DER have different
    # file hashes but the same certificate identity.  Store only the canonical
    # identity so later verification can use the schema-4-owned DER copy.
    return {key: value[key] for key in ("der_sha256", "der_size", "subject")}


def scan_source(source: Path, states, role: str, marker, updater, vendor,
                manifest_materializations):
    tracked, changed = set(), set()
    for project_path, dirty, project_tracked in states:
        tracked.update(f"{project_path}/{name}" for name in project_tracked)
        changed.update(f"{project_path}/{name}" for name in dirty)
    if role == "baseline":
        expected_changed = set()
        expected_generated = {f"{VENDOR_ROOT.as_posix()}/{name}" for name in vendor["files"]}
    else:
        owned = marker_owned_targets(marker)
        owned["packages/apps/Updater/res/values/config.xml"] = updater["configured_sha256"]
        expected_changed = set(owned) & tracked
        expected_generated = {f"{VENDOR_ROOT.as_posix()}/{name}" for name in vendor["files"]}
        expected_generated.add("external/wonad/.wonad-stage.json")
        expected_generated.update("external/wonad/" + safe_relative(name).as_posix()
                                  for name in marker["files"])
        expected_generated.add(".wonad-updater-stage.json")
        expected_generated.update(set(owned) - tracked)
    require(changed == expected_changed,
            "Tracked source changes differ from the role contract: "
            f"extra={sorted(changed - expected_changed)[:8]} "
            f"missing={sorted(expected_changed - changed)[:8]}")
    changed_rows, generated_rows = {}, {}
    for directory, directory_names, file_names in os.walk(source, topdown=True, followlinks=False):
        base = Path(directory)
        if base == source:
            directory_names[:] = [name for name in directory_names if name != ".repo"]
        directory_names[:] = [name for name in directory_names if name != ".git"]
        for name in [*directory_names, *file_names]:
            path = base / name
            relative = path.relative_to(source).as_posix()
            if name == ".git":
                continue
            try:
                mode = path.lstat().st_mode
            except OSError as error:
                raise ComparisonError(f"Cannot stat source entry {relative}: {error}") from error
            if stat.S_ISDIR(mode):
                continue
            if relative in manifest_materializations:
                continue
            if relative in tracked:
                if relative in changed:
                    require(stat.S_ISREG(mode), f"Changed source target is not ordinary: {relative}")
                    changed_rows[relative] = provenance.file_ref(
                        path, relative=PurePosixPath(relative), include_mode=True)
                continue
            require(relative in expected_generated,
                    f"Untracked or ignored source input is not role-owned: {relative}")
            require(stat.S_ISREG(mode), f"Generated source input is not ordinary: {relative}")
            generated_rows[relative] = provenance.file_ref(
                path, relative=PurePosixPath(relative), include_mode=True)
    require(set(changed_rows) == expected_changed and set(generated_rows) == expected_generated,
            "Role-owned source inventory changed during capture")
    return dict(sorted(changed_rows.items())), dict(sorted(generated_rows.items()))


def collect_source_snapshot(source_value: Path, role: str, certificate: Path | None,
                            lock_path: Path = LOCK, jobs: int = SOURCE_AUDIT_JOBS,
                            *, allow_staged_certificate=False):
    require(role in {"baseline", "custom"}, "Role must be baseline or custom")
    require(type(jobs) is int and 1 <= jobs <= 72, "Source audit jobs must be 1..72")
    try:
        source = provenance.dedicated_source(source_value)
        provenance.forbidden_roots_absent(source)
        lock = provenance.validate_lock(provenance.load_json(lock_path))
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error
    require(lock["release"] == "2026100600" and lock["device"] == "frankel" and
            lock["production_target"] == {
                "device": "Pixel 10", "product": "frankel", "abi": "arm64-v8a",
                "variant": "user", "hardware_qualified": False},
            "Lock does not select the pinned Pixel 10 ARM64 user source")
    manifest_head, default_ref, projects, manifest_payload = authenticated_manifest(source, lock)
    require_vendor_caches_absent(source)
    vendor = collect_vendor(source)
    marker_path = source / "external/wonad/.wonad-stage.json"
    updater_path = source / ".wonad-updater-stage.json"
    if role == "baseline":
        require(certificate is None, "Baseline source forbids a Wonad certificate")
        require(not (source / "external/wonad").exists() and not marker_path.is_symlink(),
                "Baseline source contains Wonad staging")
        require(not updater_path.exists() and not updater_path.is_symlink(),
                "Baseline source contains Updater staging")
        marker = updater = signer = None
        stage = {"state": "absent"}
    else:
        require(certificate is not None, "Custom source requires a public Wonad certificate")
        signer = signer_identity(certificate, source, allow_staged=allow_staged_certificate)
        try:
            marker = load_stage_module().verify_stage(source)
            updater = release_receipt.read_updater_marker(source, lock)
        except (ValueError, release_receipt.ReceiptError, OSError) as error:
            raise ComparisonError(f"Custom stage verification failed: {error}") from error
        require(marker.get("schema") == stage_contract.stage_schema() and marker.get("signer_sha256") == signer["der_sha256"],
                "Schema-4 stage signer differs from the selected public certificate")
        stage = {
            "state": f"schema-{stage_contract.stage_schema()}-with-project-updater",
            "marker": marker,
            "marker_ref": ordinary_ref(marker_path),
            "signer": signer,
            "updater": updater,
        }
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        try:
            audited_states = list(pool.map(
                lambda row: provenance.project_state(source, row, include_audit=True), projects))
        except provenance.ProvenanceError as error:
            raise ComparisonError(str(error)) from error
    states = [state[:3] for state in audited_states]
    materializations = {}
    for project_path, _dirty, _tracked, audit in audited_states:
        row = {
            "gitlinks": audit["gitlinks"],
            "materialized_eol": audit["materialized_eol"],
            "materialized_lfs": audit["materialized_lfs"],
        }
        try:
            provenance.validate_worktree_materializations(
                row, label=f"Frankel project {project_path}")
        except provenance.ProvenanceError as error:
            raise ComparisonError(str(error)) from error
        materializations[project_path] = row
    materializations = dict(sorted(materializations.items()))
    try:
        manifest_materializations = provenance.manifest_checkout_materializations(
            source, manifest_payload, projects, states)
        changed, generated = scan_source(
            source, states, role, marker, updater, vendor, manifest_materializations)
        require(provenance.manifest_checkout_materializations(
                    source, manifest_payload, projects, states) ==
                manifest_materializations,
                "Manifest checkout materializations changed during Frankel source audit")
        require(provenance.file_ref(source / ".repo/manifests/default.xml") == default_ref and
                provenance.git_bytes(source / ".repo/manifests", "show",
                                     manifest_head + ":default.xml") == manifest_payload,
                "Authenticated manifest changed during Frankel source audit")
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            final_audited_states = list(pool.map(
                lambda row: provenance.project_state(source, row, include_audit=True), projects))
        require(final_audited_states == audited_states,
                "Project worktrees changed during Frankel source audit")
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error
    repo = source / ".repo/repo"
    try:
        repo_head = provenance.git_bytes(repo, "rev-parse", "HEAD").decode().strip()
        repo_dirty = provenance.git_bytes(repo, "status", "--porcelain", "-z", "--untracked-files=all")
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error
    require(repo_head == lock["repo_tool"]["commit"] and not repo_dirty,
            "repo tool identity/worktree differs from the lock")
    ledger = [{key: row[key] for key in ("path", "name", "revision", "remote")}
              for row in projects]
    return {
        "pin": {
            "release": lock["release"], "lock": provenance.file_ref(lock_path),
            "manifest_commit": manifest_head,
            "manifest_tag_object": lock["manifest"]["tag_object"],
            "default_xml": default_ref, "projects": ledger,
            "project_count": len(ledger), "project_ledger_sha256": canonical_digest(ledger),
            "repo_tool_commit": repo_head,
        },
        "vendor": vendor,
        "stage": stage,
        "owned_tracked_changes": changed,
        "generated_inputs": generated,
        "worktree_materializations": materializations,
        "worktree_materializations_sha256": canonical_digest(materializations),
    }


def collect_toolchain(source: Path):
    result = {}
    for label, relative in TOOLCHAIN_PATHS.items():
        path = source / safe_relative(relative)
        require(path.is_file() and not path.is_symlink(), f"Pinned toolchain input is absent: {relative}")
        if label in {"siso", "clang", "java", "soong_ui"}:
            require(os.access(path, os.X_OK), f"Pinned toolchain input is not executable: {relative}")
        result[label] = {"path": relative, **ordinary_ref(path)}
    return result


def artifact_record(out_dir: Path, relative: Path, *, allow_absent=False):
    path = confined_path(out_dir, relative, "Frankel artifact", allow_absent=allow_absent)
    if not os.path.lexists(path):
        return {"path": relative.as_posix(), "state": "absent"}
    require(stat.S_ISREG(path.lstat().st_mode),
            f"Frankel artifact is not ordinary: {relative}")
    return {"path": relative.as_posix(), "state": "present", **ordinary_ref(path)}


def stable_target_files(path: Path):
    """Hash and inspect one target-files inode without reopening its pathname."""
    descriptor, before = open_regular(path)
    digest = hashlib.sha256()
    size = 0
    try:
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            size += len(block)
            digest.update(block)
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), "rb") as stream, zipfile.ZipFile(stream) as archive:
            infos = archive.infolist()
            names = [row.filename for row in infos]
            require(len(names) == len(set(names)), "Target-files ZIP contains duplicate entries")
            for row in infos:
                name = PurePosixPath(row.filename.rstrip("/"))
                require(row.filename and not name.is_absolute() and
                        all(part not in {"", ".", ".."} for part in name.parts),
                        "Target-files ZIP contains an unsafe entry")
            misc_rows = [row for row in infos if row.filename == "META/misc_info.txt"]
            require(len(misc_rows) == 1 and misc_rows[0].file_size <= 1024 * 1024,
                    "Target-files ZIP lacks one bounded misc_info.txt")
            misc_payload = archive.read(misc_rows[0])
        close_stable(path, descriptor, before, size)
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise ComparisonError(f"Cannot inspect target-files ZIP: {error}") from error
    finally:
        os.close(descriptor)
    try:
        misc = {}
        for line in misc_payload.decode("utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            require("=" in line, "Malformed target-files misc_info.txt")
            key, value = line.split("=", 1)
            require(key and key not in misc, "Duplicate target-files metadata key")
            misc[key] = value
    except UnicodeDecodeError as error:
        raise ComparisonError("Target-files metadata is not UTF-8") from error
    require(misc.get("build_number") in {None, BUILD_NUMBER} and
            misc.get("build_id") in {None, BUILD_ID},
            "Target-files metadata differs from fixed build identity")
    return ({"sha256": digest.hexdigest(), "size": size},
            {"misc_info": ordinary_ref_from_bytes(misc_payload),
             "entry_count": len(names), "build_id": misc.get("build_id"),
             "build_number": misc.get("build_number")})


def safe_target_files_metadata(path: Path):
    return stable_target_files(path)[1]


def ordinary_ref_from_bytes(payload: bytes):
    return {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}


def collect_artifacts(out_dir: Path, role: str):
    require(role in {"baseline", "custom"}, "Artifact role must be baseline or custom")
    rows = {label: artifact_record(out_dir, relative)
            for label, relative in FIXED_ARTIFACTS.items() if label != "target_files"}
    target_path = confined_path(out_dir, TARGET_FILES, "Frankel target-files artifact")
    target_ref, metadata = stable_target_files(target_path)
    rows["target_files"] = {
        "path": TARGET_FILES.as_posix(), "state": "present", **target_ref,
    }
    intermediates = confined_path(out_dir, Path("soong/.intermediates"),
                                  "Soong intermediates")
    require(stat.S_ISDIR(intermediates.lstat().st_mode),
            "Soong intermediates is not an ordinary directory")
    candidates = []
    for directory, directory_names, file_names in os.walk(
            intermediates, topdown=True, followlinks=False):
        base = Path(directory)
        directory_names[:] = [name for name in directory_names
                              if not (base / name).is_symlink()]
        if "otatools.zip" in file_names:
            relative = (base / "otatools.zip").relative_to(out_dir)
            candidate = confined_path(out_dir, relative, "Soong otatools artifact")
            require(stat.S_ISREG(candidate.lstat().st_mode),
                    "Soong otatools artifact is not ordinary")
            candidates.append(candidate)
    require(len(candidates) == 1, "Expected exactly one Soong otatools.zip artifact")
    otatools = candidates[0]
    rows["otatools"] = {"path": otatools.relative_to(out_dir).as_posix(),
                        "state": "present", **ordinary_ref(otatools)}
    os_rows = {
        label: artifact_record(out_dir, PRODUCT / Path(relative),
                               allow_absent=role == "baseline" and label in NATIVE_ONLY)
        for label, relative in sorted(OS_ARTIFACTS.items())
    }
    if role == "baseline":
        require(all(os_rows[label]["state"] == "absent" for label in NATIVE_ONLY),
                "Baseline unexpectedly contains Wonad native libraries")
    else:
        require(all(row["state"] == "present" for row in os_rows.values()),
                "Custom Frankel output lacks a Wonad OS artifact")
    fingerprint_path = confined_path(out_dir, FIXED_ARTIFACTS["build_fingerprint"],
                                     "Frankel build fingerprint")
    try:
        fingerprint_payload, fingerprint_ref = stable_bytes(fingerprint_path)
        fingerprint = fingerprint_payload.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ComparisonError(f"Cannot read Frankel build fingerprint: {error}") from error
    require(fingerprint_ref == {key: rows["build_fingerprint"][key]
                                for key in ("sha256", "size")},
            "Frankel build fingerprint changed during artifact capture")
    require(re.fullmatch(r"[^/\s]+/frankel/frankel:[^/\s]+/" + re.escape(BUILD_ID) +
                         r"/" + re.escape(BUILD_NUMBER) + r":user/[^/\s]+", fingerprint),
            "Frankel build fingerprint differs from the fixed user-build identity")
    return {"files": dict(sorted(rows.items())), "os_artifacts": os_rows,
            "fingerprint": fingerprint,
            "target_files_metadata": metadata}


def validate_build_log(path: Path):
    payload, reference = stable_bytes(path)
    require(b"\x00" not in payload, "Build log contains NUL bytes")
    statuses = re.findall(rb"^#### (build completed successfully|failed to build some targets).*####\s*$",
                          payload, re.MULTILINE)
    require(statuses == [b"build completed successfully"],
            "Build log does not prove exactly one successful build")
    expected = {"TARGET_PRODUCT": "frankel", "TARGET_BUILD_VARIANT": "user",
                "TARGET_ARCH": "arm64", "OUT_DIR": "out"}
    for key, value in expected.items():
        actual = {item.decode() for item in re.findall(
            rb"^" + key.encode() + rb"=([^\r\n]+)$", payload, re.MULTILINE)}
        require(actual == {value}, f"Build log {key} differs from the Frankel contract")
    return {**reference, "status": "success"}


def collect_build_engine(source: Path, out_dir: Path):
    try:
        return x86.collect_build_engine(source, out_dir)
    except x86.ComparisonError as error:
        raise ComparisonError(str(error)) from error


def environment_map(rows):
    require(isinstance(rows, list), "Container environment is malformed")
    result = {}
    for row in rows:
        require(isinstance(row, str) and "=" in row, "Container environment entry is malformed")
        key, value = row.split("=", 1)
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) and key not in result,
                "Container environment has an invalid or duplicate name")
        result[key] = value
    return dict(sorted(result.items()))


def docker_inspect(reference: str):
    require(CONTAINER_ID.fullmatch(reference) or CONTAINER_NAME.fullmatch(reference),
            "Container must be selected by a safe full ID or name")
    try:
        environment = locality.command_environment(os.environ)
        locality.trusted_local_docker(environment)
        payload = locality.docker(["container", "inspect", reference],
                                  environment=environment)
    except locality.ProofError as error:
        raise ComparisonError(f"Cannot inspect retained build container: {error}") from error
    try:
        rows = parse_json(payload, "Docker container inspect")
    except ComparisonError as error:
        raise ComparisonError("Docker returned invalid container JSON") from error
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict),
            "Docker must return exactly one retained container")
    return rows[0]


def container_logs(container_id: str):
    require(CONTAINER_ID.fullmatch(str(container_id)), "Docker logs require one full container ID")
    try:
        environment = locality.command_environment(os.environ)
        locality.trusted_local_docker(environment)
        result = subprocess.run([str(locality.DOCKER), "--host", locality.ENDPOINT,
                                 "container", "logs", container_id],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                env=environment, timeout=300)
    except (OSError, subprocess.TimeoutExpired, locality.ProofError) as error:
        raise ComparisonError(f"Cannot read retained container logs: {error}") from error
    require(result.returncode == 0, "Docker could not read retained container logs")
    return result.stdout


def validate_container_record(record, source: Path, out_dir: Path, build_log_ref,
                              builder, process_command):
    expected_mounts = [
        {"destination": "/sources", "mode": "rw", "propagation": "rprivate",
         "rw": True, "source": str(source), "type": "bind"},
        {"destination": "/sources/out", "mode": "rw", "propagation": "rprivate",
         "rw": True, "source": str(out_dir), "type": "bind"},
    ]
    expected_keys = {
        "id", "name", "image", "image_reference", "created", "started_at", "finished_at",
        "exit_code", "oom_killed", "user", "working_dir", "entrypoint", "command",
        "inherited_environment", "network_mode", "security_opt", "auto_remove",
        "privileged", "cap_add", "devices", "cap_drop", "group_add", "device_requests",
        "device_cgroup_rules", "tmpfs", "readonly_rootfs", "ipc_mode", "pid_mode",
        "uts_mode", "userns_mode", "restart_policy", "restart_count", "attach_stdout",
        "attach_stderr", "attach_stdin", "labels", "mounts", "logs",
        "resource_limits",
    }
    require(isinstance(record, dict) and set(record) == expected_keys,
            "Unexpected retained-container evidence fields")
    require(CONTAINER_ID.fullmatch(str(record["id"])) and
            CONTAINER_NAME.fullmatch(str(record["name"])),
            "Invalid retained-container identity")
    require(record["image"] == builder["image"]["id"] == BUILDER_DIGEST and
            record["image_reference"] == BUILDER_DIGEST,
            "Retained container did not use the exact locked builder image ID")
    for name in ("created", "started_at", "finished_at"):
        require(isinstance(record[name], str) and record[name] and
                record[name] != "0001-01-01T00:00:00Z",
                f"Invalid retained-container {name}")
    require(type(record["exit_code"]) is int and record["exit_code"] == 0 and
            record["oom_killed"] is False,
            "Retained container did not exit successfully")
    require(record["user"] == "1000:1000" and record["working_dir"] == "/sources" and
            record["entrypoint"] == ["/usr/bin/env"] and
            record["command"] == process_command and
            record["inherited_environment"] ==
            environment_map(builder["image"]["config"]["Env"]),
            "Retained-container process contract differs")
    require(isinstance(record["labels"], dict) and
            set(record["labels"]) == {
                "org.wonad.phase1.attempt", "org.wonad.phase1.locality"} and
            all(SHA256.fullmatch(str(value)) for value in record["labels"].values()),
            "Retained-container attempt/locality labels differ")
    require(record["network_mode"] == "none" and
            record["security_opt"] == ["label=disable"] and
            record["auto_remove"] is False and record["privileged"] is False and
            record["cap_add"] == [] and record["devices"] == [] and
            record["cap_drop"] == ["ALL"] and record["group_add"] == [] and
            record["device_requests"] == [] and record["device_cgroup_rules"] == [] and
            record["tmpfs"] == {} and record["readonly_rootfs"] is False and
            record["ipc_mode"] == "private" and record["pid_mode"] == "" and
            record["uts_mode"] == "" and record["userns_mode"] == "" and
            record["restart_policy"] == {"maximum_retry_count": 0, "name": "no"} and
            type(record["restart_count"]) is int and record["restart_count"] == 0 and
            record["attach_stdout"] is True and record["attach_stderr"] is True and
            record["attach_stdin"] is False,
            "Retained-container isolation contract differs")
    require(record["resource_limits"] == {
                "cpus": CONTAINER_RESOURCES["cpus"],
                "nano_cpus": CONTAINER_RESOURCES["cpus"] * 10 ** 9,
                "memory_bytes": CONTAINER_RESOURCES["memory_bytes"],
                "memory_swap_bytes": CONTAINER_RESOURCES["memory_swap_bytes"],
                "pids_limit": CONTAINER_RESOURCES["pids_limit"],
            },
            "Retained-container resource limits differ from the fixed profile")
    require(record["mounts"] == expected_mounts,
            "Retained-container source/OUT_DIR mounts differ from the fixed topology")
    require(record["logs"] == build_log_ref,
            "Retained-container log identity differs from the supplied build log")
    return record


def collect_container(reference: str, source: Path, out_dir: Path, build_log: Path,
                      builder, process_command):
    require(all(character not in str(source) and character not in str(out_dir)
                for character in (":", "\n", "\r")),
            "Build mount paths contain unsupported characters")
    info = docker_inspect(reference)
    state, config, host, mounts = (info.get("State"), info.get("Config"),
                                   info.get("HostConfig"), info.get("Mounts"))
    require(all(isinstance(row, dict) for row in (state, config, host)) and isinstance(mounts, list),
            "Retained container inspect is incomplete")
    container_id = info.get("Id")
    raw_name = info.get("Name")
    require(CONTAINER_ID.fullmatch(str(container_id)) and isinstance(raw_name, str) and
            raw_name.startswith("/") and CONTAINER_NAME.fullmatch(raw_name[1:]),
            "Retained container identity is invalid")
    require(state.get("Status") == "exited" and state.get("Running") is False and
            state.get("Paused") is False and state.get("Restarting") is False and
            state.get("Dead") is False and state.get("Error") == "" and
            type(state.get("ExitCode")) is int and state["ExitCode"] == 0 and
            state.get("OOMKilled") is False,
            "Retained container is not a clean successful exit")
    require(info.get("Image") == BUILDER_DIGEST and config.get("Image") == BUILDER_DIGEST and
            config.get("User") == "1000:1000" and config.get("WorkingDir") == "/sources" and
            config.get("Entrypoint") == ["/usr/bin/env"] and config.get("Cmd") == process_command and
            config.get("AttachStdout") is True and config.get("AttachStderr") is True and
            config.get("AttachStdin") is False and config.get("OpenStdin") is False and
            config.get("Tty") is False,
            "Retained container process/image contract differs")
    inherited = environment_map(config.get("Env"))
    expected_inherited = environment_map(builder["image"]["config"]["Env"])
    require(inherited == expected_inherited,
            "Container image environment differs; env -i process isolation is not auditable")
    require(host.get("NetworkMode") == "none" and host.get("Privileged") is False and
            host.get("AutoRemove") is False and host.get("ReadonlyRootfs") is False and
            host.get("SecurityOpt") == ["label=disable"] and host.get("CapAdd") in (None, []) and
            host.get("CapDrop") == ["ALL"] and host.get("GroupAdd") in (None, []) and
            host.get("Devices") == [] and host.get("DeviceRequests") in (None, []) and
            host.get("DeviceCgroupRules") in (None, []) and not host.get("Tmpfs") and
            host.get("IpcMode") == "private" and host.get("PidMode") == "" and
            host.get("UTSMode") == "" and host.get("UsernsMode") == "" and
            host.get("RestartPolicy") == {"Name": "no", "MaximumRetryCount": 0} and
            host.get("NanoCpus") == CONTAINER_RESOURCES["cpus"] * 10 ** 9 and
            host.get("Memory") == CONTAINER_RESOURCES["memory_bytes"] and
            host.get("MemorySwap") == CONTAINER_RESOURCES["memory_swap_bytes"] and
            host.get("PidsLimit") == CONTAINER_RESOURCES["pids_limit"] and
            type(info.get("RestartCount")) is int and info["RestartCount"] == 0,
            "Retained container isolation contract differs")
    expected_binds = {f"{source}:/sources:rw", f"{out_dir}:/sources/out:rw"}
    require(isinstance(host.get("Binds"), list) and len(host["Binds"]) == 2 and
            set(host["Binds"]) == expected_binds,
            "Retained container bind arguments differ from the fixed topology")
    selected_mounts = []
    for mount in mounts:
        require(isinstance(mount, dict), "Docker inspect returned a malformed mount")
        selected_mounts.append({
            "destination": mount.get("Destination"), "mode": mount.get("Mode"),
            "propagation": mount.get("Propagation"), "rw": mount.get("RW"),
            "source": mount.get("Source"), "type": mount.get("Type"),
        })
    selected_mounts.sort(key=lambda row: str(row["destination"]))
    log_payload, log_ref = stable_bytes(build_log)
    require(container_logs(container_id) == log_payload,
            "Retained container output differs from the supplied build log")
    record = {
        "id": container_id, "name": raw_name[1:], "image": info["Image"],
        "image_reference": config["Image"], "created": info.get("Created"),
        "started_at": state.get("StartedAt"), "finished_at": state.get("FinishedAt"),
        "exit_code": state["ExitCode"],
        "oom_killed": state["OOMKilled"], "user": config["User"],
        "working_dir": config["WorkingDir"], "entrypoint": config["Entrypoint"],
        "command": config["Cmd"], "inherited_environment": inherited,
        "network_mode": host["NetworkMode"], "security_opt": host["SecurityOpt"],
        "auto_remove": host["AutoRemove"], "privileged": host["Privileged"],
        "cap_add": host.get("CapAdd") or [], "devices": host.get("Devices") or [],
        "cap_drop": host.get("CapDrop") or [], "group_add": host.get("GroupAdd") or [],
        "device_requests": host.get("DeviceRequests") or [],
        "device_cgroup_rules": host.get("DeviceCgroupRules") or [],
        "tmpfs": host.get("Tmpfs") or {}, "readonly_rootfs": host["ReadonlyRootfs"],
        "ipc_mode": host.get("IpcMode"), "pid_mode": host.get("PidMode"),
        "uts_mode": host.get("UTSMode"), "userns_mode": host.get("UsernsMode"),
        "restart_policy": {"name": host["RestartPolicy"]["Name"],
                           "maximum_retry_count": host["RestartPolicy"]["MaximumRetryCount"]},
        "restart_count": info.get("RestartCount"),
        "attach_stdout": config.get("AttachStdout"),
        "attach_stderr": config.get("AttachStderr"),
        "attach_stdin": config.get("AttachStdin"),
        "resource_limits": {
            "cpus": CONTAINER_RESOURCES["cpus"],
            "nano_cpus": host.get("NanoCpus"),
            "memory_bytes": host.get("Memory"),
            "memory_swap_bytes": host.get("MemorySwap"),
            "pids_limit": host.get("PidsLimit"),
        },
        "labels": config.get("Labels"),
        "logs": log_ref, "mounts": selected_mounts,
    }
    return validate_container_record(record, source, out_dir, log_ref, builder, process_command)


def capture_builder():
    try:
        record = provenance.capture_builder(BUILDER_DIGEST, LOCK)
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error
    require(record["reference"] == BUILDER_REFERENCE and
            record["image"]["id"] == BUILDER_DIGEST,
            "Local builder does not have the exact locked image ID")
    return record


def load_launcher_contract():
    spec = importlib.util.spec_from_file_location("wonad_frankel_launcher", LAUNCHER)
    require(spec is not None and spec.loader is not None, "Cannot load Frankel launcher")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(module.PIN["builder_digest"] == BUILDER_DIGEST and
            module.PIN["lunch_target"] == "frankel-cur-user" and
            module.PIN["build_number"] == BUILD_NUMBER and
            module.PIN["build_jobs"] == 6 and
            module.PIN["highmem_jobs"] == 1 and
            module.PIN["container_resources"] == CONTAINER_RESOURCES,
            "Frankel launcher constants differ from comparison contract")
    return module


def validate_preflight_record(record, role: str, source: Path, out_dir: Path, log: Path,
                              preflight_path: Path, container, builder, source_snapshot):
    launcher = load_launcher_contract()
    fields = {
        "schema", "kind", "role", "contract", "process_environment", "process_command",
        "inner_command", "lock", "builder", "source", "toolchain", "locations",
        "container_name", "attempt_nonce", "docker_locality", "docker_locality_sha256",
        "location_identity", "resources", "docker_command", "launcher",
    }
    require(isinstance(record, dict) and set(record) == fields,
            "Unexpected Frankel launcher preflight fields")
    nonce = record.get("attempt_nonce")
    locality_sha256 = record.get("docker_locality_sha256")
    require(SHA256.fullmatch(str(nonce)) is not None and
            SHA256.fullmatch(str(locality_sha256)) is not None and
            canonical_digest(record.get("docker_locality")) == locality_sha256,
            "Launcher preflight Docker locality/attempt nonce is invalid")
    expected_locations = {"source": str(source), "out": str(out_dir), "log": str(log)}
    try:
        expected_identity = launcher.location_identity(source, out_dir, log, preflight_path)
        expected_identity["out"] = launcher.directory_identity(out_dir, "OUT_DIR")
        current_locality = launcher.docker_host_identity(launcher.docker_environment())
        expected_command = launcher.docker_command(
            source, out_dir, container["name"], attempt_nonce=nonce,
            locality_sha256=locality_sha256)
        daemon = current_locality.get("daemon")
        require(isinstance(daemon, dict) and isinstance(daemon.get("root_dir"), str),
                "Current Docker locality lacks its storage root")
        launcher.validate_resource_evidence(
            record["resources"], out_dir.parent, Path(daemon["root_dir"]), complete=True)
    except (ValueError, OSError) as error:
        raise ComparisonError(f"Cannot validate Frankel launcher preflight: {error}") from error
    require(record["schema"] == 2 and
            record["kind"] == "wonad-frankel-build-launch-preflight" and
            record["role"] == role and record["contract"] == launcher.PIN and
            record["process_environment"] == launcher.PROCESS_ENV and
            record["process_command"] == launcher.process_command() and
            record["inner_command"] == launcher.INNER_COMMAND and
            record["lock"] == source_snapshot["pin"]["lock"] == ordinary_ref(LOCK) and
            record["builder"] == builder and record["source"] == source_snapshot and
            record["toolchain"] == collect_toolchain(source) and
            record["locations"] == expected_locations and
            record["container_name"] == container["name"] and
            record["docker_locality"] == current_locality and
            record["location_identity"] == expected_identity and
            record["docker_command"] == expected_command and
            record["launcher"] == ordinary_ref(LAUNCHER),
            "Launcher preflight does not bind this exact Frankel build")
    labels = container.get("labels")
    require(labels == {launcher.ATTEMPT_LABEL: nonce,
                       launcher.LOCALITY_LABEL: locality_sha256},
            "Retained-container labels do not bind the launcher preflight")
    return launcher


def collect_preflight(role: str, source: Path, out_dir: Path, log: Path,
                      container, builder, source_snapshot):
    path = log.with_name(log.name + ".preflight.json")
    exact_path(path, "launcher preflight")
    try:
        payload, reference = stable_bytes(path, maximum_size=64 * 1024 * 1024)
        record = parse_json(payload, str(path))
    except (OSError, ComparisonError) as error:
        raise ComparisonError(f"Cannot parse launcher preflight: {error}") from error
    validate_preflight_record(record, role, source, out_dir, log, path,
                              container, builder, source_snapshot)
    return {"path": str(path), **reference,
            "pre_build_source_sha256": canonical_digest(source_snapshot),
            "launcher": ordinary_ref(LAUNCHER)}


def artifact_file(out_dir: Path, row):
    relative = safe_relative(row["path"])
    path = confined_path(out_dir, relative, "Receipted artifact")
    require(stat.S_ISREG(path.lstat().st_mode),
            f"Receipted artifact is absent: {relative}")
    return path


def capture(role: str, source_value: Path, out_value: Path, log_value: Path,
            container_value: str, output: Path, certificate: Path | None, jobs: int):
    require((role == "custom") == (certificate is not None),
            "Only custom capture accepts and requires a public certificate")
    source = exact_path(source_value, "source", directory=True)
    out_dir = exact_path(out_value, "OUT_DIR", directory=True)
    log = exact_path(log_value, "build log")
    require(not within(source, out_dir) and not within(out_dir, source) and
            not within(log, source) and not within(log, out_dir),
            "Source, OUT_DIR, and build log must be independent trees")
    require(output.is_absolute() and not os.path.lexists(output),
            "Receipt output must be a fresh absolute path")
    exact_path(output.parent, "receipt parent", directory=True)
    require(not within(output, source) and not within(output, out_dir),
            "Receipt must remain outside source and OUT_DIR")
    source_snapshot = collect_source_snapshot(source, role, certificate, LOCK, jobs)
    builder = capture_builder()
    launcher = load_launcher_contract()
    tools = helper_ledger()
    toolchain = collect_toolchain(source)
    artifacts = collect_artifacts(out_dir, role)
    build_log = validate_build_log(log)
    build_engine = collect_build_engine(source, out_dir)
    container = collect_container(container_value, source, out_dir, log, builder,
                                  launcher.process_command())
    preflight = collect_preflight(role, source, out_dir, log, container, builder, source_snapshot)
    # Close input races before creating immutable evidence.
    require(collect_source_snapshot(source, role, certificate, LOCK, jobs) == source_snapshot and
            collect_toolchain(source) == toolchain and collect_artifacts(out_dir, role) == artifacts and
            validate_build_log(log) == build_log and
            collect_build_engine(source, out_dir) == build_engine and
            collect_container(container["id"], source, out_dir, log, builder,
                              launcher.process_command()) == container and
            collect_preflight(role, source, out_dir, log, container, builder,
                              source_snapshot) == preflight and helper_ledger() == tools,
            "Build evidence changed during Frankel receipt capture")
    receipt = {
        "schema": RECEIPT_SCHEMA, "kind": "wonad-frankel-build-comparison-input",
        "role": role, "scope": "unsigned-build-comparison-not-release-or-runtime-qualification",
        "contract": launcher.PIN,
        "locations": {"source": str(source), "out_dir": str(out_dir), "build_log": str(log)},
        "builder": builder, "source": source_snapshot, "toolchain": toolchain,
        "artifacts": artifacts, "build_log": build_log, "build_engine": build_engine,
        "container": container, "preflight": preflight, "tools": tools,
    }
    try:
        provenance.atomic_new(output, receipt)
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error
    return receipt, ordinary_ref(output)["sha256"]


def load_authenticated(path: Path, digest: str):
    require(SHA256.fullmatch(str(digest)) is not None,
            "An exact lowercase out-of-band SHA-256 is required")
    path = exact_path(path, "receipt")
    payload, reference = stable_bytes(path)
    require(reference["sha256"] == digest, "Receipt differs from its authenticated SHA-256")
    try:
        value = parse_json(payload, str(path))
    except ComparisonError:
        raise
    require(isinstance(value, dict) and value.get("schema") == RECEIPT_SCHEMA and
            value.get("kind") == "wonad-frankel-build-comparison-input" and
            value.get("role") in {"baseline", "custom"} and
            value.get("scope") == "unsigned-build-comparison-not-release-or-runtime-qualification",
            "Unsupported Frankel receipt")
    return value


def validate_source_materializations(source):
    require(isinstance(source, dict) and set(source) == {
                "pin", "vendor", "stage", "owned_tracked_changes", "generated_inputs",
                "worktree_materializations", "worktree_materializations_sha256",
            }, "Unexpected Frankel source snapshot fields")
    pin = source["pin"]
    require(isinstance(pin, dict) and isinstance(pin.get("projects"), list) and
            type(pin.get("project_count")) is int and
            pin["project_count"] == len(pin["projects"]) and pin["project_count"] > 0,
            "Frankel source snapshot has an invalid project ledger")
    project_paths = []
    for row in pin["projects"]:
        require(isinstance(row, dict) and isinstance(row.get("path"), str),
                "Frankel source snapshot has an invalid project row")
        project_paths.append(safe_relative(row["path"]).as_posix())
    require(len(project_paths) == len(set(project_paths)),
            "Frankel source snapshot has duplicate project paths")
    materializations = source["worktree_materializations"]
    require(isinstance(materializations, dict) and
            set(materializations) == set(project_paths) and
            source["worktree_materializations_sha256"] ==
            canonical_digest(materializations),
            "Frankel source worktree materialization ledger is inconsistent")
    for path, value in materializations.items():
        safe_relative(path)
        try:
            provenance.validate_worktree_materializations(
                value, label=f"Frankel project {path}")
        except provenance.ProvenanceError as error:
            raise ComparisonError(str(error)) from error
    stage = source["stage"]
    if stage != {"state": "absent"}:
        require(stage.get("state") == f"schema-{stage_contract.stage_schema()}-with-project-updater",
                "Frankel custom source has the wrong active stage schema")
        marker = stage.get("marker")
        owned = marker_owned_targets(marker)
        if stage_contract.NATIVE_PATCH_NAMES:
            require(marker["frameworks_native_revision"] == stage_contract.native_revision_from_projects(pin["projects"]),
                    "Native Frankel revision differs from authenticated source project ledger")
        changed = source["owned_tracked_changes"]
        generated = source["generated_inputs"]
        updater_path = "packages/apps/Updater/res/values/config.xml"
        owned[updater_path] = stage["updater"]["configured_sha256"]
        require(set(changed) <= set(owned), "Frankel tracked targets are outside the active owned stage")
        expected_generated = {
            "external/wonad/.wonad-stage.json", ".wonad-updater-stage.json",
            *("external/wonad/" + safe_relative(name).as_posix() for name in marker["files"]),
            *(VENDOR_ROOT.as_posix() + "/" + safe_relative(name).as_posix() for name in source["vendor"]["files"]),
        } | (set(owned) - set(changed))
        require(set(generated) == expected_generated, "Frankel generated inventory differs from its exact owned partition")
        for name, digest in owned.items():
            row = changed.get(name) or generated.get(name)
            require(isinstance(row, dict) and row.get("sha256") == digest,
                    "Frankel tracked/generated native or platform target differs from its marker: " + name)
    return source


def verify(path: Path, digest: str, *, rehash=True):
    receipt = load_authenticated(path, digest)
    launcher = load_launcher_contract()
    require(set(receipt) == {
                "schema", "kind", "role", "scope", "contract", "locations", "builder",
                "source", "toolchain", "artifacts", "build_log", "build_engine",
                "container", "preflight", "tools"},
            "Unexpected Frankel receipt fields")
    require(receipt.get("contract") == launcher.PIN,
            "Receipt contract differs from the reviewed launcher")
    validate_helper_ledger(receipt.get("tools"))
    try:
        lock = provenance.validate_lock(provenance.load_json(LOCK))
        provenance.validate_builder(receipt["builder"], lock)
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error
    require(receipt["builder"]["image"]["id"] == BUILDER_DIGEST,
            "Receipt builder differs from the exact locked image")
    validate_source_materializations(receipt.get("source"))
    if rehash:
        locations = receipt.get("locations", {})
        source = exact_path(Path(locations["source"]), "receipted source", directory=True)
        out_dir = exact_path(Path(locations["out_dir"]), "receipted OUT_DIR", directory=True)
        log = exact_path(Path(locations["build_log"]), "receipted build log")
        require(not within(source, out_dir) and not within(out_dir, source) and
                not within(log, source) and not within(log, out_dir),
                "Receipted paths now overlap")
        certificate = None
        if receipt["role"] == "custom":
            # Reverification is self-contained: the canonical DER is staged and
            # bound by schema 4, while its identity is already in the receipt.
            marker = receipt["source"]["stage"]["marker"]
            certificate = source / "external/wonad" / marker["signer_certificate"]["path"]
        require(collect_source_snapshot(source, receipt["role"], certificate, LOCK,
                                        SOURCE_AUDIT_JOBS,
                                        allow_staged_certificate=receipt["role"] == "custom") ==
                receipt["source"],
                "Source differs from receipt")
        require(collect_toolchain(source) == receipt["toolchain"], "Toolchain differs from receipt")
        require(collect_artifacts(out_dir, receipt["role"]) == receipt["artifacts"],
                "Artifacts differ from receipt")
        require(validate_build_log(log) == receipt["build_log"], "Build log differs from receipt")
        require(collect_build_engine(source, out_dir) == receipt["build_engine"],
                "Build-engine evidence differs from receipt")
        require(collect_container(receipt["container"]["id"], source, out_dir, log,
                                  receipt["builder"],
                                  launcher.process_command()) == receipt["container"],
                "Retained container differs from receipt")
        require(collect_preflight(receipt["role"], source, out_dir, log, receipt["container"],
                                  receipt["builder"], receipt["source"]) == receipt["preflight"],
                "Launcher preflight differs from receipt")
    return receipt


def comparison_row(baseline, custom):
    if baseline.get("state") == "absent" or custom.get("state") == "absent":
        equal = baseline.get("state") == custom.get("state") == "absent"
    else:
        equal = (baseline["sha256"], baseline["size"]) == (custom["sha256"], custom["size"])
    return {"baseline": baseline, "custom": custom,
            "equal": equal}


def compare(baseline_path: Path, baseline_sha256: str, custom_path: Path,
            custom_sha256: str, output: Path, *, rehash=True):
    baseline = verify(baseline_path, baseline_sha256, rehash=rehash)
    custom = verify(custom_path, custom_sha256, rehash=rehash)
    require(baseline["role"] == "baseline" and custom["role"] == "custom",
            "Comparison requires baseline then custom receipts")
    for field in ("contract", "builder", "toolchain", "tools"):
        require(baseline[field] == custom[field], f"Baseline/custom {field} differs")
    require(baseline["source"]["pin"] == custom["source"]["pin"],
            "Baseline/custom authenticated source pin differs")
    require(baseline["source"]["worktree_materializations"] ==
            custom["source"]["worktree_materializations"] and
            baseline["source"]["worktree_materializations_sha256"] ==
            custom["source"]["worktree_materializations_sha256"],
            "Baseline/custom build-visible source materialization differs")
    require(baseline["source"]["vendor"] == custom["source"]["vendor"],
            "Baseline/custom generated Frankel vendor tree differs")
    require(baseline["source"]["stage"] == {"state": "absent"} and
            custom["source"]["stage"]["state"] == f"schema-{stage_contract.stage_schema()}-with-project-updater",
            "Baseline/custom staging roles differ")
    paths = [Path(baseline["locations"]["source"]), Path(custom["locations"]["source"]),
             Path(baseline["locations"]["out_dir"]), Path(custom["locations"]["out_dir"])]
    require(all(not within(paths[i], paths[j]) and not within(paths[j], paths[i])
                for i in range(len(paths)) for j in range(i + 1, len(paths))),
            "Baseline/custom source and OUT_DIR trees must all be distinct")
    require(baseline["container"]["id"] != custom["container"]["id"] and
            baseline["container"]["name"] != custom["container"]["name"],
            "Baseline/custom builds require distinct retained containers")
    require(baseline["artifacts"]["fingerprint"] == custom["artifacts"]["fingerprint"],
            "Baseline/custom fixed build fingerprints differ")
    artifact_rows = {
        name: comparison_row(baseline["artifacts"]["files"][name],
                             custom["artifacts"]["files"][name])
        for name in sorted(baseline["artifacts"]["files"])
    }
    require(set(artifact_rows) == set(custom["artifacts"]["files"]),
            "Baseline/custom artifact set differs")
    os_rows = {
        name: comparison_row(baseline["artifacts"]["os_artifacts"][name],
                             custom["artifacts"]["os_artifacts"][name])
        for name in sorted(baseline["artifacts"]["os_artifacts"])
    }
    require(set(os_rows) == set(custom["artifacts"]["os_artifacts"]),
            "Baseline/custom OS artifact set differs")
    require(all(os_rows[name]["baseline"]["state"] == "absent" and
                os_rows[name]["custom"]["state"] == "present" for name in NATIVE_ONLY),
            "Wonad native libraries were not introduced by the custom build")
    require(all(name in os_rows and not os_rows[name]["equal"]
                for name in x86.required_changed_artifacts(custom["source"]["stage"])),
            "Custom framework/SystemUI artifacts do not all differ from baseline")
    require(not artifact_rows["target_files"]["equal"],
            "Custom Frankel target-files archive is byte-identical to baseline")
    result = {
        "schema": COMPARISON_SCHEMA, "kind": "wonad-frankel-baseline-custom-comparison",
        "scope": "unsigned-build-artifact-delta-not-release-or-runtime-qualification",
        "baseline_receipt": {"sha256": baseline_sha256, "file": ordinary_ref(baseline_path)},
        "custom_receipt": {"sha256": custom_sha256, "file": ordinary_ref(custom_path)},
        "tools": baseline["tools"],
        "shared": {"contract": baseline["contract"],
                   "builder_image": BUILDER_DIGEST,
                   "source_pin_sha256": canonical_digest(baseline["source"]["pin"]),
                   "worktree_materializations_sha256":
                       baseline["source"]["worktree_materializations_sha256"],
                   "vendor_identity_sha256": baseline["source"]["vendor"]["identity_sha256"],
                   "toolchain_sha256": canonical_digest(baseline["toolchain"]),
                   "tool_ledger_sha256": canonical_digest(baseline["tools"]),
                   "fingerprint": baseline["artifacts"]["fingerprint"]},
        "artifacts": artifact_rows, "os_artifacts": os_rows,
        "changed": sorted(name for name, row in artifact_rows.items() if not row["equal"]),
        "changed_os_artifacts": sorted(name for name, row in os_rows.items() if not row["equal"]),
        "result": "passed_exact_frankel_clean_baseline_custom_delta",
    }
    require(output.is_absolute() and not os.path.lexists(output),
            "Comparison output must be a fresh absolute path")
    exact_path(output.parent, "comparison parent", directory=True)
    require(all(not within(output, tree) for tree in paths),
            "Comparison output must remain outside both builds")
    require(verify(baseline_path, baseline_sha256, rehash=rehash) == baseline and
            verify(custom_path, custom_sha256, rehash=rehash) == custom,
            "Comparison input changed before output creation")
    try:
        provenance.atomic_new(output, result)
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error
    return result, ordinary_ref(output)["sha256"]


def verify_comparison(path: Path, digest: str, baseline_path: Path, baseline_sha256: str,
                      custom_path: Path, custom_sha256: str, *, rehash=True):
    path = exact_path(path, "comparison")
    payload, reference = stable_bytes(path)
    require(SHA256.fullmatch(str(digest)) and reference["sha256"] == digest,
            "Comparison differs from its authenticated SHA-256")
    try:
        document = parse_json(payload, str(path))
    except ComparisonError:
        raise
    with tempfile.TemporaryDirectory(prefix="wonad-frankel-compare-") as directory:
        reproduced, _ = compare(baseline_path, baseline_sha256, custom_path, custom_sha256,
                                Path(directory) / "comparison.json", rehash=rehash)
    require(document == reproduced, "Comparison is not the exact result for its receipts")
    return document


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    actions = value.add_subparsers(dest="action", required=True)
    capture_action = actions.add_parser("capture")
    capture_action.add_argument("--role", choices=("baseline", "custom"), required=True)
    capture_action.add_argument("--source", type=Path, required=True)
    capture_action.add_argument("--out-dir", type=Path, required=True)
    capture_action.add_argument("--build-log", type=Path, required=True)
    capture_action.add_argument("--container", required=True)
    capture_action.add_argument("--certificate", type=Path)
    capture_action.add_argument("--jobs", type=int, default=SOURCE_AUDIT_JOBS)
    capture_action.add_argument("--output", type=Path, required=True)
    verify_action = actions.add_parser("verify")
    verify_action.add_argument("--receipt", type=Path, required=True)
    verify_action.add_argument("--expected-sha256", required=True)
    compare_action = actions.add_parser("compare")
    compare_action.add_argument("--baseline", type=Path, required=True)
    compare_action.add_argument("--baseline-sha256", required=True)
    compare_action.add_argument("--custom", type=Path, required=True)
    compare_action.add_argument("--custom-sha256", required=True)
    compare_action.add_argument("--output", type=Path, required=True)
    check_action = actions.add_parser("verify-comparison")
    check_action.add_argument("--comparison", type=Path, required=True)
    check_action.add_argument("--expected-sha256", required=True)
    check_action.add_argument("--baseline", type=Path, required=True)
    check_action.add_argument("--baseline-sha256", required=True)
    check_action.add_argument("--custom", type=Path, required=True)
    check_action.add_argument("--custom-sha256", required=True)
    return value


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.action == "capture":
            _, digest = capture(args.role, args.source, args.out_dir, args.build_log,
                                args.container, args.output, args.certificate, args.jobs)
            print(digest)
        elif args.action == "verify":
            verify(args.receipt, args.expected_sha256)
            print("PASS: authenticated Frankel build receipt and retained evidence")
        elif args.action == "compare":
            _, digest = compare(args.baseline, args.baseline_sha256, args.custom,
                                args.custom_sha256, args.output)
            print(digest)
        else:
            verify_comparison(args.comparison, args.expected_sha256, args.baseline,
                              args.baseline_sha256, args.custom, args.custom_sha256)
            print("PASS: authenticated Frankel baseline/custom comparison")
        return 0
    except (ComparisonError, KeyError, TypeError, AttributeError) as error:
        print("frankel_build_comparison.py: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
