#!/usr/bin/env python3
"""Seal and compare clean-baseline and Wonad x86 GrapheneOS builds.

The receipts produced here are comparison evidence, not runtime qualification.
Capture is read-only with respect to both the Android source checkout and its
external OUT_DIR.  Receipt and comparison JSON files are authenticated by the
SHA-256 printed by this program; verification therefore requires that digest
as a separate input.
"""

from __future__ import annotations

import argparse
import ast
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


ROOT = Path(__file__).resolve().parents[2]
ANDROID = ROOT / "android"
TOOLS = ANDROID / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
import phase1_provenance as provenance  # noqa: E402
import docker_locality_proof as locality  # noqa: E402
import x86_partition_capacity as partition_capacity  # noqa: E402


LOCK = ANDROID / "grapheneos.lock.json"
CONTAINER_BUILD = ANDROID / "container/build.py"
NATIVE_CANDIDATE_BUILD = ANDROID / "container/build-native-candidate.py"
X86_BUILD_LAUNCHER = ANDROID / "tools/run_x86_build.py"
STAGE_OS = ANDROID / "platform/stage-os.py"
RECEIPT_SCHEMA = 4
COMPARISON_SCHEMA = 4
SHA256 = re.compile(r"[0-9a-f]{64}")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
CONTAINER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
NONCE = re.compile(r"[0-9a-f]{64}")
FINGERPRINT = re.compile(
    r"Android/sdk_phone64_x86_64/emu64x:[^/\s]+/[^/\s]+/"
    r"wonad\.2026100600:userdebug/[^\s]+"
)
PROJECT = "target/product/emu64x"
NATIVE_ONLY = {"os_broker_native", "os_input_native"}
REQUIRED_CHANGED = {"com.android.systemui", "os_services", "os_framework"}

CONTAINER_COMMAND = [
    "bash", "-lc",
    "set -eo pipefail; source build/envsetup.sh; "
    "lunch sdk_phone64_x86_64-cur-userdebug; unset OFFICIAL_BUILD; m -j6",
]
CONTAINER_ENVIRONMENT = {
    "HOME": "/tmp/wonad-home",
    "BUILD_HOSTNAME": "r-0123456789abcdef-0123",
    "BUILD_USERNAME": "android-user",
    "BUILD_NUMBER": "wonad.2026100600",
    "BUILD_DATETIME": "1791386354",
    "NINJA_HIGHMEM_NUM_JOBS": "1",
    "BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE": "3355443200",
    "PATH": "/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "DEBIAN_FRONTEND": "noninteractive",
    "LANG": "C.UTF-8",
}
LAUNCHER_ENVIRONMENT = {
    key: CONTAINER_ENVIRONMENT[key] for key in (
        "HOME", "BUILD_HOSTNAME", "BUILD_USERNAME", "BUILD_NUMBER",
        "BUILD_DATETIME", "NINJA_HIGHMEM_NUM_JOBS",
        "BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE",
    )
}
LAUNCHER_PIN = {
    "release": "2026100600",
    "builder_reference": "wonad-grapheneos-builder:2026100600",
    "builder_digest":
        "sha256:f719a4a56095b613790ef9afcba2aabda795217ac98e08c24ba5cec65bd4ee33",
    "builder_platform": "linux/amd64",
    "lunch_target": "sdk_phone64_x86_64-cur-userdebug",
    "build_number": "wonad.2026100600",
    "build_datetime": "1791386354",
    "build_jobs": 6,
    "highmem_jobs": 1,
    "emulator_dynamic_partitions_size": 3355443200,
    "emulator_super_partition_size": 3363831808,
    "container_source": "/sources",
    "container_out": "/sources/out",
    "default_out_dir": "out",
}
BASELINE_ATTEMPT4 = {
    "id": "503ff047c5a8edba4d9e761b6e5b494b491ead99ad8d2f078354bf54649e1c96",
    "name": "wonad-phase1-x86-baseline-2026100600-4",
    "source": "/u/elric/tree/wonad-grapheneos-2026100600",
    "out": "/u/elric/tree/wonad-grapheneos-x86-baseline-out-2026100600-4",
    "log": "/u/elric/tree/wonad/android/out/phase1-x86-baseline-2026100600-build-4.log",
}
ATTEMPT4_LOCALITY_PROOF = Path(
    "/u/elric/tree/wonad/android/out/"
    "phase1-x86-baseline-2026100600-locality-proof-7.json"
)
ATTEMPT4_LOCALITY_PROOF_SHA256 = (
    "474d8fde3e2f13aecf584b94be50e20701bc0d72f4a75de07bc35ba14f4721a8"
)
ATTEMPT4_LOCALITY_GENERATOR = {
    "sha256": "2a413e9e875950f764105ed3747bc0861bee2a4ee60805405243a5a140007cb0",
    "size": 29860,
}
# Build-6's immutable schema-2 launcher preflight was sealed by this exact
# reviewed locality helper before mount projection was made insensitive to
# Docker's non-semantic Inspect.Mounts ordering.  Keep this compatibility
# identity scoped to schema-2 launcher evidence: new receipts still bind the
# complete current verification-tool ledger below.
SCHEMA2_HISTORICAL_LOCALITY_GENERATOR = {
    "sha256": "2a413e9e875950f764105ed3747bc0861bee2a4ee60805405243a5a140007cb0",
    "size": 29860,
}
ATTEMPT4_LIMITATIONS = [
    "pre_build_source_snapshot_not_independently_sealed",
    "fresh_external_out_creation_not_independently_sealed",
    "fresh_container_writable_layer_not_independently_sealed",
]
SISO_MAIN_STAR = b'''\

load("@builtin//struct.star", "module")
load("main/main.star", "main")
imports = [main]
def init(ctx):
    vars = module(
        "config",
        JAVA_HOME = "/sources/prebuilts/jdk/jdk21/linux-x86",
        OUT_DIR = "out",
        RBE_container_image = "docker://gcr.io/androidbuild-re-dockerimage/android-build-remoteexec-image@sha256:1eb7f64b9e17102b970bd7a1af7daaebdb01c3fb777715899ef462d6c6d01a45",
        RELEASE_BUILD_CLANG_VERSION = "clang-r584948b",
        use_rbe = False,
        use_reclient = False,
    )

    return main.generate(ctx, vars, imports)
'''

BUILD_CONTRACT = {
    "platform": "linux/amd64",
    "lunch_target": "sdk_phone64_x86_64-cur-userdebug",
    "target_product": "sdk_phone64_x86_64",
    "target_variant": "userdebug",
    "target_arch": "x86_64",
    "build_number": "wonad.2026100600",
    "build_datetime": "1791386354",
    "ninja_highmem_num_jobs": 1,
    "emulator_dynamic_partitions_size": 3355443200,
    "emulator_super_partition_size": 3363831808,
    "emulator_super_metadata_reserve": 8388608,
    "build_jobs": 6,
    "network": "none",
    "container_user": "1000:1000",
    "container_home": "/tmp/wonad-home",
    "container_tmpfs": "none",
    "container_source": "/sources",
    "container_out_dir": "out",
    "container_out_mount": "/sources/out",
    "host_out_dir": "external-absolute-directory",
    "selinux": "label=disable",
    "locale": "C.UTF-8",
    "official_build": "unset",
    "source_mount": "rw",
    "out_dir_mount": "rw",
    "prebuild_mutation": "receipt-specific-preflight-evidence",
    "environment": CONTAINER_ENVIRONMENT,
    "command": CONTAINER_COMMAND,
}


class ComparisonError(ValueError):
    """A fail-closed build-comparison error."""


def require(condition, message):
    if not condition:
        raise ComparisonError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ComparisonError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def parse_json(payload: bytes, label: str):
    try:
        return json.loads(payload, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ComparisonError(f"Invalid JSON in {label}: {error}") from error


def load_json(path: Path):
    payload, _ = stable_bytes(path)
    return parse_json(payload, str(path))


def canonical_digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def literal_assignment(path: Path, name: str, expected_type):
    """Read an artifact declaration without importing build drivers."""
    require(path.is_file() and not path.is_symlink(), f"Missing artifact definition: {path}")
    try:
        tree = ast.parse(path.read_bytes(), filename=str(path))
    except (OSError, SyntaxError) as error:
        raise ComparisonError(f"Cannot parse artifact definition {path}: {error}") from error
    values = []
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                try:
                    values.append(ast.literal_eval(node.value))
                except (TypeError, ValueError) as error:
                    raise ComparisonError(f"{name} is not a literal in {path}") from error
    require(len(values) == 1 and type(values[0]) is expected_type,
            f"Expected one literal {name} in {path}")
    return values[0]


IMAGE_FILES = tuple(literal_assignment(CONTAINER_BUILD, "IMAGE_FILES", tuple))
OS_PATHS = dict(literal_assignment(NATIVE_CANDIDATE_BUILD, "OS_PATHS", dict))


def safe_relative(value: str) -> PurePosixPath:
    try:
        result = provenance.safe_relative(value)
    except (provenance.ProvenanceError, ValueError) as error:
        raise ComparisonError(str(error)) from error
    return result


def ordinary_ref(path: Path, *, allow_empty=False):
    try:
        result = provenance.file_ref(path)
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error
    require(allow_empty or result["size"] > 0, f"Empty evidence input: {path}")
    return result


def verification_tool_ledger():
    """Bind every non-stdlib helper which can interpret an x86 receipt.

    Merely binding this file as the receipt generator is insufficient: both
    the source auditor and Docker locality verifier are imported Python code,
    and the custom-source auditor dynamically executes the stage verifier.
    Require the imports to originate at their reviewed in-tree paths before
    hashing them, then bind the exact host programs on which the source audit
    depends.  Validators reproduce this entire value from the current files
    and tools rather than trusting a self-described ledger in the receipt.
    """
    expected_modules = {
        "phase1_provenance": TOOLS / "phase1_provenance.py",
        "docker_locality_proof": TOOLS / "docker_locality_proof.py",
        "x86_partition_capacity": TOOLS / "x86_partition_capacity.py",
    }
    imported_modules = {
        "phase1_provenance": provenance,
        "docker_locality_proof": locality,
        "x86_partition_capacity": partition_capacity,
    }
    files = {}
    for name, expected in sorted(expected_modules.items()):
        module_path = getattr(imported_modules[name], "__file__", None)
        require(isinstance(module_path, str), f"Imported helper has no source path: {name}")
        try:
            actual = Path(module_path).resolve(strict=True)
            reviewed = expected.resolve(strict=True)
        except OSError as error:
            raise ComparisonError(f"Cannot resolve imported helper {name}: {error}") from error
        require(actual == reviewed and expected.is_file() and not expected.is_symlink(),
                f"Imported helper did not come from its reviewed path: {name}")
        files[expected.relative_to(ROOT).as_posix()] = ordinary_ref(expected)

    require(STAGE_OS.is_file() and not STAGE_OS.is_symlink(),
            "OS stage verifier is missing or symlinked")
    files[STAGE_OS.relative_to(ROOT).as_posix()] = ordinary_ref(STAGE_OS)
    try:
        host_tools = provenance.host_tool_ledger()
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error
    result = {
        "schema": 1,
        "files": dict(sorted(files.items())),
        "host_tools": host_tools,
        "source_audit_policy": provenance.GIT_RAW_AUDIT_POLICY,
    }
    result["identity_sha256"] = canonical_digest(result)
    return result


def exact_path(value: Path, label: str, *, directory=False) -> Path:
    require(value.is_absolute(), f"{label} must be an absolute path")
    require(not value.is_symlink(), f"{label} must not be a symlink")
    try:
        resolved = value.resolve(strict=True)
    except OSError as error:
        raise ComparisonError(f"Cannot resolve {label}: {error}") from error
    require(resolved == value, f"{label} must be canonical")
    require(resolved.is_dir() if directory else resolved.is_file(),
            f"{label} is not an ordinary {'directory' if directory else 'file'}")
    return resolved


def outside(path: Path, tree: Path) -> bool:
    return path != tree and tree not in path.parents


def within_filesystem(path: Path, tree: Path) -> bool:
    """Detect lexical or bind/alias ancestry for an existing tree.

    ``path`` itself may not exist yet (receipt/comparison outputs), but its
    parent must.  Comparing ``tree`` with every existing ancestor closes the
    common bind-mount alias escape which ``Path.parents`` cannot see.
    """
    current = path if path.exists() else path.parent
    while True:
        try:
            if os.path.samefile(current, tree):
                return True
        except OSError as error:
            raise ComparisonError(f"Cannot compare filesystem identity: {error}") from error
        if current == current.parent:
            return False
        current = current.parent


def filesystem_trees_overlap(first: Path, second: Path) -> bool:
    return within_filesystem(first, second) or within_filesystem(second, first)


def load_stage_module():
    spec = importlib.util.spec_from_file_location("wonad_stage_os", ANDROID / "platform/stage-os.py")
    require(spec is not None and spec.loader is not None, "Cannot load the OS stage verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def authenticated_manifest(source: Path, lock):
    default_manifest = source / ".repo/manifests/default.xml"
    default_ref = provenance.file_ref(default_manifest)
    require(default_ref == {"sha256": lock["manifest"]["default_xml_sha256"],
                            "size": lock["manifest"]["default_xml_size"]},
            "Checked-out default.xml differs from the authenticated lock")
    manifest_repository = source / ".repo/manifests"
    manifest_head = provenance.git_bytes(manifest_repository, "rev-parse", "HEAD").decode().strip()
    require(manifest_head == lock["manifest"]["commit"],
            "Manifest repository HEAD differs from lock")
    committed = provenance.git_bytes(manifest_repository, "show", manifest_head + ":default.xml")
    require(hashlib.sha256(committed).hexdigest() == default_ref["sha256"] and
            len(committed) == default_ref["size"],
            "Working default.xml differs from its authenticated manifest commit")
    require(not provenance.git_bytes(manifest_repository, "status", "--porcelain", "-z",
                                     "--untracked-files=all"),
            "Manifest repository is dirty")
    require(not (source / ".repo/local_manifests").exists(), "Local manifest overrides are forbidden")
    projects = provenance._parse_manifest_payload(committed)[1]
    project_list = source / ".repo/project.list"
    require(project_list.is_file() and not project_list.is_symlink(), "repo project.list is missing")
    listed = project_list.read_text().splitlines()
    require(len(listed) == len(set(listed)) and
            set(listed) == {row["path"] for row in projects},
            "repo project.list differs from signed default.xml")
    return manifest_head, default_ref, projects, committed


def marker_owned_targets(marker):
    expected = {
        "frameworks_base": "frameworks/base",
        "launcher3": "packages/apps/Launcher3",
        "emulator_goldfish": "device/generic/goldfish",
    }
    targets = marker.get("platform_targets") if isinstance(marker, dict) else None
    require(isinstance(targets, dict) and set(targets) == set(expected),
            "Schema-4 stage has an incomplete platform target inventory")
    owned = {}
    for label, prefix in expected.items():
        rows = targets[label]
        require(isinstance(rows, dict) and rows, f"Missing {label} stage targets")
        for name, digest in rows.items():
            relative = safe_relative(name).as_posix()
            require(isinstance(digest, str) and SHA256.fullmatch(digest),
                    f"Invalid stage target digest: {label}/{name}")
            owned[f"{prefix}/{relative}"] = digest
    return owned


def marker_external_inputs(marker):
    files = marker.get("files") if isinstance(marker, dict) else None
    require(isinstance(files, dict), "Custom marker lacks staged files")
    external = {"external/wonad/.wonad-stage.json"}
    external.update("external/wonad/" + safe_relative(name).as_posix()
                    for name in files)
    return external


def validate_custom_stage_inventory(marker, changed, generated):
    """Validate the exact tracked/generated partition of one schema-4 stage."""
    require(isinstance(changed, dict) and isinstance(generated, dict),
            "Custom source inventories must be objects")
    owned = marker_owned_targets(marker)
    owned_paths = set(owned)
    tracked_paths = set(changed)
    require(tracked_paths <= owned_paths,
            "Custom tracked inventory contains targets outside its marker")
    expected_generated = marker_external_inputs(marker) | (owned_paths - tracked_paths)
    require(set(generated) == expected_generated,
            "Custom generated inventory differs from its exact schema-4 partition")
    return owned


def scan_x86_worktree(source: Path, states, owned, expected_generated,
                      manifest_materializations):
    """Inventory the comparison source without production-only vendor assertions."""
    tracked = set()
    changes = set()
    for project_path, dirty, project_tracked in states:
        tracked.update(f"{project_path}/{name}" for name in project_tracked)
        changes.update(f"{project_path}/{name}" for name in dirty)
    expected_changes = set(owned)
    require(changes == expected_changes & tracked,
            "Tracked worktree changes differ from the complete x86 owned target set: "
            f"unexpected={sorted(changes - expected_changes)[:8]} "
            f"missing={sorted((expected_changes & tracked) - changes)[:8]}")
    allowed_generated = set(expected_generated) | (expected_changes - tracked)
    changed = {}
    generated = {}
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
                raise ComparisonError(f"Cannot stat x86 source entry {relative}: {error}") from error
            if stat.S_ISDIR(mode):
                continue
            if relative in manifest_materializations:
                continue
            if relative in tracked:
                if relative in changes:
                    require(stat.S_ISREG(mode), f"Owned tracked target is not ordinary: {relative}")
                    changed[relative] = provenance.file_ref(
                        path, relative=PurePosixPath(relative), include_mode=True)
                continue
            require(relative in allowed_generated,
                    f"Untracked or ignored x86 source input is not owned: {relative}")
            require(stat.S_ISREG(mode), f"Generated x86 source input is not ordinary: {relative}")
            generated[relative] = provenance.file_ref(
                path, relative=PurePosixPath(relative), include_mode=True)
    require(set(changed) == changes, "Owned tracked x86 changes disappeared during inventory")
    require(set(generated) == allowed_generated,
            "Owned generated x86 inputs disappeared during inventory")
    for relative, expected in owned.items():
        row = changed.get(relative) or generated.get(relative)
        require(row is not None and row["sha256"] == expected,
                f"Owned x86 target differs from stage marker: {relative}")
    return dict(sorted(changed.items())), dict(sorted(generated.items()))


def collect_source_snapshot(source_value: Path, role: str, certificate: Path | None,
                            lock_path: Path, jobs: int):
    require(role in {"baseline", "custom"}, "Build role must be baseline or custom")
    require(type(jobs) is int and 1 <= jobs <= 72, "Source audit jobs must be between 1 and 72")
    try:
        source = provenance.dedicated_source(source_value)
        provenance.forbidden_roots_absent(source)
        lock = provenance.validate_lock(provenance.load_json(lock_path))
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error
    manifest_head, default_ref, projects, manifest_payload = authenticated_manifest(source, lock)
    marker_path = source / "external/wonad/.wonad-stage.json"
    updater_marker = source / ".wonad-updater-stage.json"
    require(not updater_marker.exists() and not updater_marker.is_symlink(),
            "The x86 comparison source must not contain Updater staging")

    if role == "baseline":
        require(certificate is None, "Baseline capture must not receive a signer certificate")
        require(not (source / "external/wonad").exists() and not marker_path.is_symlink(),
                "Baseline source must have no Wonad staging")
        marker = None
        owned = {}
        signer = None
        expected_generated = set()
    else:
        require(certificate is not None, "Custom capture requires the emulator public certificate")
        try:
            marker = load_stage_module().verify_stage(source)
            signer = provenance.public_certificate(certificate)
        except (ValueError, provenance.ProvenanceError) as error:
            raise ComparisonError(f"Custom schema-4 stage verification failed: {error}") from error
        require(marker.get("schema") == 4 and
                marker.get("signer_sha256") == signer.get("der_sha256"),
                "Custom stage signer differs from the selected emulator public certificate")
        owned = marker_owned_targets(marker)
        expected_generated = marker_external_inputs(marker)

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        audited_states = list(pool.map(
            lambda row: provenance.project_state(source, row, include_audit=True), projects))
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
                row, label=f"x86 project {project_path}")
        except provenance.ProvenanceError as error:
            raise ComparisonError(str(error)) from error
        materializations[project_path] = row
    materializations = dict(sorted(materializations.items()))
    try:
        manifest_materializations = provenance.manifest_checkout_materializations(
            source, manifest_payload, projects, states)
        changed, generated = scan_x86_worktree(
            source, states, owned, expected_generated, manifest_materializations)
        require(provenance.manifest_checkout_materializations(
                    source, manifest_payload, projects, states) ==
                manifest_materializations,
                "Manifest checkout materializations changed during x86 source audit")
        require(provenance.file_ref(source / ".repo/manifests/default.xml") == default_ref and
                provenance.git_bytes(source / ".repo/manifests", "show",
                                     manifest_head + ":default.xml") == manifest_payload,
                "Authenticated manifest changed during x86 source audit")
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            final_audited_states = list(pool.map(
                lambda row: provenance.project_state(source, row, include_audit=True), projects))
        require(final_audited_states == audited_states,
                "Project worktrees changed during x86 source audit")
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error
    if role == "baseline":
        require(not changed and not generated,
                "Baseline source contains generated or modified files")
        stage = {"state": "absent"}
    else:
        validate_custom_stage_inventory(marker, changed, generated)
        stage = {
            "state": "schema-4-owned-stage",
            "marker": marker,
            "marker_sha256": ordinary_ref(marker_path)["sha256"],
            "development_certificate": signer,
            "qualification": "emulator-development-only",
        }

    repo = source / ".repo/repo"
    repo_head = provenance.git_bytes(repo, "rev-parse", "HEAD").decode().strip()
    require(repo_head == lock["repo_tool"]["commit"], "repo tool revision differs from lock")
    require(not provenance.git_bytes(repo, "status", "--porcelain", "-z",
                                     "--untracked-files=all"), "repo tool worktree is dirty")
    ledger = [{key: row[key] for key in ("path", "name", "revision", "remote")}
              for row in projects]
    return {
        "pin": {
            "release": lock["release"],
            "lock": provenance.file_ref(lock_path),
            "manifest_commit": manifest_head,
            "manifest_tag_object": lock["manifest"]["tag_object"],
            "default_xml": default_ref,
            "projects": ledger,
            "project_count": len(ledger),
            "project_ledger_sha256": canonical_digest(ledger),
            "repo_tool_commit": repo_head,
            "repo_tool_revision": lock["repo_tool"]["revision"],
        },
        "stage": stage,
        "owned_tracked_changes": changed,
        "generated_inputs": generated,
        "worktree_materializations": materializations,
        "worktree_materializations_sha256": canonical_digest(materializations),
    }


def artifact_definitions():
    require(IMAGE_FILES and len(IMAGE_FILES) == len(set(IMAGE_FILES)),
            "IMAGE_FILES must be a non-empty unique tuple")
    require(OS_PATHS and len(OS_PATHS) == len(set(OS_PATHS)),
            "OS_PATHS must be a non-empty mapping")
    for name in IMAGE_FILES:
        require(isinstance(name, str), "IMAGE_FILES contains a non-string path")
        safe_relative(name)
    for label, name in OS_PATHS.items():
        require(isinstance(label, str) and label and isinstance(name, str),
                "OS_PATHS contains an invalid entry")
        safe_relative(name)
    require("build_fingerprint-sdk_phone64_x86_64.txt" in IMAGE_FILES,
            "IMAGE_FILES no longer contains the build fingerprint")
    require(NATIVE_ONLY < set(OS_PATHS), "OS_PATHS lacks Wonad native artifacts")
    return {
        "image_files": list(IMAGE_FILES),
        "os_paths": dict(sorted(OS_PATHS.items())),
        "definition_files": {
            "android/container/build.py": ordinary_ref(CONTAINER_BUILD),
            "android/container/build-native-candidate.py": ordinary_ref(NATIVE_CANDIDATE_BUILD),
        },
    }


def artifact_path(product: Path, relative: str) -> Path:
    parts = safe_relative(relative).parts
    current = product
    for part in parts[:-1]:
        current = current / part
        require(not current.is_symlink(), f"Artifact parent is symlinked: {relative}")
        if not current.exists():
            break
        require(current.is_dir(), f"Artifact parent is not a directory: {relative}")
    return product.joinpath(*parts)


def artifact_record(product: Path, relative: str, *, allow_absent=False):
    path = artifact_path(product, relative)
    if not path.exists() and not path.is_symlink():
        require(allow_absent, f"Required build artifact is absent: {relative}")
        return {"path": relative, "state": "absent"}
    require(not path.is_symlink(), f"Build artifact is symlinked: {relative}")
    row = ordinary_ref(path)
    return {"path": relative, "state": "present", **row}


def collect_artifacts(product: Path, role: str, jobs: int):
    tasks = [("images", name, name, False) for name in IMAGE_FILES]
    tasks += [("os", label, relative, role == "baseline" and label in NATIVE_ONLY)
              for label, relative in sorted(OS_PATHS.items())]
    with ThreadPoolExecutor(max_workers=min(jobs, len(tasks))) as pool:
        values = list(pool.map(lambda task: artifact_record(product, task[2],
                                                             allow_absent=task[3]), tasks))
    images, os_artifacts = {}, {}
    for task, value in zip(tasks, values):
        (images if task[0] == "images" else os_artifacts)[task[1]] = value
    if role == "baseline":
        require(all(os_artifacts[name]["state"] == "absent" for name in NATIVE_ONLY),
                "Baseline unexpectedly contains Wonad native libraries")
        require(all(row["state"] == "present" for name, row in os_artifacts.items()
                    if name not in NATIVE_ONLY), "Baseline lacks a stock OS comparison artifact")
    else:
        require(all(row["state"] == "present" for row in os_artifacts.values()),
                "Custom build lacks a Wonad OS artifact")
    return {"images": images, "os_artifacts": os_artifacts}


def stable_bytes(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ComparisonError(f"Cannot safely open evidence input {path}: {error}") from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), f"Evidence input is not an ordinary file: {path}")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    try:
        current = os.lstat(path)
    except OSError as error:
        raise ComparisonError(f"Evidence input disappeared while reading: {path}: {error}") from error
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    require(all(getattr(before, name) == getattr(after, name) == getattr(current, name)
                for name in stable_fields) and stat.S_ISREG(current.st_mode) and
            len(payload) == before.st_size,
            f"Evidence input changed while reading: {path}")
    return payload, {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}


def inspect_container(reference: str):
    require(isinstance(reference, str) and
            (CONTAINER_ID.fullmatch(reference) or CONTAINER_NAME.fullmatch(reference)),
            "Container must be selected by one safe full ID or name")
    try:
        result = subprocess.run(
            ["docker", "container", "inspect", reference],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ComparisonError(f"Cannot inspect preserved build container: {error}") from error
    require(result.returncode == 0, "Docker could not inspect the preserved build container")
    try:
        rows = json.loads(result.stdout, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ComparisonError("Docker container inspect returned invalid JSON") from error
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict),
            "Docker container inspect must return exactly one object")
    return rows[0]


def container_logs(container_id: str) -> bytes:
    require(isinstance(container_id, str) and CONTAINER_ID.fullmatch(container_id),
            "Docker logs require one full container ID")
    try:
        # Docker otherwise writes the two container streams to two subprocess
        # pipes, destroying their observed interleaving.  The build launcher
        # used `2>&1 | tee`, so merge them here in the same way.
        result = subprocess.run(
            ["docker", "container", "logs", container_id],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ComparisonError(f"Cannot read preserved build-container logs: {error}") from error
    require(result.returncode == 0, "Docker could not read the preserved build-container logs")
    return result.stdout


def environment_map(rows):
    require(isinstance(rows, list), "Build-container environment is not a list")
    result = {}
    for row in rows:
        require(isinstance(row, str) and "=" in row,
                "Build-container environment contains a malformed entry")
        name, value = row.split("=", 1)
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) and name not in result,
                "Build-container environment contains an invalid or duplicate name")
        result[name] = value
    return dict(sorted(result.items()))


def validate_container_record(record, source: Path, out_dir: Path, build_log_ref, builder):
    expected_mounts = [
        {"destination": "/sources", "mode": "rw", "propagation": "rprivate",
         "rw": True, "source": str(source), "type": "bind"},
        {"destination": "/sources/out", "mode": "rw", "propagation": "rprivate",
         "rw": True, "source": str(out_dir), "type": "bind"},
    ]
    expected_keys = {
        "id", "name", "image", "image_reference", "created", "started_at", "finished_at",
        "exit_code", "oom_killed", "user", "working_dir", "command", "environment",
        "network_mode", "security_opt", "auto_remove", "privileged", "cap_add", "devices",
        "cap_drop", "group_add", "device_requests", "device_cgroup_rules", "tmpfs",
        "readonly_rootfs",
        "ipc_mode", "pid_mode", "uts_mode", "userns_mode", "restart_policy",
        "restart_count", "attach_stdout", "attach_stderr", "attach_stdin", "labels",
        "mounts", "logs",
    }
    require(isinstance(record, dict) and set(record) == expected_keys,
            "Unexpected build-container evidence fields")
    require(CONTAINER_ID.fullmatch(str(record["id"])) and
            CONTAINER_NAME.fullmatch(str(record["name"])),
            "Invalid preserved build-container identity")
    require(record["image"] == builder["image"]["id"] and
            record["image_reference"] == builder["reference"],
            "Build container did not use the locked immutable builder image")
    for name in ("created", "started_at", "finished_at"):
        require(isinstance(record[name], str) and record[name] and
                record[name] != "0001-01-01T00:00:00Z",
                f"Invalid build-container {name}")
    require(type(record["exit_code"]) is int and record["exit_code"] == 0 and
            record["oom_killed"] is False,
            "Build container did not exit successfully")
    require(record["user"] == BUILD_CONTRACT["container_user"] and
            record["working_dir"] == BUILD_CONTRACT["container_source"] and
            record["command"] == CONTAINER_COMMAND and
            record["environment"] == dict(sorted(CONTAINER_ENVIRONMENT.items())),
            "Build-container process contract differs")
    require(record["network_mode"] == "none" and
            record["security_opt"] == ["label=disable"] and
            record["auto_remove"] is False and record["privileged"] is False and
            record["cap_add"] == [] and record["devices"] == [] and
            record["cap_drop"] == [] and record["group_add"] == [] and
            record["device_requests"] == [] and record["device_cgroup_rules"] == [] and
            record["tmpfs"] == {} and
            record["readonly_rootfs"] is False and record["ipc_mode"] == "private" and
            record["pid_mode"] == "" and record["uts_mode"] == "" and
            record["userns_mode"] == "" and
            record["restart_policy"] == {"maximum_retry_count": 0, "name": "no"} and
            type(record["restart_count"]) is int and record["restart_count"] == 0 and
            record["attach_stdout"] is True and record["attach_stderr"] is True and
            record["attach_stdin"] is False and isinstance(record["labels"], dict) and
            all(isinstance(key, str) and key and isinstance(value, str)
                for key, value in record["labels"].items()),
            "Build-container isolation contract differs")
    require(record["mounts"] == expected_mounts,
            "Build-container source/OUT_DIR mounts differ from the fixed topology")
    require(record["logs"] == build_log_ref,
            "Build-container log identity differs from the supplied build log")
    return record


def collect_container_execution(reference: str, source: Path, out_dir: Path,
                                build_log: Path, builder):
    require(all(character not in str(source) and character not in str(out_dir)
                for character in (":", "\n", "\r")),
            "Build mount paths contain unsupported characters")
    info = inspect_container(reference)
    state = info.get("State")
    config = info.get("Config")
    host = info.get("HostConfig")
    mounts = info.get("Mounts")
    require(all(isinstance(value, dict) for value in (state, config, host)) and
            isinstance(mounts, list), "Docker inspect lacks build-container state/configuration")
    container_id = info.get("Id")
    raw_name = info.get("Name")
    require(isinstance(raw_name, str) and raw_name.startswith("/") and raw_name.count("/") == 1,
            "Docker inspect returned an invalid build-container name")
    name = raw_name[1:]
    require(CONTAINER_ID.fullmatch(str(container_id)) and CONTAINER_NAME.fullmatch(name),
            "Docker inspect returned an invalid build-container identity")
    require(state.get("Status") == "exited" and state.get("Running") is False and
            state.get("Paused") is False and state.get("Restarting") is False and
            state.get("Dead") is False and state.get("Error") == "" and
            type(state.get("ExitCode")) is int and state["ExitCode"] == 0 and
            state.get("OOMKilled") is False,
            "Preserved build container is not a clean successful exited container")
    require(config.get("Image") == builder["reference"] and
            config.get("User") == BUILD_CONTRACT["container_user"] and
            config.get("WorkingDir") == BUILD_CONTRACT["container_source"] and
            config.get("Entrypoint") in (None, []) and config.get("Cmd") == CONTAINER_COMMAND and
            config.get("Tty") is False and config.get("OpenStdin") is False and
            config.get("AttachStdout") is True and config.get("AttachStderr") is True and
            config.get("AttachStdin") is False,
            "Build-container command/image configuration differs")
    environment = environment_map(config.get("Env"))
    require(environment == dict(sorted(CONTAINER_ENVIRONMENT.items())),
            "Build-container environment differs from the fixed contract")
    require(info.get("Image") == builder["image"]["id"],
            "Build container image ID differs from the locked builder digest")
    require(host.get("NetworkMode") == "none" and
            host.get("SecurityOpt") == ["label=disable"] and
            host.get("AutoRemove") is False and host.get("Privileged") is False and
            host.get("CapAdd") in (None, []) and host.get("Devices") == [] and
            host.get("CapDrop") in (None, []) and host.get("GroupAdd") in (None, []) and
            host.get("DeviceRequests") in (None, []) and not host.get("Tmpfs") and
            host.get("DeviceCgroupRules") in (None, []) and
            host.get("ReadonlyRootfs") is False and host.get("IpcMode") == "private" and
            host.get("PidMode") == "" and host.get("UTSMode") == "" and
            host.get("UsernsMode") == "" and host.get("RestartPolicy") == {
                "Name": "no", "MaximumRetryCount": 0,
            } and type(info.get("RestartCount")) is int and info["RestartCount"] == 0,
            "Build-container host isolation differs from the fixed contract")
    expected_binds = {
        f"{source}:/sources:rw", f"{out_dir}:/sources/out:rw",
    }
    require(isinstance(host.get("Binds"), list) and set(host["Binds"]) == expected_binds and
            len(host["Binds"]) == 2,
            "Build-container bind arguments differ from the fixed topology")
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
            "Preserved build-container logs differ byte-for-byte from the supplied build log")
    record = {
        "id": container_id, "name": name,
        "image": info.get("Image"), "image_reference": config.get("Image"),
        "created": info.get("Created"), "started_at": state.get("StartedAt"),
        "finished_at": state.get("FinishedAt"), "exit_code": state.get("ExitCode"),
        "oom_killed": state.get("OOMKilled"), "user": config.get("User"),
        "working_dir": config.get("WorkingDir"), "command": config.get("Cmd"),
        "environment": environment, "network_mode": host.get("NetworkMode"),
        "security_opt": host.get("SecurityOpt"), "auto_remove": host.get("AutoRemove"),
        "privileged": host.get("Privileged"), "cap_add": host.get("CapAdd") or [],
        "cap_drop": host.get("CapDrop") or [], "group_add": host.get("GroupAdd") or [],
        "devices": host.get("Devices") or [], "device_requests": host.get("DeviceRequests") or [],
        "device_cgroup_rules": host.get("DeviceCgroupRules") or [],
        "tmpfs": host.get("Tmpfs") or {}, "readonly_rootfs": host.get("ReadonlyRootfs"),
        "ipc_mode": host.get("IpcMode"), "pid_mode": host.get("PidMode"),
        "uts_mode": host.get("UTSMode"), "userns_mode": host.get("UsernsMode"),
        "restart_policy": {
            "name": host["RestartPolicy"]["Name"],
            "maximum_retry_count": host["RestartPolicy"]["MaximumRetryCount"],
        },
        "restart_count": info.get("RestartCount"),
        "attach_stdout": config.get("AttachStdout"), "attach_stderr": config.get("AttachStderr"),
        "attach_stdin": config.get("AttachStdin"),
        "labels": config.get("Labels") or {},
        "mounts": selected_mounts, "logs": log_ref,
    }
    return validate_container_record(record, source, out_dir, log_ref, builder)


def launcher_docker_command(source: Path, out_dir: Path, name: str,
                            attempt_nonce: str, locality_sha256: str):
    command = [
        str(locality.DOCKER), "--host", locality.ENDPOINT,
        "run", "--name", name, "--platform", LAUNCHER_PIN["builder_platform"],
        "--network", "none", "--user", "1000:1000", "--security-opt", "label=disable",
        "--workdir", LAUNCHER_PIN["container_source"],
        "--label", "org.wonad.phase1.attempt=" + attempt_nonce,
        "--label", "org.wonad.phase1.locality=" + locality_sha256,
    ]
    for key, value in LAUNCHER_ENVIRONMENT.items():
        command.extend(("--env", key + "=" + value))
    command.extend((
        "--volume", f"{source}:{LAUNCHER_PIN['container_source']}:rw",
        "--volume", f"{out_dir}:{LAUNCHER_PIN['container_out']}:rw",
        LAUNCHER_PIN["builder_reference"], *CONTAINER_COMMAND,
    ))
    return command


def validate_launcher_locality(record, *, preflight_schema: int):
    require(preflight_schema == 2,
            "Historical launcher locality compatibility requires schema 2")
    fields = {"schema", "kind", "endpoint", "docker_cli", "socket", "context",
              "daemon", "host_boot_id", "generator"}
    require(isinstance(record, dict) and set(record) == fields and
            record.get("schema") == 1 and
            record.get("kind") == "wonad-build-launch-docker-locality" and
            record.get("endpoint") == locality.ENDPOINT and
            locality.BOOT_ID.fullmatch(str(record.get("host_boot_id"))),
            "Launcher Docker locality envelope is invalid")
    cli = record.get("docker_cli", {})
    endpoint = record.get("socket", {})
    context = record.get("context", {})
    daemon = record.get("daemon", {})
    require(cli.get("path") == cli.get("realpath") == str(locality.DOCKER) and
            cli.get("uid") == cli.get("gid") == 0 and
            cli.get("mode") == (stat.S_IFREG | 0o755) and
            isinstance(cli.get("file"), dict) and
            SHA256.fullmatch(str(cli["file"].get("sha256"))) and
            endpoint.get("path") == str(locality.SOCKET) and
            endpoint.get("realpath") == str(locality.SOCKET_REAL) and
            endpoint.get("uid") == 0 and
            endpoint.get("mode") == (stat.S_IFSOCK | 0o660) and
            context == {"selected": "default", "name": "default",
                        "endpoint": locality.ENDPOINT, "skip_tls_verify": False,
                        "tls_material": {}} and
            daemon.get("os") == "linux" and daemon.get("client_context") == "default" and
            isinstance(daemon.get("id"), str) and daemon["id"] and
            record.get("generator") in (
                ordinary_ref(Path(locality.__file__)),
                SCHEMA2_HISTORICAL_LOCALITY_GENERATOR,
            ),
            "Launcher Docker CLI/socket/context identity is invalid")
    return record


def validate_location_identity(record, source: Path, out_dir: Path, log: Path):
    require(isinstance(record, dict) and set(record) == {
                "source", "out_parent", "log_parent", "preflight_parent", "out"
            }, "Launcher filesystem-identity proof is incomplete")
    expected_paths = {
        "source": source, "out_parent": out_dir.parent, "log_parent": log.parent,
        "preflight_parent": log.parent, "out": out_dir,
    }
    for name, expected_path in expected_paths.items():
        row = record.get(name)
        require(isinstance(row, dict) and set(row) == {
                    "path", "device", "inode", "mode", "uid", "gid"
                } and row.get("path") == str(expected_path) and
                all(type(row.get(field)) is int
                    for field in ("device", "inode", "mode", "uid", "gid")) and
                stat.S_ISDIR(row["mode"]),
                f"Invalid launcher {name} filesystem identity")
        try:
            current = expected_path.stat()
        except OSError as error:
            raise ComparisonError(f"Cannot recheck launcher {name} identity: {error}") from error
        require({"path": str(expected_path), "device": current.st_dev,
                 "inode": current.st_ino, "mode": current.st_mode,
                 "uid": current.st_uid, "gid": current.st_gid} == row,
                f"Launcher {name} filesystem identity changed")
    return record


def validate_launcher_preflight(record, role: str, source: Path, out_dir: Path,
                                log: Path, container, builder, source_snapshot):
    fields = {
        "schema", "kind", "role", "contract", "container_environment",
        "inner_command", "lock", "builder", "source", "stage_verification",
        "locations", "container_name", "attempt_nonce", "docker_locality",
        "docker_locality_sha256", "location_identity", "docker_command",
    }
    require(isinstance(record, dict) and set(record) == fields,
            "Unexpected x86 build launcher preflight fields")
    require(record["schema"] == 2 and
            record["kind"] == "wonad-x86-build-launch-preflight" and
            record["role"] == role and record["contract"] == LAUNCHER_PIN and
            record["container_environment"] == LAUNCHER_ENVIRONMENT and
            record["inner_command"] == CONTAINER_COMMAND[2] and
            record["lock"] == ordinary_ref(LOCK) == source_snapshot["pin"]["lock"] and
            record["builder"] == builder and record["source"] == source_snapshot,
            "Launcher preflight pin, builder, or pre-build source differs")
    attempt_nonce = record["attempt_nonce"]
    locality_sha256 = record["docker_locality_sha256"]
    docker_locality = validate_launcher_locality(
        record["docker_locality"], preflight_schema=record["schema"])
    require(NONCE.fullmatch(str(attempt_nonce)) and NONCE.fullmatch(str(locality_sha256)) and
            canonical_digest(docker_locality) == locality_sha256,
            "Launcher Docker locality digest or attempt nonce is invalid")
    require(record["locations"] == {
        "source": str(source), "out": str(out_dir), "log": str(log),
    } and record["container_name"] == container["name"] and
            record["docker_command"] == launcher_docker_command(
                source, out_dir, container["name"], attempt_nonce, locality_sha256) and
            container.get("labels") == {
                "org.wonad.phase1.attempt": attempt_nonce,
                "org.wonad.phase1.locality": locality_sha256,
            },
            "Launcher preflight paths, container, or Docker argv differ")
    validate_location_identity(record["location_identity"], source, out_dir, log)
    if role == "baseline":
        require(record["stage_verification"] is None,
                "Baseline launcher preflight contains custom stage verification")
    else:
        verification = record["stage_verification"]
        require(isinstance(verification, dict) and
                set(verification) == {"command", "output"},
                "Custom launcher preflight lacks exact stage verification")
        command = verification["command"]
        require(command == [sys.executable, str(STAGE_OS), "--source", str(source),
                            "--verify-only"] and
                isinstance(verification["output"], str) and
                "PASS: exact owned Wonad stage, patches, targets and tools verified" in
                verification["output"].splitlines(),
                "Custom launcher stage verification command/output differs")
    return record


def collect_attempt4_locality_evidence(source: Path, out_dir: Path, container,
                                       builder, source_snapshot):
    """Authenticate attempt-4's immutable live-sampling proof offline.

    The proof records that the container was running when sampled. Verification
    performs no Docker operation, so it remains usable after the container exits.
    """
    try:
        record = locality.verify(
            ATTEMPT4_LOCALITY_PROOF, ATTEMPT4_LOCALITY_PROOF_SHA256)
    except (locality.ProofError, provenance.ProvenanceError, OSError) as error:
        raise ComparisonError(
            f"Pinned attempt-4 Docker locality proof failed offline verification: {error}"
        ) from error
    proof_container = record["container"]
    require({
                "id": proof_container["id"],
                "name": proof_container["name"],
                "image": proof_container["image"],
                "image_reference": proof_container["image_reference"],
                "created": proof_container["created"],
                "started_at": proof_container["started_at"],
            } == {
                "id": container["id"],
                "name": container["name"],
                "image": container["image"],
                "image_reference": container["image_reference"],
                "created": container["created"],
                "started_at": container["started_at"],
            } and proof_container["image"] == builder["image"]["id"] and
            proof_container["image_reference"] == builder["reference"],
            "Pinned attempt-4 Docker proof names a different container or builder")
    require([(row["destination"], row["source"])
             for row in record["bind_identity"]] == [
                 (locality.CONTAINER_SOURCE, str(source)),
                 (locality.CONTAINER_OUT, str(out_dir)),
             ], "Pinned attempt-4 Docker proof names different source/OUT binds")
    require(record["lock"] == source_snapshot["pin"]["lock"] == ordinary_ref(LOCK) and
            record["locked_manifest"]["host"] ==
            source_snapshot["pin"]["default_xml"],
            "Pinned attempt-4 Docker proof names a different lock or manifest")
    require(record["generator"] == ATTEMPT4_LOCALITY_GENERATOR ==
            ordinary_ref(Path(locality.__file__)),
            "Pinned attempt-4 Docker proof has the wrong generator")
    proof_file = ordinary_ref(ATTEMPT4_LOCALITY_PROOF)
    require(proof_file["sha256"] == ATTEMPT4_LOCALITY_PROOF_SHA256,
            "Pinned attempt-4 Docker proof changed after offline verification")
    return {
        "path": str(ATTEMPT4_LOCALITY_PROOF),
        "file": proof_file,
        "authenticated_sha256": ATTEMPT4_LOCALITY_PROOF_SHA256,
        "scope": record["scope"],
    }


def collect_launch_evidence(role: str, source: Path, out_dir: Path, log: Path,
                            container, builder, source_snapshot):
    preflight_path = log.with_name(log.name + ".preflight.json")
    if not os.path.lexists(preflight_path):
        require(role == "baseline" and {
            "id": container["id"], "name": container["name"],
            "source": str(source), "out": str(out_dir), "log": str(log),
        } == BASELINE_ATTEMPT4,
                "A launcher preflight sidecar is required (only pinned baseline attempt-4 "
                "has a post-hoc exception)")
        return {
            "state": "post-hoc-pinned-baseline-attempt-4",
            "expected_path": str(preflight_path),
            "scope": "post-build-clean-source-plus-retained-container-mount-and-log-evidence",
            "docker_locality_proof": collect_attempt4_locality_evidence(
                source, out_dir, container, builder, source_snapshot),
            "limitations": list(ATTEMPT4_LIMITATIONS),
        }
    require(preflight_path.is_file() and not preflight_path.is_symlink(),
            "Launcher preflight sidecar is not an ordinary file")
    payload, reference = stable_bytes(preflight_path)
    record = validate_launcher_preflight(
        parse_json(payload, str(preflight_path)), role, source, out_dir, log,
        container, builder, source_snapshot)
    result = {
        "state": "launcher-preflight",
        "path": str(preflight_path),
        "file": reference,
        "launcher": ordinary_ref(X86_BUILD_LAUNCHER),
        "pre_build_source_sha256": canonical_digest(record["source"]),
        "limitations": [],
    }
    if role == "custom":
        result["stage_verifier"] = ordinary_ref(STAGE_OS)
    return result


def validate_build_log(path: Path):
    payload, reference = stable_bytes(path)
    require(b"\x00" not in payload, "Build log contains NUL bytes")
    statuses = re.findall(rb"^#### (build completed successfully|failed to build some targets).*####\s*$",
                          payload, re.MULTILINE)
    require(statuses == [b"build completed successfully"],
            "Build log does not prove one clean successful build")
    expected_lines = {
        "TARGET_PRODUCT": BUILD_CONTRACT["target_product"],
        "TARGET_BUILD_VARIANT": BUILD_CONTRACT["target_variant"],
        "TARGET_ARCH": BUILD_CONTRACT["target_arch"],
        "OUT_DIR": BUILD_CONTRACT["container_out_dir"],
    }
    for key, expected in expected_lines.items():
        values = {value.decode("utf-8", "strict") for value in
                  re.findall(rb"^" + key.encode() + rb"=([^\r\n]+)$", payload, re.MULTILINE)}
        require(values == {expected}, f"Build log {key} differs from the fixed build contract")
    return {**reference, "status": "success"}


def collect_build_engine(source: Path, out_dir: Path):
    siso = source / "prebuilts/siso/linux-x86/siso"
    soong_log = out_dir / "soong.log"
    config_dir = out_dir / "siso_config"
    main_star = config_dir / "main.star"
    main_link = config_dir / "main"
    source_main_star = source / "build/soong/siso_config/main.star"
    for path, label in ((siso, "pinned Siso binary"), (soong_log, "Soong build log"),
                        (main_star, "Siso main.star"),
                        (source_main_star, "source Siso main.star")):
        require(path.is_file() and not path.is_symlink(), f"Missing or symlinked {label}")
    require(config_dir.is_dir() and not config_dir.is_symlink(),
            "Siso config repository is missing or symlinked")
    require({entry.name for entry in os.scandir(config_dir)} == {"main", "main.star"} and
            main_link.is_symlink() and os.readlink(main_link) == "/sources/build/soong/siso_config",
            "Siso config repository closure differs from the fixed /sources topology")
    payload, soong_ref = stable_bytes(soong_log)
    require(b"SOONG_NINJA=" not in payload and b"SOONG_NINJA " not in payload,
            "SOONG_NINJA override is forbidden for the comparison build")
    execution_lines = re.findall(
        rb'^.*"(soong bootstrap|ninja)" executing "prebuilts/siso/linux-x86/siso".*$',
        payload, re.MULTILINE)
    require(execution_lines.count(b"soong bootstrap") == 1 and
            execution_lines.count(b"ninja") == 1,
            "Soong log does not prove one pinned Siso bootstrap and final ninja execution")
    siso_lines = [line for line in payload.splitlines()
                  if b' executing "prebuilts/siso/linux-x86/siso"' in line]
    require(len(siso_lines) == 2 and
            all(b"--config_repo_dir=out/siso_config" in line for line in siso_lines),
            "Siso executions do not both use the relative config repository")
    require(not re.search(rb"--config_repo_dir=/", payload),
            "Soong log contains an absolute Siso config repository")
    main_payload, main_ref = stable_bytes(main_star)
    require(main_payload == SISO_MAIN_STAR,
            "Generated Siso main.star differs from the fixed relative-OUT_DIR configuration")
    return {
        "engine": "pinned-siso",
        "container_exec_root": BUILD_CONTRACT["container_source"],
        "container_out_dir": BUILD_CONTRACT["container_out_dir"],
        "siso_binary": ordinary_ref(siso),
        "soong_log": soong_ref,
        "siso_main_star": main_ref,
        "siso_main_link": "/sources/build/soong/siso_config",
        "siso_source_main_star": ordinary_ref(source_main_star),
        "soong_ninja_override": "absent",
        "config_repo_dir": "out/siso_config",
    }


def build_fingerprint(product: Path, artifacts):
    name = "build_fingerprint-sdk_phone64_x86_64.txt"
    path = artifact_path(product, name)
    payload, reference = stable_bytes(path)
    try:
        value = payload.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ComparisonError("Build fingerprint is not UTF-8") from error
    require(FINGERPRINT.fullmatch(value) is not None,
            "Build fingerprint differs from the fixed x86 development target")
    require(reference == {key: artifacts["images"][name][key] for key in ("sha256", "size")},
            "Build fingerprint changed during artifact capture")
    return value


def capture_builder():
    try:
        return provenance.capture_builder(provenance.load_json(LOCK)["builder"]["image_digest"], LOCK)
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error


def capture(role: str, source_value: Path, out_value: Path, log_value: Path,
            container_value: str, output: Path, certificate: Path | None, jobs: int):
    require(role in {"baseline", "custom"}, "Build role must be baseline or custom")
    verification_tools = verification_tool_ledger()
    source = exact_path(source_value, "source checkout", directory=True)
    out_dir = exact_path(out_value, "OUT_DIR", directory=True)
    log = exact_path(log_value, "build log")
    require(outside(out_dir, source) and outside(source, out_dir) and
            not filesystem_trees_overlap(source, out_dir),
            "OUT_DIR must be external to the source checkout")
    require(outside(log, source) and outside(log, out_dir) and
            not within_filesystem(log, source) and not within_filesystem(log, out_dir),
            "Build log must remain outside source and OUT_DIR")
    require(output.is_absolute(), "Receipt output must be an absolute path")
    output_parent = output.parent.resolve(strict=True)
    require(output_parent == output.parent and not output.parent.is_symlink(),
            "Receipt output parent must be canonical and not symlinked")
    require(outside(output, source) and outside(output, out_dir) and
            not within_filesystem(output, source) and not within_filesystem(output, out_dir),
            "Receipt must remain outside source and OUT_DIR")
    product = out_dir / PROJECT
    require(product.is_dir() and not product.is_symlink(), "Expected emu64x product output is absent")
    definitions = artifact_definitions()
    source_snapshot = collect_source_snapshot(source, role, certificate, LOCK, jobs)
    builder = capture_builder()
    artifacts = collect_artifacts(product, role, jobs)
    fingerprint = build_fingerprint(product, artifacts)
    build_log = validate_build_log(log)
    build_engine = collect_build_engine(source, out_dir)
    container = collect_container_execution(container_value, source, out_dir, log, builder)
    launch_evidence = collect_launch_evidence(
        role, source, out_dir, log, container, builder, source_snapshot)
    # Re-read source and artifact definitions around the potentially long image
    # hashing pass. A concurrent source restage cannot inherit this receipt.
    require(collect_source_snapshot(source, role, certificate, LOCK, jobs) == source_snapshot,
            "Source changed during receipt capture")
    require(artifact_definitions() == definitions,
            "Artifact definitions changed during receipt capture")
    require(collect_artifacts(product, role, jobs) == artifacts,
            "Build artifacts changed during receipt capture")
    require(build_fingerprint(product, artifacts) == fingerprint,
            "Build fingerprint changed during receipt capture")
    require(validate_build_log(log) == build_log,
            "Build log changed during receipt capture")
    require(collect_build_engine(source, out_dir) == build_engine,
            "Pinned Siso evidence changed during receipt capture")
    require(collect_container_execution(container["id"], source, out_dir, log, builder) == container,
            "Preserved build-container evidence changed during receipt capture")
    require(collect_launch_evidence(role, source, out_dir, log, container, builder,
                                    source_snapshot) == launch_evidence,
            "Launcher preflight evidence changed during receipt capture")
    require(verification_tool_ledger() == verification_tools,
            "Receipt verification tools changed during receipt capture")
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "kind": "wonad-x86-build-comparison-input",
        "role": role,
        "scope": "build-comparison-only-not-runtime-qualification",
        "build_contract": BUILD_CONTRACT,
        "locations": {
            "source": str(source), "out_dir": str(out_dir),
            "product": str(product), "build_log": str(log),
        },
        "builder": builder,
        "source": source_snapshot,
        "artifact_definitions": definitions,
        "fingerprint": fingerprint,
        "artifacts": artifacts,
        "build_log": build_log,
        "build_engine": build_engine,
        "container": container,
        "launch_evidence": launch_evidence,
        "verification_tools": verification_tools,
        "generator": ordinary_ref(Path(__file__)),
    }
    try:
        provenance.atomic_new(output, receipt)
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error
    return receipt, ordinary_ref(output)["sha256"]


def validate_file_row(row, *, absent_allowed=False):
    require(isinstance(row, dict) and isinstance(row.get("path"), str),
            "Invalid artifact row")
    safe_relative(row["path"])
    if row.get("state") == "absent":
        require(absent_allowed and set(row) == {"path", "state"}, "Invalid absent artifact row")
    else:
        require(set(row) == {"path", "state", "sha256", "size"} and
                row["state"] == "present" and SHA256.fullmatch(str(row["sha256"])) and
                type(row["size"]) is int and row["size"] > 0,
                "Invalid present artifact row")


def validate_source_shape(source, role):
    require(isinstance(source, dict) and set(source) == {
        "pin", "stage", "owned_tracked_changes", "generated_inputs",
        "worktree_materializations", "worktree_materializations_sha256",
    }, "Unexpected source snapshot fields")
    pin = source["pin"]
    require(isinstance(pin, dict) and set(pin) == {
        "release", "lock", "manifest_commit", "manifest_tag_object", "default_xml",
        "projects", "project_count", "project_ledger_sha256", "repo_tool_commit",
        "repo_tool_revision",
    }, "Unexpected source pin fields")
    lock = provenance.validate_lock(provenance.load_json(LOCK))
    require(pin["release"] == lock["release"] and
            pin["lock"] == provenance.file_ref(LOCK) and
            pin["manifest_commit"] == lock["manifest"]["commit"] and
            pin["manifest_tag_object"] == lock["manifest"]["tag_object"] and
            pin["default_xml"] == {"sha256": lock["manifest"]["default_xml_sha256"],
                                   "size": lock["manifest"]["default_xml_size"]} and
            pin["repo_tool_commit"] == lock["repo_tool"]["commit"] and
            pin["repo_tool_revision"] == lock["repo_tool"]["revision"] and
            re.fullmatch(r"[0-9a-f]{40}", str(pin["manifest_commit"])) and
            re.fullmatch(r"[0-9a-f]{40}", str(pin["manifest_tag_object"])) and
            re.fullmatch(r"[0-9a-f]{40}", str(pin["repo_tool_commit"])) and
            isinstance(pin["projects"], list) and
            type(pin["project_count"]) is int and pin["project_count"] == len(pin["projects"]) and
            pin["project_count"] > 0 and
            pin["project_ledger_sha256"] == canonical_digest(pin["projects"]),
            "Invalid source pin")
    for row in pin["projects"]:
        require(isinstance(row, dict) and set(row) == {"path", "name", "revision", "remote"} and
                isinstance(row["path"], str) and safe_relative(row["path"]) and
                isinstance(row["name"], str) and row["name"] and
                re.fullmatch(r"[0-9a-f]{40}", str(row["revision"])) and
                (row["remote"] is None or isinstance(row["remote"], str)),
                "Invalid source project ledger row")
    require(len({row["path"] for row in pin["projects"]}) == pin["project_count"],
            "Duplicate source project path")
    materializations = source["worktree_materializations"]
    require(isinstance(materializations, dict) and
            set(materializations) == {row["path"] for row in pin["projects"]} and
            source["worktree_materializations_sha256"] ==
            canonical_digest(materializations),
            "Source worktree materialization ledger is inconsistent")
    for path, value in materializations.items():
        safe_relative(path)
        try:
            provenance.validate_worktree_materializations(
                value, label=f"x86 project {path}")
        except provenance.ProvenanceError as error:
            raise ComparisonError(str(error)) from error
    stage = source["stage"]
    if role == "baseline":
        require(stage == {"state": "absent"} and not source["owned_tracked_changes"] and
                not source["generated_inputs"], "Baseline receipt contains staged source")
    else:
        require(isinstance(stage, dict) and set(stage) == {
            "state", "marker", "marker_sha256", "development_certificate", "qualification"
        } and stage["state"] == "schema-4-owned-stage" and
                stage["qualification"] == "emulator-development-only" and
                SHA256.fullmatch(str(stage["marker_sha256"])),
                "Custom receipt lacks schema-4 development staging")
        marker = stage["marker"]
        certificate = stage["development_certificate"]
        require(isinstance(marker, dict) and marker.get("schema") == 4 and
                isinstance(certificate, dict) and set(certificate) == {
                    "file", "der_sha256", "der_size", "subject"
                } and isinstance(certificate["file"], dict) and
                set(certificate["file"]) == {"sha256", "size"} and
                SHA256.fullmatch(str(certificate["file"]["sha256"])) and
                type(certificate["file"]["size"]) is int and certificate["file"]["size"] > 0 and
                SHA256.fullmatch(str(certificate["der_sha256"])) and
                type(certificate["der_size"]) is int and 128 <= certificate["der_size"] <= 65536 and
                isinstance(certificate["subject"], str) and certificate["subject"] and
                marker.get("signer_sha256") == certificate.get("der_sha256"),
                "Custom stage/certificate binding is invalid")
        validate_custom_stage_inventory(
            marker, source["owned_tracked_changes"], source["generated_inputs"])
    for ledger_name in ("owned_tracked_changes", "generated_inputs"):
        ledger = source[ledger_name]
        require(isinstance(ledger, dict), f"Invalid {ledger_name}")
        for name, row in ledger.items():
            safe_relative(name)
            require(isinstance(row, dict) and set(row) == {"sha256", "size", "mode"} and
                    SHA256.fullmatch(str(row["sha256"])) and type(row["size"]) is int and
                    row["size"] >= 0 and type(row["mode"]) is int,
                    f"Invalid source inventory row: {name}")
    if role == "custom":
        marker = source["stage"]["marker"]
        generated = source["generated_inputs"]
        require(source["stage"]["marker_sha256"] ==
                generated["external/wonad/.wonad-stage.json"]["sha256"],
                "Custom marker file digest differs from source inventory")
        for name, digest in marker["files"].items():
            require(isinstance(digest, str) and SHA256.fullmatch(digest) and
                    generated["external/wonad/" + safe_relative(name).as_posix()]["sha256"] == digest,
                    f"Custom staged file differs from marker: {name}")
        for name, digest in marker_owned_targets(marker).items():
            row = source["owned_tracked_changes"].get(name)
            if row is None:
                row = generated.get(name)
            require(isinstance(row, dict) and row.get("sha256") == digest,
                    f"Custom platform target differs from marker: {name}")


def validate_launch_evidence_shape(evidence, role: str, locations, container, source_snapshot):
    require(isinstance(evidence, dict), "Invalid launch evidence")
    if evidence.get("state") == "post-hoc-pinned-baseline-attempt-4":
        require(role == "baseline" and set(evidence) == {
            "state", "expected_path", "scope", "docker_locality_proof", "limitations",
        } and evidence["expected_path"] == locations["build_log"] + ".preflight.json" and
                evidence["scope"] ==
                "post-build-clean-source-plus-retained-container-mount-and-log-evidence" and
                evidence["limitations"] == ATTEMPT4_LIMITATIONS and {
                    "id": container["id"], "name": container["name"],
                    "source": locations["source"], "out": locations["out_dir"],
                    "log": locations["build_log"],
                } == BASELINE_ATTEMPT4,
                "Invalid post-hoc baseline attempt-4 exception")
        expected_proof = collect_attempt4_locality_evidence(
            Path(locations["source"]), Path(locations["out_dir"]), container,
            {"reference": container["image_reference"],
             "image": {"id": container["image"]}}, source_snapshot)
        require(evidence["docker_locality_proof"] == expected_proof,
                "Invalid or unavailable post-hoc attempt-4 Docker locality proof")
        return
    expected = {
        "state", "path", "file", "launcher", "pre_build_source_sha256", "limitations",
    }
    if role == "custom":
        expected.add("stage_verifier")
    require(evidence.get("state") == "launcher-preflight" and set(evidence) == expected and
            evidence["path"] == locations["build_log"] + ".preflight.json" and
            evidence["limitations"] == [] and
            evidence["pre_build_source_sha256"] == canonical_digest(source_snapshot),
            "Invalid launcher preflight evidence summary")
    for name in ("file", "launcher") + (("stage_verifier",) if role == "custom" else ()):
        row = evidence[name]
        require(isinstance(row, dict) and set(row) == {"sha256", "size"} and
                SHA256.fullmatch(str(row["sha256"])) and type(row["size"]) is int and
                row["size"] > 0,
                f"Invalid launch-evidence file reference: {name}")


def validate_receipt_shape(receipt):
    require(isinstance(receipt, dict) and set(receipt) == {
        "schema", "kind", "role", "scope", "build_contract", "locations", "builder",
        "source", "artifact_definitions", "fingerprint", "artifacts", "build_log",
        "build_engine", "container", "launch_evidence", "verification_tools", "generator",
    }, "Unexpected x86 build receipt fields")
    role = receipt["role"]
    require(receipt["schema"] == RECEIPT_SCHEMA and
            receipt["kind"] == "wonad-x86-build-comparison-input" and
            role in {"baseline", "custom"} and
            receipt["scope"] == "build-comparison-only-not-runtime-qualification" and
            receipt["build_contract"] == BUILD_CONTRACT,
            "Unsupported x86 build receipt")
    locations = receipt["locations"]
    require(isinstance(locations, dict) and set(locations) == {
        "source", "out_dir", "product", "build_log"
    }, "Unexpected receipt locations")
    for name, value in locations.items():
        require(isinstance(value, str) and Path(value).is_absolute(),
                f"Receipt {name} location is not absolute")
    require(locations["product"] == str(Path(locations["out_dir"]) / PROJECT),
            "Receipt product is not inside its selected OUT_DIR")
    definitions = receipt["artifact_definitions"]
    current = artifact_definitions()
    require(definitions == current,
            "Receipt artifact set differs from the current reviewed definition")
    try:
        provenance.validate_builder(receipt["builder"], provenance.validate_lock(provenance.load_json(LOCK)))
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error
    validate_source_shape(receipt["source"], role)
    require(isinstance(receipt["fingerprint"], str) and
            FINGERPRINT.fullmatch(receipt["fingerprint"]), "Invalid build fingerprint")
    artifacts = receipt["artifacts"]
    require(isinstance(artifacts, dict) and set(artifacts) == {"images", "os_artifacts"} and
            set(artifacts["images"]) == set(IMAGE_FILES) and
            set(artifacts["os_artifacts"]) == set(OS_PATHS),
            "Receipt artifact inventory is incomplete")
    for name, row in artifacts["images"].items():
        validate_file_row(row)
        require(row["path"] == name, f"Image artifact path differs: {name}")
    for name, row in artifacts["os_artifacts"].items():
        validate_file_row(row, absent_allowed=role == "baseline" and name in NATIVE_ONLY)
        require(row["path"] == OS_PATHS[name], f"OS artifact path differs: {name}")
        if role == "baseline":
            require((name in NATIVE_ONLY) == (row["state"] == "absent"),
                    "Baseline native artifact state differs")
        else:
            require(row["state"] == "present", "Custom OS artifact is absent")
    log = receipt["build_log"]
    require(isinstance(log, dict) and set(log) == {"sha256", "size", "status"} and
            SHA256.fullmatch(str(log["sha256"])) and type(log["size"]) is int and
            log["size"] > 0 and log["status"] == "success", "Invalid build log record")
    engine = receipt["build_engine"]
    require(isinstance(engine, dict) and set(engine) == {
        "engine", "container_exec_root", "container_out_dir", "siso_binary", "soong_log",
        "siso_main_star", "siso_main_link", "siso_source_main_star",
        "soong_ninja_override", "config_repo_dir",
    } and engine["engine"] == "pinned-siso" and
            engine["container_exec_root"] == "/sources" and engine["container_out_dir"] == "out" and
            engine["siso_main_link"] == "/sources/build/soong/siso_config" and
            engine["soong_ninja_override"] == "absent" and
            engine["config_repo_dir"] == "out/siso_config",
            "Invalid pinned Siso build evidence")
    for name in ("siso_binary", "soong_log", "siso_main_star", "siso_source_main_star"):
        row = engine[name]
        require(isinstance(row, dict) and set(row) == {"sha256", "size"} and
                SHA256.fullmatch(str(row["sha256"])) and type(row["size"]) is int and row["size"] > 0,
                f"Invalid build-engine evidence: {name}")
    validate_container_record(receipt["container"], Path(locations["source"]),
                              Path(locations["out_dir"]),
                              {key: log[key] for key in ("sha256", "size")},
                              receipt["builder"])
    validate_launch_evidence_shape(receipt["launch_evidence"], role, locations,
                                   receipt["container"], receipt["source"])
    require(receipt["verification_tools"] == verification_tool_ledger(),
            "Receipt verification tools differ from the current reviewed tools")
    generator = receipt["generator"]
    require(generator == ordinary_ref(Path(__file__)),
            "Receipt generator differs from the current reviewed tool")
    return receipt


def verify_artifact(product: Path, row):
    path = artifact_path(product, row["path"])
    if row["state"] == "absent":
        require(not path.exists() and not path.is_symlink(),
                f"Receipted absent artifact now exists: {row['path']}")
    else:
        require(ordinary_ref(path) == {"sha256": row["sha256"], "size": row["size"]},
                f"Build artifact differs from receipt: {row['path']}")


def verify(receipt_path: Path, expected_sha256: str, *, rehash=True):
    require(isinstance(expected_sha256, str) and SHA256.fullmatch(expected_sha256),
            "An exact lowercase out-of-band receipt SHA-256 is required")
    require(receipt_path.is_absolute(), "Receipt path must be absolute")
    receipt_path = exact_path(receipt_path, "receipt")
    payload, actual = stable_bytes(receipt_path)
    require(actual["sha256"] == expected_sha256, "Receipt differs from authenticated SHA-256")
    receipt = validate_receipt_shape(parse_json(payload, str(receipt_path)))
    if rehash:
        locations = receipt["locations"]
        source = exact_path(Path(locations["source"]), "receipted source", directory=True)
        out_dir = exact_path(Path(locations["out_dir"]), "receipted OUT_DIR", directory=True)
        product = exact_path(Path(locations["product"]), "receipted product", directory=True)
        log_path = exact_path(Path(locations["build_log"]), "receipted build log")
        require(product == out_dir / PROJECT and
                not filesystem_trees_overlap(source, out_dir) and
                not within_filesystem(log_path, source) and
                not within_filesystem(log_path, out_dir) and
                not within_filesystem(receipt_path, source) and
                not within_filesystem(receipt_path, out_dir) and
                not os.path.samefile(receipt_path, log_path),
                "Receipted locations overlap or changed identity")
        rows = [*receipt["artifacts"]["images"].values(),
                *receipt["artifacts"]["os_artifacts"].values()]
        with ThreadPoolExecutor(max_workers=min(16, len(rows))) as pool:
            list(pool.map(lambda row: verify_artifact(product, row), rows))
        require(validate_build_log(log_path) == receipt["build_log"],
                "Build log differs from receipt")
        require(collect_build_engine(source, out_dir) == receipt["build_engine"],
                "Pinned Siso build evidence differs from receipt")
        require(collect_container_execution(receipt["container"]["id"], source, out_dir,
                                            log_path, receipt["builder"]) == receipt["container"],
                "Preserved build-container evidence differs from receipt")
        require(collect_launch_evidence(
            receipt["role"], source, out_dir, log_path, receipt["container"],
            receipt["builder"], receipt["source"]) == receipt["launch_evidence"],
                "Launcher preflight evidence differs from receipt")
        require(build_fingerprint(product, receipt["artifacts"]) == receipt["fingerprint"],
                "Build fingerprint differs from receipt")
    require(receipt["verification_tools"] == verification_tool_ledger(),
            "Receipt verification tools changed during verification")
    return receipt


def comparison_row(baseline, custom):
    if baseline["state"] == "present" and custom["state"] == "present":
        equal = (baseline["sha256"], baseline["size"]) == (custom["sha256"], custom["size"])
    else:
        equal = baseline["state"] == custom["state"] == "absent"
    return {"baseline": baseline, "custom": custom, "equal": equal}


def compare(baseline_path: Path, baseline_sha256: str, custom_path: Path,
            custom_sha256: str, output: Path, *, rehash=True):
    baseline_path = exact_path(baseline_path, "baseline receipt")
    custom_path = exact_path(custom_path, "custom receipt")
    require(not os.path.samefile(baseline_path, custom_path),
            "Baseline and custom receipts must be distinct files")
    baseline = verify(baseline_path, baseline_sha256, rehash=rehash)
    custom = verify(custom_path, custom_sha256, rehash=rehash)
    require(baseline["role"] == "baseline" and custom["role"] == "custom",
            "Comparison requires baseline then custom receipts")
    for key, label in (("build_contract", "build contract"), ("builder", "builder"),
                       ("artifact_definitions", "artifact definitions"),
                       ("verification_tools", "receipt verification tools"),
                       ("generator", "receipt generator")):
        require(baseline[key] == custom[key], f"Baseline/custom {label} differs")
    require(baseline["source"]["pin"] == custom["source"]["pin"],
            "Baseline/custom signed-manifest source pin differs")
    require(baseline["source"]["worktree_materializations"] ==
            custom["source"]["worktree_materializations"] and
            baseline["source"]["worktree_materializations_sha256"] ==
            custom["source"]["worktree_materializations_sha256"],
            "Baseline/custom build-visible source materialization differs")
    baseline_source = exact_path(Path(baseline["locations"]["source"]),
                                 "baseline source", directory=True)
    custom_source = exact_path(Path(custom["locations"]["source"]),
                               "custom source", directory=True)
    baseline_out = exact_path(Path(baseline["locations"]["out_dir"]),
                              "baseline OUT_DIR", directory=True)
    custom_out = exact_path(Path(custom["locations"]["out_dir"]),
                            "custom OUT_DIR", directory=True)
    baseline_log = exact_path(Path(baseline["locations"]["build_log"]), "baseline build log")
    custom_log = exact_path(Path(custom["locations"]["build_log"]), "custom build log")
    require(not filesystem_trees_overlap(baseline_source, custom_source),
            "Baseline and custom builds must retain distinct source checkouts")
    require(not filesystem_trees_overlap(baseline_out, custom_out),
            "Baseline and custom builds must use distinct external OUT_DIR trees")
    require(not os.path.samefile(baseline_log, custom_log),
            "Baseline and custom builds must use distinct build logs")
    require(baseline["container"]["id"] != custom["container"]["id"] and
            baseline["container"]["name"] != custom["container"]["name"],
            "Baseline and custom builds must use distinct retained containers")
    require(baseline["fingerprint"] == custom["fingerprint"],
            "Baseline/custom build fingerprint differs")
    for field in ("siso_binary", "siso_main_star", "siso_main_link",
                  "siso_source_main_star", "soong_ninja_override", "config_repo_dir",
                  "container_exec_root", "container_out_dir"):
        require(baseline["build_engine"][field] == custom["build_engine"][field],
                f"Baseline/custom pinned Siso evidence differs: {field}")
    require(baseline["container"]["image"] == custom["container"]["image"],
            "Baseline/custom build-container image differs")
    images = {name: comparison_row(baseline["artifacts"]["images"][name],
                                   custom["artifacts"]["images"][name])
              for name in IMAGE_FILES}
    os_artifacts = {name: comparison_row(baseline["artifacts"]["os_artifacts"][name],
                                         custom["artifacts"]["os_artifacts"][name])
                    for name in sorted(OS_PATHS)}
    require(all(os_artifacts[name]["baseline"]["state"] == "absent" and
                os_artifacts[name]["custom"]["state"] == "present" for name in NATIVE_ONLY),
            "Wonad native libraries were not cleanly introduced by the custom build")
    require(all(not os_artifacts[name]["equal"] for name in REQUIRED_CHANGED),
            "Custom framework/SystemUI artifacts do not all differ from baseline")
    require(not images["system-qemu.img"]["equal"],
            "Custom system image is byte-identical to the clean baseline")
    changed_images = sorted(name for name, row in images.items() if not row["equal"])
    changed_os = sorted(name for name, row in os_artifacts.items() if not row["equal"])
    result = {
        "schema": COMPARISON_SCHEMA,
        "kind": "wonad-x86-baseline-custom-comparison",
        "scope": "exact-build-artifact-delta-not-runtime-qualification",
        "baseline_receipt": {"sha256": baseline_sha256, "receipt": ordinary_ref(baseline_path)},
        "custom_receipt": {"sha256": custom_sha256, "receipt": ordinary_ref(custom_path)},
        "shared": {
            "build_contract": baseline["build_contract"],
            "builder_identity_sha256": baseline["builder"]["identity_sha256"],
            "source_pin_sha256": canonical_digest(baseline["source"]["pin"]),
            "worktree_materializations_sha256":
                baseline["source"]["worktree_materializations_sha256"],
            "verification_tools_sha256": baseline["verification_tools"]["identity_sha256"],
            "fingerprint": baseline["fingerprint"],
        },
        "evidence_limitations": {
            "baseline": baseline["launch_evidence"]["limitations"],
            "custom": custom["launch_evidence"]["limitations"],
        },
        "images": images,
        "os_artifacts": os_artifacts,
        "changed": {"images": changed_images, "os_artifacts": changed_os},
        "result": "passed_exact_clean_baseline_custom_delta",
    }
    require(output.is_absolute() and not os.path.lexists(output),
            "Comparison output must be a fresh absolute path")
    output_parent = exact_path(output.parent, "comparison output parent", directory=True)
    require(output_parent == output.parent and
            all(not within_filesystem(output, tree) for tree in
                (baseline_source, custom_source, baseline_out, custom_out)) and
            output not in {baseline_path, custom_path},
            "Comparison output must remain outside both builds and receipts")
    # Close receipt/artifact/container races after all comparison calculations.
    require(verify(baseline_path, baseline_sha256, rehash=rehash) == baseline and
            verify(custom_path, custom_sha256, rehash=rehash) == custom,
            "A comparison input changed before the result was written")
    _, baseline_reference = stable_bytes(baseline_path)
    _, custom_reference = stable_bytes(custom_path)
    require(baseline_reference["sha256"] == baseline_sha256 and
            custom_reference["sha256"] == custom_sha256,
            "A comparison receipt changed before the result was written")
    result["baseline_receipt"]["receipt"] = baseline_reference
    result["custom_receipt"]["receipt"] = custom_reference
    try:
        provenance.atomic_new(output, result)
    except provenance.ProvenanceError as error:
        raise ComparisonError(str(error)) from error
    return result, ordinary_ref(output)["sha256"]


def verify_comparison(comparison_path: Path, expected_sha256: str,
                      baseline_path: Path, baseline_sha256: str,
                      custom_path: Path, custom_sha256: str, *, rehash=True):
    """Authenticate an existing comparison against its exact two receipts.

    The comparison document is reproduced through :func:`compare`, rather
    than accepted as a free-standing assertion.  This intentionally repeats
    all clean-baseline/custom source, container, engine, artifact, and delta
    checks and closes input races before returning.
    """
    require(isinstance(expected_sha256, str) and SHA256.fullmatch(expected_sha256),
            "An exact lowercase out-of-band comparison SHA-256 is required")
    comparison_path = exact_path(comparison_path, "comparison evidence")
    baseline_path = exact_path(baseline_path, "baseline receipt")
    custom_path = exact_path(custom_path, "custom receipt")
    require(not os.path.samefile(comparison_path, baseline_path) and
            not os.path.samefile(comparison_path, custom_path),
            "Comparison evidence and its receipts must be distinct files")
    payload, reference = stable_bytes(comparison_path)
    require(reference["sha256"] == expected_sha256,
            "Comparison evidence differs from authenticated SHA-256")
    document = parse_json(payload, str(comparison_path))
    with tempfile.TemporaryDirectory(prefix="wonad-x86-comparison-verify-") as directory:
        reproduced_path = Path(directory) / "comparison.json"
        reproduced, _ = compare(
            baseline_path, baseline_sha256, custom_path, custom_sha256,
            reproduced_path, rehash=rehash)
    require(document == reproduced,
            "Comparison evidence is not the exact result for the authenticated receipts")
    # `compare` reverified both receipts immediately before writing its
    # reproduced result.  Re-parse their authenticated structure without a
    # third multi-gigabyte artifact pass so callers can bind exact locations.
    baseline = verify(baseline_path, baseline_sha256, rehash=False)
    custom = verify(custom_path, custom_sha256, rehash=False)
    locations = [
        Path(baseline["locations"][name]) for name in ("source", "out_dir")
    ] + [Path(custom["locations"][name]) for name in ("source", "out_dir")]
    require(all(not within_filesystem(comparison_path, tree) for tree in locations),
            "Comparison evidence must remain outside both source and OUT_DIR trees")
    _, final_reference = stable_bytes(comparison_path)
    require(final_reference == reference,
            "Comparison evidence changed during authentication")
    return document, baseline, custom


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    actions = value.add_subparsers(dest="action", required=True)
    capture_action = actions.add_parser("capture", help="create one immutable build receipt")
    capture_action.add_argument("--role", choices=("baseline", "custom"), required=True)
    capture_action.add_argument("--source", type=Path, required=True)
    capture_action.add_argument("--out-dir", type=Path, required=True)
    capture_action.add_argument("--build-log", type=Path, required=True)
    capture_action.add_argument(
        "--container", required=True,
        help="preserved, successfully exited Docker build container name or full ID")
    capture_action.add_argument("--development-certificate", type=Path)
    capture_action.add_argument("--jobs", type=int, default=16)
    capture_action.add_argument("--output", type=Path, required=True)
    verify_action = actions.add_parser("verify", help="verify a receipt and its retained artifacts")
    verify_action.add_argument("--receipt", type=Path, required=True)
    verify_action.add_argument("--expected-sha256", required=True)
    compare_action = actions.add_parser("compare", help="compare authenticated baseline/custom receipts")
    compare_action.add_argument("--baseline", type=Path, required=True)
    compare_action.add_argument("--baseline-sha256", required=True)
    compare_action.add_argument("--custom", type=Path, required=True)
    compare_action.add_argument("--custom-sha256", required=True)
    compare_action.add_argument("--output", type=Path, required=True)
    verify_comparison_action = actions.add_parser(
        "verify-comparison", help="verify a comparison and its exact authenticated receipts")
    verify_comparison_action.add_argument("--comparison", type=Path, required=True)
    verify_comparison_action.add_argument("--expected-sha256", required=True)
    verify_comparison_action.add_argument("--baseline", type=Path, required=True)
    verify_comparison_action.add_argument("--baseline-sha256", required=True)
    verify_comparison_action.add_argument("--custom", type=Path, required=True)
    verify_comparison_action.add_argument("--custom-sha256", required=True)
    return value


def main(argv=None):
    arguments = parser().parse_args(argv)
    try:
        if arguments.action == "capture":
            if arguments.role == "baseline" and arguments.development_certificate is not None:
                raise ComparisonError("Baseline capture forbids --development-certificate")
            if arguments.role == "custom" and arguments.development_certificate is None:
                raise ComparisonError("Custom capture requires --development-certificate")
            _, digest = capture(arguments.role, arguments.source, arguments.out_dir,
                                arguments.build_log, arguments.container, arguments.output,
                                arguments.development_certificate, arguments.jobs)
            print(digest)
        elif arguments.action == "verify":
            verify(arguments.receipt, arguments.expected_sha256)
            print("PASS: authenticated x86 build receipt and retained artifacts")
        elif arguments.action == "compare":
            _, digest = compare(arguments.baseline, arguments.baseline_sha256,
                                arguments.custom, arguments.custom_sha256, arguments.output)
            print(digest)
        else:
            verify_comparison(arguments.comparison, arguments.expected_sha256,
                              arguments.baseline, arguments.baseline_sha256,
                              arguments.custom, arguments.custom_sha256)
            print("PASS: authenticated x86 baseline/custom comparison and receipts")
    except (ComparisonError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
