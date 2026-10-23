#!/usr/bin/env python3
"""Immutable inputs shared by OS staging and release-receipt validation."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import re
import subprocess
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
PATCH_ROOT = ROOT / "android/platform/patches"

FRAMEWORK_PATCH_NAMES = (
    "wonad-broker.patch", "wonad-focus.patch", "wonad-focus-lock.patch",
    "wonad-focus-order.patch", "wonad-focus-lifecycle.patch",
    "wonad-organizer-death.patch", "wonad-display-settings-lifetime.patch",
    "wonad-focused-display.patch", "wonad-focused-display-tests.patch",
    "wonad-recents-framework.patch", "wonad-recents-taskkey.patch",
    "wonad-external-ui.patch", "wonad-external-ui-lifecycle.patch",
    "wonad-external-wallpaper.patch", "wonad-external-ui-visibility.patch",
    "wonad-native-frame.patch", "wonad-native-shell-policy.patch",
    "wonad-native-task-repository.patch", "wonad-native-recovery.patch",
    "wonad-native-input-completion.patch", "wonad-native-task-bounds.patch",
    "wonad-native-protected-ui.patch", "wonad-native-permission-routing.patch",
    "wonad-native-shell-input-sink.patch",
    "wonad-native-location-button-routing.patch",
    "wonad-native-freeform-fallback.patch",
    "wonad-native-shell-home-visibility.patch",
    "wonad-native-empty-stock-roots.patch", "wonad-native-signed-frame.patch",
    "wonad-native-shortcut-priority.patch",
    "wonad-native-stock-gesture-ownership.patch",
    "wonad-native-stock-decoration-ownership.patch",
    "wonad-native-stock-decoration-boundary.patch",
    "wonad-native-home-resolution.patch", "wonad-native-home-launch-params.patch",
    "wonad-native-stock-wallpaper-boundary.patch",
    "wonad-native-incoming-wallpaper-routes.patch",
    "wonad-native-ime-parent-readiness.patch",
    "wonad-native-protected-display-raise.patch",
    "wonad-native-stock-gesture-takeover.patch",
    "wonad-authoritative-focus-framework.patch",
    "wonad-native-phone-task-return.patch",
    "wonad-shortcut-keyset.patch",
)

LAUNCHER_PATCH_NAMES = (
    "wonad-recents-launcher.patch", "wonad-external-taskbar.patch",
    "wonad-external-taskbar-readiness.patch",
    "wonad-native-taskbar-admission.patch",
    "wonad-authoritative-focus-launcher.patch",
    "wonad-recents-display-task-cache.patch",
)

EMULATOR_PATCH_NAMES = (
    "emulator-freeform.patch",
    "emulator-meta-keys.patch",
    "emulator-front-buffer-lifetime.patch",
    "emulator-multidisplay-startup-order.patch",
)

# Populate only after reviewing the native producer's actual patch bytes.
# Empty does not authorize a marker containing an undeclared native lane.
NATIVE_PATCH_NAMES = ()
NATIVE_PROJECT = "frameworks/native"
NATIVE_MANIFEST_REVISION = "1c83ac6ae533c74ecb0486369c0d2f9e79783b3d"


def reject_symlinked_path(path: Path):
    """Do not resolve an owned path into a different checkout through an ancestor."""
    absolute = path.absolute()
    if any(value.is_symlink() for value in (absolute, *absolute.parents)):
        raise ValueError("Preserving symlinked owned source path: " + str(path))


def ordinary_directory(path: Path):
    reject_symlinked_path(path)
    if not path.is_dir():
        raise ValueError("Owned source directory is missing: " + str(path))


def stage_schema() -> int:
    return 5 if NATIVE_PATCH_NAMES else 4


def platform_lanes():
    """One active contract, never choose compatibility from supplied marker."""
    lanes = {
        "frameworks_base": ("frameworks/base", FRAMEWORK_PATCH_NAMES, "frameworks_revision"),
        "launcher3": ("packages/apps/Launcher3", LAUNCHER_PATCH_NAMES, "launcher3_revision"),
        "emulator_goldfish": ("device/generic/goldfish", EMULATOR_PATCH_NAMES, "emulator_goldfish_revision"),
    }
    if NATIVE_PATCH_NAMES:
        lanes["frameworks_native"] = (NATIVE_PROJECT, NATIVE_PATCH_NAMES, "frameworks_native_revision")
    return lanes


def marker_fields():
    return {"schema", "input_profile", "signer_sha256", "signer_certificate", "files", "patches", "platform_targets", "tools"} | {
        field for path, names, field in platform_lanes().values()}


def require_stage_schema(marker):
    if (not isinstance(marker, dict) or type(marker.get("schema")) is not int or
            marker["schema"] != stage_schema()):
        raise ValueError("Owned stage schema differs from the currently registered native contract")
    if NATIVE_PATCH_NAMES:
        if (set(marker) != marker_fields() or
                marker.get("frameworks_native_revision") != NATIVE_MANIFEST_REVISION):
            raise ValueError("Native stage lacks the exact authenticated schema-5 fields/pin")
    elif "frameworks_native_revision" in marker:
        raise ValueError("Undeclared native stage pin under an empty native registry")


def native_revision_from_payload(payload: bytes, lock) -> str:
    """Derive from exact lock-authenticated bytes; a current native HEAD is not a pin."""
    pin = lock["manifest"]
    if (len(payload) != pin["default_xml_size"] or
            hashlib.sha256(payload).hexdigest() != pin["default_xml_sha256"]):
        raise ValueError("Native pin manifest bytes differ from the authenticated lock")
    root = ET.fromstring(payload)
    rows = [row for row in root.findall("project") if row.get("path") == NATIVE_PROJECT]
    if (len(rows) != 1 or rows[0].get("name") != "platform_frameworks_native" or
            rows[0].get("remote") != "grapheneos" or
            rows[0].get("revision") != NATIVE_MANIFEST_REVISION):
        raise ValueError("Native project is missing, ambiguous or outside the authenticated release")
    return rows[0].get("revision")


def native_revision_from_projects(projects) -> str:
    rows = [row for row in projects if isinstance(row, dict) and row.get("path") == NATIVE_PROJECT]
    if (len(rows) != 1 or rows[0].get("revision") != NATIVE_MANIFEST_REVISION or
            rows[0].get("name") != "platform_frameworks_native" or rows[0].get("remote") != "grapheneos"):
        raise ValueError("Native stage revision differs from the authenticated manifest project ledger")
    return rows[0]["revision"]


def authenticated_native_revision(source: Path, lock) -> str:
    manifest = source / ".repo/manifests"
    ordinary_directory(manifest)
    path = manifest / "default.xml"
    if path.is_symlink() or not path.is_file():
        raise ValueError("Native pin requires an ordinary checked-out default.xml")
    pin = lock["manifest"]
    def git(*args):
        return subprocess.check_output(["git", "-C", str(manifest), *args], timeout=30)
    if (git("rev-parse", "HEAD").decode().strip() != pin["commit"] or
            git("rev-parse", "refs/tags/" + lock["release"]).decode().strip() != pin["tag_object"] or
            git("rev-parse", "refs/tags/" + lock["release"] + "^{}").decode().strip() != pin["commit"]):
        raise ValueError("Native pin manifest checkout/tag differs from the authenticated lock")
    working = path.read_bytes()
    committed = git("show", pin["commit"] + ":default.xml")
    if working != committed:
        raise ValueError("Native pin working manifest differs from its locked committed bytes")
    return native_revision_from_payload(committed, lock)


def marker_owned_targets(marker):
    """Exact active patch-derived tracked/generated union for every consumer."""
    require_stage_schema(marker)
    lanes = platform_lanes()
    if NATIVE_PATCH_NAMES:
        expected_patches = {label: patch_ledger(names) for label, (path, names, field) in lanes.items()}
        if marker.get("patches") != expected_patches or marker.get("tools") != tool_ledger():
            raise ValueError("Native stage ordered patch/tool ledger differs from the active reviewed inputs")
    targets = marker.get("platform_targets")
    if not isinstance(targets, dict) or set(targets) != set(lanes):
        raise ValueError("Incomplete active platform target lanes")
    result = {}
    for label, (project, names, field) in lanes.items():
        rows = targets[label]
        expected = patch_target_names(names)
        if not isinstance(rows, dict) or set(rows) != expected or (names and not rows):
            raise ValueError("Incomplete " + label + " patch-derived target inventory")
        for name, digest in rows.items():
            safe_relative(name)
            if not isinstance(digest, str) or re.fullmatch("[0-9a-f]{64}", digest) is None:
                raise ValueError("Invalid owned target digest: " + label + "/" + name)
            result[project + "/" + name] = digest
    return result

# Changing any tool which defines, stages, records, or verifies the release
# invalidates the owned stage and requires an explicit restage.
STAGE_TOOL_PATHS = (
    "android/grapheneos.lock.json",
    "android/tools/stage_contract.py",
    "android/platform/stage-os.py",
    "android/platform/apply-emulator-config.sh",
    "android/platform/Dockerfile",
    "android/tools/sdk_contract.py",
    "android/tools/verify_sdk_publication.py",
    "android/platform/configure-updater.py",
    "android/platform/release-build.sh",
    "android/tools/run_release_build.py",
    "android/tools/docker_locality_proof.py",
    "android/tools/release_receipt.py",
    "android/tools/verify_release_artifacts.py",
    "android/tools/release_pair_receipt.py",
    "android/tools/verify_release_pair.py",
    "android/tools/phase1_provenance.py",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_relative(value: str) -> str:
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or path.as_posix() != value or
            any(part in {"", ".", ".."} for part in path.parts)):
        raise ValueError(f"Unsafe owned path: {value!r}")
    return value


def patches(names) -> list[Path]:
    result = []
    for name in names:
        safe_relative(name)
        path = PATCH_ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Missing or symlinked owned patch: {name}")
        result.append(path)
    return result


def patch_ledger(names) -> list[dict[str, str]]:
    return [{"name": path.name, "sha256": sha256(path)} for path in patches(names)]


def patch_target_names(names) -> set[str]:
    """Derive owned paths from registered patch bytes, never a supplied marker."""
    result = set()
    for patch in patches(names):
        targets = {safe_relative(line.removeprefix("+++ b/"))
                   for line in patch.read_text().splitlines() if line.startswith("+++ b/")}
        if not targets:
            raise ValueError("Missing declared targets in owned patch: " + patch.name)
        result.update(targets)
    return result


def tool_ledger() -> dict[str, str]:
    result = {}
    for name in STAGE_TOOL_PATHS:
        safe_relative(name)
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Missing or symlinked release tool: {name}")
        result[name] = sha256(path)
    return result

