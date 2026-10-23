#!/usr/bin/env python3
"""Immutable inputs shared by OS staging and release-receipt validation."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath


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
)

LAUNCHER_PATCH_NAMES = (
    "wonad-recents-launcher.patch", "wonad-external-taskbar.patch",
    "wonad-external-taskbar-readiness.patch",
    "wonad-native-taskbar-admission.patch",
    "wonad-authoritative-focus-launcher.patch",
)

EMULATOR_PATCH_NAMES = (
    "emulator-freeform.patch",
    "emulator-meta-keys.patch",
)

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


def tool_ledger() -> dict[str, str]:
    result = {}
    for name in STAGE_TOOL_PATHS:
        safe_relative(name)
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Missing or symlinked release tool: {name}")
        result[name] = sha256(path)
    return result

