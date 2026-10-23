#!/usr/bin/env python3
"""Fail-closed verifier for the external keyboard-containment closure."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = Path("/u/elric/tree/wonad")
STAGE = Path("/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_hash(path: Path, expected: str) -> None:
    actual = sha(path)
    if actual != expected:
        raise SystemExit(f"hash mismatch: {path}: {actual} != {expected}")


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def patch_targets(path: Path) -> list[str]:
    values = re.findall(r"^\+\+\+ b/(.+)$", path.read_text(), re.MULTILINE)
    if not values or len(values) != len(set(values)):
        raise SystemExit(f"missing or duplicate patch targets: {path}")
    if any(Path(value).is_absolute() or ".." in Path(value).parts for value in values):
        raise SystemExit(f"unsafe patch target: {path}")
    return values


def apply_patch(originals: dict[str, Path], patch: Path,
        expected: dict[str, str]) -> None:
    with tempfile.TemporaryDirectory(prefix="wonad-key-closure-") as directory:
        root = Path(directory)
        subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
        for logical, source in originals.items():
            target = root / logical
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(root), "-c", "user.name=Wonad closure",
            "-c", "user.email=closure@example.invalid", "-c", "commit.gpgsign=false",
            "commit", "-qm", "exact source inputs"], check=True)
        subprocess.run(["git", "-C", str(root), "apply", "--check", str(patch)], check=True)
        subprocess.run(["git", "-C", str(root), "apply", str(patch)], check=True)
        observed = sorted(path.relative_to(root).as_posix() for path in root.rglob("*")
            if path.is_file() and ".git" not in path.parts)
        if observed != sorted(expected):
            raise SystemExit(f"patched file inventory mismatch: {observed} != {sorted(expected)}")
        for logical, expected_hash in expected.items():
            require_hash(root / logical, expected_hash)


def main() -> None:
    data = json.loads((HERE / "source-map.json").read_text())
    if data != json.loads(json.dumps(data, sort_keys=True)):
        raise SystemExit("source map is not JSON-normalizable")
    if data.get("schema") != 1 or data.get("runtime_qualified") is not False:
        raise SystemExit("wrong closure schema or qualification claim")
    if data.get("repository_applied") is not False or data.get("stage_list_modified") is not False:
        raise SystemExit("external-only boundary changed")

    for row in data["inputs"].values():
        require_hash(Path(row["path"]), row["sha256"])
        require_hash(Path(row["generated_path"]), row["generated_sha256"])
    for row in data["additions"].values():
        require_hash(Path(row["source"]), row["sha256"])
    for name, row in data["support_inputs"].items():
        path = Path(name)
        require_hash(path, row["sha256"])
        if path.stat().st_size != row["bytes"]:
            raise SystemExit(f"support input size mismatch: {path}")
    for name, row in data["test_fixture"].items():
        path = HERE / name
        require_hash(path, row["sha256"])
        if path.stat().st_size != row["bytes"]:
            raise SystemExit(f"copied fixture size mismatch: {path}")

    stage_contract = load(ROOT / "android/tools/stage_contract.py", "closure_stage_contract")
    prefix = data["framework_prefix"]["patches"]
    if [row["name"] for row in prefix] != list(stage_contract.FRAMEWORK_PATCH_NAMES):
        raise SystemExit("framework prefix order changed")
    if prefix[-1]["name"] != "wonad-authoritative-focus-framework.patch":
        raise SystemExit("containment patch no longer follows authoritative focus")
    for row in prefix:
        path = ROOT / "android/platform/patches" / row["name"]
        require_hash(path, row["sha256"])
        if path.stat().st_size != row["bytes"]:
            raise SystemExit(f"framework prefix size mismatch: {path}")

    fixture = load(ROOT / "android/tests/platform_patch_fixture.py", "closure_patch_fixture")
    projected_targets = {
        "services/core/java/com/android/server/input/InputManagerService.java",
        "services/core/java/com/android/server/input/KeyGestureController.java",
        "services/core/java/com/android/server/policy/PhoneWindowManager.java",
    }
    for target in projected_targets:
        key = "frameworks/base/" + target
        projected = fixture.projected_framework_file(STAGE / "frameworks/base",
            ROOT / "android", target)
        actual = hashlib.sha256(projected).hexdigest()
        if actual != data["inputs"][key]["sha256"]:
            raise SystemExit(f"complete-stage projection mismatch: {target}: {actual}")

    framework_patch = HERE / "patches/wonad-policy-key-containment-framework.patch"
    integration_patch = HERE / "patches/wonad-policy-key-containment-input-integration.patch"
    if patch_targets(framework_patch) != sorted(projected_targets):
        raise SystemExit("framework patch target inventory mismatch")
    expected_integration = sorted([
        "android/input-integration/src/com/android/server/wm/WonadUiBridge.kt",
        "android/input-integration/src/org/wonad/server/input/WonadInputBridge.kt",
        "android/input-integration/src/org/wonad/server/input/WonadPolicyKeyAdapter.kt",
        "android/input-integration/src/org/wonad/server/input/WonadPolicyKeyContainment.kt",
    ])
    if sorted(patch_targets(integration_patch)) != expected_integration:
        raise SystemExit("input-integration patch target inventory mismatch")

    apply_patch({target: Path(data["inputs"]["frameworks/base/" + target]["path"])
            for target in projected_targets}, framework_patch,
        {target: data["inputs"]["frameworks/base/" + target]["generated_sha256"]
            for target in projected_targets})
    integration_originals = {
        name: Path(row["path"]) for name, row in data["inputs"].items()
        if name.startswith("android/")
    }
    integration_expected = {
        name: row["generated_sha256"] for name, row in data["inputs"].items()
        if name.startswith("android/")
    }
    integration_expected.update({name: row["sha256"]
        for name, row in data["additions"].items()})
    apply_patch(integration_originals, integration_patch, integration_expected)

    # The existing Kotlin glob stages both additions without a Java/AIDL/public ABI change.
    android_bp = (ROOT / "android/os-integration/Android.bp").read_text()
    if '"input-integration/src/**/*.kt"' not in android_bp:
        raise SystemExit("input integration Kotlin glob missing")

    # Lock/callback ordering is source-bound rather than inferred from fixture behavior.
    aidl = Path(next(name for name in data["support_inputs"]
        if name.endswith("IKeyGestureHandler.aidl"))).read_text()
    if "oneway interface IKeyGestureHandler" not in aidl:
        raise SystemExit("remote gesture callback is not oneway")
    adapter = (HERE / "candidate/WonadPolicyKeyAdapter.kt").read_text()
    if "topFocusedDisplayId" in adapter or "withWonadGlobalLock" in adapter:
        raise SystemExit("helper monitor gained WMS-global-lock acquisition")
    generated_kgc = Path(data["inputs"][
        "frameworks/base/services/core/java/com/android/server/input/KeyGestureController.java"]
        ["generated_path"]).read_text()
    if "mHandler.post(() -> applyWonadPolicyCleanup(decision))" not in generated_kgc:
        raise SystemExit("lifecycle cleanup is no longer queued off the WMS callback")
    if "synchronized (mGlobalLock)" not in Path(next(name for name in data["support_inputs"]
            if name.endswith("WindowManagerService.java"))).read_text():
        raise SystemExit("pinned WMS lock evidence missing")

    print("RESULT integration closure verified: 2 patches, 7 targets, 80 host checks bound")


if __name__ == "__main__":
    main()
