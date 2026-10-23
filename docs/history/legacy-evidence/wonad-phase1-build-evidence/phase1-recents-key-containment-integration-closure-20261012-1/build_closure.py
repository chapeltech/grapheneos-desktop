#!/usr/bin/env python3
"""Create the external-only snapshot-8 keyboard-containment integration closure.

The output is deliberately outside the Wonad repository and GrapheneOS trees.
Every input is authenticated before any output directory is created.
"""

from __future__ import annotations

import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil


ROOT = Path("/u/elric/tree/wonad")
EVIDENCE = Path("/u/elric/tree/wonad-phase1-build-evidence")
STAGE = Path("/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7")
SNAPSHOT = EVIDENCE / "phase1-recents-key-containment-kotlin-prototype-20261012-snapshot-8"
PEER = EVIDENCE / "phase1-recents-key-containment-snapshot8-independent-review-20261012-1.json"
DESIGN = EVIDENCE / "phase1-blocked-input-kotlin-minimization-and-owner-plan-20261012-1.md"
OUT = EVIDENCE / "phase1-recents-key-containment-integration-closure-20261012-1"

SOURCE_INPUTS = {
    "frameworks/base/services/core/java/com/android/server/input/InputManagerService.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/input/InputManagerService.java",
        "df0e4cc78508383cd60fd2cd534ba450a0df2071b211ee21115fa71f35470dc1",
        SNAPSHOT / "generated/InputManagerService.java",
        "22629d64dcb480972ca1350e3e8279f6366da3d3be3fa45a67954c8b4c6d54c0",
    ),
    "frameworks/base/services/core/java/com/android/server/input/KeyGestureController.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/input/KeyGestureController.java",
        "3acaa08d5a39200bbcd521f760339c4d531936656899c195b9b9fa9b28aa66c5",
        SNAPSHOT / "generated/KeyGestureController.java",
        "0894b31feb22d8c82b280eb39c1d229b6c28e002205c925ecfaf8a1b826ff753",
    ),
    "frameworks/base/services/core/java/com/android/server/policy/PhoneWindowManager.java": (
        STAGE / "frameworks/base/services/core/java/com/android/server/policy/PhoneWindowManager.java",
        "25be0cd9384ef463af854067e4904701041ece23ef0e9b9f8cc348503e6e1898",
        SNAPSHOT / "generated/PhoneWindowManager.java",
        "ce06e49edc4ecd9cb517fd1f37cf395a9103855fb4f3bf49dcd47d0504c4729a",
    ),
    "android/input-integration/src/org/wonad/server/input/WonadInputBridge.kt": (
        ROOT / "android/input-integration/src/org/wonad/server/input/WonadInputBridge.kt",
        "b512112fe58157e8e1a18baa3dbf0c0c338f073ea4d901c63d9949aaa11e60ff",
        SNAPSHOT / "generated/WonadInputBridge.kt",
        "c32093220a5a54f992ffd55f85bcaaa98a78163ecc79d3fafbf74b6a92e6a55f",
    ),
    "android/input-integration/src/com/android/server/wm/WonadUiBridge.kt": (
        ROOT / "android/input-integration/src/com/android/server/wm/WonadUiBridge.kt",
        "8d227e84eef912d1016698e018ca37642cff8ec0150a380eb25dbf7e8dc21da4",
        SNAPSHOT / "generated/WonadUiBridge.kt",
        "7215ee2a8697ffe418f38780937a95f665c8a269c1fb62c006573ac6c35094b2",
    ),
}

ADDITIONS = {
    "android/input-integration/src/org/wonad/server/input/WonadPolicyKeyContainment.kt": (
        SNAPSHOT / "candidate/WonadPolicyKeyContainment.kt",
        "c39e47f6c9635d78774faeff4241795bef99013fd2627af55c4e7d05c055005f",
    ),
    "android/input-integration/src/org/wonad/server/input/WonadPolicyKeyAdapter.kt": (
        SNAPSHOT / "candidate/WonadPolicyKeyAdapter.kt",
        "67890b473f35cc41c223fba124295f60eb053e4c8a1cda51258ce6838b7f69ef",
    ),
}

SUPPORT_INPUTS = {
    str(DESIGN): "ae870d2ed969f6fa8212b5d35f369fc8ba899191d5e74838b21cbcb61d4021f2",
    str(SNAPSHOT / "SHA256SUMS"): "c16018fce8d3a7f9ffc666d68fac0d0df497a0c65e38a23f11d217af5d02192d",
    str(SNAPSHOT / "receipt.json"): "3070c3f7530b7c420dc4bca777173424f704b279b3e05863c256678411925e89",
    str(PEER): "4d7e5556b56e6036e246179b34fe1a49dc92487b207a76b3b6dc338c9ef0533c",
    str(ROOT / "android/tools/stage_contract.py"): "8ca9548661d1527a3d1d396509d34dde5e960b82314f9ad169e44c3051039ca1",
    str(ROOT / "android/platform/stage-os.py"): "927bcb3366e4e5ba4cfae28ae94500853e7e3e333ae7770eddf5482bd057cdc6",
    str(ROOT / "android/tests/platform_patch_fixture.py"): "6c893a292acd465aa9ac4fb01190b7e101172db195bb384360179f547d6dfb5d",
    str(ROOT / "android/os-integration/Android.bp"): "9c31b895c21d1415e70d1f75092cb7ac4e0a3be91deb8e2d27d1e4fe76c4bc4f",
    str(STAGE / "frameworks/base/core/java/android/hardware/input/IKeyGestureHandler.aidl"):
        "0f0d5d606d91fe981c50564af000a18cf51fad41c6c6c07a7cc6d8d08cd14945",
    str(STAGE / "frameworks/base/core/java/android/hardware/input/InputManagerGlobal.java"):
        "8ae9a17705009ff4a65d9a64ca690733e290937288b061436430fad82807f774",
    str(STAGE / "frameworks/base/services/core/java/com/android/server/wm/WindowManagerService.java"):
        "c2eb228520a585d86aa4097230f5c88700d32c08cbc8f2cf4da93b3787d6342c",
    str(STAGE / "frameworks/base/libs/WindowManager/Shell/src/com/android/wm/shell/common/QuitFocusedAppKeyGestureHandler.kt"):
        "7e8461a7c5a71bbea3dfa4c365d4e09885feee9320453abe40704e6c4d4041c2",
    str(STAGE / "packages/apps/Launcher3/quickstep/src/com/android/quickstep/input/QuickstepKeyGestureEventsManager.kt"):
        "b5c059d20977d43e2bc03031b3694857df59c74df8a66ad9a61af18de35cbbb5",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(path: Path, expected: str) -> None:
    actual = sha(path)
    if actual != expected:
        raise SystemExit(f"input hash mismatch: {path}: {actual} != {expected}")


def diff(old: bytes | None, new: bytes, path: str, framework: bool) -> bytes:
    logical = path.removeprefix("frameworks/base/") if framework else path
    before = [] if old is None else old.decode().splitlines(keepends=True)
    after = new.decode().splitlines(keepends=True)
    fromfile = "/dev/null" if old is None else f"a/{logical}"
    tofile = f"b/{logical}"
    value = "".join(difflib.unified_diff(before, after, fromfile=fromfile,
        tofile=tofile, n=3))
    if not value:
        raise SystemExit(f"empty integration diff: {path}")
    return value.encode()


def changed_lines(old: bytes, new: bytes) -> dict[str, int]:
    added = removed = 0
    for line in difflib.ndiff(old.decode().splitlines(), new.decode().splitlines()):
        if line.startswith("+ "):
            added += 1
        elif line.startswith("- "):
            removed += 1
    return {"added": added, "removed": removed}


def load_stage_contract():
    path = ROOT / "android/tools/stage_contract.py"
    spec = importlib.util.spec_from_file_location("closure_stage_contract", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load stage contract")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    if OUT.exists():
        raise SystemExit(f"refusing existing output: {OUT}")
    for _name, (source, source_hash, generated, generated_hash) in SOURCE_INPUTS.items():
        check(source, source_hash)
        check(generated, generated_hash)
    for _name, (source, source_hash) in ADDITIONS.items():
        check(source, source_hash)
    for name, expected in SUPPORT_INPUTS.items():
        check(Path(name), expected)

    contract = load_stage_contract()
    if not contract.FRAMEWORK_PATCH_NAMES or (
            contract.FRAMEWORK_PATCH_NAMES[-1] != "wonad-authoritative-focus-framework.patch"):
        raise SystemExit("unexpected framework patch prefix")
    patch_prefix = []
    for name in contract.FRAMEWORK_PATCH_NAMES:
        path = ROOT / "android/platform/patches" / name
        patch_prefix.append({"name": name, "sha256": sha(path), "bytes": path.stat().st_size})

    OUT.mkdir(mode=0o755)
    (OUT / "patches").mkdir()
    (OUT / "candidate").mkdir()
    (OUT / "tests").mkdir()

    framework_patch = b"".join(diff(source.read_bytes(), generated.read_bytes(), name, True)
        for name, (source, _source_hash, generated, _generated_hash) in SOURCE_INPUTS.items()
        if name.startswith("frameworks/base/"))
    integration_patch = b"".join(diff(source.read_bytes(), generated.read_bytes(), name, False)
        for name, (source, _source_hash, generated, _generated_hash) in SOURCE_INPUTS.items()
        if name.startswith("android/"))
    integration_patch += b"".join(diff(None, source.read_bytes(), name, False)
        for name, (source, _source_hash) in ADDITIONS.items())
    (OUT / "patches/wonad-policy-key-containment-framework.patch").write_bytes(framework_patch)
    (OUT / "patches/wonad-policy-key-containment-input-integration.patch").write_bytes(
        integration_patch)

    for path in ["apply_candidate.py", "test_candidate.py"]:
        shutil.copyfile(SNAPSHOT / path, OUT / path)
    for path in sorted((SNAPSHOT / "candidate").iterdir()):
        if path.is_file():
            shutil.copyfile(path, OUT / "candidate" / path.name)
    for path in sorted((SNAPSHOT / "tests").rglob("*")):
        if path.is_file():
            relative = path.relative_to(SNAPSHOT / "tests")
            target = OUT / "tests" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)

    copied_tests = {}
    for base in [OUT / "candidate", OUT / "tests"]:
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            copied_tests[path.relative_to(OUT).as_posix()] = {
                "sha256": sha(path), "bytes": path.stat().st_size,
            }
    for path in [OUT / "apply_candidate.py", OUT / "test_candidate.py"]:
        copied_tests[path.relative_to(OUT).as_posix()] = {
            "sha256": sha(path), "bytes": path.stat().st_size,
        }

    source_map = {
        "schema": 1,
        "scope": "external-only-key-containment-integration-closure",
        "runtime_qualified": False,
        "repository_applied": False,
        "stage_list_modified": False,
        "intended_patch_order": {
            "framework_after": "wonad-authoritative-focus-framework.patch",
            "framework_append": "wonad-policy-key-containment-framework.patch",
            "input_integration": "wonad-policy-key-containment-input-integration.patch",
        },
        "framework_prefix": {
            "stage_contract_sha256": SUPPORT_INPUTS[str(ROOT / "android/tools/stage_contract.py")],
            "patches": patch_prefix,
        },
        "inputs": {
            name: {"path": str(source), "sha256": source_hash,
                "generated_path": str(generated), "generated_sha256": generated_hash}
            for name, (source, source_hash, generated, generated_hash) in SOURCE_INPUTS.items()
        },
        "additions": {
            name: {"source": str(source), "sha256": source_hash,
                "bytes": source.stat().st_size}
            for name, (source, source_hash) in ADDITIONS.items()
        },
        "support_inputs": {name: {"sha256": value, "bytes": Path(name).stat().st_size}
            for name, value in SUPPORT_INPUTS.items()},
        "delta": {
            name: changed_lines(source.read_bytes(), generated.read_bytes())
            for name, (source, _source_hash, generated, _generated_hash) in SOURCE_INPUTS.items()
        },
        "test_fixture": copied_tests,
        "snapshot8": {
            "path": str(SNAPSHOT),
            "sha256sums_sha256": SUPPORT_INPUTS[str(SNAPSHOT / "SHA256SUMS")],
            "receipt_sha256": SUPPORT_INPUTS[str(SNAPSHOT / "receipt.json")],
            "checks": 80,
        },
        "peer_review": {"path": str(PEER), "sha256": SUPPORT_INPUTS[str(PEER)],
            "result": "PASS 80/80; no concrete defect in callback/lifecycle slice"},
        "limitations": [
            "External host fixtures and source projection only",
            "No Android platform compile",
            "No emulator or device runtime execution",
            "No repository, stage list, source7, SDK, image, or runtime input modified",
        ],
    }
    (OUT / "source-map.json").write_text(json.dumps(source_map, indent=2, sort_keys=True) + "\n")

    shutil.copyfile(Path(__file__), OUT / "build_closure.py")


if __name__ == "__main__":
    main()
