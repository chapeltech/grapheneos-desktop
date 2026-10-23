#!/usr/bin/env python3
"""Freeze the external-only selected slice, host controls, and ordered patches."""
from pathlib import Path
import difflib
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "sealed"
STAGE = Path("/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if OUTPUT.exists():
        raise SystemExit("sealed output already exists; preserve it")
    OUTPUT.mkdir()
    for name in ("README.md", "LOCK-ORDER.md", "PRIVATE-API-PROPOSAL.md",
                 "apply_candidate.py", "test_candidate.py", "seal_candidate.py"):
        shutil.copyfile(HERE / name, OUTPUT / name)
    shutil.copytree(HERE / "candidate", OUTPUT / "candidate")
    shutil.copytree(HERE / "tests/stubs", OUTPUT / "tests/stubs")
    for name in ("TotalControlRoutingTest.kt", "NativeNonceAdapterTest.kt", "NativeLifetimeTest.cpp.in"):
        shutil.copyfile(HERE / "tests" / name, OUTPUT / "tests" / name)
    result = subprocess.run(["/usr/bin/python3", "-B", str(OUTPUT / "test_candidate.py"),
        "--evidence", str(OUTPUT / "host")], env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180)
    (OUTPUT / "host/replay-output.txt").write_text(result.stdout)
    if result.returncode:
        raise SystemExit(result.stdout)
    print(result.stdout, end="")

    spec = importlib.util.spec_from_file_location("candidate", OUTPUT / "apply_candidate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    originals = {}
    targets = {}
    patch_dir = OUTPUT / "patches"
    patch_dir.mkdir()
    native = {
        "Entry.h": "services/inputflinger/dispatcher/Entry.h",
        "InputDispatcher.cpp": "services/inputflinger/dispatcher/InputDispatcher.cpp",
        "InputDispatcherPolicyInterface.h": "services/inputflinger/dispatcher/include/InputDispatcherPolicyInterface.h",
        "FakeInputDispatcherPolicy.h": "services/inputflinger/tests/FakeInputDispatcherPolicy.h",
        "FakeInputDispatcherPolicy.cpp": "services/inputflinger/tests/FakeInputDispatcherPolicy.cpp",
    }
    base = {
        "InputManagerService.java": "services/core/java/com/android/server/input/InputManagerService.java",
        "KeyGestureController.java": "services/core/java/com/android/server/input/KeyGestureController.java",
        "com_android_server_input_InputManagerService.cpp": "services/core/jni/com_android_server_input_InputManagerService.cpp",
    }
    integration = {
        "WonadInputBridge.kt": "android/input-integration/src/org/wonad/server/input/WonadInputBridge.kt",
        "WonadUiBridge.kt": "android/input-integration/src/com/android/server/wm/WonadUiBridge.kt",
        "WonadPolicyKeyContainment.kt": "android/input-integration/src/org/wonad/server/input/WonadPolicyKeyContainment.kt",
        "WonadPolicyKeyAdapter.kt": "android/input-integration/src/org/wonad/server/input/WonadPolicyKeyAdapter.kt",
    }
    groups = [("01-frameworks-base-wonad-private-key-admission.patch", "frameworks/base", base, STAGE / "frameworks/base"),
              ("02-frameworks-native-wonad-private-key-admission.patch", "frameworks/native", native, STAGE / "frameworks/native"),
              ("03-wonad-input-integration.patch", "repository", integration, module.ROOT)]
    patch_order = []
    for name, project, mapping, source_root in groups:
        chunks = []
        exact_targets = []
        for generated_name, relative in mapping.items():
            original_path = source_root / relative
            output_path = OUTPUT / "host/generated" / generated_name
            original = original_path.read_text() if original_path.is_file() else ""
            original_sha = digest(original_path) if original_path.is_file() else None
            target_sha = digest(output_path)
            chunks.append("diff --git a/" + relative + " b/" + relative + "\n")
            if original_sha is None:
                chunks.append("new file mode 100644\n")
            chunks.extend(difflib.unified_diff(original.splitlines(keepends=True),
                output_path.read_text().splitlines(keepends=True),
                fromfile="a/" + relative if original_sha else "/dev/null",
                tofile="b/" + relative))
            key = project + "/" + relative
            originals[key] = {"path": str(original_path), "sha256": original_sha,
                              "exists": original_sha is not None}
            targets[key] = {"generated": "host/generated/" + generated_name,
                            "sha256": target_sha}
            exact_targets.append(relative)
        patch = patch_dir / name
        patch.write_text("".join(chunks))
        patch_order.append({"name": name, "project": project, "sha256": digest(patch),
                            "targets": exact_targets})
    input_pins = {label: {"path": str(path), "sha256": expected}
        for label, (path, expected) in {**module.INPUTS, **module.SUPPORT_INPUTS}.items()}
    manifest = {
        "schema": "external-private-key-admission-host-seal-v1",
        "status": "partial-unqualified-external-host-only-not-staged",
        "predecessor_manifest_sha256": "86911f6affc9128a34f9c6a736e2aeb5ace554587471fb1f4986fdaaae818b17",
        "source_manifest": {"path": str(STAGE / ".repo/manifests/default.xml"),
            "sha256": digest(STAGE / ".repo/manifests/default.xml"),
            "frameworks_base_revision": "84183aff99be5e156dc0446a6fa2d4a7150f4bc3",
            "frameworks_native_revision": "1c83ac6ae533c74ecb0486369c0d2f9e79783b3d"},
        "source_inputs": input_pins,
        "originals": originals,
        "targets": targets,
        "ordered_patches": patch_order,
        "tools": {str(path): digest(path) for path in (
            STAGE / "external/kotlinc/bin/kotlinc",
            STAGE / "prebuilts/jdk/jdk21/linux-x86/bin/java",
            STAGE / "prebuilts/jdk/jdk21/linux-x86/bin/javac", Path("/usr/bin/g++"))},
        "extra_native_source_inputs": {str(path): digest(path) for path in (
            STAGE / "frameworks/native/services/inputflinger/dispatcher/InputState.cpp",
            STAGE / "frameworks/native/services/inputflinger/Android.bp",
            STAGE / "frameworks/native/services/inputflinger/dispatcher/Android.bp")},
        "files": {str(path.relative_to(OUTPUT)): digest(path)
            for path in sorted(OUTPUT.rglob("*")) if path.is_file()},
    }
    (OUTPUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    sums = "".join(digest(path) + "  " + str(path.relative_to(OUTPUT)) + "\n"
        for path in sorted(OUTPUT.rglob("*")) if path.is_file())
    (OUTPUT / "SHA256SUMS").write_text(sums)
    for path in OUTPUT.rglob("*"):
        path.chmod(path.stat().st_mode & ~0o222)
    OUTPUT.chmod(OUTPUT.stat().st_mode & ~0o222)
    print("SEALED_MANIFEST_SHA256=" + digest(OUTPUT / "MANIFEST.json"))


if __name__ == "__main__":
    main()
