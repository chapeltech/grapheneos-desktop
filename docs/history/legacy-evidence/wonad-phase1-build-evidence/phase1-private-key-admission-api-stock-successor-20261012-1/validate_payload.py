#!/usr/bin/env python3
"""Read the frozen seal; apply ordered patches ONLY to fresh external copies."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
SEALED = HERE / "work/sealed"
EXPECTED_MANIFEST = "86911f6affc9128a34f9c6a736e2aeb5ace554587471fb1f4986fdaaae818b17"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    assert digest(SEALED / "MANIFEST.json") == EXPECTED_MANIFEST
    manifest = json.loads((SEALED / "MANIFEST.json").read_text())
    checks = 0
    with tempfile.TemporaryDirectory(prefix="wonad-private-key-patch-replay-") as raw:
        task_temp = Path(raw)
        for item in manifest["ordered_patches"]:
            project = item["project"]
            project_copy = task_temp / project.replace("/", "_")
            project_copy.mkdir()
            patch = SEALED / "patches" / item["name"]
            assert digest(patch) == item["sha256"]
            for relative in item["targets"]:
                key = project + "/" + relative
                original = manifest["originals"][key]
                path = Path(original["path"])
                if original["exists"]:
                    assert digest(path) == original["sha256"]
                    copy = project_copy / relative
                    copy.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, copy)
                else:
                    assert not path.exists()
                checks += 1
            subprocess.run(["git", "apply", "--check", str(patch)], cwd=project_copy, check=True)
            subprocess.run(["git", "apply", str(patch)], cwd=project_copy, check=True)
            for relative in item["targets"]:
                expected = manifest["targets"][project + "/" + relative]
                assert digest(project_copy / relative) == expected["sha256"]
                checks += 1
            print("PATCH_REPLAY_PASS " + item["name"])
    print("ORDERED_PRIVATE_PATCH_TARGET_PASS checks=" + str(checks))


if __name__ == "__main__":
    main()
