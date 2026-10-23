#!/usr/bin/env python3
"""Apply authenticated payload only to a new external original-copy tree."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import traceback


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_relative(value: str) -> Path:
    result = Path(value)
    assert not result.is_absolute() and ".." not in result.parts, value
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--run", required=True, type=Path)
    args = parser.parse_args()
    snapshot = args.snapshot.resolve(strict=True)
    args.run.mkdir(exist_ok=False)
    run = args.run.resolve(strict=True)
    result = {"snapshot": str(snapshot), "run": str(run), "status": "RUNNING",
              "commands": [], "targets": {}, "scope": "external copies only"}
    try:
        assert digest(snapshot / "MANIFEST.json") == args.manifest_sha256
        result["manifest_sha256"] = args.manifest_sha256
        manifest = json.loads((snapshot / "MANIFEST.json").read_text())
        for name, entry in manifest["originals"].items():
            relative = safe_relative(name)
            if not entry["exists"]:
                assert not Path(entry["path"]).exists(), entry["path"]
                continue
            original = Path(entry["path"])
            assert digest(original) == entry["sha256"], original
            for prefix in ("pristine", "applied"):
                target = run / prefix / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original, target)
                assert digest(target) == entry["sha256"], target

        expected_union = set(manifest["targets"])
        observed_union = set()
        for patch in manifest["ordered_patches"]:
            project = safe_relative(patch["project"])
            patch_path = snapshot / "patches" / safe_relative(patch["name"])
            assert digest(patch_path) == patch["sha256"], patch_path
            headers = []
            for line in patch_path.read_text().splitlines():
                if line.startswith("diff --git "):
                    fields = line.split()
                    assert len(fields) == 4 and fields[2].startswith("a/") and fields[3].startswith("b/")
                    assert fields[2][2:] == fields[3][2:]
                    headers.append(str(safe_relative(fields[3][2:])))
                if line.startswith(("new file mode ", "old mode ", "new mode ")):
                    assert line.endswith("100644"), line
            assert len(headers) == len(set(headers)) and set(headers) == set(patch["targets"]), patch["name"]
            for relative in headers:
                key = str(project / relative)
                assert key not in observed_union, key
                observed_union.add(key)
            tree = run / "applied" / project
            # The evidence directory itself sits inside a parent Git tree.
            # Isolate each test project; otherwise git apply can silently skip
            # paths outside that parent's current subdirectory prefix.
            initialized = subprocess.run(["git", "-C", str(tree), "init", "--quiet"],
                                         text=True, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, check=True)
            result["commands"].append({"argv": ["git", "-C", str(tree), "init", "--quiet"],
                                       "output": initialized.stdout})
            root = subprocess.run(["git", "-C", str(tree), "rev-parse", "--show-toplevel"],
                                  text=True, stdout=subprocess.PIPE, check=True)
            assert Path(root.stdout.strip()).resolve(strict=True) == tree.resolve(strict=True), tree
            for options in (["--check"], []):
                argv = ["git", "-C", str(tree), "apply", *options, str(patch_path)]
                checked = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, check=True)
                result["commands"].append({"argv": argv, "output": checked.stdout})
        assert observed_union == expected_union, "ordered target union drift"
        for name, fields in manifest["targets"].items():
            actual = run / "applied" / safe_relative(name)
            assert actual.is_file() and not actual.is_symlink(), actual
            assert digest(actual) == fields["sha256"], actual
            assert actual.read_bytes() == (snapshot / safe_relative(fields["generated"])).read_bytes(), actual
            result["targets"][name] = digest(actual)
        for fields in manifest["originals"].values():
            if fields["exists"]:
                assert digest(Path(fields["path"])) == fields["sha256"], fields["path"]
        result["status"] = "PASS"
        print(f"INDEPENDENT_ORDERED_PATCHES_PASS targets={len(result['targets'])} commands={len(result['commands'])}")
    except BaseException:
        result["status"] = "FAIL"
        result["error"] = traceback.format_exc()
        raise
    finally:
        (run / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(run / "result.json")


if __name__ == "__main__":
    main()
