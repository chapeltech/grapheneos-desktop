#!/usr/bin/env python3
"""Replay a frozen candidate in one new external directory, preserving outputs."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import traceback


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    snapshot = args.snapshot.resolve(strict=True)
    args.run.mkdir(exist_ok=False)
    run = args.run.resolve(strict=True)
    result = {"snapshot": str(snapshot), "run": str(run), "status": "RUNNING",
              "commands": [], "qualifier": "host/source protocol only; no platform build/runtime"}
    try:
        verified = subprocess.run(["sha256sum", "--check", "SHA256SUMS"], cwd=snapshot,
                                  text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  check=True)
        result["manifest_check"] = verified.stdout
        result["sha256sums_sha256"] = digest(snapshot / "SHA256SUMS")
        result["manifest_sha256"] = digest(snapshot / "MANIFEST.json")
        assert result["manifest_sha256"] == args.manifest_sha256, "sealed manifest identity drift"
        manifest = json.loads((snapshot / "MANIFEST.json").read_text())
        for path in [snapshot, *snapshot.rglob("*")]:
            assert not path.is_symlink(), f"sealed symlink: {path}"
            assert path.stat().st_mode & 0o222 == 0, f"writable sealed path: {path}"
        input_hashes = {}
        for fields in manifest["source_inputs"].values():
            input_hashes[fields["path"]] = fields["sha256"]
        for fields in manifest["originals"].values():
            if fields["exists"]:
                input_hashes[fields["path"]] = fields["sha256"]
            else:
                assert not Path(fields["path"]).exists(), fields["path"]
        input_hashes.update(manifest["extra_native_source_inputs"])
        input_hashes.update(manifest["tools"])
        input_hashes[manifest["source_manifest"]["path"]] = manifest["source_manifest"]["sha256"]
        for path, expected_hash in input_hashes.items():
            assert digest(Path(path)) == expected_hash, f"source/tool pin drift: {path}"
        result["verified_source_tool_pins"] = input_hashes
        generated = run / "generated"
        regenerated = subprocess.run([sys.executable, "-B", str(snapshot / "apply_candidate.py"),
                                      "--output", str(generated)], text=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     check=True)
        result["regeneration"] = regenerated.stdout
        frozen_generated = snapshot / "host" / "generated"
        frozen_files = {path.name for path in frozen_generated.iterdir() if path.is_file()}
        replay_files = {path.name for path in generated.iterdir() if path.is_file()}
        assert frozen_files == replay_files, "generated file inventory drift"
        for name in sorted(frozen_files):
            assert digest(frozen_generated / name) == digest(generated / name), name
        result["generated_byte_match"] = sorted(frozen_files)

        spec = importlib.util.spec_from_file_location("frozen_native_candidate", snapshot / "test_candidate.py")
        assert spec and spec.loader
        candidate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(candidate)
        original_run = candidate.run

        def recording_run(argv: list[str], *, expected: str | None = None) -> str:
            entry = {"argv": argv, "expected": expected}
            result["commands"].append(entry)
            try:
                output = original_run(argv, expected=expected)
                entry["output"] = output
                if output.strip():
                    print(output.strip(), flush=True)
                return output
            except BaseException as failure:
                entry["error"] = str(failure)
                raise

        candidate.run = recording_run
        candidate.source_guards(generated)
        candidate.compile_and_run(generated, run)
        result["producer_guard_checks"] = candidate.checks
        cross_file = subprocess.run([sys.executable, "-B", str(Path(__file__).parent /
                                     "verify_private_protocol.py"), str(generated)],
                                    text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, check=True)
        result["independent_private_protocol"] = cross_file.stdout
        print(cross_file.stdout, flush=True)
        result["status"] = "PASS"
    except BaseException:
        result["status"] = "FAIL"
        result["error"] = traceback.format_exc()
        raise
    finally:
        result["preserved_artifact_sha256"] = {
            str(path.relative_to(run)): digest(path)
            for path in sorted(run.rglob("*")) if path.is_file() and path.name != "result.json"
        }
        (run / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(f"INDEPENDENT_FROZEN_REVIEW_{result['status']} {run / 'result.json'}", flush=True)


if __name__ == "__main__":
    main()
