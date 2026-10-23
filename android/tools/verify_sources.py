#!/usr/bin/env python3
"""Verify existing source checkouts against the signed GrapheneOS baseline.

This command does not fetch, reset, clean or checkout either repository.
The framework repository may be a no-checkout clone for source inspection.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True,
                                   stderr=subprocess.STDOUT, timeout=60).strip()


def verify_manifest(manifest, signers, lock):
    release = lock["release"]
    expected = lock["manifest"]
    if git(manifest, "rev-parse", f"refs/tags/{release}") != expected["tag_object"]:
        raise ValueError("manifest tag object does not match the pinned baseline")
    if git(manifest, "rev-parse", f"refs/tags/{release}^{{}}") != expected["commit"]:
        raise ValueError("manifest tag resolves to the wrong commit")
    signature = git(manifest, "-c", f"gpg.ssh.allowedSignersFile={signers.resolve()}",
                    "verify-tag", release)
    if (expected["signing_key_fingerprint"] not in signature or
            f'for {expected["signer"]} ' not in signature):
        raise ValueError("signature does not match the pinned signing identity")
    if git(manifest, "rev-parse", "HEAD") != expected["commit"]:
        raise ValueError("manifest HEAD does not match the baseline")
    xml = ET.fromstring(git(manifest, "show", "HEAD:default.xml"))
    critical = {
        "frameworks/base": ("frameworks_base", "framework"),
        "packages/apps/Launcher3": ("launcher3", "Launcher3"),
        "packages/apps/Updater": ("updater", "Updater"),
    }
    projects = {p.get("path"): p.get("revision") for p in xml.findall("project")}
    for path, (key, label) in critical.items():
        revision = lock[key]["commit"]
        if projects.get(path) != revision:
            raise ValueError(f"{label} revision is not authenticated by the manifest")
    revision = lock["frameworks_base"]["commit"]
    return {"source_baseline": "verified", "release": release,
            "deployment_device": lock["device"],
            "development_target": lock["development_target"],
            "manifest_commit": expected["commit"],
            "frameworks_base_commit": revision,
            "launcher3_commit": lock["launcher3"]["commit"],
            "updater_commit": lock["updater"]["commit"],
            "scope": "signed manifest only; source checkout not attested"}


def verify(manifest, frameworks, signers, lock):
    result = verify_manifest(manifest, signers, lock)
    revision = lock["frameworks_base"]["commit"]
    if git(frameworks, "rev-parse", "HEAD") != revision:
        raise ValueError("framework HEAD does not match the authenticated revision")
    result["scope"] = "git objects only; worktree changes are not attested"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--frameworks", type=Path)
    target.add_argument("--manifest-only", action="store_true")
    parser.add_argument("--allowed-signers", type=Path, required=True)
    args = parser.parse_args()
    try:
        lock = json.loads((ROOT / "grapheneos.lock.json").read_text())
        result = (verify_manifest(args.manifest, args.allowed_signers, lock) if args.manifest_only
                  else verify(args.manifest, args.frameworks, args.allowed_signers, lock))
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, ET.ParseError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
