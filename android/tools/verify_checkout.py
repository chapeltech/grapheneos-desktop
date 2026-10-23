#!/usr/bin/env python3
"""Verify every tracked project in a stable repo checkout before OS staging.

The signed manifest authenticates commit hashes. This check binds every listed
worktree to those hashes and rejects tracked edits or local manifest overrides.
Untracked generated vendor files are intentionally outside this claim.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


TRACKED_DIFF_TIMEOUT_SECONDS = 600


def git(project, *args):
    return subprocess.check_output(
        ["git", "-C", str(project), *args], text=True,
        stderr=subprocess.STDOUT, timeout=60).strip()


def manifest_projects(manifest):
    root = ET.parse(manifest).getroot()
    projects = {}
    for project in root.findall(".//project"):
        name = project.get("name")
        path = project.get("path") or name
        revision = project.get("revision")
        if not name or not path or not revision or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
            raise ValueError(f"stable manifest contains an unpinned project: {path or name}")
        relative = Path(path)
        if relative.is_absolute() or ".." in relative.parts or path in projects:
            raise ValueError(f"invalid or duplicate manifest project path: {path}")
        projects[path] = revision
    if not projects:
        raise ValueError("manifest contains no projects")
    return projects


def verify_project(source, item, allowed_changes=None):
    relative, expected = item
    project = source / relative
    if not project.is_dir() or project.is_symlink():
        return f"{relative}: missing or symlinked project worktree"
    try:
        if git(project, "rev-parse", "HEAD") != expected:
            return f"{relative}: HEAD differs from signed manifest"
        dirty = set(filter(None, subprocess.check_output(
            ["git", "-C", str(project), "diff", "--name-only", "-z", "HEAD", "--"],
            stderr=subprocess.STDOUT,
            timeout=TRACKED_DIFF_TIMEOUT_SECONDS).decode("utf-8").split("\0")))
        allowed = set((allowed_changes or {}).get(relative, ()))
        unexpected = dirty - allowed
        if unexpected:
            return f"{relative}: unexpected tracked worktree changes present: {sorted(unexpected)[:5]}"
    except (OSError, subprocess.SubprocessError) as error:
        return f"{relative}: Git verification failed: {error}"
    return None


def verify(source, jobs=16, allowed_changes=None):
    source = source.resolve(strict=True)
    repo = source / ".repo"
    if not repo.is_dir() or repo.is_symlink():
        raise ValueError("source is not a repo checkout")
    if (repo / "local_manifests").exists():
        raise ValueError("local manifest overrides are not allowed for a release baseline")
    projects = manifest_projects(repo / "manifests/default.xml")
    listed = (repo / "project.list").read_text().splitlines()
    if any(not item or Path(item).is_absolute() or ".." in Path(item).parts for item in listed):
        raise ValueError("repo project list contains an invalid path")
    if len(listed) != len(set(listed)):
        raise ValueError("repo project list contains duplicates")
    missing = sorted(set(projects) - set(listed))
    extra = sorted(set(listed) - set(projects))
    if missing or extra:
        raise ValueError(f"repo project list differs from signed manifest: missing={missing[:5]} extra={extra[:5]}")
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        problems = sorted(problem for problem in pool.map(
            lambda item: verify_project(source, item, allowed_changes), projects.items()) if problem)
    if problems:
        raise ValueError("\n".join(problems))
    return {"projects": len(projects), "tracked_worktrees": "clean", "untracked_files": "not_attested"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--jobs", type=int, default=16)
    args = parser.parse_args()
    try:
        if not 1 <= args.jobs <= 64:
            raise ValueError("jobs must be between 1 and 64")
        result = verify(args.source, args.jobs)
        print(f"PASS: {result['projects']} signed-manifest projects at exact clean revisions; untracked files not attested")
        return 0
    except (ValueError, OSError, ET.ParseError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
