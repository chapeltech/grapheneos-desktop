#!/usr/bin/env python3
"""Read-only check for interrupted repo checkouts; not a source integrity audit."""
import argparse
from pathlib import Path
import subprocess
import sys


def check(source):
    source = source.resolve()
    projects = (source / ".repo/project.list").read_text().splitlines()
    if not projects:
        raise ValueError("repo project list is empty")
    problems = []
    for name in projects:
        relative = Path(name)
        if not name or relative.is_absolute() or ".." in relative.parts:
            raise ValueError("invalid repo project path: " + name)
        project = source / relative
        if (project / ".git").is_dir():
            index = project / ".git/index"
        elif (project / ".git").is_file():
            value = subprocess.check_output(
                ["git", "-C", str(project), "rev-parse", "--git-path", "index"],
                text=True, stderr=subprocess.STDOUT, timeout=30).strip()
            index = project / value
        else:
            problems.append(name + ": missing project Git directory")
            continue
        if not index.is_file():
            problems.append(name + ": missing Git index (incomplete checkout)")
        if index.with_name(index.name + ".lock").exists():
            problems.append(name + ": Git index lock present (sync active or interrupted)")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    args = parser.parse_args()
    try:
        problems = check(args.source)
        if problems:
            raise ValueError("\n".join(problems))
        print("PASS: repo checkout indexes initialized; worktree modifications not attested")
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("FAIL: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
