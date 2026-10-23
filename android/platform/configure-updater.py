#!/usr/bin/env python3
"""Configure GrapheneOS Updater for a project-owned HTTPS release channel.

The official GrapheneOS endpoint must never be used by a differently signed
build.  This tool only changes the pinned Updater revision, records the exact
owned edit, and refuses to overwrite unrelated worktree changes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "android/grapheneos.lock.json"
MARKER = ".wonad-updater-stage.json"
CONFIG = Path("packages/apps/Updater/res/values/config.xml")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate_url(value):
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
            parsed.password or parsed.query or parsed.fragment or not value.endswith("/")):
        raise ValueError("Update URL must be an HTTPS base URL ending in / without credentials, query or fragment")
    host = parsed.hostname.rstrip(".").lower()
    if host == "grapheneos.org" or host.endswith(".grapheneos.org"):
        raise ValueError("A custom-signed build must not use a GrapheneOS update endpoint")
    if host in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Production update URL must not be loopback")
    return value


def atomic_write(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(prefix=".wonad-updater-", dir=path.parent, delete=False)
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], timeout=60)


def configure(source, url):
    url = validate_url(url)
    source = source.resolve(strict=True)
    if source == ROOT or ROOT in source.parents or not (source / ".repo").is_dir():
        raise ValueError("Use a dedicated repo-synced OS checkout outside Wonad")
    lock = json.loads(LOCK.read_text())
    expected = lock["updater"]["commit"]
    updater = source / "packages/apps/Updater"
    if updater.is_symlink() or CONFIG.joinpath().is_absolute():
        raise ValueError("Refusing a symlinked Updater checkout")
    revision = git(updater, "rev-parse", "HEAD").decode().strip()
    if revision != expected:
        raise ValueError("Updater revision differs from the authenticated source pin")
    config = source / CONFIG
    if config.is_symlink() or not config.is_file():
        raise ValueError("Pinned Updater configuration is missing or symlinked")
    baseline = git(updater, "show", "HEAD:res/values/config.xml")
    upstream = lock["updater"]["upstream_url"].encode()
    needle = b'<string name="url" translatable="false">' + upstream + b"</string>"
    if baseline.count(needle) != 1:
        raise ValueError("Pinned Updater URL declaration changed; review required")
    replacement = b'<string name="url" translatable="false">' + url.encode() + b"</string>"
    desired = baseline.replace(needle, replacement)
    marker_path = source / MARKER
    previous = None
    if marker_path.exists():
        if marker_path.is_symlink() or not marker_path.is_file():
            raise ValueError("Refusing a symlinked Updater ownership marker")
        previous = json.loads(marker_path.read_text())
        if (previous.get("schema") != 1 or previous.get("updater_revision") != expected or
                previous.get("baseline_sha256") != digest(baseline)):
            raise ValueError("Updater ownership marker does not match the pinned baseline")
    actual = config.read_bytes()
    owned = previous is not None and previous.get("configured_sha256") == digest(actual)
    if actual != baseline and actual != desired and not owned:
        raise ValueError("Preserving independently modified Updater configuration")
    marker = {
        "schema": 1,
        "updater_revision": expected,
        "update_url": url,
        "baseline_sha256": digest(baseline),
        "configured_sha256": digest(desired),
    }
    marker_bytes = (json.dumps(marker, indent=2, sort_keys=True) + "\n").encode()
    if actual != desired:
        atomic_write(config, desired, config.stat().st_mode & 0o777)
    if not marker_path.exists() or marker_path.read_bytes() != marker_bytes:
        atomic_write(marker_path, marker_bytes, 0o600)
    print(f"Configured project update channel {url}; official GrapheneOS endpoint is not used")
    return marker


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    try:
        configure(args.source, args.url)
        return 0
    except (ValueError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
