#!/usr/bin/python3
"""Split an approved unsigned handoff for a private draft; reconstitute it on the hosted runner."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import tempfile

import apps

HERE = Path(__file__).resolve().parent
COMMON = runpy.run_path(str(HERE / "sign-release.py"))
FILES = {"os": COMMON["UNSIGNED_FILES"], "apps": apps.INPUTS}
PART = 1024 ** 3
MAX_PARTS = 16
BLOCK = 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def private_draft(kind, build):
    require(kind in FILES and apps.BUILD.fullmatch(build), "invalid intake identity")
    return f"pixel10-intake-{kind}-{build}"


def sums(kind, path, approved):
    with path.open("rb") as f:
        body = f.read(4097)
    require(len(body) <= 4096 and hashlib.sha256(body).hexdigest() == approved,
            "handoff checksums do not match the approved signing request")
    rows = {}
    for line in body.decode("ascii").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([a-zA-Z0-9_.-]+)", line)
        require(match is not None, "invalid checksum row")
        digest, name = match.groups()
        require(name in FILES[kind] and name not in rows, "unexpected checksum path")
        rows[name] = digest
    require(rows.keys() == FILES[kind], "incomplete signing handoff")
    return body, rows


def part_name(name, i):
    return f"{name}.part{i:03d}"


def pack(kind, source, dest, build, commit, approved, limit=PART):
    COMMON["identity"](build, commit, approved)
    require((source / "source-commit").read_text() == commit + "\n" and
            (source / "build-number").read_text() == build + "\n", "wrong build or commit in handoff")
    require({p.name for p in source.iterdir()} == FILES[kind] | {"SHA256SUMS"} and
            all(p.is_file() and not p.is_symlink() for p in source.iterdir()), "unexpected signing handoff inventory")
    body, rows = sums(kind, source / "SHA256SUMS", approved)
    with tempfile.TemporaryDirectory(dir=dest.parent, prefix=".stage-") as temp:
        out = Path(temp) / "assets"
        out.mkdir(mode=0o700)
        index = {}
        for name, expected in rows.items():
            digest = hashlib.sha256()
            count = 0
            with (source / name).open("rb") as src:
                while src.peek(1):
                    require(count < MAX_PARTS, "signing handoff exceeds supported part count")
                    with (out / part_name(name, count)).open("xb") as dst:
                        remaining = limit
                        while remaining and (block := src.read(min(remaining, BLOCK))):
                            dst.write(block)
                            digest.update(block)
                            remaining -= len(block)
                    count += 1
            require(count > 0 and digest.hexdigest() == expected, f"unsigned handoff mismatch: {name}")
            index[name] = count
        (out / "SHA256SUMS").write_bytes(body)
        (out / "intake-parts.json").write_text(json.dumps(index, sort_keys=True) + "\n")
        require(not dest.exists() and not dest.is_symlink(), "intake assets already exist")
        out.rename(dest)


def unpack(kind, source, dest, build, commit, approved, limit=PART):
    COMMON["identity"](build, commit, approved)
    require(all(p.is_file() and not p.is_symlink() for p in source.iterdir()),
            "intake assets must be regular files")
    body, rows = sums(kind, source / "SHA256SUMS", approved)
    with (source / "intake-parts.json").open("rb") as f:
        table = f.read(4097)
    require(len(table) <= 4096, "intake parts index too large")
    index = json.loads(table)
    require(isinstance(index, dict) and index.keys() == rows.keys() and
            all(type(x) is int and 1 <= x <= MAX_PARTS for x in index.values()), "invalid intake parts index")
    expected = {"intake-parts.json", "SHA256SUMS"}
    for name, n in index.items():
        expected.update(part_name(name, i) for i in range(n))
    require(expected == {p.name for p in source.iterdir()}, "draft assets differ from intake parts index")
    with tempfile.TemporaryDirectory(dir=dest.parent, prefix=".restore-") as temp:
        out = Path(temp) / "unsigned"
        out.mkdir(mode=0o700)
        for name, count in index.items():
            digest = hashlib.sha256()
            with (out / name).open("xb") as dst:
                for i in range(count):
                    part = source / part_name(name, i)
                    size = part.stat().st_size
                    require(0 < size <= limit and (i == count - 1 or size == limit), "invalid intake part size")
                    with part.open("rb") as src:
                        while block := src.read(BLOCK):
                            digest.update(block)
                            dst.write(block)
            require(digest.hexdigest() == rows[name], f"intake file failed approved checksum: {name}")
        require((out / "source-commit").read_text() == commit + "\n" and
                (out / "build-number").read_text() == build + "\n", "wrong target or source commit in intake")
        require(re.fullmatch(r"[a-f0-9]{64}\n", (out / "native-inputs-sha256").read_text()),
                "invalid native input digest")
        (out / "SHA256SUMS").write_bytes(body)
        require(not dest.exists() and not dest.is_symlink(), "unsigned output already exists")
        out.rename(dest)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("pack", "unpack"))
    parser.add_argument("kind", choices=FILES)
    parser.add_argument("source", type=Path)
    parser.add_argument("dest", type=Path)
    parser.add_argument("build")
    parser.add_argument("commit")
    parser.add_argument("approved")
    args = parser.parse_args()
    {"pack": pack, "unpack": unpack}[args.mode](
        args.kind, args.source, args.dest, args.build, args.commit, args.approved)


if __name__ == "__main__":
    main()
