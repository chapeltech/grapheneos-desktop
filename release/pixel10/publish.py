#!/usr/bin/python3
"""Publish verified handoff; only the last conditional write changes what phones see."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess as sp
import tempfile
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from source import PINS
from verify import digest, require, verify
from apps import verify_catalog
import ota_publication as pointers

LIMIT = 2**31
BASE = PINS["update_url"]


def assets(d, out, limit=LIMIT):
    files = []
    for src in sorted(d.iterdir()):
        if src.stat().st_size < limit:
            files.append(src)
            continue
        with src.open("rb") as f:
            i = 0
            while f.peek(1):
                part = out / f"{src.name}.part{i:03d}"
                with part.open("xb") as p:
                    remaining = limit - 1
                    while remaining and (block := f.read(min(remaining, 1024**2))):
                        p.write(block)
                        remaining -= len(block)
                files.append(part)
                i += 1
    return files


def newer(old, build, stamp, channel):
    if old is None:
        return
    prev, when, device, label = old.split()
    require(device == "frankel" and label == channel and re.fullmatch("[0-9]{10}", prev)
            and build > prev and stamp > int(when), "duplicate, downgrade or malformed channel")


def visible(path, first_byte=False):
    if path.endswith(".zip"):
        match = re.fullmatch(r"frankel-(?:ota_update|incremental-[0-9]+)-(20[0-9]{8})\.zip", path)
        require(match is not None, "invalid OTA asset")
        url = f'{PINS["ota_download_url"]}frankel-0.1-{match[1]}/{path}'
    else:
        url = BASE + path
    req = Request(url, headers={"Range":"bytes=0-0"} if first_byte else {})
    response = urlopen(req, timeout=120)
    require(response.url.startswith("https://"), "insecure redirect")
    return response


def public_metadata(name):
    try:
        with visible(name) as r:
            return r.read(32769)
    except HTTPError as e:
        if e.code != 404:
            raise
        return None


def channel_text(channel):
    value = public_metadata("frankel-" + channel)
    return value.decode() if value is not None else None


def publish():
    env = os.environ
    build, channel, commit = env["BUILD_NUMBER"], env["CHANNEL"], env["SOURCE_COMMIT"]
    require(channel in ("beta", "stable") and re.fullmatch(r"20[0-9]{8}", build), "invalid dispatch")
    d = Path(env["SIGNED_ROOT"]) / build
    trust = Path(env["PUBLIC_TRUST"])
    stamp = verify(d, trust, build, commit, env["UNSIGNED_SUMS_SHA256"])
    tag = "frankel-0.1-" + build
    ota = d / f"frankel-ota_update-{build}.zip"
    key = "frankel-" + channel
    require(ota.stat().st_size < LIMIT, "full OTA does not fit in a single GitHub Release asset")
    def gh(*args):
        return sp.check_output(["gh", *args], text=True)
    old_bytes, old_sha = pointers.read(key)
    old = old_bytes.decode() if old_bytes is not None else None
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        release = f"{build} {stamp} frankel {channel}\n"
        if old != release:
            newer(old, build, stamp, channel)
        parts = tmp / "parts"
        parts.mkdir()
        pub = assets(d,parts)
        notes = Path(__file__).with_name("INSTALL.md")
        attachments = [*pub, notes, trust / "avb_pkmd.bin"]

        def expected_assets():
            return {p.name: "sha256:" + digest(p) for p in attachments}

        def check_assets(record, expected):
            require({a["name"]: a["digest"] for a in record["assets"]} == expected and
                    len(record["assets"]) == len(expected), "GitHub assets differ from signed handoff")

        if channel == "beta":
            # Refuse old build numbers, even when they would still be newer than stable.
            tags = gh("api","--paginate","repos/{owner}/{repo}/tags","--jq",".[].name").splitlines()
            require(not any(t.startswith("frankel-0.1-") and t > tag for t in tags), "newer release exists")
            def find_draft():
                ids = gh("api", "--paginate", "repos/{owner}/{repo}/releases", "--jq",
                         f'.[] | select(.tag_name == "{tag}" and .draft) | .id').splitlines()
                require(len(ids) <= 1 and all(i.isdecimal() for i in ids), "ambiguous release draft")
                return ids[0] if ids else None

            draft = find_draft()
            expected = expected_assets()
            if tag not in tags and draft is None:
                gh("release","create",tag,"--draft","--prerelease","--target",commit,
                   "--title","Pixel 10 candidate "+build,"--notes-file",str(notes))
                gh("release","upload",tag,*map(str,attachments))
                draft = find_draft()
                require(draft is not None, "new candidate draft not found")
            if draft is not None:
                record = json.loads(gh("api", "repos/{owner}/{repo}/releases/" + draft))
                require(record["draft"] and record["prerelease"] and record["target_commitish"] == commit and
                        record["tag_name"] == tag, "candidate draft has wrong identity")
                check_assets(record, expected)
                gh("release","edit",tag,"--draft=false")
        else:
            with visible("desktop-apps-stable.json") as r:
                app = verify_catalog(r.read(32769), trust / "app-catalog.pem", "stable", int(time.time()))
            require(app["min_os"] <= build <= app["max_os"],
                    "there is no published Stable desktop app release for this OS build")
            require(channel_text("beta") == f"{build} {stamp} frankel beta\n", "untested candidate")
            previous = env["TESTED_FROM_BUILD"]
            require(re.fullmatch("20[0-9]{8}",previous) and previous < build, "need an older physical test build")
            report = env.get("HARDWARE_REPORT","")
            require(report.startswith("https://") and not any(c.isspace() for c in report),
                    "hardware qualification report URL required")
            require(gh("release","view","frankel-0.1-"+previous,"--json","isDraft","--jq",".isDraft").strip()=="false",
                    "predecessor was never released")
            expected = expected_assets()
        require(gh("api",f"repos/{{owner}}/{{repo}}/commits/{tag}","--jq",".sha").strip()==commit,
                "release tag source mismatch")
        actual = json.loads(gh("api",f"repos/{{owner}}/{{repo}}/releases/tags/{tag}"))
        require(not actual["draft"], "candidate release is still a draft")
        check_assets(actual, expected)
        try:
            with visible("frankel-incremental-0-"+build+".zip"):
                raise ValueError("nonexistent incrementals must return HTTP 404")
        except HTTPError as e:
            if e.code != 404: raise
        with visible(ota.name, True) as r:
            require(r.status == 206 and r.headers["Content-Range"] == f"bytes 0-0/{ota.stat().st_size}",
                    "update host does not support correct byte ranges")
        with visible(ota.name) as r:
            require(hashlib.file_digest(r,"sha256").hexdigest() == digest(ota), "bad publicly served OTA")
        if old != release:
            pointers.write(key, release.encode(), old_sha)
        pointers.wait_visible(key, release.encode(), public_metadata)
        if channel == "stable":
            gh("release","edit",tag,"--prerelease=false","--latest")


if __name__ == "__main__":
    publish()
