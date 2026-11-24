#!/usr/bin/python3
"""Publish verified handoff; only the last conditional write changes what phones see."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess as sp
import tempfile
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from source import PINS
from verify import digest, require, verify

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
    req = Request(BASE + path, headers={"Range":"bytes=0-0"} if first_byte else {})
    response = urlopen(req, timeout=120)
    require(response.url.startswith("https://"), "insecure redirect")
    return response


def channel_text(channel):
    try:
        with visible("frankel-"+channel) as r:
            return r.read(256).decode()
    except HTTPError as e:
        if e.code != 404:
            raise
        return None


def publish():
    env = os.environ
    build, channel, commit = env["BUILD_NUMBER"], env["CHANNEL"], env["GITHUB_SHA"]
    require(channel in ("beta", "stable") and re.fullmatch(r"20[0-9]{8}", build), "invalid dispatch")
    d = Path(env["SIGNED_ROOT"]) / build
    trust = Path(env["PUBLIC_TRUST"])
    stamp = verify(d, trust, build, commit, env["UNSIGNED_SUMS_SHA256"])
    tag = "frankel-0.1-" + build
    ota = d / f"frankel-ota_update-{build}.zip"
    key = "frankel-" + channel
    bucket = env["OTA_BUCKET"]
    def aws(*args, **kw):
        return sp.check_output(["aws","s3api",*args,"--bucket",bucket], text=True, **kw)
    def gh(*args):
        return sp.check_output(["gh", *args], text=True)
    # Read through both paths. CAS against the exact bytes/version observed, not a stale CDN.
    old = channel_text(channel)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        cas = ["--if-none-match", "*"]
        if old is not None:
            obj = json.loads(aws("get-object","--key",key,str(tmp/"prior")))
            require((tmp/"prior").read_text() == old, "origin and public channel disagree")
            cas = ["--if-match", obj["ETag"]]
        release = f"{build} {stamp} frankel {channel}\n"
        if old != release:
            newer(old, build, stamp, channel)
        parts = tmp / "parts"
        parts.mkdir()
        pub = assets(d,parts)
        if channel == "beta":
            # Refuse old build numbers, even when they would still be newer than stable.
            tags = gh("api","--paginate","repos/{owner}/{repo}/tags","--jq",".[].name").splitlines()
            require(not any(t.startswith("frankel-0.1-") and t > tag for t in tags), "newer release exists")
            if tag not in tags:
                notes = Path(__file__).with_name("INSTALL.md")
                gh("release","create",tag,"--draft","--prerelease","--target",commit,
                   "--title","Pixel 10 candidate "+build,"--notes-file",str(notes))
                gh("release","upload",tag,*map(str,pub),str(notes),str(trust/"avb_pkmd.bin"))
                gh("release","edit",tag,"--draft=false")
            # An existing tag can be retried only if its public artifacts match this handoff.
        else:
            require(channel_text("beta") == f"{build} {stamp} frankel beta\n", "untested candidate")
            previous = env["TESTED_FROM_BUILD"]
            require(re.fullmatch("20[0-9]{8}",previous) and previous < build, "need an older physical test build")
            report = env.get("HARDWARE_REPORT","")
            require(report.startswith("https://") and not any(c.isspace() for c in report),
                    "hardware qualification report URL required")
            require(gh("release","view","frankel-0.1-"+previous,"--json","isDraft","--jq",".isDraft").strip()=="false",
                    "predecessor was never released")
        require(gh("api",f"repos/{{owner}}/{{repo}}/commits/{tag}","--jq",".sha").strip()==commit,
                "release tag source mismatch")
        expected = {p.name:"sha256:"+digest(p) for p in pub}
        expected["INSTALL.md"] = "sha256:"+digest(Path(__file__).with_name("INSTALL.md"))
        expected["avb_pkmd.bin"] = "sha256:"+digest(trust/"avb_pkmd.bin")
        actual = json.loads(gh("api",f"repos/{{owner}}/{{repo}}/releases/tags/{tag}"))
        require(not actual["draft"] and {a["name"]:a["digest"] for a in actual["assets"]} == expected,
                "published release differs from offline handoff")
        # Prefer an immutable origin write; retries verify the previously uploaded object.
        if channel == "beta":
            try:
                aws("put-object","--if-none-match","*","--key",ota.name,"--body",str(ota))
            except sp.CalledProcessError:
                # Don't accept an AWS error as evidence that a valid object already exists.
                aws("head-object","--key",ota.name)
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
        metadata = tmp/"metadata"
        metadata.write_text(release)
        if old != release:
            aws("put-object","--key",key,"--body",str(metadata),"--cache-control","no-store",*cas)
        if channel == "stable":
            gh("release","edit",tag,"--prerelease=false","--latest")


if __name__ == "__main__":
    publish()
