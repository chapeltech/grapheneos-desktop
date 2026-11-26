#!/usr/bin/python3
"""Independent signed desktop APK releases, without an OS build or OS keys."""
import base64
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
from zipfile import ZipFile

APPS = {
    "controller.apk": "org.wonad.desktop",
    "styx.apk": "org.wonad.styx.desktop",
    "xmonad.apk": "org.wonad.xmonad",
    "desktop-updates.apk": "org.wonad.desktop.updates",
}
UPDATER = "desktop-updates.apk"
INPUTS = set(APPS) | {"build-number", "source-commit", "native-inputs-sha256", "os-range"}
CATALOGS = {"desktop-apps-beta.json", "desktop-apps-stable.json"}
ASSETS = set(APPS) | CATALOGS | {"app-provenance.json"}
BASE = "https://repo.chapeltech.uk/android/"
REPO = "chapeltech/grapheneos-desktop"
BUILD = re.compile(r"20[0-9]{8}")
HEX = re.compile(r"[a-f0-9]{64}")
LIFETIME = 180 * 86400


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def encoded(data):
    return base64.b64encode(data).decode("ascii")


def json_bytes(data):
    return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode()


def catalog_name(channel):
    require(channel in ("beta", "stable"), "invalid channel")
    return f"desktop-apps-{channel}.json"


def tag(build):
    require(BUILD.fullmatch(build), "invalid build")
    return "desktop-apps-0.1-" + build


def os_range(path):
    min_os, max_os = path.read_text().split()
    require(BUILD.fullmatch(min_os) and BUILD.fullmatch(max_os) and min_os <= max_os,
            "invalid OS compatibility range")
    return min_os, max_os


def apk_entry(path, pkg, build, cert):
    manifest = sp.check_output(["aapt2", "dump", "badging", path], text=True)
    code = int(build) - 2_000_000_000
    require(f"package: name='{pkg}' versionCode='{code}' versionName='0.1'" in manifest
            and "application-debuggable" not in manifest, f"wrong APK identity: {path.name}")
    match = re.search(r"^targetSdkVersion:'([0-9]+)'$", manifest, re.M)
    require(match and int(match[1]) >= 35, f"target SDK too old for background updates: {path.name}")
    output = sp.check_output(["apksigner", "verify", "--print-certs", path], text=True)
    require(re.findall(r"^Signer #\d+ certificate SHA-256 digest: (\w+)$", output, re.M) == [cert],
            f"wrong APK certificate: {path.name}")
    with ZipFile(path) as apk:
        libs = {name for name in apk.namelist() if name.startswith("lib/") and name.endswith(".so")}
        expected = {
            "styx.apk": {"libXlorie.so", "libwonad_styx_desktop.so"},
            "xmonad.apk": {"libwm_executable.so", "libstyx_wm_provider.so", "libstyx_wm_action.so"},
        }.get(path.name, set())
        require(all(item.startswith("lib/arm64-v8a/") for item in libs) and
                {f"lib/arm64-v8a/{item}" for item in expected} <= libs, "missing or non-arm64 native library")
        if path.name == "styx.apk":
            require("assets/xkb/rules/evdev" in apk.namelist(), "missing keyboard data")
    size = path.stat().st_size
    require(0 < size <= 512 * 1024**2, "unexpected APK size")
    return {"package": pkg, "version_code": code, "certificate": cert, "size": size, "sha256": digest(path)}


def verify_bootstrap(path, public_key, desktop_cert):
    der = sp.check_output(["openssl", "pkey", "-pubin", "-in", public_key, "-outform", "DER"])
    with ZipFile(path) as apk:
        dex = [apk.read(name) for name in apk.namelist() if re.fullmatch(r"classes\d*\.dex", name)]
        for pin in (encoded(der), desktop_cert):
            require(any(pin.encode() in data for data in dex), "bootstrap APK missing expected public trust pin")


def sign_catalog(payload, private_key):
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "payload"
        path.write_bytes(json_bytes(payload))
        sig = sp.check_output(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", private_key, "-in", path])
        return json_bytes({"payload": encoded(path.read_bytes()), "signature": encoded(sig)})


def verify_catalog(body, public_key, channel, now=None):
    require(len(body) <= 32768, "catalog exceeds size limit")
    envelope = json.loads(body)
    require(set(envelope) == {"payload", "signature"}, "invalid catalog envelope")
    raw = base64.b64decode(envelope["payload"], validate=True)
    sig = base64.b64decode(envelope["signature"], validate=True)
    require(len(sig) == 64, "bad catalog signature length")
    with tempfile.TemporaryDirectory() as temp:
        data, signature = Path(temp) / "payload", Path(temp) / "signature"
        data.write_bytes(raw)
        signature.write_bytes(sig)
        sp.run(["openssl", "pkeyutl", "-verify", "-pubin", "-rawin", "-inkey", public_key,
                "-in", data, "-sigfile", signature], check=True, stdout=sp.DEVNULL)
    payload = json.loads(raw)
    require(payload["format"] == 1 and payload["channel"] == channel and payload["device"] == "frankel",
            "wrong catalog identity")
    require(BUILD.fullmatch(payload["build"]) and payload["generation"] == int(payload["build"]) and
            BUILD.fullmatch(payload["min_os"]) and BUILD.fullmatch(payload["max_os"]) and
            payload["min_os"] <= payload["max_os"], "invalid catalog version or OS range")
    issued, expires = payload["issued"], payload["expires"]
    require(expires == issued + LIFETIME, "invalid catalog lifetime")
    if now is not None:
        require(0 < issued <= now + 300 and now < expires, "catalog expired or not yet valid")
    return payload


def verify_release(root, trust, build, commit, unsigned_digest, channel, now=None):
    require(not root.is_symlink() and {p.name for p in root.iterdir()} == ASSETS and
            all(p.is_file() and not p.is_symlink() for p in root.iterdir()), "unexpected signed output inventory")
    key = trust / "app-catalog.pem"
    desktop_cert, updater_cert = digest(trust / "desktop.der"), digest(trust / "updater.der")
    require(desktop_cert != updater_cert, "updater must have its own APK signing certificate")
    verify_bootstrap(root / UPDATER, key, desktop_cert)
    entries = {name: apk_entry(root / name, pkg, build, updater_cert if name == UPDATER else desktop_cert)
               for name, pkg in APPS.items()}
    payload = verify_catalog((root / catalog_name(channel)).read_bytes(), key, channel, now)
    provenance = json.loads((root / "app-provenance.json").read_bytes())
    require(payload["build"] == build and payload["apps"] == entries and payload["provenance"] == provenance and
            provenance["source_commit"] == commit and provenance["unsigned_sha256"] == unsigned_digest and
            HEX.fullmatch(provenance["native_sha256"]), "catalog does not match the APKs or approved build")
    return payload


def publicly(path):
    with urlopen(Request(BASE + path, headers={"Cache-Control": "no-cache"}), timeout=30) as response:
        require(response.url.startswith("https://"), "insecure catalog redirect")
        body = response.read(32769)
    require(len(body) <= 32768, "catalog exceeds size limit")
    return body


def public_or_missing(name):
    try:
        return publicly(name)
    except HTTPError as error:
        if error.code != 404:
            raise
        return None


def check_advance(old, channel, trust, new, build):
    if old is not None and old != new:
        prev = verify_catalog(old, trust / "app-catalog.pem", channel)
        require(prev["build"] < build, "duplicate or downgrade")


def publish():
    env = os.environ
    build, commit, channel = env["BUILD_NUMBER"], env["SOURCE_COMMIT"], env["CHANNEL"]
    name, release = catalog_name(channel), tag(build)
    root, trust = Path(env["APP_SIGNED_ROOT"]) / build, Path(env["PUBLIC_TRUST"])
    candidate = (root / name).read_bytes()
    payload = verify_release(root, trust, build, commit, env["UNSIGNED_SUMS_SHA256"], channel, int(time.time()))
    old = public_or_missing(name)
    check_advance(old, channel, trust, candidate, build)

    def gh(*args):
        return sp.check_output(["gh", *args], text=True)

    def aws(*args):
        return sp.check_output(["aws", "s3api", *args, "--bucket", env["OTA_BUCKET"]], text=True)

    expected = {p.name: "sha256:" + digest(p) for p in root.iterdir()}
    def release_id():
        result = gh("api", "--paginate", f"repos/{REPO}/releases",
                    "--jq", f'.[] | select(.tag_name == "{release}") | .id').splitlines()
        require(len(result) <= 1 and all(x.isdecimal() for x in result), "ambiguous GitHub release")
        return result[0] if result else None

    def release_info():
        require(release_dbid is not None, "app release missing")
        return json.loads(gh("api", f"repos/{REPO}/releases/{release_dbid}"))

    release_dbid = release_id()
    if channel == "beta":
        tags = gh("api", "--paginate", f"repos/{REPO}/tags", "--jq", ".[].name").splitlines()
        require(not any(t.startswith("desktop-apps-0.1-") and t > release for t in tags), "newer app release exists")
        if release_dbid is None:
            require(release not in tags, "orphaned release tag; review before publishing")
            gh("release", "create", release, "--repo", REPO, "--draft", "--prerelease", "--target", commit,
               "--title", "ChapelTech desktop apps 0.1 (" + build + ")",
               "--notes", f"Compatible Pixel 10 OS builds: {payload['min_os']}–{payload['max_os']} (inclusive). "
               "See the repository README for installation and updates.")
            gh("release", "upload", release, "--repo", REPO, *map(str, sorted(root.iterdir())))
            release_dbid = release_id()
        info = release_info()
        require({a["name"]: a["digest"] for a in info["assets"]} == expected, "draft asset mismatch")
        if info["draft"]:
            require(info["target_commitish"] == commit, "draft release targets the wrong source")
            gh("release", "edit", release, "--repo", REPO, "--draft=false")
    else:
        require(publicly(catalog_name("beta")) == (root / catalog_name("beta")).read_bytes(),
                "candidate isn't the published Beta")
        previous = env["TESTED_FROM_BUILD"]
        require(BUILD.fullmatch(previous) and previous < build, "need an older physical app test build")
        require(not json.loads(gh("api", f"repos/{REPO}/releases/tags/{tag(previous)}"))["draft"],
                "predecessor never released")
        report = env["HARDWARE_REPORT"]
        require(report.startswith("https://") and not any(c.isspace() for c in report),
                "hardware qualification report URL required")
    require(gh("api", f"repos/{REPO}/commits/{release}", "--jq", ".sha").strip() == commit,
            "app release isn't tagged at the approved source")
    info = release_info()
    require(not info["draft"] and {a["name"]: a["digest"] for a in info["assets"]} == expected,
            "public release doesn't match signed assets")
    for apk, entry in payload["apps"].items():
        url = f"https://github.com/{REPO}/releases/download/{release}/{apk}"
        with urlopen(url, timeout=120) as response:
            require(response.url.startswith("https://") and
                    hashlib.file_digest(response, "sha256").hexdigest() == entry["sha256"],
                    "public APK download failed verification")
    with tempfile.TemporaryDirectory() as temp:
        cond = ["--if-none-match", "*"]
        if old is not None:
            prior = Path(temp) / name
            result = json.loads(aws("get-object", "--key", name, str(prior)))
            require(prior.read_bytes() == old, "public catalog differs from origin")
            cond = ["--if-match", result["ETag"]]
        if old != candidate:
            aws("put-object", "--key", name, "--body", str(root / name),
                "--content-type", "application/json", "--cache-control", "no-store", *cond)
    require(publicly(name) == candidate, "published catalog not visible")
    if channel == "stable":
        gh("release", "edit", release, "--repo", REPO, "--prerelease=false", "--latest=false")


if __name__ == "__main__":
    publish()
