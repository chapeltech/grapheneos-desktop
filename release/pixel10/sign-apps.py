#!/usr/bin/python3 -I
"""Fixed, root-installed signing entry point for the dedicated APK signer."""
import fcntl
import os
from pathlib import Path
import runpy
import subprocess as sp
import sys
import tempfile
import time
import tomllib

# Imported only from the root-installed signing helpers, never from a worktree.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import apps

common = runpy.run_path(str(Path(__file__).resolve().with_name("sign-release.py")))
CONFIG = Path("/etc/chapeltech/pixel10-app-signer.toml")


def sign(config, build, commit, digest):
    common["identity"](build, commit, digest)
    apps.require((Path(config["intake_root"]) / build).read_text() == f"{commit} {digest}\n",
                 "request does not match the signing intake")
    root, trust = Path(config["signed_root"]), Path(config["public_trust"])
    target = root / build
    with (root / ".sign.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if target.exists() or target.is_symlink():
            for channel in ("beta", "stable"):
                apps.verify_release(target, trust, build, commit, digest, channel)
            return
        with tempfile.TemporaryDirectory(dir=root, prefix=".apps-") as work:
            unsigned, signed = Path(work) / "unsigned", Path(work) / "signed"
            unsigned.mkdir(mode=0o700)
            signed.mkdir(mode=0o700)
            common["stage_unsigned"](Path(config["unsigned_root"]) / build, unsigned, build, commit,
                                     digest, expected=apps.INPUTS)
            min_os, max_os = apps.os_range(unsigned / "os-range")
            certs = {kind: apps.digest(trust / (kind + ".der")) for kind in ("desktop", "updater")}
            apps.require(certs["desktop"] != certs["updater"], "APK keystores must be separate")
            apps.verify_bootstrap(unsigned / apps.UPDATER, trust / "app-catalog.pem", certs["desktop"])
            entries = {}
            for name, pkg in apps.APPS.items():
                kind = "updater" if name == apps.UPDATER else "desktop"
                sp.run(["apksigner", "sign", "--ks", config[kind + "_keystore"], "--ks-pass",
                        "file:" + config[kind + "_passfile"], "--v4-signing-enabled", "false",
                        "--out", signed / name, unsigned / name],
                       check=True, stdin=sp.DEVNULL)
                entries[name] = apps.apk_entry(signed / name, pkg, build, certs[kind])
            now = int(time.time())
            provenance = {"source_commit": commit, "unsigned_sha256": digest,
                          "native_sha256": (unsigned / "native-inputs-sha256").read_text().strip()}
            (signed / "app-provenance.json").write_bytes(apps.json_bytes(provenance))
            for channel in ("beta", "stable"):
                body = apps.sign_catalog({"format": 1, "channel": channel, "device": "frankel",
                    "build": build, "generation": int(build), "min_os": min_os, "max_os": max_os,
                    "issued": now, "expires": now + apps.LIFETIME, "apps": entries,
                    "provenance": provenance}, config["catalog_key"])
                (signed / apps.catalog_name(channel)).write_bytes(body)
            for channel in ("beta", "stable"):
                apps.verify_release(signed, trust, build, commit, digest, channel, now)
            for p in signed.iterdir():
                p.chmod(0o640)
            signed.chmod(0o750)
            signed.rename(target)


def main():
    os.umask(0o077)
    try:
        apps.require(os.geteuid() != 0 and len(sys.argv) == 4, "invalid signer invocation")
        info = CONFIG.stat()
        apps.require(info.st_uid == 0 and not info.st_mode & 0o022, "unsafe signer configuration")
        config = tomllib.loads(CONFIG.read_text())
        for key in ("intake_root", "signed_root", "unsigned_root", "public_trust", "desktop_keystore",
                    "desktop_passfile", "updater_keystore", "updater_passfile", "catalog_key"):
            apps.require(Path(config[key]).is_absolute(), "signer paths must be absolute")
        path = config["tool_path"]
        apps.require(all(Path(p).is_absolute() for p in path.split(":")), "unsafe signer tool path")
        os.environ.clear()
        os.environ.update(PATH=path, LC_ALL="C.UTF-8")
        sign(config, *sys.argv[1:])
    except (OSError, ValueError, KeyError, sp.SubprocessError):
        print("App signing refused or failed; inspect the authorized input on the signer.", file=sys.stderr)
        return 1
    print(f"Signed app handoff ready for {sys.argv[1]}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
