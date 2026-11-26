#!/usr/bin/python3
"""Authenticate a closed inventory before producing any network-visible side effect."""
import hashlib
import os
from pathlib import Path
import re
import subprocess as sp
import sys
from zipfile import ZipFile
from ota_publication import RAW

def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def signature(trust, data, sig, namespace):
    with data.open("rb") as f:
        sp.run(["ssh-keygen", "-Y", "verify", "-f", trust / "allowed_signers",
                "-I", "pixel10", "-n", namespace, "-s", sig], stdin=f, check=True)


def inventory(directory, build):
    names = {"source-commit", "build-number", "unsigned-inputs-sha256", "native-inputs-sha256", "ota-origin",
             "controller.apk", "styx.apk", "xmonad.apk", f"frankel-install-{build}.zip",
             f"frankel-install-{build}.zip.sig", f"frankel-ota_update-{build}.zip"}
    require({p.name for p in directory.iterdir()} == names | {"SHA256SUMS", "SHA256SUMS.sig"},
            "unexpected or missing release files")
    require(all(not p.is_symlink() and p.is_file() for p in directory.iterdir()), "non-file in release")
    for row in (directory / "SHA256SUMS").read_text().splitlines():
        value, name = row.split("  ", 1)
        require(name in names and digest(directory / name) == value, "bad digest or unexpected name: " + name)
        names.remove(name)
    require(not names, "unsigned files")


def ota_timestamp(ota, build):
    with ZipFile(ota) as z:
        metadata = dict(x.split("=", 1) for x in z.read("META-INF/com/android/metadata").decode().splitlines())
        require({"payload.bin", "payload_properties.txt"} <= set(z.namelist()), "missing A/B payload")
    require(metadata.get("ota-type") == "AB" and metadata["pre-device"] == "frankel" and
            metadata["post-build-incremental"] == build and
            metadata["post-build"].endswith("/" + build + ":user/release-keys") and
            not {"pre-build", "pre-build-incremental", "ota-downgrade", "ota-wipe"} & metadata.keys(),
            "not a full, non-wiping frankel user release")
    stamp = int(metadata["post-timestamp"])
    require(stamp > 0, "invalid build timestamp")
    return stamp


def verify(d, trust, build, commit, unsigned_hash):
    require(re.fullmatch(r"20[0-9]{8}", build) and re.fullmatch("[0-9a-f]{40}", commit)
            and re.fullmatch("[0-9a-f]{64}", unsigned_hash), "invalid release identity")
    signature(trust, d / "SHA256SUMS", d / "SHA256SUMS.sig", "chapeltech-pixel10-release")
    inventory(d, build)
    require((d / "ota-origin").read_text() == RAW + "\n", "wrong OS OTA origin")
    for name, value in (("source-commit", commit), ("build-number", build), ("unsigned-inputs-sha256", unsigned_hash)):
        require((d/name).read_text() == value + "\n", "wrong " + name)
    install = d / f"frankel-install-{build}.zip"
    signature(trust, install, d / (install.name + ".sig"), "factory images")
    with ZipFile(install) as z:
        require(z.read(install.stem + "/avb_pkmd.bin") == (trust / "avb_pkmd.bin").read_bytes(),
                "unexpected verified boot key")
    ota = d / f"frankel-ota_update-{build}.zip"
    sp.run(["check_ota_package_signature", trust / "releasekey.x509.pem", ota], check=True, stdout=sys.stderr)
    for app, pkg in (("controller","org.wonad.desktop"), ("styx","org.wonad.styx.desktop"), ("xmonad","org.wonad.xmonad")):
        apk = d / (app + ".apk")
        output = sp.check_output(["apksigner", "verify", "--print-certs", apk], text=True)
        pins = re.findall(r"^Signer #\d+ certificate SHA-256 digest: (\w+)$", output, re.M)
        require(pins == [digest(trust / "desktop.der")], "wrong desktop APK signer: " + app)
        manifest = sp.check_output(["aapt2", "dump", "badging", apk], text=True)
        require(f"package: name='{pkg}' versionCode='{int(build)-2000000000}' versionName='0.1'" in manifest
                and "application-debuggable" not in manifest, "wrong APK identity: " + app)
        with ZipFile(apk) as z:
            libs = {n for n in z.namelist() if n.startswith("lib/") and n.endswith(".so")}
            expected = {"controller": [], "styx": ["libXlorie.so", "libwonad_styx_desktop.so"],
                        "xmonad": ["libwm_executable.so","libstyx_wm_provider.so","libstyx_wm_action.so"]}[app]
            require(all(n.startswith("lib/arm64-v8a/") for n in libs) and
                    all("lib/arm64-v8a/"+n in libs for n in expected), "missing or non-arm64 library")
            if app == "styx":
                require("assets/xkb/rules/evdev" in z.namelist(), "missing keyboard data")
    return ota_timestamp(ota, build)


if __name__ == "__main__":
    print(verify(Path(sys.argv[1]), Path(sys.argv[2]), *sys.argv[3:]))
