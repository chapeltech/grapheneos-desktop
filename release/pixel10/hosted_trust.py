#!/usr/bin/python3
"""Export only public verification material from reviewed OS and APK signing keys."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess as sp
import tempfile

from apps import digest, require
from hosted_keys import OS_ROLES


def cert_der(bundle, password):
    pem = sp.check_output(["openssl", "pkcs12", "-in", bundle, "-clcerts", "-nokeys",
                           "-passin", "file:" + str(password)])
    require(pem.count(b"-----BEGIN CERTIFICATE-----") == 1, "expected one APK signing certificate")
    return sp.check_output(["openssl", "x509", "-outform", "DER"], input=pem)


def export(os_keys, app_keys, dest, avbtool):
    require(not dest.exists() and not dest.is_symlink(), "trust directory must be new")
    with tempfile.TemporaryDirectory(dir=dest.parent, prefix=".trust-") as tmp:
        trust = Path(tmp) / "trust"
        trust.mkdir(mode=0o700)
        allowed = sp.check_output(["ssh-keygen", "-y", "-f", os_keys / "id_ed25519"],
                                  text=True, stdin=sp.DEVNULL).split()
        require(len(allowed) >= 2 and allowed[0] == "ssh-ed25519" and
                re.fullmatch(r"[A-Za-z0-9+/]+=*", allowed[1]), "expected an Ed25519 factory key")
        (trust / "allowed_signers").write_text("pixel10 " + " ".join(allowed[:2]) + "\n")
        shutil.copyfile(os_keys / "releasekey.x509.pem", trust / "releasekey.x509.pem")
        sp.run([avbtool, "extract_public_key", "--key", os_keys / "avb.pem",
                "--output", trust / "avb_pkmd.bin"], check=True, stdin=sp.DEVNULL)
        require((trust / "avb_pkmd.bin").read_bytes() == (os_keys / "avb_pkmd.bin").read_bytes(),
                "boot key does not match its recorded public key")
        certs = {role: digest(os_keys / (role + ".x509.pem")) for role in OS_ROLES}
        require(len(set(certs.values())) == len(OS_ROLES), "OS signing certificates are not distinct")
        (trust / "os-cert-sha256.json").write_text(json.dumps(certs, sort_keys=True, indent=2) + "\n")
        for kind in ("desktop", "updater"):
            (trust / (kind + ".der")).write_bytes(cert_der(app_keys / (kind + ".p12"), app_keys / (kind + ".pass")))
        require(digest(trust / "desktop.der") != digest(trust / "updater.der"), "APK signing certificates must differ")
        public = sp.check_output(["openssl", "pkey", "-in", app_keys / "app-catalog.pem", "-pubout"],
                                 stdin=sp.DEVNULL)
        require(public.startswith(b"-----BEGIN PUBLIC KEY-----\n"), "invalid catalog verification key")
        (trust / "app-catalog.pem").write_bytes(public)
        trust.rename(dest)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("os_keys", type=Path)
    parser.add_argument("app_keys", type=Path)
    parser.add_argument("dest", type=Path)
    parser.add_argument("--avbtool", default="avbtool")
    args = parser.parse_args()
    export(args.os_keys, args.app_keys, args.dest, args.avbtool)


if __name__ == "__main__":
    main()
