#!/usr/bin/python3
"""Generate the first Pixel 10 signing identities without changing GitHub."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import secrets
import subprocess as sp
import tempfile

from apps import require
from hosted_keys import OS_ROLES
from hosted_trust import export


def run(*args, **kw):
    sp.run(args, stdin=sp.DEVNULL, stdout=sp.DEVNULL, check=True, **kw)


def android_key(role, keys, scratch, subject):
    source = scratch / (role + ".pem")
    run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096",
        "-out", source, stderr=sp.DEVNULL)
    run("openssl", "req", "-new", "-x509", "-sha256", "-days", "10000", "-key", source,
        "-out", keys / (role + ".x509.pem"), "-subj", f"/CN={subject} {role}/")
    run("openssl", "pkcs8", "-topk8", "-nocrypt", "-outform", "DER", "-in", source,
        "-out", keys / (role + ".pk8"))


def app_key(role, keys, scratch, subject):
    source = scratch / (role + ".pem")
    cert = scratch / (role + ".x509.pem")
    passfile = keys / (role + ".pass")
    with passfile.open("x") as f:
        f.write(secrets.token_hex(32) + "\n")
    run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-noenc", "-days", "10000", "-subj", f"/CN={subject} {role}/", "-keyout", source,
        "-out", cert, stderr=sp.DEVNULL)
    run("openssl", "pkcs12", "-export", "-name", role, "-in", cert, "-inkey", source,
        "-passout", "file:" + str(passfile), "-out", keys / (role + ".p12"))


def generate(dest, avbtool, subject, workers):
    require(not dest.exists() and not dest.is_symlink(), "refusing to replace an existing keyset")
    require(subject and len(subject) <= 60 and all(c.isascii() and (c.isalnum() or c in " .-") for c in subject),
            "invalid certificate subject")
    require(1 <= workers <= len(OS_ROLES), "invalid key generation concurrency")
    with tempfile.TemporaryDirectory(dir=dest.parent, prefix=".pixel10-keygen-") as stage:
        stage = Path(stage)
        work = stage / "output"
        scratch = stage / "scratch"
        for directory in (work, scratch, work / "os", work / "apps"):
            directory.mkdir(mode=0o700)
        os_keys, app_keys = work / "os", work / "apps"
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for _ in pool.map(lambda role: android_key(role, os_keys, scratch, subject), OS_ROLES):
                pass
        run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096",
            "-out", os_keys / "avb.pem", stderr=sp.DEVNULL)
        run(avbtool, "extract_public_key", "--key", os_keys / "avb.pem", "--output", os_keys / "avb_pkmd.bin")
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", subject, "-f", os_keys / "id_ed25519")
        for role in ("desktop", "updater"):
            app_key(role, app_keys, scratch, subject)
        run("openssl", "genpkey", "-algorithm", "Ed25519", "-out", app_keys / "app-catalog.pem")
        export(os_keys, app_keys, work / "trust", avbtool)
        work.rename(dest)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="new directory in the secure temporary key workspace")
    parser.add_argument("--avbtool", default="avbtool")
    parser.add_argument("--subject", default="ChapelTech Pixel 10")
    parser.add_argument("--workers", type=int, default=len(OS_ROLES))
    cli = parser.parse_args()
    generate(cli.destination, cli.avbtool, cli.subject, cli.workers)
    print("Keyset generated. Only the trust/ subdirectory may be committed.")


if __name__ == "__main__":
    main()
