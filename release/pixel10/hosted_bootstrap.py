#!/usr/bin/python3
"""Generate the first signing keys on GitHub; export only sealed slots and public trust."""
import argparse
import base64
import ctypes
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess as sp
import tempfile

from apps import require
import hosted_keys as keys
import hosted_security as security

REPO = f"repos/{security.REPO}"
ENV = f"{REPO}/environments/{security.ENVIRONMENT}"
SLOTS = {name for kind in keys.FILES for name in keys.secret_names(kind)}
PUBLIC = {"allowed_signers", "avb_pkmd.bin", "releasekey.x509.pem", "os-cert-sha256.json",
          "desktop.der", "updater.der", "app-catalog.pem"}
WORKFLOW = ".github/workflows/pixel10-apps.yml"
SEAL_BYTES = 48


def sodium():
    library = ctypes.util.find_library("sodium")
    require(library, "libsodium is unavailable")
    lib = ctypes.CDLL(library)
    lib.sodium_init.restype = ctypes.c_int
    require(lib.sodium_init() >= 0, "libsodium initialization failed")
    return lib


def seal(lib, public, message):
    require(len(public) == 32, "invalid GitHub environment key")
    encrypt = lib.crypto_box_seal
    encrypt.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p)
    encrypt.restype = ctypes.c_int
    sealed = ctypes.create_string_buffer(len(message) + SEAL_BYTES)
    require(encrypt(sealed, message, len(message), public) == 0, "could not seal a signing key slot")
    return base64.b64encode(sealed.raw).decode("ascii")


def sealed_slots(root, public):
    lib = sodium()
    return {name: seal(lib, public, value.encode("ascii")) for kind in keys.FILES
            for name, value in zip(keys.secret_names(kind), keys.pack(kind, root / kind), strict=True)}


def generate(out, avbtool):
    import hosted_keygen

    require(os.environ["GITHUB_REPOSITORY"] == security.REPO and
            os.environ["GITHUB_REF"] == security.REF and os.environ["REF_PROTECTED"] == "true" and
            os.environ["HOSTED_RUNNER"] == "github-hosted", "bootstrap needs the protected hosted release job")
    key_id, public = os.environ["SEAL_KEY_ID"], os.environ["SEAL_PUBLIC_KEY"]
    require(re.fullmatch("[0-9]{1,32}", key_id), "invalid GitHub environment key ID")
    public = base64.b64decode(public, validate=True)
    require(len(public) == 32, "invalid GitHub environment key")
    record = {"repo": security.REPO, "environment": security.ENVIRONMENT, "key_id": key_id,
              "recipient_sha256": hashlib.sha256(public).hexdigest(),
              "run": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
              "commit": os.environ["GITHUB_SHA"]}
    out.mkdir(mode=0o700)
    # No plaintext key files are ever in the workspace or artifact path.
    with tempfile.TemporaryDirectory(prefix="pixel10-first-keyset-", dir="/dev/shm") as tmp:
        root = Path(tmp) / "first"
        hosted_keygen.generate(root, avbtool, "ChapelTech Pixel 10", len(keys.OS_ROLES))
        record["encrypted"] = sealed_slots(root, public)
        require({p.name for p in (root / "trust").iterdir()} == PUBLIC, "unexpected trust inventory")
        shutil.copytree(root / "trust", out / "trust")
    (out / "sealed.json").write_text(json.dumps(record, sort_keys=True) + "\n")


def gh_api(path, body=None):
    args = ["gh", "api", path]
    if body is None:
        return json.loads(sp.check_output(args))
    sp.run(args + ["--method", "PUT", "--input", "-"], input=json.dumps(body).encode(), check=True)


def read_bundle(bundle, run, commit):
    require(re.fullmatch("[0-9]{1,20}", run) and re.fullmatch("[a-f0-9]{40}", commit),
            "supply the approved run ID and its full source commit")
    require({p.name for p in bundle.iterdir()} == {"sealed.json", "trust"}, "unexpected bootstrap artifact")
    inbox = bundle / "sealed.json"
    trust = bundle / "trust"
    require(inbox.is_file() and not inbox.is_symlink() and inbox.stat().st_size < 512 * 1024 and
            trust.is_dir() and not trust.is_symlink(), "invalid sealed bootstrap artifact")
    require({p.name for p in trust.iterdir()} == PUBLIC and all(
        p.is_file() and not p.is_symlink() and 0 < p.stat().st_size < 8192 for p in trust.iterdir()),
        "invalid public-trust inventory")
    data = json.loads(inbox.read_bytes())
    require(data["repo"] == security.REPO and data["environment"] == security.ENVIRONMENT and
            data["commit"] == commit and data["run"] == run and re.fullmatch("[0-9]{1,32}", data["key_id"]) and
            set(data["encrypted"]) == SLOTS, "bootstrap artifact does not match the requested run")
    for encrypted in data["encrypted"].values():
        require(SEAL_BYTES < len(base64.b64decode(encrypted, validate=True)) <= keys.CHUNK + SEAL_BYTES,
                "invalid sealed key slot")
    return data


def install(bundle, run, commit):
    data = read_bundle(bundle, run, commit)
    receipt = gh_api(f"{REPO}/actions/runs/{run}")
    require(receipt["event"] == "workflow_dispatch" and receipt["conclusion"] == "success" and
            receipt["head_branch"] == "release/pixel10" and receipt["head_sha"] == commit and
            receipt["head_repository"]["full_name"] == security.REPO and
            receipt["path"].split("@", 1)[0] == WORKFLOW and str(receipt["run_attempt"]) == data["attempt"],
            "bootstrap did not complete on the approved release branch")
    jobs = gh_api(f"{REPO}/actions/runs/{run}/attempts/{data['attempt']}/jobs")
    require(any(job["name"] == "bootstrap-keys" and job["conclusion"] == "success" for job in jobs["jobs"]),
            "approved run did not generate keys")
    current = gh_api(f"{ENV}/secrets/public-key")
    require(current["key_id"] == data["key_id"] and
            hashlib.sha256(base64.b64decode(current["key"], validate=True)).hexdigest()
            == data["recipient_sha256"],
            "GitHub changed the environment encryption key")
    installed = set()

    def existing():
        return {row["name"] for row in gh_api(f"{ENV}/secrets?per_page=100")["secrets"]} & SLOTS

    for name, value in sorted(data["encrypted"].items()):
        require(existing() == installed, "signing key slots changed; do not rerun or overwrite")
        gh_api(f"{ENV}/secrets/{name}", {"encrypted_value": value, "key_id": data["key_id"]})
        installed.add(name)
    require(existing() == SLOTS, "the signing key bundle was not fully installed")
    print("Both signing bundles are in pixel10-sign. Commit only the verified public trust files.")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    gen = commands.add_parser("generate")
    gen.add_argument("out", type=Path)
    gen.add_argument("avbtool")
    load = commands.add_parser("install")
    load.add_argument("bundle", type=Path)
    load.add_argument("run")
    load.add_argument("commit")
    args = parser.parse_args()
    if args.command == "generate":
        generate(args.out, args.avbtool)
    else:
        install(args.bundle, args.run, args.commit)


if __name__ == "__main__":
    main()
