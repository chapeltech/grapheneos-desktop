#!/usr/bin/python3
"""Build-independent signing and promotion on a disposable GitHub-hosted runner."""
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess as sp
import tempfile
import xml.etree.ElementTree as ET
import zipfile

import apps
import hosted_intake as intake
import hosted_keys as keys
import hosted_security as security
from source import PINS
from verify import verify as verify_os

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REPO = f"repos/{security.REPO}"
TRUST = HERE / "trust"
OTA_VERIFY_BINARIES = ("check_ota_package_signature", "avbtool", "delta_generator")


def gh(*argv):
    return sp.check_output(["gh", *argv], text=True)


def exact_release(tag, draft, commit=None):
    if draft:
        ids = gh("api", "--paginate", REPO + "/releases", "--jq",
                 f'.[] | select(.tag_name == "{tag}" and .draft) | .id').splitlines()
        apps.require(len(ids) == 1 and ids[0].isdecimal(), "expected exactly one private intake draft")
        reply = json.loads(gh("api", REPO + "/releases/" + ids[0]))
    else:
        reply = json.loads(gh("api", REPO + "/releases/tags/" + tag))
    apps.require(reply["tag_name"] == tag and reply["draft"] is draft, "wrong release or intake draft")
    if draft:
        apps.require(reply["target_commitish"] == commit and reply["prerelease"], "wrong draft source")
    return reply


def download(reply, folder, select, limit):
    assets = [a for a in reply["assets"] if select(a["name"])]
    apps.require(0 < len(assets) <= 100 and sum(a["size"] for a in assets) <= limit, "unexpected release size")
    folder.mkdir(mode=0o700)
    for asset in assets:
        name, size, asset_id = (asset[k] for k in ("name", "size", "id"))
        apps.require(re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name) and name not in (".", "..") and
                     type(size) is int and 0 < size < 2**31 and type(asset_id) is int, "invalid release asset")
        # Do not accept filenames or URLs from an HTTP redirect, or run assets.
        path = folder / name
        with path.open("xb") as f:
            sp.run(["gh", "api", REPO + "/releases/assets/" + str(asset_id), "-H",
                    "Accept: application/octet-stream"], stdout=f, check=True)
        apps.require(path.stat().st_size == size and
                     asset.get("digest") == "sha256:" + apps.digest(path), "downloaded draft/release asset differs")


def unsigned(kind, work, build, commit, digest):
    draft = exact_release(intake.private_draft(kind, build), True, commit)
    parts = work / "parts"
    download(draft, parts, lambda _: True, (6 if kind == "os" else 3) * 1024**3)
    target = work / "unsigned" / build
    target.parent.mkdir()
    intake.unpack(kind, parts, target, build, commit, digest)
    shutil.rmtree(parts)  # This invocation created this exact private scratch directory.
    return target


def git(*argv, cwd):
    return sp.check_output(["git", *argv], cwd=cwd, text=True).strip()


def upstream(work):
    graph = work / "graphene"
    manifest = graph / ".repo" / "manifests"
    manifest.mkdir(parents=True)
    git("init", "-q", cwd=manifest)
    tag = "refs/tags/" + PINS["release"]
    git("fetch", "--depth=1", "https://github.com/GrapheneOS/platform_manifest.git", f"{tag}:{tag}", cwd=manifest)
    apps.require(git("rev-parse", tag, cwd=manifest) == PINS["manifest_tag"] and
                 git("rev-parse", tag + "^{commit}", cwd=manifest) == PINS["manifest"], "manifest pin mismatch")
    git("-c", "gpg.ssh.allowedSignersFile=" + str(ROOT / "android/platform/allowed_signers"),
        "verify-tag", tag, cwd=manifest)
    git("checkout", "--detach", PINS["manifest"], cwd=manifest)
    script_commit = ET.parse(manifest / "default.xml").find('project[@name="script"]').attrib["revision"]
    apps.require(re.fullmatch("[a-f0-9]{40}", script_commit), "bad upstream release script pin")
    (graph / "script").mkdir()
    git("init", "-q", cwd=graph / "script")
    git("fetch", "--depth=1", "https://github.com/GrapheneOS/script.git", script_commit, cwd=graph / "script")
    git("checkout", "--detach", script_commit, cwd=graph / "script")
    return graph


def restore_secret(kind, dest):
    chunks = [os.environ.pop(name, None) for name in keys.secret_names(kind)]
    return keys.restore(kind, chunks, dest)


def run_verify_tools(work, target):
    tools = work / "verify-tools"
    if not tools.exists():
        tools.mkdir(mode=0o700)
        extract_verify_tools(target, tools)
    os.environ["PATH"] = str(tools / "bin") + os.pathsep + os.environ["PATH"]


def extract_verify_tools(target, tools):
    (tools / "bin").mkdir(mode=0o700)
    (tools / "lib64").mkdir(mode=0o700)
    with zipfile.ZipFile(target / "frankel-otatools.zip") as archive:
        # The A/B verifier invokes delta_generator, which finds Android host
        # libraries through $ORIGIN/../lib64. Keep the rest of otatools' bin
        # directory off PATH so it can't shadow the SDK's apksigner or aapt2.
        binaries = [archive.getinfo("bin/" + name) for name in OTA_VERIFY_BINARIES]
        libraries = [item for item in archive.infolist()
                     if re.fullmatch(r"lib64/lib[A-Za-z0-9_.+\-]+\.so(?:\.[A-Za-z0-9_.+\-]+)?", item.filename)]
        apps.require(0 < len(libraries) <= 512 and
                     sum(item.file_size for item in libraries) < 1024**3, "unexpected OTA verifier libraries")
        for item in binaries + libraries:
            kind = stat.S_IFMT(item.external_attr >> 16)
            apps.require(kind in (0, stat.S_IFREG) and 0 < item.file_size < 128 * 1024**2,
                         "unexpected verifier file type or size")
            binary = tools / item.filename
            with archive.open(item) as source, binary.open("xb") as dest:
                shutil.copyfileobj(source, dest)
            binary.chmod(0o700 if item in binaries else 0o600)


def verify_keyset(os_keys, work):
    hashes = json.loads((TRUST / "os-cert-sha256.json").read_text())
    actual = {role: apps.digest(os_keys / (role + ".x509.pem")) for role in keys.OS_ROLES}
    apps.require(actual == hashes, "unexpected OS certificate set")
    for role in keys.OS_ROLES:
        key = sp.check_output(["openssl", "pkey", "-inform", "DER", "-in", os_keys / (role + ".pk8"),
                              "-pubout"], stdin=sp.DEVNULL)
        cert = sp.check_output(["openssl", "x509", "-in", os_keys / (role + ".x509.pem"),
                               "-pubkey", "-noout"], stdin=sp.DEVNULL)
        apps.require(key == cert, f"OS key does not match its certificate: {role}")
    factory = sp.check_output(["ssh-keygen", "-y", "-f", os_keys / "id_ed25519"],
                              text=True, stdin=sp.DEVNULL).split()
    expected = (TRUST / "allowed_signers").read_text().split()
    apps.require(expected == ["pixel10"] + factory[:2], "unexpected factory signing key")
    derived = work / "derived-boot-key"
    sp.run(["avbtool", "extract_public_key", "--key", os_keys / "avb.pem", "--output", derived], check=True)
    apps.require(derived.read_bytes() == (TRUST / "avb_pkmd.bin").read_bytes() ==
                 (os_keys / "avb_pkmd.bin").read_bytes(), "unexpected boot key")


def sign(kind, work, source, build, commit, digest):
    graph = upstream(work) if kind == "os" else None
    with tempfile.TemporaryDirectory(dir=work, prefix=".ephemeral-keyset-") as temp:
        keyroot = Path(temp)
        restore_secret("apps", keyroot / "apps")
        if kind == "os":
            (keyroot / "keys").mkdir(mode=0o700)
            restore_secret("os", keyroot / "keys/frankel")
            verify_keyset(keyroot / "keys/frankel", work)
            (graph / "keys").symlink_to(keyroot / "keys")
            signed = work / "signed" / build
            signed.parent.mkdir(mode=0o700)
            checkout = work / "build-source"
            git("worktree", "add", "--detach", str(checkout), commit, cwd=ROOT)
            env = {"PATH": os.environ["PATH"], "TMPDIR": str(work / "tmp"), "LC_ALL": "C.UTF-8",
                   "BUILD_NUMBER": build, "SOURCE_COMMIT": commit, "UNSIGNED_SUMS_SHA256": digest,
                   "UNSIGNED": str(source), "SIGNED": str(signed), "ORCHESTRATION_CHECKOUT": str(checkout),
                   "DESKTOP_KEYSTORE": str(keyroot / "apps/desktop.p12"),
                   "DESKTOP_KS_PASS_FILE": str(keyroot / "apps/desktop.pass")}
            sp.run(["bash", str(HERE / "offline-sign.sh")], cwd=graph, env=env, stdin=sp.DEVNULL, check=True)
        else:
            root = work / "signed"
            root.mkdir(mode=0o700)
            record = work / "intake"
            record.mkdir(mode=0o700)
            (record / build).write_text(f"{commit} {digest}\n")
            config = {"intake_root": record, "signed_root": root, "unsigned_root": source.parent,
                      "public_trust": TRUST, "catalog_key": keyroot / "apps/app-catalog.pem"}
            for name in ("desktop", "updater"):
                config[name + "_keystore"] = str(keyroot / "apps" / (name + ".p12"))
                config[name + "_passfile"] = str(keyroot / "apps" / (name + ".pass"))
            runpy.run_path(str(HERE / "sign-apps.py"))["sign"](config, build, commit, digest)


def promotion(kind, work, build):
    tag = "frankel-0.1-" + build if kind == "os" else apps.tag(build)
    release = exact_release(tag, False)
    folder = work / "signed" / build
    folder.parent.mkdir(mode=0o700)
    download(release, folder, lambda n: n not in {"avb_pkmd.bin", "INSTALL.md"}, 8 * 1024**3)
    if kind == "os":
        factory = folder / f"frankel-install-{build}.zip"
        parts = sorted(folder.glob(factory.name + ".part[0-9][0-9][0-9]"))
        if parts:
            apps.require(not factory.exists() and [p.name for p in parts] ==
                         [f"{factory.name}.part{i:03d}" for i in range(len(parts))], "invalid factory parts")
            with factory.open("xb") as out:
                for p in parts:
                    with p.open("rb") as f:
                        shutil.copyfileobj(f, out)
                    p.unlink()


def main():
    os.umask(0o077)
    kind, phase = os.environ["RELEASE_KIND"], os.environ["RELEASE_PHASE"]
    build, commit, digest = (os.environ[var] for var in
                             ("BUILD_NUMBER", "SOURCE_COMMIT", "UNSIGNED_SUMS_SHA256"))
    intake.COMMON["identity"](build, commit, digest)
    apps.require(kind in ("os", "apps") and phase in ("prepare", "sign", "verify-and-publish"), "invalid job phase")
    work = Path(os.environ["RUNNER_TEMP"]) / ("frankel-" + kind + "-" + build)
    channel = os.environ["CHANNEL"]
    apps.require(channel in ("beta", "stable", "sign-only"), "invalid release channel")
    apps.require(phase != "sign" or channel != "stable", "stable promotion cannot use private keys")
    target = work / "unsigned" / build
    if phase == "prepare":
        free = shutil.disk_usage(work.parent).free
        minimum = (40 if kind == "os" and channel != "stable" else 16 if kind == "os" else 3) * 1024**3
        apps.require(free >= minimum, f"need {minimum // 1024**3} GiB free on the GitHub-hosted runner")
        work.mkdir(mode=0o700)
        (work / "tmp").mkdir(mode=0o700)
        if channel != "stable" or kind == "os":
            unsigned(kind, work, build, commit, digest)
        if channel == "stable":
            promotion(kind, work, build)
        return
    if kind == "os":
        run_verify_tools(work, target)
    if phase == "sign":
        sign(kind, work, target, build, commit, digest)
        return
    signed = work / "signed"
    if channel == "sign-only":
        if kind == "os":
            verify_os(signed / build, TRUST, build, commit, digest)
        else:
            apps.verify_release(signed / build, TRUST, build, commit, digest, "beta")
        print("Verified signed handoff; no release or OTA channel was changed.")
        return
    os.environ["SIGNED_ROOT"] = os.environ["APP_SIGNED_ROOT"] = str(signed)
    os.environ["PUBLIC_TRUST"] = str(TRUST)
    if kind == "os":
        from publish import publish
        publish()
    else:
        apps.publish()


if __name__ == "__main__":
    main()
