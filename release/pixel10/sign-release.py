#!/usr/bin/python3 -I
"""Fixed entry point for the isolated Pixel 10 signing account."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib


CONFIG = Path("/etc/chapeltech/pixel10-signer.toml")
UNSIGNED_FILES = {
    "frankel-target_files.zip", "frankel-otatools.zip", "controller.apk", "styx.apk",
    "xmonad.apk", "build-number", "source-commit", "native-inputs-sha256",
}
ROW = re.compile(rb"([a-f0-9]{64})  ([a-zA-Z0-9_.-]+)")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(build, commit, digest):
    require(re.fullmatch(r"20[0-9]{8}", build) and re.fullmatch(r"[a-f0-9]{40}", commit)
            and re.fullmatch(r"[a-f0-9]{64}", digest), "invalid release identity")


def open_input(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    stream = os.fdopen(fd, "rb")
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        stream.close()
        raise ValueError("unsigned inputs must be regular files")
    return stream


def stage_unsigned(source, staged, build, commit, digest, expected=UNSIGNED_FILES):
    """Snapshot only the approved bytes before starting any signing tools."""
    fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with open_input(fd, "SHA256SUMS") as f:
            sums = f.read(4097)
        require(len(sums) <= 4096 and hashlib.sha256(sums).hexdigest() == digest,
                "unsigned checksum file does not match approved digest")
        entries = {}
        for line in sums.splitlines():
            match = ROW.fullmatch(line)
            require(match is not None, "invalid unsigned inventory row")
            checksum, name = (part.decode("ascii") for part in match.groups())
            require(name in expected and name not in entries, "unexpected unsigned inventory path")
            entries[name] = checksum
        require(entries.keys() == expected, "incomplete unsigned inventory")
        require(set(os.listdir(fd)) == expected | {"SHA256SUMS"},
                "unsigned directory differs from its inventory")
        for name, checksum in entries.items():
            with open_input(fd, name) as src, (staged / name).open("xb") as dst:
                h = hashlib.sha256()
                while chunk := src.read(1024 * 1024):
                    dst.write(chunk)
                    h.update(chunk)
                require(h.hexdigest() == checksum, "unsigned file does not match inventory: " + name)
        (staged / "SHA256SUMS").write_bytes(sums)
        require((staged / "source-commit").read_text() == commit + "\n" and
                (staged / "build-number").read_text() == build + "\n" and
                re.fullmatch(r"[a-f0-9]{64}\n", (staged / "native-inputs-sha256").read_text()),
                "unsigned metadata does not match signing request")
    finally:
        os.close(fd)


def signed_identity(path, build, commit, digest):
    archive = f"frankel-install-{build}.zip"
    names = {"controller.apk", "styx.apk", "xmonad.apk", "build-number", "source-commit",
             "native-inputs-sha256", "unsigned-inputs-sha256", "ota-origin", "SHA256SUMS", "SHA256SUMS.sig",
             archive, archive + ".sig", f"frankel-ota_update-{build}.zip"}
    require(not path.is_symlink() and {p.name for p in path.iterdir()} == names and
            all(p.is_file() and not p.is_symlink() for p in path.iterdir()),
            "signed output has an unexpected inventory")
    for name, value in (("build-number", build), ("source-commit", commit), ("unsigned-inputs-sha256", digest)):
        require((path / name).read_text() == value + "\n", "signed output does not match this request")


def sign(config, build, commit, digest):
    identity(build, commit, digest)
    # Only the independent, admin-controlled intake can authorize an exact
    # handoff. A GitHub runner cannot choose another artifact or write this record.
    ticket = Path(config["intake_root"]) / build
    require(ticket.read_text() == f"{commit} {digest}\n", "request differs from the registered handoff")
    signed_root = Path(config["signed_root"])
    output = signed_root / build
    with (signed_root / ".sign.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if output.exists() or output.is_symlink():
            signed_identity(output, build, commit, digest)
            return
        source = Path(config["source_root"]) / commit
        pins = json.loads((source / "release/pixel10/pins.json").read_text())
        require(re.fullmatch(r"[a-f0-9]{40}", pins["manifest"]), "invalid GrapheneOS manifest pin")
        graphene = Path(config["graphene_root"]) / pins["manifest"]
        with tempfile.TemporaryDirectory(prefix=".request-", dir=signed_root) as tmp:
            staging = Path(tmp)
            unsigned = staging / "unsigned"
            unsigned.mkdir(mode=0o700)
            stage_unsigned(Path(config["unsigned_root"]) / build, unsigned, build, commit, digest)
            signed = staging / "signed"
            safe_dirs = (source, graphene / ".repo/manifests", graphene / "script")
            git_config = {key: value for i, path in enumerate(safe_dirs) for key, value in
                          ((f"GIT_CONFIG_KEY_{i}", "safe.directory"), (f"GIT_CONFIG_VALUE_{i}", str(path.resolve())))}
            env = dict(PATH=config["tool_path"], LC_ALL="C.UTF-8", TMPDIR=tmp,
                       BUILD_NUMBER=build, SOURCE_COMMIT=commit, UNSIGNED_SUMS_SHA256=digest,
                       UNSIGNED=str(unsigned), SIGNED=str(signed), ORCHESTRATION_CHECKOUT=str(source),
                       DESKTOP_KEYSTORE=config["apk_keystore"], DESKTOP_KS_PASS_FILE=config["apk_passfile"],
                       GIT_CONFIG_COUNT=str(len(safe_dirs)), GIT_CONFIG_GLOBAL="/dev/null", **git_config)
            log = Path(config["log_root"]) / build
            with log.open("ab") as out:
                subprocess.run(["/bin/bash", Path(__file__).with_name("offline-sign.sh")],
                               cwd=graphene, env=env, stdin=subprocess.DEVNULL, stdout=out,
                               stderr=subprocess.STDOUT, check=True)
            signed_identity(signed, build, commit, digest)
            for file in signed.iterdir():
                file.chmod(0o640)
            signed.chmod(0o750)
            signed.rename(output)  # Same filesystem; the publisher never sees a partial output.


def main():
    os.umask(0o077)
    try:
        require(os.geteuid() != 0 and len(sys.argv) == 4, "invalid signer invocation")
        info = CONFIG.stat()
        require(info.st_uid == 0 and not info.st_mode & 0o022, "unsafe signer configuration")
        with CONFIG.open("rb") as f:
            config = tomllib.load(f)
        for key in ("source_root", "graphene_root", "unsigned_root", "intake_root", "signed_root", "log_root",
                    "apk_keystore", "apk_passfile"):
            require(Path(config[key]).is_absolute(), "signer paths must be absolute")
        sign(config, *sys.argv[1:])
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("Signing refused or failed; check the dedicated signer locally.", file=sys.stderr)
        return 1
    print(f"Signed handoff ready for build {sys.argv[1]}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
