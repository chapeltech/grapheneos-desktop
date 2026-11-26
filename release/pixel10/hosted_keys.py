#!/usr/bin/python3
"""Package signing identities for protected GitHub Actions environment secrets."""
import argparse
import base64
import gzip
import io
import os
from pathlib import Path
import tarfile
import tempfile

OS_ROLES = (
    "bluetooth", "gmscompat_lib", "media", "networkstack", "nfc",
    "platform", "releasekey", "sdk_sandbox", "shared",
)
FILES = {
    "os": {f"{role}.{suffix}" for role in OS_ROLES for suffix in ("pk8", "x509.pem")}
          | {"avb.pem", "avb_pkmd.bin", "id_ed25519"},
    "apps": {"desktop.p12", "desktop.pass", "updater.p12", "updater.pass", "app-catalog.pem"},
}
# Leave room under GitHub's 48 KiB per-secret limit; reserve fixed slots for
# either identity so workflows don't need to enumerate unrelated secrets.
CHUNK = 40 * 1024
SLOTS = {"os": 3, "apps": 2}
MAX_FILE = 32 * 1024
PREFIX = {"os": "PIXEL10_OS_KEYS", "apps": "PIXEL10_APP_KEYS"}
UNUSED = "-"


def pack(kind, source):
    encoded = io.BytesIO()
    with gzip.GzipFile(fileobj=encoded, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
            for name in sorted(FILES[kind]):
                path = source / name
                if path.is_symlink() or not path.is_file():
                    raise ValueError("missing or non-regular key input: " + name)
                with path.open("rb") as f:
                    value = f.read(MAX_FILE + 1)
                if not 0 < len(value) <= MAX_FILE:
                    raise ValueError("invalid key input size: " + name)
                member = tarfile.TarInfo(name)
                member.size = len(value)
                member.mode = 0o600
                archive.addfile(member, io.BytesIO(value))
    body = base64.b64encode(encoded.getvalue()).decode("ascii")
    result = [body[i:i + CHUNK] for i in range(0, len(body), CHUNK)]
    if len(result) > SLOTS[kind]:
        raise ValueError("signing keys do not fit in the allocated GitHub environment secrets")
    return result + [UNUSED] * (SLOTS[kind] - len(result))


def decode(kind, chunks):
    if len(chunks) != SLOTS[kind] or any(not isinstance(c, str) or not 0 < len(c) <= CHUNK for c in chunks):
        raise ValueError("signing environment is missing part of its key bundle")
    first_empty = next((i for i, chunk in enumerate(chunks) if chunk == UNUSED), len(chunks))
    if first_empty == 0 or any(c != UNUSED for c in chunks[first_empty:]):
        raise ValueError("invalid signing key bundle framing")
    data = base64.b64decode("".join(chunks[:first_empty]), validate=True)
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r|gz") as archive:
        for member in archive:
            name = member.name
            if (name not in FILES[kind] or name in result or not member.isreg()
                    or not 0 < member.size <= MAX_FILE):
                raise ValueError("invalid signing key bundle inventory")
            with archive.extractfile(member) as file:
                result[name] = file.read()
    if result.keys() != FILES[kind]:
        raise ValueError("incomplete signing key bundle")
    return result


def restore(kind, chunks, dest):
    if dest.exists() or dest.is_symlink():
        raise ValueError("key destination must be new")
    contents = decode(kind, chunks)
    with tempfile.TemporaryDirectory(dir=dest.parent, prefix=".key-inputs-") as temp:
        staged = Path(temp) / "keys"
        staged.mkdir(mode=0o700)
        for name, value in contents.items():
            fd = os.open(staged / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(value)
        staged.rename(dest)


def secret_names(kind):
    return [f"{PREFIX[kind]}_{i}" for i in range(1, SLOTS[kind] + 1)]


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("pack", "restore"))
    parser.add_argument("kind", choices=FILES)
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "pack" and len(args.paths) == 2:
            source, spool = args.paths
            bundles = pack(args.kind, source)
            spool.mkdir(mode=0o700)
            for name, part in zip(secret_names(args.kind), bundles, strict=True):
                (spool / name).write_text(part)
        elif args.mode == "restore" and len(args.paths) == 1:
            chunks = [os.environ.pop(name, None) for name in secret_names(args.kind)]
            restore(args.kind, chunks, args.paths[0])
        else:
            parser.error("pack requires SOURCE SPOOL, restore requires DESTINATION")
    except (OSError, ValueError, tarfile.TarError):
        parser.exit(1, "Signing key bundle refused; no key material is printed.\n")


if __name__ == "__main__":
    main()
