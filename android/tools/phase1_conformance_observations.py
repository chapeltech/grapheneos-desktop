"""Trace-bound zero-length raw observations; never empty source/APK admission."""
from pathlib import Path
import hashlib
import os
import stat

from phase1_conformance_common import file_ref

EVENTS = ("logcat", "-b", "events", "-d", "-v", "threadtime", "am_anr:I", "am_crash:I", "*:S")
SERIAL = "emulator-5580"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def require(value, message):
    if not value: raise ValueError(message)


def canonical_path(path, root):
    path, root = Path(path).absolute(), Path(root).absolute()
    require(root.is_dir() and root.resolve(strict=True) == root and path.resolve(strict=True) == path and
            path.is_relative_to(root) and not path.is_symlink(), "Aliased/foreign observation ancestry")
    require(stat.S_ISREG(path.lstat().st_mode), "Observation is not a regular file")
    return path, root


def empty_ref(path):
    """Call only AFTER exact command authority was independently established."""
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(descriptor)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                                info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        require(stat.S_ISREG(opened.st_mode) and before.st_size == opened.st_size == 0 and
                before.st_nlink == opened.st_nlink == 1 and identity(before) == identity(opened) and
                os.read(descriptor, 1) == b"", "Empty observation changed/aliased during open")
    finally:
        os.close(descriptor)
    require(path.resolve(strict=True) == path and identity(before) == identity(path.lstat()), "Empty observation changed/aliased during read")
    return {"sha256": EMPTY_SHA256, "bytes": 0}


def command_ref(path, root, trace, container, *, outer=False):
    path, root = canonical_path(path, root)
    if path.stat().st_size: return file_ref(path)
    relative = path.relative_to(root).as_posix()
    rows = [row for row in trace if row.get("evidence") == relative]
    require(len(rows) == 1, "Empty observation lacks unique original command")
    row = rows[0]
    require(isinstance(container, str) and container and
            type(row.get("returncode")) is int and row["returncode"] == 0 and
            row.get("output_sha256") == EMPTY_SHA256 and
            all(type(row.get(key)) is int for key in ("started_monotonic_ns", "ended_monotonic_ns")) and
            0 <= row["started_monotonic_ns"] <= row["ended_monotonic_ns"],
            "Empty observation is not an original successful typed command/hash")
    if outer:
        require(set(row) == {"argv", "returncode", "started_monotonic_ns", "ended_monotonic_ns",
                             "evidence", "output_sha256"}, "Malformed original outer command")
    else:
        require(set(row) == {"kind", "sequence", "argv", "returncode", "started_monotonic_ns", "ended_monotonic_ns",
                             "evidence", "output_sha256"} and row.get("kind") == "command" and
                type(row.get("sequence")) is int and row["sequence"] >= 0,
                "Empty observation is not a completed original command")
    allowed = (["docker", "exec", container, "adb", "-s", SERIAL, "shell", *EVENTS],
               ["docker", "container", "diff", container])
    require(row.get("argv") in allowed, "Empty observation has foreign owner/serial/filter/role")
    return empty_ref(path)


def inventory_ref(path, root, contexts, container):
    """Contexts are explicit owned (raw-root, original-trace, outer-schema) tuples.

    No journal discovery, caller summary, failed-attempt omission or global cache.
    Nonempty artifacts still use the generic strictly-positive reference.
    """
    path, root = canonical_path(path, root)
    if path.stat().st_size: return file_ref(path)
    matches = []
    for raw_root, trace, outer in contexts:
        raw_root = Path(raw_root).absolute()
        require(raw_root.resolve(strict=True) == raw_root and raw_root.is_relative_to(root), "Foreign raw journal root")
        if path.is_relative_to(raw_root):
            relative = path.relative_to(raw_root).as_posix()
            if any(row.get("evidence") == relative for row in trace): matches.append((raw_root, trace, outer))
    require(len(matches) == 1, "Empty inventory observation has ambiguous/missing original journal")
    raw_root, trace, outer = matches[0]
    return command_ref(path, raw_root, trace, container, outer=outer)


def reference_equal(actual, expected):
    return (isinstance(expected, dict) and set(expected) == {"sha256", "bytes"} and
            type(expected["bytes"]) is int and expected["bytes"] >= 0 and
            isinstance(expected["sha256"], str) and actual == expected)


def inventory(directory, root, contexts, container, *, exclude=()):
    """Complete serializer used by the scoped producers; no omitted zero reads."""
    directory, root = Path(directory).absolute(), Path(root).absolute()
    require(directory.resolve(strict=True) == directory and directory.is_dir() and directory.is_relative_to(root),
            "Foreign/aliased observation inventory")
    nodes = list(directory.rglob("*"))
    require(all(not path.is_symlink() and (path.is_file() or path.is_dir()) for path in nodes),
            "Aliased/special observation inventory entry")
    excluded = {Path(path).absolute() for path in exclude}
    return {path.relative_to(root).as_posix(): inventory_ref(path, root, contexts, container)
            for path in nodes if path.is_file() and path not in excluded}
