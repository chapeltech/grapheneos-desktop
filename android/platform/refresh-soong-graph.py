#!/usr/bin/env python3
"""Refresh an existing Soong graph without surrendering direct-Ninja history.

This is the non-interactive equivalent of ``m -jN nothing``.  The two files
used by direct Ninja, OUT/.ninja_log and OUT/.ninja_deps, are moved into a
same-filesystem journal before Soong/Siso starts and are restored afterward.
The journal is intentionally durable: the next invocation completes recovery
before doing new work if this process was killed between those operations.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from typing import Any


HISTORY_NAMES = (".ninja_log", ".ninja_deps")
JOURNAL_NAME = ".wonad-soong-graph-refresh.journal"
LOCK_NAME = ".wonad-soong-graph-refresh.lock"
SCHEMA = 1
SAFE_COMPONENTS = re.compile(r"^[A-Za-z0-9._/-]+$")
SAFE_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")


class UsageError(Exception):
    """The requested refresh is unsafe or underspecified."""


class RecoveryError(Exception):
    """A durable history journal could not be recovered losslessly."""


def fail(message: str, status: int = 2) -> int:
    print(f"refresh-soong-graph.py: {message}", file=sys.stderr)
    return status


def normalized_relative(label: str, value: str) -> Path:
    if not value or value.startswith("/") or value.endswith("/") or not SAFE_COMPONENTS.fullmatch(value):
        raise UsageError(f"{label} must be a non-empty normalized relative path")
    path = Path(value)
    if value.startswith("./") or "//" in value or any(part in ("", ".", "..") for part in path.parts):
        raise UsageError(f"{label} must be a non-empty normalized relative path")
    return path


def direct_child(parent: Path, relative: Path, label: str, *, directory: bool) -> Path:
    lexical = parent / relative
    if directory:
        valid = lexical.is_dir() and not lexical.is_symlink()
    else:
        valid = lexical.is_file() and not lexical.is_symlink()
    if not valid:
        kind = "directory" if directory else "regular file"
        raise UsageError(f"{label} must be an existing, non-symlink {kind}")
    if lexical.resolve(strict=True) != lexical:
        raise UsageError(f"{label} must resolve directly below source")
    return lexical


def validate_graph(graph: Path, out_relative: str) -> None:
    if not graph.is_file() or graph.is_symlink() or graph.resolve(strict=True) != graph:
        raise UsageError("graph must remain an existing, non-symlink regular file")
    name = graph.name
    if not re.fullmatch(r"combined-[A-Za-z0-9._-]+\.ninja", name):
        raise UsageError("graph must be a combined-*.ninja file")
    builddir = f"builddir = {out_relative}"
    subninja = f"subninja {out_relative}/"
    builddir_count = 0
    has_subninja = False
    try:
        with graph.open("r", encoding="utf-8", errors="strict") as source:
            for line in source:
                value = line.rstrip("\r\n")
                builddir_count += value == builddir
                has_subninja = has_subninja or value.startswith(subninja)
    except (OSError, UnicodeError) as error:
        raise UsageError(f"cannot inspect graph: {error}") from error
    if builddir_count != 1:
        raise UsageError("graph builddir does not exactly match out")
    if not has_subninja:
        raise UsageError("graph does not include an out-tree subninja")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fingerprint(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise RecoveryError(f"{path.name} must be a non-symlink regular file")
    return {
        "sha256": sha256(path),
        "size": metadata.st_size,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mtime_ns": metadata.st_mtime_ns,
    }


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_json_durable(path: Path, value: dict[str, Any]) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def read_manifest(journal: Path, source: Path, out_relative: str) -> dict[str, Any]:
    if not journal.is_dir() or journal.is_symlink():
        raise RecoveryError(f"{journal} is not a non-symlink recovery directory")
    manifest_path = journal / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise RecoveryError(f"{journal} has no trustworthy manifest.json")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RecoveryError(f"cannot read {manifest_path}: {error}") from error
    files = manifest.get("files") if isinstance(manifest, dict) else None
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != SCHEMA
        or manifest.get("source") != str(source)
        or manifest.get("out") != out_relative
        or not isinstance(files, dict)
        or set(files) != set(HISTORY_NAMES)
    ):
        raise RecoveryError(f"{journal} does not describe this source/out pair")
    for name in HISTORY_NAMES:
        entry = manifest["files"][name]
        if not isinstance(entry, dict) or set(entry) != {"present", "fingerprint"}:
            raise RecoveryError(f"invalid {name} entry in {manifest_path}")
        if not isinstance(entry["present"], bool):
            raise RecoveryError(f"invalid {name} presence marker in {manifest_path}")
        if entry["present"] != isinstance(entry["fingerprint"], dict):
            raise RecoveryError(f"invalid {name} fingerprint in {manifest_path}")
    allowed = {"manifest.json", *HISTORY_NAMES}
    unexpected = {item.name for item in journal.iterdir()} - allowed
    if unexpected:
        raise RecoveryError(f"unexpected recovery-journal entries: {sorted(unexpected)!r}")
    return manifest


def recover_journal(out: Path, source: Path, out_relative: str) -> bool:
    """Recover an interrupted journal. Return whether one was present.

    Recovery attempts both history files even if one is damaged.  On any
    discrepancy the journal stays in place so no surviving original is thrown
    away and a later/manual recovery can continue.
    """

    journal = out / JOURNAL_NAME
    if not journal.exists() and not journal.is_symlink():
        return False
    try:
        manifest = read_manifest(journal, source, out_relative)
    except OSError as error:
        raise RecoveryError(f"cannot inspect recovery journal {journal}: {error}") from error
    errors: list[str] = []
    for name in HISTORY_NAMES:
        entry = manifest["files"][name]
        target = out / name
        backup = journal / name
        try:
            if entry["present"]:
                if backup.exists() or backup.is_symlink():
                    if fingerprint(backup) != entry["fingerprint"]:
                        raise RecoveryError(f"journaled {name} no longer matches its manifest")
                    os.replace(backup, target)
                elif not target.exists() or target.is_symlink():
                    raise RecoveryError(f"original {name} is missing from both out and journal")
                elif fingerprint(target) != entry["fingerprint"]:
                    raise RecoveryError(f"un-journaled {name} no longer matches its manifest")
            else:
                if backup.exists() or backup.is_symlink():
                    raise RecoveryError(f"journal contains {name}, but it was originally absent")
                if target.exists() or target.is_symlink():
                    if target.is_dir() and not target.is_symlink():
                        raise RecoveryError(f"refusing to remove unexpected directory {target}")
                    target.unlink()
        except (OSError, RecoveryError) as error:
            errors.append(f"{name}: {error}")
    try:
        fsync_directory(out)
        fsync_directory(journal)
    except OSError as error:
        errors.append(f"directory fsync: {error}")
    if errors:
        raise RecoveryError("; ".join(errors))
    retired = out / f"{JOURNAL_NAME}.retired.{os.getpid()}.{secrets.token_hex(8)}"
    try:
        if retired.exists() or retired.is_symlink():
            raise RecoveryError(f"refusing to replace unexpected retired journal {retired}")
        # This rename is the recovery commit point.  After it, no subsequent
        # invocation can mistake a cleanup interruption for unrestored history.
        os.replace(journal, retired)
        fsync_directory(out)
        (retired / "manifest.json").unlink()
        retired.rmdir()
        fsync_directory(out)
    except (OSError, RecoveryError) as error:
        if not journal.exists() and not journal.is_symlink():
            # The originals are committed back in place.  A retired directory
            # is harmless and must not turn a later invocation into recovery.
            print(f"refresh-soong-graph.py: warning: could not remove retired journal: {error}", file=sys.stderr)
        else:
            raise RecoveryError(f"history was restored, but the journal could not be retired: {error}") from error
    return True


def prepare_journal(out: Path, source: Path, out_relative: str) -> None:
    journal = out / JOURNAL_NAME
    if journal.exists() or journal.is_symlink():
        raise RecoveryError(f"refusing to replace existing recovery journal {journal}")
    entries: dict[str, Any] = {}
    for name in HISTORY_NAMES:
        path = out / name
        present = path.exists() or path.is_symlink()
        entries[name] = {
            "present": present,
            "fingerprint": fingerprint(path) if present else None,
        }
    temporary = Path(tempfile.mkdtemp(prefix=f"{JOURNAL_NAME}.prepare.", dir=out))
    renamed = False
    try:
        write_json_durable(temporary / "manifest.json", {
            "schema": SCHEMA,
            "source": str(source),
            "out": out_relative,
            "files": entries,
        })
        fsync_directory(temporary)
        os.replace(temporary, journal)
        renamed = True
        fsync_directory(out)
        for name in HISTORY_NAMES:
            entry = entries[name]
            if not entry["present"]:
                if (out / name).exists() or (out / name).is_symlink():
                    raise RecoveryError(f"{name} appeared while preparing the journal")
                continue
            if fingerprint(out / name) != entry["fingerprint"]:
                raise RecoveryError(f"{name} changed while preparing the journal")
            os.replace(out / name, journal / name)
            if fingerprint(journal / name) != entry["fingerprint"]:
                raise RecoveryError(f"{name} changed while entering the journal")
        fsync_directory(journal)
        fsync_directory(out)
    finally:
        if not renamed:
            shutil.rmtree(temporary, ignore_errors=True)


def acquire_lock(out: Path) -> int:
    path = out / LOCK_NAME
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except OSError as error:
        raise UsageError(f"cannot open refresh lock {path}: {error}") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise UsageError(f"refresh lock {path} is not a regular file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise UsageError(f"another graph refresh owns {path}") from error
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--graph", required=True)
    parser.add_argument("--target-product", required=True)
    parser.add_argument("--target-release", required=True)
    parser.add_argument("--target-build-variant", required=True, choices=("user", "userdebug", "eng"))
    parser.add_argument("--build-number", required=True)
    parser.add_argument("--build-datetime", required=True)
    parser.add_argument("--highmem-jobs", required=True, type=int)
    parser.add_argument("--jobs", required=True, type=int)
    parser.add_argument(
        "--recover-only",
        action="store_true",
        help="recover a stale history journal without invoking Soong",
    )
    return parser.parse_args(argv)


def validate_arguments(args: argparse.Namespace) -> tuple[Path, Path, Path, str]:
    source_input = Path(args.source)
    if not source_input.is_dir():
        raise UsageError("source directory does not exist")
    source = source_input.resolve(strict=True)
    if source == Path("/") or not (source / ".repo").is_dir():
        raise UsageError("source is not a repo-managed Android checkout")
    out_relative_path = normalized_relative("out", args.out)
    out = direct_child(source, out_relative_path, "out", directory=True)
    graph_relative_path = normalized_relative("graph", args.graph)
    try:
        graph_relative_path.relative_to(out_relative_path)
    except ValueError as error:
        raise UsageError("graph must be below out") from error
    graph = source / graph_relative_path
    for label, value in (
        ("target product", args.target_product),
        ("target release", args.target_release),
        ("build number", args.build_number),
    ):
        if not SAFE_VALUE.fullmatch(value):
            raise UsageError(f"{label} contains unsupported characters")
    if not re.fullmatch(r"0|[1-9][0-9]{0,11}", args.build_datetime):
        raise UsageError("build datetime must be a non-negative decimal epoch")
    for label, value in (("jobs", args.jobs), ("highmem jobs", args.highmem_jobs)):
        if value < 1 or value > 256:
            raise UsageError(f"{label} must be between 1 and 256")
    return source, out, graph, args.out


def child_environment(args: argparse.Namespace, out_relative: str) -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "ANDROID_BUILD_TOP",
        "ANDROID_HOST_OUT",
        "ANDROID_HOST_OUT_TESTCASES",
        "ANDROID_PRODUCT_OUT",
        "ANDROID_SOONG_HOST_OUT",
        "DIST_DIR",
        "NINJA_ARGS",
        "NINJA_EXTRA_ARGS",
        "OFFICIAL_BUILD",
        "OUT_DIR_COMMON_BASE",
        "PRODUCT_OUT",
        "SOONG_OUT_DIR",
        "TARGET_BUILD_APPS",
        "TARGET_BUILD_DENSITY",
    ):
        environment.pop(name, None)
    environment.update({
        "OUT_DIR": out_relative,
        "TARGET_PRODUCT": args.target_product,
        "TARGET_RELEASE": args.target_release,
        "TARGET_BUILD_VARIANT": args.target_build_variant,
        "TARGET_BUILD_TYPE": "release",
        "BUILD_NUMBER": args.build_number,
        "BUILD_DATETIME": args.build_datetime,
        "NINJA_HIGHMEM_NUM_JOBS": str(args.highmem_jobs),
    })
    return environment


def run_refresh(args: argparse.Namespace, source: Path, out: Path, graph: Path, out_relative: str) -> int:
    lock = acquire_lock(out)
    child: subprocess.Popen[bytes] | None = None
    caught_signal: int | None = None
    old_handlers: dict[int, Any] = {}

    def forward(signum: int, _frame: Any) -> None:
        nonlocal caught_signal
        caught_signal = caught_signal or signum
        if child is not None and child.poll() is None:
            try:
                os.killpg(child.pid, signum)
            except ProcessLookupError:
                pass

    try:
        recovered = recover_journal(out, source, out_relative)
        if recovered:
            print("Recovered an interrupted direct-Ninja history journal.", file=sys.stderr)
        if args.recover_only:
            return 0
        graph_relative = graph.relative_to(source)
        graph = direct_child(source, graph_relative, "graph", directory=False)
        validate_graph(graph, out_relative)
        soong = source / "build/soong/soong_ui.bash"
        if not soong.is_file() or soong.is_symlink() or not os.access(soong, os.X_OK):
            raise UsageError("source is missing executable build/soong/soong_ui.bash")
        if soong.resolve(strict=True) != soong:
            raise UsageError("Soong launcher must resolve directly below source")
        try:
            prepare_journal(out, source, out_relative)
        except (OSError, RecoveryError) as error:
            try:
                recover_journal(out, source, out_relative)
            except (OSError, RecoveryError) as recovery_error:
                raise RecoveryError(
                    f"journal preparation failed ({error}); immediate recovery also failed ({recovery_error})"
                ) from recovery_error
            raise RecoveryError(f"journal preparation failed before Soong started: {error}") from error
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            old_handlers[signum] = signal.signal(signum, forward)
        command = [
            str(source / "build/soong/soong_ui.bash"),
            "--make-mode",
            f"-j{args.jobs}",
            "nothing",
        ]
        returncode = 1
        postcondition_error: UsageError | None = None
        launch_error: OSError | None = None
        recovery_error: RecoveryError | None = None
        try:
            try:
                child = subprocess.Popen(
                    command,
                    cwd=source,
                    env=child_environment(args, out_relative),
                    # Keep the advisory lock alive if this wrapper is killed
                    # while Soong is still running.  Without this inherited
                    # descriptor, a second invocation could recover the
                    # journal and replace .ninja_log/.ninja_deps underneath an
                    # orphaned Soong process.  The descriptor remains owned by
                    # this process too and is closed normally below.
                    pass_fds=(lock,),
                    start_new_session=True,
                )
                if caught_signal is not None and child.poll() is None:
                    os.killpg(child.pid, caught_signal)
                returncode = child.wait()
                if returncode == 0:
                    try:
                        validate_graph(graph, out_relative)
                    except UsageError as error:
                        postcondition_error = error
                        returncode = 1
            except OSError as error:
                launch_error = error
        finally:
            try:
                recover_journal(out, source, out_relative)
            except RecoveryError as error:
                recovery_error = error
        if recovery_error is not None:
            print(f"refresh-soong-graph.py: history recovery failed: {recovery_error}", file=sys.stderr)
            return 70
        if launch_error is not None:
            print(f"refresh-soong-graph.py: could not invoke Soong: {launch_error}", file=sys.stderr)
            return 1
        if postcondition_error is not None:
            print(f"refresh-soong-graph.py: refreshed graph failed validation: {postcondition_error}", file=sys.stderr)
        if caught_signal is not None:
            return 128 + caught_signal
        return returncode if returncode >= 0 else 128 - returncode
    except RecoveryError as error:
        return fail(f"history recovery failed: {error}", 70)
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
        os.close(lock)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_arguments(sys.argv[1:] if argv is None else argv)
        source, out, graph, out_relative = validate_arguments(args)
        return run_refresh(args, source, out, graph, out_relative)
    except UsageError as error:
        return fail(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
