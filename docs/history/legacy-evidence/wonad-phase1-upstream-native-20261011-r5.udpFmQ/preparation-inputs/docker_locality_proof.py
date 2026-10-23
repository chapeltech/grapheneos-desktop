#!/usr/bin/env python3
"""Capture or verify a fail-closed local-Docker build locality proof.

Capture is deliberately limited to read-only Docker inspect/exec operations and
one fresh JSON output.  It proves that an already-running build container uses
the expected local Unix daemon and that its two bind roots are the same host
directories by device/inode/mode, rather than merely trusting Docker's source
path strings.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "android/tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
import phase1_provenance as provenance  # noqa: E402


DOCKER = Path("/usr/bin/docker")
SOCKET = Path("/var/run/docker.sock")
SOCKET_REAL = Path("/run/docker.sock")
ENDPOINT = "unix:///var/run/docker.sock"
LOCK = ROOT / "android/grapheneos.lock.json"
SCHEMA = 1
KIND = "wonad-local-docker-bind-proof"
SHA256 = re.compile(r"[0-9a-f]{64}")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
CONTAINER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
BOOT_ID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}")
FORBIDDEN_ENV = {"CONTAINER_HOST", "CONTAINER_CONTEXT"}
CONTAINER_SOURCE = "/sources"
CONTAINER_OUT = "/sources/out"
MANIFEST_RELATIVE = ".repo/manifests/default.xml"


class ProofError(ValueError):
    """The Docker endpoint or retained-container identity is not provable."""


def require(condition, message):
    if not condition:
        raise ProofError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def parse_json(payload: bytes | str, label: str):
    try:
        return json.loads(payload, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProofError(f"Invalid JSON from {label}: {error}") from error


def stable_ref(path: Path):
    try:
        return provenance.file_ref(path)
    except provenance.ProvenanceError as error:
        raise ProofError(str(error)) from error


def stable_bytes(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProofError(f"Cannot safely open authenticated proof {path}: {error}") from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), "Authenticated proof is not an ordinary file")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        current = os.lstat(path)
    except OSError as error:
        raise ProofError(f"Authenticated proof disappeared: {error}") from error
    fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    require(all(getattr(before, name) == getattr(after, name) == getattr(current, name)
                for name in fields) and stat.S_ISREG(current.st_mode),
            "Authenticated proof changed while being read")
    payload = b"".join(chunks)
    require(len(payload) == before.st_size, "Authenticated proof read was incomplete")
    return payload, {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}


def reject_overrides(environment=None):
    environment = os.environ if environment is None else environment
    names = sorted(name for name in environment
                   if name.startswith("DOCKER_") or name in FORBIDDEN_ENV)
    require(not names, "Docker/container endpoint overrides are forbidden: " + ", ".join(names))
    return True


def command_environment(environment=None):
    environment = os.environ if environment is None else environment
    reject_overrides(environment)
    home = environment.get("HOME")
    require(isinstance(home, str) and home.startswith("/") and "\x00" not in home,
            "A literal absolute HOME is required to audit Docker context selection")
    return {
        "HOME": home,
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
    }


def run(argv, *, environment, timeout=60):
    try:
        result = subprocess.run(
            [str(item) for item in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProofError(f"Cannot run trusted Docker probe {argv!r}: {error}") from error
    require(result.returncode == 0 and result.stderr == b"",
            f"Trusted Docker probe failed: {argv!r}: " +
            result.stderr.decode(errors="replace").strip())
    return result.stdout


def docker(arguments, *, environment, timeout=60):
    return run([DOCKER, "--host", ENDPOINT, *arguments],
               environment=environment, timeout=timeout)


def fs_record(value):
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "mode": value.st_mode,
        "uid": value.st_uid,
        "gid": value.st_gid,
    }


def stable_node(path: Path, *, expected_type, uid, gid=None, exact_mode=None):
    try:
        before = os.lstat(path)
        real = Path(os.path.realpath(path))
        after = os.lstat(path)
    except OSError as error:
        raise ProofError(f"Cannot inspect trusted node {path}: {error}") from error
    stable = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
    require(all(getattr(before, field) == getattr(after, field) for field in stable),
            f"Trusted node changed while inspected: {path}")
    require(expected_type(before.st_mode), f"Trusted node has the wrong type: {path}")
    require(before.st_uid == uid and (gid is None or before.st_gid == gid),
            f"Trusted node ownership differs: {path}")
    if exact_mode is not None:
        require(stat.S_IMODE(before.st_mode) == exact_mode,
                f"Trusted node mode differs: {path}")
    return {"path": str(path), "realpath": str(real), **fs_record(before)}


def trusted_local_docker(environment):
    cli = stable_node(DOCKER, expected_type=stat.S_ISREG, uid=0, gid=0, exact_mode=0o755)
    require(cli["realpath"] == str(DOCKER), "Trusted Docker CLI path resolves elsewhere")
    cli["file"] = stable_ref(DOCKER)
    try:
        docker_gid = grp.getgrnam("docker").gr_gid
    except KeyError as error:
        raise ProofError("The local docker group does not exist") from error
    endpoint = stable_node(SOCKET, expected_type=stat.S_ISSOCK, uid=0,
                           gid=docker_gid, exact_mode=0o660)
    require(endpoint["realpath"] == str(SOCKET_REAL) and os.path.samefile(SOCKET, SOCKET_REAL),
            "Docker socket is not the exact local /run/docker.sock node")

    selected = run([DOCKER, "context", "show"], environment=environment).decode().strip()
    require(selected == "default", "Selected Docker context is not the built-in default")
    contexts = parse_json(run([DOCKER, "context", "inspect", "default"],
                              environment=environment), "docker context inspect")
    require(isinstance(contexts, list) and len(contexts) == 1 and
            isinstance(contexts[0], dict), "Docker returned an ambiguous default context")
    context = contexts[0]
    docker_endpoint = context.get("Endpoints", {}).get("docker", {})
    require(context.get("Name") == "default" and context.get("Metadata") == {} and
            docker_endpoint == {"Host": ENDPOINT, "SkipTLSVerify": False} and
            context.get("TLSMaterial") == {},
            "Built-in default Docker context is not the exact local Unix endpoint")

    version = parse_json(docker(["version", "--format", "{{json .}}"],
                                environment=environment), "docker version")
    info = parse_json(docker(["info", "--format", "{{json .}}"],
                             environment=environment), "docker info")
    require(version.get("Client", {}).get("Os") == "linux" and
            version.get("Server", {}).get("Os") == "linux" and
            info.get("OSType") == "linux" and info.get("DockerRootDir", "").startswith("/") and
            isinstance(info.get("ID"), str) and info["ID"],
            "Local Docker daemon identity is incomplete")
    daemon = {
        "id": info["ID"],
        "name": info.get("Name"),
        "server_version": info.get("ServerVersion"),
        "kernel_version": info.get("KernelVersion"),
        "os": info.get("OSType"),
        "architecture": info.get("Architecture"),
        "root_dir": info.get("DockerRootDir"),
        "client_version": version.get("Client", {}).get("Version"),
        "client_context": info.get("ClientInfo", {}).get("Context"),
    }
    require(daemon["client_context"] == "default",
            "Docker daemon report does not bind the default context")
    return cli, endpoint, {
        "selected": selected,
        "name": context["Name"],
        "endpoint": docker_endpoint["Host"],
        "skip_tls_verify": docker_endpoint["SkipTLSVerify"],
        "tls_material": context["TLSMaterial"],
    }, daemon


def exact_directory(path: Path, label: str):
    require(path.is_absolute() and not path.is_symlink(),
            f"{label} must be a literal absolute non-symlink directory")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ProofError(f"Cannot resolve {label}: {error}") from error
    require(resolved == path and path.is_dir(), f"{label} must be canonical and ordinary")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProofError(f"Cannot hold {label} open: {error}") from error
    require_held_path(path, descriptor, label)
    return descriptor


def require_held_path(path: Path, descriptor: int, label: str):
    try:
        held = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise ProofError(f"Cannot recheck held {label}: {error}") from error
    require(fs_record(held) == fs_record(current) and stat.S_ISDIR(current.st_mode),
            f"{label} pathname no longer names the held directory")
    return held


def inspect_container(container_id: str, environment):
    rows = parse_json(docker(["container", "inspect", container_id],
                             environment=environment), "docker container inspect")
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict),
            "Docker inspect did not return exactly one container")
    return rows[0]


def canonical_bind_mounts(mounts):
    """Project Docker's unordered inspect Mounts set into a stable form."""
    fields = {"Type", "Source", "Destination", "Mode", "RW", "Propagation"}
    string_fields = fields - {"RW"}
    require(isinstance(mounts, list) and len(mounts) == 2 and
            all(isinstance(row, dict) and set(row) == fields and
                all(type(row[name]) is str for name in string_fields) and
                type(row["RW"]) is bool for row in mounts),
            "Container has malformed or additional mounts")
    selected = [{
        "type": row.get("Type"), "source": row.get("Source"),
        "destination": row.get("Destination"), "mode": row.get("Mode"),
        "rw": row.get("RW"), "propagation": row.get("Propagation"),
    } for row in mounts]
    destinations = [row["destination"] for row in selected]
    sources = [row["source"] for row in selected]
    require(len(set(destinations)) == len(destinations) and
            len(set(sources)) == len(sources),
            "Container has duplicate mount sources or destinations")
    return sorted(selected, key=lambda row: row["destination"])


def canonical_bind_specs(binds):
    """Parse Docker's unordered HostConfig.Binds set without type coercion."""
    require(isinstance(binds, list) and len(binds) == 2 and
            all(type(value) is str for value in binds),
            "Container has malformed or additional bind specifications")
    rows = []
    for value in binds:
        parts = value.split(":")
        require(len(parts) == 3 and all(parts) and parts[2] == "rw",
                "Container has a malformed or non-read-write bind specification")
        rows.append({"source": parts[0], "destination": parts[1], "mode": parts[2]})
    require(len({row["source"] for row in rows}) == len(rows) and
            len({row["destination"] for row in rows}) == len(rows),
            "Container has duplicate bind sources or destinations")
    rows.sort(key=lambda row: row["destination"])
    return [f"{row['source']}:{row['destination']}:{row['mode']}" for row in rows]


def bind_projection(info, *, expected_id, expected_name, expected_image,
                    expected_reference, source: Path, out: Path):
    state, config, host, mounts = (info.get("State"), info.get("Config"),
                                   info.get("HostConfig"), info.get("Mounts"))
    require(all(isinstance(value, dict) for value in (state, config, host)) and
            isinstance(mounts, list), "Docker inspect is missing container configuration")
    require(info.get("Id") == expected_id and info.get("Name") == "/" + expected_name and
            info.get("Image") == expected_image and config.get("Image") == expected_reference,
            "Retained container ID/name/image identity differs")
    require(state.get("Status") == "running" and state.get("Running") is True and
            state.get("Paused") is False and state.get("Restarting") is False and
            state.get("Dead") is False and state.get("OOMKilled") is False and
            state.get("Error") == "" and type(state.get("Pid")) is int and state["Pid"] > 1,
            "Container is not one exact healthy running build process")
    expected_binds = [f"{source}:{CONTAINER_SOURCE}:rw", f"{out}:{CONTAINER_OUT}:rw"]
    actual_binds = canonical_bind_specs(host.get("Binds"))
    require(actual_binds == expected_binds,
            "Container bind topology differs")
    selected = canonical_bind_mounts(mounts)
    expected_mounts = [
        {"type": "bind", "source": str(source), "destination": CONTAINER_SOURCE,
         "mode": "rw", "rw": True, "propagation": "rprivate"},
        {"type": "bind", "source": str(out), "destination": CONTAINER_OUT,
         "mode": "rw", "rw": True, "propagation": "rprivate"},
    ]
    require(selected == expected_mounts,
            "Container has different bind mounts")
    return {
        "id": info["Id"], "name": expected_name, "image": info["Image"],
        "image_reference": config["Image"], "created": info.get("Created"),
        "started_at": state.get("StartedAt"), "pid": state["Pid"],
        "status": state["Status"], "mounts": expected_mounts,
        "binds": expected_binds,
    }


def read_boot_id(path: Path):
    try:
        value = path.read_text().strip()
    except OSError as error:
        raise ProofError(f"Cannot read boot ID {path}: {error}") from error
    require(BOOT_ID.fullmatch(value), f"Invalid boot ID from {path}")
    return value


def container_text(container_id: str, argv, environment):
    payload = docker(["container", "exec", "--user", "1000:1000", container_id, *argv],
                     environment=environment)
    require(b"\x00" not in payload, "Container probe returned NUL bytes")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProofError("Container probe returned non-UTF-8 output") from error


def container_stat(container_id: str, path: str, environment):
    output = container_text(container_id,
                            ["/usr/bin/stat", "-Lc", "%d %i %f %u %g", path],
                            environment).strip()
    fields = output.split()
    require(len(fields) == 5 and all(re.fullmatch(r"[0-9]+", item)
                                     for item in fields[:2] + fields[3:]) and
            re.fullmatch(r"[0-9a-f]+", fields[2]),
            f"Malformed container stat for {path}")
    return {
        "device": int(fields[0]), "inode": int(fields[1]),
        "mode": int(fields[2], 16), "uid": int(fields[3]), "gid": int(fields[4]),
    }


def validate_record(record):
    expected = {"schema", "kind", "scope", "endpoint", "docker_cli", "socket",
                "context", "daemon", "host_boot_id", "container", "bind_identity",
                "locked_manifest", "lock", "generator"}
    require(isinstance(record, dict) and set(record) == expected and
            record.get("schema") == SCHEMA and record.get("kind") == KIND and
            record.get("scope") == "running-container-locality-and-bind-identity" and
            record.get("endpoint") == ENDPOINT,
            "Unexpected Docker locality proof envelope")
    file_fields = {"sha256", "size"}
    node_fields = {"path", "realpath", "device", "inode", "mode", "uid", "gid"}
    cli = record.get("docker_cli", {})
    endpoint = record.get("socket", {})
    require(isinstance(cli, dict) and set(cli) == node_fields | {"file"} and
            cli["path"] == cli["realpath"] == str(DOCKER) and cli["uid"] == cli["gid"] == 0 and
            cli["mode"] == (stat.S_IFREG | 0o755) and
            isinstance(cli["file"], dict) and set(cli["file"]) == file_fields and
            SHA256.fullmatch(str(cli["file"].get("sha256"))) and
            type(cli["file"].get("size")) is int and cli["file"]["size"] > 0,
            "Docker proof has invalid trusted CLI identity")
    require(isinstance(endpoint, dict) and set(endpoint) == node_fields and
            endpoint["path"] == str(SOCKET) and endpoint["realpath"] == str(SOCKET_REAL) and
            endpoint["uid"] == 0 and endpoint["mode"] == (stat.S_IFSOCK | 0o660) and
            all(type(endpoint[name]) is int for name in ("device", "inode", "gid")),
            "Docker proof has invalid local socket identity")
    context = record.get("context", {})
    require(isinstance(context, dict) and set(context) == {
                "selected", "name", "endpoint", "skip_tls_verify", "tls_material"
            } and context == {
                "selected": "default", "name": "default", "endpoint": ENDPOINT,
                "skip_tls_verify": False, "tls_material": {},
            } and
            record.get("host_boot_id") == record.get("container", {}).get("boot_id") and
            BOOT_ID.fullmatch(str(record.get("host_boot_id"))),
            "Docker proof does not establish one local boot/context")
    daemon = record.get("daemon", {})
    require(isinstance(daemon, dict) and set(daemon) == {
                "id", "name", "server_version", "kernel_version", "os", "architecture",
                "root_dir", "client_version", "client_context",
            } and daemon["os"] == "linux" and daemon["client_context"] == "default" and
            all(isinstance(daemon[name], str) and daemon[name]
                for name in ("id", "name", "server_version", "kernel_version",
                             "architecture", "client_version")) and
            isinstance(daemon["root_dir"], str) and daemon["root_dir"].startswith("/"),
            "Docker proof has invalid daemon identity")
    container = record.get("container", {})
    require(isinstance(container, dict) and set(container) == {
                "id", "name", "image", "image_reference", "created", "started_at", "pid",
                "status", "mounts", "binds", "boot_id", "stable",
            } and CONTAINER_ID.fullmatch(str(container.get("id"))) and
            CONTAINER_NAME.fullmatch(str(container.get("name"))) and
            re.fullmatch(r"sha256:[0-9a-f]{64}", str(container.get("image"))) and
            isinstance(container.get("image_reference"), str) and container["image_reference"] and
            all(isinstance(container.get(name), str) and container[name]
                for name in ("created", "started_at")) and
            type(container.get("pid")) is int and container["pid"] > 1 and
            container.get("status") == "running" and container.get("stable") is True and
            isinstance(container.get("mounts"), list) and len(container["mounts"]) == 2 and
            isinstance(container.get("binds"), list) and len(container["binds"]) == 2,
            "Docker proof has invalid retained-container identity")
    bindings = record.get("bind_identity")
    require(isinstance(bindings, list) and len(bindings) == 2 and
            [row.get("destination") for row in bindings] == [CONTAINER_SOURCE, CONTAINER_OUT],
            "Docker proof has invalid bind-identity rows")
    for row in bindings:
        require(isinstance(row, dict) and set(row) == {
                    "destination", "source", "host", "container"
                } and row.get("host") == row.get("container") and
                isinstance(row.get("source"), str) and row["source"].startswith("/") and
                isinstance(row["host"], dict) and set(row["host"]) == {
                    "device", "inode", "mode", "uid", "gid"
                } and all(type(row["host"][name]) is int
                          for name in ("device", "inode", "mode", "uid", "gid")) and
                stat.S_ISDIR(row["host"]["mode"]),
                "Docker bind device/inode/mode identity differs")
    require([row["source"] for row in bindings] ==
            [container["mounts"][0].get("source"), container["mounts"][1].get("source")] and
            [row["destination"] for row in bindings] ==
            [container["mounts"][0].get("destination"),
             container["mounts"][1].get("destination")] and
            all(isinstance(row, dict) and set(row) == {
                "type", "source", "destination", "mode", "rw", "propagation"
            } and row["type"] == "bind" and row["mode"] == "rw" and row["rw"] is True and
                row["propagation"] == "rprivate" for row in container["mounts"]) and
            container["binds"] == [
                f'{bindings[0]["source"]}:{CONTAINER_SOURCE}:rw',
                f'{bindings[1]["source"]}:{CONTAINER_OUT}:rw',
            ], "Docker proof mount topology is inconsistent")
    manifest = record.get("locked_manifest", {})
    require(isinstance(manifest, dict) and set(manifest) == {
                "relative", "host", "container", "probe"
            } and manifest.get("relative") == MANIFEST_RELATIVE and
            manifest.get("host") == manifest.get("container") and
            manifest.get("probe") == "read-only docker exec sha256sum/stat" and
            isinstance(manifest.get("host"), dict) and set(manifest["host"]) == file_fields and
            SHA256.fullmatch(str(manifest.get("host", {}).get("sha256"))) and
            type(manifest.get("host", {}).get("size")) is int and
            manifest["host"]["size"] > 0,
            "Locked manifest host/container identity differs")
    for name in ("lock", "generator"):
        reference = record.get(name)
        require(isinstance(reference, dict) and set(reference) == file_fields and
                SHA256.fullmatch(str(reference.get("sha256"))) and
                type(reference.get("size")) is int and reference["size"] > 0,
                f"Docker proof has invalid {name} reference")
    return record


def capture(args, environment=None):
    require(CONTAINER_ID.fullmatch(args.container_id) is not None,
            "A full lowercase container ID is required")
    require(CONTAINER_NAME.fullmatch(args.container_name) is not None,
            "A safe exact container name is required")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", args.image_digest) is not None,
            "An immutable sha256 image digest is required")
    environment = command_environment(environment)
    source_fd = exact_directory(args.source, "source")
    out_fd = exact_directory(args.out, "OUT_DIR")
    try:
        source_before, out_before = os.fstat(source_fd), os.fstat(out_fd)
        require(stat.S_ISDIR(source_before.st_mode) and stat.S_ISDIR(out_before.st_mode),
                "Build bind roots are not directories")
        lock = provenance.validate_lock(provenance.load_json(LOCK))
        lock_ref = stable_ref(LOCK)
        expected_reference = lock["builder"]["reference"]
        require(args.image_digest == lock["builder"]["image_digest"],
                "Expected image differs from the authenticated lock")
        manifest_path = args.source / MANIFEST_RELATIVE
        manifest_ref = stable_ref(manifest_path)
        require(manifest_ref == {
            "sha256": lock["manifest"]["default_xml_sha256"],
            "size": lock["manifest"]["default_xml_size"],
        }, "Host default.xml differs from the authenticated lock")

        cli_before, socket_before, context, daemon_before = trusted_local_docker(environment)
        host_boot_before = read_boot_id(Path("/proc/sys/kernel/random/boot_id"))
        first_info = inspect_container(args.container_id, environment)
        first = bind_projection(
            first_info, expected_id=args.container_id, expected_name=args.container_name,
            expected_image=args.image_digest, expected_reference=expected_reference,
            source=args.source, out=args.out,
        )
        container_boot = container_text(
            args.container_id, ["/usr/bin/cat", "/proc/sys/kernel/random/boot_id"],
            environment).strip()
        require(BOOT_ID.fullmatch(container_boot) and container_boot == host_boot_before,
                "Container and host boot IDs differ")

        source_container = container_stat(args.container_id, CONTAINER_SOURCE, environment)
        out_container = container_stat(args.container_id, CONTAINER_OUT, environment)
        source_host, out_host = fs_record(source_before), fs_record(out_before)
        require(source_container == source_host and out_container == out_host,
                "Docker bind roots differ from held host directory identities")

        container_manifest_path = CONTAINER_SOURCE + "/" + MANIFEST_RELATIVE
        digest_output = container_text(
            args.container_id, ["/usr/bin/sha256sum", container_manifest_path],
            environment).strip()
        digest_match = re.fullmatch(r"([0-9a-f]{64})  (.+)", digest_output)
        require(digest_match is not None and digest_match.group(2) == container_manifest_path,
                "Malformed in-container manifest hash")
        size_output = container_text(
            args.container_id, ["/usr/bin/stat", "-Lc", "%s", container_manifest_path],
            environment).strip()
        require(re.fullmatch(r"[0-9]+", size_output) is not None,
                "Malformed in-container manifest size")
        container_manifest = {"sha256": digest_match.group(1), "size": int(size_output)}
        require(container_manifest == manifest_ref,
                "In-container default.xml differs from held host/lock identity")

        second_info = inspect_container(args.container_id, environment)
        second = bind_projection(
            second_info, expected_id=args.container_id, expected_name=args.container_name,
            expected_image=args.image_digest, expected_reference=expected_reference,
            source=args.source, out=args.out,
        )
        host_boot_after = read_boot_id(Path("/proc/sys/kernel/random/boot_id"))
        cli_after, socket_after, context_after, daemon_after = trusted_local_docker(environment)
        source_after = require_held_path(args.source, source_fd, "source")
        out_after = require_held_path(args.out, out_fd, "OUT_DIR")
        require(first == second and context == context_after and daemon_before == daemon_after and
                cli_before == cli_after and socket_before == socket_after and
                host_boot_before == host_boot_after and
                fs_record(source_before) == fs_record(source_after) and
                fs_record(out_before) == fs_record(out_after),
                "Docker/host/container identity changed during locality capture")

        record = validate_record({
            "schema": SCHEMA,
            "kind": KIND,
            "scope": "running-container-locality-and-bind-identity",
            "endpoint": ENDPOINT,
            "docker_cli": cli_before,
            "socket": socket_before,
            "context": context,
            "daemon": daemon_before,
            "host_boot_id": host_boot_before,
            "container": {**first, "boot_id": container_boot, "stable": True},
            "bind_identity": [
                {"destination": CONTAINER_SOURCE, "source": str(args.source),
                 "host": source_host, "container": source_container},
                {"destination": CONTAINER_OUT, "source": str(args.out),
                 "host": out_host, "container": out_container},
            ],
            "locked_manifest": {
                "relative": MANIFEST_RELATIVE, "host": manifest_ref,
                "container": container_manifest,
                "probe": "read-only docker exec sha256sum/stat",
            },
            "lock": lock_ref,
            "generator": stable_ref(Path(__file__)),
        })
        require(args.output.is_absolute() and not os.path.lexists(args.output),
                "Output must be a fresh absolute path")
        try:
            provenance.atomic_new(args.output, record)
        except provenance.ProvenanceError as error:
            raise ProofError(str(error)) from error
        digest = stable_ref(args.output)["sha256"]
        print(f"PASS: local Docker bind proof {args.output}")
        print("SHA256=" + digest)
        return record, digest
    finally:
        os.close(source_fd)
        os.close(out_fd)


def verify(path: Path, digest: str):
    require(SHA256.fullmatch(digest) is not None,
            "Verification requires an exact lowercase out-of-band SHA-256")
    payload, reference = stable_bytes(path)
    require(reference["sha256"] == digest, "Proof differs from its authenticated SHA-256")
    record = validate_record(parse_json(payload, str(path)))
    print(f"PASS: authenticated offline Docker bind proof {path}")
    return record


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    capture_parser = actions.add_parser("capture")
    capture_parser.add_argument("--container-id", required=True)
    capture_parser.add_argument("--container-name", required=True)
    capture_parser.add_argument("--image-digest", required=True)
    capture_parser.add_argument("--source", type=Path, required=True)
    capture_parser.add_argument("--out", type=Path, required=True)
    capture_parser.add_argument("--output", type=Path, required=True)
    verify_parser = actions.add_parser("verify")
    verify_parser.add_argument("--proof", type=Path, required=True)
    verify_parser.add_argument("--sha256", required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        if args.action == "capture":
            capture(args)
        else:
            verify(args.proof, args.sha256)
        return 0
    except (ProofError, provenance.ProvenanceError) as error:
        print("docker_locality_proof.py: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
