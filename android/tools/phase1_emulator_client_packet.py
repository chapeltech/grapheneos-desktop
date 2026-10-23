#!/usr/bin/env python3
"""Build and verify the development-only Phase-1 x86 client APK packet.

This tool never builds an OS image and never handles production signing keys.
It consumes one already compile-qualified neutral-v3 Wonad successor, freshly
builds the emulator test applications in the pinned offline SDK container,
uses the separately stored emulator development identities, and emits a
content-addressed receipt.  Verification requires the receipt SHA-256 out of
band and rejects missing, extra, aliased, or changed packet files.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import io
import json
import os
import posixpath
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile


ROOT = Path(__file__).resolve().parents[2]
ANDROID = ROOT / "android"
DEFAULT_SUCCESSOR = ANDROID / "out/native-current-successor-12-phase1-v3-20261010-14"
DEFAULT_OUTPUT = ANDROID / "out/phase1-emulator-client-packet-20261010-4"
DEFAULT_SIGNER = Path("/u/elric/.local/state/wonad/phase1-emulator-signer")
DEFAULT_PUBLIC_CERT = Path("/u/elric/.local/state/wonad/phase1-emulator-public/wonad-phase1-emulator.x509.pem")
DEFAULT_PLATFORM_ROOT = Path("/u/elric/tree/wonad-grapheneos-2026100600")

BUILD_TOOLS = "/opt/android-sdk/build-tools/35.0.0/"
APKSIGNER = BUILD_TOOLS + "apksigner"
ZIPALIGN = BUILD_TOOLS + "zipalign"
AAPT2 = BUILD_TOOLS + "aapt2"
GRADLE = "/opt/gradle-8.11.1/bin/gradle"
JAVA_HOME = "/usr/lib/jvm/java-21-openjdk-amd64"
DEBUG_KEYSTORE = "/root/.android/debug.keystore"
KEYTOOL = JAVA_HOME + "/bin/keytool"
OPENSSL = "/usr/bin/openssl"
CONTAINER_PYTHON = "/usr/bin/python3.13"
REMOTE = "/work/phase1-emulator-client-packet-v1"
TOOLS_LABEL = "org.wonad.phase1-client-tools"
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
JAVA_RUNTIME_ELFS = tuple(JAVA_HOME + suffix for suffix in (
    "/bin/java", "/bin/keytool", "/lib/libjli.so", "/lib/server/libjvm.so",
    "/lib/libjava.so", "/lib/libzip.so", "/lib/libverify.so", "/lib/libjimage.so",
))
NONRUNTIME_TOOLS_SYMLINK_EXCLUSIONS = {
    JAVA_HOME + "/lib/src.zip": {
        "target": "../../openjdk-21/src.zip",
        "reason": "optional_absent_JDK_source_archive_not_runtime_input",
    },
}
OFFLINE_DEPENDENCY_COUNT = 437
OFFLINE_DEPENDENCY_SHA256 = "b4ddcf31964af56d8dbcc479a98843144d76055d2ef776a822002b0bf46496d5"
REQUIRED_TOOLS_FILE_COUNT = 452
REQUIRED_TOOLS_FILES_SHA256 = "4b1b6bab04e55d991678771a62023e1e687b014d40d55048d1d84e3363d764e2"
TOOLS_BOOTSTRAP_PACKET_SHA256 = "fdcab19a332fa02fc1fe3e58406039cbf480964ccfebd4ffc25bb0e5fc0e988f"
PARENT_TOOLS_FILES = {"/usr/bin/readelf", "/usr/bin/openssl", "/usr/bin/python3.13"}
TRANSFER_MAX_MEMBERS = 100000
TRANSFER_MAX_PAYLOAD_BYTES = 512 * 1024 * 1024
TRANSFER_MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024

# These packet-specific tools were installed in the selected long-lived tools
# container after its base image was created.  Pin their reviewed bytes here;
# verify_tools checks them before and after every build and on live verification.
PACKET_TOOL_SHA256 = {
    ZIPALIGN: "a205d94a45c8522ca1b571dcbe190df145c818f0a29dfb366e4dd78eef4f56a7",
    KEYTOOL: "bfd62a2ed799d9f2760ca528df3dc2df31fb6a33c521321b84e2ab67007b987d",
    OPENSSL: "38633817061f9d161c8b14c1ff72c9f223e8208d977a4c15d843010611a5dded",
    CONTAINER_PYTHON: "17b78e0a93175e86f9ac03141924fd7a7f0c0c52e66b34bfa0de20ffef989df1",
}

KIND = "phase1_source_matched_x86_development_client_packet_v1"
STATUS = "compile_qualified_development_packet_not_runtime_qualified"
WONAD_CERT = "3183261f28256159ad5e488d8a34854e77f36e14348720daae7f8cae7a8c26ff"
FIXTURE_CERT = "fdbf6a6940f8a1059fea942db2272abfb19e39716f544c92962a6e98103c4e88"
UPDATE_CANARY_SHA256 = "3e2cadb1bee2069453b3cfe84f116f8db4dae76dd6896181af9b9b2481aceef5"
SECURITY_SOURCE_FREEZE = "security-source-freeze.json"
SECURITY_BUILD_RECEIPT = "security-build-receipt.json"
CONFORMANCE_UPDATE_DIRECTORY = "conformance-version-update"
CONFORMANCE_UPDATE_RECEIPT = "preparation-receipt.json"
CONFORMANCE_UPDATE_FILES = {
    "original": "original.apk",
    "candidate": "candidate.apk",
    "unsigned": "unsigned-version-only.apk",
}
UPDATE_CANARY_RUNNER = (
    "org.wonad.desktop.test/"
    "org.wonad.desktop.security.UpdateDataInstrumentation"
)
SHA256 = re.compile(r"[0-9a-f]{64}")

MODULES = (
    "probe", "fixture", "ime-fixture", "session-security", "native-prerequisites",
    "native-task-reuse", "transition-fault", "desktop-sdk", "broker-core", "desktop",
    "conformance",
)
LIVE_TREES = (
    "android/fixture/src", "android/ime-fixture/src", "android/session-security/src",
    "android/native-prerequisites/src", "android/native-task-reuse/src",
    "android/transition-fault/src", "android/probe/src", "android/broker-core/src",
    "android/input-core", "android/feasibility", "android/broker-jni",
    "android/input-jni", "android/broker-rust",
)
LIVE_FILES = ("android/transition-fault/proguard-rules.pro",)

# role: (Gradle output, package, signer class, testOnly, ordinary eligible)
BUILT_APKS = {
    "fixture": ("fixture/build/outputs/apk/debug/fixture-debug.apk", "org.wonad.fixture", "fixture", False, True),
    "ime": ("ime-fixture/build/outputs/apk/debug/ime-fixture-debug.apk", "org.wonad.imefixture", "fixture", False, False),
    "security": ("session-security/build/outputs/apk/debug/session-security-debug.apk", "org.wonad.desktop.test", "wonad", True, False),
    "reuse": ("native-task-reuse/build/outputs/apk/release/native-task-reuse-release.apk", "org.wonad.desktop.taskreuse", "wonad", True, False),
    "fault": ("transition-fault/build/outputs/apk/debug/transition-fault-debug.apk", "org.wonad.desktop.transitionfault", "platform", True, False),
    "prerequisite": ("native-prerequisites/build/outputs/apk/debug/native-prerequisites-debug.apk", "org.wonad.desktop.prerequisites", "wonad", True, False),
    "probe": ("probe/build/outputs/apk/release/probe-release-unsigned.apk", "org.wonad.probe", "fixture", False, True),
}
FINAL_FILES = {
    "wonad": "wonad.apk", "conformance": "conformance.apk", "fixture": "fixture.apk",
    "ime": "ime.apk", "security": "security.apk", "reuse": "task-reuse.apk",
    "fault": "fault.apk", "prerequisite": "prerequisites.apk", "probe": "probe.apk",
    "wrong_wonad": "wrong-signer/wrong-wonad.apk",
    "wrong_security": "wrong-signer/wrong-security.apk",
}

GRADLE_TASKS = (
    ":fixture:testDebugUnitTest", ":fixture:lintDebug", ":fixture:assembleDebug",
    ":ime-fixture:testDebugUnitTest", ":ime-fixture:lintDebug", ":ime-fixture:assembleDebug",
    ":session-security:testDebugUnitTest", ":session-security:lintDebug", ":session-security:assembleDebug",
    ":native-task-reuse:testDebugUnitTest", ":native-task-reuse:lintRelease", ":native-task-reuse:assembleRelease",
    ":transition-fault:testDebugUnitTest", ":transition-fault:lintDebug", ":transition-fault:assembleDebug",
    ":native-prerequisites:testDebugUnitTest", ":native-prerequisites:lintDebug", ":native-prerequisites:assembleDebug",
    ":probe:lintRelease", ":probe:assembleRelease",
)


class PacketError(ValueError):
    pass


def require(value, message):
    if not value:
        raise PacketError(message)


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ref(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink(), "Not one regular packet input: " + str(path))
    return {"sha256": sha(path), "bytes": path.stat().st_size}


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key: " + key)
        result[key] = value
    return result


def load(path: Path):
    return json.loads(path.read_text(), object_pairs_hook=unique)


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def write_new(path: Path, value, *, canonical_json=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "xb" if isinstance(value, bytes) or canonical_json else "x"
    with path.open(mode) as output:
        if canonical_json:
            output.write(canonical(value))
        else:
            output.write(value)


def run(argv, *, timeout=3600, env=None, stdout=None, text=True, input=None):
    result = subprocess.run(list(map(str, argv)), timeout=timeout, env=env, stdout=stdout or subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=text, input=input)
    require(result.returncode == 0, "Command failed (%d): %s\n%s" %
            (result.returncode, " ".join(map(str, argv)), "" if stdout else result.stdout))
    return "" if stdout else result.stdout


def safe_relative(name: str) -> bool:
    return bool(name) and not Path(name).is_absolute() and "\\" not in name and \
        all(part not in ("", ".", "..") for part in name.split("/"))


def copy_file(source: Path, target: Path):
    require(source.is_file() and not source.is_symlink(), "Missing/symlinked source: " + str(source))
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as incoming, target.open("xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing)
    require(ref(source) == ref(target), "Source changed while copying: " + str(source))


def literal_existing(path: Path, *, directory: bool) -> Path:
    raw = path.absolute()
    resolved = raw.resolve(strict=True)
    require(raw == resolved and not raw.is_symlink() and
            (raw.is_dir() if directory else raw.is_file()),
            "Select one literal existing %s: %s" % ("directory" if directory else "file", raw))
    return raw


def copy_tree(source: Path, target: Path, origins: dict, origin: str, packet_source: Path):
    require(source.is_dir() and not source.is_symlink(), "Missing/symlinked source tree: " + str(source))
    for path in sorted(source.rglob("*")):
        require(not path.is_symlink(), "Symlinked source input: " + str(path))
        if not path.is_file() or any(part in {"build", "target", ".gradle", "__pycache__"}
                                     for part in path.relative_to(source).parts):
            continue
        destination = target / path.relative_to(source)
        copy_file(path, destination)
        relative = destination.relative_to(packet_source).as_posix()
        require(relative not in origins, "Duplicate staged source: " + relative)
        origins[relative] = {"origin": origin + "/" + path.relative_to(source).as_posix(), **ref(destination)}


def inventory(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "Symlink in sealed tree: " + str(path))
        if path.is_file():
            result[path.relative_to(root).as_posix()] = ref(path)
        else:
            require(path.is_dir(), "Special file in sealed tree: " + str(path))
    return result


def apk_payload(path: Path) -> dict:
    """Hash every non-signature ZIP member, independent of signing/alignment."""
    result = {}
    total = 0
    with zipfile.ZipFile(path) as archive:
        names = [entry.filename for entry in archive.infolist()]
        require(len(names) == len(set(names)), "Duplicate APK ZIP member")
        for entry in archive.infolist():
            require(safe_relative(entry.filename.rstrip("/")), "Unsafe APK ZIP member")
            if signature_member(entry.filename):
                continue
            raw = b"" if entry.is_dir() else archive.read(entry)
            total += len(raw)
            require(total <= 256 * 1024 * 1024, "Oversized APK payload")
            result[entry.filename] = {
                "sha256": sha_bytes(raw), "bytes": len(raw), "directory": entry.is_dir(),
                "compression": entry.compress_type,
            }
    require("AndroidManifest.xml" in result, "APK lacks AndroidManifest.xml")
    return result


def signature_member(name: str) -> bool:
    return re.fullmatch(r"META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC))", name, re.I) is not None


def strip_signatures(source: Path, target: Path):
    """Rewrite a safe APK without either ZIP or APK-block signatures."""
    payload = apk_payload(source)
    with zipfile.ZipFile(source) as incoming, zipfile.ZipFile(target, "x") as outgoing:
        for entry in incoming.infolist():
            if signature_member(entry.filename):
                continue
            clone = copy.copy(entry)
            clone.extra = b""  # zipalign will create the only required padding.
            raw = b"" if entry.is_dir() else incoming.read(entry)
            outgoing.writestr(clone, raw)
    require(apk_payload(target) == payload, "Signature stripping changed APK payload")


def pem_der_hash(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), "Missing literal public certificate")
    match = re.fullmatch(r"\s*-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+?)\s+"
                         r"-----END CERTIFICATE-----\s*", path.read_text(encoding="ascii"))
    require(match is not None, "Malformed or noncanonical X.509 PEM certificate")
    encoded = re.sub(r"\s+", "", match.group(1))
    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise PacketError("Malformed X.509 PEM base64") from error
    require(len(raw) > 64 and raw.startswith(b"\x30"), "Malformed X.509 DER certificate")
    return sha_bytes(raw)


def parse_signer(output: str) -> dict:
    digests = re.findall(r"Signer #\d+ certificate SHA-256 digest: ([0-9a-f]{64})", output)
    require(len(digests) == 1, "APK does not have exactly one signer")
    schemes = {}
    for version in (1, 2, 3, 3.1, 4):
        match = re.search(r"Verified using v%s scheme[^:]*: (true|false)" % re.escape(str(version)), output)
        if match:
            schemes[str(version)] = match.group(1) == "true"
    require(schemes.get("3") is True, "APK lacks a verified v3 signature")
    return {"certificate_der_sha256": digests[0], "signers": 1, "schemes": schemes}


def apk_metadata(badging: str, manifest: str) -> dict:
    package = re.findall(r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']*)'", badging, re.M)
    require(len(package) == 1, "Ambiguous APK package metadata")
    name, code, version = package[0]
    test_only = bool(re.search(
        r"android:testOnly(?:\([^)]*\))?=(?:\(type 0x12\))?(?:0xffffffff|true|\"true\")", manifest))
    shared_uid_lines = [line for line in manifest.splitlines() if "android:sharedUserId" in line]
    instrumentation_targets = sorted(set(re.findall(
        r"android:targetPackage(?:\([^)]*\))?=\"([^\"]+)\"", manifest)))
    return {
        "package": name, "version_code": int(code), "version_name": version,
        "debuggable": "application-debuggable" in badging,
        "test_only": test_only,
        "instrumentation_targets": instrumentation_targets,
        "shared_uid": bool(shared_uid_lines),
        "privileged_manifest": any("android.uid.system" in line for line in shared_uid_lines),
    }


class Tools:
    """One disposable, networkless container from an immutable tools image."""
    def __init__(self, image: str):
        require(isinstance(image, str) and IMAGE_ID.fullmatch(image),
                "Select one immutable Phase-1 tools image ID")
        self.image = image
        self.container = None
        self.token = secrets.token_hex(16)

    def __enter__(self):
        rows = json.loads(run(["docker", "image", "inspect", self.image]))
        environment = rows[0].get("Config", {}).get("Env", []) if len(rows) == 1 else []
        pairs = [value.split("=", 1) for value in environment
                 if isinstance(value, str) and "=" in value]
        environment = dict(pairs) if len(pairs) == len(environment) and \
            len({key for key, _ in pairs}) == len(pairs) else {}
        require(len(rows) == 1 and rows[0].get("Id") == self.image and
                rows[0].get("Architecture") == "amd64" and rows[0].get("Os") == "linux" and
                rows[0].get("RootFS", {}).get("Layers") and
                environment.get("JAVA_HOME") == JAVA_HOME and
                environment.get("PATH", "").startswith(JAVA_HOME + "/bin:"),
                "Immutable Phase-1 tools image is absent or changed")
        name = "wonad-phase1-client-tools-" + self.token[:12]
        identity = run(["docker", "create", "--name", name,
            "--label", TOOLS_LABEL + "=" + self.token, "--network", "none",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
            "--pids-limit", "2048", "--memory", "8g", "--cpus", "12",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=1g",
            "--tmpfs", "/work:rw,nosuid,nodev,size=8g",
            "--entrypoint", "sleep", self.image, "infinity"]).strip()
        require(CONTAINER_ID.fullmatch(identity) is not None,
                "Docker returned no exact tools container ID")
        self.container = identity
        try:
            require(run(["docker", "start", identity]).strip() == identity,
                    "Docker started a different tools container")
            self.inspect()
            return self
        except Exception:
            self.close()
            raise

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self.container is None:
            return
        identity, self.container = self.container, None
        result = subprocess.run(["docker", "container", "rm", "-f", identity],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        require(result.returncode == 0 and result.stdout.strip() == identity,
                "Could not consume disposable tools container: " + result.stdout)
        absent = subprocess.run(["docker", "container", "inspect", identity],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        require(absent.returncode == 1 and absent.stdout.strip() == "[]" and
                "No such container" in absent.stderr,
                "Disposable tools container still exists after removal")

    def inspect(self):
        require(self.container is not None, "Disposable tools container was not started")
        rows = json.loads(run(["docker", "container", "inspect", self.container]))
        require(len(rows) == 1, "Ambiguous disposable tools container")
        row = rows[0]
        host = row.get("HostConfig", {})
        values = row.get("Config", {}).get("Env", [])
        pairs = [value.split("=", 1) for value in values
                 if isinstance(value, str) and "=" in value]
        environment = dict(pairs) if len(pairs) == len(values) and \
            len({key for key, _ in pairs}) == len(pairs) else {}
        require(row.get("Id") == self.container and row.get("Image") == self.image and
                row.get("Name") == "/wonad-phase1-client-tools-" + self.token[:12] and
                row.get("Config", {}).get("Labels", {}).get(TOOLS_LABEL) == self.token and
                row.get("State", {}).get("Running") is True and not row.get("State", {}).get("Paused") and
                not row.get("State", {}).get("Dead") and row.get("Mounts") == [] and
                host.get("NetworkMode") == "none" and host.get("Privileged") is False and
                host.get("CapDrop") == ["ALL"] and not host.get("PortBindings") and
                not host.get("Binds") and host.get("Tmpfs") == {
                    "/tmp": "rw,nosuid,nodev,size=1g",
                    "/work": "rw,nosuid,nodev,size=8g",
                } and "no-new-privileges=true" in host.get("SecurityOpt", []) and
                environment.get("JAVA_HOME") == JAVA_HOME and
                environment.get("PATH", "").startswith(JAVA_HOME + "/bin:"),
                "Disposable SDK tools container identity/isolation changed")
        return row

    def exec(self, *argv, timeout=3600, env=None, text=True):
        require(self.container is not None, "Disposable tools container was not started")
        command = ["docker", "exec"]
        if env:
            for key in sorted(env):
                command += ["-e", key]
        command += [self.container, *map(str, argv)]
        environment = None if env is None else {**os.environ, **env}
        return run(command, timeout=timeout, env=environment, text=text)

    def cp_in(self, source: Path, target: str):
        require(self.container is not None, "Disposable tools container was not started")
        source = source.absolute()
        self._safe_remote(target)
        require(source.resolve(strict=True) == source and not source.is_symlink() and
                (source.is_file() or source.is_dir()),
                "Transfer input must be one literal file or directory")
        parent, name = target.rsplit("/", 1)
        self.exec("test", "-d", parent); self.exec("test", "!", "-e", target)
        before = self._local_transfer_inventory(source, include_root=True)
        with tempfile.TemporaryFile(prefix="phase1-tools-copy-in.") as stream:
            with tarfile.open(fileobj=stream, mode="w") as archive:
                def safe(info):
                    require(info.isfile() or info.isdir(),
                            "Transfer input contains a link or special file: " + info.name)
                    info.uid = info.gid = 0; info.uname = info.gname = "root"
                    return info
                archive.add(source, arcname=name, recursive=True, filter=safe)
            require(stream.tell() <= TRANSFER_MAX_ARCHIVE_BYTES,
                    "Transfer input archive exceeds its explicit bound")
            require(self._local_transfer_inventory(source, include_root=True) == before,
                    "Transfer input changed while archiving")
            stream.seek(0)
            result = subprocess.run(["docker", "exec", "-i", self.container, "/usr/bin/tar",
                "-C", parent, "-xpf", "-"], stdin=stream, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, timeout=3600)
        require(result.returncode == 0,
                "Container archive extraction failed: " + result.stdout.decode(errors="replace"))
        require(self._remote_transfer_inventory(target, include_root=True) == before,
                "Container transfer input differs by path/type/mode/bytes")

    def cp_out(self, source: str, target: Path):
        require(self.container is not None, "Disposable tools container was not started")
        contents = source.endswith("/.")
        source = source[:-2] if contents else source
        self._safe_remote(source)
        before = self._remote_transfer_inventory(source, include_root=not contents)
        require(target.parent.is_dir() and not target.is_symlink() and
                ((contents and target.is_dir()) or (not contents and not target.exists())),
                "Unsafe transfer output target")
        parent, name = source.rsplit("/", 1)
        command = ["docker", "exec", self.container, "/usr/bin/tar", "-C",
                   source if contents else parent, "-cpf", "-", "." if contents else name]
        with tempfile.TemporaryFile(prefix="phase1-tools-copy-out.") as stream:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.PIPE, timeout=3600)
            require(result.returncode == 0,
                    "Container archive creation failed: " + result.stderr.decode(errors="replace"))
            require(stream.tell() <= TRANSFER_MAX_ARCHIVE_BYTES,
                    "Container transfer archive exceeds its explicit bound")
            require(self._remote_transfer_inventory(source, include_root=not contents) == before,
                    "Container transfer output changed while archiving")
            stream.seek(0)
            if contents:
                self._extract_transfer(stream, target)
            else:
                with tempfile.TemporaryDirectory(prefix="phase1-tools-copy-out-", dir=target.parent) as temporary:
                    staging = Path(temporary)
                    self._extract_transfer(stream, staging)
                    extracted = staging / name
                    require(extracted.exists() and not extracted.is_symlink(),
                            "Container archive omitted its exact root")
                    shutil.move(str(extracted), target)
        require(self._local_transfer_inventory(target, include_root=not contents) == before,
                "Host transfer output differs by path/type/mode/bytes")

    @staticmethod
    def _safe_remote(path: str):
        require(isinstance(path, str) and path.startswith("/") and "\\" not in path and
                all(part not in ("", ".", "..") for part in path.split("/")[1:]),
                "Unsafe container transfer path")
        work = path == REMOTE or path.startswith(REMOTE + "/")
        signing = re.fullmatch(
            r"/tmp/phase1-client-signing\.[A-Za-z0-9]{8}(?:/[A-Za-z0-9_.-]+)?", path)
        require(work or signing is not None, "Container transfer path is outside owned roots")

    @staticmethod
    def _local_transfer_inventory(root: Path, *, include_root: bool) -> dict:
        root = root.absolute()
        require(root.resolve(strict=True) == root and not root.is_symlink(),
                "Transfer inventory root is aliased or symlinked")
        rows, total = {}, 0
        def paths():
            if include_root:
                yield root
            if root.is_dir():
                yield from root.rglob("*")
        for path in paths():
            value = path.lstat()
            require(not path.is_symlink() and (path.is_dir() or path.is_file()),
                    "Transfer tree contains a link or special file: " + str(path))
            name = "." if path == root else path.relative_to(root).as_posix()
            row = {"kind": "directory" if path.is_dir() else "file",
                   "mode": value.st_mode & 0o7777}
            if path.is_file(): row.update(ref(path))
            rows[name] = row
            total += row.get("bytes", 0)
            require(len(rows) <= TRANSFER_MAX_MEMBERS and total <= TRANSFER_MAX_PAYLOAD_BYTES,
                    "Transfer tree exceeds its explicit member/byte bounds")
        return rows

    def _remote_transfer_inventory(self, root: str, *, include_root: bool) -> dict:
        program = r'''import hashlib,json,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]); include=sys.argv[2]=="1"; max_members=int(sys.argv[3]); max_bytes=int(sys.argv[4])
if not root.exists() or root.is_symlink(): raise SystemExit("missing/symlinked transfer root")
rows={}; total=0
def paths():
 if include: yield root
 if root.is_dir(): yield from root.rglob("*")
for path in paths():
 value=path.lstat()
 if path.is_symlink() or not (path.is_dir() or path.is_file()): raise SystemExit("link/special transfer member")
 name="." if path==root else path.relative_to(root).as_posix()
 row={"kind":"directory" if path.is_dir() else "file","mode":stat.S_IMODE(value.st_mode)}
 if path.is_file():
  digest=hashlib.sha256()
  with path.open("rb") as stream:
   for chunk in iter(lambda:stream.read(1048576),b""): digest.update(chunk)
  row.update({"sha256":digest.hexdigest(),"bytes":value.st_size})
 rows[name]=row
 total+=row.get("bytes",0)
 if len(rows)>max_members or total>max_bytes: raise SystemExit("bounded transfer exceeded")
print(json.dumps(rows,sort_keys=True,separators=(",",":")))'''
        value = json.loads(self.exec(CONTAINER_PYTHON, "-c", program, root,
                                     "1" if include_root else "0", str(TRANSFER_MAX_MEMBERS),
                                     str(TRANSFER_MAX_PAYLOAD_BYTES)))
        require(isinstance(value, dict), "Malformed container transfer inventory")
        return value

    @staticmethod
    def _extract_transfer(stream, target: Path):
        stream.seek(0, 2)
        require(stream.tell() <= TRANSFER_MAX_ARCHIVE_BYTES,
                "Container transfer archive exceeds its explicit bound")
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r:") as archive:
            members, names, total = [], set(), 0
            for member in archive:
                members.append(member)
                total += member.size if member.isfile() else 0
                require(len(members) <= TRANSFER_MAX_MEMBERS and
                        total <= TRANSFER_MAX_PAYLOAD_BYTES,
                        "Container archive exceeds its explicit member/byte bounds")
                normalized = posixpath.normpath(member.name)
                require(not member.name.startswith("/") and "\\" not in member.name and
                        (normalized == "." or safe_relative(normalized)) and
                        member.name in (normalized, "./" + normalized) and normalized not in names and
                        (member.isfile() or member.isdir()) and
                        (normalized != "." or member.isdir()),
                        "Unsafe container archive member: " + member.name)
                names.add(normalized)
            def safe_extract(member, _destination):
                # Names and types have already been checked as one complete,
                # duplicate-free archive.  Preserve the authenticated mode but
                # never import container ownership onto the host.  A contents
                # transfer's synthetic `.` entry must not chmod its preexisting
                # host destination directory.
                normalized = posixpath.normpath(member.name)
                return member.replace(
                    mode=None if normalized == "." else member.mode,
                    uid=None, gid=None, uname=None, gname=None, deep=False)
            archive.extractall(target, members=members, filter=safe_extract)

    def clean_remote(self):
        # REMOTE is a fixed, exact child, never a caller-controlled path.
        self.exec(CONTAINER_PYTHON, "-c",
                  "import pathlib,shutil; p=pathlib.Path(%r); "
                  "assert str(p).startswith('/work/phase1-emulator-client-packet-'); "
                  "shutil.rmtree(p) if p.exists() else None" % REMOTE)


def verify_successor(successor: Path) -> dict:
    require(successor.resolve(strict=True) == successor and successor.is_dir() and not successor.is_symlink(),
            "Successor must be one literal existing directory")
    sys.path.insert(0, str(ANDROID / "tools"))
    from native_current_compile_acceptance import audit
    receipt = load(successor / "build-receipt.json")
    audit(receipt, lambda name: (successor / name).read_bytes())
    require(receipt["status"] == "current_source_compile_qualified_not_runtime" and
            receipt["artifact"]["version_code"] == 12 and receipt["artifact"]["package"] == "org.wonad.desktop",
            "Not the selected neutral-v3 successor 12")
    return receipt


def stage_sources(successor: Path, output: Path) -> tuple[Path, dict]:
    target = output / "source"
    target.mkdir(mode=0o700)
    origins = {}
    frozen = successor / "source"
    for relative in ("android/build.gradle.kts", "android/settings.gradle.kts"):
        destination = target / relative
        copy_file(frozen / relative, destination)
        origins[relative] = {"origin": "successor/" + relative, **ref(destination)}
    for module in MODULES:
        relative = "android/%s/build.gradle.kts" % module
        destination = target / relative
        copy_file(frozen / relative, destination)
        origins[relative] = {"origin": "successor/" + relative, **ref(destination)}
    # The public API must be byte-for-byte the one compiled into successor 12.
    copy_tree(frozen / "android/desktop-sdk/src", target / "android/desktop-sdk/src", origins,
              "successor/android/desktop-sdk/src", target)
    for name in ("API-v3.md", "README.md"):
        source = frozen / "android/desktop-sdk" / name
        destination = target / "android/desktop-sdk" / name
        copy_file(source, destination)
        origins[destination.relative_to(target).as_posix()] = {"origin": "successor/android/desktop-sdk/" + name, **ref(destination)}
    check = frozen / "android/tools/check_native.py"
    copy_file(check, target / "android/tools/check_native.py")
    origins["android/tools/check_native.py"] = {"origin": "successor/android/tools/check_native.py", **ref(target / "android/tools/check_native.py")}
    for relative in LIVE_TREES:
        copy_tree(ROOT / relative, target / relative, origins, "working-tree/" + relative, target)
    for relative in LIVE_FILES:
        destination = target / relative
        copy_file(ROOT / relative, destination)
        origins[relative] = {"origin": "working-tree/" + relative, **ref(destination)}
    require(all(safe_relative(path) for path in origins), "Internal source origin escaped")
    return target, origins


def native_build(source: Path, output: Path, successor_plan: dict) -> dict:
    evidence = output / "evidence/native"
    evidence.mkdir(parents=True)
    toolchain = Path(successor_plan["cross_tools"]["root"])
    require(toolchain.resolve(strict=True) == toolchain and toolchain.is_dir(), "Pinned cross toolchain missing")
    sys.path.insert(0, str(ANDROID / "tools"))
    from build_native_successor import cross_tools
    require(cross_tools() == successor_plan["cross_tools"], "Pinned native tool/dependency state changed before build")
    cross_image = successor_plan["cross_image"]
    image = json.loads(run(["docker", "image", "inspect", cross_image]))
    require(len(image) == 1 and image[0]["Id"] == cross_image, "Pinned Haskell cross image changed")
    cross_files = successor_plan["cross_tools"]["files"]
    tool_records = {}
    for relative in (
        "ghc-9.12.2/_build/stage0/bin/x86_64-unknown-linux-android-ghc",
        "android-ndk-r30/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android35-clang",
        "android-ndk-r30/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf",
        "android-ndk-r30/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/jni.h",
    ):
        path = toolchain / relative
        expected = cross_files[relative]
        actual = {"sha256": sha(path), "bytes": path.stat().st_size}
        require(actual == {key: expected[key] for key in ("sha256", "bytes")},
                "Pinned native tool changed: " + relative)
        tool_records[relative] = actual
    before = inventory(source)
    with tempfile.TemporaryDirectory(prefix="phase1-emulator-clients-native.", dir="/tmp") as tmp:
        work = Path(tmp) / "source"
        shutil.copytree(source, work)
        rust_tools = successor_plan["cross_tools"]["host_rust"]
        cargo = next(Path(path) for path in rust_tools if Path(path).name == "cargo")
        rustc = next(Path(path) for path in rust_tools if Path(path).name == "rustc")
        environment = {**os.environ, "ANDROID_NDK_HOME": str(toolchain / "android-ndk-r30"),
                       "CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "8", "RUSTC": str(rustc),
                       "PATH": str(cargo.parent) + os.pathsep + os.environ["PATH"]}
        commands = (
            ("broker-jni.log", ["bash", work / "android/broker-jni/build.sh", "android"]),
            ("input-jni.log", ["bash", work / "android/input-jni/build.sh", "android"]),
        )
        for log, command in commands:
            with (evidence / log).open("xb") as stream:
                run(command, timeout=1800, env=environment, stdout=stream)
        probe_command = ["docker", "run", "--rm", "--network", "none", "--cpus", "4",
            "--memory", "4g", "--memory-swap", "4g", "--user", str(os.getuid()) + ":" + str(os.getgid()),
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "label=disable",
            "--mount", "type=bind,src=" + str(work) + ",dst=/work",
            "--mount", "type=bind,src=" + str(toolchain) + ",dst=/sources/toolchain,readonly",
            "--env", "WONAD_ANDROID_GHC=/sources/toolchain/ghc-9.12.2/_build/stage0/bin/x86_64-unknown-linux-android-ghc",
            "--env", "ANDROID_NDK_HOME=/sources/toolchain/android-ndk-r30",
            "--env", "WONAD_ANDROID_ABI=x86_64", cross_image,
            "bash", "/work/android/feasibility/build-native.sh"]
        with (evidence / "probe-haskell.log").open("xb") as stream:
            run(probe_command, timeout=1800, stdout=stream)
        products = {
            "broker": work / "android/out/broker-native/x86_64/libwonad_broker_jni.so",
            "input": work / "android/out/broker-native/x86_64/libwonad_input_jni.so",
            "probe": work / "android/out/android-native/x86_64/libwonad_probe.so",
        }
        for path in products.values():
            require(path.is_file(), "Fresh native build omitted " + str(path))
        destinations = {
            "broker": ("android/out/broker-native/x86_64/libwonad_broker_jni.so",
                       "android/out/native-prerequisites-jni/x86_64/libwonad_broker_jni.so"),
            "input": ("android/out/broker-native/x86_64/libwonad_input_jni.so",),
            "probe": ("android/out/android-native/x86_64/libwonad_probe.so",),
        }
        result = {"cross_image": cross_image, "pinned_tool_files": tool_records,
                  "cross_tools_sha256": sha_bytes(canonical(successor_plan["cross_tools"]))}
        for role, paths in destinations.items():
            for relative in paths:
                copy_file(products[role], source / relative)
            copy_file(products[role], evidence / Path(paths[0]).name)
            result[role] = {"source_files": list(paths), **ref(evidence / Path(paths[0]).name)}
        result["logs"] = {name: ref(evidence / name) for name in
                          ("broker-jni.log", "input-jni.log", "probe-haskell.log")}
        require("PASS: Android x86_64 ELF checks" in (evidence / "broker-jni.log").read_text() and
                "PASS: Android x86_64 ELF checks" in (evidence / "input-jni.log").read_text() and
                "PASS: Android x86_64 ELF checks" in (evidence / "probe-haskell.log").read_text(),
                "A fresh native ELF check did not pass")
    require({k: v for k, v in inventory(source).items() if k in before} == before,
            "Fresh native build changed a staged source input")
    require(cross_tools() == successor_plan["cross_tools"], "Pinned native tool/dependency state changed during build")
    return result


def verify_tools(tools: Tools, plan: dict) -> dict:
    row = tools.inspect()
    expected = plan["sdk_tools"]["tools"]
    rows = tools.exec("sha256sum", *sorted(expected)).splitlines()
    actual = {line.split("  ", 1)[1]: line.split("  ", 1)[0] for line in rows}
    require(actual == expected, "Pinned SDK tool bytes changed")
    rows = tools.exec("sha256sum", *sorted(PACKET_TOOL_SHA256)).splitlines()
    packet_tools = {line.split("  ", 1)[1]: line.split("  ", 1)[0] for line in rows}
    require(packet_tools == PACKET_TOOL_SHA256, "Packet-specific signing/cleanup tool bytes changed")
    dependencies = plan["sdk_tools"]["offline_dependency_artifacts"]
    rows = tools.exec("sha256sum", *sorted(dependencies), timeout=600).splitlines()
    actual_dependencies = {line.split("  ", 1)[1]: line.split("  ", 1)[0] for line in rows}
    require(actual_dependencies == dependencies, "Pinned offline Gradle cache changed")
    key = tools.exec("sha256sum", DEBUG_KEYSTORE).split()[0]
    require(key == plan["sdk_tools"]["signing_key_sha256"], "Pinned fixture signing key changed")
    return {
        "container_id": row["Id"], "image_id": tools.image,
        "tools": expected, "packet_specific_tools": packet_tools,
        "offline_dependencies_sha256": sha_bytes(canonical(dependencies)),
        "offline_dependencies_count": len(dependencies), "fixture_keystore_sha256": key,
    }


def authenticate_tools_image_manifest(path: Path, expected_hash: str, image: str) -> dict:
    path = literal_existing(path, directory=False)
    require(SHA256.fullmatch(str(expected_hash)) is not None and sha(path) == expected_hash,
            "Tools-image manifest differs from its out-of-band SHA-256")
    value = load(path)
    require(set(value) == {"schema", "kind", "scope", "production_identity", "network_used",
            "image_id", "base_image_id", "source_container_id", "source_packet_receipt",
            "source_packet_plan", "payload_inventory", "required_files", "nonruntime_symlink_exclusions",
            "java_runtime_closure", "dockerfile", "builder"} and
            value["schema"] == 1 and value["kind"] == "phase1_immutable_client_tools_image_v1" and
            value["scope"] == "development_only_android_client_compile_and_apk_verification" and
            value["production_identity"] is False and value["network_used"] is False and
            value["image_id"] == image and IMAGE_ID.fullmatch(str(value["base_image_id"])) and
            CONTAINER_ID.fullmatch(str(value["source_container_id"])),
            "Malformed or mismatched immutable tools-image manifest")
    inventory_path = path.with_name("payload-inventory.json")
    source_receipt_path = path.with_name("source-packet-receipt.json")
    source_plan_path = path.with_name("source-packet-plan.json")
    dockerfile_path = path.with_name("Dockerfile")
    builder_path = path.with_name("build-phase1-client-tools.py")
    require(ref(source_receipt_path) == value["source_packet_receipt"] and
            value["source_packet_receipt"].get("sha256") == TOOLS_BOOTSTRAP_PACKET_SHA256 and
            ref(source_plan_path) == value["source_packet_plan"] and
            ref(dockerfile_path) == value["dockerfile"] and
            ref(builder_path) == value["builder"] and
            dockerfile_path.read_bytes() == (ANDROID / "container/Dockerfile.phase1-client-tools").read_bytes() and
            builder_path.read_bytes() == (ANDROID / "container/build-phase1-client-tools.py").read_bytes(),
            "Immutable tools-image build inputs are absent, changed, or not the reviewed sources")
    source_receipt = load(source_receipt_path)
    source_tools = source_receipt.get("tools", {})
    require(source_receipt.get("schema") == 2 and
            source_receipt.get("kind") == KIND and source_receipt.get("status") == STATUS and
            source_receipt.get("development_only") is True and
            source_tools.get("container_id") == value["source_container_id"] and
            source_tools.get("image_id") == value["base_image_id"],
            "Immutable tools-image source packet receipt is malformed or mismatched")
    require(source_receipt.get("successor", {}).get("retained_inputs", {}).get("plan.json") ==
            ref(source_plan_path), "Immutable tools-image source retained plan is absent or changed")
    source_plan = load(source_plan_path)
    required_files = source_required_tools_files(source_receipt, source_plan)
    inventory_ref = ref(inventory_path)
    summary = value["payload_inventory"]
    require(type(summary) is dict and inventory_ref == {
                "sha256": summary.get("sha256"), "bytes": summary.get("bytes")} and
            type(summary.get("entries")) is int and summary["entries"] > 0 and
            type(summary.get("regular_files")) is int and 0 < summary["regular_files"] < summary["entries"] and
            type(summary.get("payload_bytes")) is int and summary["payload_bytes"] > 0,
            "Tools-image payload inventory reference is malformed")
    inventory = load(inventory_path)
    require(type(inventory) is dict and len(inventory) == summary["entries"] and
            all(type(row) is dict for row in inventory.values()),
            "Tools-image payload inventory summary differs")
    for name, row in inventory.items():
        kind = row.get("kind")
        valid = (kind == "directory" and set(row) == {"kind", "mode", "uid", "gid"} and
                 type(row["mode"]) is int) or \
                (kind == "symlink" and set(row) == {"kind", "target", "uid", "gid"} and
                 isinstance(row["target"], str) and bool(row["target"])) or \
                (kind == "file" and set(row) == {"kind", "mode", "bytes", "sha256", "uid", "gid"} and
                 type(row["mode"]) is int and type(row["bytes"]) is int and row["bytes"] >= 0 and
                 SHA256.fullmatch(str(row["sha256"])) is not None)
        require(isinstance(name, str) and name.startswith("/") and valid and
                row.get("uid") == 0 and row.get("gid") == 0,
                "Malformed tools-image payload inventory row: " + str(name))
    require(sum(row.get("kind") == "file" for row in inventory.values()) == summary["regular_files"] and
            sum(row.get("bytes", 0) for row in inventory.values()) == summary["payload_bytes"],
            "Tools-image payload inventory totals differ")
    required_summary = value.get("required_files")
    require(type(required_summary) is dict and set(required_summary) == {"count", "sha256", "files"} and
            required_summary["files"] == required_files and
            required_summary["count"] == REQUIRED_TOOLS_FILE_COUNT == len(required_files) and
            required_summary["sha256"] == sha_bytes(canonical(required_files)),
            "Immutable tools-image required-file mapping differs from its authenticated sources")
    missing_from_payload = set(required_files) - set(inventory)
    require(missing_from_payload == PARENT_TOOLS_FILES and all(
                inventory.get(name, {}).get("kind") == "file" and
                inventory[name].get("sha256") == digest
                for name, digest in required_files.items() if name not in PARENT_TOOLS_FILES),
            "Immutable tools payload does not contain the exact copied required-file mapping")
    validate_tools_java_closure(value, inventory)
    return {"manifest_path": path, "inventory_path": inventory_path,
            "source_receipt_path": source_receipt_path, "source_plan_path": source_plan_path,
            "dockerfile_path": dockerfile_path,
            "builder_path": builder_path,
            "manifest": value, "expected_sha256": expected_hash}


def source_required_tools_files(receipt: dict, plan: dict) -> dict:
    tools = receipt.get("tools", {})
    dependencies = plan.get("sdk_tools", {}).get("offline_dependency_artifacts")
    require(type(dependencies) is dict and len(dependencies) == OFFLINE_DEPENDENCY_COUNT and
            sha_bytes(canonical(dependencies)) == OFFLINE_DEPENDENCY_SHA256 and
            all(isinstance(name, str) and name.startswith("/root/.gradle/") and
                SHA256.fullmatch(str(digest)) for name, digest in dependencies.items()),
            "Malformed authenticated offline dependency mapping")
    required = {}
    for field in ("tools", "packet_specific_tools"):
        values = tools.get(field)
        require(type(values) is dict and values and all(
                    isinstance(name, str) and name.startswith("/") and SHA256.fullmatch(str(digest))
                    for name, digest in values.items()), "Malformed packet tools mapping: " + field)
        for name, digest in values.items():
            require(name not in required or required[name] == digest,
                    "Conflicting packet required-file digest: " + name)
            required[name] = digest
    for name, digest in dependencies.items():
        require(name not in required or required[name] == digest,
                "Conflicting offline required-file digest: " + name)
        required[name] = digest
    fixture = tools.get("fixture_keystore_sha256")
    require(SHA256.fullmatch(str(fixture)) is not None,
            "Malformed packet fixture keystore digest")
    name = DEBUG_KEYSTORE
    require(name not in required or required[name] == fixture,
            "Conflicting fixture keystore digest")
    required[name] = fixture
    require(len(required) == REQUIRED_TOOLS_FILE_COUNT,
            "Authenticated required-file set has changed")
    required = dict(sorted(required.items()))
    require(sha_bytes(canonical(required)) == REQUIRED_TOOLS_FILES_SHA256,
            "Authenticated required-file mapping digest changed")
    return required


def validate_tools_java_closure(manifest: dict, inventory: dict):
    require(manifest.get("nonruntime_symlink_exclusions") == NONRUNTIME_TOOLS_SYMLINK_EXCLUSIONS and
            JAVA_HOME + "/lib/src.zip" not in inventory,
            "Immutable tools image changed its reviewed non-runtime symlink exclusion")
    require(inventory.get(JAVA_HOME + "/lib/security/cacerts") == {
                "kind": "symlink", "target": "/etc/ssl/certs/java/cacerts", "uid": 0, "gid": 0} and
            inventory.get("/etc/ssl/certs/java/cacerts", {}).get("kind") == "file" and
            inventory.get(JAVA_HOME + "/docs") == {
                "kind": "symlink", "target": "../../../share/doc/openjdk-21-jre-headless",
                "uid": 0, "gid": 0} and
            inventory.get("/usr/share/doc/openjdk-21-jre-headless", {}).get("kind") == "directory",
            "Immutable tools image does not close the JDK trust-store/docs links")
    closure = manifest.get("java_runtime_closure")
    require(type(closure) is dict and set(closure) == {
                "entrypoints", "frozen_dependencies", "parent_dependencies", "smoke"},
            "Malformed Java runtime closure")
    entrypoints = closure["entrypoints"]
    require(type(entrypoints) is dict and set(entrypoints) == set(JAVA_RUNTIME_ELFS),
            "Java runtime closure entrypoint set changed")
    for name, row in entrypoints.items():
        resolved = row.get("resolved") if isinstance(row, dict) else None
        require(set(row) == {"sha256", "closure_sha256", "resolved"} and
                inventory.get(name, {}).get("kind") == "file" and
                row["sha256"] == inventory[name]["sha256"] and
                isinstance(resolved, list) and resolved == sorted(set(resolved)) and resolved and
                all(isinstance(value, str) and value.startswith("/") for value in resolved) and
                row["closure_sha256"] == sha_bytes(canonical(resolved)),
                "Malformed Java runtime entrypoint closure: " + name)
    frozen = closure["frozen_dependencies"]
    parent = closure["parent_dependencies"]
    require(isinstance(frozen, list) and frozen == sorted(set(frozen)) and
            all(inventory.get(name, {}).get("kind") == "file" for name in frozen) and
            isinstance(parent, dict) and parent and
            all(isinstance(name, str) and name.startswith("/") and
                SHA256.fullmatch(str(digest)) for name, digest in parent.items()),
            "Malformed Java native dependency closure")
    resolved_union = {posixpath.normpath(value)
                      for row in entrypoints.values() for value in row["resolved"]}
    require(not (set(frozen) & set(parent)) and
            resolved_union == set(frozen) | set(parent),
            "Java native dependency closure omits or forges a resolved dependency")
    smoke = closure["smoke"]
    require(type(smoke) is dict and set(smoke) == {
                "java_version", "keytool_cacerts", "keytool_debug_keystore",
                "gradle_version", "apksigner_version", "apksigner_sign_verify"} and
            all(type(row) is dict and set(row) == {"sha256", "bytes"} and
                SHA256.fullmatch(str(row["sha256"])) and type(row["bytes"]) is int and row["bytes"] > 0
                for row in smoke.values()),
            "Malformed Java/SDK real-command smoke evidence")


def stage_tools_image_evidence(output: Path, evidence: dict) -> dict:
    destination = output / "evidence/tools-image"
    destination.mkdir(parents=True)
    manifest = destination / "manifest.json"
    inventory = destination / "payload-inventory.json"
    source_receipt = destination / "source-packet-receipt.json"
    source_plan = destination / "source-packet-plan.json"
    dockerfile = destination / "Dockerfile"
    builder = destination / "build-phase1-client-tools.py"
    copy_file(evidence["manifest_path"], manifest)
    copy_file(evidence["inventory_path"], inventory)
    copy_file(evidence["source_receipt_path"], source_receipt)
    copy_file(evidence["source_plan_path"], source_plan)
    copy_file(evidence["dockerfile_path"], dockerfile)
    copy_file(evidence["builder_path"], builder)
    require(sha(manifest) == evidence["expected_sha256"],
            "Tools-image manifest changed while staging")
    return {
        "kind": evidence["manifest"]["kind"],
        "image_id": evidence["manifest"]["image_id"],
        "manifest": ref(manifest),
        "payload_inventory": ref(inventory),
        "source_packet_receipt": ref(source_receipt),
        "source_packet_plan": ref(source_plan),
        "dockerfile": ref(dockerfile),
        "builder": ref(builder),
    }


def verify_tools_image_evidence(output: Path, tools_record: dict):
    evidence = tools_record.get("image_build") if isinstance(tools_record, dict) else None
    require(type(evidence) is dict and set(evidence) == {
                "kind", "image_id", "manifest", "payload_inventory", "source_packet_receipt",
                "source_packet_plan", "dockerfile", "builder"} and
            evidence["kind"] == "phase1_immutable_client_tools_image_v1" and
            evidence["image_id"] == tools_record.get("image_id"),
            "Packet lacks immutable tools-image build evidence")
    manifest_path = output / "evidence/tools-image/manifest.json"
    inventory_path = output / "evidence/tools-image/payload-inventory.json"
    source_receipt_path = output / "evidence/tools-image/source-packet-receipt.json"
    source_plan_path = output / "evidence/tools-image/source-packet-plan.json"
    dockerfile_path = output / "evidence/tools-image/Dockerfile"
    builder_path = output / "evidence/tools-image/build-phase1-client-tools.py"
    require(ref(manifest_path) == evidence["manifest"] and
            ref(inventory_path) == evidence["payload_inventory"] and
            ref(source_receipt_path) == evidence["source_packet_receipt"] and
            ref(source_plan_path) == evidence["source_packet_plan"] and
            ref(dockerfile_path) == evidence["dockerfile"] and
            ref(builder_path) == evidence["builder"],
            "Packet tools-image evidence bytes changed")
    authenticated = authenticate_tools_image_manifest(
        manifest_path, evidence["manifest"]["sha256"], evidence["image_id"])
    manifest = authenticated["manifest"]
    require(manifest.get("kind") == evidence["kind"] and
            manifest.get("payload_inventory", {}).get("sha256") == evidence["payload_inventory"]["sha256"] and
            manifest.get("payload_inventory", {}).get("bytes") == evidence["payload_inventory"]["bytes"],
            "Packet tools-image manifest binding differs")
    return evidence


def equivalent_tools_record(observed: dict, recorded: dict) -> bool:
    """Compare immutable tools state while allowing a new disposable container."""
    if not isinstance(observed, dict) or not isinstance(recorded, dict) or \
            set(recorded) != set(observed) | {"image_build"} or \
            CONTAINER_ID.fullmatch(str(observed.get("container_id"))) is None or \
            CONTAINER_ID.fullmatch(str(recorded.get("container_id"))) is None:
        return False
    return all(observed[name] == recorded[name] for name in observed if name != "container_id") and \
        isinstance(recorded.get("image_build"), dict)


def junit_audit(directory: Path) -> dict:
    cases = []
    for path in sorted(directory.rglob("TEST-*.xml")):
        root = ET.parse(path).getroot()
        require(root.tag == "testsuite" and all(int(root.get(key, "-1")) == 0 for key in ("failures", "errors", "skipped")),
                "JVM test failure/skip: " + str(path))
        rows = root.findall("testcase")
        require(int(root.get("tests", "-1")) == len(rows) and all(not list(row) for row in rows),
                "Malformed JVM results: " + str(path))
        cases.extend((row.get("classname"), row.get("name")) for row in rows)
    require(cases and len(cases) == len(set(cases)), "Missing/duplicate fresh fixture JVM tests")
    return {"count": len(cases), "cases": sorted([list(row) for row in cases])}


def lint_audit(directory: Path) -> dict:
    files = sorted(directory.rglob("*lint-results-*.xml"))
    require(files, "No fresh lint outputs")
    warnings = 0
    for path in files:
        root = ET.parse(path).getroot()
        require(root.tag == "issues", "Malformed lint output")
        require(not any(row.get("severity") in ("Fatal", "Error") for row in root.findall("issue")),
                "Lint failure: " + str(path))
        warnings += sum(row.get("severity") == "Warning" for row in root.findall("issue"))
    return {"files": len(files), "warnings": warnings}


def security_compile_evidence(output: Path, sources: dict, build: dict, artifact: dict,
                              *, write: bool) -> dict:
    """Bind the signed update harness to this packet's fresh Gradle compile.

    The runtime update freezer historically consumed a standalone security-APK
    receipt next to the APK.  A Phase-1 packet builds and signs that APK itself,
    so it emits the equivalent dedicated receipt and complete module freeze
    instead of borrowing an unrelated historical compile packet.
    """
    prefix = "android/session-security/"
    selected = {name: row for name, row in sources.items() if name.startswith(prefix)}
    require(selected and all(set(row) == {"origin", "sha256", "bytes"} for row in selected.values()),
            "Incomplete session-security source provenance")
    source_root = output / "source"
    manifest_name = prefix + "src/main/AndroidManifest.xml"
    canary_name = prefix + "src/main/kotlin/org/wonad/desktop/security/UpdateDataInstrumentation.kt"
    require(manifest_name in selected and canary_name in selected and
            selected[canary_name]["sha256"] == UPDATE_CANARY_SHA256,
            "Exact update canary source is absent from the compiled packet")
    manifest = (source_root / manifest_name).read_text()
    require(manifest.count('android:name="org.wonad.desktop.security.UpdateDataInstrumentation"') == 1 and
            manifest.count('android:targetPackage="org.wonad.desktop"') >= 1,
            "Update canary is not declared exactly once for the Wonad target")
    actual = {name: ref(source_root / name) for name in selected}
    require(all(actual[name] == {key: row[key] for key in ("sha256", "bytes")}
                for name, row in selected.items()), "Session-security source changed after compilation")

    freeze = {
        "schema": 2,
        "kind": "phase1_packet_security_source_freeze_v1",
        # Keep the simple hash map consumed by the independent runtime auditor.
        "files": {name: row["sha256"] for name, row in selected.items()},
        "records": selected,
    }
    freeze_path = output / SECURITY_SOURCE_FREEZE
    freeze_raw = canonical(freeze)

    cases = [case for case in build["jvm"]["cases"]
             if case[0].startswith("org.wonad.desktop.security.")]
    require(cases and len(cases) == len(set(map(tuple, cases))),
            "Fresh session-security JVM cases are absent or duplicated")
    security_tasks = {":session-security:testDebugUnitTest", ":session-security:lintDebug",
                      ":session-security:assembleDebug"}
    require(build.get("exit_code") == 0 and security_tasks <= set(build.get("tasks", [])),
            "Fresh session-security test/lint/assemble tasks were not successful")
    lint_path = output / "evidence/lint/session-security-lint-results-debug.xml"
    lint_root = ET.parse(lint_path).getroot()
    require(lint_root.tag == "issues" and
            not any(row.get("severity") in ("Fatal", "Error") for row in lint_root.findall("issue")),
            "Fresh session-security lint failed")
    lint_warnings = sum(row.get("severity") == "Warning" for row in lint_root.findall("issue"))
    unsigned = output / "evidence/built/security.apk"
    signed = output / "security.apk"
    require(apk_payload(unsigned) == apk_payload(signed),
            "Signing changed the freshly compiled security APK payload")
    require(artifact["package"] == "org.wonad.desktop.test" and artifact["test_only"] is True and
            artifact["privileged_manifest"] is False and artifact["shared_uid"] is False and
            artifact["certificate_der_sha256"] == WONAD_CERT and artifact["sha256"] == sha(signed),
            "Security harness artifact classification changed")
    receipt = {
        "schema": 2,
        "api": 3,
        "kind": "phase1_packet_security_compile_receipt_v1",
        "status": "compile_qualified",
        "runtime_qualified": False,
        "guests_started": False,
        "artifact": {
            "sha256": artifact["sha256"],
            "bytes": artifact["bytes"],
            "package": artifact["package"],
            "signer_sha256": artifact["certificate_der_sha256"],
            "test_only": True,
            "privileged": False,
            "shared_uid": False,
        },
        "unsigned_artifact": ref(unsigned),
        "source": {
            "path": SECURITY_SOURCE_FREEZE,
            "sha256": sha_bytes(freeze_raw),
            "bytes": len(freeze_raw),
            "compiled_files": len(selected),
        },
        "build": {
            "tasks": build["tasks"],
            "exit_code": 0,
            "tests": len(cases),
            "cases": cases,
            "lint_errors": 0,
            "lint_warnings": lint_warnings,
            "lint": ref(lint_path),
            "log": build["log"],
        },
        "signing": {
            "payload_preserved": True,
            "certificate_der_sha256": WONAD_CERT,
            "development_only": True,
        },
    }
    receipt_path = output / SECURITY_BUILD_RECEIPT
    if write:
        write_new(freeze_path, freeze, canonical_json=True)
        write_new(receipt_path, receipt, canonical_json=True)
    else:
        require(freeze_path.read_bytes() == freeze_raw and load(receipt_path) == receipt,
                "Dedicated security compile evidence changed")
    return {
        "receipt": ref(receipt_path),
        "source_freeze": ref(freeze_path),
        "canary_source_sha256": UPDATE_CANARY_SHA256,
        "compiled_files": len(selected),
        "tests": len(cases),
    }


def gradle_build(tools: Tools, source: Path, output: Path) -> dict:
    tools.exec("test", "!", "-e", REMOTE)
    tools.exec("mkdir", "-m", "700", REMOTE)
    try:
        remote_source = REMOTE + "/source"
        tools.cp_in(source, remote_source)
        before = inventory(source)
        command = ["env", "ANDROID_HOME=/opt/android-sdk", "JAVA_HOME=" + JAVA_HOME,
                   GRADLE, "--offline", "--no-daemon", "--rerun-tasks", "--no-parallel", "--max-workers=4",
                   "-Dorg.gradle.jvmargs=-Xmx3072m -XX:MaxMetaspaceSize=768m",
                   "-Pkotlin.compiler.execution.strategy=in-process", "-p", remote_source + "/android", *GRADLE_TASKS]
        with (output / "evidence/gradle.log").open("xb") as stream:
            require(tools.container is not None, "Disposable tools container was not started")
            run(["docker", "exec", tools.container, *command], timeout=3600, stdout=stream)
        require("BUILD SUCCESSFUL" in (output / "evidence/gradle.log").read_text(errors="replace"),
                "Gradle success footer absent")
        built = output / "evidence/built"
        built.mkdir(parents=True)
        for role, (relative, *_unused) in BUILT_APKS.items():
            tools.cp_out(remote_source + "/android/" + relative, built / (role + ".apk"))
        results = output / "evidence/jvm-results"
        lint = output / "evidence/lint"
        results.mkdir(); lint.mkdir()
        for module in ("fixture", "ime-fixture", "session-security", "native-task-reuse", "transition-fault", "native-prerequisites", "probe"):
            remote = remote_source + "/android/" + module + "/build/test-results"
            if module != "probe":
                tools.exec("test", "-d", remote)
                target = results / module; target.mkdir()
                tools.cp_out(remote + "/.", target)
            remote_lint = remote_source + "/android/" + module + "/build/reports"
            # Copy only the deterministic XML, never HTML caches.
            matches = tools.exec(CONTAINER_PYTHON, "-c",
                "import pathlib; print('\\n'.join(map(str,sorted(pathlib.Path(%r).glob('lint-results-*.xml')))))" % remote_lint).splitlines()
            for match in matches:
                tools.cp_out(match, lint / (module + "-" + Path(match).name))
        require(inventory(source) == before, "Host staged source changed during Gradle build")
        return {"tasks": list(GRADLE_TASKS), "jvm": junit_audit(results), "lint": lint_audit(lint),
                "log": ref(output / "evidence/gradle.log"),
                "exit_code": 0}
    finally:
        tools.clean_remote()


def export_fixture_cert(tools: Tools, output: Path):
    value = tools.exec(KEYTOOL, "-exportcert", "-rfc", "-alias", "androiddebugkey",
                       "-keystore", DEBUG_KEYSTORE, "-storepass", "android")
    write_new(output / "evidence/certificates/fixture.x509.pem", value)


class SigningSession:
    """Flat, exactly-owned temporary signing directory in the tools container."""
    def __init__(self, tools: Tools, output: Path):
        self.tools, self.output, self.remote, self.files = tools, output, None, []

    def __enter__(self):
        self.remote = self.tools.exec("mktemp", "-d", "/tmp/phase1-client-signing.XXXXXXXX").strip()
        require(re.fullmatch(r"/tmp/phase1-client-signing\.[A-Za-z0-9]{8}", self.remote), "Unsafe signing tmpdir")
        return self

    def put(self, source: Path, name: str):
        require(re.fullmatch(r"[A-Za-z0-9_.-]+", name), "Unsafe signing member")
        target = self.remote + "/" + name
        self.tools.cp_in(source, target); self.files.append(target)
        return target

    def get(self, name: str, target: Path):
        source = self.remote + "/" + name
        self.tools.cp_out(source, target)

    def command(self, *argv, env=None):
        return self.tools.exec(*argv, env=env)

    def __exit__(self, exception_type, exception, _traceback):
        if not self.remote:
            return False
        remote, self.remote = self.remote, None
        program = r'''import json,pathlib,re,sys
p=pathlib.Path(sys.argv[1])
assert p.parent==pathlib.Path("/tmp") and re.fullmatch(r"phase1-client-signing\.[A-Za-z0-9]{8}",p.name)
members=sorted(p.iterdir(),key=lambda value:value.name)
assert all(re.fullmatch(r"[A-Za-z0-9_.-]+",value.name) and value.is_file() and not value.is_symlink() for value in members)
names=[value.name for value in members]
for value in members: value.unlink()
p.rmdir()
print(json.dumps(names,separators=(",",":")))'''
        try:
            names = json.loads(self.tools.exec(CONTAINER_PYTHON, "-c", program, remote))
            require(isinstance(names, list) and all(
                isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", name) for name in names),
                "Malformed signing cleanup inventory")
        except Exception as cleanup_error:
            # Consuming the disposable container is the fail-closed cleanup.
            # Preserve a primary signing/build exception and attach cleanup
            # diagnostics instead of replacing it with a secondary failure.
            try:
                self.tools.close()
            except Exception as close_error:
                cleanup_error.add_note("Disposable container removal also failed: " + str(close_error))
            if exception is not None:
                exception.add_note("Signing-session cleanup failed; disposable container consumed: " +
                                   str(cleanup_error))
                return False
            raise
        return False


def sign_apk(tools: Tools, source: Path, target: Path, signer: str,
             signer_dir: Path, platform_root: Path):
    target.parent.mkdir(parents=True, exist_ok=True)
    stripped = target.parent / ("." + target.name + ".stripped")
    try:
        strip_signatures(source, stripped)
        with SigningSession(tools, target.parent) as session:
            session.put(stripped, "input.apk")
            session.command(ZIPALIGN, "-P", "16", "-f", "4", session.remote + "/input.apk", session.remote + "/aligned.apk")
            if signer == "fixture":
                session.command(APKSIGNER, "sign", "--ks", DEBUG_KEYSTORE, "--ks-key-alias", "androiddebugkey",
                    "--ks-pass", "env:WONAD_SIGNING_PASSWORD", "--key-pass", "env:WONAD_SIGNING_PASSWORD",
                    "--v1-signing-enabled", "true", "--v2-signing-enabled", "true", "--v3-signing-enabled", "true",
                    "--v4-signing-enabled", "false", "--out", session.remote + "/signed.apk", session.remote + "/aligned.apk",
                    env={"WONAD_SIGNING_PASSWORD": "android"})
            elif signer == "wonad":
                pem = session.put(signer_dir / "private.pem", "wonad-private.pem")
                cert = session.put(signer_dir / "certificate.x509.pem", "wonad-cert.pem")
                key = session.remote + "/wonad-private.pk8"
                session.command(OPENSSL, "pkcs8", "-topk8", "-nocrypt", "-in", pem,
                                "-outform", "DER", "-out", key)
                session.command(APKSIGNER, "sign", "--key", key, "--cert", cert,
                    "--v1-signing-enabled", "true", "--v2-signing-enabled", "true", "--v3-signing-enabled", "true",
                    "--v4-signing-enabled", "false", "--out", session.remote + "/signed.apk", session.remote + "/aligned.apk")
            elif signer == "platform":
                key = session.put(platform_root / "build/make/target/product/security/platform.pk8", "platform.pk8")
                cert = session.put(platform_root / "build/make/target/product/security/platform.x509.pem", "platform.x509.pem")
                session.command(APKSIGNER, "sign", "--key", key, "--cert", cert,
                    "--v1-signing-enabled", "true", "--v2-signing-enabled", "true", "--v3-signing-enabled", "true",
                    "--v4-signing-enabled", "false", "--out", session.remote + "/signed.apk", session.remote + "/aligned.apk")
            else:
                raise PacketError("Unknown signer role")
            session.command(ZIPALIGN, "-c", "-P", "16", "4", session.remote + "/signed.apk")
            session.get("signed.apk", target)
    finally:
        if stripped.exists():
            stripped.unlink()
    require(apk_payload(source) == apk_payload(target), "Signing changed non-signature APK payload")


def inspect_apk(tools: Tools, path: Path) -> dict:
    with SigningSession(tools, path.parent) as session:
        remote = session.put(path, "inspect.apk")
        verify = session.command(APKSIGNER, "verify", "--verbose", "--print-certs", remote)
        badging = session.command(AAPT2, "dump", "badging", remote)
        manifest = session.command(AAPT2, "dump", "xmltree", "--file", "AndroidManifest.xml", remote)
        session.command(ZIPALIGN, "-c", "-P", "16", "4", remote)
    return {**ref(path), **parse_signer(verify), **apk_metadata(badging, manifest),
            "payload_sha256": sha_bytes(canonical(apk_payload(path)))}


def conformance_input(successor: Path, tools: Tools, target: Path,
                      signer: Path, platform: Path, *, compile_receipt: dict) -> Path:
    """Sign this successor's fresh conformance output, never a historical APK.

    The caller authenticates the complete successor compile receipt first.
    Recheck the selected unsigned artifact here and after signing to keep its
    freshly compiled runtime/source freeze bound through the signing operation.
    """
    unsigned = successor / "conformance-unsigned.apk"
    expected = compile_receipt.get("conformance_artifact", {})
    require(isinstance(expected, dict) and
            expected.get("path") == str(unsigned) and
            {key: expected.get(key) for key in ("sha256", "bytes")} == ref(unsigned) and
            expected.get("package") == "org.wonad.desktop" and
            expected.get("version_code") == 1 and
            expected.get("version_name") == "3.0-phase1-conformance" and
            expected.get("signed") is False and expected.get("native_code") is False and
            all(expected.get(key) is False for key in ("privileged", "test_only", "shared_uid")),
            "Fresh conformance input differs from the authenticated successor compile artifact")
    before = ref(unsigned)
    sign_apk(tools, unsigned, target, "wonad", signer, platform)
    info = inspect_apk(tools, target)
    require(ref(unsigned) == before and info["package"] == "org.wonad.desktop" and
            info["certificate_der_sha256"] == WONAD_CERT and info["version_code"] == 1 and
            info["version_name"] == "3.0-phase1-conformance" and
            apk_payload(target) == apk_payload(unsigned),
            "Fresh signed conformance payload, version, or development signer changed")
    return target


def wrong_signer_derivatives(tools: Tools, output: Path, signer_dir: Path) -> dict:
    directory = output / "wrong-signer"; directory.mkdir()
    password = secrets.token_hex(32)
    with SigningSession(tools, directory) as session:
        keystore = session.remote + "/wrong.p12"
        session.command(KEYTOOL, "-genkeypair", "-alias", "wonad-phase1-isolated-wrong",
            "-keystore", keystore, "-storetype", "PKCS12", "-keyalg", "RSA", "-keysize", "2048", "-validity", "2",
            "-dname", "CN=Wonad Phase1 Isolated Wrong Signer Development Only",
            "-storepass:env", "WONAD_WRONG_PASSWORD", "-keypass:env", "WONAD_WRONG_PASSWORD",
            env={"WONAD_WRONG_PASSWORD": password})
        certificate = session.command(KEYTOOL, "-exportcert", "-rfc", "-alias", "wonad-phase1-isolated-wrong",
            "-keystore", keystore, "-storepass:env", "WONAD_WRONG_PASSWORD", env={"WONAD_WRONG_PASSWORD": password})
        write_new(output / "evidence/certificates/wrong.x509.pem", certificate)
        for role, source in (("wonad", output / "wonad.apk"), ("security", output / "security.apk")):
            stripped = directory / ("." + role + ".stripped")
            strip_signatures(source, stripped)
            session.put(stripped, role + "-input.apk")
            session.command(ZIPALIGN, "-P", "16", "-f", "4", session.remote + "/" + role + "-input.apk",
                            session.remote + "/" + role + "-aligned.apk")
            session.command(APKSIGNER, "sign", "--ks", keystore, "--ks-key-alias", "wonad-phase1-isolated-wrong",
                "--ks-pass", "env:WONAD_WRONG_PASSWORD", "--key-pass", "env:WONAD_WRONG_PASSWORD",
                "--v1-signing-enabled", "true", "--v2-signing-enabled", "true", "--v3-signing-enabled", "true",
                "--v4-signing-enabled", "false", "--out", session.remote + "/wrong-" + role + ".apk",
                session.remote + "/" + role + "-aligned.apk", env={"WONAD_WRONG_PASSWORD": password})
            session.get("wrong-" + role + ".apk", directory / ("wrong-" + role + ".apk"))
            stripped.unlink()
    wrong = pem_der_hash(output / "evidence/certificates/wrong.x509.pem")
    require(wrong not in (WONAD_CERT, FIXTURE_CERT), "Wrong-signer identity is not isolated")
    return {"certificate_der_sha256": wrong, "private_key_removed": True,
            "wonad_payload_unchanged": apk_payload(output / "wonad.apk") == apk_payload(directory / "wrong-wonad.apk"),
            "security_payload_unchanged": apk_payload(output / "security.apk") == apk_payload(directory / "wrong-security.apk")}


def version_prepare_command(tools: Tools, apk: Path, keystore: str, target: Path) -> list[str]:
    """Bind the legacy version-only preparer to this exact disposable container.

    The preparation process runs on the host because it also freezes host-side
    evidence, but every SDK/JDK command must execute in the already-authenticated
    immutable Tools epoch.  Passing all three identity fields prevents the child
    process from falling back to the historical named mutable tools container.
    """
    require(tools.container is not None and CONTAINER_ID.fullmatch(tools.container),
            "Disposable tools container was not started")
    return [sys.executable, str(ANDROID / "tools/native_apk_update_smoke.py"), "prepare",
            "--apk", str(apk), "--keystore", keystore, "--output", str(target),
            "--tools-container", tools.container, "--tools-image", tools.image,
            "--tools-label-token", tools.token]


def version_update(tools: Tools, output: Path, signer_dir: Path) -> dict:
    target = output / "version-update"
    password = "android"  # Only a temporary wrapper around the existing development key.
    with SigningSession(tools, target) as session:
        key = session.put(signer_dir / "private.pem", "existing.pem")
        cert = session.put(signer_dir / "certificate.x509.pem", "existing.x509.pem")
        p12 = session.remote + "/existing.p12"
        session.command(OPENSSL, "pkcs12", "-export", "-in", cert, "-inkey", key, "-name", "androiddebugkey",
                        "-out", p12, "-passout", "env:WONAD_P12_PASSWORD", env={"WONAD_P12_PASSWORD": password})
        command = version_prepare_command(tools, output / "wonad.apk", p12, target)
        run(command, timeout=600)
    sys.path.insert(0, str(ANDROID / "tools"))
    from native_apk_update_acceptance import audit_preparation
    receipt = load(target / "preparation-receipt.json")
    pair = audit_preparation(receipt, lambda name: (target / name).read_bytes())
    require(pair["original"]["signer"] == pair["candidate"]["signer"] == WONAD_CERT and
            pair["candidate"]["version"] == pair["original"]["version"] + 1,
            "Version-only derivative signer/version mismatch")
    return {"receipt": ref(target / "preparation-receipt.json"), "original": pair["original"], "candidate": pair["candidate"],
            "temporary_wrapper_keystore_removed": True}


def _conformance_update_member(path: Path, metadata: dict, archive: dict) -> dict:
    return {
        "file": ref(path),
        "package": metadata["package"],
        "version_code": metadata["version_code"],
        "version_name": metadata["version_name"],
        "certificate_der_sha256": metadata["certificate_der_sha256"],
        "normalized_manifest_sha256": archive["manifest"]["normalized_sha256"],
        "non_manifest_payload_sha256": sha_bytes(canonical(archive["payload"])),
    }


def validate_conformance_update_claim(preparation: dict, record: dict) -> dict:
    """Validate the bounded no-JNI conformance update preparation schema.

    This check deliberately does not invoke SDK tools.  The packet verifier
    separately reconstructs the signed binary-AXML pair, while this function
    gives the candidate builder a strict, relocation-safe schema check.
    """
    expected_preparation = {
        "schema", "api", "kind", "status", "development_only",
        "runtime_qualified", "guests_started", "tools", "source",
        "artifacts", "version_only", "private_data_canary", "commands", "files",
    }
    require(isinstance(preparation, dict) and set(preparation) == expected_preparation and
            type(preparation["schema"]) is int and preparation["schema"] == 1 and
            type(preparation["api"]) is int and preparation["api"] == 3 and
            preparation["kind"] == "phase1_conformance_version_only_preparation_v1" and
            preparation["status"] == "prepared_not_runtime_qualified" and
            preparation["development_only"] is True and
            preparation["runtime_qualified"] is False and
            preparation["guests_started"] is False,
            "Malformed conformance version-only preparation receipt")

    def file_record(value, label):
        require(isinstance(value, dict) and set(value) == {"sha256", "bytes"} and
                SHA256.fullmatch(str(value["sha256"])) is not None and
                type(value["bytes"]) is int and value["bytes"] > 0,
                "Malformed conformance update file reference: " + label)
        return value

    tools = preparation["tools"]
    require(isinstance(tools, dict) and set(tools) == {
                "container_id", "image_id", "label_token"} and
            CONTAINER_ID.fullmatch(str(tools["container_id"])) is not None and
            IMAGE_ID.fullmatch(str(tools["image_id"])) is not None and
            re.fullmatch(r"[0-9a-f]{32}", str(tools["label_token"])) is not None,
            "Conformance update lacks its exact disposable tools epoch")
    source = file_record(preparation["source"], "source")
    files = preparation["files"]
    require(isinstance(files, dict) and set(files) == set(CONFORMANCE_UPDATE_FILES.values()),
            "Conformance update preparation file set changed")
    for name, value in files.items():
        file_record(value, name)

    member_keys = {"file", "package", "version_code", "version_name",
        "certificate_der_sha256", "normalized_manifest_sha256",
        "non_manifest_payload_sha256"}
    artifacts = preparation["artifacts"]
    require(isinstance(artifacts, dict) and set(artifacts) == {"v1", "v2"},
            "Conformance update artifact role set changed")
    for role in ("v1", "v2"):
        value = artifacts[role]
        require(isinstance(value, dict) and set(value) == member_keys,
                "Malformed conformance update artifact: " + role)
        file_record(value["file"], role)
        require(value["package"] == "org.wonad.desktop" and
                type(value["version_code"]) is int and
                isinstance(value["version_name"], str) and value["version_name"] and
                value["certificate_der_sha256"] == WONAD_CERT and
                SHA256.fullmatch(str(value["normalized_manifest_sha256"])) is not None and
                SHA256.fullmatch(str(value["non_manifest_payload_sha256"])) is not None,
                "Invalid conformance update APK identity: " + role)
    v1, v2 = artifacts["v1"], artifacts["v2"]
    require(v1["version_code"] == 1 and v2["version_code"] == 2 and
            v1["version_name"] == v2["version_name"] and
            v1["certificate_der_sha256"] == v2["certificate_der_sha256"] and
            v1["normalized_manifest_sha256"] == v2["normalized_manifest_sha256"] and
            v1["non_manifest_payload_sha256"] == v2["non_manifest_payload_sha256"] and
            source == v1["file"] and
            files[CONFORMANCE_UPDATE_FILES["original"]] == v1["file"] and
            files[CONFORMANCE_UPDATE_FILES["candidate"]] == v2["file"],
            "Conformance update is not the exact v1/v2 version-only pair")
    version_only = {
        "package": "org.wonad.desktop",
        "version_name": v1["version_name"],
        "certificate_der_sha256": WONAD_CERT,
        "original_version_code": 1,
        "candidate_version_code": 2,
        "normalized_manifest_sha256": v1["normalized_manifest_sha256"],
        "non_manifest_payload_sha256": v1["non_manifest_payload_sha256"],
        "permissions_binding": "exact_binary_manifest_equality_except_root_version_code",
    }
    require(preparation["version_only"] == version_only,
            "Conformance version-only manifest/payload/permission binding changed")
    canary = {"runner": UPDATE_CANARY_RUNNER,
              "source_sha256": UPDATE_CANARY_SHA256}
    require(preparation["private_data_canary"] == canary,
            "Conformance update private-data canary binding changed")

    commands = preparation["commands"]
    require(isinstance(commands, list) and len(commands) == 4 and all(
        isinstance(row, dict) and set(row) == {"argv", "stdout", "stdout_sha256", "stdout_bytes"} and
        isinstance(row["argv"], list) and all(isinstance(item, str) for item in row["argv"]) and
        isinstance(row["stdout"], str) and len(row["stdout"].encode()) <= 65536 and
        SHA256.fullmatch(str(row["stdout_sha256"])) is not None and
        type(row["stdout_bytes"]) is int and row["stdout_bytes"] == len(row["stdout"].encode()) and
        row["stdout_sha256"] == sha_bytes(row["stdout"].encode())
        for row in commands), "Malformed conformance update command evidence")
    remote_values = [item for row in commands for item in row["argv"]
                     if item.startswith("/tmp/phase1-client-signing.")]
    roots = {str(Path(item).parent) for item in remote_values}
    require(len(roots) == 1, "Conformance update commands used multiple signing roots")
    remote = next(iter(roots)) if roots else ""
    require(re.fullmatch(r"/tmp/phase1-client-signing\.[A-Za-z0-9]{8}", remote) is not None,
            "Conformance update command signing root changed")
    expected_commands = [
        [OPENSSL, "pkcs8", "-topk8", "-nocrypt", "-in", remote + "/existing.pem",
         "-outform", "DER", "-out", remote + "/existing.pk8"],
        [ZIPALIGN, "-P", "16", "-f", "4", remote + "/unsigned.apk",
         remote + "/aligned.apk"],
        [APKSIGNER, "sign", "--key", remote + "/existing.pk8", "--cert",
         remote + "/existing.x509.pem", "--v1-signing-enabled", "true",
         "--v2-signing-enabled", "true", "--v3-signing-enabled", "true",
         "--v4-signing-enabled", "false", "--out", remote + "/candidate.apk",
         remote + "/aligned.apk"],
        [ZIPALIGN, "-c", "-P", "16", "4", remote + "/candidate.apk"],
    ]
    require([row["argv"] for row in commands] == expected_commands and not any(
        "keytool" in item.lower() or item in ("--ks", "--ks-pass", "--key-pass") or
        "password" in item.lower() for row in commands for item in row["argv"]),
        "Conformance update was not signed by the exact existing-key command sequence")

    expected_record = {
        "receipt": record.get("receipt") if isinstance(record, dict) else None,
        "v1": v1,
        "v2": v2,
        "version_only": version_only,
        "private_data_canary": canary,
        "temporary_private_key_removed": True,
    }
    require(isinstance(record, dict) and set(record) == set(expected_record) and
            file_record(record["receipt"], "preparation receipt") == record["receipt"] and
            record == expected_record,
            "Packet conformance update summary differs from its preparation receipt")
    return record


def audit_conformance_version_update(output: Path, record: dict) -> dict:
    """Reconstruct and audit the signed no-JNI conformance v1/v2 pair."""
    target = output / CONFORMANCE_UPDATE_DIRECTORY
    receipt_path = target / CONFORMANCE_UPDATE_RECEIPT
    preparation = load(receipt_path)
    validate_conformance_update_claim(preparation, record)
    require(ref(receipt_path) == record["receipt"],
            "Conformance update preparation receipt bytes changed")
    actual = inventory(target)
    require(set(actual) == set(preparation["files"]) | {CONFORMANCE_UPDATE_RECEIPT} and
            all(actual[name] == value for name, value in preparation["files"].items()) and
            actual[CONFORMANCE_UPDATE_RECEIPT] == record["receipt"],
            "Conformance update preparation directory changed")
    original = target / CONFORMANCE_UPDATE_FILES["original"]
    candidate = target / CONFORMANCE_UPDATE_FILES["candidate"]
    unsigned = target / CONFORMANCE_UPDATE_FILES["unsigned"]
    require(ref(output / "conformance.apk") == ref(original),
            "Conformance update v1 is not the packet conformance APK")
    sys.path.insert(0, str(ANDROID / "tools"))
    from native_apk_update_acceptance import apk_pair, manifest_version
    from native_apk_update_smoke import unsigned_version_copy
    pair = apk_pair(original.read_bytes(), candidate.read_bytes())
    with zipfile.ZipFile(original) as archive:
        original_version = manifest_version(archive.read("AndroidManifest.xml"))["version"]
    require(unsigned.read_bytes() == unsigned_version_copy(original.read_bytes(), original_version + 1),
            "Retained unsigned conformance update derivative changed")
    for role, pair_role in (("v1", "original"), ("v2", "candidate")):
        value, archive = preparation["artifacts"][role], pair[pair_role]
        require(value["file"] == {"sha256": archive["sha256"], "bytes": archive["bytes"]} and
                value["version_code"] == archive["version"] and
                value["certificate_der_sha256"] == archive["signer"] and
                value["normalized_manifest_sha256"] == archive["manifest"]["normalized_sha256"] and
                value["non_manifest_payload_sha256"] == sha_bytes(canonical(archive["payload"])),
                "Conformance update signed binary inventory changed: " + role)
    require(pair["original"]["version"] == 1 and pair["candidate"]["version"] == 2 and
            pair["original"]["signer"] == pair["candidate"]["signer"] == WONAD_CERT,
            "Conformance update signed pair version/signer changed")
    return record


def conformance_version_update(tools: Tools, output: Path, signer_dir: Path) -> dict:
    """Prepare the no-JNI conformance v1/v2 pair with the existing dev key."""
    require(tools.container is not None and CONTAINER_ID.fullmatch(tools.container),
            "Disposable tools container was not started")
    target = output / CONFORMANCE_UPDATE_DIRECTORY
    target.mkdir(mode=0o700)
    original = target / CONFORMANCE_UPDATE_FILES["original"]
    candidate = target / CONFORMANCE_UPDATE_FILES["candidate"]
    unsigned = target / CONFORMANCE_UPDATE_FILES["unsigned"]
    copy_file(output / "conformance.apk", original)
    sys.path.insert(0, str(ANDROID / "tools"))
    from native_apk_update_acceptance import apk_pair, manifest_version
    from native_apk_update_smoke import unsigned_version_copy
    with zipfile.ZipFile(original) as archive:
        original_version = manifest_version(archive.read("AndroidManifest.xml"))["version"]
    require(original_version == 1, "Conformance update source is not version 1")
    write_new(unsigned, unsigned_version_copy(original.read_bytes(), 2))

    commands = []
    with SigningSession(tools, target) as session:
        source = session.put(unsigned, "unsigned.apk")
        pem = session.put(signer_dir / "private.pem", "existing.pem")
        cert = session.put(signer_dir / "certificate.x509.pem", "existing.x509.pem")
        key = session.remote + "/existing.pk8"
        aligned = session.remote + "/aligned.apk"
        signed = session.remote + "/candidate.apk"
        argv_rows = [
            [OPENSSL, "pkcs8", "-topk8", "-nocrypt", "-in", pem,
             "-outform", "DER", "-out", key],
            [ZIPALIGN, "-P", "16", "-f", "4", source, aligned],
            [APKSIGNER, "sign", "--key", key, "--cert", cert,
             "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
             "--v3-signing-enabled", "true", "--v4-signing-enabled", "false",
             "--out", signed, aligned],
            [ZIPALIGN, "-c", "-P", "16", "4", signed],
        ]
        for argv in argv_rows:
            stdout = session.command(*argv)
            raw = stdout.encode()
            commands.append({"argv": argv, "stdout": stdout, "stdout_sha256": sha_bytes(raw),
                             "stdout_bytes": len(raw)})
        session.get("candidate.apk", candidate)

    pair = apk_pair(original.read_bytes(), candidate.read_bytes())
    metadata = {"v1": inspect_apk(tools, original),
                "v2": inspect_apk(tools, candidate)}
    metadata_keys = {"package", "version_name", "certificate_der_sha256", "debuggable",
                     "test_only", "instrumentation_targets", "shared_uid", "privileged_manifest"}
    require(all(metadata["v1"][key] == metadata["v2"][key] for key in metadata_keys) and
            metadata["v1"]["package"] == "org.wonad.desktop" and
            metadata["v1"]["certificate_der_sha256"] == WONAD_CERT and
            metadata["v1"]["version_code"] == 1 and metadata["v2"]["version_code"] == 2 and
            metadata["v1"]["debuggable"] is False and metadata["v1"]["test_only"] is False and
            metadata["v1"]["instrumentation_targets"] == ["org.wonad.desktop"] and
            metadata["v1"]["shared_uid"] is False and metadata["v1"]["privileged_manifest"] is False,
            "Conformance v1/v2 verified package/manifest identity changed")
    artifacts = {
        "v1": _conformance_update_member(original, metadata["v1"], pair["original"]),
        "v2": _conformance_update_member(candidate, metadata["v2"], pair["candidate"]),
    }
    version_only = {
        "package": "org.wonad.desktop",
        "version_name": artifacts["v1"]["version_name"],
        "certificate_der_sha256": WONAD_CERT,
        "original_version_code": 1,
        "candidate_version_code": 2,
        "normalized_manifest_sha256": artifacts["v1"]["normalized_manifest_sha256"],
        "non_manifest_payload_sha256": artifacts["v1"]["non_manifest_payload_sha256"],
        "permissions_binding": "exact_binary_manifest_equality_except_root_version_code",
    }
    canary = {"runner": UPDATE_CANARY_RUNNER,
              "source_sha256": UPDATE_CANARY_SHA256}
    preparation = {
        "schema": 1,
        "api": 3,
        "kind": "phase1_conformance_version_only_preparation_v1",
        "status": "prepared_not_runtime_qualified",
        "development_only": True,
        "runtime_qualified": False,
        "guests_started": False,
        "tools": {"container_id": tools.container, "image_id": tools.image,
                  "label_token": tools.token},
        "source": ref(output / "conformance.apk"),
        "artifacts": artifacts,
        "version_only": version_only,
        "private_data_canary": canary,
        "commands": commands,
        "files": {name: ref(target / name) for name in CONFORMANCE_UPDATE_FILES.values()},
    }
    receipt_path = target / CONFORMANCE_UPDATE_RECEIPT
    write_new(receipt_path, preparation, canonical_json=True)
    record = {
        "receipt": ref(receipt_path),
        "v1": artifacts["v1"],
        "v2": artifacts["v2"],
        "version_only": version_only,
        "private_data_canary": canary,
        "temporary_private_key_removed": True,
    }
    validate_conformance_update_claim(preparation, record)
    return audit_conformance_version_update(output, record)


def validate_artifact_contract(roles: dict, expected: dict):
    require(set(roles) == set(FINAL_FILES) == set(expected), "APK role set changed")
    test_only = {"security", "reuse", "fault", "prerequisite", "wrong_security"}
    targets = {
        "conformance": ["org.wonad.desktop"],
        "security": ["org.wonad.desktop"],
        "reuse": ["org.wonad.desktop", "org.wonad.desktop.taskreuse"],
        "fault": ["com.android.systemui"],
        "prerequisite": ["org.wonad.desktop"],
        "wrong_security": ["org.wonad.desktop"],
    }
    for role, (package, signer) in expected.items():
        value = roles[role]
        require(value["package"] == package and value["certificate_der_sha256"] == signer,
                "Final APK package/signer mismatch: " + role)
        require(value["test_only"] is (role in test_only), "APK testOnly classification changed: " + role)
        require(value["instrumentation_targets"] == targets.get(role, []),
                "APK instrumentation targets changed: " + role)
        require(not value["shared_uid"] and not value["privileged_manifest"],
                "Final APK gained shared/privileged identity: " + role)
        require(value["signers"] == 1 and value["schemes"].get("3") is True,
                "Final APK lacks exactly one verified v3 signer: " + role)
    for role in ("fixture", "ime", "probe"):
        require(roles[role]["certificate_der_sha256"] != WONAD_CERT,
                "Ordinary fixture shares Wonad signer")


def collect_receipt(output: Path, successor: Path, successor_receipt: dict, sources: dict,
                    tools: Tools, tools_record: dict, native: dict, build: dict, platform_cert: Path,
                    wrong: dict, update: dict, conformance_update: dict,
                    tool_source_hash: str) -> dict:
    roles = {}
    for role, name in FINAL_FILES.items():
        path = output / name
        roles[role] = inspect_apk(tools, path)
    platform_digest = pem_der_hash(output / "evidence/certificates/platform.x509.pem")
    expected = {
        "wonad": ("org.wonad.desktop", WONAD_CERT), "conformance": ("org.wonad.desktop", WONAD_CERT),
        "fixture": ("org.wonad.fixture", FIXTURE_CERT), "ime": ("org.wonad.imefixture", FIXTURE_CERT),
        "security": ("org.wonad.desktop.test", WONAD_CERT), "reuse": ("org.wonad.desktop.taskreuse", WONAD_CERT),
        "prerequisite": ("org.wonad.desktop.prerequisites", WONAD_CERT),
        "probe": ("org.wonad.probe", FIXTURE_CERT),
        "fault": ("org.wonad.desktop.transitionfault", platform_digest),
        "wrong_wonad": ("org.wonad.desktop", wrong["certificate_der_sha256"]),
        "wrong_security": ("org.wonad.desktop.test", wrong["certificate_der_sha256"]),
    }
    validate_artifact_contract(roles, expected)
    retained = output / "evidence/compile-input"
    require(apk_payload(retained / "wonad.apk") == apk_payload(output / "wonad.apk") and
            apk_payload(retained / "conformance-unsigned.apk") == apk_payload(output / "conformance.apk"),
            "Wonad/conformance payload changed during development signing")
    require(wrong["wonad_payload_unchanged"] and wrong["security_payload_unchanged"],
            "Wrong-signer derivative changed a payload")
    security_compile = security_compile_evidence(output, sources, build, roles["security"], write=True)
    receipt = {
        "schema": 2, "kind": KIND, "status": STATUS, "development_only": True,
        "production_identity": False, "runtime_qualified": False, "guests_started": False,
        "source_matched_image_pending": True,
        "byte_for_byte_reproducible": False,
        "determinism_scope": ("canonical content-addressed receipt for this one build; ephemeral isolated wrong-signer "
                              "identity and test-result timestamps intentionally vary across rebuilds"),
        "successor": {"directory": successor.name, "build_receipt": ref(successor / "build-receipt.json"),
                      "source_freeze": ref(successor / "source-freeze.json"),
                      "plan": ref(successor / "plan.json"),
                      "input_apk": ref(successor / "wonad.apk"),
                      "input_conformance": ref(successor / "conformance-unsigned.apk"),
                      "retained_inputs": {
                          name: ref(retained / name) for name in
                          ("build-receipt.json", "source-freeze.json", "plan.json", "wonad.apk", "conformance-unsigned.apk")
                      },
                      "version_code": successor_receipt["artifact"]["version_code"]},
        "source_files": sources, "source_tree": inventory(output / "source"),
        "tools": tools_record, "native_builds": native, "gradle_build": build,
        "signers": {
            "wonad_emulator_development": {"certificate_der_sha256": WONAD_CERT, "production": False,
                "public_certificate": ref(output / "evidence/certificates/wonad.x509.pem")},
            "ordinary_fixture_development": {"certificate_der_sha256": FIXTURE_CERT, "production": False,
                "public_certificate": ref(output / "evidence/certificates/fixture.x509.pem")},
            "systemui_platform_development": {"certificate_der_sha256": platform_digest, "production": False,
                "public_certificate": ref(output / "evidence/certificates/platform.x509.pem"),
                "compatibility": "must_match_built_SystemUI_before_runtime"},
            "isolated_wrong_development": {"certificate_der_sha256": wrong["certificate_der_sha256"],
                "production": False, "private_key_removed": True,
                "public_certificate": ref(output / "evidence/certificates/wrong.x509.pem")},
        },
        "classification": {
            "ordinary_separately_signed": ["fixture", "ime", "probe"],
            "same_wonad_signer_testonly_instrumentation": ["security", "reuse", "prerequisite"],
            "platform_signed_test_harness": ["fault"],
            "mutually_exclusive_package": ["wonad", "conformance"],
            "same_signer_harnesses_are_not_ordinary_launcher_fixtures": True,
        },
        "artifacts": roles, "wrong_signer": wrong, "version_update": update,
        "conformance_version_update": conformance_update,
        "security_compile": security_compile,
        "known_runtime_integration_gaps": [
            "fault signer must be compared with SystemUI from the finished source-matched image",
            "legacy wrong-signer preparation auditor pins the pre-resigning compile signer and cannot admit this wrapped target",
        ],
        "builder": {"tool": "android/tools/phase1_emulator_client_packet.py", "sha256": tool_source_hash},
    }
    # Seal every retained file except the receipt which would be recursive.
    receipt["files"] = inventory(output)
    receipt["files"].pop("receipt.json", None)
    return receipt


def validate_receipt(output: Path, receipt: dict, expected_hash: str, *, live_tools=True):
    require(SHA256.fullmatch(expected_hash) is not None, "An out-of-band receipt SHA-256 is mandatory")
    receipt_path = output / "receipt.json"
    require(sha(receipt_path) == expected_hash, "Receipt differs from the authenticated out-of-band SHA-256")
    require(receipt == load(receipt_path), "Receipt changed while verifying")
    legacy_fields = {"schema", "kind", "status", "development_only", "production_identity", "runtime_qualified",
        "guests_started", "source_matched_image_pending", "byte_for_byte_reproducible", "determinism_scope",
        "successor", "source_files", "source_tree", "tools",
        "native_builds", "gradle_build", "signers", "classification", "artifacts", "wrong_signer", "version_update",
        "security_compile", "known_runtime_integration_gaps", "builder", "files"}
    current_fields = legacy_fields | {"conformance_version_update"}
    require(set(receipt) in (legacy_fields, current_fields),
            "Unknown/missing packet receipt field")
    require(receipt["schema"] == 2 and receipt["kind"] == KIND and receipt["status"] == STATUS and
            receipt["development_only"] is True and receipt["production_identity"] is False and
            receipt["runtime_qualified"] is False and receipt["guests_started"] is False and
            receipt["source_matched_image_pending"] is True and receipt["byte_for_byte_reproducible"] is False and
            receipt["determinism_scope"] == ("canonical content-addressed receipt for this one build; ephemeral isolated wrong-signer "
                "identity and test-result timestamps intentionally vary across rebuilds"),
            "Packet qualification disclosure changed")
    require(receipt["known_runtime_integration_gaps"] == [
                "fault signer must be compared with SystemUI from the finished source-matched image",
                "legacy wrong-signer preparation auditor pins the pre-resigning compile signer and cannot admit this wrapped target",
            ], "Packet runtime-gap disclosure changed or retains the repaired update-canary gap")
    actual = inventory(output); actual.pop("receipt.json", None)
    require(actual == receipt["files"], "Packet file set/bytes changed or an unsealed file was added")
    require(inventory(output / "source") == receipt["source_tree"], "Packet source tree changed")
    require(sha(Path(__file__)) == receipt["builder"]["sha256"], "Packet verifier/builder source changed")
    require(set(receipt) == current_fields,
            "Historical packet requires its exact frozen packet verifier; current builder requires conformance update evidence")
    verify_tools_image_evidence(output, receipt["tools"])
    for name, record in receipt["source_files"].items():
        require(safe_relative(name) and receipt["source_tree"].get(name) ==
                {key: record[key] for key in ("sha256", "bytes")},
                "Staged source origin/inventory mismatch: " + name)
    native_source_files = {name for role in ("broker", "input", "probe")
                           for name in receipt["native_builds"][role]["source_files"]}
    require(set(receipt["source_tree"]) - set(receipt["source_files"]) == native_source_files and
            not (set(receipt["source_files"]) & native_source_files),
            "Staged source tree has an unprovenanced or overlapping file")
    signers = receipt["signers"]
    require(signers["wonad_emulator_development"]["certificate_der_sha256"] == WONAD_CERT and
            signers["ordinary_fixture_development"]["certificate_der_sha256"] == FIXTURE_CERT and
            len({value["certificate_der_sha256"] for value in signers.values()}) == 4,
            "Signer classes overlap or changed")
    certificate_paths = {
        "wonad_emulator_development": "wonad.x509.pem",
        "ordinary_fixture_development": "fixture.x509.pem",
        "systemui_platform_development": "platform.x509.pem",
        "isolated_wrong_development": "wrong.x509.pem",
    }
    for role, name in certificate_paths.items():
        certificate = output / "evidence/certificates" / name
        require(ref(certificate) == signers[role]["public_certificate"] and
                pem_der_hash(certificate) == signers[role]["certificate_der_sha256"],
                "Retained public certificate changed or mismatches signer class: " + role)
    expected = {
        "wonad": ("org.wonad.desktop", WONAD_CERT), "conformance": ("org.wonad.desktop", WONAD_CERT),
        "fixture": ("org.wonad.fixture", FIXTURE_CERT), "ime": ("org.wonad.imefixture", FIXTURE_CERT),
        "security": ("org.wonad.desktop.test", WONAD_CERT),
        "reuse": ("org.wonad.desktop.taskreuse", WONAD_CERT),
        "prerequisite": ("org.wonad.desktop.prerequisites", WONAD_CERT),
        "probe": ("org.wonad.probe", FIXTURE_CERT),
        "fault": ("org.wonad.desktop.transitionfault",
                  signers["systemui_platform_development"]["certificate_der_sha256"]),
        "wrong_wonad": ("org.wonad.desktop",
                        signers["isolated_wrong_development"]["certificate_der_sha256"]),
        "wrong_security": ("org.wonad.desktop.test",
                           signers["isolated_wrong_development"]["certificate_der_sha256"]),
    }
    validate_artifact_contract(receipt["artifacts"], expected)
    require(security_compile_evidence(output, receipt["source_files"], receipt["gradle_build"],
                receipt["artifacts"]["security"], write=False) == receipt["security_compile"],
            "Dedicated security compile receipt/source freeze differs")
    require(receipt["classification"] == {
        "ordinary_separately_signed": ["fixture", "ime", "probe"],
        "same_wonad_signer_testonly_instrumentation": ["security", "reuse", "prerequisite"],
        "platform_signed_test_harness": ["fault"],
        "mutually_exclusive_package": ["wonad", "conformance"],
        "same_signer_harnesses_are_not_ordinary_launcher_fixtures": True,
    }, "APK signer/classification disclosure changed")
    retained = output / "evidence/compile-input"
    retained_names = {
        "build-receipt.json": "build_receipt", "source-freeze.json": "source_freeze",
        "plan.json": "plan", "wonad.apk": "input_apk",
        "conformance-unsigned.apk": "input_conformance",
    }
    require(set(receipt["successor"]["retained_inputs"]) == set(retained_names),
            "Retained successor input set changed")
    for name, field in retained_names.items():
        observed = ref(retained / name)
        require(observed == receipt["successor"]["retained_inputs"][name] == receipt["successor"][field],
                "Retained successor input differs from selected compile packet: " + name)
    for role in ("broker", "input", "probe"):
        built = receipt["native_builds"][role]
        require(ref(output / "evidence/native" / ("libwonad_" +
                {"broker": "broker_jni.so", "input": "input_jni.so", "probe": "probe.so"}[role])) ==
                {key: built[key] for key in ("sha256", "bytes")}, "Native evidence changed: " + role)
        for name in built["source_files"]:
            require(ref(output / "source" / name) == {key: built[key] for key in ("sha256", "bytes")},
                    "Staged native library differs from fresh output: " + role)
    retained_plan = load(retained / "plan.json")
    require(receipt["native_builds"]["cross_image"] == retained_plan["cross_image"] and
            receipt["native_builds"]["cross_tools_sha256"] == sha_bytes(canonical(retained_plan["cross_tools"])),
            "Native tool/image binding differs from retained compile plan")
    pinned_names = {
        "ghc-9.12.2/_build/stage0/bin/x86_64-unknown-linux-android-ghc",
        "android-ndk-r30/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android35-clang",
        "android-ndk-r30/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf",
        "android-ndk-r30/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/jni.h",
    }
    require(set(receipt["native_builds"]["pinned_tool_files"]) == pinned_names and
            receipt["native_builds"]["pinned_tool_files"] == {
                name: {key: retained_plan["cross_tools"]["files"][name][key] for key in ("sha256", "bytes")}
                for name in pinned_names
            }, "Native tool-file bindings differ from retained compile plan")
    for name, record in receipt["native_builds"]["logs"].items():
        path = output / "evidence/native" / name
        require(safe_relative(name) and ref(path) == record and
                "PASS: Android x86_64 ELF checks" in path.read_text(errors="strict"),
                "Native build/check evidence changed: " + name)
    require(ref(output / "evidence/gradle.log") == receipt["gradle_build"]["log"] and
            "BUILD SUCCESSFUL" in (output / "evidence/gradle.log").read_text(errors="strict") and
            junit_audit(output / "evidence/jvm-results") == receipt["gradle_build"]["jvm"] and
            lint_audit(output / "evidence/lint") == receipt["gradle_build"]["lint"],
            "Gradle/unit/lint evidence changed or no longer passes")
    if live_tools:
        with Tools(receipt["tools"].get("image_id")) as tools:
            require(equivalent_tools_record(verify_tools(tools, retained_plan), receipt["tools"]),
                    "Live immutable SDK/dependency state differs from packet build")
            for role, filename in FINAL_FILES.items():
                observed = inspect_apk(tools, output / filename)
                require(observed == receipt["artifacts"][role], "APK verification/metadata changed: " + role)
    require(receipt["wrong_signer"]["private_key_removed"] is True and
            receipt["wrong_signer"]["wonad_payload_unchanged"] is True and
            receipt["wrong_signer"]["security_payload_unchanged"] is True,
            "Wrong-signer derivation is not payload-only/ephemeral")
    require(apk_payload(retained / "wonad.apk") == apk_payload(output / "wonad.apk") and
            apk_payload(retained / "conformance-unsigned.apk") == apk_payload(output / "conformance.apk") and
            apk_payload(output / "wonad.apk") == apk_payload(output / "wrong-signer/wrong-wonad.apk") and
            apk_payload(output / "security.apk") == apk_payload(output / "wrong-signer/wrong-security.apk"),
            "A signed target/conformance/wrong-signer payload changed")
    require(receipt["conformance_version_update"]["v1"]["file"] == {
                "sha256": receipt["artifacts"]["conformance"]["sha256"],
                "bytes": receipt["artifacts"]["conformance"]["bytes"]} and
            receipt["conformance_version_update"]["v1"]["package"] ==
                receipt["artifacts"]["conformance"]["package"] and
            receipt["conformance_version_update"]["v1"]["version_code"] ==
                receipt["artifacts"]["conformance"]["version_code"] and
            receipt["conformance_version_update"]["v1"]["version_name"] ==
                receipt["artifacts"]["conformance"]["version_name"] and
            receipt["conformance_version_update"]["v1"]["certificate_der_sha256"] ==
                receipt["artifacts"]["conformance"]["certificate_der_sha256"] and
            receipt["conformance_version_update"]["private_data_canary"] == {
                "runner": UPDATE_CANARY_RUNNER, "source_sha256": UPDATE_CANARY_SHA256},
            "Conformance update pair is not bound to the packet APK/canary")
    for role in ("security", "reuse", "prerequisite", "probe", "fault"):
        require(apk_payload(output / "evidence/built" / (role + ".apk")) ==
                apk_payload(output / FINAL_FILES[role]), "A freshly built fixture payload changed: " + role)
    require(apk_payload(output / "evidence/built/fixture.apk") == apk_payload(output / "fixture.apk") and
            apk_payload(output / "evidence/built/ime.apk") == apk_payload(output / "ime.apk"),
            "An ordinary fixture payload changed")
    sys.path.insert(0, str(ANDROID / "tools"))
    from native_apk_update_acceptance import audit_preparation
    update_root = output / "version-update"
    preparation = load(update_root / "preparation-receipt.json")
    pair = audit_preparation(preparation, lambda name: (update_root / name).read_bytes())
    require(ref(update_root / "preparation-receipt.json") == receipt["version_update"]["receipt"] and
            pair["original"] == receipt["version_update"]["original"] and
            pair["candidate"] == receipt["version_update"]["candidate"] and
            pair["original"]["signer"] == pair["candidate"]["signer"] == WONAD_CERT and
            pair["candidate"]["version"] == pair["original"]["version"] + 1,
            "Version-only derivative failed its independent preparation audit")
    audit_conformance_version_update(output, receipt["conformance_version_update"])
    return {"status": "verified_development_packet_not_runtime_qualified", "receipt_sha256": expected_hash,
            "artifacts": len(receipt["artifacts"]), "files": len(receipt["files"])}


def build(args):
    output = args.output.absolute()
    require(output.resolve() == output and output.is_relative_to(ANDROID / "out") and output != ANDROID / "out" and
            not output.exists() and not output.is_symlink(), "Select a fresh literal android/out child")
    successor = literal_existing(args.successor, directory=True)
    signer = literal_existing(args.signer, directory=True)
    public = literal_existing(args.public_cert, directory=False)
    platform = literal_existing(args.platform_root, directory=True)
    require(pem_der_hash(public) == WONAD_CERT and pem_der_hash(signer / "certificate.x509.pem") == WONAD_CERT,
            "Selected emulator-only public/private certificate identity changed")
    platform_cert = platform / "build/make/target/product/security/platform.x509.pem"
    platform_key = platform / "build/make/target/product/security/platform.pk8"
    require(platform_cert.is_file() and platform_key.is_file(),
            "Development platform signing pair missing from selected source checkout")
    private_state = {
        "wonad": ref(signer / "private.pem"), "wonad_cert": ref(signer / "certificate.x509.pem"),
        "platform": ref(platform_key), "platform_cert": ref(platform_cert),
    }
    successor_receipt = verify_successor(successor)
    successor_plan = load(successor / "plan.json")
    tools_evidence = authenticate_tools_image_manifest(
        args.tools_image_manifest, args.tools_image_manifest_sha256, args.tools_image)
    output.mkdir(mode=0o700, parents=True)
    try:
        with Tools(args.tools_image) as tools:
            tools_record = verify_tools(tools, successor_plan)
            source, origins = stage_sources(successor, output)
            native = native_build(source, output, successor_plan)
            build_result = gradle_build(tools, source, output)
            certificates = output / "evidence/certificates"; certificates.mkdir(parents=True)
            copy_file(public, certificates / "wonad.x509.pem")
            copy_file(platform_cert, certificates / "platform.x509.pem")
            export_fixture_cert(tools, output)
            require(pem_der_hash(certificates / "wonad.x509.pem") == WONAD_CERT and
                    pem_der_hash(certificates / "fixture.x509.pem") == FIXTURE_CERT and
                    pem_der_hash(certificates / "platform.x509.pem") == pem_der_hash(platform_cert),
                    "Retained development certificate identity changed")
            retained = output / "evidence/compile-input"; retained.mkdir()
            for name in ("build-receipt.json", "source-freeze.json", "plan.json", "wonad.apk", "conformance-unsigned.apk"):
                copy_file(successor / name, retained / name)
            built = output / "evidence/built"
            # The target and instrumentation harnesses need the selected Wonad dev signer.
            sign_apk(tools, successor / "wonad.apk", output / "wonad.apk", "wonad", signer, platform)
            conformance_input(successor, tools, output / "conformance.apk", signer, platform,
                              compile_receipt=successor_receipt)
            for role in ("security", "reuse", "prerequisite"):
                sign_apk(tools, built / (role + ".apk"), output / FINAL_FILES[role], "wonad", signer, platform)
            # Explicitly re-sign every ordinary fixture so they all have verified v3 signatures
            # from the one separate fixture identity, regardless of AGP's debug defaults.
            for role in ("fixture", "ime", "probe"):
                sign_apk(tools, built / (role + ".apk"), output / FINAL_FILES[role], "fixture", signer, platform)
            sign_apk(tools, built / "fault.apk", output / "fault.apk", "platform", signer, platform)
            wrong = wrong_signer_derivatives(tools, output, signer)
            update = version_update(tools, output, signer)
            conformance_update = conformance_version_update(tools, output, signer)
            require(private_state == {
                "wonad": ref(signer / "private.pem"), "wonad_cert": ref(signer / "certificate.x509.pem"),
                "platform": ref(platform_key), "platform_cert": ref(platform_cert),
            }, "Development signing input changed during packet construction")
            require(verify_tools(tools, successor_plan) == tools_record,
                    "Pinned SDK/container state changed during packet construction")
            tools_record["image_build"] = stage_tools_image_evidence(output, tools_evidence)
            tool_hash = sha(Path(__file__))
            receipt = collect_receipt(output, successor, successor_receipt, origins, tools, tools_record, native,
                                      build_result, platform_cert, wrong, update, conformance_update, tool_hash)
            write_new(output / "receipt.json", receipt, canonical_json=True)
            receipt_hash = sha(output / "receipt.json")
            result = validate_receipt(output, receipt, receipt_hash)
            print(json.dumps(result, sort_keys=True))
            return 0
    except Exception as error:
        failure = output / "failure.json"
        if not failure.exists():
            write_new(failure, {"status": "failed_not_qualified", "error": str(error)}, canonical_json=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("build")
    create.add_argument("--successor", type=Path, default=DEFAULT_SUCCESSOR)
    create.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    create.add_argument("--signer", type=Path, default=DEFAULT_SIGNER)
    create.add_argument("--public-cert", type=Path, default=DEFAULT_PUBLIC_CERT)
    create.add_argument("--platform-root", type=Path, default=DEFAULT_PLATFORM_ROOT)
    create.add_argument("--tools-image", required=True,
                        help="immutable Phase-1 client-tools image ID")
    create.add_argument("--tools-image-manifest", required=True, type=Path)
    create.add_argument("--tools-image-manifest-sha256", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--packet", type=Path, required=True)
    verify.add_argument("--expected-receipt-sha256", required=True)
    args = parser.parse_args()
    if args.command == "build":
        return build(args)
    packet = literal_existing(args.packet, directory=True)
    result = validate_receipt(packet, load(packet / "receipt.json"), args.expected_receipt_sha256)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PacketError, OSError, subprocess.SubprocessError, zipfile.BadZipFile, json.JSONDecodeError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        raise SystemExit(1)
