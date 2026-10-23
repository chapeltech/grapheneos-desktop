#!/usr/bin/env python3
"""Prepare and execute two independent Wonad SDK 3.0.1 publications.

The prepare phase is observational except for a fresh external evidence root:
it copies the exact reviewed source inventory twice, authenticates the existing
immutable SDK-tools container, and records the previously omitted AIDL compiler
identity.  The build phase is one-shot and requires the reviewed plan digest.
It runs only desktop-sdk library tasks, fully verifies each repository, and
compares the five immutable primary artifacts.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
from typing import Any


ROOT = Path("/u/elric/tree/wonad")
HERE = Path(__file__).resolve().parent
SOURCE_MANIFEST = HERE / "source-manifest.json"
SOURCE_MANIFEST_SHA256 = "de356f5143e4c7d3be53fef4cb69030f0986b355336fb9ea86110b00d516ace3"
SOURCE_RECORDS_SHA256 = "6080720b9f15eac84ab5fe8d9ed1b3a95c8ce86f6518fe8a57a95fcd9cd6ba1b"
AUTHORITY_PLAN = ROOT / "android/out/native-current-successor-12-phase1-v3-runtime-20261012-19/plan.json"
AUTHORITY_PLAN_SHA256 = "6d22d4ef85fb06190cebb305400b5709e24e1e2b3c549dbec43c73b69f4a2ed9"
AUTHORITY_GATE_SHA256 = "5a42968b602c707d5ca0d8ad55e9334ed04536adab891e8d045b9f84b3cf9758"
AUTHORITY_SDK_SHA256 = "a812e0e9a8d8d5720219cb5d878a2f44b47ae5154b69c54fa294aad53fc4219d"
GATE_ID = "51db87997ccb6b27fb5932a88b1187a748dd1908afdc32940f542a879f6b3aae"
GATE_IMAGE = "sha256:3932d980fa538e61d95708d0cb037c0ebb8257bc2639c46f468d5ec7c75fd597"
GATE_NAME = "/wonad-android-gate-tools"
DOCKER = Path("/usr/bin/docker")
DOCKER_SHA256 = "1e4ba89993b43d6ad35c0c7fad3192a1ec6eb268037768023c570ae6fadc8d38"
PYTHON = Path("/usr/bin/python3.14")
PYTHON_SHA256 = "0d64bd6d66d68dac91cdadafc46e22d4f09f22bdc997aaae870f42865b024a3e"
GRADLE = "/opt/gradle-8.11.1/bin/gradle"
JAVA_HOME = "/usr/lib/jvm/java-21-openjdk-amd64"
ANDROID_HOME = "/opt/android-sdk"
BUILD_TOOLS = "/opt/android-sdk/build-tools/35.0.0/"
PRIMARY_FILES = (
    "desktop-sdk-3.0.1.aar",
    "desktop-sdk-3.0.1-sources.jar",
    "desktop-sdk-3.0.1-contract.zip",
    "desktop-sdk-3.0.1.pom",
    "desktop-sdk-3.0.1.module",
)
GIB = 1024 ** 3
MAX_LOG = 32 * 1024 ** 2

SDK_TOOL_PATHS = (
    "/opt/gradle-8.11.1/bin/gradle",
    "/opt/gradle-8.11.1/lib/gradle-launcher-8.11.1.jar",
    "/usr/lib/jvm/java-21-openjdk-amd64/bin/java",
    "/usr/lib/jvm/java-21-openjdk-amd64/release",
    "/opt/android-sdk/platforms/android-35/android.jar",
    "/usr/bin/readelf",
    BUILD_TOOLS + "aapt2",
    BUILD_TOOLS + "apksigner",
    BUILD_TOOLS + "lib/apksigner.jar",
    BUILD_TOOLS + "dexdump",
)
AIDL = BUILD_TOOLS + "aidl"

TOOL_SCRIPT = r'''import hashlib,json,pathlib,sys
def sha(p):
 with p.open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()
paths=[pathlib.Path(p) for p in sys.argv[1:]]
cache=pathlib.Path('/root/.gradle/caches/modules-2/files-2.1')
dependencies={str(p):sha(p) for p in sorted(cache.rglob('*')) if p.is_file() and p.suffix in ('.jar','.pom','.module')}
print(json.dumps(dict(tools={str(p):sha(p) for p in paths},offline_dependency_artifacts=dependencies,
 signing_key_sha256=sha(pathlib.Path('/root/.android/debug.keystore'))),sort_keys=True))
'''

REMOTE_RECORD_SCRIPT = r'''import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]);expected=json.loads(sys.argv[2]);result={}
for name in sorted(expected):
 p=root/name
 if not p.is_file() or p.is_symlink(): raise ValueError('missing/aliased exact source: '+name)
 with p.open('rb') as f: digest=hashlib.file_digest(f,'sha256').hexdigest()
 result[name]={'sha256':digest,'bytes':p.stat().st_size}
print(json.dumps(result,sort_keys=True,separators=(',',':')))
'''


class Failure(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def canonical_sha(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def file_ref(path: Path) -> dict[str, Any]:
    path = path.absolute()
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and
            path.resolve(strict=True) == path, f"literal regular file required: {path}")
    return {"path": str(path), "sha256": sha(path), "bytes": info.st_size}


def write_new(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        data = payload.encode()
        written = os.write(descriptor, data)
        require(written == len(data), f"short evidence write: {path}")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def load_manifest() -> dict[str, Any]:
    require(file_ref(SOURCE_MANIFEST)["sha256"] == SOURCE_MANIFEST_SHA256,
            "reviewed source manifest changed")
    value = json.loads(SOURCE_MANIFEST.read_text())
    require(value.get("schema") == 1 and
            value.get("kind") == "wonad-sdk-3.0.1-independent-publication-source-manifest-v1" and
            value.get("root") == str(ROOT), "source manifest identity differs")
    files = value.get("files")
    require(isinstance(files, dict) and len(files) == 112 and
            canonical_sha(files) == SOURCE_RECORDS_SHA256,
            "exact 112-file source inventory differs")
    return value


def safe_relative(name: str) -> None:
    value = PurePosixPath(name)
    require(name == str(value) and not value.is_absolute() and ".." not in value.parts and
            all(part not in ("", ".") for part in value.parts),
            f"unsafe source path: {name!r}")


def source_records(root: Path, expected: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in sorted(expected):
        safe_relative(name)
        path = root / name
        row = file_ref(path)
        result[name] = {"sha256": row["sha256"], "bytes": row["bytes"]}
    return result


def copy_source(destination: Path, expected: dict[str, Any]) -> None:
    require(not destination.exists() and not destination.is_symlink(),
            f"fresh source destination required: {destination}")
    destination.mkdir(mode=0o700, parents=True)
    before = source_records(ROOT, expected)
    require(before == expected, "current source differs before frozen copy")
    for name in sorted(expected):
        target = destination / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (ROOT / name).open("rb") as source, target.open("xb") as output:
            shutil.copyfileobj(source, output)
        target.chmod(0o400)
    require(source_records(destination, expected) == expected and
            source_records(ROOT, expected) == expected,
            "source changed during independent frozen copy")


def authority() -> dict[str, Any]:
    require(file_ref(AUTHORITY_PLAN)["sha256"] == AUTHORITY_PLAN_SHA256,
            "SDK-tools authority plan changed")
    value = json.loads(AUTHORITY_PLAN.read_text())
    require(canonical_sha(value.get("gate")) == AUTHORITY_GATE_SHA256 and
            canonical_sha(value.get("sdk_tools")) == AUTHORITY_SDK_SHA256,
            "authority gate/SDK record differs")
    require(value["gate"]["Id"] == GATE_ID and value["gate"]["Image"] == GATE_IMAGE and
            value["gate"]["Name"] == GATE_NAME and value["gate"]["Mounts"] == [],
            "authority is not the exact immutable ordinary tools container")
    return value


def executable_guards() -> dict[str, Any]:
    docker = file_ref(DOCKER)
    python = file_ref(PYTHON)
    require(docker["sha256"] == DOCKER_SHA256 and python["sha256"] == PYTHON_SHA256,
            "host Docker/Python executable identity changed")
    return {"docker": docker, "python": python}


def resources() -> dict[str, Any]:
    match = re.findall(r"^MemAvailable:\s+([0-9]+) kB$", Path("/proc/meminfo").read_text(), re.M)
    require(len(match) == 1, "exact MemAvailable required")
    available = int(match[0]) * 1024
    free = {name: shutil.disk_usage(name).free for name in (str(HERE), "/var", "/tmp")}
    require(available >= 6 * GIB and all(value >= 8 * GIB for value in free.values()),
            "insufficient bounded SDK publication resources")
    return {"mem_available_bytes": available, "minimum_mem_available_bytes": 6 * GIB,
            "free_bytes": free, "minimum_free_bytes": 8 * GIB,
            "gradle_heap_bytes": 2 * GIB, "gradle_workers": 2}


class Runner:
    def __init__(self, evidence: Path):
        self.evidence = evidence
        self.phases = evidence / "phases"
        self.phases.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.rows: list[dict[str, Any]] = []

    def run(self, label: str, argv: list[str], timeout: int = 120) -> str:
        require(re.fullmatch(r"[a-z0-9-]+", label) is not None, "unsafe phase label")
        log = self.phases / f"{label}.log"
        row: dict[str, Any] = {"label": label, "argv": argv, "started": now()}
        write_new(self.phases / f"{label}.start.json", row)
        with log.open("xb") as output:
            child = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT)
            row["pid"] = child.pid
            try:
                code = child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                row.update(ended=now(), exit_code=child.returncode, timed_out=True)
                write_new(self.phases / f"{label}.json", row)
                self.rows.append(row)
                raise Failure(f"phase timed out: {label}")
        row.update(ended=now(), exit_code=code, timed_out=False,
                   log={"path": str(log), "sha256": sha(log), "bytes": log.stat().st_size})
        write_new(self.phases / f"{label}.json", row)
        self.rows.append(row)
        require(log.stat().st_size <= MAX_LOG, f"phase log oversized: {label}")
        require(code == 0, f"phase failed ({code}): {label}")
        return log.read_text(errors="strict")


def validate_gate(actual: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    selected = {key: actual.get(key) for key in ("Id", "Image", "Name", "Config", "HostConfig", "Mounts")}
    require(selected == auth, "gate container profile differs from reviewed authority")
    state = actual.get("State")
    require(isinstance(state, dict) and state.get("Running") is True and
            state.get("Paused") is False and state.get("Restarting") is False and
            state.get("Dead") is False and state.get("OOMKilled") is False and
            type(state.get("Pid")) is int and state["Pid"] > 0 and
            isinstance(state.get("StartedAt"), str) and state["StartedAt"],
            "tools container must be the live exact non-restarted gate")
    return {**selected, "lifecycle": {key: state[key] for key in ("Pid", "StartedAt")}}


def gate_row(runner: Runner, label: str) -> dict[str, Any]:
    raw = json.loads(runner.run(label, [str(DOCKER), "inspect", GATE_ID]))
    require(isinstance(raw, list) and len(raw) == 1 and isinstance(raw[0], dict),
            "exact one gate inspection required")
    return validate_gate(raw[0], authority()["gate"])


def validate_sdk_observation(observed: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    require(isinstance(observed, dict) and isinstance(observed.get("tools"), dict),
            "malformed SDK-tools observation")
    tools = dict(observed["tools"])
    aidl_hash = tools.pop(AIDL, None)
    require(isinstance(aidl_hash, str) and re.fullmatch(r"[0-9a-f]{64}", aidl_hash) is not None,
            "exact AIDL executable identity missing")
    base = {**observed, "tools": tools}
    require(base == expected,
            "existing SDK tools/cache/signer differ from reviewed authority")
    return {**observed, "aidl": {"path": AIDL, "sha256": aidl_hash}}


def sdk_tools(runner: Runner, label: str) -> dict[str, Any]:
    observed = json.loads(runner.run(label, [str(DOCKER), "exec", GATE_ID,
        "python3", "-B", "-c", TOOL_SCRIPT, *SDK_TOOL_PATHS, AIDL]))
    return validate_sdk_observation(observed, authority()["sdk_tools"])


def gradle_command(remote: str) -> list[str]:
    return [str(DOCKER), "exec", GATE_ID, "env",
        "ANDROID_HOME=" + ANDROID_HOME, "JAVA_HOME=" + JAVA_HOME,
        GRADLE, "--offline", "--no-daemon", "--rerun-tasks", "--no-parallel",
        "--max-workers=2", "-Dorg.gradle.jvmargs=-Xmx2048m -XX:MaxMetaspaceSize=768m",
        "-Pkotlin.compiler.execution.strategy=in-process", "-p", remote + "/android",
        ":desktop-sdk:clean", ":desktop-sdk:testReleaseUnitTest",
        ":desktop-sdk:verifyPhase1Publication"]


def remote_records_command(remote: str, expected: dict[str, Any]) -> list[str]:
    return [str(DOCKER), "exec", GATE_ID, "python3", "-B", "-c",
            REMOTE_RECORD_SCRIPT, remote, json.dumps(expected, sort_keys=True,
            separators=(",", ":"))]


def lane_commands(output: Path, lane: str, remote: str) -> dict[str, list[str]]:
    source = output / lane / "source"
    repository = output / lane / "sdk-repository"
    verifier = source / "android/tools/verify_sdk_publication.py"
    return {
        "remote_absent": [str(DOCKER), "exec", GATE_ID, "test", "!", "-e", remote],
        "copy_source": [str(DOCKER), "cp", str(source), GATE_ID + ":" + remote],
        "gradle": gradle_command(remote),
        "collect": [str(DOCKER), "cp", GATE_ID + ":" + remote +
            "/android/desktop-sdk/build/phase1-repository", str(repository)],
        "verify": [str(PYTHON), "-B", str(verifier), str(repository),
            "--source-root", str(source / "android")],
    }


def prepare(output: Path) -> None:
    require(output.is_absolute() and output.parent == HERE.parent and
            re.fullmatch(r"phase1-sdk-3\.0\.1-independent-publication-run-[A-Za-z0-9_.-]+",
                         output.name) is not None,
            "output must be a fresh bounded sibling evidence directory")
    require(not output.exists() and not output.is_symlink(), "fresh output required")
    manifest = load_manifest()
    expected = manifest["files"]
    require(source_records(ROOT, expected) == expected, "current 112-file SDK source freeze differs")
    require((ROOT / "android/desktop-sdk/build.gradle.kts").read_text().count('version = "3.0.1"') == 1,
            "SDK publication is not exactly version 3.0.1")
    output.mkdir(mode=0o700)
    runner = Runner(output)
    copy_source(output / "build-a/source", expected)
    copy_source(output / "build-b/source", expected)
    gate = gate_row(runner, "gate-prepare")
    tools = sdk_tools(runner, "sdk-tools-prepare")
    remote_base = "/work/" + output.name
    require(len(remote_base) <= 150, "remote work root too long")
    remotes = {"build-a": remote_base + "-a", "build-b": remote_base + "-b"}
    commands = {lane: lane_commands(output, lane, remote) for lane, remote in remotes.items()}
    comparison = [str(PYTHON), "-B",
        str(output / "build-a/source/android/tools/verify_sdk_publication.py"),
        str(output / "build-a/sdk-repository"), "--compare",
        str(output / "build-b/sdk-repository"), "--source-root",
        str(output / "build-a/source/android")]
    plan = {
        "schema": 1,
        "kind": "wonad-sdk-3.0.1-two-independent-publications-plan-v1",
        "status": "prepared_not_built_or_published",
        "output": str(output),
        "helper": file_ref(Path(__file__).resolve()),
        "manifest": file_ref(SOURCE_MANIFEST),
        "authority_plan": file_ref(AUTHORITY_PLAN),
        "host_executables": executable_guards(),
        "sources": expected,
        "source_records_sha256": SOURCE_RECORDS_SHA256,
        "source_copies": {lane: source_records(output / lane / "source", expected)
                          for lane in remotes},
        "gate": gate,
        "sdk_tools": tools,
        "remotes": remotes,
        "commands": commands,
        "comparison_command": comparison,
        "primary_files": list(PRIMARY_FILES),
        "resources": resources(),
        "runtime_qualified": False,
        "android_product_built": False,
        "apk_built_or_signed": False,
        "historical_3_0_0_modified": False,
    }
    write_new(output / "plan.json", plan)
    write_new(output / "prepare-commands.json", runner.rows)
    print(f"PREPARED {output / 'plan.json'} {sha(output / 'plan.json')}", flush=True)


def inventory(repository: Path) -> dict[str, Any]:
    require(repository.is_dir() and not repository.is_symlink(), "literal repository directory required")
    result: dict[str, Any] = {}
    for path in sorted(repository.rglob("*")):
        require(not path.is_symlink(), f"repository symlink forbidden: {path}")
        if path.is_file():
            relative = str(path.relative_to(repository))
            result[relative] = {"sha256": sha(path), "bytes": path.stat().st_size}
        else:
            require(path.is_dir(), f"non-file repository node: {path}")
    require(result, "empty publication repository")
    return result


def parse_verifier(text: str, *, comparison: bool) -> dict[str, Any]:
    value = json.loads(text)
    require(isinstance(value, dict), "verifier output is not an object")
    if comparison:
        require(value.get("reproducible") is True and
                value.get("comparison_scope") == list(PRIMARY_FILES),
                "two-publication comparison did not cover exact primaries")
    else:
        require(value.get("coordinate") == "org.wonad:desktop-sdk:3.0.1" and
                value.get("reproducible") is None and
                set(value.get("artifact_sha256", {})) == set(PRIMARY_FILES),
                "independent publication verifier result differs")
    return value


def build_lane(runner: Runner, output: Path, lane: str, remote: str,
               expected: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    commands = lane_commands(output, lane, remote)
    runner.run(lane + "-remote-absent", commands["remote_absent"])
    runner.run(lane + "-copy-source", commands["copy_source"], timeout=300)
    before = json.loads(runner.run(lane + "-remote-source-before",
        remote_records_command(remote, expected), timeout=300))
    require(before == expected, f"{lane} remote source differs before Gradle")
    runner.run(lane + "-gradle", commands["gradle"], timeout=1800)
    after = json.loads(runner.run(lane + "-remote-source-after",
        remote_records_command(remote, expected), timeout=300))
    require(after == expected, f"{lane} remote source differs after Gradle")
    repository = output / lane / "sdk-repository"
    require(not repository.exists() and not repository.is_symlink(),
            f"fresh {lane} publication repository required")
    runner.run(lane + "-collect", commands["collect"], timeout=300)
    verified = parse_verifier(runner.run(lane + "-verify", commands["verify"], timeout=120),
                              comparison=False)
    return verified, inventory(repository)


def build(output: Path, expected_plan_sha256: str) -> None:
    plan_path = output / "plan.json"
    require(re.fullmatch(r"[0-9a-f]{64}", expected_plan_sha256) is not None and
            file_ref(plan_path)["sha256"] == expected_plan_sha256,
            "exact reviewed publication plan required")
    plan = json.loads(plan_path.read_text())
    require(plan.get("schema") == 1 and
            plan.get("kind") == "wonad-sdk-3.0.1-two-independent-publications-plan-v1" and
            plan.get("output") == str(output), "publication plan identity differs")
    require(not (output / "attempt.json").exists() and not (output / "receipt.json").exists(),
            "publication build is one-shot and already attempted")
    expected = load_manifest()["files"]
    require(plan["sources"] == expected and plan["source_records_sha256"] == SOURCE_RECORDS_SHA256 and
            plan["helper"] == file_ref(Path(__file__).resolve()) and
            plan["manifest"] == file_ref(SOURCE_MANIFEST) and
            plan["authority_plan"] == file_ref(AUTHORITY_PLAN) and
            plan["host_executables"] == executable_guards(),
            "reviewed helper/manifest/authority/host executables changed")
    for lane in ("build-a", "build-b"):
        require(source_records(output / lane / "source", expected) == expected,
                f"{lane} frozen source changed")
    require(source_records(ROOT, expected) == expected, "current source changed after preparation")
    resources()
    write_new(output / "attempt.json", {"schema": 1,
        "kind": "wonad-sdk-3.0.1-two-publication-attempt-v1",
        "started": now(), "plan_sha256": expected_plan_sha256})
    runner = Runner(output / "build-evidence")
    require(gate_row(runner, "gate-before") == plan["gate"] and
            sdk_tools(runner, "sdk-tools-before") == plan["sdk_tools"],
            "gate lifecycle or SDK tools changed before build")
    verified: dict[str, Any] = {}
    inventories: dict[str, Any] = {}
    for lane in ("build-a", "build-b"):
        verified[lane], inventories[lane] = build_lane(
            runner, output, lane, plan["remotes"][lane], expected)
        require(source_records(ROOT, expected) == expected and
                source_records(output / lane / "source", expected) == expected,
                f"source changed during {lane}")
    comparison = parse_verifier(runner.run("compare-publications",
        plan["comparison_command"], timeout=120), comparison=True)
    require(gate_row(runner, "gate-after") == plan["gate"] and
            sdk_tools(runner, "sdk-tools-after") == plan["sdk_tools"],
            "gate lifecycle or SDK tools changed after build")
    require(source_records(ROOT, expected) == expected and all(
        source_records(output / lane / "source", expected) == expected
        for lane in ("build-a", "build-b")), "source changed during publications")
    receipt = {
        "schema": 1,
        "kind": "wonad-sdk-3.0.1-two-independent-publications-receipt-v1",
        "status": "library_publication_reproducible_not_android_runtime_qualified",
        "plan": file_ref(plan_path),
        "helper": file_ref(Path(__file__).resolve()),
        "manifest": file_ref(SOURCE_MANIFEST),
        "gate": plan["gate"],
        "sdk_tools": plan["sdk_tools"],
        "verified": verified,
        "inventories": inventories,
        "comparison": comparison,
        "commands": runner.rows,
        "ended": now(),
        "runtime_qualified": False,
        "android_product_built": False,
        "apk_built_or_signed": False,
        "historical_3_0_0_modified": False,
    }
    write_new(output / "receipt.json", receipt)
    print(f"COMPLETE {output / 'receipt.json'} {sha(output / 'receipt.json')}", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--output", type=Path, required=True)
    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("--output", type=Path, required=True)
    build_parser.add_argument("--expected-plan-sha256", required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.action == "prepare":
            prepare(arguments.output)
        else:
            build(arguments.output, arguments.expected_plan_sha256)
        return 0
    except (OSError, Failure, KeyError, TypeError, ValueError, json.JSONDecodeError,
            subprocess.SubprocessError) as error:
        print(f"SDK two-publication driver failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
