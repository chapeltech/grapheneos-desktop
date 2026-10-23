#!/usr/bin/env python3
"""Prepare and execute two independent Wonad SDK 3.0.1 publications.

The prepare phase is observational except for a fresh external evidence root:
it copies the exact reviewed source inventory twice, authenticates the existing
immutable SDK-tools container, and records the previously omitted AIDL compiler
identity.  The build phase is one-shot and requires the reviewed plan digest.
It runs only desktop-sdk library tasks, fully verifies each repository, and
compares the five immutable primary artifacts.  This generation also seals the
entire local and pre-Gradle remote source trees and refuses ambient Gradle
configuration, rather than authenticating only the selected source paths.  This
third generation also refuses distribution-level Gradle properties, permits
only the standard inert distribution init.d readme, and brackets each Gradle
invocation with immediate configuration observations.
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
SOURCE_MANIFEST_SHA256 = "986c3199e05296aeb9e4314ae6bc7a4b1e81ee61e0ea47fa0038e3dee2a43e36"
SOURCE_RECORDS_SHA256 = "e6a2dd329fcc6cc7deeb26e7ec725e2b9bf84ffc6e7967e6378d45a07addeaa1"
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
MAX_REMOTE_OUTPUT_FILES = 20_000
MAX_REMOTE_OUTPUT_BYTES = 2 * GIB
GRADLE_USER_HOME = "/root/.gradle"
GRADLE_DISTRIBUTION_INIT = "/opt/gradle-8.11.1/init.d"
GRADLE_DISTRIBUTION_PROPERTIES = "/opt/gradle-8.11.1/gradle.properties"
FORBIDDEN_GRADLE_ENV = (
    "GRADLE_USER_HOME",
    "GRADLE_OPTS",
    "JAVA_OPTS",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "_JAVA_OPTIONS",
)
CHECKSUMS = ("md5", "sha1", "sha256", "sha512")

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

REMOTE_TREE_SCRIPT = r'''import hashlib,json,os,pathlib,stat,sys
root=pathlib.Path(sys.argv[1])
def metadata(st,kind):
 return {'kind':kind,'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,'dev':st.st_dev,'ino':st.st_ino}
st=root.lstat()
if not stat.S_ISDIR(st.st_mode) or root.is_symlink(): raise ValueError('literal remote source root required')
nodes={}; stack=[root]
while stack:
 base=stack.pop()
 with os.scandir(base) as entries:
  for entry in sorted(entries,key=lambda item:item.name,reverse=True):
   p=pathlib.Path(entry.path); rel=p.relative_to(root).as_posix(); info=entry.stat(follow_symlinks=False)
   if stat.S_ISLNK(info.st_mode): raise ValueError('remote source symlink forbidden: '+rel)
   if stat.S_ISDIR(info.st_mode):
    nodes[rel]=metadata(info,'directory'); stack.append(p)
   elif stat.S_ISREG(info.st_mode):
    row=metadata(info,'file')
    with p.open('rb') as f: row.update(sha256=hashlib.file_digest(f,'sha256').hexdigest(),bytes=info.st_size)
    nodes[rel]=row
   else: raise ValueError('remote source special node forbidden: '+rel)
print(json.dumps({'root':metadata(st,'directory'),'nodes':nodes},sort_keys=True,separators=(',',':')))
'''

REMOTE_OUTPUT_SCRIPT = r'''import hashlib,json,os,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]); max_files=int(sys.argv[2]); max_bytes=int(sys.argv[3])
st=root.lstat()
if not stat.S_ISDIR(st.st_mode) or root.is_symlink(): raise ValueError('literal build output root required')
nodes={}; files=0; total=0; stack=[root]
while stack:
 base=stack.pop()
 with os.scandir(base) as entries:
  for entry in sorted(entries,key=lambda item:item.name,reverse=True):
   p=pathlib.Path(entry.path); rel=p.relative_to(root).as_posix(); info=entry.stat(follow_symlinks=False)
   common={'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid}
   if stat.S_ISLNK(info.st_mode): raise ValueError('build output symlink forbidden: '+rel)
   if stat.S_ISDIR(info.st_mode): nodes[rel]={**common,'kind':'directory'}; stack.append(p)
   elif stat.S_ISREG(info.st_mode):
    files+=1; total+=info.st_size
    if files>max_files or total>max_bytes: raise ValueError('build output inventory exceeds bound')
    with p.open('rb') as f: digest=hashlib.file_digest(f,'sha256').hexdigest()
    nodes[rel]={**common,'kind':'file','sha256':digest,'bytes':info.st_size}
   else: raise ValueError('build output special node forbidden: '+rel)
print(json.dumps({'nodes':nodes,'file_count':files,'total_file_bytes':total},sort_keys=True,separators=(',',':')))
'''

GRADLE_CONFIG_SCRIPT = r'''import hashlib,json,os,pathlib,stat
home=pathlib.Path('/root/.gradle')
distribution=pathlib.Path('/opt/gradle-8.11.1/init.d')
distribution_properties=pathlib.Path('/opt/gradle-8.11.1/gradle.properties')
def row(path):
 try: st=path.lstat()
 except FileNotFoundError: return {'state':'absent'}
 kind='directory' if stat.S_ISDIR(st.st_mode) else ('file' if stat.S_ISREG(st.st_mode) else ('symlink' if stat.S_ISLNK(st.st_mode) else 'special'))
 return {'state':'present','kind':kind,'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,'dev':st.st_dev,'ino':st.st_ino}
paths={name:row(home/name) for name in ('gradle.properties','init.gradle','init.gradle.kts','init.d')}
children=[]
if paths['init.d'].get('kind')=='directory':
 with os.scandir(home/'init.d') as entries:
  for entry in sorted(entries,key=lambda item:item.name):
   info=entry.stat(follow_symlinks=False)
   kind='directory' if stat.S_ISDIR(info.st_mode) else ('file' if stat.S_ISREG(info.st_mode) else ('symlink' if stat.S_ISLNK(info.st_mode) else 'special'))
   children.append({'name':entry.name,'kind':kind,'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid})
distribution_row=row(distribution); distribution_children=[]
if distribution_row.get('kind')=='directory':
 with os.scandir(distribution) as entries:
  for entry in sorted(entries,key=lambda item:item.name):
   info=entry.stat(follow_symlinks=False)
   kind='file' if stat.S_ISREG(info.st_mode) else ('symlink' if stat.S_ISLNK(info.st_mode) else ('directory' if stat.S_ISDIR(info.st_mode) else 'special'))
   item={'name':entry.name,'kind':kind,'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid}
   if kind=='file':
    with pathlib.Path(entry.path).open('rb') as f: item.update(sha256=hashlib.file_digest(f,'sha256').hexdigest(),bytes=info.st_size)
   distribution_children.append(item)
forbidden=sorted(name for name in os.environ if name in {'GRADLE_USER_HOME','GRADLE_OPTS','JAVA_OPTS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS'} or name.startswith('ORG_GRADLE_PROJECT_'))
print(json.dumps({'home':row(home),'paths':paths,'init_d_children':children,'distribution_gradle_properties':row(distribution_properties),'distribution_init_d':distribution_row,'distribution_init_d_children':distribution_children,'forbidden_environment_names':forbidden},sort_keys=True,separators=(',',':')))
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


def expected_source_nodes(expected: dict[str, Any]) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    for name in expected:
        safe_relative(name)
        files.add(name)
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            directories.add(str(parent))
            parent = parent.parent
    return files, directories


def tree_inventory(root: Path) -> dict[str, Any]:
    root = root.absolute()
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and not root.is_symlink() and
            root.resolve(strict=True) == root, f"literal tree root required: {root}")
    nodes: dict[str, Any] = {}
    stack = [root]
    while stack:
        base = stack.pop()
        with os.scandir(base) as entries:
            for entry in sorted(entries, key=lambda item: item.name, reverse=True):
                path = Path(entry.path)
                relative = str(path.relative_to(root))
                item = entry.stat(follow_symlinks=False)
                common = {"mode": stat.S_IMODE(item.st_mode), "uid": item.st_uid,
                          "gid": item.st_gid, "dev": item.st_dev, "ino": item.st_ino}
                require(not stat.S_ISLNK(item.st_mode),
                        f"tree symlink forbidden: {relative}")
                if stat.S_ISDIR(item.st_mode):
                    nodes[relative] = {**common, "kind": "directory"}
                    stack.append(path)
                elif stat.S_ISREG(item.st_mode):
                    nodes[relative] = {**common, "kind": "file",
                                       "sha256": sha(path), "bytes": item.st_size}
                else:
                    raise Failure(f"tree special node forbidden: {relative}")
    return {"root": {"kind": "directory", "mode": stat.S_IMODE(info.st_mode),
                     "uid": info.st_uid, "gid": info.st_gid,
                     "dev": info.st_dev, "ino": info.st_ino},
            "nodes": dict(sorted(nodes.items()))}


def validate_source_tree(value: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    require(isinstance(value, dict) and isinstance(value.get("root"), dict) and
            value["root"].get("kind") == "directory" and
            isinstance(value.get("nodes"), dict), "malformed exact source-tree inventory")
    files, directories = expected_source_nodes(expected)
    nodes = value["nodes"]
    for name, row in [("<root>", value["root"]), *nodes.items()]:
        require(isinstance(row, dict) and row.get("kind") in ("file", "directory") and
                type(row.get("mode")) is int and type(row.get("uid")) is int and
                type(row.get("gid")) is int and type(row.get("dev")) is int and
                type(row.get("ino")) is int,
                f"source-tree node metadata differs: {name}")
    require(set(nodes) == files | directories,
            f"source tree path set differs; missing={sorted((files | directories) - set(nodes))}; "
            f"extra={sorted(set(nodes) - (files | directories))}")
    for name in directories:
        row = nodes[name]
        require(isinstance(row, dict) and row.get("kind") == "directory",
                f"source directory type differs: {name}")
    for name in files:
        row = nodes[name]
        expected_row = expected[name]
        require(isinstance(row, dict) and row.get("kind") == "file" and
                row.get("sha256") == expected_row["sha256"] and
                row.get("bytes") == expected_row["bytes"],
                f"source file identity differs: {name}")
    return value


def exact_source_tree(root: Path, expected: dict[str, Any]) -> dict[str, Any]:
    return validate_source_tree(tree_inventory(root), expected)


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
            validate_source_tree(tree_inventory(destination), expected) and
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


def validate_gradle_environment_names(names: Any) -> list[str]:
    require(isinstance(names, list) and all(isinstance(name, str) for name in names) and
            names == sorted(set(names)), "malformed Gradle environment-name observation")
    require(not names, f"ambient Gradle/JVM injection environment is forbidden: {names}")
    return names


def gate_gradle_environment(gate: dict[str, Any]) -> list[str]:
    config = gate.get("Config")
    require(isinstance(config, dict) and isinstance(config.get("Env"), list) and
            all(isinstance(item, str) and "=" in item for item in config["Env"]),
            "gate configured environment is malformed")
    names = sorted({item.split("=", 1)[0] for item in config["Env"]
                    if item.split("=", 1)[0] in FORBIDDEN_GRADLE_ENV or
                    item.split("=", 1)[0].startswith("ORG_GRADLE_PROJECT_")})
    return validate_gradle_environment_names(names)


def validate_gradle_config(value: dict[str, Any]) -> dict[str, Any]:
    require(isinstance(value, dict) and isinstance(value.get("home"), dict) and
            value["home"].get("state") == "present" and
            value["home"].get("kind") == "directory" and
            isinstance(value.get("paths"), dict) and
            set(value["paths"]) == {"gradle.properties", "init.gradle",
                                     "init.gradle.kts", "init.d"} and
            isinstance(value.get("init_d_children"), list) and
            isinstance(value.get("distribution_gradle_properties"), dict) and
            isinstance(value.get("distribution_init_d"), dict) and
            isinstance(value.get("distribution_init_d_children"), list),
            "malformed Gradle user-home observation")
    def literal_directory(row: dict[str, Any], label: str) -> None:
        require(row.get("state") == "present" and row.get("kind") == "directory" and
                type(row.get("mode")) is int and type(row.get("uid")) is int and
                type(row.get("gid")) is int and type(row.get("dev")) is int and
                type(row.get("ino")) is int,
                f"malformed Gradle directory identity: {label}")
    literal_directory(value["home"], GRADLE_USER_HOME)
    validate_gradle_environment_names(value.get("forbidden_environment_names"))
    for name in ("gradle.properties", "init.gradle", "init.gradle.kts"):
        require(value["paths"][name] == {"state": "absent"},
                f"unreviewed Gradle user-home configuration exists: {name}")
    init_d = value["paths"]["init.d"]
    require(init_d == {"state": "absent"} or
            (isinstance(init_d, dict) and init_d.get("state") == "present" and
             init_d.get("kind") == "directory" and not value["init_d_children"]),
            "Gradle init.d must be absent or an exact empty literal directory")
    if init_d == {"state": "absent"}:
        require(value["init_d_children"] == [],
                "absent Gradle init.d has observed children")
    else:
        literal_directory(init_d, GRADLE_USER_HOME + "/init.d")
    require(value["distribution_gradle_properties"] == {"state": "absent"},
            "unreviewed Gradle distribution gradle.properties exists")
    distribution = value["distribution_init_d"]
    require(distribution == {"state": "absent"} or
            (distribution.get("state") == "present" and
             distribution.get("kind") == "directory"),
            "Gradle distribution init.d is not a literal directory or absent")
    if distribution == {"state": "absent"}:
        require(value["distribution_init_d_children"] == [],
                "absent Gradle distribution init.d has observed children")
    else:
        literal_directory(distribution, GRADLE_DISTRIBUTION_INIT)
    children = value["distribution_init_d_children"]
    require(len(children) <= 1,
            "Gradle distribution init.d contains more than the standard readme")
    if children:
        item = children[0]
        require(isinstance(item, dict) and item.get("name") == "readme.txt" and
                item.get("kind") == "file" and type(item.get("mode")) is int and
                item["mode"] & 0o111 == 0 and type(item.get("uid")) is int and
                type(item.get("gid")) is int and type(item.get("bytes")) is int and
                item["bytes"] >= 0 and isinstance(item.get("sha256"), str) and
                re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None,
                "Gradle distribution init.d may contain only a non-executable readme.txt")
    return value


def gradle_config(runner: Runner, label: str, gate: dict[str, Any]) -> dict[str, Any]:
    gate_gradle_environment(gate)
    observed = json.loads(runner.run(label, [str(DOCKER), "exec", GATE_ID,
        "python3", "-B", "-c", GRADLE_CONFIG_SCRIPT]))
    return validate_gradle_config(observed)


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
        "GRADLE_USER_HOME=" + GRADLE_USER_HOME,
        GRADLE, "--offline", "--no-daemon", "--rerun-tasks", "--no-parallel",
        "--max-workers=2", "-Dorg.gradle.jvmargs=-Xmx2048m -XX:MaxMetaspaceSize=768m",
        "-Pkotlin.compiler.execution.strategy=in-process", "-p", remote + "/android",
        ":desktop-sdk:clean", ":desktop-sdk:testReleaseUnitTest",
        ":desktop-sdk:verifyPhase1Publication"]


def remote_records_command(remote: str, expected: dict[str, Any]) -> list[str]:
    return [str(DOCKER), "exec", GATE_ID, "python3", "-B", "-c",
            REMOTE_RECORD_SCRIPT, remote, json.dumps(expected, sort_keys=True,
            separators=(",", ":"))]


def remote_tree_command(remote: str) -> list[str]:
    return [str(DOCKER), "exec", GATE_ID, "python3", "-B", "-c",
            REMOTE_TREE_SCRIPT, remote]


def remote_output_command(remote: str) -> list[str]:
    return [str(DOCKER), "exec", GATE_ID, "python3", "-B", "-c",
            REMOTE_OUTPUT_SCRIPT, remote + "/android/desktop-sdk/build",
            str(MAX_REMOTE_OUTPUT_FILES), str(MAX_REMOTE_OUTPUT_BYTES)]


def expected_repository_files() -> set[str]:
    prefix = "phase1-repository/org/wonad/desktop-sdk/3.0.1/"
    result: set[str] = set()
    for name in PRIMARY_FILES:
        result.add(prefix + name)
        result.update(prefix + name + "." + algorithm for algorithm in CHECKSUMS)
    metadata = "phase1-repository/org/wonad/desktop-sdk/maven-metadata.xml"
    result.add(metadata)
    result.update(metadata + "." + algorithm for algorithm in CHECKSUMS)
    return result


def validate_remote_output(value: dict[str, Any]) -> dict[str, Any]:
    require(isinstance(value, dict) and isinstance(value.get("nodes"), dict) and
            type(value.get("file_count")) is int and
            type(value.get("total_file_bytes")) is int and
            0 < value["file_count"] <= MAX_REMOTE_OUTPUT_FILES and
            0 < value["total_file_bytes"] <= MAX_REMOTE_OUTPUT_BYTES,
            "malformed or unbounded remote build-output inventory")
    files: set[str] = set()
    observed_bytes = 0
    for name, row in value["nodes"].items():
        safe_relative(name)
        require(isinstance(row, dict) and row.get("kind") in ("file", "directory") and
                type(row.get("mode")) is int and type(row.get("uid")) is int and
                type(row.get("gid")) is int, f"malformed remote output node: {name}")
        if row["kind"] == "file":
            require(isinstance(row.get("sha256"), str) and
                    re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None and
                    type(row.get("bytes")) is int and row["bytes"] >= 0,
                    f"malformed remote output file: {name}")
            files.add(name)
            observed_bytes += row["bytes"]
    require(value["file_count"] == len(files) and
            value["total_file_bytes"] == observed_bytes,
            "remote output inventory counters differ from exact nodes")
    missing = expected_repository_files() - files
    require(not missing, f"expected publication outputs absent: {sorted(missing)}")
    return value


def lane_commands(output: Path, lane: str, remote: str) -> dict[str, list[str]]:
    source = output / lane / "source"
    repository = output / lane / "sdk-repository"
    verifier = source / "android/tools/verify_sdk_publication.py"
    return {
        "remote_absent": [str(DOCKER), "exec", GATE_ID, "test", "!", "-e", remote],
        "copy_source": [str(DOCKER), "cp", str(source), GATE_ID + ":" + remote],
        "remote_tree": remote_tree_command(remote),
        "gradle": gradle_command(remote),
        "remote_output": remote_output_command(remote),
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
    config = gradle_config(runner, "gradle-config-prepare", gate)
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
        "kind": "wonad-sdk-3.0.1-two-independent-publications-plan-v3",
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
        "source_tree_inventories": {
            lane: exact_source_tree(output / lane / "source", expected)
            for lane in remotes
        },
        "gate": gate,
        "gradle_user_home": {
            "path": GRADLE_USER_HOME,
            "distribution_gradle_properties_path": GRADLE_DISTRIBUTION_PROPERTIES,
            "distribution_init_d_path": GRADLE_DISTRIBUTION_INIT,
            "configuration": config,
            "ambient_injection_environment_forbidden": True,
        },
        "sdk_tools": tools,
        "remotes": remotes,
        "commands": commands,
        "comparison_command": comparison,
        "primary_files": list(PRIMARY_FILES),
        "expected_repository_files": sorted(expected_repository_files()),
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
               expected: dict[str, Any], expected_config: dict[str, Any],
               gate: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any],
                                                   dict[str, Any], dict[str, Any],
                                                   dict[str, Any]]:
    commands = lane_commands(output, lane, remote)
    runner.run(lane + "-remote-absent", commands["remote_absent"])
    runner.run(lane + "-copy-source", commands["copy_source"], timeout=300)
    before = validate_source_tree(json.loads(runner.run(lane + "-remote-tree-before",
        commands["remote_tree"], timeout=300)), expected)
    require(gradle_config(runner, lane + "-gradle-config-immediately-before", gate) ==
            expected_config, f"Gradle configuration changed immediately before {lane}")
    runner.run(lane + "-gradle", commands["gradle"], timeout=1800)
    require(gradle_config(runner, lane + "-gradle-config-immediately-after", gate) ==
            expected_config, f"Gradle configuration changed immediately after {lane}")
    after = json.loads(runner.run(lane + "-remote-source-after",
        remote_records_command(remote, expected), timeout=300))
    require(after == expected, f"{lane} remote source differs after Gradle")
    outputs = validate_remote_output(json.loads(runner.run(lane + "-remote-output-after",
        commands["remote_output"], timeout=300)))
    repository = output / lane / "sdk-repository"
    require(not repository.exists() and not repository.is_symlink(),
            f"fresh {lane} publication repository required")
    runner.run(lane + "-collect", commands["collect"], timeout=300)
    verified = parse_verifier(runner.run(lane + "-verify", commands["verify"], timeout=120),
                              comparison=False)
    return verified, inventory(repository), before, after, outputs


def build(output: Path, expected_plan_sha256: str) -> None:
    plan_path = output / "plan.json"
    require(re.fullmatch(r"[0-9a-f]{64}", expected_plan_sha256) is not None and
            file_ref(plan_path)["sha256"] == expected_plan_sha256,
            "exact reviewed publication plan required")
    plan = json.loads(plan_path.read_text())
    require(plan.get("schema") == 1 and
            plan.get("kind") == "wonad-sdk-3.0.1-two-independent-publications-plan-v3" and
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
    local_before: dict[str, Any] = {}
    for lane in ("build-a", "build-b"):
        local_before[lane] = exact_source_tree(output / lane / "source", expected)
        require(source_records(output / lane / "source", expected) == expected and
                local_before[lane] == plan["source_tree_inventories"][lane],
                f"{lane} frozen source changed")
    require(source_records(ROOT, expected) == expected, "current source changed after preparation")
    resources()
    write_new(output / "attempt.json", {"schema": 1,
        "kind": "wonad-sdk-3.0.1-two-publication-attempt-v3",
        "started": now(), "plan_sha256": expected_plan_sha256})
    runner = Runner(output / "build-evidence")
    gate_before = gate_row(runner, "gate-before")
    require(gate_before == plan["gate"] and
            gradle_config(runner, "gradle-config-before", gate_before) ==
                plan["gradle_user_home"]["configuration"] and
            sdk_tools(runner, "sdk-tools-before") == plan["sdk_tools"],
            "gate lifecycle, Gradle configuration, or SDK tools changed before build")
    verified: dict[str, Any] = {}
    inventories: dict[str, Any] = {}
    remote_source_trees: dict[str, Any] = {}
    remote_post_source_records: dict[str, Any] = {}
    remote_output_inventories: dict[str, Any] = {}
    for lane in ("build-a", "build-b"):
        (verified[lane], inventories[lane], remote_source_trees[lane],
         remote_post_source_records[lane],
         remote_output_inventories[lane]) = build_lane(
            runner, output, lane, plan["remotes"][lane], expected,
            plan["gradle_user_home"]["configuration"], plan["gate"])
        require(source_records(ROOT, expected) == expected and
                source_records(output / lane / "source", expected) == expected and
                exact_source_tree(output / lane / "source", expected) ==
                    plan["source_tree_inventories"][lane],
                f"source changed during {lane}")
    comparison = parse_verifier(runner.run("compare-publications",
        plan["comparison_command"], timeout=120), comparison=True)
    gate_after = gate_row(runner, "gate-after")
    require(gate_after == plan["gate"] and
            gradle_config(runner, "gradle-config-after", gate_after) ==
                plan["gradle_user_home"]["configuration"] and
            sdk_tools(runner, "sdk-tools-after") == plan["sdk_tools"],
            "gate lifecycle, Gradle configuration, or SDK tools changed after build")
    local_after = {lane: exact_source_tree(output / lane / "source", expected)
                   for lane in ("build-a", "build-b")}
    require(source_records(ROOT, expected) == expected and all(
        source_records(output / lane / "source", expected) == expected and
        local_after[lane] == local_before[lane] == plan["source_tree_inventories"][lane]
        for lane in ("build-a", "build-b")), "source changed during publications")
    receipt = {
        "schema": 1,
        "kind": "wonad-sdk-3.0.1-two-independent-publications-receipt-v3",
        "status": "library_publication_reproducible_not_android_runtime_qualified",
        "plan": file_ref(plan_path),
        "helper": file_ref(Path(__file__).resolve()),
        "manifest": file_ref(SOURCE_MANIFEST),
        "gate": plan["gate"],
        "sdk_tools": plan["sdk_tools"],
        "verified": verified,
        "inventories": inventories,
        "local_source_tree_inventories": {"before": local_before, "after": local_after},
        "remote_pre_gradle_source_tree_inventories": remote_source_trees,
        "remote_post_gradle_selected_source_records": remote_post_source_records,
        "remote_post_gradle_output_inventories": remote_output_inventories,
        "gradle_user_home": plan["gradle_user_home"],
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
