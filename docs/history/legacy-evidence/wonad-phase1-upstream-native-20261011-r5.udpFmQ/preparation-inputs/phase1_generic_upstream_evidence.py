#!/usr/bin/env python3
"""Authenticate Phase-1 generic upstream plans and native machine results.

This is deliberately not a JUnit importer.  Commands come only from the
reviewed plan, Go host results are reconstructed from ``go test -json`` event
streams, and emulator results are delegated to the isolated schema-2 runner.
GrapheneOS-host applicability is a separate authenticated bounded native-source
audit, never a passing test. The actual GrapheneOS Secure Paste device overlap
is mandatory in the reviewed emulator plan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import sys

import phase1_upstream_test_comparison as atest_comparison
import run_phase1_upstream_tests as isolated_atest
import phase1_grapheneos_host_applicability as grapheneos_applicability


ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "android/platform/phase1-generic-upstream-plan-2026100600.json"
PLAN_SHA256 = "ba5c43e1bc2a2239aaf4677d483bb9d7eb3c62e0b9a6f94924a06bf503a1c386"
SCHEMA = 1
PLAN_KIND = "wonad-phase1-generic-upstream-plan"
HOST_KIND = "wonad-phase1-authenticated-native-host-run"
COMPARISON_KIND = "wonad-phase1-authenticated-generic-upstream-comparison"
POLICY = "matched-baseline-custom-native-machine-results-no-operator-commands"
RELEASE = "2026100600"
REQUIRED_CLASSES = frozenset({"grapheneos_host", "aosp_host", "aosp_emulator"})
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SHA1 = re.compile(r"[0-9a-f]{40}")
IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,63}")
MAX_JSON = 512 * 1024 * 1024
STATUS_SEVERITY = {"passed": 0, "skipped": 1, "failure": 2, "error": 3}
GO_ACTIONS = frozenset({"start", "run", "pause", "cont", "pass", "bench",
                        "fail", "output", "skip"})
GO_FIELDS = frozenset({"Time", "Action", "Package", "Test", "Elapsed", "Output",
                       "FailedBuild"})
HOST_ENVIRONMENT = frozenset({
    "CC", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_ENABLED",
    "CGO_LDFLAGS", "CXX", "DEBIAN_FRONTEND", "GOCACHE", "GOENV", "GOMODCACHE", "GOMAXPROCS", "GOMEMLIMIT", "GOPATH",
    "GOPROXY", "GOROOT", "HOME", "LANG", "LC_ALL", "PATH", "TMPDIR", "TZ",
})
HOST_RESOURCES = {"memory": 48 * 1024 ** 3, "memory_swap": 48 * 1024 ** 3,
                  "nano_cpus": 4 * 10 ** 9, "pids_limit": 4096}
HOST_MIN_AVAILABLE_MEMORY = 44 * 1024 ** 3


class EvidenceError(ValueError):
    """The plan or its machine evidence is malformed, stale, or incomplete."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "Duplicate JSON key: " + str(key))
        value[key] = item
    return value


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def stable_bytes(path: Path, *, maximum=MAX_JSON, allow_empty=False):
    path = Path(path)
    require(path.is_absolute(), "Evidence path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceError("Cannot safely open evidence: " + str(path)) from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum and
                (allow_empty or before.st_size > 0), "Invalid evidence file")
        chunks, total = [], 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            require(total <= maximum, "Evidence exceeds size limit")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = os.lstat(path)
    fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    require(all(getattr(before, field) == getattr(after, field) == getattr(current, field)
                for field in fields) and total == before.st_size,
            "Evidence changed while reading: " + str(path))
    return b"".join(chunks)


def load_json(path: Path):
    try:
        return json.loads(stable_bytes(path).decode("utf-8"), object_pairs_hook=strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError("Invalid JSON: " + str(path)) from error


def file_identity(path: Path, *, maximum=MAX_JSON, allow_empty=False):
    payload = stable_bytes(path, maximum=maximum, allow_empty=allow_empty)
    return {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}


def safe_relative(value, label):
    require(isinstance(value, str) and value and "\x00" not in value,
            "Invalid relative path: " + label)
    path = PurePosixPath(value)
    require(not path.is_absolute() and value == path.as_posix() and
            all(part not in ("", ".", "..") for part in path.parts),
            "Unsafe relative path: " + label)
    return path


def exact_keys(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys),
            label + " has unexpected fields")
    return value


def validate_hash_ref(value, label, *, value_field=False):
    keys = {"path", "sha256"} | ({"value"} if value_field else set())
    exact_keys(value, keys, label)
    safe_relative(value["path"], label)
    require(SHA256.fullmatch(str(value["sha256"])) is not None and
            (not value_field or isinstance(value["value"], str) and value["value"]),
            "Invalid source reference: " + label)
    return value


def _validate_placeholder(value, allowed, label):
    require(isinstance(value, str) and value and "\x00" not in value,
            "Invalid command/environment value: " + label)
    placeholders = set(re.findall(r"\{[a-z_]+\}", value))
    require(placeholders <= allowed, "Unknown placeholder in " + label)


def validate_plan(value):
    exact_keys(value, {"schema", "kind", "release", "policy", "classes"}, "generic plan")
    require(value["schema"] == SCHEMA and value["kind"] == PLAN_KIND and
            value["release"] == RELEASE and value["policy"] == POLICY and
            isinstance(value["classes"], list) and len(value["classes"]) == 3,
            "Unsupported generic upstream plan")
    rows = {}
    for row in value["classes"]:
        require(isinstance(row, dict) and row.get("class") in REQUIRED_CLASSES and
                row["class"] not in rows and IDENTIFIER.fullmatch(str(row.get("id", ""))) and
                row.get("state") in {"resolved", "not_applicable_source_declared"},
                "Malformed or duplicate generic coverage class")
        rows[row["class"]] = row
    require(set(rows) == REQUIRED_CLASSES, "Generic plan omits a required coverage class")

    graphene = rows["grapheneos_host"]
    exact_keys(graphene, {"id", "class", "state", "applicability_definition",
                          "result_protocol", "execution_profile"}, "GrapheneOS-host plan")
    reference = validate_hash_ref(graphene["applicability_definition"],
                                  "GrapheneOS applicability definition")
    require(graphene["state"] == "not_applicable_source_declared" and
            reference["path"] == grapheneos_applicability.DEFINITION.relative_to(ROOT).as_posix()
            and reference["sha256"] == grapheneos_applicability.DEFINITION_SHA256 and
            graphene["result_protocol"] == "pinned-source-native-applicability-scan-v1" and
            graphene["execution_profile"] ==
            "read-only-authenticated-source-inventory-no-test-execution",
            "GrapheneOS applicability differs from the reviewed bounded source audit")
    try:
        grapheneos_applicability.reviewed_definition()
    except (atest_comparison.EvidenceError, OSError) as error:
        raise EvidenceError("Invalid GrapheneOS applicability definition: " + str(error)) from error

    host = rows["aosp_host"]
    exact_keys(host, {"id", "class", "state", "modules", "source_definition",
                      "source_tools", "environment", "invocations", "minimum_cases",
                      "result_protocol", "execution_profile"}, "AOSP-host plan")
    require(host["state"] == "resolved" and host["result_protocol"] == "go-test-json-v1" and
            host["execution_profile"] ==
            "immutable-x86-builder-source-ro-fresh-test-out-network-none" and
            type(host["minimum_cases"]) is int and host["minimum_cases"] > 0 and
            isinstance(host["modules"], list) and len(host["modules"]) == 5 and
            isinstance(host["invocations"], list) and len(host["invocations"]) == 10 and
            isinstance(host["environment"], dict) and
            set(host["environment"]) == HOST_ENVIRONMENT and
            host["environment"]["GOMAXPROCS"] == "4" and
            host["environment"]["GOMEMLIMIT"] == "40GiB",
            "AOSP-host plan differs from its native-result contract")
    validate_hash_ref(host["source_definition"], "AOSP host source definition")
    require(isinstance(host["source_tools"], list) and len(host["source_tools"]) == 2,
            "AOSP host source tool set differs")
    for index, reference in enumerate(host["source_tools"]):
        validate_hash_ref(reference, "AOSP host source tool", value_field=index == 1)
    module_paths = set()
    for module in host["modules"]:
        exact_keys(module, {"path", "project_commit", "go_mod_sha256"}, "AOSP Go module")
        path = safe_relative(module["path"], "AOSP Go module")
        require(path.as_posix() not in module_paths and
                GIT_SHA1.fullmatch(str(module["project_commit"])) and
                SHA256.fullmatch(str(module["go_mod_sha256"])), "Invalid AOSP Go module")
        module_paths.add(path.as_posix())
    for name, item in host["environment"].items():
        _validate_placeholder(item, {"{source}", "{test_out}"}, "host environment " + name)
    invocation_ids = set()
    counts = {path: 0 for path in module_paths}
    for invocation in host["invocations"]:
        exact_keys(invocation, {"id", "argv", "cwd"}, "AOSP host invocation")
        identifier = invocation["id"]
        require(IDENTIFIER.fullmatch(str(identifier)) and identifier not in invocation_ids and
                isinstance(invocation["argv"], list) and invocation["argv"] and
                all(isinstance(item, str) and item for item in invocation["argv"]),
                "Invalid or duplicate AOSP host invocation")
        invocation_ids.add(identifier)
        cwd = invocation["cwd"]
        _validate_placeholder(cwd, {"{source}"}, "host invocation cwd")
        require(cwd.startswith("{source}/") and cwd[len("{source}/"):] in module_paths and
                invocation["argv"][0] == "{source}/prebuilts/go/linux-x86/bin/go" and
                invocation["argv"][1:4] == ["test", "-json", "-count=1"] and
                invocation["argv"][-1] == "./..." and
                invocation["argv"][4:-1] in (["-p=1"], ["-p=1", "-race", "-timeout", "30m", "-short"]),
                "AOSP host command is not the reviewed source-pinned Go invocation")
        counts[cwd[len("{source}/"):]] += 1
    require(set(counts.values()) == {2}, "Each AOSP Go module needs normal and race invocations")

    emulator = rows["aosp_emulator"]
    exact_keys(emulator, {"id", "class", "state", "module_plan", "runner", "command",
                          "minimum_cases", "result_protocol", "execution_profile"},
               "AOSP-emulator plan")
    require(emulator["state"] == "resolved" and
            emulator["result_protocol"] == "wonad-isolated-atest-schema-2" and
            emulator["execution_profile"] ==
            "wonad-phase1-isolated-upstream-test-run-schema-2" and
            emulator["runner"] == "android/tools/run_phase1_upstream_tests.py" and
            type(emulator["minimum_cases"]) is int and emulator["minimum_cases"] > 0 and
            isinstance(emulator["command"], list) and emulator["command"] and
            all(isinstance(item, str) and item for item in emulator["command"]),
            "AOSP-emulator plan differs from the isolated schema-2 runner")
    validate_hash_ref(emulator["module_plan"], "AOSP emulator module plan")
    for item in emulator["command"]:
        _validate_placeholder(item, {"{role}", "{build_receipt}",
                                     "{build_receipt_sha256}", "{fresh_test_out}",
                                     "{fresh_output}"}, "emulator command")
    return value


def reviewed_plan(path: Path = PLAN):
    path = Path(path)
    require(path.resolve(strict=True) == PLAN.resolve(strict=True) and not path.is_symlink(),
            "Only the repository-reviewed generic plan may be selected")
    require(file_identity(path)["sha256"] == PLAN_SHA256,
            "Reviewed generic plan bytes changed without updating the verifier")
    return validate_plan(load_json(path))


def class_row(plan, test_class):
    rows = [row for row in plan["classes"] if row["class"] == test_class]
    require(len(rows) == 1, "Plan lacks one exact coverage class: " + test_class)
    return rows[0]


def _source_path(source: Path, relative: str, label: str):
    source = Path(source).resolve(strict=True)
    parts = safe_relative(relative, label).parts
    current = source
    for index, part in enumerate(parts):
        current = current / part
        node = current.lstat()
        require(not stat.S_ISLNK(node.st_mode), label + " traverses a symlink")
        require(stat.S_ISDIR(node.st_mode) if index + 1 < len(parts)
                else stat.S_ISREG(node.st_mode), "Invalid source definition: " + label)
    return current


def authenticate_source_bindings(plan, source: Path, source_pin):
    """Bind plan modules/tools to one already-authenticated receipt source pin."""
    validate_plan(plan)
    require(isinstance(source_pin, dict) and source_pin.get("release") == RELEASE and
            isinstance(source_pin.get("projects"), list),
            "Build receipt lacks the pinned project ledger")
    projects = {row.get("path"): row.get("revision") for row in source_pin["projects"]
                if isinstance(row, dict)}
    require(len(projects) == len(source_pin["projects"]), "Pinned project ledger is ambiguous")

    def check(reference, label):
        path = _source_path(source, reference["path"], label)
        require(file_identity(path)["sha256"] == reference["sha256"],
                label + " differs from the reviewed source bytes")

    try:
        definition = grapheneos_applicability.reviewed_definition()
        grapheneos_applicability.validate_scan(
            grapheneos_applicability.scan_source(source, source_pin, definition), definition)
    except (atest_comparison.EvidenceError, OSError) as error:
        raise EvidenceError("GrapheneOS applicability source differs: " + str(error)) from error

    host = class_row(plan, "aosp_host")
    check(host["source_definition"], "AOSP host source definition")
    for row in host["source_tools"]:
        check(row, "AOSP host source tool")
    for module in host["modules"]:
        project = "build/make" if module["path"].startswith("build/make/") else module["path"]
        require(projects.get(project) == module["project_commit"],
                "AOSP host module project differs from the receipt pin: " + module["path"])
        check({"path": module["path"] + "/go.mod", "sha256": module["go_mod_sha256"]},
              "AOSP host go.mod")

    emulator = class_row(plan, "aosp_emulator")
    module_plan = _source_path(ROOT, emulator["module_plan"]["path"],
                               "reviewed emulator module plan")
    require(file_identity(module_plan)["sha256"] == emulator["module_plan"]["sha256"],
            "Reviewed emulator module plan bytes changed")
    _source_path(ROOT, emulator["runner"], "reviewed isolated Atest runner")
    return {"source_pin_sha256": canonical_digest(source_pin),
            "plan_sha256": PLAN_SHA256, "classes": sorted(REQUIRED_CLASSES)}


def parse_go_json_payload(payload: bytes, invocation_id: str, exit_code: int):
    require(IDENTIFIER.fullmatch(str(invocation_id)) is not None and
            type(exit_code) is int and 0 <= exit_code <= 255 and payload,
            "Invalid Go native-result invocation")
    packages = set()
    package_terminal = {}
    test_started = set()
    test_terminal = {}
    saw_start = False
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError("Go native result is not UTF-8") from error
    lines = text.splitlines()
    require(lines and all(line.strip() for line in lines),
            "Go native result contains an empty/non-event line")
    for ordinal, line in enumerate(lines, 1):
        try:
            event = json.loads(line, object_pairs_hook=strict_object)
        except json.JSONDecodeError as error:
            raise EvidenceError("Go native result contains prose or invalid JSON at line " +
                                str(ordinal)) from error
        require(isinstance(event, dict) and set(event) <= GO_FIELDS and
                isinstance(event.get("Action"), str) and event["Action"] in GO_ACTIONS and
                isinstance(event.get("Package"), str) and event["Package"],
                "Malformed Go native event at line " + str(ordinal))
        package = event["Package"]
        test = event.get("Test")
        action = event["Action"]
        require(test is None or isinstance(test, str) and test,
                "Malformed Go test identity")
        packages.add(package)
        if test is None:
            if action == "start":
                require(package not in package_terminal, "Go package restarts after termination")
                saw_start = True
            elif action in {"pass", "fail", "skip"}:
                require(package not in package_terminal,
                        "Go package has duplicate terminal events: " + package)
                package_terminal[package] = {
                    "pass": "passed", "fail": "failure", "skip": "skipped"}[action]
        else:
            key = (package, test)
            if action == "run":
                require(key not in test_started and key not in test_terminal,
                        "Go test has duplicate run event")
                test_started.add(key)
            elif action in {"pass", "fail", "skip"}:
                require(key in test_started and key not in test_terminal,
                        "Go test terminal event lacks one unique run event")
                test_terminal[key] = {
                    "pass": "passed", "fail": "failure", "skip": "skipped"}[action]
    require(saw_start and packages and set(package_terminal) == packages and
            test_started == set(test_terminal),
            "Go native result is empty or lacks complete package/test terminals")
    cases = {}
    for package, status in package_terminal.items():
        cases[invocation_id + "/" + package + "::<package>"] = status
    for (package, test), status in test_terminal.items():
        identity = invocation_id + "/" + package + "#" + test
        require(identity not in cases, "Duplicate normalized Go test identity")
        cases[identity] = status
    failed = any(status in {"failure", "error"} for status in cases.values())
    require((exit_code == 0) == (not failed),
            "Go command exit status differs from native terminal events")
    return dict(sorted(cases.items()))


def parse_go_json(path: Path, invocation_id: str, exit_code: int):
    return parse_go_json_payload(stable_bytes(Path(path)), invocation_id, exit_code)


def require_executed_go_test(cases, invocation_id):
    require(any("#" in identity for identity in cases),
            "Native host invocation contains no executed test cases: " + invocation_id)


def normalize_emulator(receipt_path: Path, expected_sha256: str):
    """Rebuild an emulator class ledger from an authenticated schema-2 bundle."""
    try:
        value = atest_comparison.authenticated_run(Path(receipt_path), expected_sha256)
    except (atest_comparison.EvidenceError, OSError) as error:
        raise EvidenceError("Invalid authenticated emulator run: " + str(error)) from error
    cases = {}
    for suite, row in sorted(value["suites"].items()):
        for identity, status in row["cases"].items():
            name = suite + "/" + identity
            require(name not in cases, "Duplicate emulator case identity")
            cases[name] = status
    minimum = class_row(reviewed_plan(), "aosp_emulator")["minimum_cases"]
    require(len(cases) >= minimum, "Authenticated emulator run is unexpectedly empty")
    build = value["build"]
    return {
        "class": "aosp_emulator", "role": value["role"],
        "source_pin_sha256": build["source_pin_sha256"],
        "build_receipt": {key: build["receipt"][key] for key in ("sha256", "size")},
        "plan_sha256": PLAN_SHA256,
        "authority": value["authority"],
        "module_plan_sha256": value["plan_sha256"],
        "cases": dict(sorted(cases.items())),
        "native_protocol": "wonad-isolated-atest-schema-2",
        "receipt_sha256": expected_sha256,
    }


def normalize_host_invocations(plan, invocations):
    """Produce cases from captured native streams; callers cannot supply failures."""
    host = class_row(validate_plan(plan), "aosp_host")
    require(isinstance(invocations, dict) and
            set(invocations) == {row["id"] for row in host["invocations"]},
            "AOSP host evidence omits or adds a reviewed invocation")
    cases = {}
    normalized = {}
    for command in host["invocations"]:
        identifier = command["id"]
        row = invocations[identifier]
        exact_keys(row, {"argv", "cwd", "environment", "completed", "timed_out",
                         "exit_code", "raw"}, "AOSP host execution")
        require(row["argv"] == command["argv"] and row["cwd"] == command["cwd"] and
                row["environment"] == host["environment"] and row["completed"] is True and
                row["timed_out"] is False and type(row["exit_code"]) is int and
                0 <= row["exit_code"] <= 255 and isinstance(row["raw"], bytes),
                "AOSP host execution differs from the reviewed command")
        parsed = parse_go_json_payload(row["raw"], identifier, row["exit_code"])
        require_executed_go_test(parsed, identifier)
        for identity, status in parsed.items():
            require(identity not in cases, "Duplicate case across host invocations")
            cases[identity] = status
        normalized[identifier] = {
            "exit_code": row["exit_code"], "case_count": len(parsed),
            "raw_sha256": hashlib.sha256(row["raw"]).hexdigest(),
            "raw_size": len(row["raw"]),
        }
    require(len(cases) >= host["minimum_cases"], "AOSP host native evidence is empty")
    return {"cases": dict(sorted(cases.items())), "invocations": normalized}


def expand_host_plan(plan, build):
    host = class_row(validate_plan(plan), "aosp_host")
    environment = {key: value.replace("{source}", isolated_atest.CONTAINER_SOURCE)
                   .replace("{test_out}", isolated_atest.CONTAINER_TEST)
                   for key, value in host["environment"].items()}
    require(set(environment) == HOST_ENVIRONMENT and
            all(build["source_root"] not in value and build["out_dir"] not in value
                for value in environment.values()),
            "Effective host environment exposes a protected host tree")
    commands = {}
    for row in host["invocations"]:
        argv = [item.replace("{source}", isolated_atest.CONTAINER_SOURCE)
                .replace("{test_out}", isolated_atest.CONTAINER_TEST) for item in row["argv"]]
        cwd = row["cwd"].replace("{source}", isolated_atest.CONTAINER_SOURCE)
        require(cwd.startswith(isolated_atest.CONTAINER_SOURCE + "/") and
                all(build["source_root"] not in item and build["out_dir"] not in item
                    for item in [cwd, *argv]),
                "Effective host command exposes a protected host tree")
        commands[row["id"]] = {"argv": argv, "cwd": cwd,
                                "environment": dict(sorted(environment.items()))}
    return commands


def host_docker_argv(spec):
    environment = []
    for key, value in sorted(spec["environment"].items()):
        environment += ["--env", key + "=" + value]
    return [
        str(isolated_atest.DOCKER), "--host", isolated_atest.locality.ENDPOINT,
        "run", "--name", spec["name"], "--platform", "linux/amd64", "--pull", "never",
        "--network", "none", "--read-only", "--user", spec["user"],
        "--workdir", spec["cwd"], "--cap-drop", "ALL", "--security-opt",
        "no-new-privileges:true", "--security-opt", "label=disable", "--restart", "no",
        "--cpus", "4", "--memory", str(HOST_RESOURCES["memory"]),
        "--memory-swap", str(HOST_RESOURCES["memory_swap"]),
        "--pids-limit", "4096", "--hostname", "wonad-host-tests",
        "--label", "org.wonad.phase1.nonce=" + spec["nonce"],
        "--label", "org.wonad.phase1.class=aosp_host",
        "--label", "org.wonad.phase1.invocation=" + spec["invocation"],
        "--mount", "type=bind,src=" + spec["source"] + ",dst=" +
        isolated_atest.CONTAINER_SOURCE + ",readonly,bind-propagation=rprivate",
        "--mount", "type=bind,src=" + spec["workspace"] + ",dst=" +
        isolated_atest.CONTAINER_TEST + ",readonly=false,bind-propagation=rprivate",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=268435456",
        *environment, "--entrypoint", "/usr/bin/env", spec["image"], "-i",
        *[key + "=" + value for key, value in sorted(spec["environment"].items())],
        *spec["argv"],
    ]


class HostProductionBackend(isolated_atest.ProductionBackend):
    def run_host_container(self, spec, stdout_path: Path, timeout: int):
        if spec["invocation"] == "soong":
            require_host_memory()
        argv = host_docker_argv(spec)
        stream = stdout_path.open("xb")
        process = subprocess.Popen(argv, env=self.environment, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._docker(["stop", "--time", "10", spec["name"]], timeout=30)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._docker(["kill", spec["name"]], timeout=30)
                process.wait(timeout=15)
        finally:
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
        return {"exit_code": process.returncode, "timed_out": timed_out,
                "docker_argv": argv}


def require_host_memory():
    """Do not crowd a live OS build with the full, non-short Zip64 tests."""
    values = re.findall(r"^MemAvailable:\s+([0-9]+)\s+kB$",
                        Path("/proc/meminfo").read_text(), re.M)
    require(len(values) == 1 and int(values[0]) * 1024 >= HOST_MIN_AVAILABLE_MEMORY,
            "Full AOSP-host tests require at least 44 GiB available RAM; wait for competing builds to finish")


def make_host_spec(command, build, source, workspace, prefix, nonce, invocation):
    name = prefix + "-" + invocation + "-" + nonce[:12]
    require(isolated_atest.NAME.fullmatch(name) is not None,
            "Invalid host-test container name")
    require(os.getuid() != 0, "Refusing to run host-test containers as root")
    return {
        "name": name, "nonce": nonce, "invocation": invocation,
        "image": build["builder_image"]["id"], "user": f"{os.getuid()}:{os.getgid()}",
        "source": str(source), "workspace": str(workspace), "argv": command["argv"],
        "cwd": command["cwd"], "environment": command["environment"],
        "resources": dict(HOST_RESOURCES),
    }


def validate_host_container(raw, spec, exit_code):
    row = isolated_atest.container_projection(raw)
    host_config = raw.get("HostConfig", {})
    resources = {key: host_config.get(field) for key, field in
                 (("memory", "Memory"), ("memory_swap", "MemorySwap"),
                  ("nano_cpus", "NanoCpus"), ("pids_limit", "PidsLimit"))}
    require(resources == spec.get("resources") == HOST_RESOURCES,
            "Host-test container differs from the sealed resource bounds")
    row["resources"] = resources
    expected_environment = sorted(key + "=" + value
                                  for key, value in spec["environment"].items())
    expected_mounts = sorted([
        {"type": "bind", "source": spec["source"],
         "destination": isolated_atest.CONTAINER_SOURCE, "rw": False,
         "propagation": "rprivate"},
        {"type": "bind", "source": spec["workspace"],
         "destination": isolated_atest.CONTAINER_TEST, "rw": True,
         "propagation": "rprivate"},
    ], key=lambda item: item["destination"])
    security = set(row["security_opt"])
    require(re.fullmatch(r"[0-9a-f]{64}", str(row["id"])) is not None and
            row["name"] == spec["name"] and row["image"] == spec["image"] and
            row["config_image"] == spec["image"] and row["entrypoint"] == ["/usr/bin/env"] and
            row["cmd"] == ["-i", *expected_environment, *spec["argv"]] and
            row["user"] == spec["user"] and row["working_dir"] == spec["cwd"] and
            row["environment"] == expected_environment and row["labels"] == {
                "org.wonad.phase1.nonce": spec["nonce"],
                "org.wonad.phase1.class": "aosp_host",
                "org.wonad.phase1.invocation": spec["invocation"]} and
            row["network_mode"] == "none" and row["read_only"] is True and
            row["privileged"] is False and row["cap_drop"] == ["ALL"] and
            ("no-new-privileges:true" in security or "no-new-privileges" in security) and
            "label=disable" in security and not row["devices"] and
            not row["device_requests"] and
            row["restart"] == {"Name": "no", "MaximumRetryCount": 0} and
            row["auto_remove"] is False and row["mounts"] == expected_mounts and
            row["tmpfs"] == {"/tmp": "rw,nosuid,nodev,noexec,mode=1777,size=268435456"} and
            row["running"] is False and row["restarting"] is False and
            row["dead"] is False and row["oom_killed"] is False and
            row["exit_code"] == exit_code,
            "Host-test container differs from the sealed isolation profile")
    return row


def cleanup_host_container(backend, spec):
    if backend.container_absent(spec["name"]):
        return
    raw = backend.inspect_container(spec["name"])
    row = isolated_atest.container_projection(raw)
    require(re.fullmatch(r"[0-9a-f]{64}", str(row["id"])) is not None and
            row["name"] == spec["name"] and row["image"] == spec["image"] and
            row["labels"].get("org.wonad.phase1.nonce") == spec["nonce"],
            "Cannot bind interrupted host-test container to its cleanup identity")
    backend.remove_container(row["id"])
    require(backend.container_absent(row["id"]) and
            backend.container_absent(spec["name"]),
            "Interrupted host-test container was not removed")


def run_host_invocation(backend, identifier, command, build, source, workspace,
                        output, prefix, timeout, nonce):
    destination = output / "invocations" / identifier
    destination.mkdir(mode=0o700, parents=True)
    raw_path = destination / "go-test.jsonl"
    spec = make_host_spec(command, build, source, workspace, prefix, nonce, identifier)
    try:
        execution = backend.run_host_container(spec, raw_path, timeout)
        require(not backend.container_absent(spec["name"]),
                "AOSP-host Docker invocation did not create a container (exit=" +
                str(execution["exit_code"]) + "); original output retained in " + str(raw_path))
        raw = backend.inspect_container(spec["name"])
    except BaseException:
        cleanup_host_container(backend, spec)
        raise
    identity = isolated_atest.container_projection(raw)
    require(re.fullmatch(r"[0-9a-f]{64}", str(identity["id"])) is not None and
            identity["name"] == spec["name"] and identity["image"] == spec["image"] and
            identity["labels"].get("org.wonad.phase1.nonce") == spec["nonce"],
            "Cannot bind host-test container to its cleanup identity")
    container_id = identity["id"]
    record = None
    removed = None
    try:
        observed = validate_host_container(raw, spec, execution["exit_code"])
        require(not execution["timed_out"], "AOSP host invocation timed out: " + identifier)
        cases = parse_go_json(raw_path, identifier, execution["exit_code"])
        require_executed_go_test(cases, identifier)
        record = {"schema": SCHEMA, "kind": "wonad-phase1-native-host-container",
                  "spec": spec, "docker_argv": execution["docker_argv"],
                  "observed": observed, "timed_out": False}
    except BaseException as error:
        try:
            isolated_atest.write_json_new(destination / "failure-observation.json", {
                "schema": SCHEMA, "kind": "wonad-phase1-failed-host-invocation-observation",
                "qualification_claimed": False, "spec": spec, "execution": execution,
                "inspect": raw, "failure": {"type": type(error).__name__, "message": str(error)},
            })
        except Exception as storage_error:
            error.add_note("Could not retain failure observation: " + str(storage_error))
        raise
    finally:
        backend.remove_container(container_id)
        removed = {"container_id": container_id, "name": spec["name"],
                   "id_absent": backend.container_absent(container_id),
                   "name_absent": backend.container_absent(spec["name"])}
        require(removed["id_absent"] and removed["name_absent"],
                "Exact host-test container was not removed")
    record["cleanup"] = removed
    container_path = destination / "container.json"
    isolated_atest.write_json_new(container_path, record)
    return {"case_count": len(cases), "cases": cases, "exit_code": execution["exit_code"],
            "raw": isolated_atest.portable_ref(output, raw_path, allow_empty=False),
            "container": isolated_atest.portable_ref(output, container_path, allow_empty=False)}


def host_receipt_shape(value):
    exact_keys(value, {"schema", "kind", "release", "role", "class", "plan", "build",
                       "builder", "protected_inputs", "source_binding", "isolation",
                       "cleanup", "invocations", "generator"}, "native host receipt")
    require(value["schema"] == SCHEMA and value["kind"] == HOST_KIND and
            value["release"] == RELEASE and value["role"] in {"baseline", "custom"} and
            value["class"] == "aosp_host" and isinstance(value["invocations"], dict),
            "Unsupported native host receipt")
    exact_keys(value["plan"], {"file", "sha256"}, "native host plan binding")
    exact_keys(value["build"], {"receipt", "authenticated_sha256", "before", "after"},
               "native host build binding")
    exact_keys(value["builder"], {"id", "before", "after", "docker_before", "docker_after"},
               "native host builder binding")
    require(value["plan"]["sha256"] == PLAN_SHA256 and
            SHA256.fullmatch(str(value["build"]["authenticated_sha256"])) and
            isolated_atest.IMAGE_ID.fullmatch(str(value["builder"]["id"])),
            "Native host receipt contains an invalid immutable binding")
    return value


def run_aosp_host(role: str, build_receipt: Path, build_sha256: str, test_out: Path,
                  output: Path, container_prefix: str, timeout: int, *, backend=None):
    require(role in {"baseline", "custom"} and type(timeout) is int and
            60 <= timeout <= isolated_atest.MAX_TIMEOUT and
            isolated_atest.NAME.fullmatch(container_prefix) is not None,
            "Invalid fixed AOSP-host execution parameters")
    plan = reviewed_plan()
    production = backend is None
    backend = HostProductionBackend() if production else backend
    if production:
        require_host_memory()
    docker_before = backend.docker_identity()
    if production:
        isolated_atest.locality.reject_overrides()
        selected_docker = shutil.which("docker")
        require(selected_docker is not None and
                Path(selected_docker).resolve(strict=True) == isolated_atest.DOCKER,
                "PATH does not select the audited /usr/bin/docker")
    receipt_before, build_before = isolated_atest.full_build_verify(
        Path(build_receipt), build_sha256, role)
    source, build_out, test_out, output = isolated_atest.safe_roots(
        Path(build_before["source_root"]), Path(build_before["out_dir"]),
        Path(test_out), Path(output))
    require(receipt_before["source"]["pin"]["release"] == RELEASE,
            "AOSP-host build receipt uses another release")
    source_binding = authenticate_source_bindings(plan, source,
                                                  receipt_before["source"]["pin"])
    source_before = isolated_atest.source_freeze_verify(receipt_before, build_before)
    out_before = isolated_atest.protected_tree_inventory(build_out)
    image_before = isolated_atest.normalize_image(
        backend.inspect_image(build_before["builder_image"]["id"]))
    require(image_before == build_before["builder_image"],
            "Installed builder image differs from the receipted image")
    commands = expand_host_plan(plan, build_before)

    output.mkdir(mode=0o700)
    (output / "inputs").mkdir(mode=0o700)
    isolated_atest.copy_new(Path(build_receipt), output / "inputs/build-receipt.json")
    isolated_atest.copy_new(PLAN, output / "inputs/plan.json")
    isolated_atest.copy_new(Path(__file__).resolve(), output / "inputs/generator.py")
    for name, value in (("build-before.json", build_before),
                        ("source-freeze-before.json", source_before),
                        ("build-out-before.json", out_before),
                        ("builder-before.json", image_before),
                        ("source-binding.json", source_binding),
                        ("docker-before.json", docker_before)):
        isolated_atest.write_json_new(output / name, value)

    test_out.mkdir(mode=0o700)
    node = test_out.lstat()
    nonce = secrets.token_hex(16)
    ownership = {"path": str(test_out), "device": node.st_dev, "inode": node.st_ino,
                 "uid": node.st_uid, "gid": node.st_gid, "nonce": nonce}
    isolated_atest.write_bytes_new(test_out / ".wonad-atest-owner", (nonce + "\n").encode())
    for name in ("home", "tmp", "gocache", "gomodcache", "gopath"):
        (test_out / name).mkdir(mode=0o700)
    invocations = {}
    failure = None
    cleanup = None
    try:
        for identifier, command in commands.items():
            invocations[identifier] = run_host_invocation(
                backend, identifier, command, build_before, source, test_out, output,
                container_prefix, timeout, nonce)
    except BaseException as error:
        failure = error
    finally:
        try:
            cleanup = isolated_atest.cleanup_workspace(test_out, ownership)
            isolated_atest.write_json_new(output / "cleanup.json", cleanup)
        except BaseException as cleanup_error:
            if failure is None:
                failure = cleanup_error
    if failure is not None:
        raise failure

    receipt_after, build_after = isolated_atest.full_build_verify(
        Path(build_receipt), build_sha256, role)
    require(receipt_after == receipt_before and build_after == build_before,
            "Build receipt changed during AOSP-host tests")
    source_after = isolated_atest.source_freeze_verify(receipt_after, build_after)
    out_after = isolated_atest.protected_tree_inventory(build_out)
    image_after = isolated_atest.normalize_image(
        backend.inspect_image(build_after["builder_image"]["id"]))
    docker_after = backend.docker_identity()
    require(source_after == source_before,
            "Receipted source freeze changed during AOSP-host execution")
    require(out_after == out_before,
            "Complete current receipted OUT inventory changed during AOSP-host execution")
    require(image_after == image_before and docker_after == docker_before,
            "Builder image or Docker identity changed during AOSP-host execution")
    require(authenticate_source_bindings(plan, source, receipt_after["source"]["pin"]) ==
            source_binding, "Source-pinned host modules changed during execution")
    for name, value in (("build-after.json", build_after),
                        ("source-freeze-after.json", source_after),
                        ("build-out-after.json", out_after),
                        ("builder-after.json", image_after),
                        ("docker-after.json", docker_after)):
        isolated_atest.write_json_new(output / name, value)

    receipt = {
        "schema": SCHEMA, "kind": HOST_KIND, "release": RELEASE, "role": role,
        "class": "aosp_host",
        "plan": {"file": isolated_atest.portable_ref(output, output / "inputs/plan.json"),
                 "sha256": PLAN_SHA256},
        "build": {
            "receipt": isolated_atest.portable_ref(output, output / "inputs/build-receipt.json"),
            "authenticated_sha256": build_sha256,
            "before": isolated_atest.portable_ref(output, output / "build-before.json"),
            "after": isolated_atest.portable_ref(output, output / "build-after.json")},
        "builder": {"id": image_before["id"],
                    "before": isolated_atest.portable_ref(output, output / "builder-before.json"),
                    "after": isolated_atest.portable_ref(output, output / "builder-after.json"),
                    "docker_before": isolated_atest.portable_ref(output, output / "docker-before.json"),
                    "docker_after": isolated_atest.portable_ref(output, output / "docker-after.json")},
        "protected_inputs": {
            "source_before": isolated_atest.portable_ref(output, output / "source-freeze-before.json"),
            "source_after": isolated_atest.portable_ref(output, output / "source-freeze-after.json"),
            "out_before": isolated_atest.portable_ref(output, output / "build-out-before.json"),
            "out_after": isolated_atest.portable_ref(output, output / "build-out-after.json")},
        "source_binding": isolated_atest.portable_ref(output, output / "source-binding.json"),
        "isolation": {"source": "read-only", "receipted_out": "not-mounted",
                      "test_out": "sole-writable-host-bind", "network": "none",
                      "rootfs": "read-only", "capabilities": "none",
                      "no_new_privileges": True, "container_per_invocation": True},
        "cleanup": isolated_atest.portable_ref(output, output / "cleanup.json"),
        "invocations": invocations,
        "generator": isolated_atest.portable_ref(output, output / "inputs/generator.py"),
    }
    host_receipt_shape(receipt)
    candidate = output / (".host-receipt-candidate-" + nonce + ".json")
    isolated_atest.write_json_new(candidate, receipt)
    digest = file_identity(candidate)["sha256"]
    try:
        verify_host(candidate, digest, rehash_build=False)
    except BaseException:
        candidate.unlink(missing_ok=True)
        isolated_atest.fsync_directory(output)
        raise
    final = output / "host-run-receipt.json"
    os.rename(candidate, final)
    isolated_atest.fsync_directory(output)
    return final, digest


def _portable_json(root, reference, label):
    return load_json(isolated_atest.resolve_ref(root, reference, label, allow_empty=False))


def validate_host_container_evidence(record, expected_spec, exit_code):
    exact_keys(record, {"schema", "kind", "spec", "docker_argv", "observed", "timed_out",
                        "cleanup"}, "host container evidence")
    require(record["schema"] == SCHEMA and
            record["kind"] == "wonad-phase1-native-host-container" and
            record["spec"] == expected_spec and record["docker_argv"] ==
            host_docker_argv(expected_spec) and record["timed_out"] is False,
            "Host container record differs from the reviewed execution")
    row = record["observed"]
    require(isinstance(row, dict) and row.get("resources") ==
            expected_spec.get("resources") == HOST_RESOURCES,
            "Host container evidence lacks the sealed resource bounds")
    mounts = row.get("mounts", []) if isinstance(row, dict) else []
    expected_environment = sorted(key + "=" + value
                                  for key, value in expected_spec["environment"].items())
    security = set(row.get("security_opt", []))
    expected_mounts = sorted([
        {"type": "bind", "source": expected_spec["source"],
         "destination": isolated_atest.CONTAINER_SOURCE, "rw": False,
         "propagation": "rprivate"},
        {"type": "bind", "source": expected_spec["workspace"],
         "destination": isolated_atest.CONTAINER_TEST, "rw": True,
         "propagation": "rprivate"},
    ], key=lambda item: item["destination"])
    require(re.fullmatch(r"[0-9a-f]{64}", str(row.get("id", ""))) is not None and
            row.get("name") == expected_spec["name"] and
            row.get("image") == expected_spec["image"] and
            row.get("config_image") == expected_spec["image"] and
            row.get("entrypoint") == ["/usr/bin/env"] and
            row.get("cmd") == ["-i", *expected_environment, *expected_spec["argv"]] and
            row.get("working_dir") == expected_spec["cwd"] and
            row.get("user") == expected_spec["user"] and
            row.get("environment") == expected_environment and
            row.get("labels") == {"org.wonad.phase1.nonce": expected_spec["nonce"],
                                  "org.wonad.phase1.class": "aosp_host",
                                  "org.wonad.phase1.invocation": expected_spec["invocation"]} and
            row.get("network_mode") == "none" and row.get("read_only") is True and
            row.get("privileged") is False and row.get("cap_drop") == ["ALL"] and
            ("no-new-privileges:true" in security or "no-new-privileges" in security) and
            "label=disable" in security and
            not row.get("devices") and not row.get("device_requests") and
            row.get("restart") == {"Name": "no", "MaximumRetryCount": 0} and
            row.get("auto_remove") is False and
            row.get("tmpfs") == {
                "/tmp": "rw,nosuid,nodev,noexec,mode=1777,size=268435456"} and
            row.get("running") is False and row.get("restarting") is False and
            row.get("dead") is False and row.get("oom_killed") is False and
            row.get("exit_code") == exit_code and mounts == expected_mounts,
            "Observed host container lost the sealed isolation profile")
    cleanup = record["cleanup"]
    require(cleanup == {"container_id": row.get("id"), "name": row.get("name"),
                        "id_absent": True, "name_absent": True},
            "Host container cleanup evidence is incomplete")
    return record


def verify_host(receipt_path: Path, expected_sha256: str, *, rehash_build=True):
    receipt_path = Path(receipt_path)
    require(receipt_path.is_absolute() and SHA256.fullmatch(str(expected_sha256)) and
            file_identity(receipt_path)["sha256"] == expected_sha256,
            "Native host receipt differs from its out-of-band SHA-256")
    root = receipt_path.parent
    value = host_receipt_shape(load_json(receipt_path))
    generator = isolated_atest.resolve_ref(root, value["generator"], "host generator",
                                           allow_empty=False)
    require(file_identity(generator) == file_identity(Path(__file__).resolve()),
            "Native host generator differs from the reviewed tool")

    plan_path = isolated_atest.resolve_ref(root, value["plan"]["file"], "generic plan",
                                           allow_empty=False)
    require(value["plan"]["sha256"] == PLAN_SHA256 and
            file_identity(plan_path)["sha256"] == PLAN_SHA256 and
            validate_plan(load_json(plan_path)) == reviewed_plan(),
            "Native host receipt selects a different reviewed plan")
    build_before = _portable_json(root, value["build"]["before"], "host build before")
    build_after = _portable_json(root, value["build"]["after"], "host build after")
    copied_build = isolated_atest.resolve_ref(root, value["build"]["receipt"],
                                              "host build receipt", allow_empty=False)
    copied_value = load_json(copied_build)
    require(build_before == build_after and
            value["build"]["authenticated_sha256"] ==
            value["build"]["receipt"]["sha256"] == build_before["receipt_sha256"] and
            copied_value.get("source", {}).get("pin") is not None,
            "Native host build bindings differ")
    image_before = _portable_json(root, value["builder"]["before"], "host builder before")
    image_after = _portable_json(root, value["builder"]["after"], "host builder after")
    docker_before = _portable_json(root, value["builder"]["docker_before"],
                                   "host Docker before")
    docker_after = _portable_json(root, value["builder"]["docker_after"],
                                  "host Docker after")
    require(image_before == image_after == build_before["builder_image"] and
            value["builder"]["id"] == image_before["id"] and
            docker_before == docker_after,
            "Native host builder or Docker identity changed")

    protected = value["protected_inputs"]
    exact_keys(protected, {"source_before", "source_after", "out_before", "out_after"},
               "host protected inputs")
    source_before = _portable_json(root, protected["source_before"], "host source before")
    source_after = _portable_json(root, protected["source_after"], "host source after")
    out_before = isolated_atest.validate_protected_inventory(
        _portable_json(root, protected["out_before"], "host OUT before"))
    out_after = isolated_atest.validate_protected_inventory(
        _portable_json(root, protected["out_after"], "host OUT after"))
    require(source_before == source_after and out_before == out_after and
            source_before.get("snapshot") == copied_value["source"] and
            source_before.get("snapshot_sha256") == canonical_digest(copied_value["source"]),
            "Native host source or complete OUT inventory changed")
    binding = _portable_json(root, value["source_binding"], "host source binding")
    require(binding == {"source_pin_sha256": canonical_digest(copied_value["source"]["pin"]),
                        "plan_sha256": PLAN_SHA256,
                        "classes": sorted(REQUIRED_CLASSES)},
            "Native host source-module binding differs")
    cleanup = _portable_json(root, value["cleanup"], "host cleanup")
    require(cleanup.get("workspace_absent") is True and
            cleanup.get("quarantine_absent") is True and
            cleanup.get("method") == "same-parent-rename-then-rmtree",
            "Native host disposable workspace cleanup is incomplete")
    require(value["isolation"] == {
                "source": "read-only", "receipted_out": "not-mounted",
                "test_out": "sole-writable-host-bind", "network": "none",
                "rootfs": "read-only", "capabilities": "none",
                "no_new_privileges": True, "container_per_invocation": True},
            "Native host receipt does not claim the exact isolation profile")

    commands = expand_host_plan(reviewed_plan(), build_before)
    require(set(value["invocations"]) == set(commands),
            "Native host receipt omits or adds a reviewed invocation")
    all_cases = {}
    for identifier, command in commands.items():
        row = value["invocations"][identifier]
        exact_keys(row, {"case_count", "cases", "exit_code", "raw", "container"},
                   "native host invocation")
        raw_path = isolated_atest.resolve_ref(root, row["raw"], identifier + " native Go JSON",
                                              maximum=MAX_JSON, allow_empty=False)
        cases = parse_go_json(raw_path, identifier, row["exit_code"])
        require_executed_go_test(cases, identifier)
        require(row["cases"] == cases and row["case_count"] == len(cases),
                "Native host normalized cases differ from raw Go events")
        container = _portable_json(root, row["container"], identifier + " container")
        spec = container.get("spec", {})
        require(spec.get("invocation") == identifier and spec.get("argv") == command["argv"] and
                spec.get("cwd") == command["cwd"] and
                spec.get("environment") == command["environment"] and
                spec.get("source") == build_before["source_root"] and
                spec.get("workspace") == cleanup["ownership"]["path"] and
                spec.get("image") == image_before["id"] and
                build_before["out_dir"] not in json.dumps(spec, sort_keys=True),
                "Native host container spec exposes a different input")
        validate_host_container_evidence(container, spec, row["exit_code"])
        for identity, status in cases.items():
            require(identity not in all_cases, "Duplicate native host case")
            all_cases[identity] = status
    require(len(all_cases) >= class_row(reviewed_plan(), "aosp_host")["minimum_cases"],
            "Native host receipt contains no cases")

    if rehash_build:
        live_receipt, live_build = isolated_atest.full_build_verify(
            copied_build, value["build"]["authenticated_sha256"], value["role"])
        require(live_build == build_before and
                isolated_atest.source_freeze_verify(live_receipt, live_build) == source_before and
                isolated_atest.protected_tree_inventory(Path(live_build["out_dir"])) == out_before and
                authenticate_source_bindings(reviewed_plan(), Path(live_build["source_root"]),
                                             live_receipt["source"]["pin"]) == binding,
                "Live source/build/OUT reauthentication differs from host evidence")
        backend = HostProductionBackend()
        require(backend.docker_identity() == docker_before and
                isolated_atest.normalize_image(backend.inspect_image(image_before["id"])) ==
                image_before,
                "Live immutable builder or Docker identity differs from host evidence")
    return {"class": "aosp_host", "role": value["role"],
            "source_pin_sha256": binding["source_pin_sha256"],
            "build_receipt": {key: value["build"]["receipt"][key]
                              for key in ("sha256", "size")},
            "plan_sha256": PLAN_SHA256,
            "authority": {"builder": image_before,
                          "toolchain": {"source_tools":
                                        class_row(reviewed_plan(), "aosp_host")["source_tools"],
                                        "docker": docker_before}},
            "cases": dict(sorted(all_cases.items())), "receipt_sha256": expected_sha256,
            "native_protocol": "go-test-json-v1"}


def compare_native_sides(plan, sides):
    """Compare all three classes and fail before output for unresolved/omitted input."""
    require(validate_plan(plan) == reviewed_plan(),
            "Generic comparison did not select the repository-reviewed plan")
    unresolved = sorted(row["class"] for row in plan["classes"] if row["state"] == "unresolved")
    require(not unresolved, "Reviewed generic plan has unresolved applicability gates: " +
            ", ".join(unresolved))
    require(isinstance(sides, dict) and set(sides) == REQUIRED_CLASSES,
            "Generic evidence omits a required coverage class")
    result = {}
    build_bindings, source_pins = {}, set()
    for test_class in sorted(REQUIRED_CLASSES):
        pair = sides[test_class]
        require(isinstance(pair, dict) and set(pair) == {"baseline", "custom"},
                "Coverage class lacks a matched baseline/custom pair: " + test_class)
        baseline, custom = pair["baseline"], pair["custom"]
        for role, side in (("baseline", baseline), ("custom", custom)):
            require(isinstance(side, dict) and side.get("class") == test_class and
                    side.get("role") == role,
                    "Malformed native side: " + test_class + "/" + role)
            if test_class != "grapheneos_host":
                require(isinstance(side.get("cases"), dict) and side["cases"] and
                        all(isinstance(case, str) and case and status in STATUS_SEVERITY
                            for case, status in side["cases"].items()),
                        "Native test side lacks reconstructed cases")
            reference = side.get("build_receipt")
            exact_keys(reference, {"sha256", "size"}, "native build receipt")
            require(SHA256.fullmatch(str(reference["sha256"])) and
                    type(reference["size"]) is int and reference["size"] > 0 and
                    side.get("plan_sha256") == PLAN_SHA256 and
                    SHA256.fullmatch(str(side.get("receipt_sha256", ""))) and
                    isinstance(side.get("authority"), dict) and
                    isinstance(side["authority"].get("builder"), dict) and
                    isinstance(side["authority"].get("toolchain"), dict),
                    "Native side lacks authenticated build/plan/toolchain bindings")
            require(build_bindings.setdefault(role, reference) == reference,
                    "Coverage classes use different " + role + " build receipts")
            require(isinstance(side.get("source_pin_sha256"), str) and
                    SHA256.fullmatch(side["source_pin_sha256"]),
                    "Native side lacks an authenticated source pin")
            source_pins.add(side.get("source_pin_sha256"))
        require(baseline.get("source_pin_sha256") == custom.get("source_pin_sha256") and
                SHA256.fullmatch(str(baseline.get("source_pin_sha256", ""))),
                "Matched sides use different source pins: " + test_class)
        for name in ("builder", "toolchain"):
            require(baseline["authority"][name] == custom["authority"][name],
                    "Matched native " + name + " identities differ: " + test_class)
        if test_class == "grapheneos_host":
            for side in (baseline, custom):
                require("cases" not in side and isinstance(side.get("applicability"), dict) and
                        side["applicability"].get("result") ==
                        "not_applicable_source_declared" and
                        isinstance(side["applicability"].get("evidence"), dict),
                        "GrapheneOS-host audit cannot invent passing test cases")
            require(baseline["applicability"] == custom["applicability"],
                    "Matched bounded GrapheneOS applicability inventories differ")
            result[test_class] = {"case_count": 0,
                                  "applicability": baseline["applicability"],
                                  "tests_executed": False}
            continue
        additions = set()
        required_graphene = set()
        if test_class == "aosp_emulator":
            additions = {suite + "/" + case for suite, cases in
                         atest_comparison.CUSTOM_ONLY_CASES.items() for case in cases}
            required_graphene = {"grapheneos_secure_paste/" + case for case in
                                atest_comparison.REQUIRED_GRAPHENEOS_CASES}
            require(required_graphene <= set(baseline["cases"]) and
                    required_graphene <= set(custom["cases"]),
                    "Emulator coverage omits the applicable GrapheneOS Secure Paste cases")
            require(all(custom["cases"][case] == "passed" for case in required_graphene),
                    "Applicable GrapheneOS Secure Paste cases must all pass on the custom side")
            expected_plan = canonical_digest(atest_comparison.load_json(
                ROOT / class_row(plan, test_class)["module_plan"]["path"]))
            require(baseline.get("module_plan_sha256") ==
                    custom.get("module_plan_sha256") == expected_plan,
                    "Emulator sides use different reviewed module plans")
            for name in ("device_class", "runner"):
                require(baseline["authority"].get(name) is not None and
                        baseline["authority"][name] == custom["authority"].get(name),
                        "Matched emulator " + name + " identities differ")
            require(isinstance(baseline["authority"].get("boot_id"), str) and
                    isinstance(custom["authority"].get("boot_id"), str) and
                    baseline["authority"]["boot_id"] != custom["authority"]["boot_id"],
                    "Emulator sides must use distinct guest boots")
        require(not (set(baseline["cases"]) & additions) and
                set(custom["cases"]) == set(baseline["cases"]) | additions,
                "Matched native case sets differ from the exact reviewed additions: " +
                test_class)
        require(all(custom["cases"][case] == "passed" for case in additions),
                "Reviewed emulator-only additions must all pass")
        worsened = sorted(identity for identity in baseline["cases"]
                          if STATUS_SEVERITY[custom["cases"][identity]] >
                          STATUS_SEVERITY[baseline["cases"][identity]])
        require(not worsened, "Custom side has new or worsened native failures: " + test_class)
        result[test_class] = {"case_count": len(baseline["cases"]),
                              "custom_only_passed": sorted(additions),
                              "required_custom_passed": sorted(required_graphene),
                              "worsened": worsened}
    require(len(source_pins) == 1, "Coverage classes use different pinned source identities")
    require(build_bindings["baseline"] != build_bindings["custom"],
            "Baseline and custom native tests select the same build receipt")
    return {
        "schema": SCHEMA, "kind": COMPARISON_KIND, "release": RELEASE,
        "plan_sha256": PLAN_SHA256, "classes": result,
        "result": "passed_no_new_or_worsened_native_failures",
    }


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    actions = value.add_subparsers(dest="action", required=True)
    plan = actions.add_parser("verify-plan", help="verify the frozen reviewed generic plan")
    plan.add_argument("--plan", type=Path, default=PLAN)
    go = actions.add_parser("verify-go-json", help="verify one native Go event stream")
    go.add_argument("--result", type=Path, required=True)
    go.add_argument("--invocation", required=True)
    go.add_argument("--exit-code", type=int, required=True)
    emulator = actions.add_parser("verify-emulator", help="verify one schema-2 emulator run")
    emulator.add_argument("--receipt", type=Path, required=True)
    emulator.add_argument("--expected-sha256", required=True)
    run_host = actions.add_parser("run-aosp-host",
                                  help="run the fixed AOSP host plan in sealed containers")
    run_host.add_argument("--role", choices=("baseline", "custom"), required=True)
    run_host.add_argument("--build-receipt", type=Path, required=True)
    run_host.add_argument("--build-receipt-sha256", required=True)
    run_host.add_argument("--test-out", type=Path, required=True)
    run_host.add_argument("--output", type=Path, required=True)
    run_host.add_argument("--container-prefix", default="wonad-host")
    run_host.add_argument("--timeout-seconds", type=int, default=60 * 60)
    verify_host_parser = actions.add_parser("verify-aosp-host",
                                            help="verify one native AOSP host bundle")
    verify_host_parser.add_argument("--receipt", type=Path, required=True)
    verify_host_parser.add_argument("--expected-sha256", required=True)
    return value


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.action == "verify-plan":
            reviewed_plan(args.plan)
            print("PASS: " + str(PLAN))
        elif args.action == "verify-go-json":
            cases = parse_go_json(args.result.resolve(strict=True), args.invocation,
                                  args.exit_code)
            print(json.dumps({"case_count": len(cases), "cases_sha256":
                              canonical_digest(cases)}, sort_keys=True))
        elif args.action == "verify-emulator":
            result = normalize_emulator(args.receipt.resolve(strict=True),
                                        args.expected_sha256)
            print(json.dumps({"class": result["class"], "role": result["role"],
                              "case_count": len(result["cases"])}, sort_keys=True))
        elif args.action == "run-aosp-host":
            receipt, digest = run_aosp_host(
                args.role, args.build_receipt.resolve(strict=True),
                args.build_receipt_sha256, args.test_out.resolve(strict=False),
                args.output.resolve(strict=False), args.container_prefix,
                args.timeout_seconds)
            print(str(receipt))
            print(digest)
        else:
            result = verify_host(args.receipt.resolve(strict=True), args.expected_sha256,
                                 rehash_build=True)
            print(json.dumps({"class": result["class"], "role": result["role"],
                              "case_count": len(result["cases"])}, sort_keys=True))
        return 0
    except (EvidenceError, OSError) as error:
        print("phase1_generic_upstream_evidence.py: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
