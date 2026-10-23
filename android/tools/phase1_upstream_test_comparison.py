#!/usr/bin/env python3
"""Seal and compare same-pin upstream Android test results for Phase 1.

Only the isolated runner's schema-2 evidence can qualify a run. The comparator
replays its container, toolchain, device, raw-result and cleanup proof, binds
the exact baseline/custom build comparison, and rejects missing or worsened
shared cases. The thirteen reviewed custom WmTests additions must all pass.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "android/tools"
SCHEMA = 1
COMPARISON_SCHEMA = 2
KIND_PLAN = "wonad-phase1-upstream-test-plan"
KIND_RUN = "wonad-phase1-upstream-test-run"
KIND_COMPARISON = "wonad-phase1-upstream-test-comparison"
SCOPE = "same-pin-upstream-tests-not-runtime-or-hardware-qualification"
REQUIRED_SUITES = {
    "grapheneos_secure_paste",
    "input_atms",
    "launcher3_quickstep",
    "systemui",
    "wm_shell",
    "wmtests",
}
STATUS_SEVERITY = {"passed": 0, "skipped": 1, "failure": 2, "error": 3}
SHA256 = re.compile(r"[0-9a-f]{64}")
IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,63}")
MAX_JSON = 64 * 1024 * 1024
MAX_XML = 256 * 1024 * 1024
BUILD_VERIFIERS = {
    "wonad-x86-build-comparison-input": (
        "x86_64", TOOLS / "x86_build_comparison.py"),
    "wonad-frankel-build-comparison-input": (
        "arm64", TOOLS / "frankel_build_comparison.py"),
}
ISOLATED_RUNNER = TOOLS / "run_phase1_upstream_tests.py"
CUSTOM_CASE_PATCHES = {
    "wonad-focused-display-tests.patch":
        "86127ee8f050bc9f6ae41b9f3f8430500988ee4c01066b3fdaa808af9634b0e5",
    "wonad-display-settings-lifetime.patch":
        "9b83810928d05260bf4f88600deddbb61c31589f89025b77ad112a0e0bad2590",
}
CUSTOM_ONLY_CASES = {
    "wmtests": frozenset(
        "AtestTradefedTestRunner/WmTests/com.android.server.wm." + classname + "#" + method
        for classname, methods in {
            "WonadFocusedDisplayTests": (
                "permissionDeniedDoesNotReadFocusEvenForMatchingSystemUiUid",
                "permissionAloneDoesNotAuthorizeAnotherUid",
                "sameAppIdInAnotherUserIsNotSystemUiOwner",
                "authorizedQueryReadsLiveWmsFocusIncludingEmptyDesktopAndPhone",
                "failedObservationDoesNotChangeCallingIdentity",
            ),
            "DisplayWindowSettingsTests": (
                "testVirtualReplacementKeepsSettingsUntilItsOwnRemoval",
                "testOverlayReplacementKeepsSettingsUntilItsOwnRemoval",
                "testDifferentVirtualIdentityDoesNotBlockSettingsCleanup",
                "testInvalidVirtualReplacementDoesNotRetainSettings",
                "testDifferentDisplayTypeDoesNotBlockSettingsCleanup",
                "testRemovingVirtualReplacementDoesNotRetainSettings",
                "testRemovedVirtualReplacementDoesNotRetainSettings",
                "testPhysicalDisplayRemovalStillDelegatesSettingsCleanup",
            ),
        }.items() for method in methods
    ),
}
REQUIRED_GRAPHENEOS_CASES = frozenset(
    "AtestTradefedTestRunner/InputTests/com.android.server.input.KeyGestureControllerTests#" + name
    for name in (
        "testSecurePasteShortcuts_passThroughBeforeDispatch",
        "testSecurePasteShortcuts_notInterceptedWhenUnhandled",
        "testSecurePasteGrant_onlyForTrustedInitialDown",
        "testSecurePasteGrant_notCreatedWhenWmConsumes",
    )
)


class EvidenceError(ValueError):
    """A malformed, stale or incomplete evidence bundle."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "Duplicate JSON field: " + key)
        value[key] = item
    return value


def stable_bytes(path: Path, *, maximum=MAX_JSON):
    require(path.is_absolute(), "Evidence paths must be absolute: " + str(path))
    try:
        before = path.lstat()
    except OSError as error:
        raise EvidenceError("Missing evidence file: " + str(path)) from error
    require(stat.S_ISREG(before.st_mode) and not path.is_symlink(),
            "Evidence must be an ordinary non-symlink file: " + str(path))
    require(0 < before.st_size <= maximum, "Evidence file has invalid size: " + str(path))
    with path.open("rb") as stream:
        payload = stream.read(maximum + 1)
    after = path.lstat()
    require(len(payload) <= maximum and
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
             after.st_ctime_ns), "Evidence changed while being read: " + str(path))
    return payload


def file_ref(path: Path, *, maximum=MAX_JSON):
    payload = stable_bytes(path, maximum=maximum)
    return {"path": str(path), "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload)}


def content_ref(path: Path):
    """Bind explicit comparison inputs without recording their transport path."""
    reference = file_ref(path)
    return {"sha256": reference["sha256"], "size": reference["size"]}


def validate_ref(value, label, *, maximum=MAX_JSON):
    require(isinstance(value, dict) and set(value) == {"path", "sha256", "size"} and
            isinstance(value["path"], str) and Path(value["path"]).is_absolute() and
            isinstance(value["sha256"], str) and SHA256.fullmatch(value["sha256"]) and
            type(value["size"]) is int and 0 < value["size"] <= maximum,
            "Invalid file reference: " + label)
    actual = file_ref(Path(value["path"]), maximum=maximum)
    require(actual == value, "Referenced file changed: " + label)
    return actual


def load_json(path: Path):
    try:
        return json.loads(stable_bytes(path).decode("utf-8"),
                          object_pairs_hook=strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError("Invalid JSON: " + str(path)) from error


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def safe_relative(value, label):
    require(isinstance(value, str) and value and "\x00" not in value,
            "Invalid relative path: " + label)
    path = PurePosixPath(value)
    require(not path.is_absolute() and value == path.as_posix() and
            all(part not in ("", ".", "..") for part in path.parts),
            "Unsafe relative path: " + label)
    return path


def literal_file(path: Path, label: str):
    path = Path(path)
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
            label + " must be a literal absolute path")
    try:
        status = path.lstat()
    except OSError as error:
        raise EvidenceError("Missing " + label + ": " + str(path)) from error
    require(stat.S_ISREG(status.st_mode) and not path.is_symlink(),
            label + " must be an ordinary non-symlink file")
    return path


def literal_directory(path: Path, label: str):
    path = Path(path)
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
            label + " must be a literal absolute path")
    try:
        status = path.lstat()
    except OSError as error:
        raise EvidenceError("Missing " + label + ": " + str(path)) from error
    require(stat.S_ISDIR(status.st_mode) and not path.is_symlink(),
            label + " must be an ordinary non-symlink directory")
    return path


def literal_child(root: Path, relative: str, label: str):
    parts = safe_relative(relative, label).parts
    current = root
    for index, part in enumerate(parts):
        current = current / part
        try:
            status = current.lstat()
        except OSError as error:
            raise EvidenceError("Missing " + label + ": " + str(current)) from error
        require(not stat.S_ISLNK(status.st_mode), label + " traverses a symlink")
        if index + 1 < len(parts):
            require(stat.S_ISDIR(status.st_mode), label + " has a non-directory parent")
        else:
            require(stat.S_ISREG(status.st_mode), label + " is not an ordinary file")
    return current


def load_module(path: Path, name: str):
    require(path.is_file() and not path.is_symlink(), "Missing build verifier: " + str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None,
            "Cannot load build verifier: " + str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def peek_build_kind(path: Path):
    value = load_json(path)
    require(isinstance(value, dict), "Build receipt must be an object")
    kind = value.get("kind")
    require(kind in BUILD_VERIFIERS, "Unsupported build receipt kind")
    return kind


def verify_build_receipt(path: Path, expected_sha256: str, role: str):
    require(isinstance(expected_sha256, str) and SHA256.fullmatch(expected_sha256),
            "Exact build-receipt SHA-256 is required")
    kind = peek_build_kind(path)
    architecture, verifier_path = BUILD_VERIFIERS[kind]
    module = load_module(verifier_path, "_wonad_" + architecture + "_build_verifier")
    try:
        receipt = module.verify(path, expected_sha256, rehash=False)
    except Exception as error:
        raise EvidenceError("Build receipt verification failed: " + str(error)) from error
    require(receipt.get("role") == role, "Build receipt role differs from test role")
    source = receipt.get("source")
    require(isinstance(source, dict) and isinstance(source.get("pin"), dict),
            "Build receipt lacks a source pin")
    artifacts = receipt.get("artifacts")
    require(isinstance(artifacts, dict) and isinstance(artifacts.get("os_artifacts"), dict),
            "Build receipt lacks OS artifacts")
    locations = receipt.get("locations")
    require(isinstance(locations, dict) and isinstance(locations.get("source"), str) and
            isinstance(locations.get("out_dir"), str) and
            Path(locations["source"]).is_absolute() and Path(locations["out_dir"]).is_absolute(),
            "Build receipt lacks absolute source/OUT locations")
    return receipt, {
        "architecture": architecture,
        "kind": kind,
        "receipt": file_ref(path),
        "source_pin_sha256": canonical_digest(source["pin"]),
        "artifacts_sha256": canonical_digest(artifacts),
        "fingerprint": receipt.get("fingerprint"),
        "os_artifacts": artifacts["os_artifacts"],
        "source_root": locations["source"],
        "out_dir": locations["out_dir"],
        "verifier": file_ref(verifier_path),
    }


def verify_build_comparison(path: Path, expected_sha256: str,
                            baseline_summary, custom_summary):
    require(baseline_summary["kind"] == custom_summary["kind"] and
            baseline_summary["architecture"] == custom_summary["architecture"],
            "Build receipt architectures differ")
    kind = baseline_summary["kind"]
    _, verifier_path = BUILD_VERIFIERS[kind]
    module = load_module(verifier_path, "_wonad_pair_" + baseline_summary["architecture"])
    baseline = baseline_summary["receipt"]
    custom = custom_summary["receipt"]
    try:
        module.verify_comparison(path, expected_sha256,
                                 Path(baseline["path"]), baseline["sha256"],
                                 Path(custom["path"]), custom["sha256"])
    except Exception as error:
        raise EvidenceError("Build comparison verification failed: " + str(error)) from error


def validate_plan(value):
    require(isinstance(value, dict) and set(value) == {
        "schema", "kind", "scope", "release", "suites"
    } and value.get("schema") == SCHEMA and value.get("kind") == KIND_PLAN and
            value.get("scope") == SCOPE and
            isinstance(value.get("release"), str) and
            re.fullmatch(r"[0-9]{10}", value["release"]) and
            isinstance(value.get("suites"), list) and value["suites"],
            "Invalid upstream-test plan")
    ids = []
    for suite in value["suites"]:
        require(isinstance(suite, dict) and set(suite) == {
            "id", "component", "format", "minimum_cases", "command_record",
            "result_files", "argv", "cwd", "environment"
        } and isinstance(suite.get("id"), str) and IDENTIFIER.fullmatch(suite["id"]) and
                isinstance(suite.get("component"), str) and suite["component"] and
                suite.get("format") in {"junit-xml", "atest-json"} and
                type(suite.get("minimum_cases")) is int and suite["minimum_cases"] > 0 and
                isinstance(suite.get("command_record"), str) and
                isinstance(suite.get("result_files"), list) and suite["result_files"] and
                isinstance(suite.get("argv"), list) and suite["argv"] and
                all(isinstance(item, str) and item and "\x00" not in item
                    for item in suite["argv"]) and
                isinstance(suite.get("cwd"), str) and suite["cwd"] in {"{source}", "{out_dir}"} and
                isinstance(suite.get("environment"), dict) and
                all(isinstance(key, str) and key and isinstance(item, str) and "\x00" not in item
                    for key, item in suite["environment"].items()),
                "Invalid upstream-test suite plan")
        tokens = re.compile(r"\{[^{}]+\}")
        for item in suite["argv"] + list(suite["environment"].values()):
            require(set(tokens.findall(item)) <= {"{source}", "{out_dir}"},
                    "Unknown command placeholder in suite " + suite["id"])
        safe_relative(suite["command_record"], suite["id"] + " command record")
        require(len(suite["result_files"]) == len(set(suite["result_files"])),
                "Duplicate result path in suite " + suite["id"])
        for path in suite["result_files"]:
            safe_relative(path, suite["id"] + " result")
        ids.append(suite["id"])
    require(len(ids) == len(set(ids)), "Duplicate upstream-test suite ID")
    require(REQUIRED_SUITES <= set(ids),
            "Plan omits required suites: " + ", ".join(sorted(REQUIRED_SUITES - set(ids))))
    return value


def expand_command(value, build):
    return value.replace("{source}", build["source_root"]).replace("{out_dir}", build["out_dir"])


def validate_command_record(value, suite, build):
    expected_argv = [expand_command(item, build) for item in suite["argv"]]
    expected_environment = {key: expand_command(item, build)
                            for key, item in suite["environment"].items()}
    expected_cwd = expand_command(suite["cwd"], build)
    require(isinstance(value, dict) and set(value) == {
        "schema", "kind", "suite", "argv", "cwd", "environment", "exit_code",
        "timed_out", "completed", "result_files", "build_receipt_sha256"
    } and value.get("schema") == SCHEMA and
            value.get("kind") == "wonad-phase1-upstream-test-command" and
            value.get("suite") == suite["id"] and value.get("argv") == expected_argv and
            value.get("cwd") == expected_cwd and value.get("environment") == expected_environment and
            type(value.get("exit_code")) is int and
            value.get("timed_out") is False and value.get("completed") is True and
            value.get("result_files") == suite["result_files"] and
            value.get("build_receipt_sha256") == build["receipt"]["sha256"],
            "Invalid/incomplete command record for " + suite["id"])
    return value


def parse_junit(path: Path):
    payload = stable_bytes(path, maximum=MAX_XML)
    require(b"<!DOCTYPE" not in payload.upper() and b"<!ENTITY" not in payload.upper(),
            "DTD/entity declarations are forbidden in JUnit XML: " + str(path))
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as error:
        raise EvidenceError("Invalid JUnit XML: " + str(path)) from error
    require(root.tag in {"testsuite", "testsuites"},
            "Unexpected JUnit root element: " + str(path))
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    require(suites, "JUnit XML contains no test suite: " + str(path))
    for suite in suites:
        direct = list(suite.findall("testcase"))
        count = suite.get("tests")
        require(isinstance(count, str) and re.fullmatch(r"[0-9]+", count) and
                int(count) == len(direct),
                "JUnit suite test count is missing or inconsistent: " + str(path))
    cases = {}
    for case in root.iter("testcase"):
        classname, name = case.get("classname"), case.get("name")
        require(isinstance(classname, str) and classname and
                isinstance(name, str) and name and "\x00" not in classname + name,
                "JUnit case lacks stable class/name: " + str(path))
        identity = classname + "#" + name
        require(identity not in cases, "Duplicate JUnit case: " + identity)
        known_children = {"failure", "error", "skipped", "ignored", "assumption_failure",
                          "system-out", "system-err"}
        require(all(child.tag in known_children for child in case),
                "JUnit case has an unknown result element: " + identity)
        children = [child.tag for child in case
                    if child.tag in {"failure", "error", "skipped", "ignored",
                                     "assumption_failure"}]
        require(len(children) <= 1, "JUnit case has conflicting outcomes: " + identity)
        if not children:
            require(case.get("status") in (None, "run", "passed", "success"),
                    "JUnit case has an unsupported implicit status: " + identity)
        status = {"failure": "failure", "error": "error", "skipped": "skipped",
                  "ignored": "skipped", "assumption_failure": "skipped"}.get(
                      children[0], "passed") if children else "passed"
        cases[identity] = status
    require(cases, "JUnit file contains no cases: " + str(path))
    return cases


def parse_atest(path: Path):
    value = load_json(path)
    require(isinstance(value, dict) and isinstance(value.get("test_runner"), dict) and
            isinstance(value.get("total_summary"), dict),
            "Invalid Atest result JSON: " + str(path))
    cases = {}
    totals = {"PASSED": 0, "FAILED": 0, "IGNORED": 0}
    mapping = {"PASSED": "passed", "FAILED": "failure", "IGNORED": "skipped"}
    for runner, groups in value["test_runner"].items():
        require(isinstance(runner, str) and runner and isinstance(groups, dict),
                "Invalid Atest runner result")
        for group, rows in groups.items():
            require(isinstance(group, str) and group and isinstance(rows, dict) and
                    isinstance(rows.get("summary"), dict), "Invalid Atest group result")
            require(set(rows) <= set(mapping) | {"summary"}, "Unknown Atest result status")
            summary = rows["summary"]
            require(set(summary) == set(mapping) and
                    all(type(summary[key]) is int and summary[key] >= 0 for key in mapping),
                    "Invalid Atest group summary")
            for source_status, normalized in mapping.items():
                entries = rows.get(source_status, [])
                require(isinstance(entries, list) and len(entries) == summary[source_status],
                        "Atest group summary differs from case results")
                totals[source_status] += len(entries)
                for entry in entries:
                    require(isinstance(entry, dict) and isinstance(entry.get("test_name"), str) and
                            entry["test_name"] and "\x00" not in entry["test_name"],
                            "Invalid Atest case result")
                    identity = runner + "/" + group + "/" + entry["test_name"]
                    require(identity not in cases, "Duplicate Atest case: " + identity)
                    cases[identity] = normalized
    require(value["total_summary"] == totals and cases,
            "Atest total summary differs from normalized cases")
    return cases


def parse_result(path: Path, result_format: str):
    if result_format == "junit-xml":
        return parse_junit(path)
    require(result_format == "atest-json", "Unsupported result format")
    return parse_atest(path)


def result_maximum(result_format: str):
    return MAX_XML if result_format == "junit-xml" else MAX_JSON


def collect_suite(results_root: Path, suite, build):
    command_path = literal_child(results_root, suite["command_record"],
                                 suite["id"] + " command")
    command = validate_command_record(load_json(command_path), suite, build)
    command_output = literal_child(results_root, suite["id"] + "/stdout.txt",
                                   suite["id"] + " command output")
    raw = {"command_record": file_ref(command_path),
           "command_output": file_ref(command_output, maximum=MAX_XML), "results": {}}
    cases = {}
    for relative in suite["result_files"]:
        path = literal_child(results_root, relative, suite["id"] + " result")
        raw["results"][relative] = file_ref(path, maximum=result_maximum(suite["format"]))
        for identity, status in parse_result(path, suite["format"]).items():
            require(identity not in cases,
                    "Duplicate case across result files in " + suite["id"] + ": " + identity)
            cases[identity] = status
    require(len(cases) >= suite["minimum_cases"],
            "Suite has fewer cases than its reviewed minimum: " + suite["id"])
    return {"command": command, "raw": raw,
            "cases": dict(sorted(cases.items())), "case_count": len(cases)}


def validate_device_record(value, build):
    require(isinstance(value, dict) and set(value) == {
        "schema", "kind", "serial", "build_receipt_sha256", "fingerprint",
        "boot_completed", "selinux", "adb", "artifacts"
    } and value.get("schema") == SCHEMA and
            value.get("kind") == "wonad-phase1-upstream-test-device" and
            isinstance(value.get("serial"), str) and re.fullmatch(r"emulator-[0-9]+", value["serial"]) and
            value.get("build_receipt_sha256") == build["receipt"]["sha256"] and
            value.get("fingerprint") == build["fingerprint"] and
            value.get("boot_completed") == "1" and value.get("selinux") == "Enforcing" and
            isinstance(value.get("adb"), dict) and isinstance(value.get("artifacts"), dict) and
            set(value["artifacts"]) == set(build["os_artifacts"]),
            "Invalid or non-enforcing exact-device record")
    validate_ref(value["adb"], "device adb")
    for name, expected in build["os_artifacts"].items():
        observed = value["artifacts"][name]
        require(isinstance(expected, dict) and isinstance(observed, dict) and
                observed.get("path") == "/" + expected.get("path", "") and
                observed.get("state") == expected.get("state"),
                "Device artifact identity differs: " + name)
        if expected.get("state") == "absent":
            require(set(observed) == {"path", "state"},
                    "Invalid absent device artifact: " + name)
        else:
            require(set(observed) == {"path", "state", "sha256"} and
                    observed["state"] == "present" and
                    observed["sha256"] == expected.get("sha256"),
                    "Booted device artifact differs: " + name)
    return value


def validate_run_shape(value):
    require(isinstance(value, dict) and set(value) == {
        "schema", "kind", "scope", "role", "build", "plan", "plan_sha256",
        "device", "suites", "generator"
    } and value.get("schema") == SCHEMA and value.get("kind") == KIND_RUN and
            value.get("scope") == SCOPE and value.get("role") in {"baseline", "custom"} and
            isinstance(value.get("build"), dict) and
            isinstance(value.get("plan"), dict) and
            value.get("plan_sha256") == canonical_digest(value["plan"]) and
            isinstance(value.get("suites"), dict) and
            isinstance(value.get("generator"), dict), "Invalid upstream-test run receipt")
    validate_plan(value["plan"])
    expected_ids = {suite["id"] for suite in value["plan"]["suites"]}
    require(set(value["suites"]) == expected_ids, "Run receipt suite set differs from plan")
    build = value["build"]
    require(set(build) == {"architecture", "kind", "receipt", "source_pin_sha256",
                           "artifacts_sha256", "fingerprint", "os_artifacts",
                           "source_root", "out_dir", "verifier"} and
            build["architecture"] in {"x86_64", "arm64"} and
            build["kind"] in BUILD_VERIFIERS and
            isinstance(build["source_root"], str) and Path(build["source_root"]).is_absolute() and
            isinstance(build["out_dir"], str) and Path(build["out_dir"]).is_absolute() and
            isinstance(build["fingerprint"], str) and build["fingerprint"] and
            isinstance(build["os_artifacts"], dict) and build["os_artifacts"] and
            SHA256.fullmatch(str(build["source_pin_sha256"])) and
            SHA256.fullmatch(str(build["artifacts_sha256"])), "Invalid build binding")
    for label in ("receipt", "verifier"):
        validate_ref(build[label], "build " + label)
    device = value["device"]
    require(isinstance(device, dict) and set(device) == {"record", "file"},
            "Invalid device evidence binding")
    validate_ref(device["file"], "device record")
    require(load_json(Path(device["file"]["path"])) == device["record"] and
            validate_device_record(device["record"], build) is not None,
            "Device record differs from its file")
    for suite in value["plan"]["suites"]:
        row = value["suites"][suite["id"]]
        require(isinstance(row, dict) and set(row) == {
            "command", "raw", "cases", "case_count"
        } and isinstance(row["cases"], dict) and
                row["case_count"] == len(row["cases"]) >= suite["minimum_cases"] and
                list(row["cases"]) == sorted(row["cases"]) and
                all(isinstance(case, str) and case and status in STATUS_SEVERITY
                    for case, status in row["cases"].items()),
                "Invalid suite result: " + suite["id"])
        validate_command_record(row["command"], suite, build)
        raw = row["raw"]
        require(isinstance(raw, dict) and set(raw) == {
            "command_record", "command_output", "results"
        } and
                isinstance(raw["results"], dict) and
                set(raw["results"]) == set(suite["result_files"]),
                "Invalid raw evidence set: " + suite["id"])
        validate_ref(raw["command_record"], suite["id"] + " command")
        validate_ref(raw["command_output"], suite["id"] + " command output", maximum=MAX_XML)
        for relative, reference in raw["results"].items():
            validate_ref(reference, suite["id"] + " " + relative,
                         maximum=result_maximum(suite["format"]))
            require(parse_result(Path(reference["path"]), suite["format"]) is not None,
                    "Unparseable upstream test result")
        rebuilt = {}
        for relative in suite["result_files"]:
            for identity, status in parse_result(
                    Path(raw["results"][relative]["path"]), suite["format"]).items():
                require(identity not in rebuilt, "Duplicate case while verifying " + suite["id"])
                rebuilt[identity] = status
        require(dict(sorted(rebuilt.items())) == row["cases"],
                "Normalized cases differ from raw JUnit: " + suite["id"])
    validate_ref(value["generator"], "run generator")
    require(value["generator"] == file_ref(Path(__file__)), "Run generator changed")
    return value


def capture(role: str, build_receipt: Path, build_sha256: str,
            plan_path: Path, results_root: Path, output: Path):
    require(role in {"baseline", "custom"}, "Role must be baseline or custom")
    build_receipt = literal_file(build_receipt, "build receipt")
    plan_path = literal_file(plan_path, "test plan")
    results_root = literal_directory(results_root, "results root")
    _, build = verify_build_receipt(build_receipt, build_sha256, role)
    plan = validate_plan(load_json(plan_path))
    device_path = literal_child(results_root, "device.json", "device record")
    device_record = validate_device_record(load_json(device_path), build)
    suites = {suite["id"]: collect_suite(results_root, suite, build)
              for suite in plan["suites"]}
    receipt = {"schema": SCHEMA, "kind": KIND_RUN, "scope": SCOPE, "role": role,
               "build": build, "plan": plan, "plan_sha256": canonical_digest(plan),
               "device": {"record": device_record, "file": file_ref(device_path)},
               "suites": suites, "generator": file_ref(Path(__file__))}
    validate_run_shape(receipt)
    write_new(output, receipt)
    return receipt, file_ref(output)["sha256"]


def authenticated_legacy_run(path: Path, expected_sha256: str):
    """Replay an archival schema-1 capture, never a release-qualifying run."""
    require(isinstance(expected_sha256, str) and SHA256.fullmatch(expected_sha256),
            "Exact run-receipt SHA-256 is required")
    path = literal_file(path, "run receipt")
    require(file_ref(path)["sha256"] == expected_sha256,
            "Run receipt differs from authenticated SHA-256")
    value = validate_run_shape(load_json(path))
    _, summary = verify_build_receipt(Path(value["build"]["receipt"]["path"]),
                                      value["build"]["receipt"]["sha256"], value["role"])
    require(summary == value["build"], "Build binding changed")
    return value


def isolated_runner():
    return load_module(ISOLATED_RUNNER, "_wonad_isolated_upstream_runner")


def custom_case_contract():
    for name, expected in CUSTOM_CASE_PATCHES.items():
        require(file_ref(ROOT / "android/platform/patches" / name)["sha256"] == expected,
                "Reviewed custom test patch changed: " + name)
    return {"patches": dict(sorted(CUSTOM_CASE_PATCHES.items())),
            "cases": {suite: sorted(cases)
                      for suite, cases in sorted(CUSTOM_ONLY_CASES.items())}}


def authenticated_run(path: Path, expected_sha256: str):
    """Authenticate schema-2 isolation evidence and expose its checked projection.

    The projection is not a receipt and cannot be supplied in place of the raw
    runner bundle. All container/results/cleanup proof is replayed by the runner
    and the live build is fully rehashed, not merely accepted by claimed digest.
    """
    path = literal_file(path, "isolated run receipt")
    require(isinstance(expected_sha256, str) and SHA256.fullmatch(expected_sha256) and
            file_ref(path)["sha256"] == expected_sha256,
            "Run receipt differs from authenticated SHA-256")
    claimed = load_json(path)
    require(isinstance(claimed, dict) and claimed.get("schema") == 2 and
            claimed.get("kind") == "wonad-phase1-isolated-upstream-test-run",
            "Only schema-2 isolated upstream runs qualify; schema-1 captures do not")
    runner = isolated_runner()
    try:
        raw = runner.verify(path, expected_sha256, rehash_build=True)
        root = path.parent
        summary = runner.load_portable_json(root, raw["build"]["before"], "build before")
        build_path = runner.resolve_ref(root, raw["build"]["receipt"], "build receipt",
                                        allow_empty=False)
        plan = runner.load_portable_json(root, raw["plan"]["file"], "plan")
        toolchain = runner.load_portable_json(root, raw["toolchain"]["before"], "toolchain")
        device = runner.load_portable_json(root, raw["device"]["before"], "device")
        image = runner.load_portable_json(root, raw["builder"]["before"], "builder")
    except Exception as error:
        raise EvidenceError("Isolated run verification failed: " + str(error)) from error
    contract = custom_case_contract()
    stage = load_json(build_path).get("source", {}).get("stage", {})
    if raw["role"] == "custom":
        rows = stage.get("marker", {}).get("patches", {}).get("frameworks_base")
        require(isinstance(rows, list) and
                all(isinstance(row, dict) and set(row) == {"name", "sha256"}
                    for row in rows) and
                len({row["name"] for row in rows}) == len(rows),
                "Custom build lacks an unambiguous reviewed test-patch inventory")
        patches = {row["name"]: row["sha256"] for row in rows}
        require(all(patches.get(name) == expected
                    for name, expected in contract["patches"].items()),
                "Custom test additions are not bound to their reviewed build patches")
    else:
        require(stage == {"state": "absent"}, "Baseline test run contains a custom stage")
    build = dict(summary)
    build["receipt"] = file_ref(build_path)
    return {
        "schema": 2, "kind": raw["kind"], "scope": raw["scope"], "role": raw["role"],
        "build": build, "plan": plan, "plan_sha256": canonical_digest(plan),
        "suites": raw["suites"],
        "authority": {"builder": image, "toolchain": toolchain,
                      "device_class": {key: device[key] for key in
                                       ("serial", "boot_completed", "selinux", "state")},
                      "boot_id": device["boot_id"],
                      "runner": content_ref(ISOLATED_RUNNER)},
    }


def result_delta(baseline, custom):
    require(baseline["plan_sha256"] == custom["plan_sha256"] and
            baseline["plan"] == custom["plan"], "Baseline/custom test plans differ")
    require(baseline["build"]["architecture"] == custom["build"]["architecture"] and
            baseline["build"]["source_pin_sha256"] == custom["build"]["source_pin_sha256"],
            "Baseline/custom builds are not from the same source pin")
    require(baseline.get("schema") == custom.get("schema") == 2 and
            baseline.get("role") == "baseline" and custom.get("role") == "custom" and
            isinstance(baseline.get("authority"), dict) and
            isinstance(custom.get("authority"), dict),
            "Comparison requires authenticated schema-2 baseline/custom projections")
    for name in ("builder", "toolchain", "device_class", "runner"):
        require(baseline["authority"][name] == custom["authority"][name],
                "Baseline/custom " + name + " identities differ")
    require(baseline["authority"]["boot_id"] != custom["authority"]["boot_id"],
            "Baseline/custom tests must run on distinct guest boots")
    require(set(baseline["suites"]) == set(custom["suites"]),
            "Baseline/custom suite sets differ")
    common, resolved, regressions = [], [], []
    suite_rows = {}
    for suite in sorted(baseline["suites"]):
        before = baseline["suites"][suite]["cases"]
        after = custom["suites"][suite]["cases"]
        if suite == "grapheneos_secure_paste":
            require(REQUIRED_GRAPHENEOS_CASES <= set(before) and
                    REQUIRED_GRAPHENEOS_CASES <= set(after),
                    "GrapheneOS Secure Paste coverage omits a source-declared regression case")
            require(all(after[case] == "passed" for case in REQUIRED_GRAPHENEOS_CASES),
                    "GrapheneOS Secure Paste regression cases must all pass on the custom side")
        additions = CUSTOM_ONLY_CASES.get(suite, frozenset())
        require(not (set(before) & additions),
                "Custom-only test additions appear in baseline: " + suite)
        require(set(after) == set(before) | additions,
                "Case set differs from baseline plus exact reviewed additions for suite " + suite)
        require(all(after[case] == "passed" for case in additions),
                "Reviewed custom-only test additions must all pass: " + suite)
        require(all(status in STATUS_SEVERITY for status in list(before.values()) +
                    list(after.values())), "Unsupported normalized test status")
        for case in sorted(before):
            old, new = before[case], after[case]
            row = {"suite": suite, "case": case, "baseline": old, "custom": new}
            if STATUS_SEVERITY[new] > STATUS_SEVERITY[old]:
                regressions.append(row)
            elif STATUS_SEVERITY[new] < STATUS_SEVERITY[old]:
                resolved.append(row)
            elif old != "passed":
                common.append(row)
        suite_rows[suite] = {
            "cases": len(before),
            "custom_only_passed": sorted(additions),
            "required_custom_passed": (sorted(REQUIRED_GRAPHENEOS_CASES)
                                       if suite == "grapheneos_secure_paste" else []),
            "baseline": {status: list(before.values()).count(status)
                         for status in STATUS_SEVERITY},
            "custom": {status: list(after.values()).count(status)
                       for status in STATUS_SEVERITY},
        }
    require(not regressions, "Custom build introduces/worsens upstream test failures: " +
            json.dumps(regressions[:10], sort_keys=True))
    return suite_rows, common, resolved


def compare(baseline_path: Path, baseline_sha256: str, custom_path: Path,
            custom_sha256: str, build_comparison: Path,
            build_comparison_sha256: str, output: Path):
    baseline = authenticated_run(baseline_path, baseline_sha256)
    custom = authenticated_run(custom_path, custom_sha256)
    require(baseline["role"] == "baseline" and custom["role"] == "custom",
            "Run receipt roles are reversed")
    build_comparison = literal_file(build_comparison, "build comparison")
    verify_build_comparison(build_comparison, build_comparison_sha256,
                            baseline["build"], custom["build"])
    suites, common, resolved = result_delta(baseline, custom)
    value = {
        "schema": COMPARISON_SCHEMA, "kind": KIND_COMPARISON, "scope": SCOPE,
        "architecture": baseline["build"]["architecture"],
        "source_pin_sha256": baseline["build"]["source_pin_sha256"],
        "baseline": content_ref(literal_file(baseline_path, "baseline run receipt")),
        "custom": content_ref(literal_file(custom_path, "custom run receipt")),
        "build_comparison": content_ref(build_comparison),
        "plan_sha256": baseline["plan_sha256"], "suites": suites,
        "common_baseline_failures": common, "resolved_baseline_failures": resolved,
        "new_or_worsened_failures": [], "status": "passed",
        "custom_case_contract": custom_case_contract(),
        "runner": content_ref(ISOLATED_RUNNER),
        "generator": content_ref(Path(__file__)),
    }
    write_new(output, value)
    return value, file_ref(output)["sha256"]


def verify_comparison(path: Path, expected_sha256: str,
                      baseline_path: Path, baseline_sha256: str,
                      custom_path: Path, custom_sha256: str,
                      build_comparison: Path, build_comparison_sha256: str):
    require(isinstance(expected_sha256, str) and SHA256.fullmatch(expected_sha256),
            "Exact comparison SHA-256 is required")
    path = literal_file(path, "upstream-test comparison")
    require(file_ref(path)["sha256"] == expected_sha256,
            "Comparison differs from authenticated SHA-256")
    value = load_json(path)
    require(isinstance(value, dict) and set(value) == {
        "schema", "kind", "scope", "architecture", "source_pin_sha256", "baseline",
        "custom", "build_comparison", "plan_sha256", "suites",
        "common_baseline_failures", "resolved_baseline_failures",
        "new_or_worsened_failures", "status", "generator", "custom_case_contract", "runner"
    } and value.get("schema") == COMPARISON_SCHEMA and value.get("kind") == KIND_COMPARISON and
            value.get("scope") == SCOPE and value.get("architecture") in {"x86_64", "arm64"} and
            SHA256.fullmatch(str(value.get("source_pin_sha256"))) and
            SHA256.fullmatch(str(value.get("plan_sha256"))) and
            value.get("new_or_worsened_failures") == [] and value.get("status") == "passed",
            "Invalid upstream-test comparison")
    baseline_path = literal_file(baseline_path, "baseline run receipt")
    custom_path = literal_file(custom_path, "custom run receipt")
    build_comparison = literal_file(build_comparison, "build comparison")
    require(value["baseline"] == content_ref(baseline_path) and
            value["custom"] == content_ref(custom_path) and
            value["build_comparison"] == content_ref(build_comparison),
            "Comparison input references differ")
    baseline = authenticated_run(baseline_path, baseline_sha256)
    custom = authenticated_run(custom_path, custom_sha256)
    verify_build_comparison(build_comparison, build_comparison_sha256,
                            baseline["build"], custom["build"])
    suites, common, resolved = result_delta(baseline, custom)
    require(value["architecture"] == baseline["build"]["architecture"] and
            value["source_pin_sha256"] == baseline["build"]["source_pin_sha256"] and
            value["plan_sha256"] == baseline["plan_sha256"] and
            value["suites"] == suites and value["common_baseline_failures"] == common and
            value["resolved_baseline_failures"] == resolved and
            value["custom_case_contract"] == custom_case_contract() and
            value["runner"] == content_ref(ISOLATED_RUNNER) and
            value["generator"] == content_ref(Path(__file__)),
            "Comparison semantics or generator differ")
    return value


def write_new(path: Path, value):
    path = Path(path)
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent and
            not path.exists() and not path.is_symlink(),
            "Output must be a new literal file in an existing directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    actions = value.add_subparsers(dest="action", required=True)
    capture_parser = actions.add_parser(
        "capture", help="archive legacy results only; not release-qualifying evidence")
    capture_parser.add_argument("--role", choices=("baseline", "custom"), required=True)
    capture_parser.add_argument("--build-receipt", type=Path, required=True)
    capture_parser.add_argument("--build-receipt-sha256", required=True)
    capture_parser.add_argument("--plan", type=Path, required=True)
    capture_parser.add_argument("--results", type=Path, required=True)
    capture_parser.add_argument("--output", type=Path, required=True)
    verify_parser = actions.add_parser("verify")
    verify_parser.add_argument("--receipt", type=Path, required=True)
    verify_parser.add_argument("--expected-sha256", required=True)
    compare_parser = actions.add_parser("compare")
    comparison_parser = actions.add_parser("verify-comparison")
    for selected in (compare_parser, comparison_parser):
        selected.add_argument("--baseline", type=Path, required=True)
        selected.add_argument("--baseline-sha256", required=True)
        selected.add_argument("--custom", type=Path, required=True)
        selected.add_argument("--custom-sha256", required=True)
        selected.add_argument("--build-comparison", type=Path, required=True)
        selected.add_argument("--build-comparison-sha256", required=True)
    compare_parser.add_argument("--output", type=Path, required=True)
    comparison_parser.add_argument("--comparison", type=Path, required=True)
    comparison_parser.add_argument("--expected-sha256", required=True)
    return value


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.action == "capture":
            _, digest = capture(args.role, args.build_receipt, args.build_receipt_sha256,
                                args.plan, args.results, args.output)
            print(digest)
            print("ARCHIVE ONLY: schema-1 captures cannot qualify a release; "
                  "use run_phase1_upstream_tests.py", file=sys.stderr)
        elif args.action == "verify":
            authenticated_run(args.receipt, args.expected_sha256)
            print("PASS: authenticated Phase-1 upstream-test run")
        elif args.action == "compare":
            _, digest = compare(args.baseline, args.baseline_sha256,
                                args.custom, args.custom_sha256,
                                args.build_comparison, args.build_comparison_sha256,
                                args.output)
            print(digest)
        else:
            verify_comparison(args.comparison, args.expected_sha256,
                              args.baseline, args.baseline_sha256,
                              args.custom, args.custom_sha256,
                              args.build_comparison, args.build_comparison_sha256)
            print("PASS: no new/worsened same-pin upstream test failure")
        return 0
    except (EvidenceError, OSError) as error:
        print("phase1_upstream_test_comparison.py: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
