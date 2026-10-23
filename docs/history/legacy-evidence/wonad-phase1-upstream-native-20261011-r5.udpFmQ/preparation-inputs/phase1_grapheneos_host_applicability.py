#!/usr/bin/env python3
"""Authenticate the bounded GrapheneOS-host applicability audit for Phase 1.

This tool does not run a test and cannot manufacture passing test cases.  It
replays a reviewed, source-native inventory of the exact receipted GrapheneOS
checkout and records the result ``not_applicable_source_declared``.  The claim
is deliberately bounded to declarations present in the pinned source; it says
nothing about unpublished or external GrapheneOS CI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys

import phase1_upstream_test_comparison as comparison
import run_phase1_upstream_tests as isolated


SCHEMA = 1
RELEASE = "2026100600"
DEFINITION_KIND = "wonad-phase1-grapheneos-host-applicability-definition"
SCAN_KIND = "wonad-phase1-grapheneos-host-source-scan"
RECEIPT_KIND = "wonad-phase1-grapheneos-host-applicability"
SCOPE = "pinned-source-declarations-only-no-external-ci-claim"
RESULT = "not_applicable_source_declared"
RUNNER = Path(__file__).resolve()
ROOT = RUNNER.parents[2]
DEFINITION = ROOT / "android/platform/phase1-grapheneos-host-applicability-2026100600.json"
DEFINITION_SHA256 = "658bc4ed825c17214107829e27659a4779b7dc4706123a61876aace9188374f7"
MAX_JSON = 64 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SHA1 = re.compile(r"[0-9a-f]{40}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
IDENTIFIER = re.compile(r"[A-Za-z0-9_.+-]{1,160}")
MODULE_NAME = re.compile(r"[A-Za-z0-9_.+@:/=-]{1,300}")
GOS_KEY = re.compile(r"gos[-_].*", re.IGNORECASE)
HOST_MODULE_TYPES = frozenset({
    "java_test_host", "cc_test_host", "rust_test_host", "python_test_host",
    "sh_test_host", "android_ravenwood_test",
})
HOST_SUPPORTED_TEST_TYPES = frozenset({
    "java_test", "cc_test", "rust_test", "python_test", "sh_test",
})
WALK_EXCLUSIONS = (
    {"selector": "top-level:.repo", "reason": "repo metadata is not checked-out platform source"},
    {"selector": "top-level:out", "reason": "generated build output is authenticated by the build receipt"},
    {"selector": "name:.git", "reason": "per-project Git metadata is not platform source"},
    {"selector": "kind:symlink-directory", "reason": "do not escape or duplicate the receipted source tree"},
)


class ApplicabilityError(comparison.EvidenceError):
    """The applicability definition, source, or evidence is not authentic."""


def require(condition, message):
    if not condition:
        raise ApplicabilityError(message)


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def exact_keys(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys),
            label + " has unexpected fields")
    return value


def safe_relative(value, label):
    require(isinstance(value, str) and value and "\x00" not in value,
            "Invalid relative path: " + label)
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value and
            all(part not in ("", ".", "..") for part in path.parts),
            "Unsafe relative path: " + label)
    return path


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "Duplicate JSON key")
        value[key] = item
    return value


def strip_json_comments(text):
    """Remove JSONC comments without changing strings or line positions."""
    output = []
    index = 0
    state = "normal"
    while index < len(text):
        char = text[index]
        if state == "normal":
            if char == '"':
                output.append(char)
                state = "string"
                index += 1
            elif char == "/" and index + 1 < len(text) and text[index + 1] == "/":
                output.extend("  ")
                state = "line"
                index += 2
            elif char == "/" and index + 1 < len(text) and text[index + 1] == "*":
                output.extend("  ")
                state = "block"
                index += 2
            else:
                output.append(char)
                index += 1
        elif state == "string":
            output.append(char)
            index += 1
            if char == "\\":
                require(index < len(text), "Invalid JSONC string escape")
                output.append(text[index])
                index += 1
            elif char == '"':
                state = "normal"
        elif state == "line":
            output.append(char if char in "\r\n" else " ")
            index += 1
            if char in "\r\n":
                state = "normal"
        else:
            if char == "*" and index + 1 < len(text) and text[index + 1] == "/":
                output.extend("  ")
                index += 2
                state = "normal"
            else:
                output.append(char if char in "\r\n" else " ")
                index += 1
    require(state in {"normal", "line"}, "Unterminated JSONC token")
    return "".join(output)


def load_jsonc(payload, label):
    try:
        value = json.loads(strip_json_comments(payload.decode("utf-8")),
                           object_pairs_hook=strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ApplicabilityError("Invalid JSONC: " + label) from error
    require(isinstance(value, dict), label + " is not a JSON object")
    return value


class _JsonPairs(list):
    """Preserve object members while discovering top-level JSONC keys."""


def jsonc_top_level_keys(payload, label):
    """Return every top-level key, including duplicates, without losing data.

    A few unrelated AOSP TEST_MAPPING files contain duplicate nested keys.
    Those files still need to be included byte-for-byte in the global
    inventory, but they must not prevent discovery of a GrapheneOS-owned
    top-level group elsewhere.  Any file that actually declares such a group
    is subsequently parsed with ``load_jsonc`` and therefore remains strict at
    every level.
    """
    try:
        value = json.loads(strip_json_comments(payload.decode("utf-8")),
                           object_pairs_hook=_JsonPairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ApplicabilityError("Invalid JSONC: " + label) from error
    require(isinstance(value, _JsonPairs), label + " is not a JSON object")
    keys = []
    for pair in value:
        require(isinstance(pair, tuple) and len(pair) == 2 and
                isinstance(pair[0], str), label + " has an invalid object member")
        keys.append(pair[0])
    return keys


def file_identity(path, *, allow_empty=False):
    return isolated.sha256_file(Path(path), maximum=MAX_JSON, allow_empty=allow_empty)


def source_file(source, relative, label):
    relative = safe_relative(relative, label)
    current = Path(source).resolve(strict=True)
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            node = current.lstat()
        except OSError as error:
            raise ApplicabilityError("Missing source file: " + label) from error
        require(not stat.S_ISLNK(node.st_mode), label + " traverses a symlink")
        if index + 1 < len(relative.parts):
            require(stat.S_ISDIR(node.st_mode), label + " parent is not a directory")
        else:
            require(stat.S_ISREG(node.st_mode), label + " is not an ordinary file")
    return current


def _walk_files(source, *, filename=None, roots=(".",)):
    """Yield source-relative ordinary files without following excluded trees."""
    source = Path(source).resolve(strict=True)
    rows = []
    skipped_symlink_directories = []
    for root_name in roots:
        if root_name == ".":
            start = source
        else:
            relative = safe_relative(root_name, "scan root")
            start = source
            for part in relative.parts:
                start = start / part
                node = start.lstat()
                require(stat.S_ISDIR(node.st_mode) and not stat.S_ISLNK(node.st_mode),
                        "Scan root is not a real source directory")
        for directory, directory_names, file_names in os.walk(
                start, topdown=True, followlinks=False):
            directory_path = Path(directory)
            kept = []
            for name in sorted(directory_names):
                candidate = directory_path / name
                relative = candidate.relative_to(source).as_posix()
                if name == ".git" or relative in {".repo", "out"}:
                    continue
                node = candidate.lstat()
                if stat.S_ISLNK(node.st_mode):
                    skipped_symlink_directories.append(relative)
                    continue
                require(stat.S_ISDIR(node.st_mode), "Unexpected non-directory during source walk")
                kept.append(name)
            directory_names[:] = kept
            for name in sorted(file_names):
                if name == ".git" or (filename is not None and name != filename):
                    continue
                candidate = directory_path / name
                node = candidate.lstat()
                if stat.S_ISLNK(node.st_mode):
                    require(name != filename, "Audited filename is a symlink")
                    continue
                require(stat.S_ISREG(node.st_mode), "Unexpected non-file during source walk")
                rows.append(candidate)
    rows.sort(key=lambda path: path.relative_to(source).as_posix())
    require(len(rows) == len(set(path.relative_to(source).as_posix() for path in rows)),
            "Overlapping scan roots produced duplicate files")
    return rows, sorted(set(skipped_symlink_directories))


def _blueprint_mask(text):
    """Mask Blueprint comments and string bodies while preserving brace offsets."""
    output = list(text)
    index = 0
    state = "normal"
    while index < len(text):
        char = text[index]
        if state == "normal":
            if char == '"':
                state = "string"
                index += 1
            elif char == "/" and index + 1 < len(text) and text[index + 1] == "/":
                output[index] = output[index + 1] = " "
                state = "line"
                index += 2
            elif char == "/" and index + 1 < len(text) and text[index + 1] == "*":
                output[index] = output[index + 1] = " "
                state = "block"
                index += 2
            else:
                index += 1
        elif state == "string":
            if char == "\\":
                output[index] = " "
                if index + 1 < len(text):
                    output[index + 1] = " "
                index += 2
            elif char == '"':
                state = "normal"
                index += 1
            else:
                output[index] = "\n" if char == "\n" else " "
                index += 1
        elif state == "line":
            if char in "\r\n":
                state = "normal"
            else:
                output[index] = " "
            index += 1
        else:
            if char == "*" and index + 1 < len(text) and text[index + 1] == "/":
                output[index] = output[index + 1] = " "
                state = "normal"
                index += 2
            else:
                output[index] = "\n" if char == "\n" else " "
                index += 1
    require(state in {"normal", "line"}, "Unterminated Blueprint token")
    return "".join(output)


def blueprint_modules(payload, label):
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ApplicabilityError("Blueprint is not UTF-8: " + label) from error
    mask = _blueprint_mask(text)
    rows = []
    depth = 0
    index = 0
    token = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*\{")
    while index < len(mask):
        if mask[index] == "{":
            depth += 1
            index += 1
            continue
        if mask[index] == "}":
            depth -= 1
            require(depth >= 0, "Unbalanced Blueprint braces: " + label)
            index += 1
            continue
        if depth != 0:
            index += 1
            continue
        match = token.match(mask, index)
        if match is None:
            index += 1
            continue
        module_type = match.group(0).split("{", 1)[0].strip()
        block_start = index
        cursor = match.end()
        block_depth = 1
        while cursor < len(mask) and block_depth:
            if mask[cursor] == "{":
                block_depth += 1
            elif mask[cursor] == "}":
                block_depth -= 1
            cursor += 1
        require(block_depth == 0, "Unterminated Blueprint module: " + label)
        raw_block = text[block_start:cursor]
        commentless = strip_json_comments(raw_block)
        name = re.search(r'(?m)^\s*name\s*:\s*"([^"\\]+)"\s*,', commentless)
        if name is not None:
            require(MODULE_NAME.fullmatch(name.group(1)) is not None,
                    "Invalid Blueprint module name")
            host_supported = re.search(
                r"(?m)^\s*host_supported\s*:\s*true\s*,", mask[block_start:cursor]) is not None
            rows.append({"module_type": module_type, "name": name.group(1),
                         "host_supported": host_supported})
        index = cursor
    require(depth == 0, "Unbalanced Blueprint file: " + label)
    return rows


def scan_source(source, source_pin, definition):
    """Recompute the complete bounded native inventory from a receipted source."""
    source = Path(source).resolve(strict=True)
    validate_definition(definition)
    source_pin_sha256 = authenticate_source_pin(definition, source_pin)
    mapping_paths, mapping_symlinks = _walk_files(source, filename="TEST_MAPPING")
    mappings = []
    gos_mappings = []
    for path in mapping_paths:
        relative = path.relative_to(source).as_posix()
        payload = isolated.stable_bytes(path, maximum=MAX_JSON, allow_empty=False)
        identity = {"path": relative, **file_identity(path)}
        mappings.append(identity)
        top_level_keys = jsonc_top_level_keys(payload, relative)
        gos_keys = sorted(key for key in top_level_keys if GOS_KEY.fullmatch(key))
        if gos_keys:
            require(len(gos_keys) == len(set(gos_keys)),
                    "GrapheneOS TEST_MAPPING group is duplicated")
            value = load_jsonc(payload, relative)
            keys = {key: value[key] for key in gos_keys}
            gos_mappings.append({**identity, "entries": keys})

    roots = definition["scope"]["blueprint_roots"]
    blueprint_paths, blueprint_symlinks = _walk_files(
        source, filename="Android.bp", roots=tuple(roots))
    blueprint_names = [path.relative_to(source).as_posix() for path in blueprint_paths]
    all_modules = []
    host_modules = []
    for path in blueprint_paths:
        relative = path.relative_to(source).as_posix()
        payload = isolated.stable_bytes(path, maximum=MAX_JSON, allow_empty=False)
        for module in blueprint_modules(payload, relative):
            row = {"path": relative, "module_type": module["module_type"],
                   "name": module["name"]}
            all_modules.append(row)
            if module["module_type"] in HOST_MODULE_TYPES:
                host_modules.append({**row, "host_capability":
                                     ("ravenwood" if module["module_type"] ==
                                      "android_ravenwood_test" else "host-module-type")})
            elif (module["module_type"] in HOST_SUPPORTED_TEST_TYPES and
                  module["host_supported"]):
                host_modules.append({**row, "host_capability": "host_supported"})
    all_modules.sort(key=lambda row: (row["path"], row["module_type"], row["name"]))
    host_modules.sort(key=lambda row: (row["path"], row["module_type"], row["name"]))

    audited_files = []
    for reference in definition["audited_files"]:
        path = source_file(source, reference["path"], "audited source")
        observed = {"path": reference["path"], **file_identity(path)}
        require(observed["sha256"] == reference["sha256"],
                "Audited source bytes differ")
        audited_files.append(observed)

    overlap = definition["device_overlap"]
    source_path = source_file(source, overlap["test_source_path"], "device-overlap tests")
    source_text = isolated.stable_bytes(source_path, maximum=MAX_JSON,
                                        allow_empty=False).decode("utf-8")
    observed_methods = []
    for test_filter in overlap["filters"]:
        method = test_filter.rsplit("#", 1)[1]
        require(len(re.findall(r"\bfun\s+" + re.escape(method) + r"\s*\(", source_text)) == 1,
                "Secure Paste overlap method is missing or ambiguous")
        observed_methods.append(method)
    require(source_text.count(overlap["command_anchor"]) == 1,
            "Device-only command anchor is missing or ambiguous")
    require(source_text.count(overlap["disabled_on_ravenwood_marker"]) == 1,
            "Secure Paste input tests are no longer explicitly disabled on Ravenwood")
    module_path = source_file(source, overlap["input_android_bp_path"],
                              "device-overlap module definition")
    module_rows = blueprint_modules(
        isolated.stable_bytes(module_path, maximum=MAX_JSON, allow_empty=False),
        overlap["input_android_bp_path"])
    selected = sorted((row["module_type"], row["name"]) for row in module_rows
                      if row["name"] in {overlap["device_module"], overlap["host_module"]})
    require(selected == sorted([
                ("android_test", overlap["device_module"]),
                ("android_ravenwood_test", overlap["host_module"]),
            ]), "Secure Paste overlap module types changed")
    overlap_evidence = {
        "mapping_path": overlap["mapping_path"],
        "test_source_path": overlap["test_source_path"],
        "input_android_bp_path": overlap["input_android_bp_path"],
        "device_module": overlap["device_module"], "host_module": overlap["host_module"],
        "test_class": overlap["test_class"], "command_anchor": overlap["command_anchor"],
        "filters": overlap["filters"], "methods": observed_methods,
        "disabled_on_ravenwood_marker": overlap["disabled_on_ravenwood_marker"],
        "classification": "relevant-device-only-host-class-explicitly-disabled",
    }

    scan = {
        "schema": SCHEMA, "kind": SCAN_KIND, "release": RELEASE,
        "scope": SCOPE, "source_pin_sha256": source_pin_sha256,
        "walk_exclusions": list(WALK_EXCLUSIONS),
        "skipped_symlink_directories": {
            "test_mapping_walk": mapping_symlinks,
            "blueprint_walk": blueprint_symlinks,
        },
        "test_mappings": {
            "count": len(mappings), "inventory_sha256": canonical_digest(mappings),
            "inventory": mappings, "gos_mappings": gos_mappings,
            "gos_mappings_sha256": canonical_digest(gos_mappings),
        },
        "blueprints": {
            "roots": roots, "file_count": len(blueprint_names),
            "path_inventory_sha256": canonical_digest(blueprint_names),
            "paths": blueprint_names, "module_count": len(all_modules),
            "module_inventory_sha256": canonical_digest(all_modules),
            "modules": all_modules, "host_module_count": len(host_modules),
            "host_module_inventory_sha256": canonical_digest(host_modules),
            "host_modules": host_modules,
        },
        "audited_files": audited_files,
        "device_overlap": overlap_evidence,
        "candidate_exclusions": definition["candidate_exclusions"],
        "result": RESULT,
        "disclaimer": definition["conclusion"]["disclaimer"],
    }
    normalized = normalized_inventory(scan)
    scan["normalized_native_inventory_sha256"] = canonical_digest(normalized)
    validate_scan(scan, definition)
    return scan


def normalized_inventory(scan):
    return {
        "test_mappings": {
            "count": scan["test_mappings"]["count"],
            "inventory_sha256": scan["test_mappings"]["inventory_sha256"],
            "gos_mappings": scan["test_mappings"]["gos_mappings"],
        },
        "blueprints": {
            "roots": scan["blueprints"]["roots"],
            "file_count": scan["blueprints"]["file_count"],
            "path_inventory_sha256": scan["blueprints"]["path_inventory_sha256"],
            "module_count": scan["blueprints"]["module_count"],
            "module_inventory_sha256": scan["blueprints"]["module_inventory_sha256"],
            "host_module_count": scan["blueprints"]["host_module_count"],
            "host_module_inventory_sha256":
                scan["blueprints"]["host_module_inventory_sha256"],
            "host_modules": scan["blueprints"]["host_modules"],
        },
        "audited_files": scan["audited_files"],
        "device_overlap": scan["device_overlap"],
        "candidate_exclusions": scan["candidate_exclusions"],
        "walk_exclusions": scan["walk_exclusions"],
        "skipped_symlink_directories": scan["skipped_symlink_directories"],
        "source_pin_sha256": scan["source_pin_sha256"],
        "disclaimer": scan["disclaimer"],
    }


def validate_definition(value):
    exact_keys(value, {"schema", "kind", "release", "result", "scope", "projects",
                       "gos_mappings", "audited_files", "candidate_exclusions",
                       "device_overlap", "conclusion"}, "applicability definition")
    require(value["schema"] == SCHEMA and value["kind"] == DEFINITION_KIND and
            value["release"] == RELEASE and value["result"] == RESULT,
            "Unsupported applicability definition")
    scope = exact_keys(value["scope"], {
        "claim", "walk_exclusions", "test_mapping_count", "test_mapping_inventory_sha256",
        "test_mapping_skipped_symlink_count",
        "test_mapping_skipped_symlink_inventory_sha256",
        "blueprint_roots", "blueprint_file_count", "blueprint_path_inventory_sha256",
        "blueprint_skipped_symlink_count",
        "blueprint_skipped_symlink_inventory_sha256", "module_count",
        "module_inventory_sha256", "host_module_count", "host_module_inventory_sha256",
    }, "definition scope")
    require(scope["claim"] == SCOPE and scope["walk_exclusions"] == list(WALK_EXCLUSIONS) and
            type(scope["test_mapping_count"]) is int and scope["test_mapping_count"] > 0 and
            type(scope["test_mapping_skipped_symlink_count"]) is int and
            scope["test_mapping_skipped_symlink_count"] >= 0 and
            type(scope["blueprint_file_count"]) is int and scope["blueprint_file_count"] > 0 and
            type(scope["blueprint_skipped_symlink_count"]) is int and
            scope["blueprint_skipped_symlink_count"] >= 0 and
            type(scope["module_count"]) is int and scope["module_count"] > 0 and
            type(scope["host_module_count"]) is int and scope["host_module_count"] > 0 and
            all(SHA256.fullmatch(str(scope[key])) for key in (
                "test_mapping_inventory_sha256",
                "test_mapping_skipped_symlink_inventory_sha256",
                "blueprint_path_inventory_sha256",
                "blueprint_skipped_symlink_inventory_sha256",
                "module_inventory_sha256", "host_module_inventory_sha256")),
            "Invalid definition inventory binding")
    roots = scope["blueprint_roots"]
    require(isinstance(roots, list) and roots == sorted(set(roots)) and roots,
            "Blueprint roots must be a sorted closed set")
    for root in roots:
        safe_relative(root, "Blueprint root")

    require(isinstance(value["projects"], list) and value["projects"],
            "Definition needs exact source projects")
    require(all(isinstance(row, dict) for row in value["projects"]),
            "Project bindings must be objects")
    require([row.get("path") for row in value["projects"]] ==
            sorted(row.get("path") for row in value["projects"]),
            "Project bindings must be sorted")
    project_paths = set()
    for row in value["projects"]:
        exact_keys(row, {"path", "commit"}, "project binding")
        safe_relative(row["path"], "project binding")
        require(row["path"] not in project_paths and
                GIT_SHA1.fullmatch(str(row["commit"])) is not None,
                "Invalid project binding")
        project_paths.add(row["path"])

    require(isinstance(value["gos_mappings"], list) and len(value["gos_mappings"]) == 4,
            "Definition must bind exactly four GrapheneOS TEST_MAPPING files")
    require(all(isinstance(row, dict) for row in value["gos_mappings"]),
            "GOS mapping bindings must be objects")
    require([row.get("path") for row in value["gos_mappings"]] ==
            sorted(row.get("path") for row in value["gos_mappings"]),
            "GOS mapping bindings must be sorted")
    mapping_paths = set()
    for row in value["gos_mappings"]:
        exact_keys(row, {"path", "sha256", "entries"}, "GOS mapping binding")
        safe_relative(row["path"], "GOS mapping")
        require(row["path"] not in mapping_paths and SHA256.fullmatch(str(row["sha256"])) and
                isinstance(row["entries"], dict) and len(row["entries"]) == 1 and
                all(GOS_KEY.fullmatch(key) for key in row["entries"]) and
                all(isinstance(group, list) and group and
                    all(isinstance(item, dict) for item in group)
                    for group in row["entries"].values()),
                "Invalid GOS mapping binding")
        mapping_paths.add(row["path"])

    require(isinstance(value["audited_files"], list) and value["audited_files"],
            "Definition needs audited source files")
    require(all(isinstance(row, dict) for row in value["audited_files"]),
            "Audited files must be objects")
    require([row.get("path") for row in value["audited_files"]] ==
            sorted(row.get("path") for row in value["audited_files"]),
            "Audited files must be sorted")
    audited_paths = set()
    for row in value["audited_files"]:
        exact_keys(row, {"path", "sha256"}, "audited file")
        safe_relative(row["path"], "audited file")
        require(row["path"] not in audited_paths and SHA256.fullmatch(str(row["sha256"])),
                "Invalid audited file binding")
        audited_paths.add(row["path"])
    require(mapping_paths <= audited_paths, "Every GOS mapping must be an audited file")

    require(isinstance(value["candidate_exclusions"], list) and
            len(value["candidate_exclusions"]) >= 5,
            "Definition lacks candidate exclusions")
    require(all(isinstance(row, dict) for row in value["candidate_exclusions"]),
            "Candidate exclusions must be objects")
    candidate_ids = set()
    for row in value["candidate_exclusions"]:
        exact_keys(row, {"id", "kind", "project_path", "definition_path", "module",
                         "module_type",
                         "exclusion_code", "reason"}, "candidate exclusion")
        require(IDENTIFIER.fullmatch(str(row["id"])) and row["id"] not in candidate_ids and
                row["kind"] in {"grapheneos_host_module", "grapheneos_device_module",
                                "standalone_host_check", "generic_host_module"} and
                row["project_path"] in project_paths and
                row["definition_path"] in audited_paths and
                (row["module"] is None or MODULE_NAME.fullmatch(str(row["module"]))) and
                (row["module_type"] is None or
                 IDENTIFIER.fullmatch(str(row["module_type"]))) and
                ((row["kind"] == "standalone_host_check" and
                  row["module"] is None and row["module_type"] is None) or
                 (row["kind"] != "standalone_host_check" and
                  row["module"] is not None and row["module_type"] is not None)) and
                IDENTIFIER.fullmatch(str(row["exclusion_code"])) and
                isinstance(row["reason"], str) and row["reason"],
                "Invalid candidate exclusion")
        candidate_ids.add(row["id"])

    overlap = exact_keys(value["device_overlap"], {
        "mapping_path", "input_android_bp_path", "test_source_path", "device_module",
        "host_module", "test_class", "command_anchor", "filters",
        "disabled_on_ravenwood_marker",
    }, "device overlap")
    require(overlap["mapping_path"] in mapping_paths and
            overlap["input_android_bp_path"] in audited_paths and
            overlap["test_source_path"] in audited_paths and
            overlap["device_module"] == "InputTests" and
            overlap["host_module"] == "InputTestsRavenwood" and
            overlap["test_class"] == "com.android.server.input.KeyGestureControllerTests" and
            overlap["command_anchor"] == "atest InputTests:KeyGestureControllerTests" and
            isinstance(overlap["filters"], list) and len(overlap["filters"]) == 4 and
            len(set(overlap["filters"])) == 4 and all(
                item.startswith(overlap["test_class"] + "#testSecurePaste")
                for item in overlap["filters"]) and
            isinstance(overlap["disabled_on_ravenwood_marker"], str) and
            "DisabledOnRavenwood" in overlap["disabled_on_ravenwood_marker"],
            "Invalid Secure Paste device-only overlap")
    mapping = next(row for row in value["gos_mappings"]
                   if row["path"] == overlap["mapping_path"])
    mapping_groups = list(mapping["entries"].values())
    require(len(mapping_groups) == 1 and isinstance(mapping_groups[0], list),
            "Secure Paste GOS mapping has an invalid group")
    input_rows = [row for row in mapping_groups[0]
                  if isinstance(row, dict) and row.get("name") == overlap["device_module"]]
    require(len(input_rows) == 1 and isinstance(input_rows[0].get("options"), list) and
            [option.get("include-filter") for option in input_rows[0]["options"]
             if isinstance(option, dict) and set(option) == {"include-filter"}] ==
            overlap["filters"] and len(input_rows[0]["options"]) == 4,
            "Secure Paste mapping does not declare the exact four device filters")
    gos_modules = {
        row.get("name") for mapping_row in value["gos_mappings"]
        for group in mapping_row["entries"].values() for row in group
        if isinstance(row, dict)
    }
    require(gos_modules == {
        "GosCompatMapsScanTests", "GosCompatWebViewTests",
        "GosCompatDmaBufReleaseTests", "GosCompatWifiScanTimeoutTests",
        "GosCompatSecureSpawnTests", "SecurePasteTests", "InputTests",
        "ContactScopesTests",
    } and gos_modules <= {row["module"] for row in value["candidate_exclusions"]},
            "GrapheneOS mapped modules lack an exact reviewed disposition")
    conclusion = exact_keys(value["conclusion"], {"result", "reason", "disclaimer"},
                            "definition conclusion")
    require(conclusion["result"] == RESULT and isinstance(conclusion["reason"], str) and
            conclusion["reason"] and conclusion["disclaimer"] ==
            "No applicable GrapheneOS-specific host check is declared in the exact pinned "
            "source within the reviewed bounds; this does not assert absence from external "
            "or unpublished GrapheneOS CI.", "Invalid bounded conclusion")
    return value


def validate_scan(scan, definition):
    validate_definition(definition)
    require(scan.get("schema") == SCHEMA and scan.get("kind") == SCAN_KIND and
            scan.get("release") == RELEASE and scan.get("scope") == SCOPE and
            scan.get("result") == RESULT and scan.get("walk_exclusions") ==
            list(WALK_EXCLUSIONS) and scan.get("candidate_exclusions") ==
            definition["candidate_exclusions"] and scan.get("disclaimer") ==
            definition["conclusion"]["disclaimer"], "Invalid source scan envelope")
    require(SHA256.fullmatch(str(scan.get("source_pin_sha256", ""))) is not None,
            "Source scan lacks its authenticated source pin")
    skipped = scan.get("skipped_symlink_directories", {})
    require(set(skipped) == {"test_mapping_walk", "blueprint_walk"} and
            len(skipped["test_mapping_walk"]) ==
            definition["scope"]["test_mapping_skipped_symlink_count"] and
            canonical_digest(skipped["test_mapping_walk"]) ==
            definition["scope"]["test_mapping_skipped_symlink_inventory_sha256"] and
            len(skipped["blueprint_walk"]) ==
            definition["scope"]["blueprint_skipped_symlink_count"] and
            canonical_digest(skipped["blueprint_walk"]) ==
            definition["scope"]["blueprint_skipped_symlink_inventory_sha256"],
            "Excluded symlink-directory inventory differs")
    mappings = scan.get("test_mappings", {})
    require(mappings.get("count") == len(mappings.get("inventory", [])) ==
            definition["scope"]["test_mapping_count"] and
            mappings.get("inventory_sha256") == canonical_digest(mappings["inventory"]) ==
            definition["scope"]["test_mapping_inventory_sha256"] and
            mappings.get("gos_mappings_sha256") == canonical_digest(
                mappings.get("gos_mappings")), "TEST_MAPPING inventory differs")
    expected_gos = [{"path": row["path"], "sha256": row["sha256"],
                     "size": next(item["size"] for item in mappings["inventory"]
                                  if item["path"] == row["path"]),
                     "entries": row["entries"]}
                    for row in definition["gos_mappings"]]
    expected_gos.sort(key=lambda row: row["path"])
    require(mappings["gos_mappings"] == expected_gos,
            "GrapheneOS TEST_MAPPING declarations differ")
    blueprints = scan.get("blueprints", {})
    scope = definition["scope"]
    require(blueprints.get("roots") == scope["blueprint_roots"] and
            blueprints.get("file_count") == len(blueprints.get("paths", [])) ==
            scope["blueprint_file_count"] and
            blueprints.get("path_inventory_sha256") == canonical_digest(
                blueprints["paths"]) == scope["blueprint_path_inventory_sha256"] and
            blueprints.get("module_count") == len(
                blueprints.get("modules", [])) == scope["module_count"] and
            blueprints.get("module_inventory_sha256") == canonical_digest(
                blueprints["modules"]) == scope["module_inventory_sha256"] and
            blueprints.get("host_module_count") == len(
                blueprints.get("host_modules", [])) == scope["host_module_count"] and
            blueprints.get("host_module_inventory_sha256") == canonical_digest(
                blueprints["host_modules"]) == scope["host_module_inventory_sha256"],
            "Host-module inventory differs")
    observed_audited = {row["path"]: row["sha256"] for row in scan.get("audited_files", [])}
    require(observed_audited == {row["path"]: row["sha256"]
                                for row in definition["audited_files"]},
            "Audited source identities differ")
    overlap = scan.get("device_overlap", {})
    require(overlap.get("filters") == definition["device_overlap"]["filters"] and
            overlap.get("classification") ==
            "relevant-device-only-host-class-explicitly-disabled" and
            overlap.get("disabled_on_ravenwood_marker") ==
            definition["device_overlap"]["disabled_on_ravenwood_marker"],
            "Device-only Secure Paste overlap differs")
    module_keys = {(row["path"], row["name"], row["module_type"])
                   for row in blueprints["modules"]}
    host_keys = {(row["path"], row["name"], row["module_type"])
                 for row in blueprints["host_modules"]}
    for candidate in definition["candidate_exclusions"]:
        if candidate["kind"] != "standalone_host_check":
            key = (candidate["definition_path"], candidate["module"],
                   candidate["module_type"])
            require(key in module_keys, "Reviewed candidate is absent from native inventory")
        if candidate["kind"] in {"grapheneos_host_module", "generic_host_module"}:
            require(key in host_keys,
                    "Reviewed host candidate is absent from the native inventory")
    normalized_hash = canonical_digest(normalized_inventory(scan))
    require(scan.get("normalized_native_inventory_sha256") == normalized_hash,
            "Normalized native inventory digest differs")
    return scan


def reviewed_definition(path=None):
    if path is None:
        path = DEFINITION
    path = comparison.literal_file(Path(path), "applicability definition")
    require(path.resolve(strict=True) == DEFINITION.resolve(strict=True) and not path.is_symlink(),
            "Only the repository-reviewed applicability definition may be used")
    identity = file_identity(path)
    require(identity["sha256"] == DEFINITION_SHA256,
            "Reviewed applicability definition bytes changed")
    return validate_definition(comparison.load_json(path))


def authenticate_source_pin(definition, pin):
    try:
        projects = pin["projects"]
    except (KeyError, TypeError) as error:
        raise ApplicabilityError("Source pin lacks its project ledger") from error
    require(pin.get("release") == RELEASE and isinstance(projects, list),
            "Build receipt source pin differs from the reviewed release")
    ledger = {}
    for row in projects:
        require(isinstance(row, dict) and isinstance(row.get("path"), str) and
                isinstance(row.get("revision"), str) and row["path"] not in ledger,
                "Build receipt project ledger is ambiguous")
        ledger[row["path"]] = row["revision"]
    require(all(ledger.get(row["path"]) == row["commit"] for row in definition["projects"]),
            "Reviewed project commit differs from the build receipt")
    return canonical_digest(pin)


def authenticate_projects(definition, build_receipt):
    try:
        pin = build_receipt["source"]["pin"]
    except (KeyError, TypeError) as error:
        raise ApplicabilityError("Build receipt lacks its source project ledger") from error
    authenticate_source_pin(definition, pin)
    return pin


def authority_snapshot(backend, source, build):
    docker_identity = backend.docker_identity()
    image = isolated.normalize_image(backend.inspect_image(build["builder_image"]["id"]))
    require(image == build["builder_image"] and IMAGE_ID.fullmatch(str(image.get("id", ""))),
            "Installed builder differs from the immutable receipted image")
    toolchain = isolated.toolchain_record(Path(source), image, docker_identity)
    return image, toolchain


def portable_ref(root, path):
    return isolated.portable_ref(root, path, maximum=MAX_JSON, allow_empty=False)


def copy_input(source, destination):
    isolated.copy_new(source, destination)


def applicability_evidence(definition_identity, scan):
    return {
        "definition_sha256": definition_identity["sha256"],
        "definition_size": definition_identity["size"],
        "normalized_native_inventory_sha256": scan["normalized_native_inventory_sha256"],
        "test_mapping_count": scan["test_mappings"]["count"],
        "test_mapping_inventory_sha256": scan["test_mappings"]["inventory_sha256"],
        "gos_mappings_sha256": scan["test_mappings"]["gos_mappings_sha256"],
        "blueprint_file_count": scan["blueprints"]["file_count"],
        "blueprint_path_inventory_sha256": scan["blueprints"]["path_inventory_sha256"],
        "host_module_count": scan["blueprints"]["host_module_count"],
        "host_module_inventory_sha256":
            scan["blueprints"]["host_module_inventory_sha256"],
        "module_count": scan["blueprints"]["module_count"],
        "module_inventory_sha256": scan["blueprints"]["module_inventory_sha256"],
        "device_overlap_sha256": canonical_digest(scan["device_overlap"]),
        "scope": SCOPE,
        "disclaimer": scan["disclaimer"],
    }


def validate_receipt_shape(value):
    exact_keys(value, {"schema", "kind", "scope", "role", "build", "plan", "definition",
                       "builder", "toolchain", "source_freeze", "scan", "applicability",
                       "generator"}, "applicability receipt")
    require(value["schema"] == SCHEMA and value["kind"] == RECEIPT_KIND and
            value["scope"] == SCOPE and value["role"] in {"baseline", "custom"},
            "Invalid applicability receipt envelope")
    exact_keys(value["build"], {"receipt", "authenticated_sha256", "before", "after",
                                "source_pin_sha256", "verification"}, "build binding")
    exact_keys(value["plan"], {"file", "sha256"}, "plan binding")
    exact_keys(value["definition"], {"file", "sha256", "size"}, "definition binding")
    exact_keys(value["builder"], {"id", "identity_sha256", "before", "after"},
               "builder binding")
    exact_keys(value["toolchain"], {"identity_sha256", "before", "after"},
               "toolchain binding")
    exact_keys(value["source_freeze"], {"snapshot_sha256", "before", "after",
                                        "verification"}, "source freeze binding")
    exact_keys(value["scan"], {"normalized_native_inventory_sha256", "before", "after",
                               "verification"}, "source scan binding")
    exact_keys(value["applicability"], {"result", "evidence"}, "applicability result")
    require(value["build"]["verification"] ==
            "receipt-verifier-rehash-true-before-and-after" and
            value["source_freeze"]["verification"] ==
            "complete-receipted-source-recollection-before-and-after" and
            value["scan"]["verification"] ==
            "full-pinned-source-native-inventory-before-and-after" and
            value["applicability"]["result"] == RESULT and
            IMAGE_ID.fullmatch(str(value["builder"]["id"])) and
            all(SHA256.fullmatch(str(item)) for item in (
                value["build"]["authenticated_sha256"], value["build"]["source_pin_sha256"],
                value["plan"]["sha256"], value["definition"]["sha256"],
                value["builder"]["identity_sha256"], value["toolchain"]["identity_sha256"],
                value["source_freeze"]["snapshot_sha256"],
                value["scan"]["normalized_native_inventory_sha256"])),
            "Applicability receipt bindings are invalid")
    forbidden = json.dumps(value["applicability"], sort_keys=True).lower()
    require('"cases"' not in forbidden and '"passed"' not in forbidden and
            '"command"' not in forbidden and '"failure"' not in forbidden,
            "Applicability evidence must not imitate test execution")
    return value


def _build_projection(value, receipt_sha256):
    return {
        "class": "grapheneos_host", "role": value["role"],
        "source_pin_sha256": value["build"]["source_pin_sha256"],
        "build_receipt": {
            "sha256": value["build"]["receipt"]["sha256"],
            "size": value["build"]["receipt"]["size"],
        },
        "receipt_sha256": receipt_sha256,
        "plan_sha256": value["plan"]["sha256"],
        "authority": {
            "builder": {"id": value["builder"]["id"],
                        "identity_sha256": value["builder"]["identity_sha256"]},
            "toolchain": {"identity_sha256": value["toolchain"]["identity_sha256"]},
        },
        "applicability": value["applicability"],
    }


def _verify(receipt_path, expected_sha256, *, rehash_build, backend):
    receipt_path = comparison.literal_file(Path(receipt_path), "applicability receipt")
    require(SHA256.fullmatch(str(expected_sha256)) and
            file_identity(receipt_path)["sha256"] == expected_sha256,
            "Applicability receipt differs from its out-of-band SHA-256")
    root = receipt_path.parent
    value = validate_receipt_shape(comparison.load_json(receipt_path))
    generator = isolated.resolve_ref(root, value["generator"], "generator",
                                     maximum=MAX_JSON, allow_empty=False)
    require(file_identity(generator) == file_identity(RUNNER),
            "Applicability generator differs from the reviewed tool")
    copied_definition = isolated.resolve_ref(
        root, value["definition"]["file"], "definition", maximum=MAX_JSON,
        allow_empty=False)
    require(file_identity(copied_definition) == {
                "sha256": value["definition"]["sha256"],
                "size": value["definition"]["size"]} == file_identity(DEFINITION) and
            value["definition"]["sha256"] == DEFINITION_SHA256,
            "Applicability definition differs from the reviewed bytes")
    definition = validate_definition(comparison.load_json(copied_definition))
    plan = isolated.resolve_ref(root, value["plan"]["file"], "generic plan",
                                maximum=MAX_JSON, allow_empty=False)
    require(file_identity(plan)["sha256"] == value["plan"]["sha256"],
            "Generic plan differs from its authenticated SHA-256")

    build_before = comparison.load_json(isolated.resolve_ref(
        root, value["build"]["before"], "build before", maximum=MAX_JSON,
        allow_empty=False))
    build_after = comparison.load_json(isolated.resolve_ref(
        root, value["build"]["after"], "build after", maximum=MAX_JSON,
        allow_empty=False))
    require(build_before == build_after and build_before["receipt_sha256"] ==
            value["build"]["authenticated_sha256"] and build_before["source_pin_sha256"] ==
            value["build"]["source_pin_sha256"] and build_before["builder_image"] ==
            comparison.load_json(isolated.resolve_ref(
                root, value["builder"]["before"], "builder before", maximum=MAX_JSON,
                allow_empty=False)), "Build/builder evidence changed")
    builder_after = comparison.load_json(isolated.resolve_ref(
        root, value["builder"]["after"], "builder after", maximum=MAX_JSON,
        allow_empty=False))
    require(builder_after == build_before["builder_image"] and
            value["builder"]["id"] == builder_after["id"] and
            value["builder"]["identity_sha256"] == canonical_digest(builder_after),
            "Immutable builder binding differs")
    tool_before = comparison.load_json(isolated.resolve_ref(
        root, value["toolchain"]["before"], "toolchain before", maximum=MAX_JSON,
        allow_empty=False))
    tool_after = comparison.load_json(isolated.resolve_ref(
        root, value["toolchain"]["after"], "toolchain after", maximum=MAX_JSON,
        allow_empty=False))
    require(tool_before == tool_after and canonical_digest(tool_before) ==
            value["toolchain"]["identity_sha256"] and
            tool_before.get("builder_image_id") == value["builder"]["id"],
            "Source-pinned toolchain changed")
    source_before = comparison.load_json(isolated.resolve_ref(
        root, value["source_freeze"]["before"], "source freeze before",
        maximum=MAX_JSON, allow_empty=False))
    source_after = comparison.load_json(isolated.resolve_ref(
        root, value["source_freeze"]["after"], "source freeze after",
        maximum=MAX_JSON, allow_empty=False))
    copied_build = isolated.resolve_ref(root, value["build"]["receipt"], "build receipt",
                                        maximum=MAX_JSON, allow_empty=False)
    require(file_identity(copied_build)["sha256"] ==
            value["build"]["authenticated_sha256"],
            "Copied build receipt differs from its authenticated SHA-256")
    copied_build_value = comparison.load_json(copied_build)
    require(source_before == source_after and source_before.get("snapshot") ==
            copied_build_value.get("source") and source_before.get("snapshot_sha256") ==
            value["source_freeze"]["snapshot_sha256"] == canonical_digest(
                source_before["snapshot"]), "Source-freeze evidence differs")
    authenticate_projects(definition, copied_build_value)

    scan_before = comparison.load_json(isolated.resolve_ref(
        root, value["scan"]["before"], "scan before", maximum=MAX_JSON,
        allow_empty=False))
    scan_after = comparison.load_json(isolated.resolve_ref(
        root, value["scan"]["after"], "scan after", maximum=MAX_JSON,
        allow_empty=False))
    require(scan_before == scan_after, "Pinned-source inventories changed during scanning")
    require(scan_before.get("source_pin_sha256") ==
            value["build"]["source_pin_sha256"],
            "Source scan is bound to a different source pin")
    validate_scan(scan_before, definition)
    require(scan_before["normalized_native_inventory_sha256"] ==
            value["scan"]["normalized_native_inventory_sha256"] and
            value["applicability"] == {"result": RESULT, "evidence":
                applicability_evidence(file_identity(copied_definition), scan_before)},
            "Applicability result is not reconstructed from native evidence")

    if rehash_build:
        live_receipt, live_build = isolated.full_build_verify(
            copied_build, value["build"]["authenticated_sha256"], value["role"])
        require(live_build == build_before,
                "Live full build verification differs from applicability evidence")
        live_freeze = isolated.source_freeze_verify(live_receipt, live_build)
        require(live_freeze == source_before,
                "Live source-freeze recollection differs from applicability evidence")
        source = isolated.exact_existing_directory(Path(live_build["source_root"]),
                                                   "receipted source")
        live_image, live_toolchain = authority_snapshot(backend, source, live_build)
        require(live_image == builder_after and live_toolchain == tool_after,
                "Live builder/toolchain differs from applicability evidence")
        require(scan_source(source, live_receipt["source"]["pin"], definition) == scan_before,
                "Live pinned-source applicability inventory differs")
    return _build_projection(value, expected_sha256)


def verify(receipt_path, expected_sha256, *, rehash_build=True):
    """Verify a portable applicability receipt and return its normalized projection."""
    return _verify(receipt_path, expected_sha256, rehash_build=rehash_build,
                   backend=isolated.ProductionBackend())


def scan(role, build_receipt, build_receipt_sha256, generic_plan,
         generic_plan_sha256, output, *, backend=None):
    """Scan and seal a bounded N/A result without executing tests or containers."""
    require(role in {"baseline", "custom"}, "Role must be baseline or custom")
    require(SHA256.fullmatch(str(build_receipt_sha256)) and
            SHA256.fullmatch(str(generic_plan_sha256)), "Exact input SHA-256 is required")
    backend = isolated.ProductionBackend() if backend is None else backend
    build_receipt = comparison.literal_file(Path(build_receipt), "build receipt")
    generic_plan = comparison.literal_file(Path(generic_plan), "generic upstream plan")
    definition = reviewed_definition()
    require(file_identity(generic_plan)["sha256"] == generic_plan_sha256,
            "Generic plan differs from its authenticated SHA-256")
    output = isolated.exact_new_path(Path(output), "applicability evidence output")

    # Pin the local Docker authority before inherited build-verifier Docker probes.
    docker_before = backend.docker_identity()
    receipt_before, build_before = isolated.full_build_verify(
        build_receipt, build_receipt_sha256, role)
    authenticate_projects(definition, receipt_before)
    source = isolated.exact_existing_directory(Path(build_before["source_root"]),
                                               "receipted source")
    build_out = isolated.exact_existing_directory(Path(build_before["out_dir"]),
                                                  "receipted OUT")
    require(not isolated.overlaps(output, source) and not isolated.overlaps(output, build_out),
            "Evidence output overlaps a protected source/build tree")
    image_before = isolated.normalize_image(
        backend.inspect_image(build_before["builder_image"]["id"]))
    require(image_before == build_before["builder_image"],
            "Installed builder differs from the receipted immutable image")
    tool_before = isolated.toolchain_record(source, image_before, docker_before)
    freeze_before = isolated.source_freeze_verify(receipt_before, build_before)
    scan_before = scan_source(source, receipt_before["source"]["pin"], definition)

    output.mkdir(mode=0o700)
    (output / "inputs").mkdir(mode=0o700)
    copy_input(build_receipt, output / "inputs/build-receipt.json")
    copy_input(generic_plan, output / "inputs/generic-plan.json")
    copy_input(DEFINITION, output / "inputs/applicability-definition.json")
    copy_input(RUNNER, output / "inputs/phase1_grapheneos_host_applicability.py")
    isolated.write_json_new(output / "build-before.json", build_before)
    isolated.write_json_new(output / "builder-before.json", image_before)
    isolated.write_json_new(output / "toolchain-before.json", tool_before)
    isolated.write_json_new(output / "source-freeze-before.json", freeze_before)
    isolated.write_json_new(output / "scan-before.json", scan_before)

    receipt_after, build_after = isolated.full_build_verify(
        build_receipt, build_receipt_sha256, role)
    require(receipt_after == receipt_before and build_after == build_before,
            "Build receipt changed during applicability scanning")
    authenticate_projects(definition, receipt_after)
    freeze_after = isolated.source_freeze_verify(receipt_after, build_after)
    require(freeze_after == freeze_before,
            "Source freeze changed during applicability scanning")
    scan_after = scan_source(source, receipt_after["source"]["pin"], definition)
    require(scan_after == scan_before,
            "Native source inventory changed during applicability scanning")
    image_after = isolated.normalize_image(
        backend.inspect_image(build_after["builder_image"]["id"]))
    docker_after = backend.docker_identity()
    tool_after = isolated.toolchain_record(source, image_after, docker_after)
    require(image_after == image_before and tool_after == tool_before,
            "Immutable builder/toolchain changed during applicability scanning")
    require(file_identity(build_receipt)["sha256"] == build_receipt_sha256 and
            file_identity(generic_plan)["sha256"] == generic_plan_sha256 and
            file_identity(DEFINITION)["sha256"] == DEFINITION_SHA256 and
            file_identity(RUNNER) == file_identity(
                output / "inputs/phase1_grapheneos_host_applicability.py"),
            "Authenticated applicability inputs changed during scanning")

    isolated.write_json_new(output / "build-after.json", build_after)
    isolated.write_json_new(output / "builder-after.json", image_after)
    isolated.write_json_new(output / "toolchain-after.json", tool_after)
    isolated.write_json_new(output / "source-freeze-after.json", freeze_after)
    isolated.write_json_new(output / "scan-after.json", scan_after)
    definition_identity = file_identity(DEFINITION)
    receipt = {
        "schema": SCHEMA, "kind": RECEIPT_KIND, "scope": SCOPE, "role": role,
        "build": {
            "receipt": portable_ref(output, output / "inputs/build-receipt.json"),
            "authenticated_sha256": build_receipt_sha256,
            "before": portable_ref(output, output / "build-before.json"),
            "after": portable_ref(output, output / "build-after.json"),
            "source_pin_sha256": build_before["source_pin_sha256"],
            "verification": "receipt-verifier-rehash-true-before-and-after",
        },
        "plan": {"file": portable_ref(output, output / "inputs/generic-plan.json"),
                 "sha256": generic_plan_sha256},
        "definition": {
            "file": portable_ref(output, output / "inputs/applicability-definition.json"),
            **definition_identity,
        },
        "builder": {
            "id": image_before["id"], "identity_sha256": canonical_digest(image_before),
            "before": portable_ref(output, output / "builder-before.json"),
            "after": portable_ref(output, output / "builder-after.json"),
        },
        "toolchain": {
            "identity_sha256": canonical_digest(tool_before),
            "before": portable_ref(output, output / "toolchain-before.json"),
            "after": portable_ref(output, output / "toolchain-after.json"),
        },
        "source_freeze": {
            "snapshot_sha256": freeze_before["snapshot_sha256"],
            "before": portable_ref(output, output / "source-freeze-before.json"),
            "after": portable_ref(output, output / "source-freeze-after.json"),
            "verification": "complete-receipted-source-recollection-before-and-after",
        },
        "scan": {
            "normalized_native_inventory_sha256":
                scan_before["normalized_native_inventory_sha256"],
            "before": portable_ref(output, output / "scan-before.json"),
            "after": portable_ref(output, output / "scan-after.json"),
            "verification": "full-pinned-source-native-inventory-before-and-after",
        },
        "applicability": {"result": RESULT,
                          "evidence": applicability_evidence(
                              definition_identity, scan_before)},
        "generator": portable_ref(
            output, output / "inputs/phase1_grapheneos_host_applicability.py"),
    }
    validate_receipt_shape(receipt)
    nonce = secrets.token_hex(16)
    candidate = output / (".applicability-receipt-" + nonce + ".json")
    isolated.write_json_new(candidate, receipt)
    digest = file_identity(candidate)["sha256"]
    try:
        _verify(candidate, digest, rehash_build=False, backend=backend)
    except BaseException:
        candidate.unlink(missing_ok=True)
        isolated.fsync_directory(output)
        raise
    receipt_path = output / "applicability-receipt.json"
    os.rename(candidate, receipt_path)
    isolated.fsync_directory(output)
    return receipt_path, digest


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    actions = value.add_subparsers(dest="action", required=True)
    scan_parser = actions.add_parser("scan", help="seal a bounded pinned-source N/A result")
    scan_parser.add_argument("--role", choices=("baseline", "custom"), required=True)
    scan_parser.add_argument("--build-receipt", type=Path, required=True)
    scan_parser.add_argument("--build-receipt-sha256", required=True)
    scan_parser.add_argument("--generic-plan", type=Path, required=True)
    scan_parser.add_argument("--generic-plan-sha256", required=True)
    scan_parser.add_argument("--output", type=Path, required=True)
    verify_parser = actions.add_parser("verify", help="verify an applicability receipt")
    verify_parser.add_argument("--receipt", type=Path, required=True)
    verify_parser.add_argument("--expected-sha256", required=True)
    verify_parser.add_argument("--no-rehash-build", action="store_true")
    return value


def main(argv=None):
    arguments = parser().parse_args(argv)
    try:
        if arguments.action == "scan":
            path, digest = scan(
                arguments.role, arguments.build_receipt, arguments.build_receipt_sha256,
                arguments.generic_plan, arguments.generic_plan_sha256, arguments.output)
            print(str(path))
            print(digest)
        else:
            projection = verify(arguments.receipt, arguments.expected_sha256,
                                rehash_build=not arguments.no_rehash_build)
            print(json.dumps(projection, indent=2, sort_keys=True))
    except comparison.EvidenceError as error:
        print("FAIL: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
