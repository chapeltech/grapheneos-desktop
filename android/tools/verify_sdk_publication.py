#!/usr/bin/env python3
"""Fail-closed verifier for the Wonad desktop SDK v3.0.1 publication.

The verifier deliberately knows the complete Maven and archive shape.  A file
which a future publisher adds is not silently trusted: updating this verifier
and its tests is part of changing the publication contract.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile


SDK_CONTRACT_PATH = Path(__file__).with_name("sdk_contract.py")
SDK_CONTRACT_SPEC = importlib.util.spec_from_file_location("wonad_sdk_contract", SDK_CONTRACT_PATH)
if SDK_CONTRACT_SPEC is None or SDK_CONTRACT_SPEC.loader is None:
    raise RuntimeError("Cannot load the SDK contract verifier")
sdk_contract = importlib.util.module_from_spec(SDK_CONTRACT_SPEC)
SDK_CONTRACT_SPEC.loader.exec_module(sdk_contract)


GROUP = "org.wonad"
ARTIFACT = "desktop-sdk"
VERSION = "3.0.1"
COORDINATE_PATH = Path("org/wonad/desktop-sdk")
VERSION_PATH = COORDINATE_PATH / VERSION
BASE_NAME = f"{ARTIFACT}-{VERSION}"
PRIMARY_FILES = (
    f"{BASE_NAME}.aar",
    f"{BASE_NAME}-sources.jar",
    f"{BASE_NAME}-contract.zip",
    f"{BASE_NAME}.pom",
    f"{BASE_NAME}.module",
)
CHECKSUMS = ("md5", "sha1", "sha256", "sha512")
EXPECTED_SIGNATURE = "db6ac649c34d8c25ab0bdd4a46802639deb3972d376070c6c3cdd811d7962fff"
CONTRACT_FILES = {
    "API-v3.md": 0o644,
    "desktop-sdk-contract-v3.json": 0o644,
    "verify-desktop-sdk-contract.py": 0o755,
}
DOCUMENTATION_REQUIREMENTS = (
    "# Wonad external-desktop API v3 — SDK documentation 3.0.1",
    "one process-global monotonic clock",
    "`T + 1000` milliseconds",
    "Attempts strictly before that boundary are rejected",
    "`launcherPage` is synchronous and nullable",
    "`showTransferPicker` is a one-way, fire-and-forget request",
    "API v3 has no exact",
    "`org.wonad:desktop-sdk:3.0.1`",
)
AAR_FILES = {
    "R.txt",
    "AndroidManifest.xml",
    "classes.jar",
    "META-INF/com/android/build/gradle/aar-metadata.properties",
}
SOURCE_FILES = {
    "META-INF/MANIFEST.MF",
    *{
        f"org/wonad/desktop/api/{name}.java"
        for name in (
            "DesktopDisplay", "DesktopFrame", "DesktopLaunchEntry",
            "DesktopLaunchPage", "DesktopPlacement", "DesktopRect",
            "DesktopShellRegion", "DesktopSnapshot", "DesktopTask",
            "IDesktopBroker", "IDesktopCallback", "IDesktopSession",
        )
    },
    "org/wonad/desktop/api/DesktopFailure.kt",
    "org/wonad/desktop/api/DesktopProtocol.kt",
}
SOURCE_DIRECTORIES = {
    "META-INF/", "org/", "org/wonad/", "org/wonad/desktop/",
    "org/wonad/desktop/api/",
}
CLASS_FILES = {
    "META-INF/desktop-sdk_release.kotlin_module",
    "org/wonad/desktop/api/DesktopFailure.class",
    "org/wonad/desktop/api/DesktopProtocol.class",
    *{
        f"org/wonad/desktop/api/{name}{suffix}.class"
        for name, suffixes in {
            "DesktopDisplay": ("", "$1", "$_Parcel"),
            "DesktopFrame": ("", "$1"),
            "DesktopLaunchEntry": ("", "$1"),
            "DesktopLaunchPage": ("", "$1"),
            "DesktopPlacement": ("", "$1", "$_Parcel"),
            "DesktopRect": ("", "$1"),
            "DesktopShellRegion": ("", "$1", "$_Parcel"),
            "DesktopSnapshot": ("", "$1"),
            "DesktopTask": ("", "$1", "$_Parcel"),
            "IDesktopBroker": ("", "$Default", "$Stub", "$Stub$Proxy"),
            "IDesktopCallback": ("", "$Default", "$Stub", "$Stub$Proxy", "$_Parcel"),
            "IDesktopSession": ("", "$Default", "$Stub", "$Stub$Proxy", "$_Parcel"),
        }.items()
        for suffix in suffixes
    },
}
CLASS_DIRECTORIES = {
    "META-INF/", "org/", "org/wonad/", "org/wonad/desktop/",
    "org/wonad/desktop/api/",
}
FORBIDDEN_PUBLIC_NAME = re.compile(r"\b[A-Za-z0-9_]*Native[A-Za-z0-9_]*\b")
FORBIDDEN_API2_NAMES = (
    "DesktopLayout", "DesktopWorkspace", "DesktopWindow", "DesktopMonitor",
    "DesktopCommand", "openNativeSession", "NATIVE_API_VERSION",
)
MAX_ARCHIVE_ENTRIES = 256
MAX_ENTRY_SIZE = 16 * 1024 * 1024
MAX_ARCHIVE_SIZE = 64 * 1024 * 1024


class VerificationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def digest(data: bytes, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, data).hexdigest()


def _safe_member_name(name: str) -> None:
    require(bool(name) and "\x00" not in name, f"unsafe empty/NUL ZIP entry: {name!r}")
    require(not any(ord(character) < 32 or ord(character) == 127 for character in name),
            f"unsafe control character ZIP entry: {name!r}")
    require("\\" not in name, f"unsafe backslash ZIP entry: {name!r}")
    require(not name.startswith("/"), f"unsafe absolute ZIP entry: {name!r}")
    require(not re.match(r"^[A-Za-z]:", name), f"unsafe drive ZIP entry: {name!r}")
    value = name[:-1] if name.endswith("/") else name
    require(bool(value), f"unsafe root ZIP entry: {name!r}")
    raw_parts = value.split("/")
    require(all(raw_parts), f"unsafe empty path component ZIP entry: {name!r}")
    parts = PurePosixPath(value).parts
    require(all(part not in ("", ".", "..") for part in parts),
            f"unsafe traversal ZIP entry: {name!r}")


def read_safe_zip(source: Path | bytes, label: str) -> dict[str, tuple[zipfile.ZipInfo, bytes]]:
    """Read and CRC-check a bounded ZIP while rejecting extraction hazards."""
    stream = io.BytesIO(source) if isinstance(source, bytes) else source
    try:
        archive = zipfile.ZipFile(stream)
    except (OSError, zipfile.BadZipFile) as exc:
        raise VerificationError(f"{label}: invalid ZIP: {exc}") from exc
    with archive:
        require(not archive.comment, f"{label}: ZIP comment is not allowed")
        infos = archive.infolist()
        require(len(infos) <= MAX_ARCHIVE_ENTRIES, f"{label}: too many ZIP entries")
        names = [info.filename for info in infos]
        require(len(names) == len(set(names)), f"{label}: duplicate ZIP entry")
        total = 0
        result: dict[str, tuple[zipfile.ZipInfo, bytes]] = {}
        for info in infos:
            _safe_member_name(info.filename)
            require(not (info.flag_bits & 1), f"{label}: encrypted ZIP entry: {info.filename}")
            mode = (info.external_attr >> 16) & 0o177777
            kind = stat.S_IFMT(mode)
            if kind:
                require(kind in (stat.S_IFREG, stat.S_IFDIR),
                        f"{label}: non-regular ZIP entry: {info.filename}")
                require((kind == stat.S_IFDIR) == info.filename.endswith("/"),
                        f"{label}: ZIP mode/name type mismatch: {info.filename}")
            require(not info.is_dir() or info.file_size == 0,
                    f"{label}: directory ZIP entry has payload: {info.filename}")
            require(info.file_size <= MAX_ENTRY_SIZE,
                    f"{label}: oversized ZIP entry: {info.filename}")
            total += info.file_size
            require(total <= MAX_ARCHIVE_SIZE, f"{label}: oversized ZIP payload")
            if info.file_size > 1024 * 1024:
                require(info.compress_size > 0 and info.file_size / info.compress_size <= 200,
                        f"{label}: suspicious ZIP compression ratio: {info.filename}")
            try:
                payload = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                raise VerificationError(f"{label}: unreadable ZIP entry {info.filename}: {exc}") from exc
            require(len(payload) == info.file_size,
                    f"{label}: short ZIP entry: {info.filename}")
            result[info.filename] = (info, payload)
        return result


def _file_entries(entries: dict[str, tuple[zipfile.ZipInfo, bytes]]) -> set[str]:
    return {name for name, (info, _) in entries.items() if not info.is_dir()}


def _reject_legacy_names(text: str, label: str) -> None:
    match = FORBIDDEN_PUBLIC_NAME.search(text)
    require(match is None, f"{label}: forbidden Native public name {match.group(0)!r}" if match else "")
    for name in FORBIDDEN_API2_NAMES:
        require(name not in text, f"{label}: forbidden draft-v2 name {name!r}")


def canonical_contract_signature(contract: dict[str, object]) -> str:
    signed = {
        "aidl": contract.get("aidl"),
        "constants": contract.get("constants"),
        "binder_transactions": contract.get("binder_transactions"),
        "kotlin_api": contract.get("kotlin_api"),
        "jvm_abi": contract.get("jvm_abi"),
    }
    encoded = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
    return digest(encoded)


def _verify_contract(entries: dict[str, tuple[zipfile.ZipInfo, bytes]], source_root: Path,
                     classes_jar: bytes, actual_jvm_abi: dict[str, object]) -> tuple[str, dict[str, object]]:
    require(_file_entries(entries) == set(CONTRACT_FILES),
            f"contract ZIP entries differ: {sorted(_file_entries(entries))}")
    require(set(entries) == set(CONTRACT_FILES), "contract ZIP contains directory or extra entries")
    for name, wanted_mode in CONTRACT_FILES.items():
        info, payload = entries[name]
        mode = (info.external_attr >> 16) & 0o777
        require(mode == wanted_mode, f"contract ZIP mode for {name}: {oct(mode)}")
        require(info.date_time == (1980, 2, 1, 0, 0, 0),
                f"contract ZIP timestamp for {name} is not normalized")
        expected_path = {
            "API-v3.md": source_root / "desktop-sdk/API-v3.md",
            "desktop-sdk-contract-v3.json": source_root / ("tests/fixtures/desktop-sdk-contract-v3.1.json"
                if VERSION == "3.1.0" else "tests/fixtures/desktop-sdk-contract-v3.json"),
            "verify-desktop-sdk-contract.py": source_root / "tools/sdk_contract.py",
        }[name]
        require(expected_path.is_file(), f"missing publication input: {expected_path}")
        require(payload == expected_path.read_bytes(), f"contract ZIP {name} differs from source")

    try:
        contract = json.loads(entries["desktop-sdk-contract-v3.json"][1])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid contract JSON: {exc}") from exc
    require(contract.get("schema") == 3, "contract schema is not 3")
    require(contract.get("scope") ==
            "source_and_published_jvm_compatibility_not_runtime_qualification",
            "contract scope differs")
    require(contract.get("constants", {}).get("API_VERSION") == "3", "contract API_VERSION is not 3")
    signature = canonical_contract_signature(contract)
    require(contract.get("signature_sha256") == signature,
            "contract canonical signature is inconsistent")
    require(signature == EXPECTED_SIGNATURE, "contract canonical signature is not frozen v3")
    require(contract.get("jvm_abi") == actual_jvm_abi,
            "compiled public JVM ABI differs from the frozen ledger")
    serialized = json.dumps(contract, sort_keys=True)
    _reject_legacy_names(serialized, "contract JSON")

    api_text = entries["API-v3.md"][1].decode("utf-8")
    signatures = re.findall(r"\b[0-9a-f]{64}\b", api_text)
    require(signatures.count(signature) == 1,
            "API-v3.md must state the frozen signature exactly once")
    require("`API_VERSION` is exactly 3" in api_text, "API-v3.md does not freeze API_VERSION 3")
    require(all(api_text.count(marker) == 1 for marker in DOCUMENTATION_REQUIREMENTS),
            "API-v3.md lacks unique SDK 3.0.1 picker admission/observability language")

    with tempfile.TemporaryDirectory(prefix="wonad-sdk-contract-") as temporary:
        temp = Path(temporary)
        script = temp / "verify-desktop-sdk-contract.py"
        baseline = temp / "desktop-sdk-contract-v3.json"
        compiled = temp / "classes.jar"
        script.write_bytes(entries["verify-desktop-sdk-contract.py"][1])
        baseline.write_bytes(entries["desktop-sdk-contract-v3.json"][1])
        compiled.write_bytes(classes_jar)
        script.chmod(0o700)
        process = subprocess.run(
            [sys.executable, str(script), "--sdk", str(source_root / "desktop-sdk"),
             "--baseline", str(baseline), "--classes-jar", str(compiled)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
        )
        require(process.returncode == 0,
                "bundled contract verifier rejected source: " + process.stdout.strip())
    members = {
        name: {
            "sha256": digest(entries[name][1]),
            "bytes": len(entries[name][1]),
            "mode": (entries[name][0].external_attr >> 16) & 0o777,
        }
        for name in sorted(CONTRACT_FILES)
    }
    return signature, members


def _verify_sources(entries: dict[str, tuple[zipfile.ZipInfo, bytes]], source_root: Path) -> None:
    require(_file_entries(entries) == SOURCE_FILES,
            f"source JAR files differ: {sorted(_file_entries(entries) ^ SOURCE_FILES)}")
    require(set(entries) == SOURCE_FILES | SOURCE_DIRECTORIES,
            "source JAR directory/entry set differs")
    for name in SOURCE_FILES:
        require(entries[name][0].date_time == (1980, 2, 1, 0, 0, 0),
                f"source JAR timestamp is not normalized: {name}")
        if name.endswith((".java", ".kt")):
            try:
                text = entries[name][1].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise VerificationError(f"source JAR non-UTF-8 source: {name}") from exc
            require("org.wonad.desktop.api" in text, f"source has wrong package: {name}")
            require(" * Using: " not in text,
                    f"source JAR leaks a nondeterministic AIDL invocation: {name}")
            if name.endswith(".java"):
                require(" * Generated from the frozen Wonad API-v3 AIDL." in text,
                        f"source JAR lacks normalized AIDL provenance: {name}")
            _reject_legacy_names(name + "\n" + text, f"source JAR {name}")
            if name.endswith(".kt"):
                expected = source_root / "desktop-sdk/src/main/kotlin" / name
                require(expected.is_file() and entries[name][1] == expected.read_bytes(),
                        f"source JAR Kotlin source differs from contract source: {name}")
    require(entries["META-INF/MANIFEST.MF"][1] == b"Manifest-Version: 1.0\r\n\r\n",
            "source JAR manifest differs")
    protocol = entries["org/wonad/desktop/api/DesktopProtocol.kt"][1].decode()
    require(re.search(r"\bAPI_VERSION\s*=\s*3\b", protocol) is not None,
            "DesktopProtocol source does not set API_VERSION to 3")


def _verify_aar(entries: dict[str, tuple[zipfile.ZipInfo, bytes]]) -> tuple[bytes, dict[str, object]]:
    require(_file_entries(entries) == AAR_FILES,
            f"AAR files differ: {sorted(_file_entries(entries) ^ AAR_FILES)}")
    require(set(entries) == AAR_FILES, "AAR contains directory or extra entries")
    for name, (info, _) in entries.items():
        require(info.date_time == (1980, 2, 1, 0, 0, 0),
                f"AAR timestamp is not normalized: {name}")
    require(entries["R.txt"][1] == b"", "types-only AAR unexpectedly contains resources")
    require(entries["META-INF/com/android/build/gradle/aar-metadata.properties"][1] == (
        b"aarFormatVersion=1.0\n"
        b"aarMetadataVersion=1.0\n"
        b"minCompileSdk=1\n"
        b"minCompileSdkExtension=0\n"
        b"minAndroidGradlePluginVersion=1.0.0\n"
        b"coreLibraryDesugaringEnabled=false\n"
    ), "AAR metadata differs")
    try:
        manifest = ET.fromstring(entries["AndroidManifest.xml"][1])
    except ET.ParseError as exc:
        raise VerificationError(f"invalid AAR manifest: {exc}") from exc
    require(manifest.tag == "manifest", "AAR manifest root is not manifest")
    require(manifest.attrib == {"package": "org.wonad.desktop.api"},
            "AAR manifest attributes/package differ")
    require([child.tag for child in manifest] == ["uses-sdk"],
            "types-only AAR manifest contains permissions/components")
    android_ns = "{http://schemas.android.com/apk/res/android}"
    require(manifest[0].attrib == {android_ns + "minSdkVersion": "35"},
            "AAR uses-sdk/minSdk differs")

    classes = read_safe_zip(entries["classes.jar"][1], "AAR classes.jar")
    require(_file_entries(classes) == CLASS_FILES,
            f"classes.jar files differ: {sorted(_file_entries(classes) ^ CLASS_FILES)}")
    require(set(classes) == CLASS_FILES | CLASS_DIRECTORIES,
            "classes.jar directory/entry set differs")
    for name, (info, payload) in classes.items():
        _reject_legacy_names(name, "classes.jar")
        if not info.is_dir() and name.endswith(".class"):
            # JVM constant-pool strings are modified UTF-8/ASCII for these
            # identifiers, so a byte scan also catches an old method or
            # descriptor hidden inside an otherwise neutrally named class.
            _reject_legacy_names(payload.decode("latin-1"), f"classes.jar {name}")
    class_payloads = {name: payload for name, (info, payload) in classes.items()
                      if not info.is_dir() and name.endswith(".class")}
    try:
        ledger = sdk_contract.jvm_abi_from_entries(class_payloads)
    except (ValueError, KeyError, TypeError) as exc:
        raise VerificationError(f"invalid compiled public JVM ABI: {exc}") from exc
    return entries["classes.jar"][1], ledger


def _verify_pom(data: bytes) -> None:
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise VerificationError(f"invalid POM: {exc}") from exc
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    local_names = [child.tag.rsplit("}", 1)[-1] for child in root]
    require(local_names == ["modelVersion", "groupId", "artifactId", "version", "packaging",
                            "dependencies"], "POM element set/order differs")
    get = lambda tag: root.findtext(f"m:{tag}", namespaces=ns)
    require((get("groupId"), get("artifactId"), get("version"), get("packaging")) ==
            (GROUP, ARTIFACT, VERSION, "aar"), "POM coordinates/packaging differ")
    dependencies = root.findall("m:dependencies/m:dependency", ns)
    require(len(dependencies) == 1, "POM dependency set differs")
    dep = dependencies[0]
    require([child.tag.rsplit("}", 1)[-1] for child in dep] ==
            ["groupId", "artifactId", "version", "scope"],
            "POM dependency element set/order differs")
    find = lambda tag: dep.findtext(f"m:{tag}", namespaces=ns)
    require((find("groupId"), find("artifactId"), find("version"), find("scope")) ==
            ("org.jetbrains.kotlin", "kotlin-stdlib", "2.1.21", "compile"),
            "POM dependency differs")


def _verify_module(data: bytes, version_dir: Path) -> None:
    try:
        module = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid Gradle module metadata: {exc}") from exc
    require(module.get("formatVersion") == "1.1", "Gradle module format differs")
    require(set(module) == {"formatVersion", "component", "createdBy", "variants"},
            "Gradle module top-level fields differ")
    require(module.get("component") == {"group": GROUP, "module": ARTIFACT, "version": VERSION,
                                        "attributes": {"org.gradle.status": "release"}},
            "Gradle module component differs")
    require(module.get("createdBy") == {"gradle": {"version": "8.11.1"}},
            "Gradle module producer differs")
    expected_variants = {
        "releaseVariantReleaseApiPublication": {
            "attributes": {
                "org.gradle.category": "library",
                "org.gradle.dependency.bundling": "external",
                "org.gradle.libraryelements": "aar",
                "org.gradle.usage": "java-api",
            },
            "file": f"{BASE_NAME}.aar",
            "dependency": True,
        },
        "releaseVariantReleaseRuntimePublication": {
            "attributes": {
                "org.gradle.category": "library",
                "org.gradle.dependency.bundling": "external",
                "org.gradle.libraryelements": "aar",
                "org.gradle.usage": "java-runtime",
            },
            "file": f"{BASE_NAME}.aar",
            "dependency": True,
        },
        "releaseVariantReleaseSourcePublication": {
            "attributes": {
                "org.gradle.category": "documentation",
                "org.gradle.dependency.bundling": "external",
                "org.gradle.docstype": "sources",
                "org.gradle.usage": "java-runtime",
            },
            "file": f"{BASE_NAME}-sources.jar",
            "dependency": False,
        },
    }
    variants = module.get("variants")
    require(isinstance(variants, list), "Gradle module variants are not a list")
    require(all(isinstance(item, dict) for item in variants), "invalid Gradle module variant")
    require([item.get("name") for item in variants] == list(expected_variants),
            "Gradle module variant set/order differs")
    files: list[dict[str, object]] = []
    for variant in variants:
        require(isinstance(variant, dict), "invalid Gradle module variant")
        expected = expected_variants[variant["name"]]
        expected_keys = {"name", "attributes", "files"}
        if expected["dependency"]:
            expected_keys.add("dependencies")
        require(set(variant) == expected_keys, f"Gradle module fields differ for {variant['name']}")
        require(variant.get("attributes") == expected["attributes"],
                f"Gradle module attributes differ for {variant['name']}")
        if expected["dependency"]:
            require(variant.get("dependencies") == [{
                "group": "org.jetbrains.kotlin", "module": "kotlin-stdlib",
                "version": {"requires": "2.1.21"},
            }], f"Gradle module dependencies differ for {variant['name']}")
        variant_files = variant.get("files")
        require(isinstance(variant_files, list) and len(variant_files) == 1,
                f"Gradle module file list differs for {variant['name']}")
        require(isinstance(variant_files[0], dict) and
                variant_files[0].get("name") == expected["file"],
                f"Gradle module file differs for {variant['name']}")
        files.extend(variant_files)
    for item in files:
        require(isinstance(item, dict), "invalid Gradle module file metadata")
        require(set(item) == {"name", "url", "size", *CHECKSUMS},
                f"Gradle module file fields differ for {item.get('name')}")
        name = item["name"]
        target = version_dir / str(name)
        require(item.get("url") == name, f"Gradle module has non-local URL for {name}")
        require(item.get("size") == target.stat().st_size, f"Gradle module size differs for {name}")
        for algorithm in CHECKSUMS:
            require(item.get(algorithm) == digest(target.read_bytes(), algorithm),
                    f"Gradle module {algorithm} differs for {name}")
    names = {item.get("name") for item in files}
    require(names == {f"{BASE_NAME}.aar", f"{BASE_NAME}-sources.jar"},
            "Gradle module file set differs")


def _verify_metadata(data: bytes) -> str:
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise VerificationError(f"invalid Maven metadata: {exc}") from exc
    require(root.findtext("groupId") == GROUP and root.findtext("artifactId") == ARTIFACT,
            "Maven metadata coordinates differ")
    require([child.tag for child in root] == ["groupId", "artifactId", "versioning"],
            "Maven metadata element set/order differs")
    versioning = root.find("versioning")
    require(versioning is not None, "Maven metadata lacks versioning")
    require([child.tag for child in versioning] ==
            ["latest", "release", "versions", "lastUpdated"],
            "Maven metadata versioning element set/order differs")
    require(versioning.findtext("latest") == VERSION and versioning.findtext("release") == VERSION,
            "Maven metadata latest/release differs")
    require([item.text for item in versioning.findall("versions/version")] == [VERSION],
            "Maven metadata version set differs")
    updated = versioning.findtext("lastUpdated") or ""
    require(re.fullmatch(r"[0-9]{14}", updated) is not None, "Maven metadata lastUpdated differs")
    return updated


def _expected_repository_files() -> set[Path]:
    versioned = set()
    for name in PRIMARY_FILES:
        path = VERSION_PATH / name
        versioned.add(path)
        versioned.update(Path(str(path) + "." + algorithm) for algorithm in CHECKSUMS)
    metadata = COORDINATE_PATH / "maven-metadata.xml"
    return versioned | {metadata} | {
        Path(str(metadata) + "." + algorithm) for algorithm in CHECKSUMS
    }


def _verify_tree(repository: Path) -> None:
    require(repository.is_dir() and not repository.is_symlink(),
            f"publication repository is not a real directory: {repository}")
    found: set[Path] = set()
    found_directories: set[Path] = set()
    for root, directories, files in os.walk(repository, followlinks=False):
        base = Path(root)
        for directory in directories:
            path = base / directory
            require(not path.is_symlink(), f"publication contains symlink directory: {path}")
            found_directories.add(path.relative_to(repository))
        for filename in files:
            path = base / filename
            require(not path.is_symlink() and path.is_file(),
                    f"publication contains non-regular file: {path}")
            found.add(path.relative_to(repository))
    expected = _expected_repository_files()
    expected_directories = {
        Path("org"), Path("org/wonad"), COORDINATE_PATH, VERSION_PATH,
    }
    require(found_directories == expected_directories,
            f"publication directory set differs; missing={sorted(map(str, expected_directories-found_directories))}, "
            f"extra={sorted(map(str, found_directories-expected_directories))}")
    require(found == expected,
            f"publication file set differs; missing={sorted(map(str, expected-found))}, "
            f"extra={sorted(map(str, found-expected))}")
    for relative in found:
        size = (repository / relative).stat().st_size
        if any(str(relative).endswith("." + algorithm) for algorithm in CHECKSUMS):
            require(size in {32, 40, 64, 128}, f"checksum sidecar size differs: {relative}")
        elif relative.name.endswith((".pom", ".module", ".xml")):
            require(size <= 1024 * 1024, f"oversized metadata file: {relative}")
        else:
            require(size <= 128 * 1024 * 1024, f"oversized publication artifact: {relative}")


def _verify_sidecars(repository: Path) -> None:
    primaries = [VERSION_PATH / name for name in PRIMARY_FILES]
    primaries.append(COORDINATE_PATH / "maven-metadata.xml")
    for relative in primaries:
        data = (repository / relative).read_bytes()
        for algorithm in CHECKSUMS:
            sidecar = Path(str(repository / relative) + "." + algorithm)
            expected = digest(data, algorithm)
            try:
                stated = sidecar.read_text("ascii")
            except UnicodeDecodeError as exc:
                raise VerificationError(f"non-ASCII checksum sidecar: {sidecar}") from exc
            require(stated == expected, f"incorrect {algorithm} sidecar for {relative}")


def verify_repository(repository: Path, source_root: Path) -> dict[str, object]:
    require(not repository.is_symlink(), f"publication repository is symlinked: {repository}")
    repository = repository.resolve()
    source_root = source_root.resolve()
    _verify_tree(repository)
    _verify_sidecars(repository)
    version_dir = repository / VERSION_PATH
    aar_path = version_dir / f"{BASE_NAME}.aar"
    sources_path = version_dir / f"{BASE_NAME}-sources.jar"
    contract_path = version_dir / f"{BASE_NAME}-contract.zip"
    pom_path = version_dir / f"{BASE_NAME}.pom"
    module_path = version_dir / f"{BASE_NAME}.module"
    classes_jar, actual_jvm_abi = _verify_aar(read_safe_zip(aar_path, "desktop SDK AAR"))
    _verify_sources(read_safe_zip(sources_path, "desktop SDK source JAR"), source_root)
    signature, contract_members = _verify_contract(
        read_safe_zip(contract_path, "desktop SDK contract ZIP"),
        source_root, classes_jar, actual_jvm_abi)
    _verify_pom(pom_path.read_bytes())
    _verify_module(module_path.read_bytes(), version_dir)
    last_updated = _verify_metadata((repository / COORDINATE_PATH / "maven-metadata.xml").read_bytes())
    hashes = {name: digest((version_dir / name).read_bytes()) for name in PRIMARY_FILES}
    return {
        "coordinate": f"{GROUP}:{ARTIFACT}:{VERSION}",
        "contract_signature": signature,
        "contract_members": contract_members,
        "artifact_sha256": hashes,
        "maven_last_updated": last_updated,
    }


def compare_repositories(first: Path, second: Path, source_root: Path) -> dict[str, object]:
    first_result = verify_repository(first, source_root)
    second_result = verify_repository(second, source_root)
    require(first_result["artifact_sha256"] == second_result["artifact_sha256"],
            "immutable artifact hashes differ between publications")
    # Maven's repository index records publication wall-clock time.  It and its
    # checksum sidecars are not release artifacts; both repositories were still
    # fully verified above.  Everything under the immutable version is compared.
    return {
        "first": first_result,
        "second": second_result,
        "reproducible": True,
        "comparison_scope": list(PRIMARY_FILES),
        "excluded_repository_index_field": "maven-metadata.xml/versioning/lastUpdated",
    }


def select_version_3_1():
    """Explicit successor profile; the default historical 3.0.1 pins stay intact."""
    global VERSION, VERSION_PATH, BASE_NAME, PRIMARY_FILES, EXPECTED_SIGNATURE, DOCUMENTATION_REQUIREMENTS
    VERSION = "3.1.0"
    VERSION_PATH = COORDINATE_PATH / VERSION
    BASE_NAME = f"{ARTIFACT}-{VERSION}"
    PRIMARY_FILES = tuple(BASE_NAME + suffix for suffix in (".aar", "-sources.jar", "-contract.zip", ".pom", ".module"))
    EXPECTED_SIGNATURE = "0182df553005ed145288380526f40f593763573d458f8147970840d973d13adf"
    DOCUMENTATION_REQUIREMENTS = tuple(marker.replace("3.0.1", "3.1.0") for marker in DOCUMENTATION_REQUIREMENTS)
    SOURCE_FILES.update({"org/wonad/desktop/api/DesktopShortcutKeys.kt", "org/wonad/desktop/api/DesktopShortcutProfile.java"})
    CLASS_FILES.update({"org/wonad/desktop/api/DesktopShortcutKeys.class",
        "org/wonad/desktop/api/DesktopShortcutProfile.class", "org/wonad/desktop/api/DesktopShortcutProfile$1.class"})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path, help="root of the Maven repository")
    parser.add_argument("--compare", type=Path,
                        help="independently verify this repository and compare immutable artifacts")
    parser.add_argument("--source-root", type=Path,
                        default=Path(__file__).resolve().parents[1],
                        help="Android source root used to verify the contract payload")
    parser.add_argument("--version", choices=("3.0.1", "3.1.0"), default="3.0.1")
    arguments = parser.parse_args(argv)
    if arguments.version == "3.1.0":
        select_version_3_1()
    try:
        if arguments.compare:
            result = compare_repositories(arguments.repository, arguments.compare,
                                          arguments.source_root)
        else:
            result = verify_repository(arguments.repository, arguments.source_root)
            result["reproducible"] = None
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, VerificationError, KeyError, TypeError, AttributeError,
            UnicodeError, subprocess.TimeoutExpired) as exc:
        print(f"desktop SDK publication verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
