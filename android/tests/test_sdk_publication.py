#!/usr/bin/env python3
"""Host-side negative and reproducibility tests for the SDK publisher."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import stat
import struct
import tempfile
import unittest
import warnings
import zipfile


ANDROID = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_sdk_publication", ANDROID / "tools/verify_sdk_publication.py")
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)
verifier.select_version_3_1()


def zip_bytes(files: dict[str, bytes], modes: dict[str, int] | None = None,
              directories: set[str] | None = None) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(directories or ()):
            info = zipfile.ZipInfo(name, (1980, 2, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFDIR | 0o755) << 16
            archive.writestr(info, b"")
        for name in sorted(files):
            info = zipfile.ZipInfo(name, (1980, 2, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            mode = (modes or {}).get(name, 0o644)
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(info, files[name])
    return output.getvalue()


class ConstantPool:
    def __init__(self):
        self.entries: list[tuple[int, bytes] | None] = [None]
        self.index: dict[tuple[object, ...], int] = {}

    def add(self, key: tuple[object, ...], tag: int, payload: bytes,
            wide: bool = False) -> int:
        if key in self.index:
            return self.index[key]
        result = len(self.entries)
        self.index[key] = result
        self.entries.append((tag, payload))
        if wide:
            self.entries.append(None)
        return result

    def utf8(self, value: str) -> int:
        payload = value.encode("utf-8")
        return self.add(("utf8", value), 1, struct.pack(">H", len(payload)) + payload)

    def clazz(self, value: str) -> int:
        return self.add(("class", value), 7, struct.pack(">H", self.utf8(value)))

    def constant(self, value: dict[str, object]) -> int:
        kind, item = value["kind"], value["value"]
        if kind == "Integer":
            return self.add((kind, item), 3, int(item).to_bytes(4, "big", signed=True))
        if kind == "Float":
            return self.add((kind, item), 4, bytes.fromhex(str(item)))
        if kind == "Long":
            return self.add((kind, item), 5, int(item).to_bytes(8, "big", signed=True), True)
        if kind == "Double":
            return self.add((kind, item), 6, bytes.fromhex(str(item)), True)
        if kind == "String":
            return self.add((kind, item), 8, struct.pack(">H", self.utf8(str(item))))
        raise AssertionError(f"unsupported fixture constant {kind}")

    def encode(self) -> bytes:
        body = b"".join(bytes((entry[0],)) + entry[1]
                        for entry in self.entries[1:] if entry is not None)
        return struct.pack(">H", len(self.entries)) + body


def class_bytes(name: str, row: dict[str, object] | None,
                private_padding: bytes = b"") -> bytes:
    pool = ConstantPool()
    access = int(row["access"]) if row is not None else 0x0020
    super_name = row.get("super") if row is not None else "java/lang/Object"
    interfaces = list(row.get("interfaces", [])) if row is not None else []
    this_index = pool.clazz(name)
    super_index = pool.clazz(str(super_name)) if super_name else 0
    interface_indexes = [pool.clazz(str(item)) for item in interfaces]

    def attribute(attribute_name: str, payload: bytes) -> bytes:
        return struct.pack(">HI", pool.utf8(attribute_name), len(payload)) + payload

    def attributes(items: list[bytes]) -> bytes:
        return struct.pack(">H", len(items)) + b"".join(items)

    def member(item: dict[str, object], kind: str) -> bytes:
        member_attributes = []
        if "signature" in item:
            member_attributes.append(attribute("Signature", struct.pack(">H", pool.utf8(str(item["signature"])))))
        if kind == "field" and "constant" in item:
            member_attributes.append(attribute("ConstantValue", struct.pack(">H", pool.constant(item["constant"]))))
        if kind == "method" and item.get("exceptions"):
            exceptions = [pool.clazz(str(value)) for value in item["exceptions"]]
            member_attributes.append(attribute("Exceptions", struct.pack(">H", len(exceptions)) +
                                               b"".join(struct.pack(">H", value) for value in exceptions)))
        return (struct.pack(">HHH", int(item["access"]), pool.utf8(str(item["name"])),
                            pool.utf8(str(item["descriptor"]))) + attributes(member_attributes))

    fields = [member(item, "field") for item in (row or {}).get("fields", [])]
    methods = [member(item, "method") for item in (row or {}).get("methods", [])]
    class_attributes = []
    if row is not None and "signature" in row:
        class_attributes.append(attribute("Signature", struct.pack(">H", pool.utf8(str(row["signature"])))))
    if row is not None and "inner_access" in row:
        outer, inner = name.rsplit("$", 1)
        inner_payload = (struct.pack(">H", 1) + struct.pack(">HHHH", this_index,
                         pool.clazz(outer), pool.utf8(inner), int(row["inner_access"])))
        class_attributes.append(attribute("InnerClasses", inner_payload))
    if private_padding:
        class_attributes.append(attribute("FixturePrivatePadding", private_padding))
    # Member encoding may have extended the pool, so emit it only now.
    return (struct.pack(">IHH", 0xCAFEBABE, 0, 61) + pool.encode() +
            struct.pack(">HHH", access, this_index, super_index) +
            struct.pack(">H", len(interface_indexes)) +
            b"".join(struct.pack(">H", value) for value in interface_indexes) +
            struct.pack(">H", len(fields)) + b"".join(fields) +
            struct.pack(">H", len(methods)) + b"".join(methods) + attributes(class_attributes))


def aar_bytes(class_payload: bytes = b"", abi_mutator=None) -> bytes:
    baseline = json.loads((ANDROID / "tests/fixtures/desktop-sdk-contract-v3.1.json").read_text())
    ledger = copy.deepcopy(baseline["jvm_abi"])
    if abi_mutator is not None:
        abi_mutator(ledger)
    files: dict[str, bytes] = {}
    padded = False
    for name in verifier.CLASS_FILES:
        if name.endswith(".class"):
            internal = name[:-6]
            padding = class_payload if class_payload and not padded else b""
            files[name] = class_bytes(internal, ledger["classes"].get(internal), padding)
            padded = padded or bool(padding)
        else:
            files[name] = b"fixture kotlin module"
    classes = zip_bytes(files, directories=verifier.CLASS_DIRECTORIES)
    manifest = (
        b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        b'package="org.wonad.desktop.api"><uses-sdk android:minSdkVersion="35"/>'
        b'</manifest>'
    )
    return zip_bytes({
        "R.txt": b"",
        "AndroidManifest.xml": manifest,
        "classes.jar": classes,
        "META-INF/com/android/build/gradle/aar-metadata.properties": (
            b"aarFormatVersion=1.0\n"
            b"aarMetadataVersion=1.0\n"
            b"minCompileSdk=1\n"
            b"minCompileSdkExtension=0\n"
            b"minAndroidGradlePluginVersion=1.0.0\n"
            b"coreLibraryDesugaringEnabled=false\n"
        ),
    })


def source_bytes(extra_text: str = "", extra_file: str | None = None) -> bytes:
    files: dict[str, bytes] = {}
    for name in verifier.SOURCE_FILES:
        if name == "META-INF/MANIFEST.MF":
            files[name] = b"Manifest-Version: 1.0\r\n\r\n"
        elif name.endswith("DesktopProtocol.kt"):
            files[name] = ((ANDROID / "desktop-sdk/src/main/kotlin" / name).read_text() +
                           extra_text).encode()
        elif name.endswith(".kt"):
            files[name] = (ANDROID / "desktop-sdk/src/main/kotlin" / name).read_bytes()
        else:
            simple = Path(name).stem
            files[name] = (
                "/*\n * Generated from the frozen Wonad API-v3 AIDL.\n */\n"
                f"package org.wonad.desktop.api; public class {simple} {{}}\n"
            ).encode()
    if extra_file:
        files[extra_file] = b"package org.wonad.desktop.api;"
    return zip_bytes(files, directories=verifier.SOURCE_DIRECTORIES)


def contract_bytes(extra: dict[str, bytes] | None = None) -> bytes:
    files = {
        "API-v3.md": (ANDROID / "desktop-sdk/API-v3.md").read_bytes(),
        "desktop-sdk-contract-v3.json":
            (ANDROID / "tests/fixtures/desktop-sdk-contract-v3.1.json").read_bytes(),
        "verify-desktop-sdk-contract.py": (ANDROID / "tools/sdk_contract.py").read_bytes(),
    }
    files.update(extra or {})
    return zip_bytes(files, {"verify-desktop-sdk-contract.py": 0o755})


def pom_bytes() -> bytes:
    return b"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion><groupId>org.wonad</groupId>
  <artifactId>desktop-sdk</artifactId><version>3.1.0</version><packaging>aar</packaging>
  <dependencies><dependency><groupId>org.jetbrains.kotlin</groupId>
  <artifactId>kotlin-stdlib</artifactId><version>2.1.21</version>
  <scope>compile</scope></dependency></dependencies>
</project>"""


def metadata_bytes(updated: str = "20261010123456") -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<metadata><groupId>org.wonad</groupId><artifactId>desktop-sdk</artifactId>
<versioning><latest>3.1.0</latest><release>3.1.0</release>
<versions><version>3.1.0</version></versions><lastUpdated>{updated}</lastUpdated>
</versioning></metadata>""".encode()


def module_bytes(version_dir: Path) -> bytes:
    def file_metadata(name: str) -> dict[str, object]:
        payload = (version_dir / name).read_bytes()
        item: dict[str, object] = {"name": name, "url": name, "size": len(payload)}
        item.update({algorithm: hashlib.new(algorithm, payload).hexdigest()
                     for algorithm in verifier.CHECKSUMS})
        return item
    aar = f"{verifier.BASE_NAME}.aar"
    sources = f"{verifier.BASE_NAME}-sources.jar"
    dependency = [{"group": "org.jetbrains.kotlin", "module": "kotlin-stdlib",
                   "version": {"requires": "2.1.21"}}]
    return json.dumps({
        "formatVersion": "1.1",
        "component": {"group": "org.wonad", "module": "desktop-sdk", "version": "3.1.0",
                      "attributes": {"org.gradle.status": "release"}},
        "createdBy": {"gradle": {"version": "8.11.1"}},
        "variants": [
            {"name": "releaseVariantReleaseApiPublication",
             "attributes": {"org.gradle.category": "library",
                            "org.gradle.dependency.bundling": "external",
                            "org.gradle.libraryelements": "aar", "org.gradle.usage": "java-api"},
             "dependencies": dependency, "files": [file_metadata(aar)]},
            {"name": "releaseVariantReleaseRuntimePublication",
             "attributes": {"org.gradle.category": "library",
                            "org.gradle.dependency.bundling": "external",
                            "org.gradle.libraryelements": "aar", "org.gradle.usage": "java-runtime"},
             "dependencies": dependency, "files": [file_metadata(aar)]},
            {"name": "releaseVariantReleaseSourcePublication",
             "attributes": {"org.gradle.category": "documentation",
                            "org.gradle.dependency.bundling": "external",
                            "org.gradle.docstype": "sources", "org.gradle.usage": "java-runtime"},
             "files": [file_metadata(sources)]},
        ],
    }, sort_keys=True).encode()


def refresh(repository: Path) -> None:
    version_dir = repository / verifier.VERSION_PATH
    (version_dir / f"{verifier.BASE_NAME}.module").write_bytes(module_bytes(version_dir))
    primaries = [version_dir / name for name in verifier.PRIMARY_FILES]
    primaries.append(repository / verifier.COORDINATE_PATH / "maven-metadata.xml")
    for primary in primaries:
        payload = primary.read_bytes()
        for algorithm in verifier.CHECKSUMS:
            Path(str(primary) + "." + algorithm).write_text(
                hashlib.new(algorithm, payload).hexdigest(), encoding="ascii")


def make_repository(root: Path, *, class_payload: bytes = b"",
                    updated: str = "20261010123456") -> Path:
    repository = root / "repository"
    version_dir = repository / verifier.VERSION_PATH
    version_dir.mkdir(parents=True)
    (version_dir / f"{verifier.BASE_NAME}.aar").write_bytes(aar_bytes(class_payload))
    (version_dir / f"{verifier.BASE_NAME}-sources.jar").write_bytes(source_bytes())
    (version_dir / f"{verifier.BASE_NAME}-contract.zip").write_bytes(contract_bytes())
    (version_dir / f"{verifier.BASE_NAME}.pom").write_bytes(pom_bytes())
    metadata = repository / verifier.COORDINATE_PATH / "maven-metadata.xml"
    metadata.write_bytes(metadata_bytes(updated))
    refresh(repository)
    return repository


class PublicationVerifierTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wonad-sdk-publication-test-")
        self.root = Path(self.temporary.name)
        self.repository = make_repository(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def verify(self, repository: Path | None = None):
        return verifier.verify_repository(repository or self.repository, ANDROID)

    def test_valid_exact_publication(self):
        result = self.verify()
        self.assertEqual(verifier.EXPECTED_SIGNATURE, result["contract_signature"])
        self.assertEqual(set(verifier.PRIMARY_FILES), set(result["artifact_sha256"]))
        self.assertEqual(set(verifier.CONTRACT_FILES), set(result["contract_members"]))
        for name, mode in verifier.CONTRACT_FILES.items():
            payload = contract_bytes()
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                value = archive.read(name)
            self.assertEqual(result["contract_members"][name], {
                "sha256": hashlib.sha256(value).hexdigest(),
                "bytes": len(value),
                "mode": mode,
            })

    def test_unlisted_repository_file_and_bad_checksum_fail_closed(self):
        unexpected = self.repository / verifier.VERSION_PATH / "desktop-sdk-3.1.0-debug.jar"
        unexpected.write_bytes(b"debug")
        with self.assertRaisesRegex(verifier.VerificationError, "file set differs"):
            self.verify()
        unexpected.unlink()
        sidecar = Path(str(self.repository / verifier.VERSION_PATH /
                           f"{verifier.BASE_NAME}.aar") + ".sha256")
        sidecar.write_text("0" * 64)
        with self.assertRaisesRegex(verifier.VerificationError, "incorrect sha256"):
            self.verify()

    def test_historical_3_0_0_coordinates_cannot_be_relabelled_as_3_1_0(self):
        pom = self.repository / verifier.VERSION_PATH / f"{verifier.BASE_NAME}.pom"
        pom.write_bytes(pom_bytes().replace(b"<version>3.1.0</version>",
                                            b"<version>3.0.0</version>", 1))
        refresh(self.repository)
        with self.assertRaisesRegex(verifier.VerificationError, "POM coordinates"):
            self.verify()

        pom.write_bytes(pom_bytes())
        metadata = self.repository / verifier.COORDINATE_PATH / "maven-metadata.xml"
        metadata.write_bytes(metadata_bytes().replace(b"3.1.0", b"3.0.0"))
        refresh(self.repository)
        with self.assertRaisesRegex(verifier.VerificationError, "metadata latest/release"):
            self.verify()

    def test_unlisted_directory_and_symlinked_repository_fail_closed(self):
        unexpected = self.repository / "unexpected-empty-directory"
        unexpected.mkdir()
        with self.assertRaisesRegex(verifier.VerificationError, "directory set differs"):
            self.verify()
        unexpected.rmdir()
        linked = self.root / "linked-repository"
        linked.symlink_to(self.repository, target_is_directory=True)
        with self.assertRaisesRegex(verifier.VerificationError, "repository is symlinked"):
            self.verify(linked)

    def test_unsafe_and_duplicate_zip_entries_fail_closed(self):
        contract = self.repository / verifier.VERSION_PATH / f"{verifier.BASE_NAME}-contract.zip"
        contract.write_bytes(contract_bytes({"../escape": b"no"}))
        refresh(self.repository)
        with self.assertRaisesRegex(verifier.VerificationError, "unsafe traversal"):
            self.verify()

        contract.write_bytes(contract_bytes())
        with zipfile.ZipFile(contract, "a") as archive:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr("API-v3.md", b"duplicate")
        refresh(self.repository)
        with self.assertRaisesRegex(verifier.VerificationError, "duplicate ZIP entry"):
            self.verify()

    def test_symlink_archive_entry_fails_closed(self):
        path = self.root / "symlink.zip"
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(info, "target")
        with self.assertRaisesRegex(verifier.VerificationError, "non-regular"):
            verifier.read_safe_zip(path, "test")

    def test_native_and_draft_v2_names_are_rejected(self):
        source = self.repository / verifier.VERSION_PATH / f"{verifier.BASE_NAME}-sources.jar"
        source.write_bytes(source_bytes("class NativeDesktopFrame\n"))
        refresh(self.repository)
        with self.assertRaisesRegex(verifier.VerificationError, "forbidden Native"):
            self.verify()

        source.write_bytes(source_bytes("class DesktopWorkspace\n"))
        refresh(self.repository)
        with self.assertRaisesRegex(verifier.VerificationError, "forbidden draft-v2"):
            self.verify()

    def test_extra_source_file_is_rejected(self):
        source = self.repository / verifier.VERSION_PATH / f"{verifier.BASE_NAME}-sources.jar"
        source.write_bytes(source_bytes(extra_file="org/wonad/desktop/api/Surprise.java"))
        refresh(self.repository)
        with self.assertRaisesRegex(verifier.VerificationError, "source JAR files differ"):
            self.verify()

    def test_aidl_absolute_invocation_trace_is_rejected(self):
        source = self.repository / verifier.VERSION_PATH / f"{verifier.BASE_NAME}-sources.jar"
        source.write_bytes(source_bytes("//  * Using: /tmp/random/aidl -d/tmp/random.d\n"))
        refresh(self.repository)
        with self.assertRaisesRegex(verifier.VerificationError, "nondeterministic AIDL invocation"):
            self.verify()

    def test_contract_signature_tampering_is_rejected(self):
        baseline = json.loads((ANDROID / "tests/fixtures/desktop-sdk-contract-v3.1.json").read_text())
        changed = copy.deepcopy(baseline)
        changed["constants"]["API_VERSION"] = "2"
        self.assertNotEqual(changed["signature_sha256"],
                            verifier.canonical_contract_signature(changed))

        files = {
            "API-v3.md": (ANDROID / "desktop-sdk/API-v3.md").read_bytes(),
            "desktop-sdk-contract-v3.json": json.dumps(changed).encode(),
            "verify-desktop-sdk-contract.py": (ANDROID / "tools/sdk_contract.py").read_bytes(),
        }
        contract = self.repository / verifier.VERSION_PATH / f"{verifier.BASE_NAME}-contract.zip"
        contract.write_bytes(zip_bytes(files, {"verify-desktop-sdk-contract.py": 0o755}))
        refresh(self.repository)
        with self.assertRaises(verifier.VerificationError):
            self.verify()

    def test_readonly_contract_member_modes_are_not_accepted_as_canonical(self):
        files = {
            "API-v3.md": (ANDROID / "desktop-sdk/API-v3.md").read_bytes(),
            "desktop-sdk-contract-v3.json": (ANDROID / "tests/fixtures/desktop-sdk-contract-v3.1.json").read_bytes(),
            "verify-desktop-sdk-contract.py": (ANDROID / "tools/sdk_contract.py").read_bytes(),
        }
        contract = self.repository / verifier.VERSION_PATH / f"{verifier.BASE_NAME}-contract.zip"
        for name in ("API-v3.md", "desktop-sdk-contract-v3.json"):
            with self.subTest(member=name):
                contract.write_bytes(zip_bytes(files, {
                    "verify-desktop-sdk-contract.py": 0o755, name: 0o400,
                }))
                refresh(self.repository)
                with self.assertRaisesRegex(verifier.VerificationError, "contract ZIP mode"):
                    self.verify()

    def test_publisher_normalizes_readonly_sources_without_weakening_verifier(self):
        build = (ANDROID / "desktop-sdk/build.gradle.kts").read_text()
        self.assertEqual(2, build.count('filePermissions { unix("rw-r--r--") }'))
        self.assertEqual(1, build.count('filePermissions { unix("rwxr-xr-x") }'))
        self.assertEqual({"API-v3.md": 0o644, "desktop-sdk-contract-v3.json": 0o644,
                          "verify-desktop-sdk-contract.py": 0o755}, verifier.CONTRACT_FILES)

    def test_compiled_desktop_failure_throwable_to_any_is_rejected(self):
        def mutate(ledger):
            methods = ledger["classes"]["org/wonad/desktop/api/DesktopFailure"]["methods"]
            method = next(row for row in methods if row["name"] == "describe")
            method["descriptor"] = "(Ljava/lang/Object;)Ljava/lang/String;"

        aar = self.repository / verifier.VERSION_PATH / f"{verifier.BASE_NAME}.aar"
        aar.write_bytes(aar_bytes(abi_mutator=mutate))
        refresh(self.repository)
        with self.assertRaisesRegex(verifier.VerificationError,
                                    "compiled public JVM ABI differs"):
            self.verify()

    def test_compiled_class_field_method_and_generic_signature_mutations_are_rejected(self):
        def field_descriptor(ledger):
            fields = ledger["classes"]["org/wonad/desktop/api/DesktopTask"]["fields"]
            next(row for row in fields if row["name"] == "title")["descriptor"] = "Ljava/lang/Object;"

        def method_descriptor(ledger):
            methods = ledger["classes"]["org/wonad/desktop/api/IDesktopSession"]["methods"]
            next(row for row in methods if row["name"] == "heartbeat")["descriptor"] = "(J)V"

        def generic_signature(ledger):
            fields = ledger["classes"]["org/wonad/desktop/api/DesktopTask"]["fields"]
            next(row for row in fields if row["name"] == "CREATOR")["signature"] = (
                "Landroid/os/Parcelable$Creator<Lorg/wonad/desktop/api/DesktopRect;>;")

        def checked_exceptions(ledger):
            methods = ledger["classes"]["org/wonad/desktop/api/IDesktopSession"]["methods"]
            next(row for row in methods if row["name"] == "heartbeat").pop("exceptions")

        def class_relationship(ledger):
            ledger["classes"]["org/wonad/desktop/api/IDesktopSession"]["interfaces"] = []

        def nested_visibility(ledger):
            row = ledger["classes"]["org/wonad/desktop/api/IDesktopSession$Stub"]
            row["inner_access"] = (row["inner_access"] & ~0x0005) | 0x0004

        aar = self.repository / verifier.VERSION_PATH / f"{verifier.BASE_NAME}.aar"
        for mutation in (field_descriptor, method_descriptor, generic_signature,
                         checked_exceptions, class_relationship, nested_visibility):
            with self.subTest(mutation=mutation.__name__):
                aar.write_bytes(aar_bytes(abi_mutator=mutation))
                refresh(self.repository)
                with self.assertRaisesRegex(verifier.VerificationError,
                                            "compiled public JVM ABI differs"):
                    self.verify()

    def test_comparison_ignores_only_repository_timestamp(self):
        second_root = self.root / "second"
        second = make_repository(second_root, updated="20261010130000")
        result = verifier.compare_repositories(self.repository, second, ANDROID)
        self.assertTrue(result["reproducible"])
        self.assertEqual("maven-metadata.xml/versioning/lastUpdated",
                         result["excluded_repository_index_field"])

        # Both publications remain individually valid, but a changed class byte
        # must be caught by the immutable-artifact comparison.
        third_root = self.root / "third"
        third = make_repository(third_root, class_payload=b"different")
        self.verify(third)
        with self.assertRaisesRegex(verifier.VerificationError, "artifact hashes differ"):
            verifier.compare_repositories(self.repository, third, ANDROID)


if __name__ == "__main__":
    unittest.main()
