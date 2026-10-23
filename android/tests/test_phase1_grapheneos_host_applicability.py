import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import phase1_grapheneos_host_applicability as applicability
import run_phase1_upstream_tests as isolated


SECURE_CLASS = "com.android.server.input.KeyGestureControllerTests"
SECURE_METHODS = [
    "testSecurePasteShortcuts_passThroughBeforeDispatch",
    "testSecurePasteShortcuts_notInterceptedWhenUnhandled",
    "testSecurePasteGrant_onlyForTrustedInitialDown",
    "testSecurePasteGrant_notCreatedWhenWmConsumes",
]
SECURE_FILTERS = [SECURE_CLASS + "#" + method for method in SECURE_METHODS]


def write(root, relative, payload):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload)
    return path


def json_file(root, relative, value):
    return write(root, relative, json.dumps(value, indent=2) + "\n")


def module(module_type, name, *, host_supported=False):
    extra = "    host_supported: true,\n" if host_supported else ""
    return f'{module_type} {{\n    name: "{name}",\n{extra}}}\n'


def make_source_fixture(root):
    source = root / "source"
    source.mkdir()
    gos_compat = {
        "gos_postsubmit": [
            {"name": "GosCompatMapsScanTests"},
            {"name": "GosCompatWebViewTests"},
            {"name": "GosCompatDmaBufReleaseTests"},
            {"name": "GosCompatWifiScanTimeoutTests"},
            {"name": "GosCompatSecureSpawnTests"},
        ]
    }
    secure = {
        "gos-postsubmit": [
            {"name": "SecurePasteTests"},
            {"name": "InputTests",
             "options": [{"include-filter": value} for value in SECURE_FILTERS]},
        ],
        "ordinary-device-group": [{"name": "UnrelatedDeviceTests"}],
    }
    contacts = {"gos-postsubmit": [{"name": "ContactScopesTests"}]}
    mappings = {
        "frameworks/base/tests/GosCompatTests/TEST_MAPPING": gos_compat,
        "frameworks/base/tests/SecurePasteTests/TEST_MAPPING": secure,
        "packages/providers/ContactsProvider/TEST_MAPPING": contacts,
        "packages/providers/ContactsProvider/tests/ContactScopesTests/TEST_MAPPING": contacts,
    }
    for relative, value in mappings.items():
        json_file(source, relative, value)
    # AOSP contains unrelated files with duplicate nested keys.  They remain
    # byte-authenticated while only top-level GOS groups receive strict parsing.
    write(source, "unrelated/TEST_MAPPING",
          '{"presubmit":[{"name":"x","options":{"same":1,"same":2}}]}\n')

    input_bp = "".join((
        module("android_test", "GosCompatMapsScanTests"),
        module("android_test", "GosCompatWebViewTests"),
        module("android_test", "GosCompatDmaBufReleaseTests"),
        module("android_test", "GosCompatWifiScanTimeoutTests"),
        module("java_test_host", "GosCompatSecureSpawnTests"),
        module("android_test", "SecurePasteTests"),
        module("android_test", "InputTests"),
        module("android_ravenwood_test", "InputTestsRavenwood"),
    ))
    input_bp_path = write(source, "frameworks/base/tests/Input/Android.bp", input_bp)
    contacts_bp_path = write(
        source, "packages/providers/ContactsProvider/tests/ContactScopesTests/Android.bp",
        module("java_test_host", "ContactScopesTests"))
    marker = ('@DisabledOnRavenwood(reason = "Static mocking in bivalent tests is tricky", '
              'bug = 310268946)')
    test_source = """/** Build/Install/Run: atest InputTests:KeyGestureControllerTests */
%s
class KeyGestureControllerTests {
%s
}
""" % (marker, "\n".join("    fun " + name + "() {}" for name in SECURE_METHODS))
    test_source_path = write(
        source,
        "frameworks/base/tests/Input/src/com/android/server/input/KeyGestureControllerTests.kt",
        test_source)

    projects = [
        {"path": "frameworks/base", "commit": "1" * 40},
        {"path": "packages/providers/ContactsProvider", "commit": "2" * 40},
    ]
    pin = {
        "release": applicability.RELEASE,
        "projects": [{"path": row["path"], "revision": row["commit"]}
                     for row in projects],
    }
    mapping_rows = []
    for relative, entries in sorted(mappings.items()):
        identity = applicability.file_identity((source / relative).resolve())
        gos_entries = {key: entries[key] for key in sorted(entries)
                       if applicability.GOS_KEY.fullmatch(key)}
        mapping_rows.append({"path": relative, "sha256": identity["sha256"],
                             "entries": gos_entries})

    module_rows = [
        ("GosCompatDmaBufReleaseTests", "android_test", "grapheneos_device_module",
         "frameworks/base"),
        ("GosCompatMapsScanTests", "android_test", "grapheneos_device_module",
         "frameworks/base"),
        ("GosCompatSecureSpawnTests", "java_test_host", "grapheneos_host_module",
         "frameworks/base"),
        ("GosCompatWebViewTests", "android_test", "grapheneos_device_module",
         "frameworks/base"),
        ("GosCompatWifiScanTimeoutTests", "android_test", "grapheneos_device_module",
         "frameworks/base"),
        ("SecurePasteTests", "android_test", "grapheneos_device_module",
         "frameworks/base"),
        ("InputTests", "android_test", "grapheneos_device_module", "frameworks/base"),
        ("ContactScopesTests", "java_test_host", "grapheneos_host_module",
         "packages/providers/ContactsProvider"),
        ("InputTestsRavenwood", "android_ravenwood_test", "generic_host_module",
         "frameworks/base"),
    ]
    candidates = []
    for index, (name, module_type, kind, project) in enumerate(module_rows):
        definition_path = (contacts_bp_path if name == "ContactScopesTests"
                           else input_bp_path).relative_to(source).as_posix()
        candidates.append({
            "id": "candidate_%02d" % index, "kind": kind,
            "project_path": project, "definition_path": definition_path,
            "module": name, "module_type": module_type,
            "exclusion_code": "reviewed_not_applicable_%02d" % index,
            "reason": "Fixture candidate has an explicit reviewed disposition.",
        })

    audited_paths = sorted(set(mappings) | {
        input_bp_path.relative_to(source).as_posix(),
        contacts_bp_path.relative_to(source).as_posix(),
        test_source_path.relative_to(source).as_posix(),
    })
    audited = [{"path": relative,
                "sha256": applicability.file_identity((source / relative).resolve())["sha256"]}
               for relative in audited_paths]
    roots = ["frameworks/base/tests", "packages/providers/ContactsProvider"]
    mapping_paths, mapping_symlinks = applicability._walk_files(
        source, filename="TEST_MAPPING")
    mapping_inventory = [
        {"path": path.relative_to(source).as_posix(),
         **applicability.file_identity(path)} for path in mapping_paths
    ]
    blueprint_paths, blueprint_symlinks = applicability._walk_files(
        source, filename="Android.bp", roots=tuple(roots))
    blueprint_names = [path.relative_to(source).as_posix() for path in blueprint_paths]
    all_modules = []
    host_modules = []
    for path in blueprint_paths:
        relative = path.relative_to(source).as_posix()
        for row in applicability.blueprint_modules(path.read_bytes(), relative):
            item = {"path": relative, "module_type": row["module_type"],
                    "name": row["name"]}
            all_modules.append(item)
            if row["module_type"] in applicability.HOST_MODULE_TYPES:
                host_modules.append({
                    **item, "host_capability":
                    ("ravenwood" if row["module_type"] == "android_ravenwood_test"
                     else "host-module-type")})
            elif (row["module_type"] in applicability.HOST_SUPPORTED_TEST_TYPES and
                  row["host_supported"]):
                host_modules.append({**item, "host_capability": "host_supported"})
    all_modules.sort(key=lambda row: (row["path"], row["module_type"], row["name"]))
    host_modules.sort(key=lambda row: (row["path"], row["module_type"], row["name"]))
    definition = {
        "schema": applicability.SCHEMA, "kind": applicability.DEFINITION_KIND,
        "release": applicability.RELEASE, "result": applicability.RESULT,
        "scope": {
            "claim": applicability.SCOPE,
            "walk_exclusions": list(applicability.WALK_EXCLUSIONS),
            "test_mapping_count": len(mapping_inventory),
            "test_mapping_inventory_sha256":
                applicability.canonical_digest(mapping_inventory),
            "test_mapping_skipped_symlink_count": len(mapping_symlinks),
            "test_mapping_skipped_symlink_inventory_sha256":
                applicability.canonical_digest(mapping_symlinks),
            "blueprint_roots": roots, "blueprint_file_count": len(blueprint_names),
            "blueprint_path_inventory_sha256":
                applicability.canonical_digest(blueprint_names),
            "blueprint_skipped_symlink_count": len(blueprint_symlinks),
            "blueprint_skipped_symlink_inventory_sha256":
                applicability.canonical_digest(blueprint_symlinks),
            "module_count": len(all_modules),
            "module_inventory_sha256": applicability.canonical_digest(all_modules),
            "host_module_count": len(host_modules),
            "host_module_inventory_sha256":
                applicability.canonical_digest(host_modules),
        },
        "projects": projects, "gos_mappings": mapping_rows,
        "audited_files": audited, "candidate_exclusions": candidates,
        "device_overlap": {
            "mapping_path": "frameworks/base/tests/SecurePasteTests/TEST_MAPPING",
            "input_android_bp_path": input_bp_path.relative_to(source).as_posix(),
            "test_source_path": test_source_path.relative_to(source).as_posix(),
            "device_module": "InputTests", "host_module": "InputTestsRavenwood",
            "test_class": SECURE_CLASS,
            "command_anchor": "atest InputTests:KeyGestureControllerTests",
            "filters": SECURE_FILTERS,
            "disabled_on_ravenwood_marker": marker,
        },
        "conclusion": {
            "result": applicability.RESULT, "reason": "Fixture reviewed result.",
            "disclaimer":
                "No applicable GrapheneOS-specific host check is declared in the exact pinned "
                "source within the reviewed bounds; this does not assert absence from external "
                "or unpublished GrapheneOS CI.",
        },
    }
    applicability.validate_definition(definition)
    return source, pin, definition


class FakeBackend:
    def __init__(self, image):
        self.image = copy.deepcopy(image)

    @staticmethod
    def docker_identity():
        return {
            "endpoint": "unix:///run/docker.sock",
            "cli": {"path": "/usr/bin/docker", "sha256": "d" * 64},
            "socket": {"path": "/run/docker.sock", "device": 1, "inode": 2},
            "context": {"name": "default"},
            "daemon": {"id": "fixture-daemon", "architecture": "x86_64"},
        }

    def inspect_image(self, image_id):
        value = copy.deepcopy(self.image)
        value["id"] = image_id
        return value


class GrapheneHostSourceScanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.source, self.pin, self.definition = make_source_fixture(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def test_repository_definition_is_hash_pinned_and_bounded(self):
        value = applicability.reviewed_definition()
        self.assertEqual(value["scope"]["test_mapping_count"], 2096)
        self.assertEqual(len(value["gos_mappings"]), 4)
        self.assertEqual(value["device_overlap"]["filters"], SECURE_FILTERS)
        self.assertEqual(applicability.file_identity(applicability.DEFINITION)["sha256"],
                         applicability.DEFINITION_SHA256)

    def test_scan_authenticates_native_inventory_and_never_claims_a_test_pass(self):
        value = applicability.scan_source(self.source, self.pin, self.definition)
        self.assertEqual(value["test_mappings"]["count"], 5)
        self.assertEqual(len(value["test_mappings"]["gos_mappings"]), 4)
        self.assertEqual(value["result"], applicability.RESULT)
        self.assertEqual(value["device_overlap"]["filters"], SECURE_FILTERS)
        self.assertNotIn("passed", json.dumps(value).lower())

    def test_scan_rejects_wrong_frozen_project_revision(self):
        changed = copy.deepcopy(self.pin)
        changed["projects"][0]["revision"] = "f" * 40
        with self.assertRaisesRegex(applicability.ApplicabilityError,
                                    "project commit differs"):
            applicability.scan_source(self.source, changed, self.definition)

    def test_scan_rejects_added_grapheneos_mapping(self):
        write(self.source, "unrelated/TEST_MAPPING",
              '{"gos-postsubmit":[{"name":"InventedHostTest"}]}\n')
        with self.assertRaisesRegex(applicability.ApplicabilityError,
                                    "TEST_MAPPING inventory differs"):
            applicability.scan_source(self.source, self.pin, self.definition)

    def test_scan_rejects_duplicate_grapheneos_group(self):
        write(self.source, "unrelated/TEST_MAPPING",
              '{"gos-postsubmit":[],"gos-postsubmit":[]}\n')
        with self.assertRaisesRegex(applicability.ApplicabilityError,
                                    "group is duplicated"):
            applicability.scan_source(self.source, self.pin, self.definition)

    def test_scan_rejects_audited_module_drift(self):
        path = self.source / "frameworks/base/tests/Input/Android.bp"
        path.write_text(path.read_text().replace('name: "InputTests"',
                                                 'name: "InputTestsChanged"'))
        with self.assertRaisesRegex(applicability.ApplicabilityError,
                                    "Audited source bytes differ"):
            applicability.scan_source(self.source, self.pin, self.definition)

    def test_scan_rejects_new_excluded_symlink_directory(self):
        (self.source / "linked-source").symlink_to(
            self.source / "frameworks", target_is_directory=True)
        with self.assertRaisesRegex(applicability.ApplicabilityError,
                                    "Excluded symlink-directory inventory differs"):
            applicability.scan_source(self.source, self.pin, self.definition)

    def test_definition_rejects_missing_secure_paste_filter(self):
        changed = copy.deepcopy(self.definition)
        changed["device_overlap"]["filters"].pop()
        with self.assertRaisesRegex(applicability.ApplicabilityError,
                                    "Secure Paste device-only overlap"):
            applicability.validate_definition(changed)


class GrapheneHostReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.source, self.pin, self.definition = make_source_fixture(self.root)
        for relative, payload, mode in (
            ("prebuilts/runtime/adb", "adb\n", 0o755),
            ("prebuilts/asuite/atest/linux-x86/atest", "atest\n", 0o755),
            ("build/make/envsetup.sh", "# envsetup\n", 0o644),
        ):
            path = write(self.source, relative, payload)
            path.chmod(mode)
        (self.source / "build/envsetup.sh").symlink_to("make/envsetup.sh")
        self.build_out = self.root / "build-out"
        self.build_out.mkdir()
        self.image = {
            "id": "sha256:" + "a" * 64,
            "repo_digests": ["builder@sha256:" + "a" * 64],
            "os": "linux", "architecture": "amd64", "size": 1234,
            "rootfs": {"type": "layers", "layers": ["sha256:" + "b" * 64]},
            "config": {
                "User": "builder",
                "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        "LANG=C.UTF-8"],
                "Entrypoint": None, "Cmd": ["bash"], "WorkingDir": "/sources",
                "Labels": None,
            },
        }
        self.receipt = {
            "role": "baseline", "kind": "wonad-x86-build-comparison-input",
            "source": {"pin": self.pin},
            "artifacts": {"images": {}, "os_artifacts": {
                "system": {"path": "system.img", "state": "present",
                           "sha256": "3" * 64, "size": 42}}},
            "locations": {"source": str(self.source), "out_dir": str(self.build_out)},
            "builder": {"image": self.image},
            "fingerprint": "Android/fixture/emu64x:17/test:userdebug/test-keys",
        }
        self.build_receipt = self.root / "build-receipt.json"
        self.build_receipt.write_text(json.dumps(self.receipt, sort_keys=True) + "\n")
        self.build_sha = hashlib.sha256(self.build_receipt.read_bytes()).hexdigest()
        self.build = isolated.summarize_build(
            self.build_receipt, self.receipt, "baseline")
        self.plan = self.root / "generic-plan.json"
        self.plan.write_text('{"reviewed":"fixture"}\n')
        self.plan_sha = hashlib.sha256(self.plan.read_bytes()).hexdigest()
        self.definition_path = self.root / "definition.json"
        self.definition_path.write_text(
            json.dumps(self.definition, indent=2, sort_keys=True) + "\n")
        self.definition_sha = hashlib.sha256(self.definition_path.read_bytes()).hexdigest()
        self.output = self.root / "evidence"
        self.backend = FakeBackend(self.image)
        self.freeze = {
            "schema": isolated.SCHEMA,
            "kind": "wonad-phase1-current-source-freeze",
            "receipt_sha256": self.build_sha,
            "snapshot_sha256": applicability.canonical_digest(self.receipt["source"]),
            "snapshot": self.receipt["source"],
        }
        self.definition_patch = mock.patch.object(
            applicability, "DEFINITION", self.definition_path)
        self.definition_sha_patch = mock.patch.object(
            applicability, "DEFINITION_SHA256", self.definition_sha)
        self.build_verify_patch = mock.patch.object(
            isolated, "full_build_verify", return_value=(self.receipt, self.build))
        self.freeze_patch = mock.patch.object(
            isolated, "source_freeze_verify", return_value=self.freeze)
        self.definition_patch.start()
        self.definition_sha_patch.start()
        self.build_verify = self.build_verify_patch.start()
        self.freeze_verify = self.freeze_patch.start()

    def tearDown(self):
        mock.patch.stopall()
        self.temporary.cleanup()

    def produce(self):
        return applicability.scan(
            "baseline", self.build_receipt, self.build_sha, self.plan, self.plan_sha,
            self.output, backend=self.backend)

    def test_portable_receipt_verifies_to_normalized_not_applicable_projection(self):
        receipt, digest = self.produce()
        with mock.patch.object(isolated, "ProductionBackend", return_value=self.backend):
            value = applicability.verify(receipt, digest, rehash_build=False)
        self.assertEqual(value["class"], "grapheneos_host")
        self.assertEqual(value["applicability"]["result"], applicability.RESULT)
        self.assertNotIn("cases", value)
        self.assertEqual(self.build_verify.call_count, 2)

    def test_receipt_verifies_after_bundle_relocation(self):
        receipt, digest = self.produce()
        relocated = self.root / "relocated"
        self.output.rename(relocated)
        value = applicability._verify(
            relocated / receipt.name, digest, rehash_build=False, backend=self.backend)
        self.assertEqual(value["build_receipt"]["sha256"], self.build_sha)

    def test_verifier_rejects_tampered_scan_evidence(self):
        receipt, digest = self.produce()
        value = json.loads(receipt.read_text())
        scan = self.output / value["scan"]["before"]["path"]
        scan.write_text("{}\n")
        with self.assertRaisesRegex(applicability.comparison.EvidenceError,
                                    "Referenced evidence changed"):
            applicability._verify(
                receipt, digest, rehash_build=False, backend=self.backend)

    def test_verifier_rejects_wrong_out_of_band_digest(self):
        receipt, _digest = self.produce()
        with self.assertRaisesRegex(applicability.ApplicabilityError,
                                    "out-of-band SHA-256"):
            applicability._verify(
                receipt, "0" * 64, rehash_build=False, backend=self.backend)

    def test_live_verify_rejects_source_freeze_mismatch(self):
        receipt, digest = self.produce()
        changed = copy.deepcopy(self.freeze)
        changed["snapshot"]["pin"]["projects"][0]["revision"] = "f" * 40
        changed["snapshot_sha256"] = applicability.canonical_digest(changed["snapshot"])
        self.freeze_verify.return_value = changed
        with self.assertRaisesRegex(applicability.ApplicabilityError,
                                    "source-freeze recollection differs"):
            applicability._verify(receipt, digest, rehash_build=True,
                                  backend=self.backend)

    def test_live_verify_rejects_native_source_drift(self):
        receipt, digest = self.produce()
        write(self.source, "unrelated/TEST_MAPPING",
              '{"gos-postsubmit":[{"name":"InventedHostTest"}]}\n')
        with self.assertRaisesRegex(applicability.ApplicabilityError,
                                    "TEST_MAPPING inventory differs"):
            applicability._verify(receipt, digest, rehash_build=True,
                                  backend=self.backend)

    def test_scan_requires_exact_generic_plan_hash(self):
        with self.assertRaisesRegex(applicability.ApplicabilityError,
                                    "Generic plan differs"):
            applicability.scan(
                "baseline", self.build_receipt, self.build_sha, self.plan, "0" * 64,
                self.output, backend=self.backend)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
