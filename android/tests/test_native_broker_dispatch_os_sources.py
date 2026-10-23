"""Private prototype controls: retained real build data, not a guest runtime PASS."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "android/tools"))
import native_broker_dispatch_os_sources as source
import native_broker_dispatch_smoke as driver
import native_evidence

FIXTURES = Path(os.environ.get("WONAD_BROKER_DISPATCH_UNIT_FIXTURES", ROOT / "fixtures"))
CID = "a" * 64
IMAGE = "sha256:" + "b" * 64  # Deliberately not the original image: no image/hash hardcoding.


class BrokerDispatchSignerReferenceTests(unittest.TestCase):
    def test_fault_signer_uses_actual_evidence_product_in_both_modes(self):
        for bundled in (False, True):
            with self.subTest(bundled=bundled), tempfile.TemporaryDirectory() as directory:
                product = Path(directory) / "product"
                systemui = product / "system_ext/priv-app/SystemUI/SystemUI.apk"
                systemui.parent.mkdir(parents=True)
                systemui.write_bytes(b"synthetic SystemUI")
                path = Path(directory) / "fault.apk"
                path.write_bytes(b"synthetic fault")
                reference = SimpleNamespace(product=product,
                    initial={"artifacts": {"com.android.systemui": {"sha256": driver.digest(systemui)}}})
                host = Mock(return_value="synthetic tool output")
                host.side_effect = lambda *args: "/tmp/wonad-dispatch-check.A1234567" if "mktemp" in args else "synthetic tool output"
                subject = SimpleNamespace(product=None if bundled else product, native_evidence=reference, host=host)
                with patch.object(driver, "check_fault_runtime"), \
                        patch.object(driver, "signer_digest", return_value="c" * 64), \
                        patch.object(driver, "fault_manifest"):
                    result = driver.verify_fault(subject, path)
                self.assertTrue(result["actual_product_systemui_signer_matches"])
                self.assertIn(unittest.mock.call("docker", "cp", systemui,
                    driver.TOOLS + ":/tmp/wonad-dispatch-check.A1234567/SystemUI.apk"), host.call_args_list)

    def test_changed_systemui_reference_rejected_before_tool_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory)
            systemui = product / "system_ext/priv-app/SystemUI/SystemUI.apk"
            systemui.parent.mkdir(parents=True)
            systemui.write_bytes(b"wrong SystemUI")
            subject = SimpleNamespace(product=None, host=Mock(), native_evidence=SimpleNamespace(product=product,
                initial={"artifacts": {"com.android.systemui": {"sha256": "d" * 64}}}))
            with patch.object(driver, "check_fault_runtime"), \
                    self.assertRaisesRegex(ValueError, "actual admitted SystemUI"):
                driver.verify_fault(subject, product / "fault.apk")
            subject.host.assert_not_called()


class BrokerDispatchOsSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (FIXTURES / "sources.tar.gz").is_file():
            raise unittest.SkipTest("Select the retained authenticated archive/receipt/manifest unit fixtures")
        cls.original_archive = (FIXTURES / "sources.tar.gz").read_bytes()
        cls.original_receipt = (FIXTURES / "x86-custom-receipt.json").read_bytes()
        cls.original_manifest = json.loads((FIXTURES / "manifest.json").read_bytes())
        cls.contents = source.archive_members(cls.original_archive,
            (*source.MEMBERS, *source.DEFINITIONS, source.LOCK_MEMBER, source.STAGE_CONTRACT_MEMBER))
        marker = json.loads(cls.original_receipt)["source"]["stage"]["marker"]
        patch_names = tuple("android/platform/patches/" + row["name"]
                            for family in marker["patches"].values() for row in family)
        cls.contents.update(source.archive_members(cls.original_archive, patch_names))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wonad-dispatch-os-unit-", dir="/var/tmp")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def emulator(self, *, archive=None, receipt=None, manifest=None, actual_systemui=None):
        archive = self.original_archive if archive is None else archive
        receipt = self.original_receipt if receipt is None else receipt
        admitted = copy.deepcopy(self.original_manifest if manifest is None else manifest)
        remote = {source.MANIFEST: json.dumps(admitted).encode(), source.ARCHIVE: archive, source.RECEIPT: receipt}
        systemui = dict(path=source.SYSTEMUI, sha256=admitted["os_artifacts"]["com.android.systemui"])
        if actual_systemui is not None:
            systemui["sha256"] = actual_systemui
        test = SimpleNamespace(output=self.directory, identity=CID, trace=[], owned=Mock(),
            report=dict(manifest=admitted, image_id=IMAGE, test_sources_sha256={}),
            native_evidence=SimpleNamespace(initial=dict(artifacts={"com.android.systemui": systemui})))
        def host(*arguments):
            command = list(map(str, arguments))
            if command[:2] == ["docker", "cp"]:
                (Path(command[3])).write_bytes(remote[command[2].split(":", 1)[1]])
                output = ""
            else:
                self.assertEqual(command, ["docker", "exec", CID, "sha256sum", *source.INPUTS])
                output = "\n".join(hashlib.sha256(remote[name]).hexdigest() + "  " + name for name in source.INPUTS)
            test.trace.append(dict(command=command, output=output))
            return output
        test.host = Mock(side_effect=host)
        return test

    def capture(self, **changes):
        test = self.emulator(**changes)
        binding = source.capture_os_source_binding(test)
        (self.directory / "commands.json").write_text(json.dumps(test.trace))
        common = dict(container=CID, candidate_runtime=dict(image_id=IMAGE),
            artifacts=test.native_evidence.initial["artifacts"],
            evidence_files=native_evidence.evidence_files(self.directory))
        return test, binding, common

    def repack(self, entries):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            for name, value, kind in entries:
                row = tarfile.TarInfo(name)
                row.type = kind
                row.size = len(value) if kind == tarfile.REGTYPE else 0
                row.linkname = "elsewhere" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                archive.addfile(row, io.BytesIO(value) if row.isreg() else None)
        return stream.getvalue()

    def changed_archive(self, change):
        entries = [(name, value, tarfile.REGTYPE) for name, value in self.contents.items()]
        change(entries)
        raw = self.repack(entries)
        manifest = copy.deepcopy(self.original_manifest)
        manifest["files"][source.ARCHIVE] = hashlib.sha256(raw).hexdigest()
        return raw, manifest

    def changed_receipt(self, change):
        receipt = json.loads(self.original_receipt)
        change(receipt)
        raw = json.dumps(receipt).encode()
        manifest = copy.deepcopy(self.original_manifest)
        sha = hashlib.sha256(raw).hexdigest()
        manifest["files"][source.RECEIPT] = sha
        manifest["phase1_build_evidence"]["custom_receipt"]["expected_sha256"] = sha
        manifest["phase1_build_evidence"]["custom_receipt"]["file"] = dict(sha256=sha, size=len(raw))
        return raw, manifest

    def test_retained_real_archive_receipt_members_link_actual_systemui_not_host_fix(self):
        original_lock = source.comparison.LOCK
        test, binding, common = self.capture()
        derived = source.audit_os_source_binding(test.report, self.directory, common,
            dict(os_source_binding=binding), test.trace)
        self.assertEqual(derived, binding)
        self.assertEqual(len(binding["members"]), 2)
        self.assertEqual(len(binding["original_artifact_definitions"]["os_paths"]), 5)
        self.assertIn("not_current_full_build_recapture", binding["validation_scope"])
        controller = next(name for name in source.MEMBERS if name.endswith("NativeDesktopController.kt"))
        host_controller = (ROOT / controller).read_bytes()
        self.assertNotEqual(binding["members"][controller]["sha256"], hashlib.sha256(host_controller).hexdigest())
        self.assertFalse(binding["host_controller_used_as_runtime_proof"])
        self.assertEqual(binding["command_binding"], dict(copy_indices=[0, 1, 2], sha256_index=3))
        self.assertEqual(test.owned.call_count, 4)
        self.assertEqual(source.comparison.LOCK, original_lock)
        self.assertNotIn("bundle_manifest", test.report)
        self.assertTrue(set(source.INPUTS.values()) | set(source.MEMBERS.values()) |
                        {source.LOCK_FILE} <= set(common["evidence_files"]))
        for name, row in binding["members"].items():
            self.assertEqual((self.directory / row["path"]).read_bytes(), self.contents[name])

    def test_original_current_full_build_validator_remains_fail_closed_and_unchanged(self):
        test, _, _ = self.capture()
        receipt = self.directory / source.INPUTS[source.RECEIPT]
        with self.assertRaisesRegex(ValueError, "artifact set differs"):
            source.comparison.verify(receipt, hashlib.sha256(receipt.read_bytes()).hexdigest(), rehash=False)
        self.assertEqual(source.comparison.LOCK, ROOT / "android/grapheneos.lock.json")

    def test_foreign_archive_receipt_systemui_or_admitted_manifest_is_rejected(self):
        cases = (
            dict(archive=self.original_archive + b"foreign"),
            dict(receipt=self.original_receipt + b"foreign"),
            dict(actual_systemui="f" * 64),
        )
        for index, changes in enumerate(cases):
            directory = self.directory / str(index); directory.mkdir()
            test = self.emulator(**changes); test.output = directory
            with self.subTest(changes=changes.keys()), self.assertRaises(ValueError):
                source.capture_os_source_binding(test)
        test, binding, common = self.capture()
        declared = copy.deepcopy(test.report); declared["manifest"]["fingerprint"] = "foreign"
        with self.assertRaisesRegex(ValueError, "admitted bundle"):
            source.audit_os_source_binding(declared, self.directory, common, dict(os_source_binding=binding), test.trace)

    def test_missing_duplicate_symlink_hardlink_or_noncanonical_required_members_reject(self):
        for member in (*source.MEMBERS, *source.DEFINITIONS, source.LOCK_MEMBER):
            mutations = (
                lambda rows, m=member: rows.__setitem__(slice(None), [row for row in rows if row[0] != m]),
                lambda rows, m=member: rows.append((m, self.contents[m], tarfile.REGTYPE)),
                lambda rows, m=member: rows.__setitem__(next(i for i,r in enumerate(rows) if r[0] == m),
                                                      (m, b"", tarfile.SYMTYPE)),
                lambda rows, m=member: rows.__setitem__(next(i for i,r in enumerate(rows) if r[0] == m),
                                                      (m, b"", tarfile.LNKTYPE)),
                lambda rows, m=member: rows.__setitem__(next(i for i,r in enumerate(rows) if r[0] == m),
                                                      ("./" + m, self.contents[m], tarfile.REGTYPE)),
            )
            for ordinal, mutation in enumerate(mutations):
                archive, manifest = self.changed_archive(mutation)
                directory = self.directory / (str(len(list(self.directory.iterdir()))) + "-bad"); directory.mkdir()
                test = self.emulator(archive=archive, manifest=manifest); test.output = directory
                with self.subTest(member=member, mutation=ordinal), self.assertRaises(ValueError):
                    source.capture_os_source_binding(test)

    def test_host_new_controller_or_tampered_archived_definition_cannot_be_substituted(self):
        controller = next(name for name in source.MEMBERS if name.endswith("NativeDesktopController.kt"))
        for member, value in ((controller, (ROOT / controller).read_bytes()),
                              (source.DEFINITIONS[0], b"IMAGE_FILES = ()\n"),
                              (source.DEFINITIONS[1], self.contents[source.DEFINITIONS[1]] + b"\n# changed definition bytes\n")):
            archive, manifest = self.changed_archive(lambda rows: rows.__setitem__(
                next(i for i,r in enumerate(rows) if r[0] == member), (member, value, tarfile.REGTYPE)))
            directory = self.directory / str(len(list(self.directory.iterdir()))); directory.mkdir()
            test = self.emulator(archive=archive, manifest=manifest); test.output = directory
            with self.subTest(member=member), self.assertRaises(ValueError):
                source.capture_os_source_binding(test)
        test, binding, common = self.capture()
        changed = copy.deepcopy(binding)
        changed["members"][controller]["sha256"] = hashlib.sha256((ROOT / controller).read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "authenticated originals"):
            source.audit_os_source_binding(test.report, self.directory, common, dict(os_source_binding=changed), test.trace)

    def test_unrelated_or_current_host_lock_is_not_the_compiled_historical_lock(self):
        original = source.comparison.LOCK
        test, binding, common = self.capture()
        current = original.read_bytes()
        self.assertNotEqual(current, self.contents[source.LOCK_MEMBER])
        (self.directory / source.LOCK_FILE).write_bytes(current)
        common["evidence_files"][source.LOCK_FILE] = hashlib.sha256(current).hexdigest()
        with self.assertRaisesRegex(ValueError, "lock differs"):
            source.audit_os_source_binding(test.report, self.directory, common, dict(os_source_binding=binding), test.trace)
        self.assertEqual(source.comparison.LOCK, original)

    def test_historical_lock_adapter_does_not_change_current_frankel_policy(self):
        validator = source.comparison.provenance.validate_lock
        document = json.loads(self.contents[source.LOCK_MEMBER])
        self.assertEqual(document["device"], "frankel")
        document["device"] = "shiba"
        with self.assertRaisesRegex(ValueError, "must select frankel"):
            validator(document)
        self.capture()
        self.assertIs(source.comparison.provenance.validate_lock, validator)
        with self.assertRaisesRegex(ValueError, "must select frankel"):
            validator(document)

    def test_resealed_archive_and_receipt_pin_cannot_substitute_unrelated_stage_tool_lock(self):
        current = source.comparison.LOCK.read_bytes()
        archive, _ = self.changed_archive(lambda rows: rows.__setitem__(
            next(i for i, r in enumerate(rows) if r[0] == source.LOCK_MEMBER),
            (source.LOCK_MEMBER, current, tarfile.REGTYPE)))
        receipt, manifest = self.changed_receipt(lambda value: value["source"]["pin"].__setitem__(
            "lock", dict(sha256=hashlib.sha256(current).hexdigest(), size=len(current))))
        manifest["files"][source.ARCHIVE] = hashlib.sha256(archive).hexdigest()
        test = self.emulator(archive=archive, receipt=receipt, manifest=manifest)
        with self.assertRaisesRegex(ValueError, "stage-tool lock"):
            source.capture_os_source_binding(test)

    def test_runtime_manifest_key_is_anchored_to_actual_startup_source_not_normal_subclass(self):
        import inspect
        from startup_regression_smoke import StartupSmoke
        self.assertIn("manifest=manifest", inspect.getsource(StartupSmoke.start))
        self.assertNotIn("bundle_manifest", inspect.getsource(StartupSmoke.start))
        test, binding, common = self.capture()
        self.assertIn("manifest", test.report)
        self.assertNotIn("bundle_manifest", test.report)
        self.assertEqual(source.audit_os_source_binding(dict(startup=test.report), self.directory,
                         common, dict(os_source_binding=binding), test.trace), binding)
        missing = copy.deepcopy(test.report)
        missing["bundle_manifest"] = missing.pop("manifest")
        with self.assertRaisesRegex(ValueError, "admitted bundle"):
            source.audit_os_source_binding(dict(startup=missing), self.directory,
                         common, dict(os_source_binding=binding), test.trace)

    def test_changed_or_noncustom_receipt_pin_stage_and_artifact_rows_reject(self):
        controller = next(name for name in source.MEMBERS if name.endswith("NativeDesktopController.kt"))
        staged = controller.removeprefix("android/")
        changes = (
            lambda r: r.__setitem__("role", "baseline"),
            lambda r: r.__setitem__("schema", True),
            lambda r: r["source"]["stage"]["marker"]["files"].__setitem__(staged, "f" * 64),
            lambda r: r["artifacts"]["os_artifacts"]["com.android.systemui"].__setitem__("sha256", "f" * 64),
            lambda r: r["artifact_definitions"]["definition_files"][source.DEFINITIONS[0]].__setitem__("sha256", "f" * 64),
            lambda r: r["source"]["pin"]["lock"].__setitem__("sha256", "f" * 64),
        )
        for ordinal, change in enumerate(changes):
            receipt, manifest = self.changed_receipt(change)
            directory = self.directory / str(ordinal); directory.mkdir()
            test = self.emulator(receipt=receipt, manifest=manifest); test.output = directory
            with self.subTest(change=ordinal), self.assertRaises(ValueError):
                source.capture_os_source_binding(test)

    def test_trace_and_sealed_file_foreign_duplicate_order_and_missing_reads_reject(self):
        test, binding, common = self.capture()
        mutations = (
            lambda rows: rows[0]["command"].__setitem__(2, "c" * 64 + ":" + source.MANIFEST),
            lambda rows: rows.append(copy.deepcopy(rows[0])),
            lambda rows: rows.pop(),
            lambda rows: rows[3].__setitem__("output", "0" * 64 + "  " + source.MANIFEST),
            lambda rows: rows.reverse(),
            lambda rows: rows[1].__setitem__("error", "failed actual source read"),
        )
        for ordinal, mutation in enumerate(mutations):
            trace = copy.deepcopy(test.trace); mutation(trace)
            with self.subTest(mutation=ordinal), self.assertRaises(ValueError):
                source.audit_os_source_binding(test.report, self.directory, common,
                                               dict(os_source_binding=binding), trace)
        controller_path = self.directory / next(iter(source.MEMBERS.values()))
        controller_path.write_bytes(b"tampered original")
        with self.assertRaisesRegex(ValueError, "observation changed"):
            source.audit_os_source_binding(test.report, self.directory, common, dict(os_source_binding=binding), test.trace)

    def test_absent_binding_never_upgrades_otherwise_passed_case_fields(self):
        with self.assertRaisesRegex(ValueError, "Missing required OS source"):
            source.audit_os_source_binding({}, self.directory, {}, {}, [])

    def test_existing_source_output_is_preserved_before_any_owned_read(self):
        for name in (*source.INPUTS.values(), *source.MEMBERS.values(), source.LOCK_FILE):
            path = self.directory / name; path.write_bytes(b"prior evidence")
            test = self.emulator()
            with self.subTest(name=name), self.assertRaises(ValueError):
                source.capture_os_source_binding(test)
            test.owned.assert_not_called(); test.host.assert_not_called()
            self.assertEqual(path.read_bytes(), b"prior evidence")
            path.unlink()

    def test_instrumentation_host_bindings_and_both_dispatch_case_requirements_preserved(self):
        test = self.emulator(); driver.bind_sources(test)
        names = test.report["test_sources_sha256"]
        self.assertTrue(all(name not in names for name in source.MEMBERS))
        for name in ("NativeBrokerDispatchInstrumentation.kt", "NativeLauncherPageTimeoutInstrumentation.kt",
                     "NativeSecurityClient.kt", "NativeCompletionProofInstrumentation.kt"):
            self.assertEqual(len([key for key in names if key.endswith("/" + name)]), 1)
        body = Path(driver.__file__).read_text().split("def run_dispatch(", 1)[1].split("def bind_sources(", 1)[0]
        self.assertLess(body.index("capture_os_source_binding(test)"), body.index("with RunningProbe"))
        self.assertIn("run_launcher_dispatch(checks, host, baseline, uid, processes)", body)
        self.assertIn('initial_launcher_page_timeout=True', body)
        self.assertIn('actual_public_binder_timeout=True', body)

    def product_mode_model(self):
        from native_backend_acceptance import IMAGE_NAMES
        from startup_regression_smoke import LABEL
        test, binding, common = self.capture()
        common["run"] = "d" * 32
        common["product_images"] = {name: dict(sha256=test.report["manifest"]["files"]["/product/" + name],
            bytes=100 + index) for index, name in enumerate(IMAGE_NAMES)}
        test.report["bundled_product_inventory"] = dict(images=copy.deepcopy(common["product_images"]),
            manifest_sha256=binding["manifest"]["sha256"])
        info = dict(Id=CID, Image=IMAGE, State=dict(Running=True),
            Config=dict(Labels={LABEL: common["run"]}),
            HostConfig=dict(NetworkMode="none", Privileged=False, PortBindings={}),
            Mounts=[dict(Destination="/state", Source=str(self.directory / "emulator-state"), RW=True, Type="bind"),
                    dict(Destination="/tmp", Source="", RW=True, Type="tmpfs")])
        inspect = dict(command=["docker", "inspect", CID], output=json.dumps([info]))
        names = ["/product/" + name for name in IMAGE_NAMES]
        reads = [dict(command=["docker", "exec", CID, "cat", source.MANIFEST],
                      output=json.dumps(test.report["manifest"])),
                 dict(command=["docker", "exec", CID, "sha256sum", *names, source.MANIFEST],
                      output="\n".join(common["product_images"][name]["sha256"] + "  /product/" + name
                          for name in IMAGE_NAMES) + "\n" + binding["manifest"]["sha256"] + "  " + source.MANIFEST),
                 dict(command=["docker", "exec", CID, "stat", "-c", "%n:%s", *names],
                      output="\n".join("/product/" + name + ":" + str(common["product_images"][name]["bytes"])
                                      for name in IMAGE_NAMES))]
        trace = [copy.deepcopy(inspect), *copy.deepcopy(reads), *copy.deepcopy(test.trace),
                 dict(instrumentation_args=["unit-probe-order-model"]),
                 copy.deepcopy(inspect), *copy.deepcopy(reads), copy.deepcopy(inspect)]
        return test.report, binding, common, trace

    def test_bundled_mode_auditor_requires_actual_owned_bytes_sizes_and_probe_bracketing(self):
        report, binding, common, trace = self.product_mode_model()
        self.assertEqual(source.audit_dispatch_product_mode(dict(startup=report), self.directory,
            common, trace, binding), "actual_bundled_product_with_reference_only")
        mutations = (
            lambda r, t: r.pop("bundled_product_inventory"),
            lambda r, t: r.__setitem__("product_override", dict(path="/var/tmp/foreign", files={})),
            lambda r, t: r["bundled_product_inventory"].__setitem__("manifest_sha256", "f" * 64),
            lambda r, t: t[2].__setitem__("output", "f" * 64 + t[2]["output"][64:]),
            lambda r, t: t[3].__setitem__("output", t[3]["output"].replace(":100", ":999", 1)),
            lambda r, t: t[1].__setitem__("output", "{}"),
            lambda r, t: t[2]["command"].__setitem__(2, "e" * 64),
            lambda r, t: t[2].__setitem__("error", "actual read failed"),
            lambda r, t: t.__setitem__(slice(-4, -1), []),
            lambda r, t: t.insert(0, t.pop(8)),  # Probe before initial inventory.
        )
        for ordinal, mutation in enumerate(mutations):
            changed, rows = copy.deepcopy(report), copy.deepcopy(trace)
            mutation(changed, rows)
            with self.subTest(mutation=ordinal), self.assertRaises(ValueError):
                source.audit_dispatch_product_mode(dict(startup=changed), self.directory, common, rows, binding)

    def test_bundled_mode_rejects_actual_product_or_repair_mount_identity_and_isolation(self):
        from startup_regression_smoke import LABEL
        report, binding, common, trace = self.product_mode_model()
        mutations = (
            lambda i: i.__setitem__("Image", "sha256:" + "e" * 64),
            lambda i: i.__setitem__("Id", "e" * 64),
            lambda i: i["Config"]["Labels"].__setitem__(LABEL, "e" * 32),
            lambda i: i["HostConfig"].__setitem__("NetworkMode", "host"),
            lambda i: i["HostConfig"].__setitem__("Privileged", True),
            lambda i: i["Mounts"].append(dict(Destination="/product", Source="/var/tmp/other", RW=False, Type="bind")),
            lambda i: i["Mounts"].append(dict(Destination="/opt/wonad/wonad.apk", Source="/var/tmp/other", RW=False, Type="bind")),
            lambda i: i["Mounts"].append(copy.deepcopy(i["Mounts"][0])),
            lambda i: i["Mounts"][1].__setitem__("Type", "bind"),
            lambda i: i["Mounts"][0].__setitem__("RW", False),
        )
        for ordinal, mutation in enumerate(mutations):
            rows = copy.deepcopy(trace)
            info = json.loads(rows[0]["output"])[0]; mutation(info)
            rows[0]["output"] = json.dumps([info])
            with self.subTest(mutation=ordinal), self.assertRaises(ValueError):
                source.audit_dispatch_product_mode(dict(startup=report), self.directory, common, rows, binding)

    def test_default_explicit_product_mode_remains_actual_exact_readonly_mount(self):
        report, binding, common, trace = self.product_mode_model()
        report.pop("bundled_product_inventory")
        product = "/var/tmp/host-unit-product-reference"
        report["product_override"] = dict(path=product, files={name: row["sha256"]
                                                              for name, row in common["product_images"].items()})
        for row in trace:
            if row.get("command") == ["docker", "inspect", CID]:
                info = json.loads(row["output"])[0]
                info["Mounts"].append(dict(Destination="/product", Source=product, RW=False, Type="bind"))
                row["output"] = json.dumps([info])
        self.assertEqual(source.audit_dispatch_product_mode(dict(startup=report), self.directory,
            common, trace, binding), "explicit_readonly_product_override")
        for field, value in (("RW", True), ("Source", "/var/tmp/foreign")):
            rows = copy.deepcopy(trace)
            info = json.loads(rows[0]["output"])[0]
            info["Mounts"][-1][field] = value; rows[0]["output"] = json.dumps([info])
            with self.subTest(field=field), self.assertRaises(ValueError):
                source.audit_dispatch_product_mode(dict(startup=report), self.directory, common, rows, binding)


class BrokerDispatchBundledProductCliTests(unittest.TestCase):
    def test_explicit_flag_uses_reference_only_and_default_retains_readonly_override(self):
        for bundled in (False, True):
            with self.subTest(bundled=bundled), tempfile.TemporaryDirectory(
                    prefix="wonad-dispatch-cli-unit-", dir="/var/tmp") as directory:
                root = Path(directory) / "android"
                product = Path(directory) / "product"; product.mkdir()
                inputs = []
                for name in ("owner.apk", "fixture.apk", "security.apk", "fault.apk"):
                    path = Path(directory) / name; path.write_bytes(b"host-unit-" + name.encode())
                    inputs.append(path)
                apk, fixture, security, fault = inputs
                output = root / "out/dispatch"
                fake = SimpleNamespace(output=output, report={}, trace=[])
                argv = ["native_broker_dispatch_smoke", "--image", IMAGE, "--product", str(product),
                        "--apk", str(apk), "--fixture-apk", str(fixture), "--security-apk", str(security),
                        "--fault-apk", str(fault), "--output", str(output)]
                if bundled: argv.append("--bundled-product")
                with patch.object(driver, "__file__", str(root / "tools/native_broker_dispatch_smoke.py")), \
                        patch.object(sys, "argv", argv), \
                        patch.object(driver, "NativeBrokerDispatchEmulator", return_value=fake) as create, \
                        patch.object(driver, "run_dispatch", side_effect=RuntimeError("stop-before-guest")) as run, \
                        patch.object(driver, "finish") as finish:
                    self.assertEqual(driver.main(), 1)
                self.assertEqual(create.call_args.args, (IMAGE, output, apk, None if bundled else product))
                self.assertEqual(create.call_args.kwargs, {"first_attach_only": True})
                self.assertEqual(getattr(fake, "evidence_product", None), product if bundled else None)
                run.assert_called_once_with(fake, fixture, security, fault)
                finish.assert_called_once()
                self.assertEqual(fake.trace, [])

    def test_real_constructor_and_start_lifecycle_bind_instrumentation_after_source_map_exists(self):
        with tempfile.TemporaryDirectory(prefix="wonad-dispatch-start-unit-", dir="/var/tmp") as directory:
            test = driver.NativeBrokerDispatchEmulator(IMAGE, Path(directory), None, None,
                                                       first_attach_only=True)
            self.assertNotIn("test_sources_sha256", test.report)
            events = []
            def ordinary_start(subject):
                self.assertIs(subject, test)
                events.append("ordinary-start")
                subject.report["test_sources_sha256"] = {"existing-unit-source": "0" * 64}
            real_bind = driver.bind_sources
            def bound(subject, expected):
                self.assertEqual(events, ["ordinary-start"])
                self.assertEqual(expected, driver.dispatch_source_hashes())
                real_bind(subject, expected)
                events.append("instrumentation-bound")
            with patch.object(driver.NativeShellEmulator, "start", ordinary_start), \
                    patch.object(driver, "bind_sources", side_effect=bound):
                test.start()
            self.assertEqual(events, ["ordinary-start", "instrumentation-bound"])
            self.assertEqual(test.report["test_sources_sha256"]["existing-unit-source"], "0" * 64)
            self.assertTrue(any(name.endswith("NativeLauncherPageTimeoutInstrumentation.kt")
                                for name in test.report["test_sources_sha256"]))

    def test_whole_boot_source_drift_rejects_before_evidence_or_instrumentation(self):
        with tempfile.TemporaryDirectory(prefix="wonad-dispatch-source-drift-", dir="/var/tmp") as directory:
            test = driver.NativeBrokerDispatchEmulator(IMAGE, Path(directory), None, None,
                                                       first_attach_only=True)
            events = []
            def ordinary_start(subject):
                self.assertEqual(events, ["before-hashes"])
                events.append("ordinary-start")
                subject.report["test_sources_sha256"] = {"parent-overwrote-map": "0" * 64}
            def observe():
                if not events:
                    events.append("before-hashes")
                    return {"unit-instrumentation": "1" * 64}
                events.append("after-hashes")
                return {"unit-instrumentation": "2" * 64}
            with patch.object(driver.NativeShellEmulator, "start", ordinary_start), \
                    patch.object(driver, "dispatch_source_hashes", side_effect=observe):
                with self.assertRaisesRegex(ValueError, "changed during emulator boot"):
                    test.start()
            self.assertEqual(events, ["before-hashes", "ordinary-start", "after-hashes"])
            self.assertEqual(test.report["test_sources_sha256"], {"parent-overwrote-map": "0" * 64})

    def test_real_prepare_passes_bundled_reference_to_existing_actual_evidence_model(self):
        import native_lock_user_security_smoke as ordinary
        for bundled in (False, True):
            with self.subTest(bundled=bundled), tempfile.TemporaryDirectory(
                    prefix="wonad-dispatch-prepare-unit-", dir="/var/tmp") as directory:
                fixture = Path(directory) / "fixture.apk"; fixture.write_bytes(b"unit-fixture")
                security = Path(directory) / "security.apk"; security.write_bytes(b"unit-security")
                product = Path(directory) / "product"; product.mkdir()
                fake = SimpleNamespace(start=Mock(), run_cases=Mock(), report={}, identity=CID,
                    host=lambda *args: ordinary.digest(security if args[-1].endswith("security.apk") else fixture),
                    command=Mock(), shell=Mock(return_value="unit-package-uid"),
                    output=Path(directory), product=None if bundled else product)
                if bundled: fake.evidence_product = product
                checks = Mock(evidence={})
                evidence = Mock(); evidence.begin.side_effect = RuntimeError("stop-before-evidence-guest-read")
                with patch.object(ordinary, "NativeIsolationChecks", return_value=checks), \
                        patch.object(ordinary, "systemui_uid", return_value=10148), \
                        patch.object(ordinary, "freeze_apk", side_effect=lambda path, *args: path), \
                        patch.object(ordinary, "NativeEvidence", return_value=evidence) as capture:
                    with self.assertRaisesRegex(RuntimeError, "stop-before-evidence-guest-read"):
                        driver.prepare(fake, fixture, security)
                capture.assert_called_once_with(fake, checks, product=product if bundled else None)
                fake.start.assert_called_once(); fake.run_cases.assert_called_once()
                evidence.begin.assert_called_once()


if __name__ == "__main__":
    unittest.main()
