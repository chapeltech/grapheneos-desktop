"""Host-only tests for the prepared packet7 full-matrix generation."""

import ast
from dataclasses import replace
import errno
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


EVIDENCE = Path("/u/elric/tree/wonad-phase1-build-evidence")
ROOT = Path("/u/elric/tree/wonad")
WRAPPER_PATH = EVIDENCE / "run-phase1-native-matrix-custom7-5-packet7-5.py"
FREEZER_PATH = EVIDENCE / "freeze-phase1-native-matrix-custom7-5-packet7-5.sh"
EXPECTED_GATES = {
    "shell", "session_security", "systemui_death", "dead_binders",
    "transaction_timeout", "native_constraint", "wrong_signer",
    "credential_sleep", "credential_key", "user_switch", "frozen_client",
    "task_reuse", "apk_update", "core", "dialogs", "hardware_ime",
    "fixed_size", "recents_transfer", "unavailable_choice", "prerequisites",
    "browser_keyboard", "linux_profile_oracle", "broker_dispatch",
}
EXPECTED_GUI = ("startup_1", "startup_2", "startup_3", "host_x11")


def load_wrapper():
    spec = importlib.util.spec_from_file_location("phase1_matrix_wrapper5_tests", WRAPPER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assigned_literal(path, name):
    tree = ast.parse(path.read_bytes(), filename=str(path))
    for row in tree.body:
        if isinstance(row, ast.Assign) and any(isinstance(target, ast.Name) and
                target.id == name for target in row.targets):
            return ast.literal_eval(row.value)
    raise AssertionError("Missing literal " + name)


class FakeBase:
    BLOCKED_RUNNERS = {"run_native_matrix.py"}
    BLOCKED_COMPILERS = {"ninja"}

    @staticmethod
    def require(value, message):
        if not value:
            raise ValueError(message)

    @staticmethod
    def process_kind(argv):
        if not argv:
            return None
        executable = Path(argv[0]).name
        names = {Path(value).name for value in argv}
        if executable == "emulator" or executable.startswith("qemu-system"):
            return "emulator_or_qemu"
        if names & FakeBase.BLOCKED_RUNNERS:
            return "phase1_runner_or_build"
        if executable in FakeBase.BLOCKED_COMPILERS:
            return "compiler"
        return None


class PendingAndFreezeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wrapper = load_wrapper()

    def test_every_unpublished_identity_is_literal_pending(self):
        self.assertEqual("PENDING_ACTUAL_NATIVE4_IMMUTABLE_IMAGE_ID", self.wrapper.IMAGE)
        self.assertEqual("PENDING_ACTUAL_DERIVED6_IMMUTABLE_IMAGE_ID", self.wrapper.PAIR_IMAGE)
        self.assertEqual("PENDING_ACTUAL_WRONG7_SIGNING_RECEIPT_SHA256", self.wrapper.WRONG_SHA)
        self.assertEqual("PENDING_FROZEN_PACKET7_INPUTS_SHA256", self.wrapper.INPUTS_SHA)
        self.assertEqual("PENDING_ACTUAL_PAIR6_API_REPORT_SHA256",
                         self.wrapper.PAIR_API_REPORT_SHA)
        self.assertEqual("PENDING_ACTUAL_PAIR6_RECENTS_REPORT_SHA256",
                         self.wrapper.PAIR_RECENTS_REPORT_SHA)
        self.assertFalse(self.wrapper.INPUTS.exists())
        self.assertFalse(self.wrapper.OUTPUT.exists())
        self.assertFalse(self.wrapper.PAIR_API_REPORT.exists())
        self.assertFalse(self.wrapper.PAIR_RECENTS_REPORT.exists())

    def test_pending_fails_before_dependencies_lock_docker_auditor_or_output(self):
        with mock.patch.object(self.wrapper, "load_dependencies",
                side_effect=AssertionError("dependency/lock path reached")) as loader, \
             mock.patch.object(self.wrapper, "validate_pair_reports",
                side_effect=AssertionError("auditor reached")) as auditor:
            with self.assertRaisesRegex(ValueError, "input digest is unresolved"):
                self.wrapper.main(["--check-only"])
        loader.assert_not_called()
        auditor.assert_not_called()
        self.assertFalse(self.wrapper.OUTPUT.exists())

    def test_each_external_publication_is_independently_mandatory(self):
        resolved = {
            "INPUTS_SHA": "1" * 64,
            "IMAGE": "sha256:" + "2" * 64,
            "PAIR_IMAGE": "sha256:" + "3" * 64,
            "WRONG_SHA": "4" * 64,
            "PAIR_API_REPORT_SHA": "5" * 64,
            "PAIR_RECENTS_REPORT_SHA": "6" * 64,
        }
        messages = {
            "INPUTS_SHA": "input digest", "IMAGE": "Native4", "PAIR_IMAGE": "Derived6",
            "WRONG_SHA": "Wrong-signer7", "PAIR_API_REPORT_SHA": "API acceptance",
            "PAIR_RECENTS_REPORT_SHA": "Recents acceptance",
        }
        for missing, message in messages.items():
            values = dict(resolved)
            values[missing] = "PENDING_INDEPENDENT_CONTROL"
            patches = [mock.patch.object(self.wrapper, name, value)
                       for name, value in values.items()]
            for patch in patches:
                patch.start()
            try:
                with self.assertRaisesRegex(ValueError, message):
                    self.wrapper.pending_gate()
            finally:
                for patch in reversed(patches):
                    patch.stop()

    def test_freezer_pending_gate_runs_before_any_external_program(self):
        output = ROOT / "android/out/phase1-native-matrix-custom7-5-packet7-inputs-5"
        before = output.exists() or output.is_symlink()
        result = subprocess.run(["/bin/bash", str(FREEZER_PATH)], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={"PATH": "/definitely/absent"}, timeout=5)
        self.assertEqual(78, result.returncode, result)
        self.assertIn("unresolved", result.stderr)
        self.assertEqual(before, output.exists() or output.is_symlink())

    def test_freezer_has_exact_packet7_inputs_and_all_prerequisites(self):
        raw = FREEZER_PATH.read_text()
        self.assertIn("matrix_packet_sha=5d5737ebe26048152fccfb4881cd89fb4b583ca2df0cfc84fbe8d023799cc459", raw)
        self.assertIn("matrix_update_sha=1eef12a24e976bf4711c8c2e2872096436f28621c6ebe07c0151dd37aa29e177", raw)
        self.assertIn("matrix_wrong_sha=PENDING_ACTUAL_WRONG7_SIGNING_RECEIPT_SHA256", raw)
        self.assertIn("matrix_image=PENDING_ACTUAL_NATIVE4_IMMUTABLE_IMAGE_ID", raw)
        required = {
            "--image", "--product", "--apk", "--fixture-apk", "--security-apk",
            "--fault-apk", "--reuse-apk", "--ime-apk", "--probe-apk",
            "--prerequisite-apk", "--wrong-artifacts", "--update-preparation",
            "--browser-cache", "--linux-reference", "--output",
        }
        freeze_argv = raw.split("android/tools/run_native_matrix.py freeze \\\n", 1)[1]
        observed = {word for word in freeze_argv.replace("\\\n", " ").split()
                    if word.startswith("--")}
        self.assertEqual(required, observed)
        self.assertIn("phase1-native-matrix-custom7-5-packet7-inputs-5", raw)
        self.assertIn("phase1-native-candidate-custom7-5-4/built-image.id", raw)


class ClosureAndInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wrapper = load_wrapper()

    def test_exact_reviewed_source_closure_and_full_command(self):
        base_source = self.wrapper.capture_source(
            self.wrapper.BASE_WRAPPER, self.wrapper.BASE_WRAPPER_SHA)
        pair_source = self.wrapper.capture_source(
            self.wrapper.PAIR_DRIVER, self.wrapper.PAIR_DRIVER_SHA)
        base = self.wrapper.execute_source(base_source, "packet7_base_control")
        pair = self.wrapper.execute_source(pair_source, "packet7_pair_control")
        configured = self.wrapper.configure(base, pair)
        self.assertEqual([str(configured.PYTHON), "-B", str(configured.RUNNER), "run",
            "--inputs", str(self.wrapper.INPUTS), "--output", str(self.wrapper.OUTPUT),
            "--phase", "all", "--jobs", "2", "--timeout", "7200"],
            configured.COMMAND)
        self.assertEqual(self.wrapper.IMAGE, configured.IMAGE)
        self.assertEqual(self.wrapper.PAIR_IMAGE, configured.PAIR_IMAGE)
        self.assertEqual(pair, configured.reviewed_pair_module())

    def test_repository_inventory_is_exact_required23_plus_gui4(self):
        tools = str(ROOT / "android/tools")
        sys.path.insert(0, tools)
        try:
            import native_backend_acceptance
            gates = set(native_backend_acceptance.GATES)
        finally:
            sys.path.remove(tools)
        gui = assigned_literal(ROOT / "android/tools/run_native_matrix.py", "GUI")
        self.assertEqual(EXPECTED_GATES, gates)
        self.assertEqual(EXPECTED_GUI, gui)
        self.assertEqual(23, len(gates))
        self.assertEqual(4, len(gui))

    def test_packet7_source_and_runner_bindings_are_exact(self):
        self.assertEqual("5d5737ebe26048152fccfb4881cd89fb4b583ca2df0cfc84fbe8d023799cc459",
                         self.wrapper.PACKET_SHA)
        self.assertEqual("f29b136a2ea62c02c7c722f2746a4ce92b8ea666e87ba1c0656d028d7d68be8e",
                         hashlib.sha256((ROOT / "android/tools/run_native_matrix.py").read_bytes()).hexdigest())
        self.assertEqual(self.wrapper.PACKET / "receipt.json",
                         ROOT / "android/out/phase1-emulator-client-packet-20261011-7/receipt.json")

    def test_predecessors_are_unchanged(self):
        expected = {
            "run-phase1-native-matrix-custom7-5-packet4-1.py":
                "1191e75b3d8bdd8ed6302297fcd0446e97c9699e43eee474c28144f8ef1d6f8a",
            "run-phase1-native-matrix-custom7-5-packet6-4.py":
                "b179fe1076298161c66c889a30669e6917e0f16a1783c2fac47d0a51bf5dc370",
            "freeze-phase1-native-matrix-custom7-5-packet6-3.sh":
                "bb48f79bde2100d8d3054f55b9aa7df0d7b6cfe7a596b36aeb60266da0a7cf7c",
        }
        for name, digest in expected.items():
            self.assertEqual(digest, hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest())


class CaptureAndProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wrapper = load_wrapper()

    def proc(self, payload):
        root = tempfile.TemporaryDirectory(prefix="wonad-matrix5-proc-")
        path = Path(root.name) / "101"
        path.mkdir()
        (path / "cmdline").write_bytes(payload)
        return root, Path(root.name)

    def test_captured_bytes_execute_after_pathname_swap(self):
        with tempfile.TemporaryDirectory(prefix="wonad-matrix5-source-") as name:
            path = Path(name) / "source.py"
            original = b"observed = 'captured'\n"
            path.write_bytes(original)
            path.chmod(0o600)
            source = self.wrapper.capture_source(path,
                hashlib.sha256(original).hexdigest())
            path.rename(path.with_suffix(".old"))
            path.write_text("raise RuntimeError('pathname reopened')\n")
            path.chmod(0o600)
            module = self.wrapper.execute_source(source, "captured_swap_control")
            self.assertEqual("captured", module.observed)

    def test_tampered_captured_bytes_never_compile(self):
        with tempfile.TemporaryDirectory(prefix="wonad-matrix5-source-") as name:
            path = Path(name) / "source.py"
            path.write_text("observed = 1\n")
            path.chmod(0o600)
            source = self.wrapper.capture_source(path,
                hashlib.sha256(path.read_bytes()).hexdigest())
            tampered = replace(source, data=b"observed = 2\n")
            compiler = mock.Mock()
            with self.assertRaisesRegex(ValueError, "authenticated digest"):
                self.wrapper.execute_source(tampered, "wrong_sha_control", compiler=compiler)
            compiler.assert_not_called()

    def test_full_argv_competing_lanes_are_blocked(self):
        cases = [
            ["/usr/bin/python3", "-B", "/tmp/build_native_successor.py", "build"],
            ["/bin/bash", "/tmp/freeze-phase1-native-matrix-custom7-5-packet7-5.sh"],
            ["/usr/bin/python3", "/tmp/run-phase1-custom7-api-recents-packet7.py"],
            ["/usr/bin/python3", "/tmp/phase1_emulator_client_packet.py", "build"],
            ["/bin/bash", "/tmp/prepare-phase1-client-packet7.sh"],
            ["/bin/bash", "/tmp/run-phase1-native-candidate-custom7-5-4.sh"],
            ["/usr/bin/python3", "/tmp/native-x11-keyboard-smoke.py"],
            ["/usr/bin/qemu-kvm", "-machine", "q35"],
        ]
        for argv in cases:
            self.assertIsNotNone(self.wrapper.hardened_process_kind(FakeBase, argv), argv)
        self.assertIsNone(self.wrapper.hardened_process_kind(FakeBase, ["/usr/bin/true"]))

    def test_full_argv_detection_is_used_by_proc_scan(self):
        temporary, root = self.proc(
            b"/usr/bin/python3\0-B\0/tmp/build-phase1-conformance-candidate.py\0")
        try:
            with self.assertRaisesRegex(ValueError, "phase1_runner_or_build"):
                self.wrapper.inspect_live_processes(FakeBase, proc_root=root, own_pid=999)
        finally:
            temporary.cleanup()

    def test_oversized_and_unreadable_cmdlines_fail_closed(self):
        temporary, root = self.proc(b"x" * (self.wrapper.MAX_CMDLINE_BYTES + 1))
        try:
            with self.assertRaisesRegex(ValueError, "exceeds bounded observation"):
                self.wrapper.inspect_live_processes(FakeBase, proc_root=root, own_pid=999)
        finally:
            temporary.cleanup()
        temporary, root = self.proc(b"/usr/bin/true\0")
        try:
            def denied(_path):
                raise PermissionError(errno.EACCES, "denied")
            with self.assertRaisesRegex(ValueError, "Cannot observe live process"):
                self.wrapper.inspect_live_processes(FakeBase, proc_root=root, own_pid=999,
                                                     cmdline_reader=denied)
        finally:
            temporary.cleanup()

    def test_disappeared_pid_and_ordinary_process_are_controls(self):
        temporary, root = self.proc(b"/usr/bin/true\0")
        try:
            self.assertEqual({"blocked_processes": 0},
                self.wrapper.inspect_live_processes(FakeBase, proc_root=root, own_pid=999))
            self.assertEqual({"blocked_processes": 0},
                self.wrapper.inspect_live_processes(FakeBase, proc_root=root, own_pid=999,
                    cmdline_reader=lambda _path: (_ for _ in ()).throw(
                        FileNotFoundError(errno.ENOENT, "gone"))))
        finally:
            temporary.cleanup()


class FutureAuditBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wrapper = load_wrapper()

    def test_auditors_must_bind_exact_reports_and_images(self):
        with tempfile.TemporaryDirectory(prefix="wonad-matrix5-reports-") as name:
            root = Path(name)
            api = root / "api.json"
            recents = root / "recents.json"
            api.write_text('{"status":"passed"}\n')
            recents.write_text('{"status":"passed"}\n')
            api.chmod(0o600)
            recents.chmod(0o600)
            selection = {"native_image_id": "sha256:" + "1" * 64,
                         "derived_image_id": "sha256:" + "2" * 64,
                         "packet_receipt_sha256": self.wrapper.PACKET_SHA,
                         "product": "/product"}

            class Pair:
                WRONG_SHA = "3" * 64
                PYTHON = Path("/python")
                PACKET = self.wrapper.PACKET

                @staticmethod
                def actual_identity_ready():
                    return None

                @staticmethod
                def local_inputs():
                    return None

                @staticmethod
                def selected():
                    return selection

                @staticmethod
                def commands(selected, lane, audit=False):
                    tool = {"api": "phase1_conformance_acceptance.py",
                            "recents": "phase1_conformance_recents_guest_acceptance.py"}[lane]
                    path = {"api": api, "recents": recents}[lane]
                    return ["/python", "-B", str(ROOT / "android/tools" / tool),
                            "--report", str(path), "--product", selected["product"],
                            "--packet", str(self.wrapper.PACKET),
                            "--expected-receipt-sha256", self.wrapper.PACKET_SHA]

            completed = subprocess.CompletedProcess([], 0, "accepted\n", "")
            with mock.patch.object(self.wrapper, "WRONG_SHA", "3" * 64), \
                 mock.patch.object(self.wrapper, "IMAGE", selection["native_image_id"]), \
                 mock.patch.object(self.wrapper, "PAIR_IMAGE", selection["derived_image_id"]), \
                 mock.patch.object(self.wrapper, "PAIR_API_REPORT", api), \
                 mock.patch.object(self.wrapper, "PAIR_RECENTS_REPORT", recents), \
                 mock.patch.object(self.wrapper, "PAIR_API_REPORT_SHA",
                    hashlib.sha256(api.read_bytes()).hexdigest()), \
                 mock.patch.object(self.wrapper, "PAIR_RECENTS_REPORT_SHA",
                    hashlib.sha256(recents.read_bytes()).hexdigest()):
                runner = mock.Mock(return_value=completed)
                self.assertEqual(selection,
                    self.wrapper.validate_pair_reports(Pair, run=runner))
                self.assertEqual(2, runner.call_count)
                self.assertEqual({"api", "recents"}, {
                    "api" if "phase1_conformance_acceptance.py" in call.args[0][2]
                    else "recents" for call in runner.call_args_list})


if __name__ == "__main__":
    unittest.main()
