"""Host-only hostile tests for the sealed packet6 matrix admission wrapper."""

from dataclasses import replace
import errno
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


WRAPPER_PATH = Path("/u/elric/tree/wonad-phase1-build-evidence/" \
                    "run-phase1-native-matrix-custom7-5-packet6-4.py")


def load_wrapper():
    spec = importlib.util.spec_from_file_location("phase1_matrix_wrapper4_tests", WRAPPER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


class CapturedSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wrapper = load_wrapper()

    def test_authenticated_captured_bytes_execute_after_pathname_swap(self):
        with tempfile.TemporaryDirectory(prefix="wonad-matrix-source-") as name:
            path = Path(name) / "source.py"
            original = b"observed = 'captured'\n"
            path.write_bytes(original)
            path.chmod(0o600)
            expected = self.wrapper.hashlib.sha256(original).hexdigest()
            source = self.wrapper.capture_source(path, expected)
            old = path.with_suffix(".old")
            path.rename(old)
            path.write_text("raise RuntimeError('pathname reopen')\n")
            path.chmod(0o600)
            module = self.wrapper.execute_source(source, "captured_swap_control")
            self.assertEqual("captured", module.observed)

    def test_tampered_captured_bytes_are_rejected_before_compile(self):
        with tempfile.TemporaryDirectory(prefix="wonad-matrix-source-") as name:
            path = Path(name) / "source.py"
            path.write_text("observed = 1\n")
            path.chmod(0o600)
            expected = self.wrapper.hashlib.sha256(path.read_bytes()).hexdigest()
            source = self.wrapper.capture_source(path, expected)
            tampered = replace(source, data=b"observed = 2\n")
            called = []

            def compiler(*args, **kwargs):
                called.append((args, kwargs))
                return compile(*args, **kwargs)

            with self.assertRaisesRegex(ValueError, "authenticated digest"):
                self.wrapper.execute_source(tampered, "wrong_sha_control", compiler=compiler)
            self.assertEqual([], called)

    def test_wrong_expected_sha_is_never_captured(self):
        with tempfile.TemporaryDirectory(prefix="wonad-matrix-source-") as name:
            path = Path(name) / "source.py"
            path.write_text("observed = 1\n")
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "digest changed"):
                self.wrapper.capture_source(path, "0" * 64)


class ProcessObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wrapper = load_wrapper()

    def proc(self, payload):
        root = tempfile.TemporaryDirectory(prefix="wonad-matrix-proc-")
        path = Path(root.name) / "101"
        path.mkdir()
        (path / "cmdline").write_bytes(payload)
        return root, Path(root.name)

    def test_ordinary_control_is_admitted(self):
        temporary, root = self.proc(b"/usr/bin/true\0")
        try:
            self.assertEqual({"blocked_processes": 0},
                self.wrapper.inspect_live_processes(FakeBase, proc_root=root, own_pid=999))
        finally:
            temporary.cleanup()

    def test_oversized_cmdline_fails_closed(self):
        temporary, root = self.proc(b"x" * (self.wrapper.MAX_CMDLINE_BYTES + 1))
        try:
            with self.assertRaisesRegex(ValueError, "exceeds bounded observation"):
                self.wrapper.inspect_live_processes(FakeBase, proc_root=root, own_pid=999)
        finally:
            temporary.cleanup()

    def test_unreadable_cmdline_fails_closed(self):
        temporary, root = self.proc(b"/usr/bin/true\0")

        def denied(_path):
            raise PermissionError(errno.EACCES, "denied")

        try:
            with self.assertRaisesRegex(ValueError, "Cannot observe live process"):
                self.wrapper.inspect_live_processes(FakeBase, proc_root=root, own_pid=999,
                                                     cmdline_reader=denied)
        finally:
            temporary.cleanup()

    def test_disappeared_pid_is_the_only_unreadable_control(self):
        temporary, root = self.proc(b"/usr/bin/true\0")

        def gone(_path):
            raise FileNotFoundError(errno.ENOENT, "gone")

        try:
            self.assertEqual({"blocked_processes": 0},
                self.wrapper.inspect_live_processes(FakeBase, proc_root=root, own_pid=999,
                                                     cmdline_reader=gone))
        finally:
            temporary.cleanup()

    def test_foreign_qemu_kvm_is_blocked(self):
        temporary, root = self.proc(b"/usr/bin/qemu-kvm\0-machine\0q35\0")
        try:
            with self.assertRaisesRegex(ValueError, "emulator_or_qemu"):
                self.wrapper.inspect_live_processes(FakeBase, proc_root=root, own_pid=999)
        finally:
            temporary.cleanup()


class ClosureAndPendingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wrapper = load_wrapper()

    def test_exact_reviewed_source_closure_and_command(self):
        base_source = self.wrapper.capture_source(
            self.wrapper.BASE_WRAPPER, self.wrapper.BASE_WRAPPER_SHA)
        pair_source = self.wrapper.capture_source(
            self.wrapper.PAIR_DRIVER, self.wrapper.PAIR_DRIVER_SHA)
        base = self.wrapper.execute_source(base_source, "base_closure_control")
        pair = self.wrapper.execute_source(pair_source, "pair_closure_control")
        configured = self.wrapper.configure(base, pair)
        self.assertEqual("f29b136a2ea62c02c7c722f2746a4ce92b8ea666e87ba1c0656d028d7d68be8e",
                         configured.RUNNER_SHA)
        self.assertEqual([str(configured.PYTHON), "-B", str(configured.RUNNER), "run",
            "--inputs", str(self.wrapper.INPUTS), "--output", str(self.wrapper.OUTPUT),
            "--phase", "all", "--jobs", "2", "--timeout", "7200"], configured.COMMAND)
        self.assertIn("len(run_native_matrix.GATES) == 23", base_source.data.decode())
        self.assertIn("len(run_native_matrix.GUI) == 4", base_source.data.decode())
        self.assertEqual(pair, configured.reviewed_pair_module())
        self.assertEqual(self.wrapper.IMAGE, configured.IMAGE)
        self.assertEqual(self.wrapper.PAIR_IMAGE, configured.PAIR_IMAGE)

    def test_existing_classifications_are_unchanged_and_qemu_kvm_is_added(self):
        source = self.wrapper.capture_source(
            self.wrapper.BASE_WRAPPER, self.wrapper.BASE_WRAPPER_SHA)
        base = self.wrapper.execute_source(source, "classification_control")
        controls = [[], ["/usr/bin/true"], ["/opt/emulator"],
                    ["/usr/bin/qemu-system-x86_64"], ["python3", "run_native_matrix.py"],
                    ["/usr/bin/ninja"], ["docker", "build", "."],
                    ["gradle", "assemble"]]
        for argv in controls:
            self.assertEqual(base.process_kind(argv),
                             self.wrapper.hardened_process_kind(base, argv), argv)
        self.assertIsNone(base.process_kind(["/usr/bin/qemu-kvm", "-machine", "q35"]))
        self.assertEqual("emulator_or_qemu", self.wrapper.hardened_process_kind(
            base, ["/usr/bin/qemu-kvm", "-machine", "q35"]))

    def test_pending_input_digest_prevents_any_dependency_execution(self):
        self.assertEqual("PENDING_FROZEN_PACKET6_INPUTS_SHA256", self.wrapper.INPUTS_SHA)
        with mock.patch.object(self.wrapper, "load_dependencies",
                               side_effect=AssertionError("dependencies executed")) as loader:
            with self.assertRaisesRegex(ValueError, "input digest is unresolved"):
                self.wrapper.main(["--check-only"])
        loader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
