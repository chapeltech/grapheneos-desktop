import argparse
from contextlib import contextmanager, ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "android/tools/run_frankel_vendor.py"
GENERATOR = ROOT / "android/platform/generate-frankel-vendor.sh"
BRIDGE = Path("/u/elric/tree/wonad-phase1-build-evidence") / \
    "prepare-phase1-frankel-vendor-cache-20261012-5.sh"
BRIDGE6 = Path("/u/elric/tree/wonad-phase1-build-evidence") / \
    "prepare-phase1-frankel-vendor-cache-20261012-6.sh"
BRIDGE7 = Path("/u/elric/tree/wonad-phase1-build-evidence") / \
    "prepare-phase1-frankel-vendor-cache-20261012-7.sh"
SPEC = importlib.util.spec_from_file_location("run_frankel_vendor", TOOL)
vendor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vendor)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Config(types.SimpleNamespace):
    pass


@contextmanager
def mocked_execution():
    """Run the real lifecycle with all external/mutating seams replaced."""
    with tempfile.TemporaryDirectory() as root:
        root = Path(root)
        source = root / "source"
        repo = root / "repo"
        repo.mkdir()
        for relative in (".repo", "out", "vendor/adevtool"):
            (source / relative).mkdir(parents=True, exist_ok=True)
        config = Config(
            run=True, source=source, repo=repo, repo_inputs={},
            work=root / "work", log=root / "run.log",
            preflight=root / "preflight.json", result=root / "result.json",
            attempt_lock=root / "attempt.json",
            container="wonad-phase1-frankel-vendor-lifecycle-test")
        identities = vendor.source_directory_identities(config)
        authority = {"topology": {"directory_identities": identities}}
        clean_inodes = []
        writes = {}

        def cleanup(path):
            clean_inodes.append(Path(path).lstat().st_ino)
            return ["synthetic-cache"]

        def write(path, value):
            writes[Path(path)] = value
            return {"path": str(path), "bytes": 0, "sha256": "0" * 64}

        modules = (types.SimpleNamespace(clean_vendor_cache=cleanup),
                   object(), object(), object(), object())
        with ExitStack() as stack:
            enter = stack.enter_context
            enter(mock.patch.object(
                vendor, "initial_inputs",
                return_value=({}, {"android/grapheneos.lock.json": b"{}\n"}, {})))
            enter(mock.patch.object(vendor, "load_authority_modules", return_value=modules))
            enter(mock.patch.object(vendor, "docker_authority", return_value={}))
            enter(mock.patch.object(vendor, "source_authority", return_value=authority))
            enter(mock.patch.object(vendor, "missing_container", return_value=True))
            enter(mock.patch.object(vendor, "resources", return_value={"clear": True}))
            enter(mock.patch.object(vendor, "source_caches_absent", return_value={}))
            enter(mock.patch.object(vendor, "prepare_reflink", return_value={"clone": True}))
            enter(mock.patch.object(vendor, "captured_inventory", return_value=({}, {})))
            enter(mock.patch.object(vendor, "validate_cache", return_value={}))
            enter(mock.patch.object(
                vendor, "create_command",
                return_value=[*vendor.DOCKER, "create", "synthetic"]))
            enter(mock.patch.object(vendor, "write_new", side_effect=write))
            enter(mock.patch.object(
                vendor, "verify_generated_vendor", return_value={"generated": True}))
            yield config, identities, clean_inodes, writes


class StaticBoundaryTests(unittest.TestCase):
    @staticmethod
    def bridge_arguments(path=BRIDGE):
        source = path.read_text()
        command = source[source.index("exec /usr/bin/python3"):].replace("\\\n", " ")
        words = shlex.split(command)
        index = words.index(str(TOOL))
        arguments = words[index + 1:]
        arguments[arguments.index("$1")] = "--check-only"
        return arguments

    def test_builder_action_contains_generation_only(self):
        source = GENERATOR.read_text()
        self.assertIn("v24.21.0", source)
        self.assertIn("1.22.19", source)
        self.assertIn("install --frozen-lockfile --non-interactive", source)
        self.assertIn('vendor/adevtool/bin/run generate-all -d "$device"', source)
        self.assertIn("AndroidProducts.mk", source)
        self.assertIn("adevtool-version-check.mk", source)
        self.assertNotIn("phase1_provenance", source)
        self.assertNotIn("release-build.sh", source)
        self.assertNotRegex(source, r"\b(?:curl|wget|docker|git clean|git reset|rm -rf)\b")

    def test_runner_invokes_builder_action_not_release_wrapper(self):
        config = Config(adevtool_commit="1" * 40)
        command = vendor.payload(config)
        self.assertEqual("/wonad/android/platform/generate-frankel-vendor.sh", command[-1])
        self.assertNotIn("release-build.sh", " ".join(command))
        self.assertNotIn("clean-vendor-cache", " ".join(command))

    def test_external_bridge_is_default_read_only_and_fresh_generation_five(self):
        source = BRIDGE.read_text()
        self.assertIn("set -- --check-only", source)
        self.assertIn("--check-only|--run", source)
        self.assertNotIn("--create-only", source)
        self.assertNotRegex(source, r"\bdocker\b")
        self.assertIn("phase1-frankel-vendor-cache-work-20261012-4", source)
        self.assertIn("phase1-frankel-baseline-vendor-cache-20261012-5.result.json", source)
        self.assertIn("wonad-phase1-frankel-vendor-2026100600-005", source)
        self.assertEqual(len(vendor.REQUIRED_REPO_INPUTS), source.count("--repo-input "))
        self.assertEqual(len(vendor.REQUIRED_SOURCE_INPUTS), source.count("--source-input "))
        repo_rows = dict(re.findall(r"--repo-input ([^= ]+)=([0-9a-f]{64})", source))
        self.assertEqual(set(vendor.REQUIRED_REPO_INPUTS), set(repo_rows))
        for relative, digest in repo_rows.items():
            if relative == "android/tools/run_frankel_vendor.py":
                self.assertEqual(
                    "ec99cec9408f51b551ae59933a5d3f39ec77421bc646fde2c0229c0a463c0762",
                    digest, "generation 5 must retain its reviewed runner")
            else:
                self.assertEqual(digest, sha(ROOT / relative), relative)

    def test_external_bridge_source_pins_match_the_explicit_checkout(self):
        source = BRIDGE.read_text()
        root_match = re.search(r"--source (\S+)", source)
        self.assertIsNotNone(root_match)
        checkout = Path(root_match.group(1))
        rows = dict(re.findall(r"--source-input ([^= ]+)=([0-9a-f]{64})", source))
        self.assertEqual(set(vendor.REQUIRED_SOURCE_INPUTS), set(rows))
        for relative, digest in rows.items():
            self.assertEqual(digest, sha(checkout / relative), relative)

    def test_generation_six_bridge_retains_its_original_runner(self):
        source = BRIDGE6.read_text()
        self.assertIn("set -- --check-only", source)
        self.assertIn("phase1-frankel-vendor-cache-work-20261012-5", source)
        self.assertIn("phase1-frankel-baseline-vendor-cache-20261012-6.result.json", source)
        self.assertIn("wonad-phase1-frankel-vendor-2026100600-006", source)
        self.assertNotIn("phase1-frankel-vendor-cache-work-20261012-4", source)
        repo_rows = dict(re.findall(r"--repo-input ([^= ]+)=([0-9a-f]{64})", source))
        source_rows = dict(re.findall(r"--source-input ([^= ]+)=([0-9a-f]{64})", source))
        self.assertEqual(set(vendor.REQUIRED_REPO_INPUTS), set(repo_rows))
        self.assertEqual(set(vendor.REQUIRED_SOURCE_INPUTS), set(source_rows))
        for relative, digest in repo_rows.items():
            if relative == "android/tools/run_frankel_vendor.py":
                self.assertEqual(
                    "35b2b23b94e9c29a87b21a87c3ff3f5a8bfb003ac797efc2040c524932ff55fc",
                    digest, "generation 6 must retain its failed noexec profile")
            else:
                self.assertEqual(digest, sha(ROOT / relative), relative)
        checkout = Path(re.search(r"--source (\S+)", source).group(1))
        for relative, digest in source_rows.items():
            self.assertEqual(digest, sha(checkout / relative), relative)

    def test_generation_six_bridge_parser_is_side_effect_free_after_execution(self):
        arguments = self.bridge_arguments(BRIDGE6)
        paths = [Path(arguments[arguments.index(flag) + 1]) for flag in
                 ("--work", "--log", "--preflight", "--result", "--attempt-lock")]
        before = [path.lstat() if os.path.lexists(path) else None for path in paths]
        parsed = vendor.config_from_args(
            vendor.build_parser().parse_args(arguments))
        self.assertFalse(parsed.run)
        self.assertEqual("wonad-phase1-frankel-vendor-2026100600-006", parsed.container)
        after = [path.lstat() if os.path.lexists(path) else None for path in paths]
        self.assertEqual(before, after)

    def test_generation_seven_bridge_pins_current_runner_and_fresh_names(self):
        source = BRIDGE7.read_text()
        self.assertIn("set -- --check-only", source)
        self.assertIn("phase1-frankel-vendor-cache-work-20261012-6", source)
        self.assertIn("phase1-frankel-baseline-vendor-cache-20261012-7.result.json", source)
        self.assertIn("wonad-phase1-frankel-vendor-2026100600-007", source)
        self.assertNotIn("phase1-frankel-baseline-vendor-cache-20261012-6.", source)
        repo_rows = dict(re.findall(r"--repo-input ([^= ]+)=([0-9a-f]{64})", source))
        source_rows = dict(re.findall(r"--source-input ([^= ]+)=([0-9a-f]{64})", source))
        self.assertEqual(set(vendor.REQUIRED_REPO_INPUTS), set(repo_rows))
        self.assertEqual(set(vendor.REQUIRED_SOURCE_INPUTS), set(source_rows))
        for relative, digest in repo_rows.items():
            self.assertEqual(digest, sha(ROOT / relative), relative)
        checkout = Path(re.search(r"--source (\S+)", source).group(1))
        for relative, digest in source_rows.items():
            self.assertEqual(digest, sha(checkout / relative), relative)

    def test_generation_seven_bridge_parser_has_no_side_effects(self):
        arguments = self.bridge_arguments(BRIDGE7)
        paths = [Path(arguments[arguments.index(flag) + 1]) for flag in
                 ("--work", "--log", "--preflight", "--result", "--attempt-lock")]
        before = [path.lstat() if os.path.lexists(path) else None for path in paths]
        parsed = vendor.config_from_args(vendor.build_parser().parse_args(arguments))
        self.assertFalse(parsed.run)
        self.assertEqual("wonad-phase1-frankel-vendor-2026100600-007", parsed.container)
        self.assertEqual(before,
                         [path.lstat() if os.path.lexists(path) else None for path in paths])

    def test_external_bridge_is_accepted_by_the_real_parser_without_side_effects(self):
        arguments = self.bridge_arguments()
        parsed = vendor.config_from_args(vendor.build_parser().parse_args(arguments))
        self.assertFalse(parsed.run)
        self.assertEqual("wonad-phase1-frankel-vendor-2026100600-005", parsed.container)
        for path in (parsed.work, parsed.log, parsed.preflight, parsed.result,
                     parsed.attempt_lock):
            self.assertFalse(os.path.lexists(path), path)

    def test_actual_adevtool_dependency_inventory_is_fourteen(self):
        path = Path("/u/elric/tree/wonad-grapheneos-2026100600-frankel-baseline-1") / \
            "vendor/adevtool/src/config/paths.ts"
        if not path.exists():
            self.skipTest("pinned Frankel source is unavailable")
        self.assertEqual(vendor.EXPECTED_ADEVTOOL_TARGETS,
                         vendor.reviewed_adevtool_targets(path.read_bytes()))
        self.assertEqual(14, len(vendor.EXPECTED_ADEVTOOL_TARGETS))

    def test_product_and_out_are_not_misreported_as_targets(self):
        payload = b"""let knownPrograms = [
          'aapt2', 'apksigner', 'aprotoc', 'arsclib', 'debugfs', 'dispol',
          'fsck.erofs', 'lpdump', 'lpunpack', 'lz4', 'ota_extractor',
          'simg2img', 'sqlite3', 'toybox',
        ]
        args: ['sdk_phone64_x86_64', outDir, ...knownPrograms]
        """
        self.assertEqual(14, len(vendor.reviewed_adevtool_targets(payload)))
        with self.assertRaisesRegex(vendor.Refusal, "target inventory"):
            vendor.reviewed_adevtool_targets(payload.replace(b"'toybox',", b"'toybox', 'extra',"))


class PinAndJsonTests(unittest.TestCase):
    def test_exact_pin_inventory(self):
        required = ("a", "b")
        value = vendor.parse_pin_rows(["a=" + "1" * 64, "b=" + "2" * 64], required, "test")
        self.assertEqual({"a", "b"}, set(value))
        for hostile in (["a=" + "1" * 64],
                        ["a=" + "1" * 64, "a=" + "2" * 64, "b=" + "2" * 64],
                        ["../a=" + "1" * 64, "b=" + "2" * 64],
                        ["a=true", "b=" + "2" * 64]):
            with self.subTest(hostile=hostile), self.assertRaises(vendor.Refusal):
                vendor.parse_pin_rows(hostile, required, "test")

    def test_duplicate_json_is_rejected(self):
        with self.assertRaisesRegex(vendor.Refusal, "Duplicate"):
            vendor.unique_json(b'{"a":1,"a":2}', "fixture")

    def test_capture_executes_the_captured_object(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "module.py"
            path.write_text("VALUE = 'reviewed'\n")
            payload, reference = vendor.capture_regular(path)
            path.write_text("VALUE = 'replacement'\n")
            module = vendor.load_captured_module(payload, path, "captured_test_module")
            self.assertEqual("reviewed", module.VALUE)
            self.assertNotEqual(reference["sha256"], sha(path))


class AdmissionTests(unittest.TestCase):
    def test_process_classifier_covers_builds_guests_and_qemu_kvm(self):
        rows = {
            "/usr/bin/qemu-kvm": "KVM guest",
            "/x/run_native_matrix.py": "native/GUI matrix",
            "/x/build_native_successor.py": "APK successor build",
            "/x/phase1_emulator_client_packet.py": "emulator packet build",
            "/x/run_frankel_vendor.py": "Frankel vendor preparation",
            "/x/freeze-phase1-native-matrix-a.sh": "native/GUI matrix wrapper",
            "/x/phase1_frankel_vendor_cache_driver_20261011_4.py":
                "Frankel vendor preparation wrapper",
            "/x/prepare-phase1-frankel-vendor-cache-20261012-5.sh":
                "Frankel vendor preparation wrapper",
        }
        for command, expected in rows.items():
            with self.subTest(command=command):
                self.assertEqual(expected, vendor.process_kind([command]))
        self.assertEqual("Frankel vendor preparation wrapper",
                         vendor.process_kind(["/bin/bash", "/x/release-build.sh",
                                              "prepare-vendor"]))
        self.assertEqual("Gradle daemon", vendor.process_kind([
            "/usr/lib/jvm/java/bin/java", "-Xmx2g",
            "org.gradle.launcher.daemon.bootstrap.GradleDaemon", "8.11.1"]))
        self.assertEqual("Kotlin compiler daemon", vendor.process_kind([
            "/usr/lib/jvm/java/bin/java", "-Xmx2g",
            "org.jetbrains.kotlin.daemon.KotlinCompileDaemon",
            "--daemon-runFilesPath", "/tmp/kotlin-daemon"]))

    def test_oversized_and_malformed_process_evidence_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            proc = Path(root)
            pid = proc / "42"
            pid.mkdir()
            (pid / "stat").write_text("42 (x) S 1 0 0\n")
            (pid / "cmdline").write_bytes(b"a" * (vendor.MAX_CMDLINE + 1))
            with self.assertRaisesRegex(vendor.Refusal, "exceeds"):
                vendor.live_process_lanes(proc, ignored=set())
            (pid / "cmdline").write_bytes(b"/usr/bin/qemu-kvm")
            with self.assertRaisesRegex(vendor.Refusal, "Malformed"):
                vendor.live_process_lanes(proc, ignored=set())

    def test_unreadable_process_error_is_not_skipped(self):
        with tempfile.TemporaryDirectory() as root:
            proc = Path(root)
            pid = proc / "42"
            pid.mkdir()
            with mock.patch.object(vendor, "_bounded_read", side_effect=PermissionError(13, "denied")):
                with self.assertRaisesRegex(vendor.Refusal, "Cannot authenticate"):
                    vendor.live_process_lanes(proc, ignored=set())

    def test_outcome_keeps_primary_failure_when_cleanup_also_fails(self):
        cleanup = RuntimeError("cleanup failed")
        self.assertEqual("failed_builder", vendor.outcome_status(17, None, cleanup))
        primary = RuntimeError("builder invocation failed")
        self.assertEqual("failed_exception", vendor.outcome_status(None, primary, cleanup))
        self.assertEqual("failed_cleanup", vendor.outcome_status(0, None, cleanup))

    def test_cleanup_never_races_a_created_or_running_container(self):
        self.assertTrue(vendor.source_cleanup_is_safe(False, None, False))
        self.assertFalse(vendor.source_cleanup_is_safe(True, None, False))
        self.assertTrue(vendor.source_cleanup_is_safe(True, "a" * 64, True))
        self.assertFalse(vendor.source_cleanup_is_safe(True, "a" * 64, False))
        self.assertFalse(vendor.source_cleanup_is_safe(True, "malformed", True))

    def test_attempt_lock_is_create_only_and_source_lock_is_exclusive(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "source"
            source.mkdir()
            lock = Path(root) / "attempt.json"
            config = Config(source=source, container="wonad-phase1-frankel-vendor-test")
            fd = vendor.acquire_lock(lock, config)
            try:
                with self.assertRaises(FileExistsError):
                    vendor.acquire_lock(lock, config)
            finally:
                os.close(fd)
            one = vendor.acquire_source_lock(source)
            try:
                with self.assertRaises(BlockingIOError):
                    vendor.acquire_source_lock(source)
            finally:
                os.close(one)

    def test_attempt_lock_open_object_must_remain_at_its_path(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "source"
            source.mkdir()
            lock = root / "attempt.json"
            config = Config(source=source, container="wonad-phase1-frankel-vendor-test")
            descriptor = vendor.acquire_lock(lock, config)
            try:
                reference = vendor.capture_open_regular(lock, descriptor)
                self.assertEqual(64, len(reference["sha256"]))
                lock.unlink()
                lock.write_text('{"replacement":true}\n')
                with self.assertRaisesRegex(
                        vendor.Refusal, "pathname changed|not one ordinary file"):
                    vendor.capture_open_regular(lock, descriptor)
            finally:
                os.close(descriptor)


class ExecutionLifecycleTests(unittest.TestCase):
    def test_unreadable_successful_create_result_never_enables_cleanup(self):
        with mocked_execution() as (config, _identities, clean_inodes, writes), \
                mock.patch.object(vendor, "docker_checked", return_value=b"\xff"):
            self.assertEqual(2, vendor.execute(config))
            self.assertEqual(1, len(clean_inodes))
            result = writes[config.result]
            self.assertIs(result["container"]["create_attempted"], True)
            self.assertIsNone(result["container"]["id"])
            self.assertIn("not proven stopped", result["cleanup"]["exception"]["message"])

    def test_postlaunch_source_replacement_skips_final_cleanup(self):
        identity = "c" * 64
        created = {"State": {"Status": "created", "ExitCode": 0,
                             "OOMKilled": False}}
        exited = {"State": {"Status": "exited", "ExitCode": 0,
                            "OOMKilled": False}}
        with mocked_execution() as (config, identities, clean_inodes, writes):
            original_inode = identities["source"]["inode"]

            def replace_source(*unused):
                config.source.rename(config.source.parent / "original-source")
                for relative in (".repo", "out", "vendor/adevtool"):
                    (config.source / relative).mkdir(parents=True, exist_ok=True)
                return 0

            with mock.patch.object(
                    vendor, "docker_checked", return_value=(identity + "\n").encode()), \
                    mock.patch.object(
                        vendor, "docker_inspect",
                        side_effect=[(created, b"created"), (exited, b"exited")]), \
                    mock.patch.object(vendor, "validate_container", return_value=True), \
                    mock.patch.object(vendor, "run_builder", side_effect=replace_source):
                self.assertEqual(2, vendor.execute(config))
            self.assertEqual([original_inode], clean_inodes)
            self.assertIn("identity changed",
                          writes[config.result]["cleanup"]["exception"]["message"])

    def test_successful_stopped_container_runs_both_cleanups(self):
        identity = "d" * 64
        created = {"State": {"Status": "created", "ExitCode": 0,
                             "OOMKilled": False}}
        exited = {"State": {"Status": "exited", "ExitCode": 0,
                            "OOMKilled": False}}
        with mocked_execution() as (config, identities, clean_inodes, writes), \
                mock.patch.object(
                    vendor, "docker_checked", return_value=(identity + "\n").encode()), \
                mock.patch.object(
                    vendor, "docker_inspect",
                    side_effect=[(created, b"created"), (exited, b"exited")]), \
                mock.patch.object(vendor, "validate_container", return_value=True), \
                mock.patch.object(vendor, "run_builder", return_value=0):
            self.assertEqual(0, vendor.execute(config))
            self.assertEqual([identities["source"]["inode"]] * 2, clean_inodes)
            result = writes[config.result]
            self.assertEqual("generated", result["status"])
            self.assertEqual(result["inputs"]["attempt_lock"]["initial"],
                             result["inputs"]["attempt_lock"]["final"])

    def test_source_directory_identity_is_bound_to_locked_root(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "source"
            for relative in (".repo", "out", "vendor/adevtool"):
                (source / relative).mkdir(parents=True, exist_ok=True)
            config = Config(source=source)
            expected = vendor.source_directory_identities(config)
            self.assertEqual(
                {"source", "repo_metadata", "out", "adevtool"}, set(expected))
            descriptor = vendor.acquire_source_lock(source)
            try:
                self.assertEqual(
                    expected,
                    vendor.require_source_directory_identities(
                        config, expected, descriptor))
                source.rename(root / "original-source")
                for relative in (".repo", "out", "vendor/adevtool"):
                    (source / relative).mkdir(parents=True, exist_ok=True)
                with self.assertRaisesRegex(vendor.Refusal, "identity changed"):
                    vendor.require_source_directory_identities(
                        config, expected, descriptor)
            finally:
                os.close(descriptor)


class DockerProfileTests(unittest.TestCase):
    def config(self, root):
        root = Path(root)
        return Config(
            source=root / "source", repo=root / "repo", work=root / "work",
            container="wonad-phase1-frankel-vendor-test-001",
            builder_image="sha256:" + "a" * 64, adevtool_commit="b" * 40,
        )

    def test_create_command_has_reviewed_bounds_and_three_binds(self):
        with tempfile.TemporaryDirectory() as root:
            config = self.config(root)
            command = vendor.create_command(config, "c" * 64)
            self.assertEqual(list(vendor.DOCKER) + ["create"], command[:4])
            self.assertIn("34359738368", command)
            self.assertEqual(2, command.count("34359738368"))
            self.assertIn("0-3", command)
            self.assertIn("2048", command)
            self.assertIn("no-new-privileges=true", command)
            self.assertIn("--read-only", command)
            self.assertEqual(3, command.count("--volume"))
            self.assertNotIn("/dev/kvm", command)
            self.assertEqual("bridge", command[command.index("--network") + 1])
            self.assertEqual("/tmp:rw,nosuid,nodev,exec,size=4294967296,mode=1777",
                             command[command.index("--tmpfs") + 1])

    def test_tmpfs_explicitly_allows_go_bootstrap_execution(self):
        self.assertEqual("rw,nosuid,nodev,exec,size=4294967296,mode=1777", vendor.TMPFS)
        self.assertNotIn("noexec", vendor.TMPFS.split(","))

    def info(self, config, mounts=None):
        identity = "d" * 64
        nonce = "e" * 64
        binds = [f"{config.source}:/grapheneos:rw", f"{config.repo}:/wonad:ro",
                 f"{config.work}:/adevtool-images:rw"]
        host = {"Memory": vendor.MEMORY, "MemorySwap": vendor.MEMORY,
                "NanoCpus": 4_000_000_000, "CpusetCpus": "0-3", "PidsLimit": 2048,
                "ReadonlyRootfs": True, "NetworkMode": "bridge", "Privileged": False,
                "AutoRemove": False, "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "Tmpfs": {"/tmp": vendor.TMPFS}, "CapDrop": ["ALL"],
                "SecurityOpt": ["label=disable", "no-new-privileges=true"], "Binds": binds,
                "IpcMode": "private", "PidMode": "", "UTSMode": "", "UsernsMode": ""}
        config_row = {"Image": config.builder_image, "User": "1000:1000",
                      "WorkingDir": "/grapheneos", "Entrypoint": ["/usr/bin/env"],
                      "Cmd": vendor.payload(config), "Labels": {
                          "org.wonad.phase1.vendor-attempt": nonce,
                          "org.wonad.phase1.vendor-mode": "prepare"},
                      "AttachStdin": False, "AttachStdout": True, "AttachStderr": True,
                      "OpenStdin": False, "StdinOnce": False, "Tty": False}
        rows = list(vendor._expected_mounts(config).values()) if mounts is None else mounts
        return identity, nonce, {"Id": identity, "Name": "/" + config.container,
            "Image": config.builder_image, "Path": "/usr/bin/env", "Args": vendor.payload(config),
            "Config": config_row, "HostConfig": host,
            "Mounts": rows, "State": {"Status": "created", "Running": False,
                "Paused": False, "Restarting": False, "Dead": False, "OOMKilled": False,
                "Pid": 0, "ExitCode": 0, "StartedAt": "0001-01-01T00:00:00Z",
                "FinishedAt": "0001-01-01T00:00:00Z"}}

    def test_mount_order_is_not_semantic_but_rows_are_exact(self):
        with tempfile.TemporaryDirectory() as root:
            config = self.config(root)
            identity, nonce, info = self.info(config)
            info["Mounts"].reverse()
            self.assertTrue(vendor.validate_container(info, config, identity, nonce, stopped=False))
            for mutation in ("duplicate", "mode", "source", "destination", "propagation", "rw"):
                hostile = json.loads(json.dumps(info))
                if mutation == "duplicate":
                    hostile["Mounts"].append(dict(hostile["Mounts"][0]))
                else:
                    row = hostile["Mounts"][0]
                    key = {"mode": "Mode", "source": "Source", "destination": "Destination",
                           "propagation": "Propagation", "rw": "RW"}[mutation]
                    row[key] = "wrong" if key != "RW" else not row[key]
                with self.subTest(mutation=mutation), self.assertRaises(vendor.Refusal):
                    vendor.validate_container(hostile, config, identity, nonce, stopped=False)

    def test_implicit_or_explicit_noexec_container_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            config = self.config(root)
            identity, nonce, info = self.info(config)
            self.assertTrue(vendor.validate_container(info, config, identity, nonce, stopped=False))
            for options in ("rw,nosuid,nodev,size=4294967296,mode=1777",
                            "rw,nosuid,nodev,noexec,size=4294967296,mode=1777"):
                hostile = json.loads(json.dumps(info))
                hostile["HostConfig"]["Tmpfs"] = {"/tmp": options}
                with self.subTest(options=options), self.assertRaisesRegex(
                        vendor.Refusal, "Tmpfs"):
                    vendor.validate_container(hostile, config, identity, nonce, stopped=False)


class ReflinkAndOutputTests(unittest.TestCase):
    def test_ficlone_failure_has_no_copy_fallback(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            cache = root / "cache"
            cache.mkdir()
            archive = cache / "factory.zip"
            archive.write_bytes(b"authenticated bytes")
            config = Config(cache=cache, archive_name=archive.name,
                            archive_bytes=archive.stat().st_size,
                            archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                            work=root / "work")
            with mock.patch.object(vendor, "validate_cache", return_value={}), \
                    self.assertRaises(OSError):
                vendor.prepare_reflink(config, ioctl_fn=mock.Mock(side_effect=OSError(95, "no clone")))
            destination = config.work / archive.name
            self.assertTrue(destination.exists())
            self.assertEqual(0, destination.stat().st_size)

    def test_reflink_records_receipt_hash_without_claiming_future_recheck(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            cache = root / "cache"
            cache.mkdir()
            archive = cache / "factory.zip"
            archive.write_bytes(b"small synthetic archive")
            config = Config(cache=cache, archive_name=archive.name,
                            archive_bytes=archive.stat().st_size,
                            archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                            work=root / "work")

            def synthetic_clone(destination, operation, source):
                self.assertEqual(vendor.FICLONE, operation)
                os.lseek(source, 0, os.SEEK_SET)
                os.write(destination, os.read(source, config.archive_bytes))

            with mock.patch.object(vendor, "validate_cache", return_value={}):
                evidence = vendor.prepare_reflink(config, ioctl_fn=synthetic_clone)
            row = evidence["archive"]
            self.assertNotIn("sha256_rechecked_by_adevtool", row)
            self.assertEqual(config.archive_sha256,
                             row["sha256_from_authenticated_receipt"])
            self.assertIs(row["adevtool_consumption_and_recheck_pending"], True)

    def test_generated_output_checks_exact_version_guard(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root)
            output = source / "vendor/google_devices/frankel"
            output.mkdir(parents=True)
            for name in ("Android.mk", "AndroidProducts.mk", "BoardConfig.mk", "README.md",
                         "frankel.mk"):
                (output / name).write_text(name)
            for name in ("proprietary", "firmware"):
                (output / name).mkdir()
            commit = "a" * 40
            (output / "adevtool-version-check.mk").write_text(
                f"ifneq ($(shell git -C vendor/adevtool rev-parse HEAD),{commit})\n"
                "  $(error frankel vendor module is outdated. Run `adevtool generate-all -d frankel` to update it)\n"
                "endif")
            config = Config(source=source, adevtool_commit=commit)
            self.assertEqual(commit, vendor.verify_generated_vendor(config)["adevtool_version_commit"])
            (output / "adevtool-version-check.mk").write_text("wrong")
            with self.assertRaisesRegex(vendor.Refusal, "version guard"):
                vendor.verify_generated_vendor(config)


if __name__ == "__main__":
    unittest.main()
