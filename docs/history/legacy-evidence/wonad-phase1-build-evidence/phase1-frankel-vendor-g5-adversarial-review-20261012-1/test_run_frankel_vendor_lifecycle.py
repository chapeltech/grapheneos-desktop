"""Adversarial host-only lifecycle probes for frozen run_frankel_vendor.py.

These tests intentionally state the desired fail-closed contracts.  A failing
test is retained evidence of a concrete gap; this file never invokes Docker,
the real checkout cleanup, FICLONE, or the factory archive.
"""
from contextlib import ExitStack
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock


TOOL = Path("/u/elric/tree/wonad/android/tools/run_frankel_vendor.py")
TOOL_SHA256 = "ec99cec9408f51b551ae59933a5d3f39ec77421bc646fde2c0229c0a463c0762"
assert hashlib.sha256(TOOL.read_bytes()).hexdigest() == TOOL_SHA256
SPEC = importlib.util.spec_from_file_location("frozen_run_frankel_vendor", TOOL)
vendor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vendor)


class ExecuteFixture:
    """Replace every external seam while retaining execute()'s lifecycle."""

    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.repo = self.root / "repo"
        self.source.mkdir()
        self.repo.mkdir()
        self.config = types.SimpleNamespace(
            run=True,
            source=self.source,
            repo=self.repo,
            work=self.root / "work",
            log=self.root / "run.log",
            preflight=self.root / "preflight.json",
            result=self.root / "result.json",
            attempt_lock=self.root / "attempt.json",
            container="wonad-phase1-frankel-vendor-adversarial",
            repo_inputs={},
        )
        self.clean_inodes = []
        self.writes = {}
        self.provenance = types.SimpleNamespace(clean_vendor_cache=self.cleanup)
        self.modules = (self.provenance, object(), object(), object(), object())
        self.stack = ExitStack()

    def cleanup(self, path):
        self.clean_inodes.append(Path(path).lstat().st_ino)
        return ["synthetic-cache"]

    def write(self, path, value):
        self.writes[Path(path)] = value
        return {"path": str(path), "sha256": "0" * 64, "bytes": 0}

    @staticmethod
    def capture(path, maximum=vendor.MAX_JSON):
        return b"", {"path": str(path), "sha256": "0" * 64, "bytes": 0}

    def __enter__(self):
        patch = self.stack.enter_context
        patch(mock.patch.object(
            vendor, "initial_inputs",
            return_value=({}, {"android/grapheneos.lock.json": b"{}\n"}, {})))
        patch(mock.patch.object(vendor, "load_authority_modules", return_value=self.modules))
        patch(mock.patch.object(vendor, "docker_authority", return_value={}))
        patch(mock.patch.object(vendor, "source_authority", return_value={"same": True}))
        patch(mock.patch.object(vendor, "missing_container", return_value=True))
        patch(mock.patch.object(vendor, "resources", return_value={"clear": True}))
        patch(mock.patch.object(vendor, "source_caches_absent", return_value={}))
        patch(mock.patch.object(vendor, "prepare_reflink", return_value={"clone": True}))
        patch(mock.patch.object(vendor, "captured_inventory", return_value=({}, {})))
        patch(mock.patch.object(vendor, "validate_cache", return_value={}))
        patch(mock.patch.object(vendor, "create_command",
                                return_value=[*vendor.DOCKER, "create", "synthetic"]))
        patch(mock.patch.object(vendor, "write_new", side_effect=self.write))
        patch(mock.patch.object(vendor, "capture_regular", side_effect=self.capture))
        patch(mock.patch.object(vendor, "verify_generated_vendor", return_value={"ok": True}))
        return self

    def __exit__(self, *exc):
        self.stack.close()
        self.temporary.cleanup()


def state(status, exit_code=0):
    return {"State": {"Status": status, "ExitCode": exit_code, "OOMKilled": False}}


class ExistingSafeBehavior(unittest.TestCase):
    def test_ascii_malformed_create_id_never_cleans_after_create_attempt(self):
        with ExecuteFixture() as fixture, \
                mock.patch.object(vendor, "docker_checked", return_value=b"malformed-id\n"), \
                mock.patch.object(vendor, "docker_inspect",
                                  side_effect=vendor.Refusal("unknown created identity")):
            self.assertEqual(2, vendor.execute(fixture.config))
            self.assertEqual(1, len(fixture.clean_inodes))

    def test_interrupted_start_with_live_container_preserves_primary_and_skips_cleanup(self):
        identity = "a" * 64
        rows = [(state("created"), b"created"), (state("running"), b"running")]

        def validate(info, config, actual, nonce, *, stopped):
            if stopped:
                raise vendor.Refusal("container is still running")
            return True

        with ExecuteFixture() as fixture, \
                mock.patch.object(vendor, "docker_checked", return_value=(identity + "\n").encode()), \
                mock.patch.object(vendor, "docker_inspect", side_effect=rows), \
                mock.patch.object(vendor, "validate_container", side_effect=validate), \
                mock.patch.object(vendor, "run_builder", side_effect=KeyboardInterrupt("stop")):
            with self.assertRaises(KeyboardInterrupt) as raised:
                vendor.execute(fixture.config)
            self.assertEqual("stop", str(raised.exception))
            self.assertEqual(1, len(fixture.clean_inodes))
            result = fixture.writes[fixture.config.result]
            self.assertEqual("KeyboardInterrupt", result["primary"]["exception"]["class"])
            self.assertEqual("Refusal", result["container"]["stop_proof_exception"]["class"])

    def test_stop_proof_error_does_not_replace_original_failure(self):
        identity = "b" * 64
        with ExecuteFixture() as fixture, \
                mock.patch.object(vendor, "docker_checked", return_value=(identity + "\n").encode()), \
                mock.patch.object(vendor, "docker_inspect",
                                  side_effect=[(state("created"), b"created"),
                                               RuntimeError("stop-proof")]), \
                mock.patch.object(vendor, "validate_container", return_value=True), \
                mock.patch.object(vendor, "run_builder", side_effect=RuntimeError("primary")):
            self.assertEqual(2, vendor.execute(fixture.config))
            self.assertEqual(1, len(fixture.clean_inodes))
            result = fixture.writes[fixture.config.result]
            self.assertEqual("primary", result["primary"]["exception"]["message"])
            self.assertEqual("stop-proof",
                             result["container"]["stop_proof_exception"]["message"])


class ConfirmedGaps(unittest.TestCase):
    def test_non_utf8_successful_create_output_must_not_be_treated_as_precreate(self):
        """The daemon may create a container before client output decoding fails."""
        with ExecuteFixture() as fixture, \
                mock.patch.object(vendor, "docker_checked", return_value=b"\xff"):
            self.assertEqual(2, vendor.execute(fixture.config))
            # Desired: only the pre-create cleanup.  Current frozen code performs
            # a second cleanup because identity stayed None after decode failed.
            self.assertEqual(1, len(fixture.clean_inodes))

    def test_postlaunch_source_path_replacement_must_not_redirect_cleanup(self):
        identity = "c" * 64
        with ExecuteFixture() as fixture:
            original_inode = fixture.source.lstat().st_ino

            def run(*unused):
                fixture.source.rename(fixture.root / "original-source")
                fixture.source.mkdir()
                return 0

            rows = [(state("created"), b"created"), (state("exited"), b"exited")]
            with mock.patch.object(vendor, "docker_checked",
                                   return_value=(identity + "\n").encode()), \
                    mock.patch.object(vendor, "docker_inspect", side_effect=rows), \
                    mock.patch.object(vendor, "validate_container", return_value=True), \
                    mock.patch.object(vendor, "run_builder", side_effect=run):
                self.assertEqual(0, vendor.execute(fixture.config))
            # Desired: cleanup is anchored to the locked original directory.
            # Current frozen code calls cleanup on the replacement pathname.
            self.assertEqual([original_inode, original_inode], fixture.clean_inodes)

    def test_attempt_lock_path_replacement_must_not_be_accepted_as_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "source"
            source.mkdir()
            path = root / "attempt.json"
            config = types.SimpleNamespace(
                source=source, container="wonad-phase1-frankel-vendor-adversarial")
            descriptor = vendor.acquire_lock(path, config)
            try:
                expected = hashlib.sha256(path.read_bytes()).hexdigest()
                path.unlink()
                path.write_text('{"replacement":true}\n')
                observed = vendor.capture_regular(path)[1]["sha256"]
                # execute() later captures the pathname, not the still-open lock fd.
                self.assertEqual(expected, observed)
            finally:
                os.close(descriptor)

    def test_gradle_and_kotlin_daemons_are_competing_build_lanes(self):
        commands = (
            ["/usr/lib/jvm/java/bin/java", "-Xmx2g",
             "org.gradle.launcher.daemon.bootstrap.GradleDaemon", "8.11.1"],
            ["/usr/lib/jvm/java/bin/java", "-Xmx2g",
             "org.jetbrains.kotlin.daemon.KotlinCompileDaemon",
             "--daemon-runFilesPath", "/tmp/kotlin-daemon"],
        )
        for argv in commands:
            with self.subTest(argv=argv):
                self.assertIsNotNone(vendor.process_kind(argv))


if __name__ == "__main__":
    unittest.main()
