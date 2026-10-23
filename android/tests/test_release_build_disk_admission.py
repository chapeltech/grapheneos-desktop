"""Source-bound Frankel disk-admission controls; all Docker/build work is mocked."""
import copy
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ANDROID = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_disk_launcher_tested", ANDROID / "tools/run_release_build.py")
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


class DiskAdmission(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="frankel-disk-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "source"
        (self.source / ".repo").mkdir(parents=True)
        self.selected = self.root / "selected-out-fs"
        self.selected.mkdir()
        self.docker_root = self.root / "actual-docker-root"
        self.docker_root.mkdir()
        self.args = SimpleNamespace(
            source=self.source, out=self.selected / "fresh-out", log=self.root / "build.log",
            evidence=self.root / "execution.json", builder_record=self.root / "builder.json",
            source_record=self.root / "source.json", build_number="2026101000",
            build_datetime="1791288000", jobs=6, highmem_jobs=1,
            container_name="wonad-phase1-frankel-release-2026101000-disk-unit")
        self.docker_identity = {"daemon": {"root_dir": str(self.docker_root)},
                                "fixture": "read-only Docker identity"}

    def capacity(self, out_free=None, docker_free=None):
        out_free = launcher.DISK_ADMISSION["out_free_bytes"] if out_free is None else out_free
        docker_free = (launcher.DISK_ADMISSION["docker_free_bytes"]
                       if docker_free is None else docker_free)
        visited = []
        def observe(descriptor):
            checked = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
            visited.append(checked)
            self.assertIn(checked, (self.selected, self.docker_root))
            available = out_free if checked == self.selected else docker_free
            return SimpleNamespace(f_bavail=available // 4096, f_frsize=4096)
        return observe, visited

    def preparation_seams(self, stack):
        stack.enter_context(patch.object(launcher, "validate_inherited_environment"))
        stack.enter_context(patch.object(launcher, "docker_environment", return_value={}))
        stack.enter_context(patch.object(launcher, "docker_host_identity",
                                         return_value=self.docker_identity))
        fresh = stack.enter_context(patch.object(launcher, "require_fresh_container"))
        provenance = stack.enter_context(patch.object(
            launcher, "load_provenance", return_value=(
                {"fixture": "builder"}, {"sha256": "1" * 64, "size": 1},
                {}, {"sha256": "2" * 64, "size": 1})))
        stack.enter_context(patch.object(launcher, "verify_local_builder"))
        return fresh, provenance

    def evidence(self):
        observe, _ = self.capacity()
        with patch.object(launcher.os, "fstatvfs", side_effect=observe):
            first = launcher.observe_host_disk_admission(self.selected, self.docker_root)
            second = launcher.observe_host_disk_admission(
                self.selected, self.docker_root, expected=first)
        return {"before_source_audit": first, "before_container_create": second}

    def test_explicit_planning_thresholds_are_not_frankel_thresholds(self):
        self.assertEqual({"out_free_bytes": 128 * 1024**3,
                          "docker_free_bytes": 16 * 1024**3}, launcher.DISK_ADMISSION)
        self.assertEqual(2, launcher.SCHEMA)

    def test_exact_selected_parent_and_actual_docker_root_are_checked_independently(self):
        observe, visited = self.capacity()
        with patch.object(launcher.os, "fstatvfs", side_effect=observe):
            result = launcher.observe_host_disk_admission(self.selected, self.docker_root)
        self.assertEqual([self.selected, self.docker_root], visited)
        self.assertNotIn(self.source, visited)
        self.assertEqual(str(self.selected), result["filesystems"]["out_parent"]["identity"]["path"])
        self.assertEqual(str(self.docker_root), result["filesystems"]["docker_root"]["identity"]["path"])
        self.assertEqual(launcher.DISK_ADMISSION["out_free_bytes"],
                         result["filesystems"]["out_parent"]["available_bytes"])

    def test_missing_out_capacity_fails_before_mkdir_source_audit_or_container(self):
        # Even combined mocked capacities exceed 128 GiB: no cross-FS summing.
        observe, visited = self.capacity(96 * launcher.GIB, 64 * launcher.GIB)
        with ExitStack() as stack:
            fresh, provenance = self.preparation_seams(stack)
            stack.enter_context(patch.object(launcher.os, "fstatvfs", side_effect=observe))
            audit = stack.enter_context(patch.object(launcher, "verify_source_freeze"))
            create = stack.enter_context(patch.object(launcher, "create_container"))
            start = stack.enter_context(patch.object(launcher, "start_container"))
            with self.assertRaisesRegex(launcher.ReleaseBuildError, "Insufficient OUT_DIR parent"):
                launcher.run_build(self.args)
        self.assertEqual([self.selected], visited)
        for seam in (fresh, provenance, audit, create, start):
            seam.assert_not_called()
        self.assertFalse(self.args.out.exists())
        self.assertFalse(self.args.evidence.exists())
        self.assertFalse(self.args.evidence.with_name("execution.json.preflight.json").exists())

    def test_missing_docker_capacity_is_not_hidden_by_large_out_filesystem(self):
        observe, visited = self.capacity(256 * launcher.GIB, 0)
        with ExitStack() as stack:
            self.preparation_seams(stack)
            stack.enter_context(patch.object(launcher.os, "fstatvfs", side_effect=observe))
            create = stack.enter_context(patch.object(launcher, "create_container"))
            with self.assertRaisesRegex(launcher.ReleaseBuildError, "Insufficient Docker root"):
                launcher.run_build(self.args)
        create.assert_not_called()
        self.assertFalse(self.args.out.exists())
        self.assertEqual([self.selected, self.docker_root], visited)

    def test_failed_statvfs_is_not_a_capacity_fallback(self):
        with ExitStack() as stack:
            self.preparation_seams(stack)
            stack.enter_context(patch.object(launcher.os, "fstatvfs",
                                             side_effect=OSError("fixture statvfs failure")))
            create = stack.enter_context(patch.object(launcher, "create_container"))
            with self.assertRaisesRegex(launcher.ReleaseBuildError, "Cannot observe OUT_DIR parent"):
                launcher.run_build(self.args)
        create.assert_not_called()
        self.assertFalse(self.args.out.exists())

    def test_invalid_filesystem_values_fail_closed(self):
        for available, fragment in ((True, 4096), (-1, 4096), (1, 0), (1, True), (1, 4096.0)):
            with self.subTest(available=available, fragment=fragment), \
                    patch.object(launcher.os, "fstatvfs", return_value=
                                 SimpleNamespace(f_bavail=available, f_frsize=fragment)), \
                    self.assertRaisesRegex(launcher.ReleaseBuildError, "Invalid OUT_DIR parent"):
                launcher.filesystem_disk_observation(self.selected, "OUT_DIR parent", 1)

    def test_symlink_or_noncanonical_docker_path_is_rejected_before_capacity_read(self):
        alias = self.root / "docker-alias"
        alias.symlink_to(self.docker_root, target_is_directory=True)
        for path in (alias, self.docker_root / "..", Path("relative-docker-root")):
            with self.subTest(path=path), patch.object(launcher.os, "fstatvfs") as observe, \
                    self.assertRaises(launcher.ReleaseBuildError):
                launcher.filesystem_disk_observation(path, "Docker root", 1)
            observe.assert_not_called()

    def test_identity_change_after_initial_admission_is_rejected(self):
        expected = self.evidence()["before_source_audit"]
        expected["filesystems"]["docker_root"]["identity"]["inode"] += 1
        observe, _ = self.capacity()
        with patch.object(launcher.os, "fstatvfs", side_effect=observe), \
                self.assertRaisesRegex(launcher.ReleaseBuildError, "identity changed"):
            launcher.observe_host_disk_admission(self.selected, self.docker_root, expected=expected)

    def test_space_loss_during_source_audit_stops_before_container_and_keeps_preflight(self):
        observe, visited = self.capacity()
        def capacity_loss(descriptor):
            result = observe(descriptor)
            if len(visited) == 3:
                result.f_bavail -= 1
            return result
        with ExitStack() as stack:
            self.preparation_seams(stack)
            stack.enter_context(patch.object(launcher.os, "fstatvfs", side_effect=capacity_loss))
            audit = stack.enter_context(patch.object(launcher, "verify_source_freeze", return_value={}))
            create = stack.enter_context(patch.object(launcher, "create_container"))
            start = stack.enter_context(patch.object(launcher, "start_container"))
            with self.assertRaisesRegex(launcher.ReleaseBuildError, "Insufficient OUT_DIR parent"):
                launcher.run_build(self.args)
        audit.assert_called_once()
        create.assert_not_called()
        start.assert_not_called()
        self.assertEqual([self.selected, self.docker_root, self.selected], visited)
        preflight = self.args.evidence.with_name("execution.json.preflight.json")
        record = json.loads(preflight.read_text())
        self.assertEqual({"before_source_audit"}, set(record["host_disk_admission"]))
        self.assertFalse(self.args.evidence.exists())
        self.assertFalse(self.args.log.exists())

    def test_positive_recheck_reaches_only_mocked_create_after_both_admissions(self):
        observe, visited = self.capacity()
        reached = []
        def stop_before_docker(command, environment):
            reached.append((len(visited), command, environment))
            raise RuntimeError("fixture stops before any actual Docker create")
        with ExitStack() as stack:
            self.preparation_seams(stack)
            stack.enter_context(patch.object(launcher.os, "fstatvfs", side_effect=observe))
            audit = stack.enter_context(patch.object(launcher, "verify_source_freeze", return_value={}))
            stack.enter_context(patch.object(launcher, "create_container", side_effect=stop_before_docker))
            start = stack.enter_context(patch.object(launcher, "start_container"))
            with self.assertRaisesRegex(RuntimeError, "fixture stops"):
                launcher.run_build(self.args)
        audit.assert_called_once()
        start.assert_not_called()
        self.assertEqual([self.selected, self.docker_root] * 2, visited)
        self.assertEqual(4, reached[0][0])
        self.assertIn("create", reached[0][1])
        self.assertFalse(self.args.evidence.exists())

    def test_docker_space_loss_at_final_check_also_prevents_creation(self):
        observe, visited = self.capacity()
        def capacity_loss(descriptor):
            result = observe(descriptor)
            if len(visited) == 4:
                result.f_bavail -= 1
            return result
        with ExitStack() as stack:
            self.preparation_seams(stack)
            stack.enter_context(patch.object(launcher.os, "fstatvfs", side_effect=capacity_loss))
            stack.enter_context(patch.object(launcher, "verify_source_freeze", return_value={}))
            create = stack.enter_context(patch.object(launcher, "create_container"))
            with self.assertRaisesRegex(launcher.ReleaseBuildError, "Insufficient Docker root"):
                launcher.run_build(self.args)
        create.assert_not_called()
        self.assertEqual([self.selected, self.docker_root] * 2, visited)
        self.assertFalse(self.args.evidence.exists())

    def test_docker_daemon_root_change_during_source_audit_is_rejected(self):
        observe, _ = self.capacity()
        changed = copy.deepcopy(self.docker_identity)
        changed["daemon"]["root_dir"] = str(self.root)
        with ExitStack() as stack:
            self.preparation_seams(stack)
            stack.enter_context(patch.object(launcher, "docker_host_identity",
                                             side_effect=[self.docker_identity, changed]))
            stack.enter_context(patch.object(launcher.os, "fstatvfs", side_effect=observe))
            stack.enter_context(patch.object(launcher, "verify_source_freeze", return_value={}))
            create = stack.enter_context(patch.object(launcher, "create_container"))
            with self.assertRaisesRegex(launcher.ReleaseBuildError, "Local Docker identity changed"):
                launcher.run_build(self.args)
        create.assert_not_called()
        self.assertFalse(self.args.evidence.exists())

    def test_out_on_different_filesystem_than_admitted_parent_is_rejected(self):
        observe, _ = self.capacity()
        original = launcher.held_directory
        def different_out_device(path, label):
            descriptor, identity = original(path, label)
            if path == self.args.out:
                identity["device"] += 1
            return descriptor, identity
        with ExitStack() as stack:
            self.preparation_seams(stack)
            stack.enter_context(patch.object(launcher.os, "fstatvfs", side_effect=observe))
            stack.enter_context(patch.object(launcher, "verify_source_freeze", return_value={}))
            stack.enter_context(patch.object(launcher, "held_directory", side_effect=different_out_device))
            create = stack.enter_context(patch.object(launcher, "create_container"))
            with self.assertRaisesRegex(launcher.ReleaseBuildError, "OUT_DIR is not on its admitted parent"):
                launcher.run_build(self.args)
        create.assert_not_called()
        self.assertFalse(self.args.evidence.exists())

    def test_complete_independent_evidence_validation(self):
        evidence = self.evidence()
        self.assertIs(evidence, launcher.validate_host_disk_admission(
            evidence, self.args.out, self.docker_root))
        mutations = [
            lambda value: value.pop("before_source_audit"),
            lambda value: value.pop("before_container_create"),
            lambda value: value.update(extra=True),
            lambda value: value["before_container_create"].update(observed_monotonic_ns=0),
            lambda value: value["before_container_create"].update(
                observed_monotonic_ns=value["before_source_audit"]["observed_monotonic_ns"]),
            lambda value: value["before_container_create"]["filesystems"]["out_parent"]["identity"].update(path=str(self.source)),
            lambda value: value["before_container_create"]["filesystems"]["docker_root"]["identity"].update(path=str(self.root)),
            lambda value: value["before_container_create"]["filesystems"]["docker_root"]["identity"].update(inode=999),
            lambda value: value["before_container_create"]["filesystems"]["out_parent"]["identity"].update(uid=0),
            lambda value: value["before_container_create"]["filesystems"]["out_parent"].update(available_bytes=1),
            lambda value: value["before_container_create"]["filesystems"]["docker_root"].update(available_blocks=0, available_bytes=0),
            lambda value: value["before_container_create"]["filesystems"]["out_parent"].update(fragment_size=True),
        ]
        for mutate in mutations:
            candidate = copy.deepcopy(evidence)
            mutate(candidate)
            with self.subTest(mutation=mutate), self.assertRaises(launcher.ReleaseBuildError):
                launcher.validate_host_disk_admission(candidate, self.args.out, self.docker_root)


if __name__ == "__main__":
    unittest.main()
