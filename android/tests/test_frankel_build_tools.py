#!/usr/bin/env python3
"""Adversarial tests for the pinned Pixel 10 ARM64 build lane."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import ANY, Mock, patch
import zipfile

from android.tools import frankel_build_comparison as comparison
from android.tools import run_frankel_build as launcher


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class FrankelBuildToolTests(unittest.TestCase):
    NONCE = "1" * 64
    LOCALITY = "2" * 64

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.repo = self.root / "wonad"; self.repo.mkdir()
        self.source = self.root / "source"; self.source.mkdir(); (self.source / ".repo").mkdir()
        self.out = self.root / "out"
        self.log = self.root / "frankel.log"

    def resource_observation(self, monotonic_ns):
        fragment = 4096
        out_free = launcher.PIN["host_admission"]["out_free_bytes"]
        docker_free = launcher.PIN["host_admission"]["docker_free_bytes"]
        def filesystem(path, available):
            blocks = available // fragment
            return {
                "identity": launcher.directory_identity(path, "fixture resource path"),
                "available_blocks": blocks,
                "fragment_size": fragment,
                "available_bytes": blocks * fragment,
            }
        return {
            "observed_monotonic_ns": monotonic_ns,
            "memory": {
                "path": str(launcher.MEMINFO),
                "total_bytes": 64 * launcher.GIB,
                "available_bytes": 48 * launcher.GIB,
            },
            "filesystems": {
                "out": filesystem(self.out.parent, out_free),
                "docker": filesystem(self.root, docker_free),
            },
        }

    def resource_evidence(self, *, complete=False):
        value = {
            "schema": 1,
            "container": dict(launcher.PIN["container_resources"]),
            "admission": dict(launcher.PIN["host_admission"]),
            "before_source_audit": self.resource_observation(1),
        }
        if complete:
            value["before_docker_run"] = self.resource_observation(2)
        return value

    def test_launcher_uses_digest_env_i_no_network_exact_user_and_retains_container(self):
        name = "wonad-phase1-frankel-baseline-2026100600-unit"
        command = launcher.docker_command(
            self.source, self.out, name, attempt_nonce=self.NONCE,
            locality_sha256=self.LOCALITY)
        self.assertEqual(command[:26], [
            "/usr/bin/docker", "--host", "unix:///var/run/docker.sock",
            "run", "--name", name, "--platform", "linux/amd64",
            "--network", "none", "--user", "1000:1000", "--cap-drop", "ALL",
            "--security-opt", "label=disable",
            "--cpus", "6", "--memory", str(48 * launcher.GIB),
            "--memory-swap", str(48 * launcher.GIB),
            "--pids-limit", "4096", "--workdir", "/sources",
        ])
        self.assertNotIn("--rm", command)
        self.assertNotIn("--env", command)
        self.assertNotIn(launcher.PIN["builder_reference"], command)
        image_index = command.index(launcher.PIN["builder_digest"])
        self.assertEqual(command[image_index + 1], "-i")
        self.assertEqual(command[image_index + 1:], launcher.process_command())
        self.assertEqual(command[command.index("--entrypoint") + 1], "/usr/bin/env")
        self.assertIn(f"{self.source}:/sources:rw", command)
        self.assertIn(f"{self.out}:/sources/out:rw", command)
        self.assertIn(launcher.ATTEMPT_LABEL + "=" + self.NONCE, command)
        self.assertIn(launcher.LOCALITY_LABEL + "=" + self.LOCALITY, command)
        self.assertNotIn("OUT_DIR=", " ".join(command))
        self.assertNotIn("SOONG_NINJA", " ".join(command))
        self.assertIn("m -j6 vendorbootimage", launcher.INNER_COMMAND)

    def test_process_environment_is_complete_and_official_but_has_no_out_override(self):
        process = launcher.process_command()
        self.assertEqual(process[0], "-i")
        values = dict(row.split("=", 1) for row in process[1:1 + len(launcher.PROCESS_ENV)])
        self.assertEqual(values, launcher.PROCESS_ENV)
        self.assertEqual(values["OFFICIAL_BUILD"], "true")
        self.assertEqual(values["BUILD_NUMBER"], "2026100600")
        self.assertNotIn("OUT_DIR", values)
        self.assertEqual(process[-5:], ["/bin/bash", "--noprofile", "--norc", "-c",
                                       launcher.INNER_COMMAND])

    def test_host_resource_admission_rejects_missing_zero_and_insufficient_values(self):
        meminfo = self.root / "meminfo"
        block = 4096
        enough = 128 * launcher.GIB
        good_vfs = os.statvfs_result(
            (block, block, enough // block, enough // block, enough // block,
             0, 0, 0, 255, 255))

        for payload, message in (
                ("MemTotal: 67108864 kB\n", "unique MemTotal/MemAvailable"),
                ("MemTotal: 0 kB\nMemAvailable: 50331648 kB\n",
                 "MemTotal must be one positive"),
                ("MemTotal: 67108864 kB\nMemAvailable: 0 kB\n",
                 "MemAvailable must be one positive"),
                ("MemTotal: 67108864 kB\nMemAvailable: 41943039 kB\n",
                 "Insufficient actual host MemAvailable")):
            with self.subTest(payload=payload), patch.object(
                    launcher.os, "statvfs", return_value=good_vfs):
                meminfo.write_text(payload)
                with self.assertRaisesRegex(launcher.LauncherError, message):
                    launcher.observe_host_resources(
                        self.out.parent, self.root, meminfo_path=meminfo)

        meminfo.write_text(
            "MemTotal: 67108864 kB\nMemAvailable: 50331648 kB\n")
        zero = os.statvfs_result((block, block, 1, 1, 0, 0, 0, 0, 255, 255))
        with patch.object(launcher.os, "statvfs", return_value=zero), \
             self.assertRaisesRegex(launcher.LauncherError,
                                    "available blocks must be one positive"):
            launcher.observe_host_resources(
                self.out.parent, self.root, meminfo_path=meminfo)
        too_small = os.statvfs_result(
            (block, block, 1, 1,
             launcher.PIN["host_admission"]["out_free_bytes"] // block - 1,
             0, 0, 0, 255, 255))
        with patch.object(launcher.os, "statvfs", return_value=too_small), \
             self.assertRaisesRegex(launcher.LauncherError,
                                    "Insufficient OUT_DIR parent free space"):
            launcher.observe_host_resources(
                self.out.parent, self.root, meminfo_path=meminfo)
        docker_small = os.statvfs_result(
            (block, block, 1, 1,
             launcher.PIN["host_admission"]["docker_free_bytes"] // block - 1,
             0, 0, 0, 255, 255))
        with patch.object(launcher.os, "statvfs",
                          side_effect=[good_vfs, docker_small]), \
             self.assertRaisesRegex(launcher.LauncherError,
                                    "Insufficient Docker root free space"):
            launcher.observe_host_resources(
                self.out.parent, self.root, meminfo_path=meminfo)
        with patch.object(launcher.os, "statvfs", side_effect=FileNotFoundError("gone")), \
             self.assertRaisesRegex(launcher.LauncherError,
                                    "Cannot observe OUT_DIR parent free space"):
            launcher.observe_host_resources(
                self.out.parent, self.root, meminfo_path=meminfo)

    def test_prepare_admits_resources_before_the_expensive_source_audit(self):
        events = []
        docker_identity = {
            "daemon": {"root_dir": str(self.root)},
            "fixture": "local",
        }
        lock = {"builder": {"image_digest": launcher.PIN["builder_digest"]}}
        lock_ref = launcher.provenance.file_ref(launcher.LOCK)
        builder = {"image": {"id": launcher.PIN["builder_digest"]}}
        observation = self.resource_observation(1)

        def observe(*_arguments):
            events.append("admission")
            return observation

        def audit(*_arguments):
            events.append("source-audit")
            return {"stage": {"state": "absent"}}, {"siso": {}}

        with patch.object(launcher, "validate_inherited_environment"), \
             patch.object(launcher, "docker_environment", return_value={}), \
             patch.object(launcher, "docker_host_identity", return_value=docker_identity), \
             patch.object(launcher, "load_contract", return_value=(lock, lock_ref)), \
             patch.object(launcher, "require_fresh_container"), \
             patch.object(launcher, "observe_host_resources", side_effect=observe), \
             patch.object(launcher, "audit_source", side_effect=audit), \
             patch.object(launcher, "capture_builder", return_value=builder):
            record, *_unused = launcher.prepare(
                "baseline", self.source, self.out, self.log,
                "wonad-phase1-frankel-baseline-2026100600-resource", None)
        self.assertEqual(events, ["admission", "source-audit"])
        self.assertEqual(record["resources"], self.resource_evidence())

    def test_rejects_every_inherited_build_or_output_control(self):
        for name in sorted(launcher.FORBIDDEN_ENV_NAMES):
            with self.subTest(name=name), self.assertRaisesRegex(
                    launcher.LauncherError, name):
                launcher.validate_inherited_environment({name: "foreign"})
        for name in ("RBE_instance", "SOONG_FOO", "TARGET_FOO", "ANDROID_BUILD_TOP2",
                     "BUILD_BROKEN_FOO"):
            with self.subTest(name=name), self.assertRaisesRegex(
                    launcher.LauncherError, name):
                launcher.validate_inherited_environment({name: "foreign"})
        self.assertTrue(launcher.validate_inherited_environment(
            {"HOME": "/home/test", "PATH": "/usr/bin", "DISPLAY": ":0"}))
        for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "CONTAINER_HOST"):
            with self.subTest(name=name), self.assertRaisesRegex(
                    launcher.LauncherError, "Docker"):
                launcher.validate_inherited_environment({name: ""})
        fake = self.root / "bin"; fake.mkdir()
        candidate = fake / "docker"; candidate.write_text("#!/bin/sh\n"); candidate.chmod(0o755)
        with self.assertRaisesRegex(launcher.LauncherError, "PATH substitutes"):
            launcher.validate_inherited_environment({"PATH": str(fake)})

    def test_paths_must_be_fresh_canonical_external_and_non_symlinked(self):
        launcher.validate_paths(self.source, self.out, self.log, repo_root=self.repo)
        self.out.mkdir()
        with self.assertRaisesRegex(launcher.LauncherError, "already exists"):
            launcher.validate_paths(self.source, self.out, self.log, repo_root=self.repo)
        self.out.rmdir()
        self.log.symlink_to(self.root / "missing")
        with self.assertRaisesRegex(launcher.LauncherError, "already exists"):
            launcher.validate_paths(self.source, self.out, self.log, repo_root=self.repo)
        self.log.unlink()
        with self.assertRaisesRegex(launcher.LauncherError, "overlap"):
            launcher.validate_paths(self.source, self.out, self.log, repo_root=self.root)

    def test_bind_alias_and_parent_replacement_fail_closed(self):
        original = launcher.os.path.samefile
        def aliased(first, second):
            if Path(first) == self.out.parent and Path(second) == self.source:
                return True
            return original(first, second)
        with patch.object(launcher.os.path, "samefile", side_effect=aliased), \
             self.assertRaisesRegex(launcher.LauncherError, "filesystem identity|aliases"):
            launcher.validate_paths(self.source, self.out, self.log, repo_root=self.repo)
        preflight = self.log.with_name(self.log.name + ".preflight.json")
        identity = launcher.location_identity(self.source, self.out, self.log, preflight)
        identity["log_parent"]["inode"] += 1
        with self.assertRaisesRegex(launcher.LauncherError, "replaced"):
            launcher.revalidate_location_identity(identity)

    def test_lock_pins_pixel10_arm64_targets_and_exact_builder(self):
        original = json.loads(launcher.LOCK.read_text())
        lock_path = self.root / "lock.json"
        lock_path.write_text(json.dumps(original))
        lock, _ = launcher.load_contract(lock_path)
        self.assertEqual(lock["production_target"]["abi"], "arm64-v8a")
        mutations = [
            ("builder", "image_digest", "sha256:" + "0" * 64),
            ("production_target", "product", "shiba"),
            ("release_pipeline", "lunch_target", "frankel-cur-userdebug"),
            ("release_pipeline", "build_targets", ["droid"]),
        ]
        for section, key, value in mutations:
            changed = copy.deepcopy(original); changed[section][key] = value
            lock_path.write_text(json.dumps(changed))
            with self.subTest(section=section, key=key), self.assertRaisesRegex(
                    launcher.LauncherError, "differs"):
                launcher.load_contract(lock_path)

    def test_source_roles_are_independently_fail_closed(self):
        baseline = {"stage": {"state": "absent"}, "owned_tracked_changes": {},
                    "vendor": {"identity_sha256": "a" * 64}}
        toolchain = {"siso": {"sha256": "b" * 64}}
        with patch.object(launcher.comparison, "collect_source_snapshot", return_value=baseline), \
             patch.object(launcher.comparison, "collect_toolchain", return_value=toolchain):
            self.assertEqual(launcher.audit_source("baseline", self.source, None),
                             (baseline, toolchain))
        with self.assertRaisesRegex(launcher.LauncherError, "forbids"):
            launcher.audit_source("baseline", self.source, self.root / "certificate")
        certificate = self.root / "certificate.der"; certificate.write_bytes(b"public")
        custom = {"stage": {"state": "schema-4-with-project-updater",
                            "marker": {"schema": 4}},
                  "owned_tracked_changes": {"owned": {}},
                  "vendor": {"identity_sha256": "a" * 64}}
        with patch.object(launcher.comparison, "collect_source_snapshot", return_value=custom), \
             patch.object(launcher.comparison, "collect_toolchain", return_value=toolchain):
            self.assertEqual(launcher.audit_source("custom", self.source, certificate),
                             (custom, toolchain))
        broken = copy.deepcopy(custom); broken["stage"]["marker"]["schema"] = 3
        with patch.object(launcher.comparison, "collect_source_snapshot", return_value=broken), \
             patch.object(launcher.comparison, "collect_toolchain", return_value=toolchain), \
             self.assertRaisesRegex(launcher.LauncherError, "active-schema"):
            launcher.audit_source("custom", self.source, certificate)

    def test_builder_and_retained_container_require_exact_image_id(self):
        record = {"reference": launcher.PIN["builder_reference"],
                  "image": {"id": launcher.PIN["builder_digest"],
                            "config": {"Env": ["PATH=/usr/bin"]}}}
        def captured(value):
            inspected = subprocess.CompletedProcess([], 0, b"[{}]", b"")
            runtime = subprocess.CompletedProcess([], 0, b"v24.21.0\n1.22.19\n", b"")
            with patch.object(launcher, "run_docker", side_effect=[inspected, runtime]), \
                 patch.object(launcher.provenance, "builder_subset", return_value=value["image"]), \
                 patch.object(launcher.provenance, "validate_builder",
                              side_effect=lambda actual, _lock: actual):
                return launcher.capture_builder({"HOME": "/tmp", "PATH": "/usr/bin:/bin",
                                                 "LANG": "C", "LC_ALL": "C"})
        self.assertEqual(captured(record)["image"], record["image"])
        changed = copy.deepcopy(record); changed["image"]["id"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(launcher.LauncherError, "exact locked"):
            captured(changed)
        name = "wonad-phase1-frankel-baseline-2026100600-retained"
        value = {"Id": "a" * 64, "Name": "/" + name,
                 "Image": launcher.PIN["builder_digest"],
                 "State": {"Status": "exited", "ExitCode": 0, "Running": False,
                           "OOMKilled": False},
                 "HostConfig": {
                     "NanoCpus": 6 * 10 ** 9,
                     "Memory": 48 * launcher.GIB,
                     "MemorySwap": 48 * launcher.GIB,
                     "PidsLimit": 4096,
                 },
                 "Config": {"Image": launcher.PIN["builder_digest"], "Labels": {
                     launcher.ATTEMPT_LABEL: self.NONCE,
                     launcher.LOCALITY_LABEL: self.LOCALITY}}}
        good = subprocess.CompletedProcess([], 0, json.dumps([value]).encode(), b"")
        with patch.object(launcher.subprocess, "run", return_value=good):
            launcher.verify_retained_container(name, self.NONCE, self.LOCALITY)
        value["Config"]["Labels"][launcher.ATTEMPT_LABEL] = "0" * 64
        bad = subprocess.CompletedProcess([], 0, json.dumps([value]).encode(), b"")
        with patch.object(launcher.subprocess, "run", return_value=bad), \
             self.assertRaisesRegex(launcher.LauncherError, "differs"):
            launcher.verify_retained_container(name, self.NONCE, self.LOCALITY)
        value["Config"]["Labels"][launcher.ATTEMPT_LABEL] = self.NONCE
        for field in ("NanoCpus", "Memory", "MemorySwap", "PidsLimit"):
            changed = copy.deepcopy(value)
            del changed["HostConfig"][field]
            bad = subprocess.CompletedProcess([], 0, json.dumps([changed]).encode(), b"")
            with self.subTest(field=field), patch.object(
                    launcher.subprocess, "run", return_value=bad), \
                 self.assertRaisesRegex(launcher.LauncherError, "differs"):
                launcher.verify_retained_container(name, self.NONCE, self.LOCALITY)

    def test_container_name_freshness_fails_closed_on_daemon_errors(self):
        missing = subprocess.CompletedProcess([], 1, "", "Error: No such container: fresh\n")
        with patch.object(launcher.subprocess, "run", return_value=missing):
            launcher.require_fresh_container("fresh")
        exists = subprocess.CompletedProcess([], 0, "a" * 64 + "\n", "")
        with patch.object(launcher.subprocess, "run", return_value=exists), \
             self.assertRaisesRegex(launcher.LauncherError, "already in use"):
            launcher.require_fresh_container("used")
        unknown = subprocess.CompletedProcess([], 1, "", "permission denied\n")
        with patch.object(launcher.subprocess, "run", return_value=unknown), \
             self.assertRaisesRegex(launcher.LauncherError, "could not prove"):
            launcher.require_fresh_container("unknown")

    def execution_record(self, name):
        docker = {"fixture": "local", "daemon": {"root_dir": str(self.root)}}
        digest = launcher.provenance.canonical_digest(docker)
        return {"role": "baseline", "container_name": name,
                "locations": {"source": str(self.source)},
                "attempt_nonce": self.NONCE, "docker_locality": docker,
                "docker_locality_sha256": digest,
                "resources": self.resource_evidence(),
                "location_identity": launcher.location_identity(
                    self.source, self.out, self.log,
                    self.log.with_name(self.log.name + ".preflight.json"))}

    def test_failed_attempt_retains_output_log_and_preflight(self):
        name = "wonad-phase1-frankel-baseline-2026100600-failure"
        record = self.execution_record(name)
        command = launcher.docker_command(
            self.source, self.out, name, attempt_nonce=self.NONCE,
            locality_sha256=record["docker_locality_sha256"])
        preflight = self.log.with_name(self.log.name + ".preflight.json")

        def fail(argv, **kwargs):
            self.assertEqual(argv, command)
            kwargs["stdout"].write(b"deliberate failure\n")
            return subprocess.CompletedProcess(argv, 19)

        with patch.object(launcher, "docker_host_identity",
                          return_value=record["docker_locality"]), \
             patch.object(launcher, "observe_host_resources",
                          return_value=self.resource_observation(2)):
            self.assertEqual(launcher.execute(record, self.out, self.log, preflight,
                                              command, runner=fail), 19)
        self.assertTrue(self.out.is_dir())
        self.assertEqual(self.log.read_bytes(), b"deliberate failure\n")
        self.assertEqual(json.loads(preflight.read_text()), record)
        with self.assertRaisesRegex(launcher.LauncherError, "resource evidence"):
            with patch.object(launcher, "docker_host_identity",
                              return_value=record["docker_locality"]):
                launcher.execute(record, self.out, self.log, preflight, command, runner=fail)

    def test_prelaunch_resource_drift_fails_before_docker_and_writes_no_success_evidence(self):
        name = "wonad-phase1-frankel-baseline-2026100600-drift"
        record = self.execution_record(name)
        preflight = self.log.with_name(self.log.name + ".preflight.json")
        command = launcher.docker_command(
            self.source, self.out, name, attempt_nonce=self.NONCE,
            locality_sha256=record["docker_locality_sha256"])
        drifted = self.resource_observation(2)
        drifted["memory"]["available_bytes"] = (
            launcher.PIN["host_admission"]["memory_available_bytes"] - 1)
        run = Mock()
        with patch.object(launcher, "docker_host_identity",
                          return_value=record["docker_locality"]), \
             patch.object(launcher, "observe_host_resources", return_value=drifted), \
             self.assertRaisesRegex(launcher.LauncherError,
                                    "pre-launch host-memory admission"):
            launcher.execute(record, self.out, self.log, preflight, command, runner=run)
        run.assert_not_called()
        self.assertTrue(self.out.is_dir())
        self.assertFalse(preflight.exists())
        self.assertFalse(self.log.exists())

    def test_success_requires_retained_container_log_siso_and_product_artifacts(self):
        name = "wonad-phase1-frankel-baseline-2026100600-success"
        preflight = self.log.with_name(self.log.name + ".preflight.json")
        record = self.execution_record(name)
        command = ["docker", "run"]

        def success(_argv, **kwargs):
            kwargs["stdout"].write(b"fixture\n")
            return subprocess.CompletedProcess([], 0)

        with patch.object(launcher, "verify_retained_container") as retained, \
             patch.object(launcher.comparison, "validate_build_log") as log, \
             patch.object(launcher.comparison, "collect_build_engine") as engine, \
             patch.object(launcher.comparison, "collect_artifacts") as artifacts, \
             patch.object(launcher, "docker_host_identity",
                          return_value=record["docker_locality"]), \
             patch.object(launcher, "observe_host_resources",
                          return_value=self.resource_observation(2)):
            self.assertEqual(launcher.execute(record, self.out, self.log, preflight,
                                              command, runner=success), 0)
        retained.assert_called_once_with(name, self.NONCE,
                                         record["docker_locality_sha256"], ANY)
        log.assert_called_once_with(self.log)
        engine.assert_called_once_with(self.source, self.out)
        artifacts.assert_called_once_with(self.out, "baseline")

    def make_vendor_fixture(self):
        adevtool = self.source / "vendor/adevtool"
        adevtool.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(adevtool)], check=True)
        subprocess.run(["git", "-C", str(adevtool), "config", "user.name", "fixture"], check=True)
        subprocess.run(["git", "-C", str(adevtool), "config", "user.email", "fixture@example.invalid"], check=True)
        marker = adevtool / "tracked"; marker.write_text("fixture\n")
        subprocess.run(["git", "-C", str(adevtool), "add", "tracked"], check=True)
        subprocess.run(["git", "-C", str(adevtool), "commit", "-qm", "fixture"], check=True)
        revision = subprocess.check_output(["git", "-C", str(adevtool), "rev-parse", "HEAD"],
                                           text=True).strip()
        config = self.source / comparison.VENDOR_CONFIG
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text("device:\n  build_id: CP3A.261005.005\n")
        vendor = self.source / comparison.VENDOR_ROOT
        (vendor / "proprietary").mkdir(parents=True)
        values = {"AndroidProducts.mk": b"products\n", "frankel.mk": b"frankel\n",
                  "proprietary/blob.bin": b"blob\x00data"}
        for name, payload in values.items():
            path = vendor / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(payload)
        (vendor / comparison.VENDOR_VERSION_FILE).write_bytes(
            comparison.expected_version_check(revision))
        spec = self.source / comparison.VENDOR_SPEC
        spec.parent.mkdir(parents=True, exist_ok=True)
        spec.write_text(
            f"AndroidProducts.mk: {digest(values['AndroidProducts.mk'])}\n"
            f"frankel.mk: {digest(values['frankel.mk'])}\n"
            "proprietary: dir\n"
            f"proprietary/blob.bin: {digest(values['proprietary/blob.bin'])}\n")
        return vendor

    def test_vendor_readiness_checks_every_file_directory_hash_and_revision_guard(self):
        vendor = self.make_vendor_fixture()
        record = comparison.collect_vendor(self.source)
        self.assertEqual(record["build_id"], "CP3A.261005.005")
        self.assertIn("adevtool-version-check.mk", record["files"])
        self.assertRegex(record["identity_sha256"], r"^[0-9a-f]{64}$")
        (vendor / "proprietary/blob.bin").write_bytes(b"tampered")
        with self.assertRaisesRegex(comparison.ComparisonError, "differs from pinned spec"):
            comparison.collect_vendor(self.source)

    def test_vendor_readiness_rejects_extra_and_symlinked_content(self):
        vendor = self.make_vendor_fixture()
        (vendor / "extra").write_text("foreign")
        with self.assertRaisesRegex(comparison.ComparisonError, "inventory differs"):
            comparison.collect_vendor(self.source)
        (vendor / "extra").unlink()
        blob = vendor / "proprietary/blob.bin"; blob.unlink(); blob.symlink_to("../frankel.mk")
        with self.assertRaisesRegex(comparison.ComparisonError, "not ordinary"):
            comparison.collect_vendor(self.source)

    def make_artifacts(self, role="baseline"):
        for relative in comparison.FIXED_ARTIFACTS.values():
            path = self.out / relative; path.parent.mkdir(parents=True, exist_ok=True)
            if relative == comparison.TARGET_FILES:
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("META/misc_info.txt",
                                     "build_id=CP3A.261005.005\nbuild_number=2026100600\n")
            elif relative.name.startswith("build_fingerprint"):
                path.write_text("google/frankel/frankel:17/CP3A.261005.005/2026100600:user/test-keys\n")
            else:
                path.write_bytes(relative.name.encode())
        otatools = self.out / "soong/.intermediates/build/otatools/otatools.zip"
        otatools.parent.mkdir(parents=True); otatools.write_bytes(b"otatools")
        for label, relative in comparison.OS_ARTIFACTS.items():
            if role == "baseline" and label in comparison.NATIVE_ONLY:
                continue
            path = self.out / comparison.PRODUCT / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((role + ":" + label).encode())
        return otatools

    def test_product_artifacts_bind_images_target_files_fingerprint_and_unique_otatools(self):
        self.make_artifacts()
        record = comparison.collect_artifacts(self.out, "baseline")
        self.assertEqual(set(record["files"]),
                         {"vendor_boot", "vendor_kernel_boot", "build_fingerprint",
                          "target_files", "otatools"})
        self.assertEqual(record["target_files_metadata"]["build_id"], "CP3A.261005.005")
        self.assertTrue(all(record["os_artifacts"][name]["state"] == "absent"
                            for name in comparison.NATIVE_ONLY))
        second = self.out / "soong/.intermediates/other/otatools.zip"
        second.parent.mkdir(parents=True); second.write_bytes(b"other")
        with self.assertRaisesRegex(comparison.ComparisonError, "exactly one"):
            comparison.collect_artifacts(self.out, "baseline")

    def test_artifact_rejects_symlinked_ancestor_escape(self):
        self.out.mkdir()
        outside = self.root / "outside"
        artifact = outside / "target/product/frankel/vendor_boot.img"
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b"foreign")
        (self.out / "target").symlink_to(outside / "target", target_is_directory=True)
        with self.assertRaisesRegex(comparison.ComparisonError, "symlink component"):
            comparison.artifact_record(
                self.out, comparison.FIXED_ARTIFACTS["vendor_boot"])

    def test_target_files_rejects_unsafe_or_duplicate_zip_entries(self):
        archive = self.root / "target.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("../escape", "bad")
            output.writestr("META/misc_info.txt", "build_id=CP3A.261005.005\n")
        with self.assertRaisesRegex(comparison.ComparisonError, "unsafe"):
            comparison.safe_target_files_metadata(archive)

    def test_large_sparse_reference_streams_without_stable_bytes(self):
        artifact = self.root / "large-sparse.img"
        with artifact.open("wb") as output:
            output.seek(32 * 1024 * 1024 - 1)
            output.write(b"x")
        with patch.object(comparison, "stable_bytes",
                          side_effect=AssertionError("must not materialize")):
            reference = comparison.ordinary_ref(artifact)
        self.assertEqual(reference["size"], 32 * 1024 * 1024)
        self.assertRegex(reference["sha256"], r"^[0-9a-f]{64}$")

    def test_fd_reference_rejects_pathname_swap_after_read(self):
        artifact = self.root / "swapped.img"
        artifact.write_bytes(b"original payload")
        displaced = self.root / "displaced.img"
        real_lstat = os.lstat
        swapped = False

        def swap_on_recheck(path):
            nonlocal swapped
            if Path(path) == artifact and not swapped:
                swapped = True
                os.replace(artifact, displaced)
                artifact.write_bytes(b"replacement payload")
            return real_lstat(path)

        with patch.object(comparison.os, "lstat", side_effect=swap_on_recheck), \
             self.assertRaisesRegex(comparison.ComparisonError, "pathname changed"):
            comparison.ordinary_ref(artifact)

    def test_fd_parse_and_hash_rejects_pathname_swap_after_read(self):
        evidence = self.root / "preflight.json"
        evidence.write_text('{"schema": 1}\n')
        displaced = self.root / "old-preflight.json"
        real_lstat = os.lstat
        swapped = False

        def swap_on_recheck(path):
            nonlocal swapped
            if Path(path) == evidence and not swapped:
                swapped = True
                os.replace(evidence, displaced)
                evidence.write_text('{"schema": 2}\n')
            return real_lstat(path)

        with patch.object(comparison.os, "lstat", side_effect=swap_on_recheck), \
             self.assertRaisesRegex(comparison.ComparisonError, "pathname changed"):
            comparison.stable_bytes(evidence, maximum_size=1024)

    def container_fixture(self):
        self.out.mkdir()
        self.log.write_bytes(b"exact merged output\n")
        container_id = "a" * 64
        process = ["-i", "HOME=/tmp/home", "/bin/bash", "-c", "true"]
        builder = {"image": {"id": comparison.BUILDER_DIGEST,
                             "config": {"Env": ["PATH=/usr/bin", "LANG=C.UTF-8"]}}}
        info = {
            "Id": container_id, "Name": "/frankel-fixture", "Image": comparison.BUILDER_DIGEST,
            "Created": "2026-10-10T01:00:00Z", "RestartCount": 0,
            "State": {"Status": "exited", "Running": False, "Paused": False,
                      "Restarting": False, "Dead": False, "ExitCode": 0,
                      "OOMKilled": False, "Error": "",
                      "StartedAt": "2026-10-10T01:00:01Z",
                      "FinishedAt": "2026-10-10T01:01:00Z"},
            "Config": {"Image": comparison.BUILDER_DIGEST, "User": "1000:1000",
                       "WorkingDir": "/sources", "Entrypoint": ["/usr/bin/env"],
                       "Cmd": process, "AttachStdout": True, "AttachStderr": True,
                       "AttachStdin": False, "OpenStdin": False, "Tty": False,
                       "Env": ["PATH=/usr/bin", "LANG=C.UTF-8"],
                       "Labels": {"org.wonad.phase1.attempt": "1" * 64,
                                  "org.wonad.phase1.locality": "2" * 64}},
            "HostConfig": {"NetworkMode": "none", "Privileged": False,
                           "AutoRemove": False, "ReadonlyRootfs": False,
                           "SecurityOpt": ["label=disable"], "CapAdd": None,
                           "CapDrop": ["ALL"], "GroupAdd": None, "Devices": [],
                           "DeviceRequests": None, "DeviceCgroupRules": None,
                           "Tmpfs": None, "IpcMode": "private", "PidMode": "",
                           "UTSMode": "", "UsernsMode": "",
                           "NanoCpus": 6 * 10 ** 9,
                           "Memory": 48 * launcher.GIB,
                           "MemorySwap": 48 * launcher.GIB,
                           "PidsLimit": 4096,
                           "Binds": [f"{self.source}:/sources:rw",
                                     f"{self.out}:/sources/out:rw"],
                           "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}},
            "Mounts": [
                {"Source": str(self.source), "Destination": "/sources", "Mode": "rw",
                 "Propagation": "rprivate", "RW": True, "Type": "bind"},
                {"Source": str(self.out), "Destination": "/sources/out", "Mode": "rw",
                 "Propagation": "rprivate", "RW": True, "Type": "bind"},
            ],
        }
        return info, builder, process

    def test_retained_container_binds_image_isolation_mounts_and_exact_log(self):
        info, builder, process = self.container_fixture()
        with patch.object(comparison, "docker_inspect", return_value=info), \
             patch.object(comparison, "container_logs", return_value=self.log.read_bytes()):
            record = comparison.collect_container(
                "frankel-fixture", self.source, self.out, self.log, builder, process)
        self.assertEqual(record["image"], comparison.BUILDER_DIGEST)
        self.assertEqual(record["network_mode"], "none")
        self.assertEqual(record["cap_drop"], ["ALL"])
        self.assertEqual(record["logs"], comparison.ordinary_ref(self.log))
        mutations = [
            ("Image", "sha256:" + "0" * 64),
            ("State.OOMKilled", True),
            ("Config.User", "0:0"),
            ("HostConfig.NetworkMode", "default"),
            ("HostConfig.CapDrop", []),
            ("HostConfig.IpcMode", "host"),
            ("HostConfig.NanoCpus", 5 * 10 ** 9),
            ("HostConfig.Memory", 47 * launcher.GIB),
            ("HostConfig.MemorySwap", 49 * launcher.GIB),
            ("HostConfig.PidsLimit", 4095),
            ("Mounts.0.Propagation", "shared"),
        ]
        for dotted, value in mutations:
            changed = copy.deepcopy(info)
            target = changed
            parts = dotted.split(".")
            for part in parts[:-1]:
                target = target[int(part)] if part.isdigit() else target[part]
            if parts[-1].isdigit():
                target[int(parts[-1])] = value
            else:
                target[parts[-1]] = value
            with self.subTest(field=dotted), patch.object(
                    comparison, "docker_inspect", return_value=changed), \
                 patch.object(comparison, "container_logs", return_value=self.log.read_bytes()), \
                 self.assertRaises(comparison.ComparisonError):
                comparison.collect_container(
                    "frankel-fixture", self.source, self.out, self.log, builder, process)
        missing_limit = copy.deepcopy(info)
        del missing_limit["HostConfig"]["Memory"]
        with patch.object(comparison, "docker_inspect", return_value=missing_limit), \
             patch.object(comparison, "container_logs", return_value=self.log.read_bytes()), \
             self.assertRaisesRegex(comparison.ComparisonError, "isolation contract"):
            comparison.collect_container(
                "frankel-fixture", self.source, self.out, self.log, builder, process)
        duplicate = copy.deepcopy(info)
        duplicate["HostConfig"]["Binds"].append(duplicate["HostConfig"]["Binds"][0])
        duplicate["Mounts"].append(copy.deepcopy(duplicate["Mounts"][0]))
        with patch.object(comparison, "docker_inspect", return_value=duplicate), \
             patch.object(comparison, "container_logs", return_value=self.log.read_bytes()), \
             self.assertRaisesRegex(comparison.ComparisonError, "bind arguments"):
            comparison.collect_container(
                "frankel-fixture", self.source, self.out, self.log, builder, process)
        with patch.object(comparison, "docker_inspect", return_value=info), \
             patch.object(comparison, "container_logs", return_value=b"different\n"), \
             self.assertRaisesRegex(comparison.ComparisonError, "differs"):
            comparison.collect_container(
                "frankel-fixture", self.source, self.out, self.log, builder, process)

    def test_receipt_authentication_rejects_tamper_and_wrong_digest(self):
        receipt = self.root / "receipt.json"
        value = {"schema": comparison.RECEIPT_SCHEMA,
                 "kind": "wonad-frankel-build-comparison-input",
                 "role": "baseline",
                 "scope": "unsigned-build-comparison-not-release-or-runtime-qualification"}
        receipt.write_text(json.dumps(value))
        actual = digest(receipt.read_bytes())
        self.assertEqual(comparison.load_authenticated(receipt, actual), value)
        with self.assertRaisesRegex(comparison.ComparisonError, "authenticated"):
            comparison.load_authenticated(receipt, "0" * 64)
        receipt.write_text(json.dumps({**value, "role": "custom"}))
        with self.assertRaisesRegex(comparison.ComparisonError, "authenticated"):
            comparison.load_authenticated(receipt, actual)

    def test_authenticated_json_rejects_duplicate_fields(self):
        receipt = self.root / "duplicate.json"
        receipt.write_text(
            '{"schema":3,"schema":3,"kind":"wonad-frankel-build-comparison-input",'
            '"role":"baseline",'
            '"scope":"unsigned-build-comparison-not-release-or-runtime-qualification"}')
        with self.assertRaisesRegex(comparison.ComparisonError, "Duplicate JSON field"):
            comparison.load_authenticated(receipt, digest(receipt.read_bytes()))

    def test_helper_ledger_binds_every_imported_verifier_and_rejects_drift(self):
        ledger = comparison.helper_ledger()
        self.assertEqual(set(ledger), set(comparison.HELPER_FILES))
        self.assertEqual(ledger["frankel_comparison"]["path"],
                         "android/tools/frankel_build_comparison.py")
        real_ref = comparison.ordinary_ref

        def drifted(path, **kwargs):
            value = real_ref(path, **kwargs)
            if Path(path) == comparison.HELPER_FILES["x86_comparison"]:
                value = {**value, "sha256": "0" * 64}
            return value

        with patch.object(comparison, "ordinary_ref", side_effect=drifted), \
             self.assertRaisesRegex(comparison.ComparisonError, "ledger differs"):
            comparison.validate_helper_ledger(ledger)

    def test_hardened_preflight_binds_locality_paths_labels_and_exact_docker_argv(self):
        self.out.mkdir()
        preflight = self.log.with_name(self.log.name + ".preflight.json")
        docker_identity = {
            "kind": "fixture-local-docker",
            "daemon": {"root_dir": str(self.root)},
        }
        locality_sha = comparison.canonical_digest(docker_identity)
        nonce = "3" * 64
        source_snapshot = {"pin": {"lock": comparison.ordinary_ref(comparison.LOCK)}}
        builder = {"fixed": True}
        container = {"name": "frankel-fixture", "labels": {
            launcher.ATTEMPT_LABEL: nonce,
            launcher.LOCALITY_LABEL: locality_sha,
        }}
        identity = launcher.location_identity(
            self.source, self.out, self.log, preflight)
        identity["out"] = launcher.directory_identity(self.out, "OUT_DIR")
        record = {
            "schema": 2, "kind": "wonad-frankel-build-launch-preflight",
            "role": "baseline", "contract": launcher.PIN,
            "process_environment": launcher.PROCESS_ENV,
            "process_command": launcher.process_command(),
            "inner_command": launcher.INNER_COMMAND,
            "lock": source_snapshot["pin"]["lock"], "builder": builder,
            "source": source_snapshot, "toolchain": {},
            "locations": {"source": str(self.source), "out": str(self.out),
                          "log": str(self.log)},
            "container_name": container["name"], "attempt_nonce": nonce,
            "docker_locality": docker_identity,
            "docker_locality_sha256": locality_sha,
            "location_identity": identity,
            "resources": self.resource_evidence(complete=True),
            "docker_command": launcher.docker_command(
                self.source, self.out, container["name"], attempt_nonce=nonce,
                locality_sha256=locality_sha),
            "launcher": comparison.ordinary_ref(comparison.LAUNCHER),
        }
        patches = (
            patch.object(comparison, "load_launcher_contract", return_value=launcher),
            patch.object(comparison, "collect_toolchain", return_value={}),
            patch.object(launcher, "docker_environment", return_value={}),
            patch.object(launcher, "docker_host_identity", return_value=docker_identity),
        )
        with patches[0], patches[1], patches[2], patches[3]:
            self.assertIs(comparison.validate_preflight_record(
                record, "baseline", self.source, self.out, self.log, preflight,
                container, builder, source_snapshot), launcher)
        altered = copy.deepcopy(record)
        altered["docker_command"][-1] = "foreign command"
        with patch.object(comparison, "load_launcher_contract", return_value=launcher), \
             patch.object(comparison, "collect_toolchain", return_value={}), \
             patch.object(launcher, "docker_environment", return_value={}), \
             patch.object(launcher, "docker_host_identity", return_value=docker_identity), \
             self.assertRaisesRegex(comparison.ComparisonError, "does not bind"):
            comparison.validate_preflight_record(
                altered, "baseline", self.source, self.out, self.log, preflight,
                container, builder, source_snapshot)
        altered = copy.deepcopy(record)
        altered["resources"]["before_docker_run"]["memory"]["available_bytes"] = 0
        with patch.object(comparison, "load_launcher_contract", return_value=launcher), \
             patch.object(comparison, "collect_toolchain", return_value={}), \
             patch.object(launcher, "docker_environment", return_value={}), \
             patch.object(launcher, "docker_host_identity", return_value=docker_identity), \
             self.assertRaisesRegex(comparison.ComparisonError, "resource|admission"):
            comparison.validate_preflight_record(
                altered, "baseline", self.source, self.out, self.log, preflight,
                container, builder, source_snapshot)
        altered = copy.deepcopy(record)
        del altered["resources"]["before_docker_run"]["filesystems"]["docker"]
        with patch.object(comparison, "load_launcher_contract", return_value=launcher), \
             patch.object(comparison, "collect_toolchain", return_value={}), \
             patch.object(launcher, "docker_environment", return_value={}), \
             patch.object(launcher, "docker_host_identity", return_value=docker_identity), \
             self.assertRaisesRegex(comparison.ComparisonError, "resource|filesystem"):
            comparison.validate_preflight_record(
                altered, "baseline", self.source, self.out, self.log, preflight,
                container, builder, source_snapshot)

    def test_signer_binding_is_canonical_across_external_and_staged_encodings(self):
        external = self.root / "signer.pem"; external.write_text("external encoding")
        staged = self.source / "external/wonad/WonadReleaseCertificate.der"
        staged.parent.mkdir(parents=True); staged.write_text("staged encoding")
        first = {"file": {"sha256": "1" * 64, "size": 17},
                 "der_sha256": "a" * 64, "der_size": 512, "subject": "subject=Wonad"}
        second = {"file": {"sha256": "2" * 64, "size": 15},
                  "der_sha256": "a" * 64, "der_size": 512, "subject": "subject=Wonad"}
        with patch.object(comparison.provenance, "public_certificate",
                          side_effect=[first, second]):
            external_identity = comparison.signer_identity(external, self.source)
            staged_identity = comparison.signer_identity(
                staged, self.source, allow_staged=True)
        self.assertEqual(external_identity, staged_identity)
        self.assertNotIn("file", external_identity)
        with patch.object(comparison.provenance, "public_certificate", return_value=second), \
             self.assertRaisesRegex(comparison.ComparisonError, "outside"):
            comparison.signer_identity(staged, self.source)

    def fake_receipt(self, role: str, source: Path, out: Path, container: str):
        common_file = lambda name, value: {"path": name, "state": "present",
                                           "sha256": value * 64, "size": 1}
        files = {
            "build_fingerprint": common_file("target/product/frankel/build_fingerprint-frankel.txt", "1"),
            "otatools": common_file("soong/x/otatools.zip", "2"),
            "target_files": common_file("target/product/frankel/x.zip", "3" if role == "baseline" else "4"),
            "vendor_boot": common_file("target/product/frankel/vendor_boot.img", "5"),
            "vendor_kernel_boot": common_file("target/product/frankel/vendor_kernel_boot.img", "6"),
        }
        os_files = {}
        values = {"com.android.systemui": "7", "os_services": "8", "os_framework": "9",
                  "os_input_dispatcher": "0", "os_android_servers": "1"}
        for label, relative in comparison.OS_ARTIFACTS.items():
            if role == "baseline" and label in comparison.NATIVE_ONLY:
                os_files[label] = {"path": relative, "state": "absent"}
            elif label in comparison.NATIVE_ONLY:
                os_files[label] = common_file(relative, "a" if label == "os_broker_native" else "b")
            else:
                value = values[label] if role == "baseline" else chr(ord(values[label]) + 3)
                os_files[label] = common_file(relative, value)
        materializations = {
            "build/make": {
                "gitlinks": {"nested": {
                    "mode": "160000", "oid": "1" * 40, "state": "absent",
                }},
                "materialized_eol": {}, "materialized_lfs": {},
            },
        }
        marker = {
            "schema": 4,
            "files": {"fixture-source.kt": "e" * 64},
            "platform_targets": {
                label: {name: "d" * 64 for name in comparison.stage_contract.patch_target_names(names)}
                for label, (project, names, field) in comparison.stage_contract.platform_lanes().items()
            },
        }
        owned = comparison.stage_contract.marker_owned_targets(marker)
        owned["packages/apps/Updater/res/values/config.xml"] = "c" * 64
        generated = {
            "external/wonad/.wonad-stage.json": {"sha256": "b" * 64},
            "external/wonad/fixture-source.kt": {"sha256": "e" * 64},
            ".wonad-updater-stage.json": {"sha256": "a" * 64},
        }
        return {
            "role": role, "contract": {"fixed": True}, "builder": {"fixed": True},
            "toolchain": {"fixed": True}, "tools": {"fixed": True},
            "locations": {"source": str(source), "out_dir": str(out)},
            "source": {"pin": {"fixed": True},
                       "vendor": {"identity_sha256": "a" * 64, "files": {}},
                       "stage": ({"state": "absent"} if role == "baseline" else
                                 {"state": "schema-4-with-project-updater", "marker": marker,
                                  "updater": {"configured_sha256": "c" * 64}}),
                       "owned_tracked_changes": ({} if role == "baseline" else
                                                 {name: {"sha256": value} for name, value in owned.items()}),
                       "generated_inputs": {} if role == "baseline" else generated,
                       "worktree_materializations": materializations,
                       "worktree_materializations_sha256":
                           comparison.canonical_digest(materializations)},
            "container": {"id": container * 64, "name": role + "-container"},
            "artifacts": {"fingerprint": "same", "files": files,
                          "os_artifacts": os_files},
        }

    def test_comparison_requires_same_vendor_and_a_changed_target_files_archive(self):
        sources = [self.root / "baseline-source", self.root / "custom-source"]
        outs = [self.root / "baseline-out", self.root / "custom-out"]
        for path in [*sources, *outs]: path.mkdir()
        receipts = [self.root / "baseline.json", self.root / "custom.json"]
        for path in receipts: path.write_text("fixture")
        baseline = self.fake_receipt("baseline", sources[0], outs[0], "a")
        custom = self.fake_receipt("custom", sources[1], outs[1], "b")
        output = self.root / "comparison.json"
        with patch.object(comparison, "verify", side_effect=lambda path, _digest, rehash=True:
                          baseline if path == receipts[0] else custom):
            result, result_digest = comparison.compare(
                receipts[0], "1" * 64, receipts[1], "2" * 64, output, rehash=False)
        self.assertEqual(result["result"], "passed_exact_frankel_clean_baseline_custom_delta")
        self.assertEqual(result_digest, digest(output.read_bytes()))
        bad_vendor = copy.deepcopy(custom)
        bad_vendor["source"]["vendor"]["identity_sha256"] = "f" * 64
        with patch.object(comparison, "verify", side_effect=lambda path, _digest, rehash=True:
                          baseline if path == receipts[0] else bad_vendor), \
             self.assertRaisesRegex(comparison.ComparisonError, "vendor tree differs"):
            comparison.compare(receipts[0], "1" * 64, receipts[1], "2" * 64,
                               self.root / "bad-vendor.json", rehash=False)
        bad_tools = copy.deepcopy(custom)
        bad_tools["tools"] = {"fixed": False}
        with patch.object(comparison, "verify", side_effect=lambda path, _digest, rehash=True:
                          baseline if path == receipts[0] else bad_tools), \
             self.assertRaisesRegex(comparison.ComparisonError, "tools differs"):
            comparison.compare(receipts[0], "1" * 64, receipts[1], "2" * 64,
                               self.root / "bad-tools.json", rehash=False)
        same = copy.deepcopy(custom)
        same["artifacts"]["files"]["target_files"] = \
            copy.deepcopy(baseline["artifacts"]["files"]["target_files"])
        with patch.object(comparison, "verify", side_effect=lambda path, _digest, rehash=True:
                          baseline if path == receipts[0] else same), \
             self.assertRaisesRegex(comparison.ComparisonError, "byte-identical"):
            comparison.compare(receipts[0], "1" * 64, receipts[1], "2" * 64,
                               self.root / "same.json", rehash=False)

    def test_frankel_receipts_bind_eol_lfs_and_gitlink_representations(self):
        sources = [self.root / "material-baseline-source",
                   self.root / "material-custom-source"]
        outs = [self.root / "material-baseline-out", self.root / "material-custom-out"]
        for path in [*sources, *outs]:
            path.mkdir()
        receipts = [self.root / "material-baseline.json", self.root / "material-custom.json"]
        for path in receipts:
            path.write_text("fixture")
        baseline = self.fake_receipt("baseline", sources[0], outs[0], "a")

        eol_row = {
            "mode": "100644",
            "attributes": {
                "text": "auto", "eol": "crlf", "filter": "unspecified",
                "ident": "unspecified", "working-tree-encoding": "unspecified",
            },
            "object": {"oid": "2" * 40, "sha256": "3" * 64, "size": 8},
            "worktree": {"sha256": "4" * 64, "size": 10},
        }
        mutations = {
            "LF-versus-CRLF": lambda rows: rows["build/make"]["materialized_eol"].update(
                {"eol.txt": eol_row}),
            "LFS-pointer-versus-payload": lambda rows: rows["build/make"]
                ["materialized_lfs"].update({
                    "payload.bin": {"sha256": "5" * 64, "size": 9},
                }),
            "absent-versus-empty-gitlink": lambda rows: rows["build/make"]["gitlinks"]
                ["nested"].update(state="empty-directory"),
        }
        for label, mutate in mutations.items():
            with self.subTest(representation=label):
                custom = self.fake_receipt("custom", sources[1], outs[1], "b")
                mutate(custom["source"]["worktree_materializations"])
                custom["source"]["worktree_materializations_sha256"] = \
                    comparison.canonical_digest(custom["source"]["worktree_materializations"])
                self.assertNotEqual(
                    baseline["source"]["worktree_materializations_sha256"],
                    custom["source"]["worktree_materializations_sha256"])
                with patch.object(
                        comparison, "verify",
                        side_effect=lambda path, _digest, rehash=True:
                        baseline if path == receipts[0] else custom), \
                     self.assertRaisesRegex(comparison.ComparisonError,
                                            "source materialization differs"):
                    comparison.compare(
                        receipts[0], "1" * 64, receipts[1], "2" * 64,
                        self.root / (label + ".json"), rehash=False)

                validating = copy.deepcopy(custom["source"])
                validating["pin"] = {
                    "projects": [{"path": "build/make"}], "project_count": 1,
                }
                self.assertIs(comparison.validate_source_materializations(validating),
                              validating)


if __name__ == "__main__":
    unittest.main()
