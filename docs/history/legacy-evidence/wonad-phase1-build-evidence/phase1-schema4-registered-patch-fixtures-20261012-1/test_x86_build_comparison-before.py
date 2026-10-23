#!/usr/bin/env python3
"""Adversarial tests for clean-baseline/custom x86 build receipts."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ANDROID = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "x86_build_comparison", ANDROID / "tools/x86_build_comparison.py")
assert SPEC and SPEC.loader
comparison = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(comparison)


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def write_json(path: Path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def attempt4_locality_record(container, source: Path, out: Path, source_snapshot):
    def identity(path):
        value = path.stat()
        return {
            "device": value.st_dev, "inode": value.st_ino, "mode": value.st_mode,
            "uid": value.st_uid, "gid": value.st_gid,
        }

    source_identity = identity(source)
    out_identity = identity(out)
    mounts = [
        {"type": "bind", "source": str(source), "destination": "/sources",
         "mode": "rw", "rw": True, "propagation": "rprivate"},
        {"type": "bind", "source": str(out), "destination": "/sources/out",
         "mode": "rw", "rw": True, "propagation": "rprivate"},
    ]
    boot_id = "12345678-1234-1234-1234-123456789abc"
    return {
        "schema": 1,
        "kind": "wonad-local-docker-bind-proof",
        "scope": "running-container-locality-and-bind-identity",
        "endpoint": "unix:///var/run/docker.sock",
        "docker_cli": {
            "path": "/usr/bin/docker", "realpath": "/usr/bin/docker",
            "device": 1, "inode": 2, "mode": stat.S_IFREG | 0o755,
            "uid": 0, "gid": 0,
            "file": {"sha256": "d" * 64, "size": 100},
        },
        "socket": {
            "path": "/var/run/docker.sock", "realpath": "/run/docker.sock",
            "device": 3, "inode": 4, "mode": stat.S_IFSOCK | 0o660,
            "uid": 0, "gid": 987,
        },
        "context": {
            "selected": "default", "name": "default",
            "endpoint": "unix:///var/run/docker.sock",
            "skip_tls_verify": False, "tls_material": {},
        },
        "daemon": {
            "id": "daemon", "name": "builder", "server_version": "29.7.2",
            "kernel_version": "7.1", "os": "linux", "architecture": "x86_64",
            "root_dir": "/var/lib/docker", "client_version": "29.7.2",
            "client_context": "default",
        },
        "host_boot_id": boot_id,
        "container": {
            "id": container["id"], "name": container["name"],
            "image": container["image"],
            "image_reference": container["image_reference"],
            "created": container["created"], "started_at": container["started_at"],
            "pid": 1234, "status": "running", "mounts": mounts,
            "binds": [f"{source}:/sources:rw", f"{out}:/sources/out:rw"],
            "boot_id": boot_id, "stable": True,
        },
        "bind_identity": [
            {"destination": "/sources", "source": str(source),
             "host": source_identity, "container": source_identity},
            {"destination": "/sources/out", "source": str(out),
             "host": out_identity, "container": out_identity},
        ],
        "locked_manifest": {
            "relative": ".repo/manifests/default.xml",
            "host": source_snapshot["pin"]["default_xml"],
            "container": source_snapshot["pin"]["default_xml"],
            "probe": "read-only docker exec sha256sum/stat",
        },
        "lock": source_snapshot["pin"]["lock"],
        "generator": comparison.ordinary_ref(Path(comparison.locality.__file__)),
    }


def git(repository: Path, *arguments) -> str:
    return subprocess.check_output(["git", "-C", str(repository), *arguments],
                                   text=True).strip()


def init_git(repository: Path, files: dict[str, str | bytes]) -> str:
    repository.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(["git", "-C", str(repository), "config", "user.name", "x86 test"], check=True)
    subprocess.run(["git", "-C", str(repository), "config", "user.email",
                    "x86-test@example.invalid"], check=True)
    for name, payload in files.items():
        path = repository / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload if isinstance(payload, bytes) else payload.encode())
    subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repository), "commit", "-qm", "fixture"], check=True)
    return git(repository, "rev-parse", "HEAD")


def init_repo_project(source: Path, project_path: str, project_name: str,
                      files: dict[str, str | bytes]) -> str:
    repository = source / project_path
    revision = init_git(repository, files)
    git_dir = source / ".repo/projects" / (project_path + ".git")
    git_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(repository / ".git", git_dir)
    object_store = source / ".repo/project-objects" / (project_name + ".git") / "objects"
    object_store.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(git_dir / "objects", object_store)
    (git_dir / "objects").symlink_to(os.path.relpath(object_store, git_dir), target_is_directory=True)
    (repository / ".git").symlink_to(os.path.relpath(git_dir, repository), target_is_directory=True)
    (git_dir / "config").write_text(
        "[core]\n\trepositoryFormatVersion = 1\n\tfilemode = true\n"
        "[filter \"lfs\"]\n\tsmudge = git-lfs smudge --skip -- %f\n"
        "\tprocess = git-lfs filter-process --skip\n"
        "[remote \"aosp\"]\n"
        f"\turl = https://android.googlesource.com/{project_name}\n"
        "\treview = https://android-review.googlesource.com/\n"
        f"\tprojectname = {project_name}\n\tfetch = +refs/heads/*:refs/remotes/aosp/*\n"
        "\tpartialclonefilter = blob:limit=10485760\n"
        "[maintenance]\n\tauto = false\n[gc]\n\tauto = 0\n"
        "[extensions]\n\tpartialclone = aosp\n")
    return revision


class ReceiptFixture:
    ATTEMPT_NONCE = "1" * 64
    IMAGES = ("system-qemu.img", "system/build.prop",
              "build_fingerprint-sdk_phone64_x86_64.txt")
    OS = {
        "com.android.systemui": "system_ext/priv-app/SystemUI/SystemUI.apk",
        "os_broker_native": "system_ext/lib64/libwonad_broker_jni.so",
        "os_input_native": "system/lib64/libwonad_input_jni.so",
        "os_services": "system/framework/services.jar",
        "os_framework": "system/framework/framework.jar",
    }
    FINGERPRINT = (
        "Android/sdk_phone64_x86_64/emu64x:17/CP2A.260605.016/"
        "wonad.2026100600:userdebug/test-keys"
    )

    def __init__(self, root: Path):
        self.root = root
        self.sources = {}
        for role in ("baseline", "custom"):
            source = root / (role + "-source")
            (source / ".repo").mkdir(parents=True)
            siso = source / "prebuilts/siso/linux-x86/siso"
            siso.parent.mkdir(parents=True)
            siso.write_bytes(b"pinned siso fixture\n")
            source_main = source / "build/soong/siso_config/main.star"
            source_main.parent.mkdir(parents=True)
            source_main.write_bytes(b"source siso config fixture\n")
            self.sources[role] = source
        self.source = self.sources["baseline"]
        self.builder = self.make_builder()

    @staticmethod
    def make_builder():
        lock = comparison.provenance.load_json(comparison.LOCK)
        image = {
            "id": lock["builder"]["image_digest"], "repo_digests": [],
            "os": "linux", "architecture": "amd64", "size": 1,
            "rootfs": {"type": "layers", "layers": ["sha256:" + "b" * 64]},
            "config": {
                "User": "builder",
                "Env": ["PATH=/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
                "Entrypoint": None, "Cmd": ["bash"], "WorkingDir": "/sources", "Labels": None,
            },
        }
        return {
            "schema": 1, "kind": "wonad-phase1-builder",
            "reference": lock["builder"]["reference"], "image": image,
            "identity_sha256": comparison.canonical_digest(image),
            "dockerfile": comparison.provenance.file_ref(comparison.provenance.DOCKERFILE),
            "runtime": {"node": lock["builder"]["node_version"],
                        "yarn": lock["builder"]["yarn_version"]},
        }

    @staticmethod
    def pin():
        lock = comparison.provenance.load_json(comparison.LOCK)
        projects = [{"path": "build/make", "name": "platform/build",
                     "revision": "1" * 40, "remote": "aosp"}]
        return {
            "release": lock["release"], "lock": comparison.provenance.file_ref(comparison.LOCK),
            "manifest_commit": lock["manifest"]["commit"],
            "manifest_tag_object": lock["manifest"]["tag_object"],
            "default_xml": {"sha256": lock["manifest"]["default_xml_sha256"],
                            "size": lock["manifest"]["default_xml_size"]},
            "projects": projects, "project_count": 1,
            "project_ledger_sha256": comparison.canonical_digest(projects),
            "repo_tool_commit": lock["repo_tool"]["commit"],
            "repo_tool_revision": lock["repo_tool"]["revision"],
        }

    def source_snapshot(self, _source, role, _certificate, _lock, _jobs):
        materializations = {
            "build/make": {
                "gitlinks": {"nested": {
                    "mode": "160000", "oid": "1" * 40, "state": "absent",
                }},
                "materialized_eol": {}, "materialized_lfs": {},
            },
        }
        materialization_fields = {
            "worktree_materializations": materializations,
            "worktree_materializations_sha256":
                comparison.canonical_digest(materializations),
        }
        if role == "baseline":
            return {"pin": self.pin(), "stage": {"state": "absent"},
                    "owned_tracked_changes": {}, "generated_inputs": {},
                    **materialization_fields}
        marker = {
            "schema": 4, "signer_sha256": "c" * 64,
            "platform_targets": {
                "frameworks_base": {"owned.java": "1" * 64},
                "launcher3": {"owned.java": "2" * 64},
                "emulator_goldfish": {"owned.mk": "3" * 64},
            },
            "files": {"Android.bp": "4" * 64},
        }
        row = lambda value: {"sha256": value, "size": 1, "mode": 0o644}
        return {
            "pin": self.pin(),
            "stage": {
                "state": "schema-4-owned-stage", "marker": marker,
                "marker_sha256": "5" * 64,
                "development_certificate": {
                    "file": {"sha256": "6" * 64, "size": 700},
                    "der_sha256": "c" * 64, "der_size": 600,
                    "subject": "subject=Wonad emulator development",
                },
                "qualification": "emulator-development-only",
            },
            "owned_tracked_changes": {
                "frameworks/base/owned.java": row("1" * 64),
                "packages/apps/Launcher3/owned.java": row("2" * 64),
                "device/generic/goldfish/owned.mk": row("3" * 64),
            },
            "generated_inputs": {
                "external/wonad/.wonad-stage.json": row("5" * 64),
                "external/wonad/Android.bp": row("4" * 64),
            },
            **materialization_fields,
        }

    def product(self, role: str, suffix: str):
        out = self.root / (role + "-out-" + suffix)
        product = out / comparison.PROJECT
        product.mkdir(parents=True)
        values = {}
        for name in self.IMAGES:
            payload = (role + ":" + name).encode()
            if name == "build_fingerprint-sdk_phone64_x86_64.txt":
                payload = (self.FINGERPRINT + "\n").encode()
            path = product / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            values[name] = payload
        for label, name in self.OS.items():
            if role == "baseline" and label in comparison.NATIVE_ONLY:
                continue
            payload = (role + ":" + label).encode()
            path = product / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            values[label] = payload
        log = self.root / (role + "-" + suffix + ".log")
        log.write_text(
            "TARGET_PRODUCT=sdk_phone64_x86_64\n"
            "TARGET_BUILD_VARIANT=userdebug\n"
            "TARGET_ARCH=x86_64\n"
            "OUT_DIR=out\n"
            "#### build completed successfully (0:01 (mm:ss)) ####\n"
        )
        (out / "siso_config").mkdir()
        (out / "siso_config/main.star").write_bytes(comparison.SISO_MAIN_STAR)
        (out / "siso_config/main").symlink_to("/sources/build/soong/siso_config")
        (out / "soong.log").write_text(
            '"soong bootstrap" executing "prebuilts/siso/linux-x86/siso" '
            '[prebuilts/siso/linux-x86/siso --config_repo_dir=out/siso_config]\n'
            '"ninja" executing "prebuilts/siso/linux-x86/siso" '
            '[prebuilts/siso/linux-x86/siso --config_repo_dir=out/siso_config]\n'
        )
        return out, log, values

    def container_execution(self, _reference, source, out, log, builder):
        role, suffix = out.name.split("-out-", 1)
        record = {
            "id": sha(str(out).encode()),
            "name": f"wonad-phase1-x86-{role}-2026100600-{suffix}",
            "image": builder["image"]["id"],
            "image_reference": builder["reference"],
            "created": "2026-10-10T15:00:00.000000000Z",
            "started_at": "2026-10-10T15:00:01.000000000Z",
            "finished_at": "2026-10-10T15:01:01.000000000Z",
            "exit_code": 0,
            "oom_killed": False,
            "user": "1000:1000",
            "working_dir": "/sources",
            "command": list(comparison.CONTAINER_COMMAND),
            "environment": dict(sorted(comparison.CONTAINER_ENVIRONMENT.items())),
            "network_mode": "none",
            "security_opt": ["label=disable"],
            "auto_remove": False,
            "privileged": False,
            "cap_add": [],
            "cap_drop": [],
            "group_add": [],
            "devices": [],
            "device_requests": [],
            "device_cgroup_rules": [],
            "tmpfs": {},
            "readonly_rootfs": False,
            "ipc_mode": "private",
            "pid_mode": "",
            "uts_mode": "",
            "userns_mode": "",
            "restart_policy": {"maximum_retry_count": 0, "name": "no"},
            "restart_count": 0,
            "attach_stdout": True,
            "attach_stderr": True,
            "attach_stdin": False,
            "labels": {
                "org.wonad.phase1.attempt": self.ATTEMPT_NONCE,
                "org.wonad.phase1.locality": comparison.canonical_digest(
                    self.docker_locality()),
            },
            "mounts": [
                {"destination": "/sources", "mode": "rw", "propagation": "rprivate",
                 "rw": True, "source": str(source), "type": "bind"},
                {"destination": "/sources/out", "mode": "rw", "propagation": "rprivate",
                 "rw": True, "source": str(out), "type": "bind"},
            ],
            "logs": comparison.ordinary_ref(log),
        }
        return comparison.validate_container_record(
            record, source, out, comparison.ordinary_ref(log), builder)

    @staticmethod
    def docker_locality():
        return {
            "schema": 1, "kind": "wonad-build-launch-docker-locality",
            "endpoint": "unix:///var/run/docker.sock",
            "docker_cli": {
                "path": "/usr/bin/docker", "realpath": "/usr/bin/docker",
                "device": 1, "inode": 2, "mode": stat.S_IFREG | 0o755,
                "uid": 0, "gid": 0,
                "file": {"sha256": "d" * 64, "size": 100},
            },
            "socket": {
                "path": "/var/run/docker.sock", "realpath": "/run/docker.sock",
                "device": 3, "inode": 4, "mode": stat.S_IFSOCK | 0o660,
                "uid": 0, "gid": 987,
            },
            "context": {
                "selected": "default", "name": "default",
                "endpoint": "unix:///var/run/docker.sock",
                "skip_tls_verify": False, "tls_material": {},
            },
            "daemon": {
                "id": "daemon", "name": "builder", "server_version": "29.7.2",
                "kernel_version": "7.1", "os": "linux", "architecture": "x86_64",
                "root_dir": "/var/lib/docker", "client_version": "29.7.2",
                "client_context": "default",
            },
            "host_boot_id": "12345678-1234-1234-1234-123456789abc",
            "generator": comparison.ordinary_ref(Path(comparison.locality.__file__)),
        }

    @staticmethod
    def path_identity(path: Path):
        value = path.stat()
        return {"path": str(path), "device": value.st_dev, "inode": value.st_ino,
                "mode": value.st_mode, "uid": value.st_uid, "gid": value.st_gid}

    def write_preflight(self, role: str, source: Path, out: Path, log: Path,
                        container):
        verification = None
        if role == "custom":
            verification = {
                "command": [comparison.sys.executable, str(comparison.STAGE_OS),
                            "--source", str(source), "--verify-only"],
                "output":
                    "PASS: exact owned Wonad stage, patches, targets and tools verified\n",
            }
        record = {
            "schema": 2,
            "kind": "wonad-x86-build-launch-preflight",
            "role": role,
            "contract": comparison.LAUNCHER_PIN,
            "container_environment": comparison.LAUNCHER_ENVIRONMENT,
            "inner_command": comparison.CONTAINER_COMMAND[2],
            "lock": comparison.ordinary_ref(comparison.LOCK),
            "builder": self.builder,
            "source": self.source_snapshot(source, role, None, comparison.LOCK, 4),
            "stage_verification": verification,
            "locations": {"source": str(source), "out": str(out), "log": str(log)},
            "container_name": container["name"],
            "attempt_nonce": self.ATTEMPT_NONCE,
            "docker_locality": self.docker_locality(),
            "docker_locality_sha256": comparison.canonical_digest(self.docker_locality()),
            "location_identity": {
                "source": self.path_identity(source),
                "out_parent": self.path_identity(out.parent),
                "log_parent": self.path_identity(log.parent),
                "preflight_parent": self.path_identity(log.parent),
                "out": self.path_identity(out),
            },
            "docker_command": comparison.launcher_docker_command(
                source, out, container["name"], self.ATTEMPT_NONCE,
                comparison.canonical_digest(self.docker_locality())),
        }
        write_json(log.with_name(log.name + ".preflight.json"), record)

    def capture(self, role: str, suffix="one"):
        out, log, _ = self.product(role, suffix)
        source = self.sources[role]
        receipt = self.root / (role + "-" + suffix + ".json")
        certificate = self.root / "development.x509.pem" if role == "custom" else None
        container = self.container_execution(f"{role}-{suffix}", source, out, log, self.builder)
        self.write_preflight(role, source, out, log, container)
        with patch.object(comparison, "IMAGE_FILES", self.IMAGES), \
                patch.object(comparison, "OS_PATHS", self.OS), \
                patch.object(comparison, "capture_builder", return_value=self.builder), \
                patch.object(comparison, "collect_source_snapshot",
                             side_effect=self.source_snapshot):
            _, digest = comparison.capture(role, source, out, log,
                                           f"{role}-{suffix}", receipt,
                                           certificate, 4)
        return receipt, digest, out, log


class X86BuildReceiptTest(unittest.TestCase):
    def test_emulator_partition_capacity_is_a_fixed_symmetric_build_input(self):
        self.assertEqual(6, comparison.LAUNCHER_PIN["build_jobs"])
        self.assertEqual(6, comparison.BUILD_CONTRACT["build_jobs"])
        self.assertTrue(comparison.CONTAINER_COMMAND[2].endswith("m -j6"))
        self.assertEqual(
            "3355443200",
            comparison.CONTAINER_ENVIRONMENT[
                "BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE"])
        self.assertEqual(
            comparison.CONTAINER_ENVIRONMENT[
                "BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE"],
            comparison.LAUNCHER_ENVIRONMENT[
                "BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE"])
        self.assertEqual(
            3355443200,
            comparison.BUILD_CONTRACT["emulator_dynamic_partitions_size"])
        self.assertEqual(
            3363831808,
            comparison.BUILD_CONTRACT["emulator_super_partition_size"])
        self.assertEqual(
            8388608,
            comparison.BUILD_CONTRACT["emulator_super_metadata_reserve"])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wonad-x86-comparison-")
        self.root = Path(self.temporary.name).resolve()
        self.fixture = ReceiptFixture(self.root)
        self.definition_patch = patch.multiple(
            comparison, IMAGE_FILES=self.fixture.IMAGES, OS_PATHS=self.fixture.OS)
        self.definition_patch.start()
        self.container_patch = patch.object(
            comparison, "collect_container_execution",
            side_effect=self.fixture.container_execution)
        self.container_patch.start()

    def tearDown(self):
        self.container_patch.stop()
        self.definition_patch.stop()
        self.temporary.cleanup()

    def test_baseline_capture_and_out_of_band_verification(self):
        receipt, digest, _, _ = self.fixture.capture("baseline")
        value = comparison.verify(receipt, digest)
        self.assertEqual("absent", value["source"]["stage"]["state"])
        self.assertEqual(comparison.verification_tool_ledger(),
                         value["verification_tools"])
        self.assertTrue(all(value["artifacts"]["os_artifacts"][name]["state"] == "absent"
                            for name in comparison.NATIVE_ONLY))
        with self.assertRaisesRegex(comparison.ComparisonError, "authenticated SHA-256"):
            comparison.verify(receipt, "0" * 64)

    def test_custom_receipt_accepts_only_exact_tracked_generated_partition(self):
        source = self.fixture.source_snapshot(None, "custom", None, None, None)
        created = "packages/apps/Launcher3/owned.java"
        source["generated_inputs"][created] = source["owned_tracked_changes"].pop(created)
        comparison.validate_source_shape(source, "custom")

        mutations = {}
        missing = copy.deepcopy(source)
        missing["generated_inputs"].pop(created)
        mutations["missing"] = missing
        duplicate = copy.deepcopy(source)
        duplicate["owned_tracked_changes"][created] = duplicate["generated_inputs"][created]
        mutations["duplicate"] = duplicate
        foreign = copy.deepcopy(source)
        foreign["generated_inputs"]["external/wonad/foreign.kt"] = {
            "sha256": "a" * 64, "size": 1, "mode": 0o644,
        }
        mutations["foreign"] = foreign
        relocated = copy.deepcopy(source)
        relocated["generated_inputs"]["packages/apps/Launcher3/relocated.java"] = \
            relocated["generated_inputs"].pop(created)
        mutations["relocated"] = relocated
        wrong_digest = copy.deepcopy(source)
        wrong_digest["generated_inputs"][created]["sha256"] = "f" * 64
        mutations["wrong digest"] = wrong_digest

        for label, value in mutations.items():
            with self.subTest(label=label), self.assertRaises(comparison.ComparisonError):
                comparison.validate_source_shape(value, "custom")

    def test_receipt_cannot_self_describe_a_different_imported_helper(self):
        receipt, _, _, _ = self.fixture.capture("baseline")
        value = json.loads(receipt.read_text())
        helper = value["verification_tools"]["files"][
            "android/tools/phase1_provenance.py"]
        helper["sha256"] = "f" * 64
        unsigned = dict(value["verification_tools"])
        unsigned.pop("identity_sha256")
        value["verification_tools"]["identity_sha256"] = comparison.canonical_digest(unsigned)
        forged = self.root / "forged-helper-receipt.json"
        write_json(forged, value)
        with self.assertRaisesRegex(comparison.ComparisonError,
                                    "current reviewed tools"):
            comparison.verify(forged, sha(forged.read_bytes()), rehash=False)

    def test_imported_helper_must_originate_at_reviewed_path(self):
        fake = self.root / "phase1_provenance.py"
        fake.write_text("# hostile shadow module\n")
        with patch.object(comparison.provenance, "__file__", str(fake)), \
                self.assertRaisesRegex(comparison.ComparisonError, "reviewed path"):
            comparison.verification_tool_ledger()

    def test_mutated_present_and_receipted_absent_artifacts_fail(self):
        receipt, digest, out, _ = self.fixture.capture("baseline")
        (out / comparison.PROJECT / "system-qemu.img").write_bytes(b"mutated")
        with self.assertRaisesRegex(comparison.ComparisonError, "differs from receipt"):
            comparison.verify(receipt, digest)
        receipt, digest, out, _ = self.fixture.capture("baseline", "two")
        native = out / comparison.PROJECT / self.fixture.OS["os_broker_native"]
        native.parent.mkdir(parents=True, exist_ok=True)
        native.write_bytes(b"stale")
        with self.assertRaisesRegex(comparison.ComparisonError, "absent artifact now exists"):
            comparison.verify(receipt, digest)

    def test_failed_or_ambiguous_log_cannot_receive_a_receipt(self):
        out, log, _ = self.fixture.product("baseline", "failure")
        log.write_text(log.read_text().replace("build completed successfully",
                                              "failed to build some targets"))
        with patch.object(comparison, "capture_builder", return_value=self.fixture.builder), \
                patch.object(comparison, "collect_source_snapshot",
                             side_effect=self.fixture.source_snapshot), \
                self.assertRaisesRegex(comparison.ComparisonError, "clean successful build"):
            comparison.capture("baseline", self.fixture.source, out, log, "failed-container",
                               self.root / "failed.json", None, 4)

    def test_exact_custom_delta_comparison(self):
        baseline, baseline_digest, _, _ = self.fixture.capture("baseline")
        custom, custom_digest, _, _ = self.fixture.capture("custom")
        output = self.root / "comparison.json"
        result, result_digest = comparison.compare(
            baseline, baseline_digest, custom, custom_digest, output)
        self.assertEqual("passed_exact_clean_baseline_custom_delta", result["result"])
        self.assertEqual(result_digest, sha(output.read_bytes()))
        self.assertEqual(sorted(self.fixture.OS), result["changed"]["os_artifacts"])
        self.assertIn("system-qemu.img", result["changed"]["images"])
        self.assertNotIn("build_fingerprint-sdk_phone64_x86_64.txt",
                         result["changed"]["images"])
        self.assertEqual(
            comparison.verification_tool_ledger()["identity_sha256"],
            result["shared"]["verification_tools_sha256"])

    def test_comparison_requires_identical_receipt_verification_tools(self):
        baseline, _, _, _ = self.fixture.capture("baseline")
        custom, _, _, _ = self.fixture.capture("custom")
        baseline_value = json.loads(baseline.read_text())
        custom_value = json.loads(custom.read_text())
        custom_value["verification_tools"] = copy.deepcopy(
            custom_value["verification_tools"])
        custom_value["verification_tools"]["identity_sha256"] = "f" * 64
        with patch.object(comparison, "verify",
                          side_effect=[baseline_value, custom_value]), \
                self.assertRaisesRegex(comparison.ComparisonError,
                                       "receipt verification tools differs"):
            comparison.compare(
                baseline, sha(baseline.read_bytes()), custom, sha(custom.read_bytes()),
                self.root / "must-not-exist.json", rehash=False)

    def test_comparison_rejects_eol_lfs_and_gitlink_representation_drift(self):
        baseline_path, _, _, _ = self.fixture.capture("baseline")
        custom_path, _, _, _ = self.fixture.capture("custom")
        baseline = json.loads(baseline_path.read_text())
        original_custom = json.loads(custom_path.read_text())
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
            "eol": lambda rows: rows["build/make"]["materialized_eol"].update(
                {"eol.txt": eol_row}),
            "lfs": lambda rows: rows["build/make"]["materialized_lfs"].update(
                {"payload.bin": {"sha256": "5" * 64, "size": 9}}),
            "gitlink": lambda rows: rows["build/make"]["gitlinks"]["nested"].update(
                state="empty-directory"),
        }
        for label, mutate in mutations.items():
            with self.subTest(representation=label):
                custom = copy.deepcopy(original_custom)
                mutate(custom["source"]["worktree_materializations"])
                custom["source"]["worktree_materializations_sha256"] = \
                    comparison.canonical_digest(custom["source"]["worktree_materializations"])
                comparison.validate_source_shape(custom["source"], "custom")
                with patch.object(comparison, "verify", side_effect=[baseline, custom]), \
                     self.assertRaisesRegex(comparison.ComparisonError,
                                            "source materialization differs"):
                    comparison.compare(
                        baseline_path, sha(baseline_path.read_bytes()),
                        custom_path, sha(custom_path.read_bytes()),
                        self.root / ("drift-" + label + ".json"), rehash=False)

    def test_existing_comparison_is_authenticated_against_exact_receipts(self):
        baseline, baseline_digest, _, _ = self.fixture.capture("baseline")
        custom, custom_digest, custom_out, _ = self.fixture.capture("custom")
        output = self.root / "comparison.json"
        expected, output_digest = comparison.compare(
            baseline, baseline_digest, custom, custom_digest, output)
        actual, actual_baseline, actual_custom = comparison.verify_comparison(
            output, output_digest, baseline, baseline_digest, custom, custom_digest)
        self.assertEqual(expected, actual)
        self.assertEqual("baseline", actual_baseline["role"])
        self.assertEqual("custom", actual_custom["role"])

        changed = json.loads(output.read_text())
        changed["result"] = "forged"
        forged = self.root / "forged-comparison.json"
        write_json(forged, changed)
        with self.assertRaisesRegex(comparison.ComparisonError, "not the exact result"):
            comparison.verify_comparison(
                forged, sha(forged.read_bytes()), baseline, baseline_digest,
                custom, custom_digest)

        inside = custom_out / "comparison.json"
        inside.write_bytes(output.read_bytes())
        with self.assertRaisesRegex(comparison.ComparisonError, "outside both source and OUT_DIR"):
            comparison.verify_comparison(
                inside, sha(inside.read_bytes()), baseline, baseline_digest,
                custom, custom_digest)

    def test_comparison_rejects_different_pin_even_with_new_authenticated_digest(self):
        baseline, baseline_digest, _, _ = self.fixture.capture("baseline")
        custom, _, _, _ = self.fixture.capture("custom")
        value = json.loads(custom.read_text())
        value["source"]["pin"]["manifest_commit"] = "9" * 40
        changed = self.root / "custom-other-pin.json"
        write_json(changed, value)
        with self.assertRaisesRegex(comparison.ComparisonError, "Invalid source pin"):
            comparison.compare(baseline, baseline_digest, changed, sha(changed.read_bytes()),
                               self.root / "not-created.json")

    def test_duplicate_json_keys_are_rejected(self):
        receipt = self.root / "duplicate.json"
        receipt.write_text('{"schema":1,"schema":1}\n')
        with self.assertRaisesRegex(comparison.ComparisonError, "Duplicate JSON field"):
            comparison.verify(receipt, sha(receipt.read_bytes()), rehash=False)

    def test_custom_capture_requires_untampered_launcher_preflight(self):
        out, log, _ = self.fixture.product("custom", "no-preflight")
        source = self.fixture.sources["custom"]
        with patch.object(comparison, "capture_builder", return_value=self.fixture.builder), \
                patch.object(comparison, "collect_source_snapshot",
                             side_effect=self.fixture.source_snapshot), \
                self.assertRaisesRegex(comparison.ComparisonError, "sidecar is required"):
            comparison.capture("custom", source, out, log, "custom-no-preflight",
                               self.root / "missing-preflight.json",
                               self.root / "development.x509.pem", 4)

        receipt, digest, _, log = self.fixture.capture("custom", "tampered-preflight")
        sidecar = log.with_name(log.name + ".preflight.json")
        record = json.loads(sidecar.read_text())
        record["docker_command"].append("unexpected")
        write_json(sidecar, record)
        with self.assertRaisesRegex(comparison.ComparisonError,
                                    "preflight paths, container, or Docker argv"):
            comparison.verify(receipt, digest)

    def test_launcher_preflight_rejects_coordinated_locality_nonce_label_and_path_tamper(self):
        source = self.fixture.sources["custom"]
        out, log, _ = self.fixture.product("custom", "locality-adversary")
        container = self.fixture.container_execution(
            "custom-locality-adversary", source, out, log, self.fixture.builder)
        self.fixture.write_preflight("custom", source, out, log, container)
        path = log.with_name(log.name + ".preflight.json")
        original = json.loads(path.read_text())
        snapshot = self.fixture.source_snapshot(source, "custom", None,
                                                comparison.LOCK, 4)

        cases = []
        changed = copy.deepcopy(original)
        changed["docker_locality"]["context"]["endpoint"] = "ssh://remote"
        changed["docker_locality_sha256"] = comparison.canonical_digest(
            changed["docker_locality"])
        changed["docker_command"] = comparison.launcher_docker_command(
            source, out, container["name"], changed["attempt_nonce"],
            changed["docker_locality_sha256"])
        relabelled = copy.deepcopy(container)
        relabelled["labels"]["org.wonad.phase1.locality"] = changed["docker_locality_sha256"]
        cases.append((changed, relabelled))
        changed = copy.deepcopy(original); changed["attempt_nonce"] = "short"
        cases.append((changed, container))
        changed = copy.deepcopy(original); changed["location_identity"]["source"]["inode"] += 1
        cases.append((changed, container))
        relabelled = copy.deepcopy(container)
        relabelled["labels"]["org.wonad.phase1.attempt"] = "0" * 64
        cases.append((copy.deepcopy(original), relabelled))

        for record, observed_container in cases:
            with self.subTest(record=record), self.assertRaises(comparison.ComparisonError):
                comparison.validate_launcher_preflight(
                    record, "custom", source, out, log, observed_container,
                    self.fixture.builder, snapshot)

    def test_schema2_launcher_locality_accepts_only_exact_historical_generator(self):
        current = self.fixture.docker_locality()
        self.assertEqual(
            current,
            comparison.validate_launcher_locality(current, preflight_schema=2),
        )

        historical = copy.deepcopy(current)
        historical["generator"] = dict(
            comparison.SCHEMA2_HISTORICAL_LOCALITY_GENERATOR)
        self.assertEqual(
            historical,
            comparison.validate_launcher_locality(historical, preflight_schema=2),
        )

        near_misses = []
        changed = copy.deepcopy(historical)
        changed["generator"]["sha256"] = "0" * 64
        near_misses.append(changed)
        changed = copy.deepcopy(historical)
        changed["generator"]["size"] += 1
        near_misses.append(changed)
        for record in near_misses:
            with self.subTest(generator=record["generator"]), \
                    self.assertRaisesRegex(
                        comparison.ComparisonError,
                        "Launcher Docker CLI/socket/context identity is invalid"):
                comparison.validate_launcher_locality(record, preflight_schema=2)

        with self.assertRaisesRegex(
                comparison.ComparisonError,
                "Historical launcher locality compatibility requires schema 2"):
            comparison.validate_launcher_locality(historical, preflight_schema=3)

    def test_post_hoc_baseline_exception_is_exact_and_discloses_limits(self):
        out, log, _ = self.fixture.product("baseline", "legacy")
        source = self.fixture.sources["baseline"]
        container = self.fixture.container_execution(
            "baseline-legacy", source, out, log, self.fixture.builder)
        snapshot = self.fixture.source_snapshot(
            source, "baseline", None, comparison.LOCK, 4)
        proof = self.root / "attempt4-locality.json"
        write_json(proof, attempt4_locality_record(container, source, out, snapshot))
        proof_digest = sha(proof.read_bytes())
        exception = {
            "id": container["id"], "name": container["name"],
            "source": str(source), "out": str(out), "log": str(log),
        }
        output = self.root / "legacy.json"
        with patch.object(comparison, "capture_builder", return_value=self.fixture.builder), \
                patch.object(comparison, "collect_source_snapshot",
                             side_effect=self.fixture.source_snapshot), \
                patch.object(comparison, "BASELINE_ATTEMPT4", exception), \
                patch.object(comparison, "ATTEMPT4_LOCALITY_PROOF", proof), \
                patch.object(comparison, "ATTEMPT4_LOCALITY_PROOF_SHA256", proof_digest), \
                patch.object(comparison, "ATTEMPT4_LOCALITY_GENERATOR",
                             comparison.ordinary_ref(Path(comparison.locality.__file__))):
            value, receipt_digest = comparison.capture(
                "baseline", source, out, log, "baseline-legacy", output, None, 4)
            verified = comparison.verify(output, receipt_digest, rehash=False)
            self.assertEqual(value["launch_evidence"], verified["launch_evidence"])
            proof.unlink()
            with self.assertRaisesRegex(comparison.ComparisonError,
                                        "failed offline verification"):
                comparison.verify(output, receipt_digest, rehash=False)
        self.assertEqual("post-hoc-pinned-baseline-attempt-4",
                         value["launch_evidence"]["state"])
        self.assertEqual(comparison.ATTEMPT4_LIMITATIONS,
                         value["launch_evidence"]["limitations"])
        self.assertEqual(proof_digest, value["launch_evidence"]
                         ["docker_locality_proof"]["authenticated_sha256"])

    def test_attempt4_locality_proof_is_offline_and_fail_closed(self):
        out, log, _ = self.fixture.product("baseline", "locality-proof")
        source = self.fixture.sources["baseline"]
        container = self.fixture.container_execution(
            "baseline-locality-proof", source, out, log, self.fixture.builder)
        snapshot = self.fixture.source_snapshot(
            source, "baseline", None, comparison.LOCK, 4)
        original = attempt4_locality_record(container, source, out, snapshot)
        proof = self.root / "attempt4-locality-adversarial.json"
        expected_generator = comparison.ordinary_ref(Path(comparison.locality.__file__))

        def collect(record):
            write_json(proof, record)
            digest = sha(proof.read_bytes())
            with patch.object(comparison, "ATTEMPT4_LOCALITY_PROOF", proof), \
                    patch.object(comparison, "ATTEMPT4_LOCALITY_PROOF_SHA256", digest), \
                    patch.object(comparison, "ATTEMPT4_LOCALITY_GENERATOR",
                                 expected_generator):
                return comparison.collect_attempt4_locality_evidence(
                    source, out, container, self.fixture.builder, snapshot)

        # The retained execution record is exited, while the immutable proof
        # records the earlier live sample. No Docker call is needed here.
        self.assertIn("finished_at", container)
        self.assertEqual("running-container-locality-and-bind-identity",
                         collect(copy.deepcopy(original))["scope"])

        absent = self.root / "absent-locality.json"
        with patch.object(comparison, "ATTEMPT4_LOCALITY_PROOF", absent), \
                patch.object(comparison, "ATTEMPT4_LOCALITY_PROOF_SHA256", "0" * 64), \
                self.assertRaisesRegex(comparison.ComparisonError,
                                       "failed offline verification"):
            comparison.collect_attempt4_locality_evidence(
                source, out, container, self.fixture.builder, snapshot)

        write_json(proof, original)
        authenticated = sha(proof.read_bytes())
        proof.write_bytes(proof.read_bytes() + b" ")
        with patch.object(comparison, "ATTEMPT4_LOCALITY_PROOF", proof), \
                patch.object(comparison, "ATTEMPT4_LOCALITY_PROOF_SHA256", authenticated), \
                self.assertRaisesRegex(comparison.ComparisonError,
                                       "failed offline verification"):
            comparison.collect_attempt4_locality_evidence(
                source, out, container, self.fixture.builder, snapshot)

        wrong_container = copy.deepcopy(original)
        wrong_container["container"]["id"] = "0" * 64
        with self.assertRaisesRegex(comparison.ComparisonError, "different container"):
            collect(wrong_container)

        for index, label in ((0, "source"), (1, "OUT")):
            wrong_bind = copy.deepcopy(original)
            replacement = str(self.root / ("wrong-" + label.lower()))
            wrong_bind["bind_identity"][index]["source"] = replacement
            wrong_bind["container"]["mounts"][index]["source"] = replacement
            destination = wrong_bind["bind_identity"][index]["destination"]
            wrong_bind["container"]["binds"][index] = (
                f"{replacement}:{destination}:rw")
            with self.subTest(bind=label), \
                    self.assertRaisesRegex(comparison.ComparisonError,
                                           "different source/OUT binds"):
                collect(wrong_bind)

        wrong_generator = copy.deepcopy(original)
        wrong_generator["generator"] = {"sha256": "f" * 64, "size": 1}
        with self.assertRaisesRegex(comparison.ComparisonError, "wrong generator"):
            collect(wrong_generator)

    def test_siso_closure_requires_generated_link_and_both_executions(self):
        out, _, _ = self.fixture.product("baseline", "bad-siso-main")
        (out / "siso_config/main.star").write_text("not the fixed config\n")
        with self.assertRaisesRegex(comparison.ComparisonError, "main.star differs"):
            comparison.collect_build_engine(self.fixture.sources["baseline"], out)

        out, _, _ = self.fixture.product("baseline", "bad-siso-link")
        (out / "siso_config/main").unlink()
        (out / "siso_config/main").symlink_to("relative/wrong")
        with self.assertRaisesRegex(comparison.ComparisonError, "closure differs"):
            comparison.collect_build_engine(self.fixture.sources["baseline"], out)

        out, _, _ = self.fixture.product("baseline", "bad-siso-final")
        soong = out / "soong.log"
        soong.write_text(soong.read_text().splitlines()[0] + "\n")
        with self.assertRaisesRegex(comparison.ComparisonError,
                                    "bootstrap and final ninja"):
            comparison.collect_build_engine(self.fixture.sources["baseline"], out)

    def test_comparison_rejects_receipt_alias_and_output_inside_build(self):
        baseline, baseline_digest, baseline_out, _ = self.fixture.capture("baseline")
        alias = self.root / "baseline-alias.json"
        alias.hardlink_to(baseline)
        with self.assertRaisesRegex(comparison.ComparisonError, "distinct files"):
            comparison.compare(baseline, baseline_digest, alias, baseline_digest,
                               self.root / "alias-result.json")

        custom, custom_digest, _, _ = self.fixture.capture("custom")
        with self.assertRaisesRegex(comparison.ComparisonError,
                                    "outside both builds and receipts"):
            comparison.compare(baseline, baseline_digest, custom, custom_digest,
                               baseline_out / "comparison.json")

    def test_comparison_reverifies_inputs_immediately_before_write(self):
        baseline, baseline_digest, _, _ = self.fixture.capture("baseline")
        custom, custom_digest, custom_out, _ = self.fixture.capture("custom")
        original = comparison.verify
        calls = 0

        def race(path, digest, *, rehash=True):
            nonlocal calls
            value = original(path, digest, rehash=rehash)
            calls += 1
            if calls == 2:
                artifact = custom_out / comparison.PROJECT / "system-qemu.img"
                artifact.write_bytes(b"changed after initial verification")
            return value

        with patch.object(comparison, "verify", side_effect=race), \
                self.assertRaisesRegex(comparison.ComparisonError, "differs from receipt"):
            comparison.compare(baseline, baseline_digest, custom, custom_digest,
                               self.root / "raced.json")


class X86ContainerEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wonad-x86-container-")
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.out = self.root / "out"
        self.source.mkdir()
        self.out.mkdir()
        self.log = self.root / "build.log"
        self.log.write_bytes(b"exact merged container output\n")
        self.builder = ReceiptFixture.make_builder()
        self.identifier = "a" * 64

    def tearDown(self):
        self.temporary.cleanup()

    def inspect_record(self):
        return {
            "Id": self.identifier,
            "Name": "/wonad-phase1-x86-baseline-2026100600-fixture",
            "Image": self.builder["image"]["id"],
            "Created": "2026-10-10T15:00:00.000000000Z",
            "RestartCount": 0,
            "State": {
                "Status": "exited", "Running": False, "Paused": False,
                "Restarting": False, "Dead": False, "Error": "", "ExitCode": 0,
                "OOMKilled": False,
                "StartedAt": "2026-10-10T15:00:01.000000000Z",
                "FinishedAt": "2026-10-10T15:01:01.000000000Z",
            },
            "Config": {
                "Image": self.builder["reference"], "User": "1000:1000",
                "WorkingDir": "/sources", "Entrypoint": None,
                "Cmd": list(comparison.CONTAINER_COMMAND),
                "Env": [key + "=" + value
                        for key, value in comparison.CONTAINER_ENVIRONMENT.items()],
                "Tty": False, "OpenStdin": False, "AttachStdout": True,
                "AttachStderr": True, "AttachStdin": False,
            },
            "HostConfig": {
                "NetworkMode": "none", "SecurityOpt": ["label=disable"],
                "AutoRemove": False, "Privileged": False, "CapAdd": None,
                "CapDrop": None, "GroupAdd": None, "Devices": [],
                "DeviceRequests": None, "DeviceCgroupRules": None,
                "Tmpfs": None, "ReadonlyRootfs": False,
                "IpcMode": "private", "PidMode": "", "UTSMode": "",
                "UsernsMode": "",
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "Binds": [f"{self.source}:/sources:rw",
                          f"{self.out}:/sources/out:rw"],
            },
            "Mounts": [
                {"Destination": "/sources", "Mode": "rw", "Propagation": "rprivate",
                 "RW": True, "Source": str(self.source), "Type": "bind"},
                {"Destination": "/sources/out", "Mode": "rw", "Propagation": "rprivate",
                 "RW": True, "Source": str(self.out), "Type": "bind"},
            ],
        }

    def collect(self, record, logs=None):
        logs = self.log.read_bytes() if logs is None else logs
        with patch.object(comparison, "inspect_container", return_value=record), \
                patch.object(comparison, "container_logs", return_value=logs):
            return comparison.collect_container_execution(
                self.identifier, self.source, self.out, self.log, self.builder)

    def test_exact_retained_container_is_accepted(self):
        value = self.collect(self.inspect_record())
        self.assertEqual(self.identifier, value["id"])
        self.assertEqual(comparison.ordinary_ref(self.log), value["logs"])

    def test_container_contract_mutations_fail_closed(self):
        mutations = {
            "running": lambda row: row["State"].update(Status="running", Running=True),
            "exit": lambda row: row["State"].update(ExitCode=1),
            "oom": lambda row: row["State"].update(OOMKilled=True),
            "immutable image": lambda row: row.update(Image="sha256:" + "f" * 64),
            "image reference": lambda row: row["Config"].update(Image="other:tag"),
            "user": lambda row: row["Config"].update(User="0:0"),
            "workdir": lambda row: row["Config"].update(WorkingDir="/tmp"),
            "command": lambda row: row["Config"]["Cmd"].append("extra"),
            "environment": lambda row: row["Config"]["Env"].append("EXTRA=1"),
            "network": lambda row: row["HostConfig"].update(NetworkMode="bridge"),
            "security": lambda row: row["HostConfig"].update(SecurityOpt=[]),
            "privileged": lambda row: row["HostConfig"].update(Privileged=True),
            "capability": lambda row: row["HostConfig"].update(CapAdd=["SYS_ADMIN"]),
            "device": lambda row: row["HostConfig"].update(
                Devices=[{"PathOnHost": "/dev/kvm"}]),
            "device cgroup rule": lambda row: row["HostConfig"].update(
                DeviceCgroupRules=["c 10:232 rwm"]),
            "tmpfs": lambda row: row["HostConfig"].update(Tmpfs={"/tmp": "rw"}),
            "restart": lambda row: row.update(RestartCount=1),
            "extra bind": lambda row: row["HostConfig"]["Binds"].append("/tmp:/extra:rw"),
            "mount source": lambda row: row["Mounts"][0].update(Source="/wrong"),
            "attach": lambda row: row["Config"].update(AttachStdout=False),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                record = copy.deepcopy(self.inspect_record())
                mutate(record)
                with self.assertRaises(comparison.ComparisonError):
                    self.collect(record)

    def test_container_log_must_match_build_log_byte_for_byte(self):
        with self.assertRaisesRegex(comparison.ComparisonError, "byte-for-byte"):
            self.collect(self.inspect_record(), b"different output\n")


class SourceAuditFixture:
    def __init__(self, root: Path):
        self.root = root
        self.source = root / "grapheneos"
        self.source.mkdir()
        (self.source / ".repo/projects").mkdir(parents=True)
        (self.source / ".repo/project-objects").mkdir(parents=True)
        self.eol_blob = b"one\ntwo\n"
        self.lfs_payload = b"materialized x86 source payload\n"
        pointer = ("version https://git-lfs.github.com/spec/v1\n"
                   f"oid sha256:{sha(self.lfs_payload)}\n"
                   f"size {len(self.lfs_payload)}\n")
        projects = {
            "frameworks/base": {"owned.java": "baseline\n"},
            "packages/apps/Launcher3": {"owned.java": "baseline\n"},
            "device/generic/goldfish": {"owned.mk": "baseline\n"},
            "build/make": {
                "core.mk": "baseline\n",
                "root.bp": "build root\n",
                "copied.mk": "copied build input\n",
                ".gitattributes": (
                    "eol.txt text=auto eol=crlf\n"
                    "payload.bin filter=lfs diff=lfs merge=lfs -text\n"),
                "eol.txt": self.eol_blob,
                "payload.bin": pointer,
            },
        }
        rows = []
        for name, files in projects.items():
            project_name = "platform/" + name
            revision = init_repo_project(self.source, name, project_name, files)
            if name == "build/make":
                self.gitlink_oid = rows[0][1]
                repository = self.source / name
                subprocess.run([
                    "git", "-C", str(repository), "update-index", "--add", "--cacheinfo",
                    f"160000,{self.gitlink_oid},nested",
                ], check=True)
                subprocess.run(["git", "-C", str(repository), "commit", "-qm", "gitlink"],
                               check=True)
                subprocess.run(["git", "-C", str(repository), "config", "--remove-section", "lfs"],
                               check=False, capture_output=True)
                revision = git(repository, "rev-parse", "HEAD")
            rows.append((name, revision))
        manifest_rows = []
        for name, revision in rows:
            prefix = (f'<project name="platform/{name}" path="{name}" '
                      f'remote="aosp" revision="{revision}"')
            if name == "build/make":
                manifest_rows.append(
                    prefix + '><linkfile src="root.bp" dest="Android.bp"/>'
                    '<copyfile src="copied.mk" dest="copied.mk"/></project>')
            else:
                manifest_rows.append(prefix + "/>")
        default = "<?xml version=\"1.0\"?><manifest>" + "".join(manifest_rows) + \
            "</manifest>\n"
        manifests = self.source / ".repo/manifests"
        manifest_revision = init_git(manifests, {"default.xml": default})
        repo = self.source / ".repo/repo"
        repo_revision = init_git(repo, {"repo": "#!/bin/sh\n"})
        (self.source / ".repo/project.list").write_text(
            "\n".join(name for name, _ in rows) + "\n")
        (self.source / "Android.bp").symlink_to("build/make/root.bp")
        shutil.copy2(self.source / "build/make/copied.mk", self.source / "copied.mk")
        (self.source / "copied.mk").chmod(
            (self.source / "copied.mk").stat().st_mode &
            ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        base_lock = comparison.provenance.load_json(comparison.LOCK)
        self.lock = {
            "schema": 2, "device": "frankel", "release": "2026100600",
            "manifest": {
                "commit": manifest_revision, "tag_object": "a" * 40,
                "default_xml_sha256": sha(default.encode()),
                "default_xml_size": len(default.encode()),
            },
            "repo_tool": {"revision": "refs/tags/test", "commit": repo_revision},
            "emulator_goldfish": {"url": "https://example.invalid/goldfish",
                                  "commit": dict(rows)["device/generic/goldfish"]},
            "builder": base_lock["builder"],
        }
        self.lock_path = root / "lock.json"
        write_json(self.lock_path, self.lock)


class X86SourceAuditTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wonad-x86-source-audit-")
        self.root = Path(self.temporary.name).resolve()
        self.fixture = SourceAuditFixture(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def test_baseline_requires_completely_clean_unstaged_checkout(self):
        value = comparison.collect_source_snapshot(
            self.fixture.source, "baseline", None, self.fixture.lock_path, 4)
        self.assertEqual({"state": "absent"}, value["stage"])
        surprise = self.fixture.source / "build/make/surprise.bp"
        surprise.write_text("unowned\n")
        with self.assertRaisesRegex(comparison.ComparisonError, "not owned"):
            comparison.collect_source_snapshot(
                self.fixture.source, "baseline", None, self.fixture.lock_path, 4)

    def test_manifest_materializations_are_accepted_only_when_exact(self):
        comparison.collect_source_snapshot(
            self.fixture.source, "baseline", None, self.fixture.lock_path, 4)
        link = self.fixture.source / "Android.bp"
        link.unlink()
        link.symlink_to("build/make/copied.mk")
        with self.assertRaisesRegex(comparison.ComparisonError, "linkfile target differs"):
            comparison.collect_source_snapshot(
                self.fixture.source, "baseline", None, self.fixture.lock_path, 4)
        link.unlink()
        link.symlink_to("build/make/root.bp")
        copied = self.fixture.source / "copied.mk"
        copied.chmod(0o644)
        with self.assertRaisesRegex(comparison.ComparisonError, "copyfile differs"):
            comparison.collect_source_snapshot(
                self.fixture.source, "baseline", None, self.fixture.lock_path, 4)

    def test_tracked_source_mutation_after_inventory_is_rejected(self):
        original = comparison.scan_x86_worktree

        def mutate_after_inventory(*args, **kwargs):
            result = original(*args, **kwargs)
            (self.fixture.source / "build/make/root.bp").write_text("raced source\n")
            return result

        with patch.object(comparison, "scan_x86_worktree",
                          side_effect=mutate_after_inventory), \
                self.assertRaisesRegex(comparison.ComparisonError,
                                            "Project worktrees changed"):
            comparison.collect_source_snapshot(
                self.fixture.source, "baseline", None, self.fixture.lock_path, 4)

    def test_snapshot_binds_eol_lfs_and_gitlink_worktree_representations(self):
        project = self.fixture.source / "build/make"
        initial = comparison.collect_source_snapshot(
            self.fixture.source, "baseline", None, self.fixture.lock_path, 4)
        initial_rows = initial["worktree_materializations"]["build/make"]
        self.assertEqual({}, initial_rows["materialized_eol"])
        self.assertEqual({}, initial_rows["materialized_lfs"])
        self.assertEqual("absent", initial_rows["gitlinks"]["nested"]["state"])

        variants = []
        eol = project / "eol.txt"
        eol.write_bytes(self.fixture.eol_blob.replace(b"\n", b"\r\n"))
        variants.append(comparison.collect_source_snapshot(
            self.fixture.source, "baseline", None, self.fixture.lock_path, 4))
        self.assertIn("eol.txt", variants[-1]["worktree_materializations"]
                      ["build/make"]["materialized_eol"])
        eol.write_bytes(self.fixture.eol_blob)

        payload = project / "payload.bin"
        pointer = payload.read_bytes()
        payload.write_bytes(self.fixture.lfs_payload)
        variants.append(comparison.collect_source_snapshot(
            self.fixture.source, "baseline", None, self.fixture.lock_path, 4))
        self.assertIn("payload.bin", variants[-1]["worktree_materializations"]
                      ["build/make"]["materialized_lfs"])
        payload.write_bytes(pointer)

        nested = project / "nested"
        nested.mkdir()
        variants.append(comparison.collect_source_snapshot(
            self.fixture.source, "baseline", None, self.fixture.lock_path, 4))
        self.assertEqual("empty-directory", variants[-1]["worktree_materializations"]
                         ["build/make"]["gitlinks"]["nested"]["state"])

        for variant in variants:
            self.assertNotEqual(initial["worktree_materializations_sha256"],
                                variant["worktree_materializations_sha256"])
            self.assertNotEqual(initial, variant)

    def test_custom_accepts_only_exact_schema4_stage(self):
        marker = {
            "schema": 4, "signer_sha256": "c" * 64,
            "platform_targets": {
                "frameworks_base": {"owned.java": "1" * 64},
                "launcher3": {"created.java": "2" * 64},
                "emulator_goldfish": {"owned.mk": "3" * 64},
            },
            "files": {"Android.bp": "4" * 64},
        }
        actual_hashes = {}
        for prefix, name in (("frameworks/base", "owned.java"),
                             ("packages/apps/Launcher3", "created.java"),
                             ("device/generic/goldfish", "owned.mk")):
            path = self.fixture.source / prefix / name
            path.write_text("custom " + prefix + "\n")
            actual_hashes[(prefix, name)] = sha(path.read_bytes())
        marker["platform_targets"] = {
            "frameworks_base": {"owned.java": actual_hashes[("frameworks/base", "owned.java")]},
            "launcher3": {"created.java": actual_hashes[("packages/apps/Launcher3", "created.java")]},
            "emulator_goldfish": {"owned.mk": actual_hashes[("device/generic/goldfish", "owned.mk")]},
        }
        staged = self.fixture.source / "external/wonad"
        staged.mkdir(parents=True)
        (staged / "Android.bp").write_text("rust_library {}\n")
        marker["files"]["Android.bp"] = sha((staged / "Android.bp").read_bytes())
        write_json(staged / ".wonad-stage.json", marker)
        stage = type("Stage", (), {"verify_stage": staticmethod(lambda _source: marker)})
        certificate = {"der_sha256": "c" * 64}
        with patch.object(comparison, "load_stage_module", return_value=stage), \
                patch.object(comparison.provenance, "public_certificate", return_value=certificate):
            value = comparison.collect_source_snapshot(
                self.fixture.source, "custom", self.root / "public.pem",
                self.fixture.lock_path, 4)
            self.assertEqual("schema-4-owned-stage", value["stage"]["state"])
            created = "packages/apps/Launcher3/created.java"
            self.assertNotIn(created, value["owned_tracked_changes"])
            self.assertIn(created, value["generated_inputs"])
            (self.fixture.source / "build/make/foreign.bp").write_text("foreign\n")
            with self.assertRaisesRegex(comparison.ComparisonError, "not owned"):
                comparison.collect_source_snapshot(
                    self.fixture.source, "custom", self.root / "public.pem",
                    self.fixture.lock_path, 4)

if __name__ == "__main__":
    unittest.main()
