import copy
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import phase1_upstream_test_comparison as comparison
import run_phase1_upstream_tests as runner


SOURCE_FREEZE_VERIFY = runner.source_freeze_verify


class FakeBackend:
    def __init__(self, image, fingerprint, artifacts):
        self.image = copy.deepcopy(image)
        self.fingerprint = fingerprint
        self.artifacts = artifacts
        self.specs = {}
        self.removed = set()
        self.image_inspections = 0
        self.device_round = 0
        self.bad_network = False
        self.timeout = False
        self.reboot_after_first_capture = False
        self.escape_result = False
        self.interrupt_container_start = False
        self.mutate_protected_out = None

    def docker_identity(self):
        return {
            "endpoint": "unix:///run/docker.sock",
            "cli": {"path": "/usr/bin/docker", "sha256": "d" * 64},
            "socket": {"path": "/run/docker.sock", "device": 1, "inode": 2},
            "context": {"name": "default"},
            "daemon": {"id": "test-daemon", "architecture": "x86_64"},
        }

    def inspect_image(self, image_id):
        self.image_inspections += 1
        if image_id != self.image["id"]:
            return {**self.image, "id": image_id}
        return copy.deepcopy(self.image)

    def start_broker(self, adb, workspace, serial):
        adb_dir = workspace / "adb"
        home = workspace / "adb-home"
        temporary = workspace / "adb-tmp"
        for path in (adb_dir, home, temporary):
            path.mkdir(mode=0o700)
        socket = adb_dir / "adb.sock"
        socket.write_text("fake socket\n")
        log = workspace / "adb-server.log"
        log.write_text("private fake adb\n")
        return {
            "socket": socket, "log": log, "pid": 4242,
            "argv": [str(adb), "-L", "localfilesystem:" + str(socket),
                     "--one-device", serial, "nodaemon", "server"],
            "environment": {"HOME": str(home), "TMPDIR": str(temporary),
                            "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        }

    def stop_broker(self, broker):
        broker["socket"].unlink(missing_ok=True)
        broker["stopped"] = True
        broker["exit_code"] = 0
        return broker

    def adb(self, _adb, _broker, _serial, arguments, *, timeout=60):
        del timeout
        arguments = tuple(arguments)
        if arguments == ("get-state",):
            self.device_round += 1
            output, code = "device\n", 0
        elif arguments == ("shell", "getprop", "sys.boot_completed"):
            output, code = "1\n", 0
        elif arguments == ("shell", "getprop", "ro.build.fingerprint"):
            output, code = self.fingerprint + "\n", 0
        elif arguments == ("shell", "getenforce"):
            output, code = "Enforcing\n", 0
        elif arguments == ("shell", "cat", "/proc/sys/kernel/random/boot_id"):
            boot_id = ("87654321-4321-4321-4321-cba987654321"
                       if self.reboot_after_first_capture and self.device_round > 1
                       else "12345678-1234-1234-1234-123456789abc")
            output, code = boot_id + "\n", 0
        elif arguments[:2] == ("shell", "sha256sum"):
            path = arguments[2]
            expected = next(row for row in self.artifacts.values()
                            if "/" + row["path"] == path)
            output, code = expected["sha256"] + "  " + path + "\n", 0
        elif arguments[:3] == ("shell", "sh", "-c"):
            output, code = "", 0
        else:
            raise AssertionError("unexpected adb command " + repr(arguments))
        return subprocess.CompletedProcess(arguments, code, output)

    @staticmethod
    def atest_value(suite):
        return {
            "args": suite,
            "test_runner": {"AtestTradefedTestRunner": {suite: {
                "PASSED": [{"test_name": "Class#method"}],
                "summary": {"PASSED": 1, "FAILED": 0, "IGNORED": 0},
            }}},
            "total_summary": {"PASSED": 1, "FAILED": 0, "IGNORED": 0},
        }

    def run_container(self, spec, stdout_path, timeout):
        del timeout
        self.specs[spec["name"]] = copy.deepcopy(spec)
        if self.mutate_protected_out is not None:
            Path(self.mutate_protected_out, "atest-mutation").write_text("forbidden\n")
            self.mutate_protected_out = None
        if self.interrupt_container_start:
            raise OSError("simulated docker client interruption")
        temporary = Path(spec["workspace"]) / "out/phase1-upstream-tmp" / (
            "result-" + spec["suite"])
        temporary.mkdir(parents=True, exist_ok=True)
        (temporary / "test_result").write_text(json.dumps(self.atest_value(spec["suite"])))
        container_result = ("/test-out/escaped-result" if self.escape_result else
                            "/test-out/out/phase1-upstream-tmp/result-" + spec["suite"])
        stdout_path.write_text(runner.RESULT_PREFIX + container_result + "\ncompleted\n")
        return {"exit_code": 0, "timed_out": self.timeout,
                "docker_argv": runner.container_docker_argv(spec)}

    def inspect_container(self, name):
        spec = self.specs[name]
        identifier = hashlib.sha256(name.encode()).hexdigest()
        environment = sorted(key + "=" + value for key, value in spec["environment"].items())
        return {
            "Id": identifier, "Name": "/" + name, "Image": spec["image"],
            "Config": {
                "Image": spec["image"], "Entrypoint": ["/usr/bin/env"],
                "Cmd": ["-i", *environment, *spec["argv"]], "User": spec["user"],
                "WorkingDir": "/sources", "Env": environment,
                "Labels": {"org.wonad.phase1.nonce": spec["nonce"],
                           "org.wonad.phase1.suite": spec["suite"]},
            },
            "HostConfig": {
                "NetworkMode": "host" if self.bad_network else "none",
                "ReadonlyRootfs": True, "Privileged": False, "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true", "label=disable"],
                "Devices": [], "DeviceRequests": [],
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "AutoRemove": False,
                "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,mode=1777,size=268435456"},
            },
            "Mounts": [
                {"Type": "bind", "Source": spec["source"], "Destination": "/sources",
                 "RW": False, "Propagation": "rprivate"},
                {"Type": "bind", "Source": spec["workspace"], "Destination": "/test-out",
                 "RW": True, "Propagation": "rprivate"},
                {"Type": "bind", "Source": spec["adb_dir"], "Destination": "/adb",
                 "RW": False, "Propagation": "rprivate"},
            ],
            "State": {"Running": False, "Restarting": False, "Dead": False,
                      "OOMKilled": False, "ExitCode": 0},
        }

    def remove_container(self, identity):
        self.removed.add(identity)
        for name in self.specs:
            if hashlib.sha256(name.encode()).hexdigest() == identity:
                self.removed.add(name)

    def container_absent(self, identity):
        return identity in self.removed


class IsolatedUpstreamRunner(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.build_out = self.root / "build-out"
        self.test_out = self.root / "disposable-test-out"
        self.output = self.root / "evidence"
        self.source.mkdir()
        self.build_out.mkdir()
        for relative, content, mode in (
            ("prebuilts/runtime/adb", "fake adb\n", 0o755),
            ("prebuilts/asuite/atest/linux-x86/atest", "fake atest\n", 0o755),
            ("build/make/envsetup.sh", "# envsetup\n", 0o644),
        ):
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            path.chmod(mode)
        (self.source / "build/envsetup.sh").symlink_to("make/envsetup.sh")
        self.build_receipt = self.root / "build-receipt.json"
        self.image = {
            "id": "sha256:" + "a" * 64,
            "repo_digests": ["builder@sha256:" + "a" * 64],
            "os": "linux", "architecture": "amd64", "size": 1234,
            "rootfs": {"type": "layers", "layers": ["sha256:" + "b" * 64]},
            "config": {
                "User": "builder",
                "Env": ["PATH=/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        "LANG=C.UTF-8", "DEBIAN_FRONTEND=noninteractive"],
                "Entrypoint": None, "Cmd": ["bash"], "WorkingDir": "/sources",
                "Labels": None,
            },
        }
        self.fingerprint = "Android/example/emu64x:17/test:userdebug/test-keys"
        self.artifacts = {
            "services": {"path": "system/framework/services.jar", "state": "present",
                         "sha256": "3" * 64, "size": 99},
            "native": {"path": "system/lib64/libwonad.so", "state": "absent"},
        }
        self.receipt = {
            "role": "baseline", "kind": "wonad-x86-build-comparison-input",
            "source": {"pin": {"release": "2026100600", "commit": "1" * 40}},
            "artifacts": {"images": {}, "os_artifacts": self.artifacts},
            "locations": {"source": str(self.source), "out_dir": str(self.build_out)},
            "builder": {"image": self.image}, "fingerprint": self.fingerprint,
        }
        self.build_receipt.write_text(json.dumps(self.receipt, sort_keys=True) + "\n")
        self.build_sha = hashlib.sha256(self.build_receipt.read_bytes()).hexdigest()
        self.build = runner.summarize_build(self.build_receipt, self.receipt, "baseline")
        self.plan_path = self.root / "plan.json"
        self.plan = self.make_plan()
        self.plan_path.write_text(json.dumps(self.plan))
        self.backend = FakeBackend(self.image, self.fingerprint, self.artifacts)
        self.source_verify = mock.patch.object(
            runner, "source_freeze_verify", side_effect=self.fake_source_freeze).start()

    def tearDown(self):
        mock.patch.stopall()
        self.temporary.cleanup()

    @staticmethod
    def fake_source_freeze(receipt, build):
        snapshot = receipt["source"]
        return {
            "schema": runner.SCHEMA, "kind": "wonad-phase1-current-source-freeze",
            "receipt_sha256": build["receipt_sha256"],
            "snapshot_sha256": runner.canonical_digest(snapshot), "snapshot": snapshot,
        }

    def make_plan(self):
        environment = {
            "ANDROID_BUILD_TOP": "{source}", "ANDROID_SERIAL": "emulator-5580",
            "BOARD_EMULATOR_DYNAMIC_PARTITIONS_SIZE": "3355443200",
            "BUILD_DATETIME": "1791386354", "BUILD_HOSTNAME": "fixed-host",
            "BUILD_NUMBER": "wonad.2026100600", "BUILD_USERNAME": "android-user",
            "DEBIAN_FRONTEND": "noninteractive", "ENABLE_ATEST_LOG_UPLOADING": "0",
            "HOME": "{out_dir}/phase1-upstream-home", "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8", "NINJA_HIGHMEM_NUM_JOBS": "1",
            "OUT_DIR": "{out_dir}",
            "PATH": "/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "TMPDIR": "{out_dir}/phase1-upstream-tmp", "TZ": "UTC",
        }
        suites = []
        for name in sorted(comparison.REQUIRED_SUITES):
            suites.append({
                "id": name, "component": "frameworks/base:" + name,
                "format": "atest-json", "minimum_cases": 1,
                "command_record": name + "/command.json",
                "result_files": [name + "/test_result.json"],
                "argv": ["bash", "--noprofile", "--norc", "-c", "atest " + name],
                "cwd": "{source}", "environment": copy.deepcopy(environment),
            })
        return {"schema": 1, "kind": comparison.KIND_PLAN,
                "scope": comparison.SCOPE, "release": "2026100600", "suites": suites}

    def execute(self, *, post=None):
        values = [(self.receipt, self.build),
                  (self.receipt, self.build if post is None else post)]
        with mock.patch.object(runner, "full_build_verify", side_effect=values) as verify:
            result = runner.run(
                "baseline", self.build_receipt, self.build_sha, self.plan_path,
                self.test_out, self.output, "wonad-atest", 60,
                backend=self.backend)
        return result, verify

    def test_success_is_fully_isolated_portable_and_verifiable(self):
        (receipt_path, digest), full_verify = self.execute()
        self.assertEqual(full_verify.call_count, 2)
        self.assertFalse(self.test_out.exists())
        self.assertEqual(self.backend.image_inspections, 2)
        value = runner.verify(receipt_path, digest)
        self.assertEqual(value["schema"], 2)
        self.assertEqual(set(value["suites"]), comparison.REQUIRED_SUITES)
        for reference in self.references(value):
            self.assertFalse(Path(reference["path"]).is_absolute())
        for spec in self.backend.specs.values():
            self.assertEqual(spec["source"], str(self.source))
            self.assertNotIn(str(self.build_out), json.dumps(spec))
            argv = runner.container_docker_argv(spec)
            self.assertIn("none", argv)
            self.assertIn("--read-only", argv)
            self.assertIn("no-new-privileges:true", argv)
            self.assertIn("ALL", argv)
            self.assertIn("localfilesystem:/adb/adb.sock", json.dumps(spec))

    @staticmethod
    def references(value):
        rows = []
        if isinstance(value, dict):
            if set(value) == {"path", "sha256", "size"}:
                rows.append(value)
            else:
                for item in value.values():
                    rows.extend(IsolatedUpstreamRunner.references(item))
        elif isinstance(value, list):
            for item in value:
                rows.extend(IsolatedUpstreamRunner.references(item))
        return rows

    def test_container_network_drift_fails_closed_and_cleans(self):
        self.backend.bad_network = True
        with mock.patch.object(runner, "full_build_verify",
                               return_value=(self.receipt, self.build)):
            with self.assertRaisesRegex(comparison.EvidenceError, "isolation profile"):
                runner.run("baseline", self.build_receipt, self.build_sha, self.plan_path,
                           self.test_out, self.output, "wonad-atest", 60,
                           backend=self.backend)
        self.assertFalse((self.output / "run-receipt.json").exists())
        self.assertFalse(self.test_out.exists())
        self.assertTrue(self.backend.removed)

    def test_interrupted_container_start_removes_exact_created_container(self):
        self.backend.interrupt_container_start = True
        with mock.patch.object(runner, "full_build_verify",
                               return_value=(self.receipt, self.build)):
            with self.assertRaisesRegex(OSError, "simulated"):
                runner.run("baseline", self.build_receipt, self.build_sha, self.plan_path,
                           self.test_out, self.output, "wonad-atest", 60,
                           backend=self.backend)
        self.assertTrue(self.backend.removed)
        self.assertFalse(self.test_out.exists())
        self.assertFalse((self.output / "run-receipt.json").exists())

    def test_timeout_fails_closed_and_cleans(self):
        self.backend.timeout = True
        with mock.patch.object(runner, "full_build_verify",
                               return_value=(self.receipt, self.build)):
            with self.assertRaisesRegex(comparison.EvidenceError, "timed out"):
                runner.run("baseline", self.build_receipt, self.build_sha, self.plan_path,
                           self.test_out, self.output, "wonad-atest", 60,
                           backend=self.backend)
        self.assertFalse((self.output / "run-receipt.json").exists())
        self.assertFalse(self.test_out.exists())

    def test_device_reboot_during_run_fails_closed(self):
        self.backend.reboot_after_first_capture = True
        with mock.patch.object(runner, "full_build_verify",
                               return_value=(self.receipt, self.build)):
            with self.assertRaisesRegex(comparison.EvidenceError, "identity/state changed"):
                runner.run("baseline", self.build_receipt, self.build_sha, self.plan_path,
                           self.test_out, self.output, "wonad-atest", 60,
                           backend=self.backend)
        self.assertFalse((self.output / "run-receipt.json").exists())
        self.assertFalse(self.test_out.exists())

    def test_atest_result_escape_fails_closed(self):
        self.backend.escape_result = True
        with mock.patch.object(runner, "full_build_verify",
                               return_value=(self.receipt, self.build)):
            with self.assertRaisesRegex(comparison.EvidenceError, "escaped"):
                runner.run("baseline", self.build_receipt, self.build_sha, self.plan_path,
                           self.test_out, self.output, "wonad-atest", 60,
                           backend=self.backend)
        self.assertFalse((self.output / "run-receipt.json").exists())
        self.assertFalse(self.test_out.exists())

    def test_post_run_full_rehash_drift_never_seals(self):
        changed = copy.deepcopy(self.build)
        changed["fingerprint"] = "wrong"
        with self.assertRaisesRegex(comparison.EvidenceError, "inputs changed"):
            self.execute(post=changed)
        self.assertFalse((self.output / "run-receipt.json").exists())
        self.assertFalse(self.test_out.exists())

    def test_source_freeze_drift_never_seals(self):
        before = self.fake_source_freeze(self.receipt, self.build)
        after = copy.deepcopy(before)
        after["snapshot"]["pin"]["commit"] = "2" * 40
        after["snapshot_sha256"] = runner.canonical_digest(after["snapshot"])
        self.source_verify.side_effect = [before, after]
        with self.assertRaisesRegex(comparison.EvidenceError, "source freeze changed"):
            self.execute()
        self.assertFalse((self.output / "run-receipt.json").exists())
        self.assertFalse(self.test_out.exists())

    def test_complete_current_out_inventory_detects_added_file(self):
        self.backend.mutate_protected_out = self.build_out
        with self.assertRaisesRegex(comparison.EvidenceError, "OUT inventory changed"):
            self.execute()
        self.assertFalse((self.output / "run-receipt.json").exists())
        self.assertFalse(self.test_out.exists())

    def test_pruned_style_out_does_not_require_missing_intermediates(self):
        retained = self.build_out / "retained.img"
        retained.write_bytes(b"retained only\n")
        config = self.build_out / "siso_config"
        config.mkdir()
        (config / "main.star").write_text("# retained\n")
        (config / "main").symlink_to("main.star")
        (receipt_path, digest), _ = self.execute()
        value = runner.verify(receipt_path, digest)
        inventory = runner.load_portable_json(
            self.output, value["protected_inputs"]["receipted_out"]["before"], "inventory")
        self.assertEqual(inventory["semantics"],
                         "complete-current-tree-including-pruned-state-not-required-intermediates")
        self.assertEqual({row["path"] for row in inventory["entries"]},
                         {".", "retained.img", "siso_config", "siso_config/main",
                          "siso_config/main.star"})

    def test_test_out_may_not_overlap_receipted_out(self):
        test_out = self.build_out / "atest"
        with mock.patch.object(runner, "full_build_verify",
                               return_value=(self.receipt, self.build)):
            with self.assertRaisesRegex(comparison.EvidenceError, "protected"):
                runner.run("baseline", self.build_receipt, self.build_sha, self.plan_path,
                           test_out, self.output, "wonad-atest", 60,
                           backend=self.backend)
        self.assertFalse(test_out.exists())
        self.assertFalse(self.output.exists())

    def test_wrong_installed_builder_image_is_rejected(self):
        self.backend.image["size"] += 1
        with mock.patch.object(runner, "full_build_verify",
                               return_value=(self.receipt, self.build)):
            with self.assertRaisesRegex(comparison.EvidenceError, "builder image differs"):
                runner.run("baseline", self.build_receipt, self.build_sha, self.plan_path,
                           self.test_out, self.output, "wonad-atest", 60,
                           backend=self.backend)
        self.assertFalse(self.output.exists())

    def test_verifier_rejects_tampered_native_result(self):
        (receipt_path, digest), _ = self.execute()
        runner.verify(receipt_path, digest)
        result = next(self.output.glob("suites/*/test_result.json"))
        result.write_text("{}\n")
        with self.assertRaisesRegex(comparison.EvidenceError, "changed"):
            runner.verify(receipt_path, digest)

    def test_schema2_bundle_verifies_after_directory_move(self):
        (receipt_path, digest), _ = self.execute()
        relocated = self.root / "relocated-evidence"
        self.output.rename(relocated)
        moved_receipt = relocated / receipt_path.name
        value = runner.verify(moved_receipt, digest)
        self.assertEqual(value["schema"], 2)

    def test_verifier_rejects_absolute_portable_reference(self):
        (receipt_path, _digest), _ = self.execute()
        value = json.loads(receipt_path.read_text())
        value["generator"]["path"] = str(self.output / "inputs/run_phase1_upstream_tests.py")
        receipt_path.write_text(json.dumps(value))
        digest = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(comparison.EvidenceError, "relative path"):
            runner.verify(receipt_path, digest)

    def test_docker_argv_has_exact_sealing_controls(self):
        broker = {"socket": self.root / "adb/adb.sock"}
        effective, _ = runner.validate_plan_environment(self.plan, self.image, self.build)
        with mock.patch.object(os, "getuid", return_value=1000), \
             mock.patch.object(os, "getgid", return_value=1000):
            spec = runner.make_container_spec(
                self.plan["suites"][0], effective[self.plan["suites"][0]["id"]],
                self.build, self.source, self.test_out, broker, "wonad-atest", "f" * 32)
        argv = runner.container_docker_argv(spec)
        self.assertEqual(argv[:5], ["/usr/bin/docker", "--host", runner.locality.ENDPOINT,
                                    "run", "--name"])
        self.assertIn("--network", argv)
        self.assertIn("none", argv)
        self.assertEqual(sum("dst=/test-out" in item for item in argv), 1)
        writable_mount = next(item for item in argv if "dst=/test-out" in item)
        self.assertIn(",readonly=false,", writable_mount)
        self.assertNotIn(",rw,", writable_mount)
        self.assertNotIn(str(self.build_out), "\n".join(argv))

    def test_full_build_verifier_always_requests_rehash(self):
        module = mock.Mock()
        module.verify.return_value = self.receipt
        with mock.patch.object(comparison, "peek_build_kind",
                               return_value="wonad-x86-build-comparison-input"), \
             mock.patch.object(comparison, "load_module", return_value=module):
            _receipt, value = runner.full_build_verify(
                self.build_receipt, self.build_sha, "baseline")
        module.verify.assert_called_once_with(self.build_receipt, self.build_sha, rehash=True)
        self.assertEqual(value, self.build)

    def test_cleanup_refuses_special_entries(self):
        workspace = self.root / "cleanup-test"
        workspace.mkdir(mode=0o700)
        nonce = "9" * 32
        (workspace / ".wonad-atest-owner").write_text(nonce + "\n")
        node = workspace.lstat()
        ownership = {"path": str(workspace), "device": node.st_dev, "inode": node.st_ino,
                     "uid": node.st_uid, "gid": node.st_gid, "nonce": nonce}
        os.mkfifo(workspace / "unexpected-fifo")
        with self.assertRaisesRegex(comparison.EvidenceError, "special entry"):
            runner.cleanup_workspace(workspace, ownership)
        self.assertTrue(workspace.exists())

    def test_source_tool_accepts_only_source_internal_symlinks(self):
        record = runner.source_tool(self.source / "build/envsetup.sh", self.source, "envsetup")
        self.assertEqual(record["link_target"], "make/envsetup.sh")
        outside = self.root / "outside-tool"
        outside.write_text("outside\n")
        bad = self.source / "bad-tool"
        bad.symlink_to(outside)
        with self.assertRaisesRegex(comparison.EvidenceError, "escapes source"):
            runner.source_tool(bad, self.source, "bad tool")

    def test_source_freeze_recollector_uses_authenticated_custom_stage_certificate(self):
        certificate = self.source / "external/wonad/WonadReleaseCertificate.der"
        certificate.parent.mkdir(parents=True)
        certificate.write_bytes(b"public certificate fixture\n")
        reference = runner.sha256_file(certificate, allow_empty=False)
        receipt = copy.deepcopy(self.receipt)
        receipt["role"] = "custom"
        receipt["source"]["stage"] = {"marker": {"signer_certificate": {
            "path": "WonadReleaseCertificate.der", **reference}}}
        observed = receipt["source"]
        trace = self.root / "source-freeze-child-arguments.json"
        parent_pid = os.getpid()
        def collect(source, role, selected_certificate, lock, jobs):
            trace.write_text(json.dumps({
                "pid": os.getpid(), "source": str(source), "role": role,
                "certificate": str(selected_certificate), "lock": str(lock),
                "jobs": jobs,
            }, sort_keys=True))
            return observed
        module = mock.Mock()
        module.LOCK = self.root / "lock.json"
        module.collect_source_snapshot.side_effect = collect
        build = copy.deepcopy(self.build)
        with mock.patch.object(comparison, "load_module", return_value=module):
            value = SOURCE_FREEZE_VERIFY(receipt, build)
        arguments = json.loads(trace.read_text())
        self.assertNotEqual(arguments["pid"], parent_pid)
        self.assertEqual(arguments["source"], str(self.source))
        self.assertEqual(arguments["role"], "custom")
        self.assertEqual(arguments["certificate"], str(certificate))
        self.assertEqual(arguments["lock"], str(module.LOCK))
        self.assertEqual(arguments["jobs"], min(72, max(1, os.cpu_count() or 1)))
        self.assertEqual(value["snapshot"], observed)
        self.assertEqual(value["snapshot_sha256"], runner.canonical_digest(observed))
        self.assertNotIn("jobs", value)

    def test_source_freeze_child_failure_and_snapshot_mismatch_fail_closed(self):
        module = mock.Mock()
        module.LOCK = self.root / "lock.json"
        with mock.patch.object(comparison, "load_module", return_value=module):
            module.collect_source_snapshot.side_effect = RuntimeError("collector exploded")
            with self.assertRaisesRegex(
                    comparison.EvidenceError,
                    r"collector child failed \(RuntimeError\): collector exploded"):
                SOURCE_FREEZE_VERIFY(self.receipt, self.build)

            module.collect_source_snapshot.side_effect = None
            module.collect_source_snapshot.return_value = {"wrong": "snapshot"}
            with self.assertRaisesRegex(
                    comparison.EvidenceError,
                    "Current source worktrees differ from the receipted source freeze"):
                SOURCE_FREEZE_VERIFY(self.receipt, self.build)

    def test_source_freeze_child_rejects_malformed_truncated_and_wrong_ipc(self):
        module = mock.Mock()
        module.LOCK = self.root / "lock.json"
        wrong = runner._source_freeze_ipc_bytes({
            "schema": runner.SOURCE_FREEZE_IPC_SCHEMA,
            "status": "ok", "snapshot": self.receipt["source"], "extra": True,
        })
        cases = (
            (b"not-json", "Malformed source-freeze child IPC"),
            (b'{"schema":1', "Malformed source-freeze child IPC"),
            (wrong, "Invalid successful source-freeze child IPC"),
            (b"", "Source-freeze child returned no IPC evidence"),
        )
        for payload, message in cases:
            with self.subTest(payload=payload[:24]):
                def child(descriptor, *_arguments, payload=payload):
                    if payload:
                        os.write(descriptor, payload)
                    return 0 if payload else 23
                with mock.patch.object(comparison, "load_module", return_value=module), \
                     mock.patch.object(runner, "_source_freeze_child", side_effect=child), \
                     self.assertRaisesRegex(comparison.EvidenceError, message):
                    SOURCE_FREEZE_VERIFY(self.receipt, self.build)

    def test_source_freeze_child_rejects_oversized_ipc(self):
        module = mock.Mock()
        module.LOCK = self.root / "lock.json"
        def child(descriptor, *_arguments):
            os.write(descriptor, b"x" * 257)
            return 0
        with mock.patch.object(comparison, "load_module", return_value=module), \
             mock.patch.object(runner, "SOURCE_FREEZE_IPC_MAX", 128), \
             mock.patch.object(runner, "_source_freeze_child", side_effect=child), \
             self.assertRaisesRegex(comparison.EvidenceError,
                                    "IPC exceeds its bounded limit"):
            SOURCE_FREEZE_VERIFY(self.receipt, self.build)

    def test_source_freeze_interrupt_during_read_kills_reaps_and_preserves_identity(self):
        module = mock.Mock()
        module.LOCK = self.root / "lock.json"
        module.collect_source_snapshot.return_value = self.receipt["source"]
        interrupted = KeyboardInterrupt("operator interrupt during source IPC read")
        killed = []
        reaped = []
        terminate = runner._terminate_source_freeze_child
        reap = runner._reap_source_freeze_child_uninterruptibly
        def record_terminate(pid):
            killed.append(pid)
            return terminate(pid)
        def record_reap(pid):
            reaped.append(pid)
            return reap(pid)
        with mock.patch.object(comparison, "load_module", return_value=module), \
             mock.patch.object(runner.os, "read", side_effect=interrupted), \
             mock.patch.object(runner, "_terminate_source_freeze_child",
                               side_effect=record_terminate), \
             mock.patch.object(runner, "_reap_source_freeze_child_uninterruptibly",
                               side_effect=record_reap), \
             self.assertRaises(KeyboardInterrupt) as caught:
            SOURCE_FREEZE_VERIFY(self.receipt, self.build)
        self.assertIs(caught.exception, interrupted)
        self.assertEqual(killed, reaped)
        self.assertEqual(len(killed), 1)
        with self.assertRaises(ChildProcessError):
            os.waitpid(killed[0], os.WNOHANG)

    def test_source_freeze_interrupt_during_wait_kills_reaps_and_preserves_identity(self):
        module = mock.Mock()
        module.LOCK = self.root / "lock.json"
        module.collect_source_snapshot.return_value = self.receipt["source"]
        interrupted = SystemExit("operator exit during source child wait")
        killed = []
        reaped = []
        wait = runner._wait_source_freeze_child
        terminate = runner._terminate_source_freeze_child
        reap = runner._reap_source_freeze_child_uninterruptibly
        wait_calls = 0
        def interrupt_once(pid):
            nonlocal wait_calls
            wait_calls += 1
            if wait_calls == 1:
                raise interrupted
            return wait(pid)
        def record_terminate(pid):
            killed.append(pid)
            return terminate(pid)
        def record_reap(pid):
            reaped.append(pid)
            return reap(pid)
        with mock.patch.object(comparison, "load_module", return_value=module), \
             mock.patch.object(runner, "_wait_source_freeze_child",
                               side_effect=interrupt_once), \
             mock.patch.object(runner, "_terminate_source_freeze_child",
                               side_effect=record_terminate), \
             mock.patch.object(runner, "_reap_source_freeze_child_uninterruptibly",
                               side_effect=record_reap), \
             self.assertRaises(SystemExit) as caught:
            SOURCE_FREEZE_VERIFY(self.receipt, self.build)
        self.assertIs(caught.exception, interrupted)
        self.assertEqual(killed, reaped)
        self.assertEqual(len(killed), 1)
        with self.assertRaises(ChildProcessError):
            os.waitpid(killed[0], os.WNOHANG)

    def test_source_freeze_interrupt_after_wait_reaped_does_not_kill_reused_pid(self):
        module = mock.Mock()
        module.LOCK = self.root / "lock.json"
        module.collect_source_snapshot.return_value = self.receipt["source"]
        interrupted = KeyboardInterrupt("interrupt after wait reaped collector")
        waited = []
        wait = runner._wait_source_freeze_child

        def reap_then_interrupt(pid):
            wait(pid)
            waited.append(pid)
            raise interrupted

        with mock.patch.object(comparison, "load_module", return_value=module), \
             mock.patch.object(runner, "_wait_source_freeze_child",
                               side_effect=reap_then_interrupt), \
             mock.patch.object(runner, "_terminate_source_freeze_child") as terminate, \
             self.assertRaises(KeyboardInterrupt) as caught:
            SOURCE_FREEZE_VERIFY(self.receipt, self.build)
        self.assertIs(caught.exception, interrupted)
        self.assertEqual(len(waited), 1)
        terminate.assert_not_called()
        with self.assertRaises(ChildProcessError):
            os.waitpid(waited[0], os.WNOHANG)

    def test_source_freeze_collector_dies_if_exact_parent_is_killed(self):
        child_record = self.root / "parent-death-collector.pid"
        supervisor = os.fork()
        if supervisor == 0:
            module = mock.Mock()
            module.LOCK = self.root / "lock.json"
            def collect(*_arguments):
                child_record.write_text(str(os.getpid()) + "\n")
                while True:
                    time.sleep(1)
            module.collect_source_snapshot.side_effect = collect
            try:
                runner._isolated_source_snapshot(
                    module, self.source, "baseline", None, 1)
            finally:
                os._exit(126)

        collector = None
        collector_pidfd = None
        supervisor_reaped = False
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not child_record.exists():
                time.sleep(0.01)
            self.assertTrue(child_record.is_file(), "collector child never started")
            collector = int(child_record.read_text().strip())
            self.assertGreater(collector, 1)
            collector_pidfd = os.pidfd_open(collector, 0)
            collector_events = select.poll()
            collector_events.register(collector_pidfd, select.POLLIN)
            self.assertEqual(collector_events.poll(0), [],
                             "collector exited before its parent was killed")
            status_lines = Path(f"/proc/{collector}/status").read_text().splitlines()
            parent_lines = [line for line in status_lines if line.startswith("PPid:")]
            self.assertEqual(parent_lines, [f"PPid:\t{supervisor}"])
            self.assertEqual(collector_events.poll(0), [],
                             "collector exited during pidfd identity validation")
            os.kill(supervisor, signal.SIGKILL)
            found, status = os.waitpid(supervisor, 0)
            supervisor_reaped = True
            self.assertEqual(found, supervisor)
            self.assertTrue(os.WIFSIGNALED(status))
            self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)

            # A pidfd continues to name this exact process even after numeric
            # PID reuse. It becomes readable as soon as the collector exits,
            # including while an init/subreaper still retains its zombie.
            events = collector_events.poll(5000)
            self.assertTrue(events, "collector survived exact parent death")
            self.assertEqual(events[0][0], collector_pidfd)
            self.assertTrue(events[0][1] & select.POLLIN)
        finally:
            if not supervisor_reaped:
                runner._cleanup_source_freeze_child_uninterruptibly(supervisor)
            if collector_pidfd is not None:
                try:
                    exact_events = select.poll()
                    exact_events.register(collector_pidfd, select.POLLIN)
                    if not exact_events.poll(0):
                        signal.pidfd_send_signal(
                            collector_pidfd, signal.SIGKILL, None, 0)
                except ProcessLookupError:
                    pass
                finally:
                    os.close(collector_pidfd)

    def test_execution_target_records_cover_all_three_classes(self):
        emulator = copy.deepcopy(next(row for row in self.plan["suites"]
                                      if row["id"] == "input_atms"))
        aosp_host = copy.deepcopy(emulator)
        del aosp_host["environment"]["ANDROID_SERIAL"]
        graphene_host = copy.deepcopy(aosp_host)
        graphene_host["component"] = "vendor/grapheneos/tests:HostTests"
        self.assertEqual(runner.classify_suite(emulator),
                         {"platform": "aosp", "execution": "emulator-device"})
        self.assertEqual(runner.classify_suite(aosp_host),
                         {"platform": "aosp", "execution": "host"})
        self.assertEqual(runner.classify_suite(graphene_host),
                         {"platform": "grapheneos", "execution": "host"})


if __name__ == "__main__":
    unittest.main()
