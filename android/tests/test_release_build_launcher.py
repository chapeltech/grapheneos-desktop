import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ANDROID = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "run_release_build_tested", ANDROID / "tools/run_release_build.py")
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)
LOCK = json.loads((ANDROID / "grapheneos.lock.json").read_text())


def builder_record():
    image = {
        "id": launcher.IMAGE_ID,
        "repo_digests": ["wonad-grapheneos-builder@" + launcher.IMAGE_ID],
        "os": "linux", "architecture": "amd64", "size": 1,
        "rootfs": {"type": "layers", "layers": ["sha256:" + "1" * 64]},
        "config": {
            "User": "builder",
            "Env": ["PATH=/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "Entrypoint": None, "Cmd": ["bash"], "WorkingDir": "/sources",
            "Labels": None,
        },
    }
    return {
        "schema": launcher.provenance.BUILDER_SCHEMA,
        "kind": "wonad-phase1-builder", "reference": launcher.IMAGE_REFERENCE,
        "image": image,
        "identity_sha256": launcher.provenance.canonical_digest(image),
        "dockerfile": launcher.provenance.file_ref(ANDROID / "platform/Dockerfile"),
        "runtime": {"node": LOCK["builder"]["node_version"],
                    "yarn": LOCK["builder"]["yarn_version"]},
    }


class ReleaseBuildLauncher(unittest.TestCase):
    def test_shiba_container_name_is_rejected(self):
        with self.assertRaises(launcher.ReleaseBuildError):
            launcher.validate_container_name(
                "wonad-phase1-shiba-release-2026101000-test", "2026101000")
        self.assertEqual("wonad-phase1-frankel-release-2026101000-test",
                         launcher.validate_container_name(
                             "wonad-phase1-frankel-release-2026101000-test", "2026101000"))

    def test_command_is_immutable_sanitized_and_has_no_host_fallback(self):
        environment = launcher.process_environment("2026101000", "1791288000", 1)
        inside = launcher.inner_command(8, "1" * 64)
        process = launcher.process_command(environment, inside)
        command = launcher.docker_command(
            Path("/build/source"), Path("/build/out"),
            "wonad-phase1-frankel-release-2026101000-test", "1" * 64,
            "2" * 64, process)
        self.assertEqual(str(launcher.locality.DOCKER), command[0])
        self.assertEqual(launcher.locality.ENDPOINT, command[2])
        self.assertIn("--platform", command)
        self.assertIn(launcher.PLATFORM, command)
        self.assertIn("create", command)
        self.assertIn("--network", command)
        self.assertIn("none", command)
        self.assertEqual("json-file", command[command.index("--log-driver") + 1])
        self.assertEqual(3, command.count("--log-opt"))
        self.assertIn("mode=blocking", command)
        self.assertIn("max-size=1t", command)
        self.assertIn("max-file=1", command)
        self.assertNotIn("--rm", command)
        self.assertIn(launcher.IMAGE_ID, command)
        self.assertNotIn(launcher.IMAGE_REFERENCE, command)
        self.assertEqual("-i", command[command.index(launcher.IMAGE_ID) + 1])
        self.assertEqual("/tmp/wonad-home", environment["HOME"])
        self.assertIn("install -d -m 0700 -- /tmp/wonad-home", inside)
        self.assertIn("1000:1000:700:directory", inside)
        self.assertLess(inside.index("install -d -m 0700"),
                        inside.index("while [[ ! -f"))
        self.assertLess(inside.index("1000:1000:700:directory"),
                        inside.index("source build/envsetup.sh"))
        self.assertIn("script/finalize.sh", inside)
        self.assertIn("m -j8", inside)

        driver = (ANDROID / "platform/release-build.sh").read_text()
        self.assertIn('run_release_build.py" run', driver)
        self.assertNotIn("source build/envsetup.sh", driver)
        self.assertNotIn('m -j"$jobs"', driver)

    def test_final_container_accepts_only_inspect_mount_order_variation(self):
        source = Path("/build/source")
        out = Path("/build/out")
        name = "wonad-phase1-frankel-release-2026101000-test"
        nonce = "1" * 64
        locality_sha256 = "2" * 64
        process = launcher.process_command(
            launcher.process_environment("2026101000", "1791288000", 1),
            launcher.inner_command(8, nonce))

        def info():
            mounts = [
                {"Type": "bind", "Source": str(source),
                 "Destination": launcher.CONTAINER_SOURCE, "Mode": "rw",
                 "RW": True, "Propagation": "rprivate"},
                {"Type": "bind", "Source": str(out),
                 "Destination": launcher.CONTAINER_OUT, "Mode": "rw",
                 "RW": True, "Propagation": "rprivate"},
            ]
            mounts.reverse()
            return {
                "Id": "a" * 64, "Name": "/" + name,
                "Image": launcher.IMAGE_ID, "Created": "created",
                "State": {"Status": "exited", "ExitCode": 0, "Running": False,
                          "Paused": False, "Restarting": False, "Dead": False,
                          "OOMKilled": False, "Error": "", "StartedAt": "started",
                          "FinishedAt": "finished"},
                "Config": {"Image": launcher.IMAGE_ID, "User": "1000:1000",
                           "WorkingDir": launcher.CONTAINER_SOURCE,
                           "Entrypoint": ["/usr/bin/env"], "Cmd": process,
                           "Labels": {launcher.ATTEMPT_LABEL: nonce,
                                      launcher.LOCALITY_LABEL: locality_sha256}},
                "HostConfig": {
                    "Binds": [f"{source}:{launcher.CONTAINER_SOURCE}:rw",
                              f"{out}:{launcher.CONTAINER_OUT}:rw"],
                    "NetworkMode": "none", "AutoRemove": False,
                    "Privileged": False, "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges", "label=disable"],
                    "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                    "LogConfig": {"Type": "json-file", "Config": {
                        "max-file": "1", "max-size": "1t", "mode": "blocking"}},
                },
                "Mounts": mounts,
            }

        reordered = info()
        reordered["HostConfig"]["Binds"].reverse()
        expected = launcher.container_evidence(
            reordered, name=name, source=source, out=out, nonce=nonce,
            locality_sha256=locality_sha256, process=process)
        self.assertEqual([launcher.CONTAINER_SOURCE, launcher.CONTAINER_OUT],
                         [row["destination"] for row in expected["mounts"]])

        mutations = [
            lambda row: row["HostConfig"]["Binds"].__setitem__(
                0, "/foreign:/sources:rw"),
            lambda row: row["HostConfig"]["Binds"].__setitem__(
                0, f"{source}:{launcher.CONTAINER_SOURCE}:ro"),
            lambda row: row["HostConfig"]["Binds"].__setitem__(0, "malformed"),
            lambda row: row["HostConfig"]["Binds"].__setitem__(0, 1),
            lambda row: row["HostConfig"]["Binds"].__setitem__(
                1, f"{source}:{launcher.CONTAINER_OUT}:rw"),
            lambda row: row["HostConfig"]["Binds"].__setitem__(
                1, f"{out}:{launcher.CONTAINER_SOURCE}:rw"),
            lambda row: row["HostConfig"]["Binds"].pop(),
            lambda row: row["HostConfig"]["Binds"].append("/extra:/extra:rw"),
            lambda row: row["Mounts"][0].update(RW=1),
            lambda row: row["Mounts"][1].update(
                Source=row["Mounts"][0]["Source"]),
            lambda row: row["Mounts"].__setitem__(
                1, copy.deepcopy(row["Mounts"][0])),
            lambda row: row["Mounts"].__setitem__(0, "malformed"),
            lambda row: row["Mounts"][0].update(Unexpected="field"),
            lambda row: row["Mounts"].append(copy.deepcopy(row["Mounts"][0])),
            lambda row: row["HostConfig"]["LogConfig"]["Config"].update(
                {"max-size": "10m"}),
        ]
        for mutate in mutations:
            value = info()
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(
                    launcher.ReleaseBuildError):
                launcher.container_evidence(
                    value, name=name, source=source, out=out, nonce=nonce,
                    locality_sha256=locality_sha256, process=process)

    def test_builder_tag_drift_and_wrong_platform_fail_closed(self):
        builder = builder_record()
        expected = builder["image"]
        with patch.object(launcher, "inspect_image", side_effect=[expected, expected]):
            self.assertEqual(expected, launcher.verify_local_builder(builder, {}))

        drift = copy.deepcopy(expected)
        drift["id"] = "sha256:" + "0" * 64
        with patch.object(launcher, "inspect_image", side_effect=[expected, drift]), \
                self.assertRaisesRegex(launcher.ReleaseBuildError, "tag.*immutable image ID"):
            launcher.verify_local_builder(builder, {})

        wrong_platform = copy.deepcopy(expected)
        wrong_platform["architecture"] = "arm64"
        wrong_builder = copy.deepcopy(builder)
        wrong_builder["image"] = wrong_platform
        with patch.object(launcher, "inspect_image",
                          side_effect=[wrong_platform, wrong_platform]), \
                self.assertRaisesRegex(launcher.ReleaseBuildError, "wrong.*platform"):
            launcher.verify_local_builder(wrong_builder, {})

    def test_remote_daemon_or_context_override_is_rejected(self):
        base = {"HOME": "/tmp/home", "PATH": "/usr/bin:/bin"}
        with patch.object(launcher.shutil, "which", return_value=str(launcher.locality.DOCKER)):
            for name, value in (("DOCKER_HOST", "tcp://remote:2375"),
                                ("DOCKER_CONTEXT", "remote"),
                                ("CONTAINER_HOST", "ssh://remote")):
                with self.subTest(name=name), self.assertRaisesRegex(
                        launcher.ReleaseBuildError, "endpoint/configuration"):
                    launcher.validate_inherited_environment({**base, name: value})

    def test_preflight_input_mutation_cannot_mint_success_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "lock.json"
            builder = root / "builder.json"
            source = root / "source.json"
            lock.write_text("lock\n")
            builder.write_text("builder\n")
            source.write_text("source\n")
            record = {
                "lock": launcher.provenance.file_ref(lock),
                "builder_record": launcher.provenance.file_ref(builder),
                "source_record": launcher.provenance.file_ref(source),
            }
            with patch.object(launcher, "LOCK", lock):
                self.assertEqual(
                    {name: record[name] for name in record},
                    launcher.recheck_input_identities(record, builder, source))
                builder.write_text("mutated builder\n")
                with self.assertRaisesRegex(
                        launcher.ReleaseBuildError, "changed during release build"):
                    launcher.recheck_input_identities(record, builder, source)

    def _failed_attempt(self, *, docker_status, missing_container=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source = root / "source"
        source.mkdir()
        out = root / "out"
        log = root / "build.log"
        evidence = root / "execution.json"
        preflight = root / "execution.json.preflight.json"
        locality_record = {"fixture": "local", "daemon": {"root_dir": str(root)}}
        def disk_observation(clock):
            def row(minimum):
                return {"identity": launcher.directory_identity(root, "fixture parent"),
                        "available_blocks": minimum // 4096, "fragment_size": 4096,
                        "available_bytes": minimum}
            return {"observed_monotonic_ns": clock, "filesystems": {
                "out_parent": row(launcher.DISK_ADMISSION["out_free_bytes"]),
                "docker_root": row(launcher.DISK_ADMISSION["docker_free_bytes"])}}
        nonce = "1" * 64
        record = {
            "location_identity": {
                "source": {"fixture": True},
                "log_parent": launcher.directory_identity(root, "fixture parent"),
                "evidence_parent": launcher.directory_identity(root, "fixture parent"),
            },
            "docker_locality": locality_record, "container_name": "fixture",
            "attempt_nonce": nonce, "docker_locality_sha256": "2" * 64,
            "process_environment": {}, "inner_command": "fixture", "builder": {},
            "host_disk_admission": {"before_source_audit": disk_observation(1)},
        }
        bind_proof = root / "execution.json.bind-proof.json"
        prepared = (record, source, out, log, evidence, preflight, bind_proof,
                    ["/usr/bin/docker", "fixture"], {"PATH": "/usr/bin:/bin"})
        patches = [
            patch.object(launcher, "prepare", return_value=prepared),
            patch.object(launcher, "docker_host_identity", return_value=locality_record),
            patch.object(launcher, "observe_host_disk_admission",
                         return_value=disk_observation(2)),
            patch.object(launcher, "verify_source_freeze", return_value={}),
            patch.object(launcher, "create_container", return_value="a" * 64),
            patch.object(launcher, "start_container", return_value={}),
            patch.object(launcher, "capture_live_bind_proof", return_value={"fixture": True}),
            patch.object(launcher, "release_gate", return_value=out / "already-consumed"),
            patch.object(launcher, "wait_container", return_value=docker_status),
            patch.object(launcher, "write_container_log",
                         side_effect=lambda _name, path, _env: path.write_bytes(b"fixture log")),
            patch.object(launcher, "stop_failed_container", return_value=None),
        ]
        if missing_container:
            patches.extend([
                patch.object(launcher, "docker_host_identity", return_value=locality_record),
                patch.object(launcher, "verify_local_builder", return_value={}),
                patch.object(launcher, "inspect_container",
                             side_effect=launcher.ReleaseBuildError(
                                 "Retained build container is missing")),
            ])
        for active in patches:
            active.start()
            self.addCleanup(active.stop)
        with self.assertRaises(launcher.ReleaseBuildError):
            launcher.run_build(SimpleNamespace(
                source_record=root / "source.json", builder_record=root / "builder.json"))
        self.assertFalse(evidence.exists(), "failed execution minted success evidence")
        self.assertTrue(preflight.exists())
        self.assertTrue(log.exists())

    def test_claimed_builder_without_successful_execution_cannot_mint_evidence(self):
        self._failed_attempt(docker_status=19)

    def test_missing_retained_container_cannot_mint_evidence(self):
        self._failed_attempt(docker_status=0, missing_container=True)

    def test_consumption_removes_full_id_and_proves_id_and_name_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            out = root / "out"
            source.mkdir()
            out.mkdir()
            evidence = root / "execution.json"
            evidence.write_text("execution evidence\n")
            consumption = root / "consumption.json"
            container_id = "a" * 64
            container_name = "wonad-phase1-frankel-release-2026101000-fixture"
            locality_record = {
                "daemon": {"id": "daemon"},
                "host_boot_id": "12345678-1234-1234-1234-123456789012",
            }
            record = {
                "locations": {"source": str(source), "out": str(out)},
                "container": {"id": container_id, "name": container_name},
                "docker_locality": locality_record,
                "docker_locality_sha256": "b" * 64,
                "contract": {"build_number": "2026101000"},
            }
            removed = subprocess.CompletedProcess(
                ["docker", "rm", container_id], 0, stdout=container_id + "\n", stderr="")
            with patch.object(launcher, "docker_host_identity",
                              return_value=locality_record), \
                    patch.object(launcher, "run_docker", return_value=removed) as docker, \
                    patch.object(launcher, "container_absent", return_value=True) as absent:
                value, reference = launcher.consume_container(
                    record, evidence, consumption, {"PATH": "/usr/bin:/bin"})
            self.assertEqual("consumed-confirmed-absent", value["status"])
            self.assertEqual(launcher.provenance.file_ref(consumption), reference)
            self.assertEqual(["container", "rm", container_id], docker.call_args.args[0])
            self.assertEqual([((container_id, {"PATH": "/usr/bin:/bin"}), {}),
                              ((container_name, {"PATH": "/usr/bin:/bin"}), {})],
                             absent.call_args_list)

            with patch.object(launcher, "docker_host_identity",
                              return_value=locality_record), \
                    patch.object(launcher, "run_docker") as docker, \
                    patch.object(launcher, "container_absent", return_value=True):
                launcher.consume_container(record, evidence, consumption,
                                           {"PATH": "/usr/bin:/bin"})
            docker.assert_not_called()

    def test_absent_container_requires_exact_empty_inspect_array_and_diagnostic(self):
        identity = "a" * 64
        accepted = subprocess.CompletedProcess(
            ["docker", "inspect", identity], 1, stdout="[]\n",
            stderr=f"Error response from daemon: No such container: {identity}\n")
        with patch.object(launcher, "run_docker", return_value=accepted):
            self.assertTrue(launcher.container_absent(identity, {}))
        for stdout, stderr in (
                ("", accepted.stderr), ("[{}]\n", accepted.stderr),
                ("[]\n", "permission denied\n")):
            with self.subTest(stdout=stdout, stderr=stderr), \
                    patch.object(launcher, "run_docker", return_value=
                                 subprocess.CompletedProcess([], 1, stdout=stdout,
                                                             stderr=stderr)):
                self.assertFalse(launcher.container_absent(identity, {}))


if __name__ == "__main__":
    unittest.main()
