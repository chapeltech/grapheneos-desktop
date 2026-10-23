#!/usr/bin/python3
"""Mock-only tests for the bounded API startup watcher.

No test invokes Docker, ADB, an emulator, or a repository producer.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

import watch_api_startup as watch


BOOT = "12345678-1234-4234-8234-123456789abc"
RUN = "12" * 16
NONCE = "34" * 16
CID = "56" * 32
IMAGE = "sha256:" + "78" * 32
PACKET = "9a" * 32


def ref(path: Path) -> dict:
    raw = path.read_bytes()
    return {"path": str(path), "sha256": watch.digest_bytes(raw), "bytes": len(raw)}


def status(**changes) -> dict:
    value = {
        "schema": 1,
        "run": RUN,
        "mode": "full",
        "state": "running",
        "phase": "enabling-external-ui",
        "started_elapsed_ms": 100,
        "updated_elapsed_ms": 200,
        "api_version": 3,
        "capabilities": 127,
        "generation": 41,
        "display_ids": [2],
        "heartbeat_count": 1,
        "operations": ["getApiVersion", "getCapabilities", "openSession", "heartbeat",
                       "enableExternalUi", "showShell"],
        "callbacks": {"onSnapshot": 3, "onCommand": 0, "onResult": 0, "onRevoked": 0},
        "facades": ["ExternalHomeActivity:valid", "ExternalShellActivity:valid",
                    "LauncherActivity:valid"],
        "failure": None,
    }
    value.update(changes)
    return value


def status_output(value=None) -> bytes:
    value = status() if value is None else value
    return ("SERVICE org.wonad.desktop/.ConformanceService\n"
            "  Client:\nWONAD_CONFORMANCE_STATUS " +
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def inspect_value(state_directory: Path) -> dict:
    return {
        "Id": CID,
        "Name": "/wonad-phase1-conformance-" + NONCE[:12],
        "Image": IMAGE,
        "Config": {"User": "1000:1000", "Labels": {watch.LABEL: NONCE}},
        "HostConfig": {
            "Binds": [str(state_directory) + ":/state:rw,Z"],
            "NetworkMode": "none",
            "Privileged": False,
            "PortBindings": {},
            "PublishAllPorts": False,
            "CapAdd": None,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges=true"],
            "DeviceRequests": None,
            "DeviceCgroupRules": None,
            "VolumesFrom": None,
            "PidMode": "",
            "IpcMode": "private",
            "CgroupnsMode": "private",
            "UTSMode": "",
            "UsernsMode": "",
            "ReadonlyRootfs": False,
            "AutoRemove": False,
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "GroupAdd": ["103"],
            "Devices": [{"PathOnHost": "/dev/kvm", "PathInContainer": "/dev/kvm",
                         "CgroupPermissions": "rwm"}],
            "PidsLimit": 1024,
            "Memory": 8 * 1024**3,
            "MemorySwap": 16 * 1024**3,
            "MemoryReservation": 0,
            "NanoCpus": 12_000_000_000,
            "ShmSize": 512 * 1024**2,
            "Tmpfs": {"/tmp": "rw,nosuid,nodev,size=2g"},
            "Ulimits": [{"Name": "core", "Hard": 0, "Soft": 0},
                        {"Name": "nofile", "Hard": 65536, "Soft": 65536}],
        },
        "Mounts": [{"Type": "bind", "Source": str(state_directory),
                    "Destination": "/state", "Mode": "rw,Z", "RW": True,
                    "Propagation": "rprivate"}],
        "State": {"Status": "running", "Running": True, "Paused": False,
                  "Restarting": False, "OOMKilled": False, "Dead": False, "Pid": 2222},
    }


class FakeBackend:
    def __init__(self, info: dict):
        self.info = info
        self.clock = 1_000_000_000
        self.calls = []
        self.guest_calls = []
        self.timeout_command = None
        self.oversize_command = None
        self.status_bytes = status_output()
        self.boot_id = BOOT
        self.inspect_returncode = 0

    def locality(self):
        static = {
            "cli": {"path": "/usr/bin/docker", "realpath": "/usr/bin/docker",
                    "device": 1, "inode": 2, "mode": watch.stat.S_IFREG | 0o755,
                    "uid": 0, "gid": 0},
            "socket": {"path": "/var/run/docker.sock", "realpath": "/run/docker.sock",
                       "device": 3, "inode": 4, "mode": watch.stat.S_IFSOCK | 0o660,
                       "uid": 0, "gid": 999},
        }
        rows = [
            ("docker-context-show", ["/usr/bin/docker", "context", "show"], b"default\n"),
            ("docker-context-inspect", ["/usr/bin/docker", "context", "inspect", "default"],
             json.dumps([{"Name": "default", "Metadata": {},
                          "Endpoints": {"docker": {"Host": watch.ENDPOINT,
                                                     "SkipTLSVerify": False}},
                          "TLSMaterial": {}}]).encode()),
            ("docker-version", ["/usr/bin/docker", "--host", watch.ENDPOINT, "version",
                                "--format", "{{json .}}"],
             json.dumps({"Client": {"Os": "linux", "Version": "mock"},
                         "Server": {"Os": "linux"}}).encode()),
            ("docker-info", ["/usr/bin/docker", "--host", watch.ENDPOINT, "info",
                             "--format", "{{json .}}"],
             json.dumps({"ID": "daemon-for-mock-only", "Name": "mock",
                         "ServerVersion": "mock", "KernelVersion": "mock",
                         "OSType": "linux", "Architecture": "x86_64",
                         "DockerRootDir": "/var/lib/docker",
                         "ClientInfo": {"Context": "default"}}).encode()),
        ]
        captures = []
        for role, argv, output in rows:
            self.calls.append(argv)
            captures.append((role, self._capture(argv, output)))
        return static, captures

    def kvm_gid(self):
        return 103

    def now_ns(self):
        return self.clock

    def sleep(self, seconds):
        self.clock += int(seconds * 1_000_000_000)

    def _capture(self, argv, output, *, timed_out=False, oversized=False, returncode=0):
        start = self.clock
        self.clock += 1_000_000
        return watch.Capture(tuple(argv), start, self.clock, returncode, output,
                             timed_out=timed_out, oversized=oversized)

    def inspect(self, container, timeout=watch.PROCESS_TIMEOUT):
        argv = ["/usr/bin/docker", "--host", watch.ENDPOINT,
                "container", "inspect", container]
        self.calls.append(argv)
        return self._capture(argv, json.dumps([self.info]).encode(),
                             returncode=self.inspect_returncode)

    def guest(self, container, command, timeout=watch.PROCESS_TIMEOUT):
        command = list(command)
        argv = ["/usr/bin/docker", "--host", watch.ENDPOINT, "exec", container,
                "adb", "-s", watch.SERIAL, *command]
        self.calls.append(argv)
        self.guest_calls.append(command)
        if command == watch.Watcher.BOOT:
            output = (self.boot_id + "\n").encode()
        elif command == watch.Watcher.SERVICE:
            output = self.status_bytes
        else:
            output = ("bounded mock output for " + " ".join(command) + "\n").encode()
        timed_out = command == self.timeout_command
        oversized = command == self.oversize_command
        if oversized:
            output = b"x" * watch.MAX_OUTPUT
        return self._capture(argv, output, timed_out=timed_out, oversized=oversized,
                             returncode=-9 if timed_out or oversized else 0)


class Fixture:
    def __init__(self, root: Path):
        self.root = root
        self.pair = root / "pair.py"
        self.selection = root / "selection.json"
        self.acceptance = root / "acceptance.py"
        self.locality = root / "locality.py"
        self.watcher = root / "watcher.py"
        self.state = root / "state"
        self.evidence = root / "evidence"
        self.authorization = root / "authorization.json"
        self.product = root / "product"
        self.state.mkdir()
        self.product.mkdir()
        self.pair.write_text("# exact mock pair authority\n")
        self.acceptance.write_text("# exact mock profile authority\n")
        self.locality.write_text("# exact mock locality authority\n")
        self.watcher.write_text("# exact mock watcher authority\n")
        selection = {
            "schema": 1,
            "scope": "custom7-packet6-two-separate-fresh-guests-not-runtime-qualified",
            "native_image_id": "sha256:" + "ab" * 32,
            "derived_image_id": IMAGE,
            "native_manifest": str(root / "native.json"),
            "native_manifest_sha256": "bc" * 32,
            "derived_manifest": str(root / "derived.json"),
            "derived_manifest_sha256": "cd" * 32,
            "product": str(self.product),
            "packet_receipt_sha256": PACKET,
            "baseline_receipt_sha256": "de" * 32,
            "custom_receipt_sha256": "ef" * 32,
            "comparison_sha256": "01" * 32,
        }
        self.selection.write_bytes(watch.canonical(selection))
        self.policy = watch.Policy(
            pair_driver=self.pair,
            selection=self.selection,
            acceptance_source=self.acceptance,
            acceptance_sha256=watch.digest_bytes(self.acceptance.read_bytes()),
            locality_source=self.locality,
            locality_sha256=watch.digest_bytes(self.locality.read_bytes()),
            state_directory=self.state,
            product=self.product,
            packet_sha256=PACKET,
            evidence_root=self.evidence,
            authorization_path=self.authorization,
            watcher_source=self.watcher,
        )
        authorization = {
            "schema": 1,
            "kind": watch.AUTH_KIND,
            "scope": watch.SCOPE,
            "pair_driver": ref(self.pair),
            "selection": ref(self.selection),
            "container": {
                "id": CID,
                "name": "/wonad-phase1-conformance-" + NONCE[:12],
                "nonce": NONCE,
                "image_id": IMAGE,
                "boot_id": BOOT,
                "run": RUN,
                "state_directory": str(self.state),
                "user": "1000:1000",
                "kvm_group": "103",
            },
        }
        self.authorization.write_bytes(watch.canonical(authorization))
        self.authorization_sha = watch.digest_bytes(self.authorization.read_bytes())
        self.info = inspect_value(self.state)

    def execute(self, backend=None):
        backend = FakeBackend(copy.deepcopy(self.info)) if backend is None else backend
        return watch.execute(self.authorization, self.authorization_sha, backend, self.policy), backend


class StartupWatchTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Fixture(Path(temporary.name))

    def failure(self, fixture):
        value = json.loads((fixture.evidence / "failure.json").read_text())
        self.assertEqual(watch.SCOPE, value["scope"])
        self.assertTrue(value["diagnostic_only"])
        self.assertIs(value["runtime_pass"], False)
        self.assertIs(value["release_qualification"], False)
        self.assertNotEqual("passed", value.get("status"))
        self.assertNotEqual("passed", value.get("result"))
        return value

    def test_three_bounded_samples_are_read_only_and_never_a_pass(self):
        fixture = self.fixture()
        code, backend = fixture.execute()
        self.assertEqual(0, code)
        result = json.loads((fixture.evidence / "receipt.json").read_text())
        self.assertEqual("startup-sampled", result["disposition"])
        self.assertEqual(3, len(result["samples"]))
        self.assertTrue(result["diagnostic_only"])
        self.assertIs(result["runtime_pass"], False)
        self.assertIs(result["release_qualification"], False)
        self.assertEqual([0.0, 4.0, 9.0], result["sampling"]["offset_seconds"])
        self.assertLessEqual(max(row["raw"]["bytes"] for row in result["commands"]),
                             watch.MAX_OUTPUT)
        commands = backend.guest_calls
        self.assertEqual(2, commands.count(watch.Watcher.BOOT))
        self.assertEqual(3, commands.count(watch.Watcher.SERVICE))
        self.assertEqual(3, commands.count(watch.Watcher.ACTIVITIES))
        self.assertEqual(3, commands.count(watch.Watcher.WINDOWS))
        self.assertEqual(3, commands.count(watch.Watcher.SYSTEMUI))
        self.assertEqual(3, commands.count(watch.Watcher.LOGCAT))
        flattened = "\0".join("\0".join(command) for command in commands)
        for forbidden in (" settings ", " input ", " install ", " uninstall ",
                          "docker stop", "docker kill", "logcat -c"):
            self.assertNotIn(forbidden, " " + flattened.replace("\0", " ") + " ")

    def test_wrong_container_identity_fails_before_any_guest_read(self):
        fixture = self.fixture()
        backend = FakeBackend(copy.deepcopy(fixture.info))
        backend.info["Id"] = "ff" * 32
        code, backend = fixture.execute(backend)
        self.assertEqual(1, code)
        self.assertIn("identity differs", self.failure(fixture)["failure"]["message"])
        self.assertEqual([], backend.guest_calls)

    def test_stopped_container_fails_before_any_guest_read(self):
        fixture = self.fixture()
        backend = FakeBackend(copy.deepcopy(fixture.info))
        backend.info["State"].update({"Status": "exited", "Running": False, "Pid": 0})
        code, backend = fixture.execute(backend)
        self.assertEqual(1, code)
        self.assertIn("not running", self.failure(fixture)["failure"]["message"])
        self.assertEqual([], backend.guest_calls)

    def test_resource_profile_mutation_fails_before_any_guest_read(self):
        fixture = self.fixture()
        backend = FakeBackend(copy.deepcopy(fixture.info))
        backend.info["HostConfig"]["Memory"] += 1
        code, backend = fixture.execute(backend)
        self.assertEqual(1, code)
        self.assertIn("resource profile differs", self.failure(fixture)["failure"]["message"])
        self.assertEqual([], backend.guest_calls)

    def test_wrong_guest_boot_identity_fails_before_status_or_dump_reads(self):
        fixture = self.fixture()
        backend = FakeBackend(copy.deepcopy(fixture.info))
        backend.boot_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        code, backend = fixture.execute(backend)
        self.assertEqual(1, code)
        self.assertIn("boot identity differs", self.failure(fixture)["failure"]["message"])
        self.assertEqual([watch.Watcher.BOOT], backend.guest_calls)

    def test_timed_out_status_is_sealed_and_fails(self):
        fixture = self.fixture()
        backend = FakeBackend(copy.deepcopy(fixture.info))
        backend.timeout_command = watch.Watcher.SERVICE
        code, _backend = fixture.execute(backend)
        self.assertEqual(1, code)
        value = self.failure(fixture)
        self.assertIn("timed out", value["failure"]["message"])
        self.assertTrue(any(row["timed_out"] for row in value["commands"]))

    def test_oversized_dump_is_capped_sealed_and_fails(self):
        fixture = self.fixture()
        backend = FakeBackend(copy.deepcopy(fixture.info))
        backend.oversize_command = watch.Watcher.ACTIVITIES
        code, _backend = fixture.execute(backend)
        self.assertEqual(1, code)
        value = self.failure(fixture)
        self.assertIn("exceeded 512KiB", value["failure"]["message"])
        row = next(row for row in value["commands"] if row["oversized"])
        self.assertEqual(watch.MAX_OUTPUT, row["raw"]["bytes"])

    def test_missing_duplicate_and_malformed_status_fail_closed(self):
        attacks = {
            "missing": b"No services match\n",
            "duplicate": status_output() + status_output(),
            "wrong-run": status_output(status(run="ff" * 16)),
            "boolean-generation": status_output(status(generation=True)),
            "duplicate-json-key":
                b'WONAD_CONFORMANCE_STATUS {"schema":1,"schema":1}\n',
        }
        for label, raw in attacks.items():
            with self.subTest(label=label):
                fixture = self.fixture()
                backend = FakeBackend(copy.deepcopy(fixture.info))
                backend.status_bytes = raw
                code, _backend = fixture.execute(backend)
                self.assertEqual(1, code)
                self.failure(fixture)

    def test_changed_authority_is_rejected_before_evidence_creation(self):
        fixture = self.fixture()
        fixture.pair.write_text("changed after root authorization\n")
        with self.assertRaisesRegex(watch.WatchError, "Authority file bytes differ"):
            fixture.execute()
        self.assertFalse(fixture.evidence.exists())


if __name__ == "__main__":
    unittest.main()
