import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


DRIVER = Path(__file__).with_name("run-phase1-native-matrix-custom7-5-packet4-1.py")
spec = importlib.util.spec_from_file_location("native_matrix_driver", DRIVER)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class DriverTests(unittest.TestCase):
    def test_exact_full_campaign_command(self):
        self.assertEqual([
            str(driver.PYTHON), "-B", str(driver.RUNNER), "run",
            "--inputs", str(driver.INPUTS), "--output", str(driver.OUTPUT),
            "--phase", "all", "--jobs", "2", "--timeout", "7200",
        ], driver.COMMAND)
        self.assertTrue(str(driver.OUTPUT).endswith("custom7-5-packet4-run-1"))

    def test_process_classifier_refuses_runtime_build_and_vm_lanes(self):
        cases = {
            ("python3", "/x/phase1_conformance_guest.py"): "phase1_runner_or_build",
            ("python3", "/x/run_phase1_conformance_recents_guest.py"): "phase1_runner_or_build",
            ("python3", "/x/native_core_smoke.py"): "native_gate",
            ("emulator", "-avd", "pixel"): "emulator_or_qemu",
            ("qemu-system-x86_64", "-enable-kvm"): "emulator_or_qemu",
            ("ninja", "target"): "compiler",
            ("docker", "buildx", "build", "."): "docker_build",
            ("java", "org.gradle.launcher.daemon.bootstrap.GradleDaemon"): "gradle_build",
        }
        for argv, expected in cases.items():
            with self.subTest(argv=argv):
                self.assertEqual(expected, driver.process_kind(list(argv)))
        self.assertIsNone(driver.process_kind(["curl", "https://example.invalid/archive.zip"]))
        self.assertIsNone(driver.process_kind(["adb", "-L", "tcp:5037", "server"]));

    def inspect(self, rows, pair=None):
        pair = pair or SimpleNamespace(preserved_debug_check=lambda _info: None)
        identifiers = "\n".join(row["Id"] for row in rows) + ("\n" if rows else "")
        by_id = {row["Id"]: row for row in rows}

        def output(argv, **_kwargs):
            if argv[:4] == ["docker", "ps", "-q", "--no-trunc"]:
                return identifiers
            if argv[:3] == ["docker", "container", "inspect"]:
                return json.dumps([by_id[argv[3]]])
            raise AssertionError(argv)

        with patch.object(driver.subprocess, "check_output", side_effect=output):
            return driver.inspect_running_containers(pair)

    def test_only_exact_reviewed_debug_kvm_container_is_allowed(self):
        calls = []
        row = {"Id": driver.DEBUG_ID, "Image": "debug", "Name": "/wonad-emulator-debug",
               "Config": {"Labels": {}}, "HostConfig": {"Devices": [
                   {"PathOnHost": "/dev/kvm", "PathInContainer": "/dev/kvm"}]}, "Mounts": []}
        result = self.inspect([row], SimpleNamespace(
            preserved_debug_check=lambda info: calls.append(info["Id"])))
        self.assertEqual([driver.DEBUG_ID], calls)
        self.assertTrue(result["preserved_debug_seen"])

    def test_api_recents_or_other_kvm_container_is_refused(self):
        identifier = "a" * 64
        base = {"Id": identifier, "Image": driver.PAIR_IMAGE,
                "Name": "/wonad-phase1-conformance-0123456789ab",
                "Config": {"Labels": {driver.PAIR_LABEL: "0" * 32}},
                "HostConfig": {"Devices": []}, "Mounts": []}
        for mutation in ("labelled", "kvm-device", "kvm-mount"):
            with self.subTest(mutation=mutation):
                row = json.loads(json.dumps(base))
                if mutation != "labelled":
                    row["Image"] = "sha256:" + "f" * 64
                    row["Name"] = "/foreign"
                    row["Config"]["Labels"] = {}
                if mutation == "kvm-device":
                    row["HostConfig"]["Devices"] = [
                        {"PathOnHost": "/dev/kvm", "PathInContainer": "/dev/kvm"}]
                elif mutation == "kvm-mount":
                    row["Mounts"] = [{"Source": "/dev/kvm", "Destination": "/dev/kvm"}]
                with self.assertRaisesRegex(ValueError, "Live API/Recents/native/GUI/KVM"):
                    self.inspect([row])

    def test_unrelated_non_kvm_container_is_not_relabelled_as_vm(self):
        row = {"Id": "b" * 64, "Image": "sha256:" + "c" * 64, "Name": "/unrelated",
               "Config": {"Labels": {}}, "HostConfig": {"Devices": []}, "Mounts": []}
        self.assertEqual(1, self.inspect([row])["running_container_count"])


if __name__ == "__main__":
    unittest.main()
