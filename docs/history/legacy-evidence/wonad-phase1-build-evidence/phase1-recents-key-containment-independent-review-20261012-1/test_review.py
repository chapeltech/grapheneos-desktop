#!/usr/bin/python3
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


EVIDENCE = Path("/u/elric/tree/wonad-phase1-build-evidence")
SNAPSHOT = EVIDENCE / "phase1-recents-key-containment-kotlin-prototype-20261012-snapshot-1"
REVIEW = EVIDENCE / "phase1-recents-key-containment-independent-review-20261012-1"
SOURCE = Path("/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7")
JAVA_HOME = SOURCE / "prebuilts/jdk/jdk21/linux-x86"
JAVA = JAVA_HOME / "bin/java"
KOTLINC = SOURCE / "external/kotlinc/bin/kotlinc"
STDLIB = SOURCE / "external/kotlinc/lib/kotlin-stdlib.jar"

PINS = {
    SNAPSHOT / "candidate/WonadPolicyKeyContainment.kt":
        "87efbd72fe0fe21850a2dc0317578a05d08b24d614e4089580586bec60ad1628",
    SNAPSHOT / "candidate/WonadPolicyKeyAdapter.kt":
        "6833a7eec4a29dfa91a1d0643d4aea5bbf33033acd958358b930568d577c9570",
    SNAPSHOT / "generated/KeyGestureController.java":
        "c274656a314896ca4afa5f1b40448f1e0a43ac60573c68350d91585e7bc6a065",
    SNAPSHOT / "generated/PhoneWindowManager.java":
        "ce06e49edc4ecd9cb517fd1f37cf395a9103855fb4f3bf49dcd47d0504c4729a",
    SNAPSHOT / "generated/WonadInputBridge.kt":
        "fe92720aad5d576fefb015d52186cf68d3cc40b02c59bd5b6b0b3760a2405096",
    SNAPSHOT / "apply_candidate.py":
        "141bf068b3d1b309c2191b93caa40f8564fe668547078a2dee15119588723e0e",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FrozenContainmentReview(unittest.TestCase):
    def test_snapshot_is_exact_and_immutable(self):
        for path, expected in PINS.items():
            with self.subTest(path=str(path)):
                self.assertEqual(sha(path), expected)
                self.assertEqual(path.stat().st_mode & 0o222, 0)

        rows = []
        for path in sorted(p for p in SNAPSHOT.rglob("*") if p.is_file()):
            rows.append(f"{sha(path)}  {path}\n".encode())
        self.assertEqual(
            hashlib.sha256(b"".join(rows)).hexdigest(),
            "008cf05a8816453e6db561d1308f18cedb328034450fa688d4d8d25c7ef87315",
        )

    def test_generated_adapter_has_no_saturation_reconciliation_callsite(self):
        kgc = (SNAPSHOT / "generated/KeyGestureController.java").read_text()
        self.assertIn("WonadPolicyKeyAdapter.removeDevice(deviceId)", kgc)
        self.assertNotIn("WonadPolicyKeyAdapter.reconcileDevices(", kgc)
        adapter = (SNAPSHOT / "candidate/WonadPolicyKeyAdapter.kt").read_text()
        self.assertIn("@JvmStatic fun reconcileDevices(", adapter)

    def test_exact_helper_compiles_and_adversarial_schedules_reproduce(self):
        with tempfile.TemporaryDirectory(prefix="wonad-key-containment-review-") as raw:
            classes = Path(raw) / "classes"
            classes.mkdir()
            env = {
                **os.environ,
                "JAVA_HOME": str(JAVA_HOME),
                "PATH": str(JAVA_HOME / "bin") + os.pathsep + os.environ.get("PATH", ""),
                "JAVA_TOOL_OPTIONS": "-Dfile.encoding=UTF-8",
            }
            built = subprocess.run(
                [
                    str(KOTLINC),
                    "-J-Xms32m",
                    "-J-Xmx256m",
                    "-J-XX:MaxMetaspaceSize=128m",
                    str(SNAPSHOT / "candidate/WonadPolicyKeyContainment.kt"),
                    str(REVIEW / "AdversarialContainmentFixture.kt"),
                    "-d",
                    str(classes),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
                env=env,
            )
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            ran = subprocess.run(
                [
                    str(JAVA),
                    "-Xms16m",
                    "-Xmx64m",
                    "-XX:MaxMetaspaceSize=64m",
                    "-cp",
                    os.pathsep.join((str(classes), str(STDLIB))),
                    "org.wonad.server.input.AdversarialContainmentFixtureKt",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            for marker in (
                "ordinary_pair_leak=true",
                "passive_replacement_clear=true",
                "cross_thread_pwm_owner=true",
                "saturation_without_wiring=true",
            ):
                self.assertIn(marker, ran.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
