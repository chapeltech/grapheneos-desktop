#!/usr/bin/python3
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path("/u/elric/tree/wonad-phase1-build-evidence")
PROPOSAL = ROOT / "phase1-recents-authoritative-focus-routing-proposal-20261012-1"
REVIEW = ROOT / "phase1-recents-authoritative-focus-routing-independent-review-20261012-1"
SOURCE = Path("/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7")
KOTLINC = SOURCE / "external/kotlinc/bin/kotlinc"
COMPILER = SOURCE / "external/kotlinc/lib/kotlin-compiler.jar"
STDLIB = SOURCE / "external/kotlinc/lib/kotlin-stdlib.jar"
JAVA_HOME = SOURCE / "prebuilts/jdk/jdk21/linux-x86"
JAVA = JAVA_HOME / "bin/java"

EXPECTED = {
    PROPOSAL / "candidate/FocusQueryCoordinator.kt":
        "1355c4282e280fbc6de8da27f62f9b4f8617f0e955cd7c6ba80eeecdaa82a788",
    PROPOSAL / "candidate/FocusCommandGate.kt":
        "3025432ac31039b6af82d217ac94f82635067f94a25e3f470c101d27f857826e",
    PROPOSAL / "tests/FocusRoutingFixture.kt":
        "ef865479d38b5d72bae4ddb48fc661dc100eb059e51b5b2fd39ebd5cb6bc338e",
    SOURCE / "frameworks/base/libs/WindowManager/Shell/src/com/android/wm/shell/common/HandlerExecutor.java":
        "cacb177ad81b8b92e7df67ad816019f7f38d9e511b523b4094d001c4d6a9c81d",
    SOURCE / "frameworks/base/core/java/android/os/RemoteCallback.java":
        "de6969a49c42afa42f0f032b3eb1445e5c2e80847f0e3e33ac6f92e2bb981775",
    SOURCE / "frameworks/base/core/java/android/os/IRemoteCallback.aidl":
        "31120af262690e1d7f4dd4f2befdcca13c4fa30ed10278bfdc722c31298e0b2a",
    KOTLINC:
        "64d62a197fbec5f32f77c6724cce33ead4034b2ec3f873c056cde19fe00f324e",
    COMPILER:
        "6f1a8eea4cf61dc5de2f36734bfe945b7bb0b64dd2f92b2f63243fe2a56c1248",
    STDLIB:
        "073d176769242ecc972d6b6499c8343ac4c83c86062fed6f43b6b4f5af8a81ff",
    JAVA:
        "cfa21aeadd00925925c9e1287f5c08f3e04ee7f26a9e23d9dbfb16149153d842",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FrozenFocusProposalReview(unittest.TestCase):
    def test_inputs_are_exact_frozen_bytes(self):
        for path, expected in EXPECTED.items():
            with self.subTest(path=str(path)):
                self.assertEqual(digest(path), expected)

    def test_real_handler_executor_throws_uncaught_type(self):
        coordinator = (PROPOSAL / "candidate/FocusQueryCoordinator.kt").read_text()
        handler_text = (
            SOURCE /
            "frameworks/base/libs/WindowManager/Shell/src/com/android/wm/shell/common/HandlerExecutor.java"
        ).read_text()
        self.assertIn('throw new RuntimeException(mHandler + " is probably exiting")', handler_text)
        self.assertIn("catch (_: RejectedExecutionException)", coordinator)
        self.assertNotIn("catch (_: RuntimeException)", coordinator)

    def test_remote_callback_is_oneway_and_swallows_remote_exception(self):
        aidl = (
            SOURCE / "frameworks/base/core/java/android/os/IRemoteCallback.aidl"
        ).read_text()
        remote = (
            SOURCE / "frameworks/base/core/java/android/os/RemoteCallback.java"
        ).read_text()
        self.assertIn("oneway interface IRemoteCallback", aidl)
        self.assertIn("mCallback.sendResult(result);", remote)
        self.assertIn("catch (RemoteException e)", remote)

    def test_exact_frozen_methods_compile_and_adversarial_schedule_runs(self):
        self.assertTrue(KOTLINC.is_file())
        self.assertTrue(COMPILER.is_file())
        self.assertTrue(STDLIB.is_file())
        with tempfile.TemporaryDirectory(prefix="wonad-focus-independent-") as raw:
            work = Path(raw)
            classes = work / "classes"
            classes.mkdir()
            compile_cmd = [
                str(KOTLINC),
                "-J-Xms32m",
                "-J-Xmx256m",
                "-J-XX:MaxMetaspaceSize=128m",
                str(PROPOSAL / "candidate/FocusQueryCoordinator.kt"),
                str(PROPOSAL / "candidate/FocusCommandGate.kt"),
                str(REVIEW / "AdversarialFocusRoutingFixture.kt"),
                "-d",
                str(classes),
            ]
            compiled = subprocess.run(
                compile_cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
                env={
                    **os.environ,
                    "JAVA_HOME": str(JAVA_HOME),
                    "PATH": str(JAVA_HOME / "bin") + os.pathsep + os.environ.get("PATH", ""),
                    "JAVA_TOOL_OPTIONS": "-Dfile.encoding=UTF-8",
                },
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            runtime_cp = os.pathsep.join((str(classes), str(STDLIB)))
            ran = subprocess.run(
                [
                    str(JAVA),
                    "-Xms16m",
                    "-Xmx64m",
                    "-XX:MaxMetaspaceSize=64m",
                    "-cp",
                    runtime_cp,
                    "org.wonad.focusproposal.AdversarialFocusRoutingFixtureKt",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn("confirmed_runtime_rejection_wedge=true", ran.stdout)
            self.assertIn("confirmed_final_route_race=true", ran.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
