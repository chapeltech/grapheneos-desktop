"""Pixel 10 pins and ABI isolation; no flash/build or device access."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from android.tools import run_frankel_vendor as vendor
from android.tools import run_frankel_build as build
from android.tools import pixel10_preflight as readiness

ROOT = Path(__file__).resolve().parents[2]


class Pixel10TargetTests(unittest.TestCase):
    def test_readiness_includes_the_os_launchers_actual_memory_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(readiness.build, "observe_host_resources", side_effect=build.LauncherError("Insufficient actual host MemAvailable")) as observe:
                result = readiness.inspect(root, root, root / "missing-toolchain")
            row = next(check for check in result["checks"] if check["name"] == "os_host_resource_admission")
            self.assertFalse(row["passed"])
            self.assertIn("MemAvailable", row["detail"])
            self.assertFalse(result["ready_for_unsigned_build"])
            observe.assert_called_once_with(root, Path("/var/lib/docker"))

    def test_device_and_vendor_pins_agree(self):
        lock, _ = build.load_contract(build.LOCK)
        self.assertEqual("frankel", lock["device"])
        self.assertEqual("Pixel 10", lock["production_target"]["device"])
        self.assertEqual("frankel-cur-user", lock["release_pipeline"]["lunch_target"])
        self.assertEqual("x86_64", lock["development_target"]["abi"])
        self.assertEqual("pixel_8", lock["development_target"]["avd_profile"])
        pin = lock["production_vendor"]
        self.assertEqual(vendor.FACTORY_ARCHIVE_NAME, pin["factory_archive"])
        self.assertEqual(vendor.FACTORY_ARCHIVE_SHA256, pin["factory_archive_sha256"])
        self.assertEqual(vendor.FACTORY_BUILD_ID, pin["factory_build_id"])
        for role in ("device", "family"):
            self.assertEqual(vendor.TARGET_CONFIG_SHA256[pin[role+"_config"]],
                             pin[role+"_config_sha256"])

    def test_wrong_android_compiler_fails_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            script = stage / "android/desktop-native/build-haskell.sh"
            script.parent.mkdir(parents=True)
            script.write_bytes((ROOT / "android/desktop-native/build-haskell.sh").read_bytes())
            compiler = stage / "fake-ghc"
            compiler.write_text('#!/bin/sh\nprintf \'%s\\n\' \'[("LLVM target","x86_64-unknown-linux-android")]\'\n')
            compiler.chmod(0o755)
            result = subprocess.run(["bash", str(script)], capture_output=True, text=True,
                env=dict(os.environ, WONAD_ANDROID_GHC=str(compiler),
                         ANDROID_NDK_HOME=str(stage), WONAD_ANDROID_ABI="arm64-v8a"))
            self.assertEqual(2, result.returncode)
            self.assertIn("matching arm64-v8a", result.stderr)
            self.assertFalse((stage / "android/out").exists())

    def test_toolchain_directory_cannot_be_repurposed_for_another_abi(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary) / "toolchain"
            work.mkdir()
            marker = work / ".wonad-android-target"
            original = "x86_64-unknown-linux-android\n"
            marker.write_text(original)
            result = subprocess.run(["bash", str(ROOT / "android/toolchain/build.sh")],
                capture_output=True, text=True, env=dict(os.environ,
                    WONAD_TOOLCHAIN_WORK=str(work), WONAD_ANDROID_ABI="arm64-v8a"))
            self.assertEqual(2, result.returncode)
            self.assertIn("another ABI", result.stderr)
            self.assertEqual(original, marker.read_text())
            self.assertEqual([marker], list(work.iterdir()))

    def test_android_arm64_compiler_uses_separate_native_and_object_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            script = stage / "android/desktop-native/build-haskell.sh"
            script.parent.mkdir(parents=True)
            script.write_bytes((ROOT / "android/desktop-native/build-haskell.sh").read_bytes())
            compiler = stage / "fake-ghc"
            compiler.write_text('#!/bin/sh\nif [ "$1" = --info ]; then\n'
                'printf \'%s\\n\' \'[("LLVM target","aarch64-unknown-linux-android")]\'\n'
                'else exit 77; fi\n')
            compiler.chmod(0o755)
            result = subprocess.run(["bash", str(script)], capture_output=True, text=True,
                env=dict(os.environ, WONAD_ANDROID_GHC=str(compiler),
                         ANDROID_NDK_HOME=str(stage), WONAD_ANDROID_ABI="arm64-v8a"))
            self.assertEqual(77, result.returncode)  # Stopped at compilation, not ELF qualification.
            self.assertTrue((stage / "android/out/desktop-native/arm64-v8a").is_dir())
            self.assertTrue((stage / "android/out/desktop-haskell-objects/arm64-v8a").is_dir())
            self.assertFalse((stage / "android/out/desktop-native/x86_64").exists())

    def test_arm64_release_does_not_implicitly_select_the_emulator_signer(self):
        script = (ROOT / "android/desktop/build.gradle.kts").read_text()
        self.assertIn('if (desktopAbi == "x86_64") signingConfig', script)
        self.assertIn('abiFilters += desktopAbi', script)
        self.assertIn('"--abi", desktopAbi', script)

    def test_os_jni_arm64_linkers_are_selected_without_reusing_x86_outputs(self):
        for component in ("broker-jni", "input-jni"):
            with self.subTest(component=component), tempfile.TemporaryDirectory() as temporary:
                stage = Path(temporary)
                script = stage / "android" / component / "build.sh"
                script.parent.mkdir(parents=True)
                script.write_bytes((ROOT / "android" / component / "build.sh").read_bytes())
                tools = stage / "ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
                tools.mkdir(parents=True)
                compiler = tools / "aarch64-linux-android35-clang"
                compiler.write_text("#!/bin/sh\nexit 99\n")
                compiler.chmod(0o755)
                commands = stage / "commands"
                commands.mkdir()
                cargo = commands / "cargo"
                cargo.write_text('#!/bin/sh\nprintf \'%s\\n\' "$*" "$CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"\nexit 77\n')
                cargo.chmod(0o755)
                result = subprocess.run(["bash", str(script), "android"], capture_output=True, text=True,
                    env=dict(os.environ, PATH=str(commands)+os.pathsep+os.environ["PATH"],
                             ANDROID_NDK_HOME=str(stage / "ndk"), WONAD_ANDROID_ABI="arm64-v8a"))
                self.assertEqual(77, result.returncode)
                self.assertIn("--target aarch64-linux-android", result.stdout)
                self.assertIn(str(compiler), result.stdout)
                self.assertFalse((stage / "android/out/broker-native/x86_64").exists())


if __name__ == "__main__":
    unittest.main()
