#!/usr/bin/python3
"""Read-only Pixel 10 build readiness; never flash, sign, sync or delete files."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "android/tools"))
import run_frankel_build as build
import run_frankel_vendor as vendor
import frankel_build_comparison as comparison


def inspect(source, output_parent, toolchain, *, audit_vendor=False):
    lock = json.loads((ROOT / "android/grapheneos.lock.json").read_bytes())
    checks = []

    def check(name, action):
        try:
            detail = action()
            checks.append(dict(name=name, passed=True, detail=detail))
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            checks.append(dict(name=name, passed=False, detail=str(error)))

    def require(condition, message):
        if not condition:
            raise ValueError(message)

    def target():
        build.load_contract(build.LOCK)
        require(lock["device"] == "frankel", "Not the Pixel 10 lock")
        return lock["production_target"]

    def upstream():
        pin = lock["production_vendor"]
        require(pin["factory_archive"] == vendor.FACTORY_ARCHIVE_NAME and
                pin["factory_archive_sha256"] == vendor.FACTORY_ARCHIVE_SHA256 and
                pin["factory_build_id"] == vendor.FACTORY_BUILD_ID,
                "Vendor runner/factory lock mismatch")
        for name, expected in vendor.TARGET_CONFIG_SHA256.items():
            path = source / name
            require(path.is_file() and not path.is_symlink(), "Missing source: " + str(path))
            require(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                    "Vendor config bytes differ: " + name)
        require(pin["device_config_sha256"] == vendor.TARGET_CONFIG_SHA256[pin["device_config"]]
                and pin["family_config_sha256"] == vendor.TARGET_CONFIG_SHA256[pin["family_config"]],
                "Vendor runner/config lock mismatch")
        revision = subprocess.check_output(
            ["git", "-C", str(source / "vendor/adevtool"), "rev-parse", "HEAD"],
            text=True, timeout=15).strip()
        require(revision == pin["adevtool_commit"], "Wrong adevtool revision")
        device_make = source / "vendor/adevtool/config/mk/google_devices/device/frankel/device.mk"
        require("device/google/laguna-kernels/6.6/grapheneos/muzel" in device_make.read_text(),
                "Frankel kernel family/codename differs")
        require((source / "vendor/google_devices/frankel/AndroidProducts.mk").is_file(),
                "Generated Pixel 10 vendor tree absent")
        result = dict(adevtool_commit=revision, kernel="laguna/6.6/muzel",
                      scope="target/config presence only, not full source/vendor byte audit")
        if audit_vendor:
            ledger = comparison.collect_vendor(source)
            result.update(vendor_identity_sha256=ledger["identity_sha256"],
                          vendor_files=len(ledger["files"]),
                          vendor_directories=len(ledger["directories"]),
                          scope="generated vendor bytes match pinned spec; not a full source freeze")
        return result

    def space(path, minimum):
        require(path.is_absolute() and path.is_dir() and not path.is_symlink(),
                "Supply a literal existing directory: " + str(path))
        free = shutil.disk_usage(path).free
        require(free >= minimum, f"{path}: {free} bytes free; {minimum} required")
        return dict(path=str(path), free_bytes=free, minimum_bytes=minimum)

    def compiler():
        ghc = toolchain / "ghc-9.12.2/_build/stage0/bin/aarch64-unknown-linux-android-ghc"
        require(ghc.is_file(), "ARM64 Android GHC not built: " + str(ghc))
        info = subprocess.check_output([str(ghc), "--info"], text=True, timeout=30)
        require('("LLVM target","aarch64-unknown-linux-android")' in info and
                '("Project version","9.12.2")' in info,
                "Compiler is not Android ARM64 GHC 9.12.2")
        return str(ghc)

    check("pixel10_target", target)
    check("pixel10_vendor_inputs", upstream)
    check("os_output_space", lambda: space(output_parent, build.PIN["host_admission"]["out_free_bytes"]))
    check("docker_storage_space", lambda: space(Path("/var/lib/docker"),
                                              build.PIN["host_admission"]["docker_free_bytes"]))
    # The OS launcher also has a host-MemAvailable guard. Reporting only free
    # disk/compiler presence would misleadingly advertise readiness while that
    # same launcher necessarily refuses to start on a busy host.
    check("os_host_resource_admission", lambda: build.observe_host_resources(
        output_parent, Path("/var/lib/docker")))
    check("arm64_policy_compiler", compiler)
    return dict(schema=1, kind="wonad-pixel10-readiness-not-release-qualification",
                source_release=lock["release"], checks=checks,
                ready_for_unsigned_build=all(row["passed"] for row in checks),
                flashable_release_available=False, hardware_qualified=False,
                further_release_requirements=[
                    "full source/vendor audit and current OS glue staging",
                    "successful ARM64 OS/APK builds and independent artifact verification",
                    "selected public Wonad release signer and project-owned HTTPS update endpoint",
                    "protected OS/AVB/OTA keys; offline signing and authenticated public anchors",
                    "check installed-phone firmware/anti-rollback compatibility before flashing",
                    "physical Pixel 10 USB-C 5120x1440 mode, 1:1 pixels and input qualification"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output-parent", type=Path, required=True)
    parser.add_argument("--toolchain", type=Path, required=True)
    parser.add_argument("--audit-vendor", action="store_true",
                        help="Also rehash the complete generated vendor tree against its pinned spec")
    args = parser.parse_args()
    result = inspect(args.source, args.output_parent, args.toolchain, audit_vendor=args.audit_vendor)
    print(json.dumps(result, indent=2))
    return 0 if result["ready_for_unsigned_build"] else 1


if __name__ == "__main__":
    sys.exit(main())
