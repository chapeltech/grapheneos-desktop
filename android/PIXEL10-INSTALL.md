# Pixel 10: build and installation handoff

Target: **Pixel 10 (`frankel`), ARM64, `user`**. Not Pixel 10 Pro/XL/Fold,
Pixel 8, or the x86-64 emulator. The phone stays an ordinary GrapheneOS phone;
Wonad manages the external displays. A native **5120×1440** monitor is a required
test configuration, not an optional downscaled preview.

## Availability — 20 October 2026

**There is not yet a flashable Wonad Pixel 10 release. Do not unlock, wipe or
flash the phone using the emulator files.** The instructions below are the
installation procedure for the eventual verified release, not a claim that
an archive already exists or that physical installation has passed.

The device build/vendor/signing/OTA verifiers now select `frankel-cur-user`.
The source remains pinned to GrapheneOS `2026100600`; this is not a claim to
track today's latest stable release or to be safe to downgrade newer firmware.
Frankel's pinned vendor configuration uses `laguna` / `6.6` / `muzel`, not
Pixel 8's kernel/device family. Old source/vendor receipts retain their dates
and scope. They do not qualify the current OS modifications or ARM64 binaries.
A fresh read-only baseline audit on October 20 passes for 1,057 manifest-pinned
projects and all 6,449 generated vendor files. That is baseline input evidence,
not a custom OS build or hardware qualification; see the build record below.

The ARM64 Android GHC 9.12.2 toolchain and both APKs' native dependencies have
now built. **Unsigned** production-flavour APK preparation artifacts are available:

| Component | Artifact | SHA-256 |
| --- | --- | --- |
| Wonad 19 | [wonad-arm64-unsigned.apk](out/pixel10-wonad-arm64-20261020-1/wonad-arm64-unsigned.apk) | `bd8a222aa76337316f6dc051dcae37698fabd63e056cbe4b02f091ccd39b94ef` |
| StyX11 7 | [styx-arm64-unsigned.apk](out/pixel10-styx-arm64-20261020-2/styx-arm64-unsigned.apk) | `b068a5f28f40ab85d65674b96ba752daacb412c93a11a2c61d1dcf6e7acb5a8f` |

These passed release assembly/lint, ARM64 ELF/16-KiB checks, manifest checks,
ZIP alignment and exact packaged-native/keyboard-asset comparisons. They are
**not installable until signed** and are not runtime/hardware qualified.
Even signed APKs require the Wonad-enabled custom OS; installing APKs on stock
GrapheneOS does not add the privileged interface. Do not push the standalone
broker/input `.so` files into a stock phone as a substitute for that OS image.
See [the actual build record](out/pixel10-arm64-20261020-1/README.md).

The full unsigned OS launcher requires 42 GiB host `MemAvailable`, 96 GiB
available on its output filesystem and 16 GiB on Docker's filesystem. Final
release-build admission requires 128 GiB output space, with additional room
for signing/staging. After cleanup the native builds fit, but `/u` remains
below OS-output admission and the host currently fails the launcher's memory
guard. `/tmp` has enough space for unsigned-output admission only; free space
on separate filesystems is not interchangeable. No guard was bypassed.
Public Wonad signer selection, protected OS/AVB/APK signing-key custody and
a project-owned HTTPS update endpoint also remain prerequisites; emulator
debug identities are not a substitute. Never send private keys to this checkout.

A separate [custom ARM64 development compilation](out/pixel10-custom-os-development-20261020-2/README.md)
is now running with an isolated source/output, the existing development public
identity, no automatic Updater and a smaller bounded resource profile. It does
not change the strict release gates above or supply a flashable release. Do
not install this development output on the phone based on compilation alone.

Read-only readiness check, from the Wonad checkout:

```sh
android/tools/pixel10_preflight.py \
  --source /u/elric/tree/wonad-grapheneos-2026100600-frankel-baseline-1 \
  --output-parent /u/elric/tree \
  --toolchain /u/elric/tree/wonad-android-arm64-toolchain
```

Exit 1 means a listed prerequisite is missing. Exit 0 is still only readiness,
not a source freeze, build result, signing result or phone qualification.
The full [build comparison](platform/FRANKEL-BUILD-COMPARISON.md),
[release provenance](platform/PHASE1-PROVENANCE.md) and
[signing ceremony](platform/PHASE1-SIGNING-CEREMONY.md) remain mandatory.

For native builds use a **separate** ARM64 toolchain work directory and
`WONAD_ANDROID_ABI=arm64-v8a`. `android/toolchain/build.sh` selects Android
AArch64 GHC; `desktop-native/build-haskell.sh` and `build-jni.sh` check/package
that ABI. Gradle requires `-PwonadAbi=arm64-v8a` for both APKs. ARM64 Wonad
release assembly deliberately does not select the emulator debug signer.
StyX11 must use `productionRelease`, not `emulatorTestDebug`; its Heimdal/grsh,
private Xorg engine, assets and Rust JNI libraries must all be rebuilt for ARM64.
Do not extract x86 libraries from emulator APKs or bypass native ELF checks.

When ready to supply the physical phone's installed version, these commands are
read-only (replace `SERIAL` with its explicitly authorized USB ADB serial):

```sh
adb -s SERIAL shell getprop ro.product.device
adb -s SERIAL shell getprop ro.build.fingerprint
adb -s SERIAL shell getprop ro.build.version.security_patch
adb -s SERIAL shell getprop ro.bootloader
adb -s SERIAL shell getconf PAGE_SIZE
```

The product must be `frankel`. These observations help compare a candidate
against the installed firmware; they do not by themselves prove downgrade or
rollback safety. No unlock/wipe/flash command is needed to collect them.

## What the completed release must contain

- A verified `frankel-install-BUILD.zip` and its factory signature: complete
  factory installation including firmware and the project's custom AVB key.
- The signed `frankel-ota_update-BUILD.zip` for same-lineage recovery/updates,
  plus signed target-files and the authenticated release/index receipts.
- Separate signed ARM64 Wonad and StyX11 APKs, version/signing identities,
  hashes and public trust anchors. The Wonad signer must match the OS pin.
- The project's own AVB key fingerprint and update endpoint. Neither is
  GrapheneOS's official identity. Do not obtain an expected digest from the
  same unauthenticated archive you are checking.

Use the offline verifiers in
[the complete installation/update/recovery runbook](platform/PHASE1-INSTALL-UPDATE-RECOVERY.md)
before proceeding. No successful release index is currently available; do not
waive its pending qualification checks to make an archive appear releasable.

## Installation, once that release is available

Unlocking **and relocking** erase phone data. Back up first. Check the exact
phone SKU supports OEM unlocking. Use a direct reliable USB cable, current
platform-tools (`fastboot` at least 35.0.1, or the bundle's higher minimum),
and a host with at least 32 GiB free for extraction/flashing. These baseline
requirements follow the [official GrapheneOS CLI guide](https://grapheneos.org/install/cli).
For this custom build, the verified Wonad bundle and its keys replace the
official release download; the official installer does not include Wonad glue.

1. Before touching firmware, compare the phone's installed build/security
   patch and bootloader version with the candidate's authenticated firmware
   requirements. Stop if rollback compatibility is unknown. Do not force a
   downgrade to the October 6 development pin.
2. Enable OEM unlocking in Settings → System → Developer options. Power off,
   then hold Volume Down while powering on to enter the bootloader. Connect
   the USB cable and inspect:

   ```sh
   fastboot --version
   fastboot devices
   fastboot getvar product
   ```

   Exactly one device must be attached and its product must be `frankel`.
3. Only after verifying the release and accepting the wipe:

   ```sh
   fastboot flashing unlock
   ```

   Confirm on the phone. Extract the verified install archive into a fresh
   directory, enter it and run its unmodified script:

   ```sh
   ./flash-all.sh
   ```

   Stop on any error. Do not edit product checks, mix partitions, add `--force`
   or disable AVB verification.
4. For this first custom hardware candidate, verify it boots while unlocked
   and record its build/SELinux state. Authenticate the bundle's AVB public
   key against the independent release identity before relocking; the orange
   unlocked-device warning is not verification of the installed custom key.
   Return to the bootloader and relock:

   ```sh
   fastboot flashing lock
   ```

   Confirm the second wipe on the phone. Verify the locked boot warning shows
   the **project's** expected key, then finish normal phone setup. Failure to
   boot locked is a failed candidate, not a reason to disable verified boot.
5. Install the release's separate signed ARM64 APKs. With USB debugging
   explicitly enabled and this host authorized:

   ```sh
   adb install wonad-arm64.apk
   adb install styx11-arm64.apk
   ```

   These filenames describe the required bundle contents; they are not
   currently supplied artifacts. Subsequent same-signer APK updates can use
   `adb install -r`; changing the Wonad signer requires OS requalification.
6. Enable Wonad in the OS's external-desktop permission settings. Connect
   keyboard, mouse and display; select the monitor in StyX11 on the phone for
   remote X11. Phone launcher/Recents remain ordinary Android. For remote apps,
   enroll/sign in through grsh/PKINIT using the real-phone production profile;
   development Asgard enrollment is not production issuance. Trusted Pixel 10
   StrongBox/attestation policy and issuance still require qualification.

## 5120×1440 external-display acceptance

The cable, hub/dock, monitor input and refresh mode must actually negotiate
5120×1440. A 3840×1080 fallback is not a pass. Check both display-device mode
and logical desktop dimensions without using `wm size` overrides:

```sh
adb shell dumpsys display
adb shell dumpsys activity service org.wonad.desktop/.DesktopService
adb shell dumpsys activity service org.wonad.styx.desktop/org.wonad.styx.XService
```

Confirm the external mode and Wonad monitor area are 5120×1440. At multiple
densities, test native Android and grsh-launched X11 applications in tiled,
Full and floating layouts; click/type/scroll near all four corners, especially
x > 4095. An X11 client's content size excludes Wonad's borders (a Full window
with 3-pixel borders has 5114×1434 content). Check `ConfigureNotify` and
`GetGeometry` against that content size, never a dp-scaled approximation.
Draw/check single-pixel patterns, resize repeatedly, unplug/redock while
populated, and repeat with a second differently sized monitor. Inspect phone
functionality and intentional phone keyboard focus after the final unplug.

Software regression checks already exercise 5120×1440 X11 geometry,
right-edge input and a one-pixel update on private Xvfb, plus Haskell layouts
and the Kotlin SDK codec at several densities. They do **not** establish the
Pixel 10/dock's mode support, refresh rate, performance or physical pixel path.
The [official wired-display instructions](https://support.google.com/pixelphone/answer/2865484?hl=en)
establish wired display support, but do not establish this particular timing.
A 4K-capable path must still be tested for the separate 5120-pixel edge limit.
The frame is 29,491,200 RGBA bytes, below the presenter's unchanged 32-MiB
limit. Proxy wire and MIT-SHM snapshots now admit the same bounded 32-MiB
image plus X11 framing instead of their old 16-MiB cap; per-segment/client/
context quotas and upstream request limits still apply. The actual private
proxy also passes a full-image readback and one-pixel-update test. There is no
downscaling fallback.

## Updating and returning to stock

After the first installation, a same-key signed full OTA can be sideloaded
from recovery. Automatic OTA additionally needs the selected project HTTPS
channel; it is not configured merely by having an OTA zip. Both successor
build number and timestamp must increase. OTA must preserve userdata; factory
reflashing/unlock/relock wipes it. Never mix official and custom signing lines.

For rescue or return to official GrapheneOS/Google firmware, follow
[the recovery runbook](platform/PHASE1-INSTALL-UPDATE-RECOVERY.md#failed-boot-or-failed-update)
and the publisher's current official instructions. Returning to stock is a
clean installation, not a supported OTA downgrade. Replace the custom AVB key
as prescribed by the official procedure, then authenticate the resulting
stock key before relocking. This recovery path has not yet been rehearsed on
the physical phone.
