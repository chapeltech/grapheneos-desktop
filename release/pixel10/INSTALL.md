# ChapelTech Pixel 10 (frankel) — 0.1

This is a custom operating system, not an official GrapheneOS release. A
prerelease is not hardware-qualified. Only install on an OEM-unlockable **Pixel
10**, not a Pro, Fold or emulator. Do not downgrade newer device firmware.
Unlocking **and relocking** erase data. Back up before starting.

## Download and verify on Linux

Use the [ChapelTech GitHub releases](https://github.com/chapeltech/grapheneos-desktop/releases),
not an Actions artifact. If there is no published `frankel-0.1-YYYYMMDDNN`
release, there is nothing to flash. The unsigned signing handoff is not an
install package.

1. Obtain the release signing public key and verified-boot fingerprint from
   your administrator independently. Save the public key in `allowed_signers`
   as `pixel10 ssh-ed25519 …`, and download `SHA256SUMS` and its signature.
   Verify the checksum file before using it as the download list:

   ```sh
   ssh-keygen -Y verify -f allowed_signers -I pixel10 -n chapeltech-pixel10-release -s SHA256SUMS.sig < SHA256SUMS
   ```

2. Download all files named in the verified `SHA256SUMS`. If only numbered
   ZIP parts are listed as assets, download every part and concatenate them in
   order. Set `build` to the ten-digit suffix of the release tag. In Bash:

   ```bash
   build=YYYYMMDDNN   # replace with the exact release build number
   install="frankel-install-$build.zip"
   ota="frankel-ota_update-$build.zip"
   (
       set -e
       export LC_ALL=C
       for archive in "$install" "$ota"; do
           if [[ ! -f "$archive" ]]; then
               cat -- "$archive".part[0-9][0-9][0-9] > "$archive"
           fi
       done
       sha256sum -c --strict SHA256SUMS
       ssh-keygen -Y verify -f allowed_signers -I pixel10 -n 'factory images' -s "$install.sig" < "$install"
   )
   ```

   Stop on any verification error. To confirm the verified-boot key before
   flashing, run `unzip -p "$install" "${install%.zip}/avb_pkmd.bin" | sha256sum`
   and compare the result with the independently obtained fingerprint.

## Flash and enable the desktop

1. Follow the [upstream command-line install procedure](https://grapheneos.org/install/cli)
   for USB drivers, current platform-tools, OEM unlocking, fastboot bootloader
   unlock and relock. Use **this verified install ZIP's** flash-all script,
   not the official web installer or emulator images. Stop on any flashing
   error; do not relock a partial flash. Check the boot key fingerprint on the
   handset before entering personal data.
2. Follow the [repository README](../../README.md#install-on-a-pixel-10) to
   install the signed **ChapelTech Desktop Updates** APK from the separate
   desktop apps release and use it to install the three desktop apps.
   Open **Settings → Apps → Special app access →
   External desktop** (or use the controller's **OS permission settings**
   button) and approve the installed controller.
   The OS ships with no approved app. Connect a monitor and keyboard, and use
   the controller to choose XMonad. Verify the phone UI is unchanged and the
   external monitor accepts the chosen manager. Physical-device XMonad
   shortcuts use Super without the emulator's extra Ctrl modifier.
3. For candidate testing select **Beta** in the system updater. Use **Stable**
   for qualified releases. A normal OTA must not require USB, unlocking,
   relocking, reinstalling the APKs, or wiping the phone. A stable feed may
   not exist before the first hardware qualification. Report the build numbers
   and updater error if an update fails; do not unlock or downgrade.

For physical qualification, test both paths separately: OS OTA with the
desktop app versions held constant, and app-only OTA with the OS build held
constant. Verify the locked boot key, phone data, StyX11 settings, controller
approval, normal phone behavior, and the external desktop at 5120×1440.
Record Android's observed behavior for unattended app updates and approval
fallback, including a fresh install through Desktop Updates.
