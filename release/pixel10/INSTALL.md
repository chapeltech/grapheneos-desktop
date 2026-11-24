# ChapelTech Pixel 10 (frankel) — 0.1

This is a custom operating system, not an official GrapheneOS release. A
prerelease is not hardware-qualified. Only install on an OEM-unlockable **Pixel
10**, not a Pro, Fold or emulator. Do not downgrade newer device firmware.
Unlocking **and relocking** erase data. Back up before starting.

1. Obtain the release signing public key and verified-boot fingerprint from
   your administrator independently. On Linux, download the release assets.
   If a ZIP is split, reassemble the numbered parts in order, e.g.
   `cat frankel-install-BUILD.zip.part[0-9][0-9][0-9] > frankel-install-BUILD.zip`
   (replace BUILD). Do the same for a split OTA.
2. With the public key in an OpenSSH allowed-signers file as
   `pixel10 ssh-ed25519 …`, run
   `ssh-keygen -Y verify -f allowed_signers -I pixel10 -n chapeltech-pixel10-release -s SHA256SUMS.sig < SHA256SUMS`
   and then `sha256sum -c SHA256SUMS` with all listed assets present.
   Confirm the SHA-256 of the install ZIP's embedded `avb_pkmd.bin` against the
   independent fingerprint; don't trust a key simply because it came in the ZIP.
3. Follow the [upstream command-line install procedure](https://grapheneos.org/install/cli)
   for USB drivers, current platform-tools, OEM unlocking, fastboot bootloader
   unlock and relock. Use **this verified install ZIP's** flash-all script,
   not the official web installer or emulator images. Stop on any flashing
   error; do not relock a partial flash. Check the boot key fingerprint on the
   handset before entering personal data.
4. Install `controller.apk`, `styx.apk` and `xmonad.apk` from the release,
   separately from the OS. Enable external desktop consent. Verify that the
   phone UI remains ordinary and that the external monitor accepts the selected
   window manager.
5. For candidate testing select **Beta** in the system updater. Use **Stable**
   for qualified releases. A normal OTA must not require USB, unlocking,
   relocking, reinstalling the APKs, or wiping the phone. A stable feed may
   not exist before the first hardware qualification. Report the build numbers
   and updater error if an update fails; do not unlock or downgrade.
