# ChapelTech Pixel 10 (frankel) — 0.1

This is a custom operating system, not an official GrapheneOS release. A
prerelease is not hardware-qualified. Only install on an OEM-unlockable **Pixel
10**, not a Pro, Fold or emulator. Do not downgrade newer device firmware.
Unlocking **and relocking** erase data. Back up before starting.

## 1. Prepare the phone and computer

1. On the phone, open **Settings → About phone → Android version** and check the
   **Android security update** date. Do not flash over a newer security patch or
   firmware. The first Beta, `2026112603`, carries the **2026-11-05** Android
   security patch. If compatibility is unclear, stop and check before unlocking.
2. In the Android system currently installed, go to **Settings → About phone**
   and tap **Build number** seven times. Enter the device PIN if prompted.
   Under **Settings → System → Developer options**, turn on **OEM unlocking**.
   If the switch is unavailable, connect the phone to the internet and check
   again. Do not proceed if it remains unavailable. **USB debugging is not
   required for flashing.**
3. Use a Linux computer with at least 2 GB of free memory and 32 GB of free
   storage, and connect a data-capable USB cable directly to it. Install current [Android SDK
   Platform-Tools](https://developer.android.com/tools/releases/platform-tools)
   and put their directory on your `PATH`. You also need Bash, OpenSSH
   (`ssh-keygen`), `sha256sum`, and `unzip`. Run the commands in a Bash terminal
   and keep it open through flashing. Run `fastboot --version` to confirm you
   are using the tools you just installed. If Linux cannot access the phone
   as your user, see [GrapheneOS's USB setup](https://grapheneos.org/install/cli#flashing-as-non-root)
   for the correct udev rules.

## 2. Download and verify the factory image

Use the [ChapelTech GitHub releases](https://github.com/chapeltech/grapheneos-desktop/releases),
not an Actions artifact. If there is no published `frankel-0.1-YYYYMMDDNN`
release, there is nothing to flash. The unsigned signing handoff is not an
install package.

1. Obtain the release signing public key and verified-boot fingerprint from
   your administrator independently. Save the public key in `allowed_signers`
   as `pixel10 ssh-ed25519 …`. If you already trust the [reviewed signing-key
   commit](https://github.com/chapeltech/grapheneos-desktop/tree/48967efd4be7b81262a737361aa131fe291b6319/release/pixel10/trust),
   it provides `allowed_signers`; SHA-256 of that directory's `avb_pkmd.bin`
   is the boot-key fingerprint. Do not use a key supplied only by the download
   you are verifying. Download `SHA256SUMS` and `SHA256SUMS.sig` into a clean
   directory alongside `allowed_signers`.
   Verify the checksum file before using it as the download list:

   ```sh
   ssh-keygen -Y verify -f allowed_signers -I pixel10 -n chapeltech-pixel10-release -s SHA256SUMS.sig < SHA256SUMS
   ```

2. Download the factory ZIP and its `.sig` file. If the factory ZIP is split,
   download every numbered factory part instead of the ZIP. You do **not**
   need the OTA ZIP or the APKs to flash the OS. Set `build` to the ten-digit
   suffix of the release tag. In Bash:

   ```bash
   build=YYYYMMDDNN   # replace with the exact release build number
   install="frankel-install-$build.zip"
   (
       set -eo pipefail
       export LC_ALL=C
       [[ "$build" =~ ^20[0-9]{8}$ ]]
       if [[ ! -f "$install" ]]; then
           cat -- "$install".part[0-9][0-9][0-9] > "$install.reassembled"
           mv -- "$install.reassembled" "$install"
       fi
       awk -v name="$install" '$2 == name {print; found++} END {exit(found != 1)}' SHA256SUMS |
           sha256sum -c --strict
       ssh-keygen -Y verify -f allowed_signers -I pixel10 -n 'factory images' -s "$install.sig" < "$install"
   )
   ```

   Stop on any verification error. To confirm the verified-boot key before
   flashing, run `unzip -p "$install" "${install%.zip}/avb_pkmd.bin" | sha256sum`
   and compare the result with the independently obtained fingerprint.

## 3. Unlock, flash, and relock

1. Power off the phone. Hold **Volume Down** and **Power** until the bootloader
   screen appears, then connect USB. Check that `fastboot devices` lists your
   phone and that `fastboot getvar product` reports `frankel`. Stop if it does not.
2. Run `fastboot flashing unlock`. On the phone, use the volume buttons to
   select unlock and the power button to confirm the data wipe.
3. From the download directory in the same shell as above, extract and
   flash the verified ZIP:

   ```sh
   unzip "$install" &&
     (cd "${install%.zip}" && bash flash-all.sh)
   ```

   Use this archive's script, not the official GrapheneOS web installer.
   Leave the phone and cable alone while the script runs. **If any flash
   command fails, stop: do not relock a partial flash.** Keep the terminal
   output for troubleshooting.
4. After a successful flash, confirm the phone is at the bootloader screen.
   Run `fastboot flashing lock`, select lock on the phone and confirm the
   second wipe. Confirm the device state shows **locked** before selecting
   **Start**. On boot, compare the full hash on the yellow alternate-OS screen
   to the independently obtained ChapelTech boot-key fingerprint. Stop on a
   mismatch; do not enter personal data.
5. Finish Android setup. Leave **Disable OEM unlocking** selected in setup
   (or turn **OEM unlocking** off afterward in Developer options if needed).
   For fastboot troubleshooting, see the
   [upstream CLI guide](https://grapheneos.org/install/cli).

## 4. Install the desktop APKs

The OS does not preinstall the desktop apps. For the first Beta, download
`controller.apk`, `styx.apk`, and `xmonad.apk` from the **same OS release**
as your factory image. In the download directory, verify each against the
already authenticated `SHA256SUMS` before transferring or installing it:

```sh
(
    set -eo pipefail
    for apk in controller.apk styx.apk xmonad.apk; do
        awk -v name="$apk" '$2 == name {print; found++} END {exit(found != 1)}' SHA256SUMS |
            sha256sum -c --strict
    done
)
```

Stop on any verification failure. Install the three verified APKs in the
phone's owner profile. Pick one of these methods:

- **Files (no USB debugging):** Copy the verified files to the phone's
  **Downloads** folder. For USB file transfer, unlock the phone, open its USB
  notification, and select **File transfer** under **Use USB for**; then copy
  the files with an MTP-capable file manager on the computer. Open the APKs
  individually in **Files**. If Android blocks installation, use
  **Settings → Apps → Special app access → Install unknown apps → Files → Allow
  from this source**. If you opened the APK from a different app, Android
  names that app instead of Files. Install the three APKs, then turn off
  **Allow from this source** for the installer you used.
- **ADB (optional):** On the newly flashed Android system, tap **Build number**
  seven times in **Settings → About phone**. Turn on **USB debugging** in
  **Settings → System → Developer options**, connect the phone, and approve
  your computer on the unlocked phone. Leave **OEM unlocking** off.
  Verify that `adb devices` shows the phone as `device`, not `unauthorized`.
  In the download directory run:

  ```sh
  adb install controller.apk &&
    adb install styx.apk &&
    adb install xmonad.apk
  ```

  Turn off **USB debugging** when finished. The Files app's install permission
  is not required for this route.

## 5. Enable the external desktop

1. Open **Settings → Apps → Special app access → External desktop** and approve
   **Desktop Controller**. You can also reach this screen from the controller's
   **OS permission settings** button. This is a separate permission from
   installing APKs; it is not granted automatically.
2. Connect your monitor, keyboard, and mouse. In **Desktop Controller** select
   **XMonad** and check that the phone screen is still normal while the
   external monitor is managed. Physical-device shortcuts use **Super** without
   the emulator's extra **Ctrl** modifier. Openbox and i3 are not part of this
   Beta's published APKs.

## 6. Set up updates

- **OS:** In **Settings → System → System updates → Release channel**, select
  **Beta** for test builds, or **Stable** when using a qualified release.
  A normal update does not require USB, unlocking, relocking, APK reinstall,
  or a wipe. A newer build must be published before an update appears. Report
  the build numbers and update error if an OTA fails; do not unlock or downgrade
  to work around it.
- **Apps:** The first Beta uses manual APK installation. When a compatible
  `desktop-apps-0.1-YYYYMMDDNN` release includes `desktop-updates.apk`, verify
  its signing certificate against the independently trusted **updater** key
  (`apksigner verify --print-certs desktop-updates.apk` and SHA-256 of the
  trusted `updater.der`), then install it using either APK method above.
  In **ChapelTech Desktop Updates**
  use **Allow app installation**, select **Use Beta app releases** if needed,
  and tap **Install desktop apps / check now**. Approve Android's install
  prompts. The updater handles the desktop APKs, not the OS. Until it is
  available, update the apps with verified, same-signer APKs; do not uninstall
  to work around a signature error.

For physical qualification, test both paths separately: OS OTA with the
desktop app versions held constant, and app-only OTA with the OS build held
constant. Verify the locked boot key, phone data, StyX11 settings, controller
approval, normal phone behavior, and the external desktop at 5120×1440.
Record Android's observed behavior for unattended app updates and approval
fallback, including a fresh install through Desktop Updates.
