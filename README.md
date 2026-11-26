# ChapelTech GrapheneOS Desktop

This is a custom GrapheneOS build for the **Pixel 10 (`frankel`)**, not the
Pixel 10 Pro, Fold or an emulator. It adds an external desktop without
replacing the normal phone interface.

## Install on a Pixel 10

1. **Back up first.** Unlocking **and relocking** erase the phone. Make sure
   **OEM unlocking** is available and never downgrade its firmware.
2. Open [GitHub Releases](https://github.com/chapeltech/grapheneos-desktop/releases).
   Use the [latest Stable OS release](https://github.com/chapeltech/grapheneos-desktop/releases/latest),
   tagged `frankel-0.1-YYYYMMDDNN`. If there is no Stable OS release, wait
   unless you are deliberately testing a Beta. Actions artifacts and source
   ZIPs are not install images.
3. Download and verify the **factory install** ZIP (or all its numbered
   parts), its signature, and the signed checksums. Get the release public
   key and verified-boot fingerprint independently through your ChapelTech
   administrator, not from the download you are verifying. Follow the exact
   [verification and flashing commands on the Pixel 10 release branch](https://github.com/chapeltech/grapheneos-desktop/blob/release/pixel10/release/pixel10/INSTALL.md). Use
   that ZIP's `flash-all` script, not the official GrapheneOS web installer.
   Stop on any flashing error; never relock a partial flash. Relock only
   after successfully flashing and verify the boot-key fingerprint on the
   phone before entering personal data.
4. From [GitHub Releases](https://github.com/chapeltech/grapheneos-desktop/releases),
   choose the newest `desktop-apps-0.1-YYYYMMDDNN` release whose OS range
   includes your build. Choose Stable for normal use, or a compatible
   prerelease if you are testing Beta. Download `desktop-updates.apk` and compare
   its APK signing certificate with the independently obtained ChapelTech
   **updater** fingerprint (`apksigner verify --print-certs desktop-updates.apk`)
   before installing. Open **ChapelTech Desktop Updates**, select **Allow
   app installation**, then **Install desktop apps / check now** and
   approve the Android prompts. This installs Desktop Controller, StyX11 and
   XMonad together. For a test release, explicitly select **Use Beta app
   releases** in Desktop Updates.
5. Open **Settings → Apps → Special app access → External desktop** and
   approve the installed controller. Connect a monitor, keyboard and mouse,
   and choose XMonad in Desktop Controller. The phone does not approve a
   controller automatically.

## Updates

- **OS:** **Settings → System → System updates** downloads and applies the
  selected GrapheneOS OTA channel. Stable is for qualified builds; only select
  Beta if you are testing. Routine updates do not require USB or a wipe.
- **Apps:** ChapelTech Desktop Updates checks automatically on unmetered
  networks, independently of the OS channel. If Android needs confirmation,
  tap the notification or reopen Desktop Updates and tap **Install desktop
  apps / check now**. Updates can restart the desktop apps and interrupt
  running sessions. Turn background updates off in the updater if you want
  to control when that happens.
- `controller.apk`, `styx.apk` and `xmonad.apk` are also available for
  manual recovery. Verify those against the ChapelTech **desktop** APK
  fingerprint. A manually installed APK may need an Android confirmation
  when first updated by Desktop Updates. Do not uninstall an app to work
  around a signature mismatch; doing so can erase its data.

## Development

This repository owns the privileged desktop extension, SDK, conformance tests,
upstream manifest pins, build tools, and the Pixel 10 release and OTA pipelines.
See the [release operator guide on the Pixel 10 release branch](https://github.com/chapeltech/grapheneos-desktop/blob/release/pixel10/release/pixel10/README.md).
It does not own window-manager policy, StyX11, grsh or the Compose laboratory.

Our Android project modifications are commits in independent Git repositories
under `forks/`, indexed by `forks.lock.json`. There are no object alternates into
the old checkouts; immutable upstream objects are hard-linked locally to avoid
duplicating gigabytes. Deleting an old checkout does not delete a fork's links.
Do not add `forks/` as ordinary files to this integration repository: use the
lab's source export, which bundles the unique commits separately.

Edit upstream changes in the small canonical Git worktrees under `projects/`
(for example `projects/frameworks/base`), on `desktop/work`. They initially show
only changed files; use Git sparse-checkout to expand the view when needed.
Keep new commits in the fork, then deliberately update the lock before using them
in a reproducible build. The lab export includes dirty fork worktrees as well as refs.

Each preserved checkout has an `archive/...` branch. `desktop/emulator` and
`desktop/pixel10` also preserve the previously selected development trees.
The active lock now selects `desktop/source-stack`: the exact current declared
43 framework / 6 Launcher / 4 Goldfish patch inputs, mechanically imported into
Git with no manual edits. `current-input-import.json` records that conversion;
`previous_active` retains the older selections. None implies runtime qualification.
Old patches/staging tools are provenance/compatibility material, not an authority
for new edits. Modify fork commits and update the lock for future source changes.

Generate a repo local manifest using the lab's `tools/fork_manifest.py
grapheneos-desktop --profile emulator` (or `pixel10`). It pins exact fork commits;
keep the authenticated upstream manifest for all unchanged projects. Application
of this manifest and subsequent builds require an explicitly chosen build workspace.

Build the SDK directly with `gradle --offline -p android
:desktop-sdk:verifyPhase1Publication`. Its Maven coordinate remains
`org.wonad:desktop-sdk:3.1.0`; no API/package identity was changed in migration.
The native broker/input and OS integration modules remain below `android/`.

The [shared lab](../wonad-lab/README.md) owns image composition and cross-component
tests. The Pixel 10 target remains frankel; the x86-64 emulator is only a development
sibling. Existing release/build/source gates remain required; moving files does
not qualify a release or grant authority to install one.
