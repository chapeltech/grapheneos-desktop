# ChapelTech GrapheneOS Desktop

This is a custom GrapheneOS build for the **Pixel 10 (`frankel`)**, not the
Pixel 10 Pro, Fold or an emulator. It adds an external desktop without
replacing the normal phone interface.

## Install on a Pixel 10

Follow the [complete Pixel 10 install guide](https://github.com/chapeltech/grapheneos-desktop/blob/release/pixel10/release/pixel10/INSTALL.md)
for the phone settings, downloads, verification, and command lines.
The [first Beta](https://github.com/chapeltech/grapheneos-desktop/releases/tag/frankel-0.1-2026112603)
has a factory image and three APKs to install manually. It does not include
Openbox, i3, or `desktop-updates.apk`.

1. **Back up first.** Unlocking and relocking both erase data. Do not downgrade
   the phone's security patch or firmware. In the existing Android system, tap
   **Build number** seven times in **Settings → About phone**. Turn on **OEM
   unlocking** in **Settings → System → Developer options**. USB debugging is
   not needed for flashing.
2. From [GitHub Releases](https://github.com/chapeltech/grapheneos-desktop/releases),
   download the factory ZIP (or every numbered part), its signature, and the
   signed checksums. Verify them using independently trusted ChapelTech keys.
   Unlock the bootloader, run the verified archive's `flash-all` script, and
   relock only after a successful flash. Check the boot-key fingerprint on the
   phone before entering personal data, and leave OEM unlocking off after setup.
3. Verify and install `controller.apk`, `styx.apk`, and `xmonad.apk` from the
   same release. The guide covers installing via **Files** with its temporary
   **Install unknown apps** permission, or via **ADB** with temporary **USB
   debugging**. Neither option requires unlocking the bootloader again.
4. In **Settings → Apps → Special app access → External desktop**, approve
   **Desktop Controller**. Connect a monitor, keyboard, and mouse, then choose
   XMonad in Desktop Controller.

## Updates

- **OS:** In **Settings → System → System updates → Release channel**, select
  **Beta** for a Beta build, or **Stable** for a qualified release. Routine OS
  updates do not require USB, unlocking, or a wipe.
- **Apps:** Update the APKs manually for now. When a compatible
  `desktop-apps-0.1-YYYYMMDDNN` release is published, the install guide explains
  how to set up its separate **ChapelTech Desktop Updates** APK. Do not uninstall
  an existing app to work around a signature mismatch.

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
