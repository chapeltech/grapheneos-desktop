# Building and operating the Pixel 10 release

Owner: chapeltech/grapheneos-desktop. The phone reads channel metadata from
[GitHub Raw](https://raw.githubusercontent.com/chapeltech/grapheneos-desktop/ota/)
and downloads signed payloads from this repo's [GitHub Releases](https://github.com/chapeltech/grapheneos-desktop/releases).
Version 0.1; tags are
`frankel-0.1-YYYYMMDDNN`. These workflows do not run on PRs or flash phones.

## One-time operator setup

* Publish the three fork commits and the StyX11 commit from `pins.json` so the
  runner can fetch them by SHA. Merge the workflows into protected
  `release/pixel10`. The phone release does not use the
  emulator lock, the legacy API-v3 signing pipeline, or workstation paths.
* Register the dedicated Linux build runner. Allow only the named build
  workflows on the protected branch, never fork or PR workflows.
  Signing and publishing run on GitHub-hosted runners. Require reviewers on
  build, signing, and stable environments.
* Build runner: provision the [GrapheneOS build dependencies](https://grapheneos.org/build),
  repo, Node 24+, Yarn, Android SDK 35/build tools, JDK and AGP-compatible Gradle
  with its offline dependencies. Use a non-root account with read-only access
  to all selected repositories (including private ones), no publishing or signing
  credentials, and a **fresh** large source/output filesystem per build.
  Reserve at least 1 TiB free for a full checkout, vendor extraction, build
  and transfer headroom. Don't use the occupied emulator build tree.
* The first three APKs are the controller, StyX11 and the XMonad provider.
  Set build environment variables `BUILD_ROOT` (parent for unique build directories),
  `NATIVE_INPUTS` and `NATIVE_SHA256` to an independently reviewed ARM64 tar
  and its SHA-256; this runner assembles new APKs, not recycled APKs. Its
  contents are `styx/native/arm64-v8a/{libXlorie,libwonad_styx_desktop}.so`,
  `styx/assets/` (including XKB and licenses), `xmonad/native/arm64-v8a/`
  (executable) and `provider/native/arm64-v8a/` (provider and action).
  Produce them with the pinned client project's native recipes, retaining
  dependency source pins, licenses and toolchain record. Do not substitute
  the emulator payload. Neither the OS nor the APK build needs a signing
  certificate. The system owner chooses an installed controller after boot.
* Follow [GitHub-hosted signing](SIGNING.md) to provision the protected
  environment, key secrets and independently reviewed public trust.
  Build runners never get the private keys. Never expose production keys,
  signed target-files or otatools as public release assets.
* The publisher updates the metadata-only `ota` branch using GitHub's
  Contents API and the previous blob SHA. Do not edit channel pointers by
  hand or put binaries on that branch. No S3 bucket or ChapelTech redirect
  is used. GitHub's final asset URL must serve verified bytes and support
  HTTP Range; absent incrementals must return 404 so the updater can fall
  back to the full OTA. Publishers refuse to change the boot key, OS
  signing certificate set, or the relevant app signing identities relative
  to existing channels. Keep the first release's signing keys for updates.
  Run one production OS or app release workflow at a time; both write to
  the same metadata branch.

## Cut a release

1. Choose a new ten-digit build number. Check the live frankel stable channel,
   verify its signed manifest, rebase the three fork deltas, update pins.json,
   review vendor/firmware revisions against the previous release and the target
   phone. Never move an installed fleet backward. Build from a reviewed
   `release/pixel10` commit. Dispatch **Build unsigned Pixel 10 release**.
   If the manifest's Settings revision changed, review and rebase the small
   `settings-external-desktop.patch` before updating its revision pin. It only
   links Special app access to SystemUI; there is no Settings fork.
2. Independently record the commit, build number and SHA256SUMS digest in the
   build summary. Stage the verified unsigned handoff in a
   [private intake draft](SIGNING.md#stage-a-build). The checksum-bound OTA
   tools from this draft run on the GitHub-hosted signing runner.
3. From protected `release/pixel10`, dispatch **Sign and publish Pixel 10 release** with
   channel **beta**, the unsigned digest and its source commit. Review the build
   identity in the preflight summary, then approve `pixel10-sign`. Choose
   **sign-only** to test signing without touching GitHub Releases or OTA.
   The publisher checks both signed inventories, AVB key,
   OTA signature, APK identity/pins and version, and the complete OTA served
   through the phone URL before updating the channel. A full OTA must fit
   in one GitHub Release asset (strictly below 2 GiB); the factory ZIP can
   be split for manual download. If interrupted mid-draft, inspect the draft
   and finish/remove it manually; never overwrite a published asset.
4. See [installation and qualification](INSTALL.md). For the first stable
   release, install candidate N, relock and verify its boot key, install the
   apps, enable consent and create test data. Publish N+1 to Beta, update via
   Settings without USB and verify the boot key, user data, APKs, consent and
   external desktop on the 5120×1440 monitor. Record the exact builds, locked
   boot status, and results in a hardware report. Dispatch stable for the exact
   N+1 handoff with predecessor and report URL; only then approve promotion.
   Promote a compatible, independently qualified Stable app release first;
   the OS publisher verifies its signed catalog covers the OS being promoted.
   Future releases repeat the predecessor-to-candidate test. Never move a
   channel backward; release a higher-numbered fix or pause promotion.

## Desktop app releases (no OS rebuild)

1. Follow [SIGNING.md](SIGNING.md) to provision the APK signing identities
   and the Ed25519 catalog key in the protected signing environment.
   Distribute both APK fingerprints independently for first install.
2. Set `APP_CATALOG_PUBLIC_KEY` on the build environment to
   `openssl pkey -pubin -in app-catalog.pem -outform DER | base64 -w0`;
   set `DESKTOP_APK_SHA256` to the SHA-256 of `desktop.der`. Set
   `APP_BUILD_ROOT` and `SDK_CHECKOUT` (a local framework/base Git repository
   containing the exact pinned commit), and the same reviewed ARM64 native
   input variables as the OS build. Pre-cache the updater's pinned Gradle
   dependencies, including its JVM test dependencies, for the offline build.
3. Dispatch **Build, sign and publish Pixel 10 desktop apps** with operation
   **build**, a unique app build number, and the minimum/maximum tested OS
   builds, inclusive. Stage the exact unsigned app handoff as a private
   `pixel10-intake-apps-<build>` draft, separate from the OS.
   Run **sign-only** or **beta**. The publisher verifies the public tagged
   assets before advancing the signed Beta catalog. An interrupted draft
   with missing assets needs operator review; never overwrite public assets.
4. After testing the app-only update from a published Beta predecessor on
   hardware, run **stable** with its predecessor and qualification report.
   Stable app releases do not become GitHub's latest **OS** release. Catalogs
   expire 180 days after signing; cut a higher app release before expiry,
   even if the sources have not changed. Publish a higher app build if the
   compatible OS range changes. Phones never downgrade when switching channels.
