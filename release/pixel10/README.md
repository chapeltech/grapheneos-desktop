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
* Register dedicated build, signing and publishing Linux runners (labels in the workflows).
  Restrict runner groups to the named workflows on the protected branch; do
  not permit fork/PR workflows or reuse a public general-purpose runner.
  Require reviewers on build, signing and stable environments, particularly
  independent approval of the hardware report before stable publication.
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
* Generate fresh per-device release keys on a separate offline system following
  the selected upstream tag's key instructions (including the factory Ed25519
  key); separately create one desktop APK keystore for the three companion apps.
  Never use any OS key for the desktop APKs. Back up and test restoration
  offline before publishing. Never upload private keys, signed target-files,
  otatools, or keystores as public release assets.
* Provision the separate signing host as described in [Signing with GitHub
  Actions](SIGNING.md). No signing keys or key passwords belong in GitHub.
* On the publisher install gh, Python 3.11+,
  aapt2, apksigner and the trusted matching `check_ota_package_signature` tool.
  Mount signed inputs read-only at SIGNED_ROOT/BUILD. PUBLIC_TRUST is an
  independently provisioned directory of **public** releasekey.x509.pem,
  avb_pkmd.bin, desktop.der, and allowed_signers
  containing `pixel10 <factory SSH public key>`. Supply the protected values to both
  publication environments. No private signing keys on the build or publish runner.
* The publisher updates the metadata-only `ota` branch using GitHub's
  Contents API and the previous blob SHA. Do not edit channel pointers by
  hand or put binaries on that branch. No S3 bucket or ChapelTech redirect
  is used. GitHub's final asset URL must serve verified bytes and support
  HTTP Range; absent incrementals must return 404 so the updater can fall
  back to the full OTA.

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
   build summary. Stage the unsigned handoff and exact intake record on the
   signing host; only accept outputs from the dedicated reviewed build. The
   tools inside otatools execute on the signing host.
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

1. Install `apps.py`, `ota_publication.py`, `sign-release.py` and `sign-apps.py` as root-owned
   code on the existing dedicated signer; name the last executable
   `/usr/local/libexec/pixel10/sign-apps`. Give the runner sudo access only to
   that fixed command as `pixel10-sign`; do not add source checkout steps
   on the signing runner. Restrict the runner group and signing environment
   to the OS and app workflows on protected `release/pixel10`. Follow [SIGNING.md](SIGNING.md)
   for ownership, intake, permissions, and token separation.
2. Configure `/etc/chapeltech/pixel10-app-signer.toml` using
   [app-signer.toml.example](app-signer.toml.example). Use the existing
   desktop APK signing key for the three apps, plus a distinct updater APK
   signing key and an Ed25519 catalog key. Keep all private keys on the signer
   and backed up offline. Export the two public APK certificates as
   `desktop.der` and `updater.der` and the catalog public key as
   `app-catalog.pem` to the independently provisioned public-trust directory.
   Distribute both APK fingerprints independently for first install.
3. Set `APP_CATALOG_PUBLIC_KEY` on the build environment to
   `openssl pkey -pubin -in app-catalog.pem -outform DER | base64 -w0`;
   set `DESKTOP_APK_SHA256` to the SHA-256 of `desktop.der`. Set
   `APP_BUILD_ROOT` and `SDK_CHECKOUT` (a local framework/base Git repository
   containing the exact pinned commit), and the same reviewed ARM64 native
   input variables as the OS build. Pre-cache the updater's pinned Gradle
   dependencies, including its JVM test dependencies, for the offline build.
   Mount the signer output read-only as
   `APP_SIGNED_ROOT` on the publisher. The publisher also writes the two
   `desktop-apps-{beta,stable}.json` pointers on GitHub's `ota` branch.
   Only then enable
   `PIXEL10_APP_SIGNING_ENABLED=true`.
4. Dispatch **Build, sign and publish Pixel 10 desktop apps** with operation
   **build**, a unique app build number, and the minimum/maximum tested OS
   builds, inclusive. Stage the exact unsigned app handoff and its
   `SOURCE_COMMIT SHA256SUMS_DIGEST` intake record separately from the OS.
   Run **sign-only** or **beta**. The publisher verifies the public tagged
   assets before advancing the signed Beta catalog. An interrupted draft
   with missing assets needs operator review; never overwrite public assets.
5. After testing the app-only update from a published Beta predecessor on
   hardware, run **stable** with its predecessor and qualification report.
   Stable app releases do not become GitHub's latest **OS** release. Catalogs
   expire 180 days after signing; cut a higher app release before expiry,
   even if the sources have not changed. Publish a higher app build if the
   compatible OS range changes. Phones never downgrade when switching channels.
