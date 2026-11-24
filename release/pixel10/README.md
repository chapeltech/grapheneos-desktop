# Building and operating the Pixel 10 release

Owner: chapeltech/grapheneos-desktop. Public updater base:
`https://repo.chapeltech.uk/android/`. Version 0.1; tags are
`frankel-0.1-YYYYMMDDNN`. These workflows do not run on PRs or flash phones.

## One-time operator setup

* Publish the three fork commits from pins.json on their existing new
  `desktop/pixel10-release-2026111800` refs and the pinned StyX11 revision
  on `wonad/integration`. Merge the workflows into the protected default
  branch. Preserve existing branch names. The phone release does not use the
  emulator lock, the legacy API-v3 signing pipeline, or workstation paths.
* Register two dedicated self-hosted Linux runners (labels in the workflows).
  Restrict runner groups to the named workflows on the protected branch; do
  not permit fork/PR workflows or reuse a public general-purpose runner.
  Require reviewers on build, beta and stable environments, particularly
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
* On the publisher install gh, AWS CLI v2 with conditional S3 writes, Python 3.11+,
  aapt2, apksigner and the trusted matching `check_ota_package_signature` tool.
  Mount signed inputs read-only at SIGNED_ROOT/BUILD. PUBLIC_TRUST is an
  independently provisioned directory of **public** releasekey.x509.pem,
  avb_pkmd.bin, desktop.der, and allowed_signers
  containing `pixel10 <factory SSH public key>`. Set OTA_BUCKET and an instance
  role limited to serving/writing the OTA objects and channel pointers (no
  deletes); protect/version these objects. Supply the protected values to both
  publication environments. No private signing keys on either runner.
* Provision `android-ota.chapeltech.uk` as the HTTPS public origin for that
  bucket (TLS and DNS). Deploy the reserved `/android/*` redirect from
  chapeltech/pkgs' `netlify/_redirects` on its Netlify publication branch.
  The origin
  must support ranges, return **404**, not 403, for absent incrementals and
  channels, and serve channel files without caching. Never embed a transient
  bucket hostname in phones. Publish commits with the existing ChapelTech
  deployment process rather than overwriting unrelated package routes.

## Cut a release

1. Choose a new ten-digit build number. Check the live frankel stable channel,
   verify its signed manifest, rebase the three fork deltas, update pins.json,
   review vendor/firmware revisions against the previous release and the target
   phone. Never move an installed fleet backward. Build from a reviewed default
   branch commit. Dispatch **Build unsigned Pixel 10 release**.
   If the manifest's Settings revision changed, review and rebase the small
   `settings-external-desktop.patch` before updating its revision pin. It only
   links Special app access to SystemUI; there is no Settings fork.
2. Independently record the commit, build number and SHA256SUMS digest in the
   build summary. Transfer only the unsigned directory to the offline signer.
   The build tools inside otatools execute on the signer: do not sign artifacts
   from untrusted runners. From the pinned GrapheneOS checkout, run
   `bash /path/to/this/release/pixel10/offline-sign.sh` with BUILD_NUMBER,
   SOURCE_COMMIT, UNSIGNED, UNSIGNED_SUMS_SHA256, SIGNED (new absolute directory)
   and DESKTOP_KEYSTORE (absolute path to the desktop-only keystore).
   Use the reviewed orchestration checkout at SOURCE_COMMIT. Transfer only the
   resulting signed directory back.
3. Dispatch **Publish signed Pixel 10 release**, channel **beta**, with the
   original unsigned digest, at the same reviewed source commit. Reviewers
   check source and inputs. The job checks both signed inventories, AVB key,
   OTA signature, APK identity/pins and version, and the complete OTA served
   through the phone URL before updating the channel. A full OTA up to S3's
   single-PUT size limit is supported; GitHub assets at or above 2 GiB are
   split for manual download only. If interrupted mid-draft, inspect the draft
   and finish/remove it manually; never overwrite a published asset.
4. See [installation and qualification](INSTALL.md). For the first stable
   release, install candidate N, relock and verify its boot key, install the
   apps, enable consent and create test data. Publish N+1 to Beta, update via
   Settings without USB and verify the boot key, user data, APKs, consent and
   external desktop on the 5120×1440 monitor. Record the exact builds, locked
   boot status, and results in a hardware report. Dispatch stable for the exact
   N+1 handoff with predecessor and report URL; only then approve promotion.
   Future releases repeat the predecessor-to-candidate test. Never move a
   channel backward; release a higher-numbered fix or pause promotion.
