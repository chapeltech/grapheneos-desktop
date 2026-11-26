# GitHub-hosted Pixel 10 signing

Build on the existing dedicated **build** runner without signing credentials.
Both OS and app release jobs run on disposable GitHub-hosted runners. Production
private keys are held as GitHub environment secrets, not in Git, release assets,
Actions artifacts, or on the build host. No signing or publishing server is
required. The public OS and app OTA pointers live on the `ota` branch.

## Protect signing and publication

1. Protect `release/pixel10` and require review of changes to release workflows,
   signing scripts, and trust files. In GitHub Settings → Environments, restrict
   `pixel10-sign` to the literal `release/pixel10` **branch** (not tags),
   configure a required reviewer, and disable administrator bypass. Configure
   `pixel10-stable` the same way, with an independent reviewer of the physical
   hardware report. The Stable environment does not need any key secrets.
2. The OS signing job needs at least 40 GiB free. If the default GitHub-hosted
   runner has less, set `PIXEL10_GITHUB_RUNNER` to the organization's
   GH-hosted larger Ubuntu runner. Install Android build tools 35.0.0 on the
   runner image (the workflow uses `ANDROID_HOME/build-tools/35.0.0`).
   A self-hosted runner cannot access production keys through this workflow.
3. Follow the key directions for the pinned [GrapheneOS release](https://grapheneos.org/build#generating-release-signing-keys).
   Use the nine OS signing roles, the AVB RSA4096 key plus `avb_pkmd.bin`,
   and a separate Ed25519 factory key `id_ed25519`. For the protected runner,
   the OS key files must be unwrapped PKCS#8/PEM; the GitHub environment
   supplies the protection at rest. Use a separate PKCS#12 signing identity
   for the three desktop APKs (`desktop.p12` and `desktop.pass`), another
   for the updater (`updater.p12` and `updater.pass`), and a separate Ed25519
   catalog key (`app-catalog.pem`). Generate or open the keys only in a
   private temporary workspace (or use a trusted administrator workstation).
   Back up the keyset in encrypted form before a production phone uses it;
   GitHub environment secrets cannot be downloaded back through the API.
   Never generate replacement keys for an already-installed fleet.
4. Export public trust and add only the resulting public files to a reviewed PR
   targeting `release/pixel10`:

   ```sh
   python3 release/pixel10/hosted_trust.py "$OS_KEYS" "$APP_KEYS" release/pixel10/trust --avbtool "$AVBTOOL"
   ```

   Distribute the factory signing public key and boot / APK fingerprints to
   the installer independently of GitHub Releases. Use the same public APK
   and catalog values for the updater build as in [the operator guide](README.md).
5. In a private temporary workspace, package the two directories into GitHub's
   per-secret size limit. Use a GitHub CLI session authorized to write this
   environment's secrets, after checking the protections above:

   ```sh
   umask 077
   python3 release/pixel10/hosted_keys.py pack os "$OS_KEYS" "$SECURE_TMP/os-parts"
   python3 release/pixel10/hosted_keys.py pack apps "$APP_KEYS" "$SECURE_TMP/app-parts"
   for part in "$SECURE_TMP"/os-parts/* "$SECURE_TMP"/app-parts/*; do
       gh secret set --repo chapeltech/grapheneos-desktop --env pixel10-sign "${part##*/}" < "$part" || break
   done
   ```

   Do not echo, paste, commit, or upload the private inputs or chunks as
   assets. A final chunk containing `-` is intentional. Confirm both complete
   packs are present, then enable `PIXEL10_SIGNING_ENABLED` and
   `PIXEL10_APP_SIGNING_ENABLED` and remove the private temporary copies.

## Stage a build

From the reviewed build output, obtain the handoff's type (`os` or `apps`),
build, protected source commit and SHA-256 of its `SHA256SUMS` file.
Use a **private prerelease draft**, not a tag or a public release, for intake.
Never publish an intake draft. The step restores the exact approved bytes
and checks the GitHub asset digests as well as the handoff checksums.

```sh
repo=chapeltech/grapheneos-desktop
tag="pixel10-intake-$kind-$build"
python3 release/pixel10/hosted_intake.py pack "$kind" "$unsigned" "$parts" "$build" "$commit" "$digest"
gh release create "$tag" --repo "$repo" --draft --prerelease --target "$commit" \
  --title "Private unsigned signing intake: $kind $build — do not publish"
gh release upload "$tag" --repo "$repo" "$parts"/*
```

Dispatch the OS or app release workflow on `release/pixel10`, selecting
`sign-only` to verify without publishing or `beta` for the first installable
candidate. Supply the exact approved digest and source commit, then review
the run summary before approving the signing environment. Keep the OS
intake draft until Stable promotion; the verifier uses its checksum-bound
OTA tools. Promote the published Beta without re-signing only after the
hardware test and Stable review described in the operator guide.
