# Signing with GitHub Actions

GitHub schedules and approves the release; the OS and desktop APK private
keys stay on a dedicated ChapelTech signing host. The build and publication
hosts must not be able to read those keys. Do not use the shared build host
as the signer or put keys or key passwords in GitHub Actions secrets.

## GitHub setup

1. Protect `master` and require review of changes to the release workflows
   and scripts. Create the `pixel10-sign` environment, allow only deploys
   from `master`, require a reviewer, and disable administrator bypass.
   For two-person control, prohibit approval by the person who dispatched
   the run. Leave the hardware-review requirement on `pixel10-stable`.
2. Create the organization runner group `pixel10-signers`. Allow only
   `chapeltech/grapheneos-desktop` and the workflow
   `chapeltech/grapheneos-desktop/.github/workflows/pixel10-publish.yml@refs/heads/master`.
   Register the dedicated host in this group with the label `pixel10-signer`.
   Do not register it in a general-purpose group or allow PR jobs on it.
3. When the host setup is verified, set the repository Actions variable
   `PIXEL10_SIGNING_ENABLED` to `true`. Leave it unset until then.
   `pixel10-beta` can use the signing approval without a second required
   reviewer; `pixel10-stable` is an independent approval and never signs.

## Signing host

Use a Linux host with Python 3.11+, Git, Bash, GrapheneOS release-tool
dependencies, JDK, Android build tools and enough scratch for the OS package.
Use two unprivileged service accounts: the GitHub runner and `pixel10-sign`.
Install the two reviewed scripts as root, outside the runner's work directory:

```sh
install -d -m 0755 /usr/local/libexec/pixel10
install -m 0755 release/pixel10/sign-release.py /usr/local/libexec/pixel10/sign-release
install -m 0644 release/pixel10/offline-sign.sh /usr/local/libexec/pixel10/offline-sign.sh
```

Install [signer.toml.example](signer.toml.example) as
`/etc/chapeltech/pixel10-signer.toml`, owned by root and writable only by root.
Grant read access to `pixel10-sign` and keep every configured directory and
the tool search path outside the GitHub runner's write access. As root, use
`visudo` to grant the runner account just this command (substitute its name):

```sudoers
pixel10-runner ALL=(pixel10-sign) NOPASSWD: NOSETENV: /usr/local/libexec/pixel10/sign-release
```

Put the reviewed release-repository checkout at `source_root/COMMIT` and a
checkout of the pinned GrapheneOS manifest at `graphene_root/MANIFEST_SHA`.
Keep source and tools administrator-controlled; only the signing account
needs write access to the GrapheneOS checkout's `releases/` directory. Follow
the upstream key instructions; use a separate desktop keystore. The automated
path expects OS and factory SSH key files without individual passphrases on an
encrypted, access-restricted volume, and the desktop keystore password in
the configured local file. Keep the backup offline and encrypted. Decrypted
key files, transient scratch, and private logs must not be readable by the
runner or publisher; disable swap or use encrypted swap on the signer.

`signed_root` must be owned by the signer with the publisher read group and
the setgid bit (mode `2750`). Mount it read-only on the publisher as `SIGNED_ROOT`.
The signer verifies the copied bytes in private scratch and exposes the
completed directory atomically. Each build's signing log stays in `log_root`.

## Stage and sign a build

Stage only the unsigned handoff at `unsigned_root/BUILD`. Register the exact
`COMMIT DIGEST` (one space, final newline) in `intake_root/BUILD`, where `DIGEST`
is the SHA-256 of the handoff's `SHA256SUMS`. Use a trusted intake account, not
the GitHub runner account, and compare the values against the reviewed build.
This matters because the GrapheneOS release script executes the build's
`otatools` archive. A checksum proves which bytes were approved, not that an
untrusted build is safe. Never accept arbitrary otatools or GitHub artifacts.

Dispatch **Sign and publish Pixel 10 release** on `master` with the build,
source commit, and unsigned digest. Use **sign-only** for the first trial;
**beta** signs and publishes. Review the identity in the preflight summary
before approving `pixel10-sign`. Re-dispatching Beta for the exact handoff
after a successful sign-only run reuses those signed files. A different
digest cannot replace an already signed build. After a failed signing run,
inspect the private log and move aside only that build's incomplete
GrapheneOS scratch before retrying. The publisher independently verifies
the signatures and OTA delivery.

For recovery, `offline-sign.sh` still works interactively from the reviewed
offline GrapheneOS checkout with `BUILD_NUMBER`, `SOURCE_COMMIT`, `UNSIGNED`,
`UNSIGNED_SUMS_SHA256`, `SIGNED`, and `DESKTOP_KEYSTORE` set. Do not set the
automated passfile variable on that path.
