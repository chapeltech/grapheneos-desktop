#!/bin/bash
# Run only on the offline signer with the reviewed GrapheneOS tools checkout.
set -eu -o pipefail
: "${BUILD_NUMBER:?}" "${SOURCE_COMMIT:?}" "${UNSIGNED:?}" "${UNSIGNED_SUMS_SHA256:?}" "${SIGNED:?}" "${DESKTOP_KEYSTORE:?}"
[[ "$BUILD_NUMBER" =~ ^20[0-9]{8}$ && "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ && "$UNSIGNED_SUMS_SHA256" =~ ^[0-9a-f]{64}$ ]]
[[ "$SIGNED" = /* && "$UNSIGNED" = /* && ! -e "$SIGNED" ]]
root=$PWD
here=$(cd "$(dirname "$0")" && pwd)
source_checkout=${ORCHESTRATION_CHECKOUT:-"$here/../.."}
pins="$source_checkout/release/pixel10/pins.json"
(cd "$UNSIGNED"; printf '%s  SHA256SUMS\n' "$UNSIGNED_SUMS_SHA256" | sha256sum -c -; sha256sum -c --strict SHA256SUMS)
test "$(cat "$UNSIGNED/source-commit")" = "$SOURCE_COMMIT"
test "$(cat "$UNSIGNED/build-number")" = "$BUILD_NUMBER"
test "$(git -C "$source_checkout" rev-parse HEAD)" = "$SOURCE_COMMIT"
test "$(git -C .repo/manifests rev-parse HEAD)" = "$(jq -r .manifest "$pins")"
test "$(jq -r .update_url "$pins")" = "https://raw.githubusercontent.com/chapeltech/grapheneos-desktop/ota/"
python3 "$source_checkout/release/pixel10/check-target.py" "$UNSIGNED/frankel-target_files.zip"
script_pin=$(git -C .repo/manifests show HEAD:default.xml | python3 -c 'import sys,xml.etree.ElementTree as E; print(E.parse(sys.stdin).find("project[@name=\"script\"]").get("revision"))')
test "$(git -C script rev-parse HEAD)" = "$script_pin"
test -z "$(git -C script status --porcelain)"
test -f keys/frankel/id_ed25519
mkdir -p releases
mkdir "releases/$BUILD_NUMBER"
cp "$UNSIGNED"/frankel-{otatools,target_files}.zip "releases/$BUILD_NUMBER/"
apk_password=()
if [[ -n ${DESKTOP_KS_PASS_FILE:-} ]]; then
    test -r "$DESKTOP_KS_PASS_FILE"
    apk_password=(--ks-pass "file:$DESKTOP_KS_PASS_FILE")
    # The automated signer keeps OS and SSH keys on an unlocked encrypted
    # volume. An explicitly empty password disables the upstream OS prompt.
    password= script/generate-release.sh frankel "$BUILD_NUMBER" </dev/null
else
    script/generate-release.sh frankel "$BUILD_NUMBER"
fi
out="$root/releases/$BUILD_NUMBER/release-frankel-$BUILD_NUMBER"
mkdir -m 700 "$SIGNED"
cp "$out/frankel-install-$BUILD_NUMBER.zip"{,.sig} "$out/frankel-ota_update-$BUILD_NUMBER.zip" "$SIGNED/"
cp "$UNSIGNED"/{source-commit,build-number,native-inputs-sha256} "$SIGNED/"
printf '%s\n' "$UNSIGNED_SUMS_SHA256" > "$SIGNED/unsigned-inputs-sha256"
jq -r .update_url "$pins" > "$SIGNED/ota-origin"
for name in controller styx xmonad; do
    apksigner sign --ks "$DESKTOP_KEYSTORE" "${apk_password[@]}" --v4-signing-enabled false \
        --out "$SIGNED/$name.apk" "$UNSIGNED/$name.apk"
done
desktop_cert=$(apksigner verify --print-certs "$SIGNED/controller.apk" |
    sed -n 's/^Signer #1 certificate SHA-256 digest: //p')
[[ "$desktop_cert" =~ ^[a-f0-9]{64}$ ]]
for cert in "$root"/keys/frankel/*.x509.pem; do
    os_cert=$(openssl x509 -in "$cert" -outform DER | sha256sum)
    test "${os_cert%% *}" != "$desktop_cert" || {
        echo "The desktop APK signing key must not be an OS signing key." >&2
        exit 1
    }
done
cd "$SIGNED"
sha256sum *.apk *.zip *.zip.sig source-commit build-number native-inputs-sha256 unsigned-inputs-sha256 ota-origin > SHA256SUMS
ssh-keygen -Y sign -f "$root/keys/frankel/id_ed25519" -n chapeltech-pixel10-release SHA256SUMS
