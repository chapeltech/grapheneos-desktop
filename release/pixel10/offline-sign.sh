#!/bin/bash
# Run only on the offline signer with the reviewed GrapheneOS tools checkout.
set -eu -o pipefail
: "${BUILD_NUMBER:?}" "${SOURCE_COMMIT:?}" "${UNSIGNED:?}" "${UNSIGNED_SUMS_SHA256:?}" "${SIGNED:?}" "${ANDROID_KEYS:?}"
[[ "$BUILD_NUMBER" =~ ^20[0-9]{8}$ && "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ && "$UNSIGNED_SUMS_SHA256" =~ ^[0-9a-f]{64}$ ]]
[[ "$SIGNED" = /* && "$UNSIGNED" = /* && ! -e "$SIGNED" ]]
root=$PWD
here=$(cd "$(dirname "$0")" && pwd)
(cd "$UNSIGNED"; printf '%s  SHA256SUMS\n' "$UNSIGNED_SUMS_SHA256" | sha256sum -c -; sha256sum -c --strict SHA256SUMS)
test "$(cat "$UNSIGNED/source-commit")" = "$SOURCE_COMMIT"
test "$(cat "$UNSIGNED/build-number")" = "$BUILD_NUMBER"
test "$(git -C "$here" rev-parse HEAD)" = "$SOURCE_COMMIT"
test "$(git -C .repo/manifests rev-parse HEAD)" = "$(jq -r .manifest "$here/pins.json")"
script_pin=$(git -C .repo/manifests show HEAD:default.xml | python3 -c 'import sys,xml.etree.ElementTree as E; print(E.parse(sys.stdin).find("project[@name=\"script\"]").get("revision"))')
test "$(git -C script rev-parse HEAD)" = "$script_pin"
test -z "$(git -C script status --porcelain)"
test -f keys/frankel/id_ed25519
mkdir -p releases
mkdir "releases/$BUILD_NUMBER"
cp "$UNSIGNED"/frankel-{otatools,target_files}.zip "releases/$BUILD_NUMBER/"
script/generate-release.sh frankel "$BUILD_NUMBER"
out="$root/releases/$BUILD_NUMBER/release-frankel-$BUILD_NUMBER"
mkdir -m 700 "$SIGNED"
cp "$out/frankel-install-$BUILD_NUMBER.zip"{,.sig} "$out/frankel-ota_update-$BUILD_NUMBER.zip" "$SIGNED/"
cp "$UNSIGNED"/{source-commit,build-number,native-inputs-sha256} "$SIGNED/"
printf '%s\n' "$UNSIGNED_SUMS_SHA256" > "$SIGNED/unsigned-inputs-sha256"
for name in controller styx xmonad; do
    apksigner sign --ks "$ANDROID_KEYS/$name.jks" --out "$SIGNED/$name.apk" "$UNSIGNED/$name.apk"
done
cd "$SIGNED"
sha256sum *.apk *.zip *.zip.sig source-commit build-number native-inputs-sha256 unsigned-inputs-sha256 > SHA256SUMS
ssh-keygen -Y sign -f "$root/keys/frankel/id_ed25519" -n chapeltech-pixel10-release SHA256SUMS
