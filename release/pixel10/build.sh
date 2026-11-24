#!/bin/bash
# Dedicated non-root ephemeral runner. No signing material on this machine.
set -eo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo_dir=$(git -C "$here" rev-parse --show-toplevel)
: "${BUILD_NUMBER:?}" "${BUILD_ROOT:?}" "${NATIVE_INPUTS:?}" "${NATIVE_SHA256:?}"
[[ "$BUILD_ROOT" = /* && "$BUILD_NUMBER" =~ ^20[0-9]{8}$ && "$NATIVE_SHA256" =~ ^[a-f0-9]{64}$ ]]
export LC_ALL=C.UTF-8
work="$BUILD_ROOT/$BUILD_NUMBER"
mkdir -m 700 -- "$work"
mkdir "$work/os" "$work/unsigned" "$work/sdk"
cd "$work"
printf '%s  %s\n' "$NATIVE_SHA256" "$NATIVE_INPUTS" | sha256sum -c -
python3 - "$NATIVE_INPUTS" <<'PY'
import sys, tarfile
with tarfile.open(sys.argv[1]) as f:
    if any(not (m.isdir() or m.isfile()) for m in f):
        raise ValueError("native inputs must contain only directories and regular files")
    f.extractall("deps", filter="data")
PY
cd os
tag=$(jq -r .release "$here/pins.json")
read -r stable _ < <(curl --proto '=https' --fail --silent --show-error https://releases.grapheneos.org/frankel-stable)
test "$tag" = "$stable" || { echo "Review and port the current frankel stable tag before a new release." >&2; exit 1; }
repo init -u https://github.com/GrapheneOS/platform_manifest.git -b "refs/tags/$tag" --depth=1
git -C .repo/manifests fetch --depth=1 origin "refs/tags/$tag:refs/tags/$tag"
git -C .repo/manifests -c "gpg.ssh.allowedSignersFile=$repo_dir/android/platform/allowed_signers" verify-tag "$tag"
test "$(git -C .repo/manifests rev-parse HEAD)" = "$(jq -r .manifest "$here/pins.json")"
repo sync --fail-fast -j8
python3 "$here/source.py"
export OFFICIAL_BUILD=true BUILD_NUMBER
source build/envsetup.sh
yarn --cwd vendor/adevtool install --frozen-lockfile
vendor/adevtool/bin/run generate-all -d frankel
lunch frankel-cur-user
m -j72 vendorbootimage vendorkernelbootimage target-files-package otatools-package
script/finalize.sh
cp "releases/$BUILD_NUMBER/"{frankel-target_files,frankel-otatools}.zip "$work/unsigned/"
python3 "$here/check-target.py" "$work/unsigned/frankel-target_files.zip"
cd "$work"
git init -q apps
apps_sha=$(jq -r .styx11 "$here/pins.json")
git -C apps fetch --depth=1 https://github.com/chapeltech/styX11.git "$apps_sha"
git -C apps checkout --detach "$apps_sha"
cp "$here/sdk.gradle.kts" sdk/build.gradle.kts
ln -s "$work/os/frameworks/base/libs/WindowManager/Shell/externaldesktop/contract/src" sdk/src
code=$((10#$BUILD_NUMBER - 2000000000))
gradle --offline --max-workers=72 -p apps/android -PdesktopSdkSource="$work/sdk" \
    -PwonadAbi=arm64-v8a -PwmEmulator=false -PdesktopVersionCode="$code" -PwmBuildNumber="$code" \
    -PstyxNativeDir="$work/deps/styx/native" -PstyxAssetsDir="$work/deps/styx/assets" \
    -PwmXmonadNativeDir="$work/deps/xmonad/native" -PwmProviderNativeDir="$work/deps/provider/native" \
    :desktop-controller:assembleRelease :styx-desktop:assembleProductionRelease :wm-xmonad:assembleRelease
for pair in desktop-controller:controller styx-desktop:styx wm-xmonad:xmonad; do
    mapfile -t apk < <(find "apps/android/${pair%:*}/build/outputs/apk" -name '*release-unsigned.apk')
    test "${#apk[@]}" -eq 1
    cp "${apk[0]}" "unsigned/${pair#*:}.apk"
done
cd unsigned
git -C "$repo_dir" rev-parse HEAD > source-commit
printf '%s\n' "$BUILD_NUMBER" > build-number
printf '%s\n' "$NATIVE_SHA256" > native-inputs-sha256
sha256sum *.zip *.apk source-commit build-number native-inputs-sha256 > SHA256SUMS
sha256sum SHA256SUMS
