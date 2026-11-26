#!/bin/bash
# Build a desktop release independently of the Android system image.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
: "${BUILD_NUMBER:?}" "${APP_BUILD_ROOT:?}" "${NATIVE_INPUTS:?}" "${NATIVE_SHA256:?}"
: "${SDK_CHECKOUT:?}" "${CATALOG_KEY:?}" "${DESKTOP_CERT:?}" "${MIN_OS:?}" "${MAX_OS:?}"
[[ "$APP_BUILD_ROOT" = /* && "$BUILD_NUMBER" =~ ^20[0-9]{8}$ && "$NATIVE_SHA256" =~ ^[a-f0-9]{64}$ ]]
[[ "$MIN_OS" =~ ^20[0-9]{8}$ && "$MAX_OS" =~ ^20[0-9]{8}$ &&
   ( "$MIN_OS" < "$MAX_OS" || "$MIN_OS" == "$MAX_OS" ) ]]
work="$APP_BUILD_ROOT/$BUILD_NUMBER"
mkdir -m 700 "$work"
cd "$work"
mkdir unsigned sdk deps
printf '%s  %s\n' "$NATIVE_SHA256" "$NATIVE_INPUTS" | sha256sum -c -
python3 - "$NATIVE_INPUTS" <<'PY'
import sys, tarfile
with tarfile.open(sys.argv[1]) as f:
    if any(not (m.isdir() or m.isfile()) for m in f):
        raise ValueError("native inputs must contain only directories and regular files")
    f.extractall("deps", filter="data")
PY
base=$(jq -er '.forks["frameworks/base"][1]' "$here/pins.json")
contract=libs/WindowManager/Shell/externaldesktop/contract
git -C "$SDK_CHECKOUT" archive "$base" "$contract/src" |
    tar -x -C sdk --strip-components=5
test -d sdk/src/main
cp "$here/sdk.gradle.kts" sdk/build.gradle.kts
git init -q apps
apps_sha=$(jq -er .styx11 "$here/pins.json")
git -C apps fetch --depth=1 https://github.com/chapeltech/styX11.git "$apps_sha"
git -C apps checkout --detach "$apps_sha"
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
gradle --offline --max-workers=72 -p "$here/updater" -PdesktopVersionCode="$code" \
    -PcatalogKey="$CATALOG_KEY" -PdesktopCert="$DESKTOP_CERT" testDebugUnitTest assembleRelease
cp "$here/updater/build/outputs/apk/release/chapeltech-desktop-updates-release-unsigned.apk" unsigned/desktop-updates.apk
cd unsigned
git -C "$here" rev-parse HEAD > source-commit
printf '%s\n' "$BUILD_NUMBER" > build-number
printf '%s\n' "$NATIVE_SHA256" > native-inputs-sha256
printf '%s %s\n' "$MIN_OS" "$MAX_OS" > os-range
sha256sum *.apk source-commit build-number native-inputs-sha256 os-range > SHA256SUMS
sha256sum SHA256SUMS
