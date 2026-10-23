#!/usr/bin/env bash
# The immutable-builder half of Frankel vendor generation.
#
# Source authentication and cache cleanup deliberately do not belong here:
# they use host-pinned tools and are owned by run_frankel_vendor.py on the
# host.  This action may only install the pinned adevtool JavaScript
# dependencies and generate the authenticated Frankel vendor module.
set -euo pipefail

die() { echo "generate-frankel-vendor.sh: $*" >&2; exit 2; }

[[ $# == 0 ]] || die 'this builder action takes no arguments'
[[ $(id -u) == 1000 && $(id -g) == 1000 ]] || die 'run as UID/GID 1000:1000'

source_dir=${WONAD_GRAPHENEOS_RELEASE_SOURCE:-}
device=${WONAD_VENDOR_DEVICE:-}
yarn_bin=${WONAD_YARN_BIN:-}
expected_adevtool_commit=${WONAD_ADEVTOOL_COMMIT:-}

[[ "$source_dir" == /grapheneos ]] || die 'source must be the reviewed /grapheneos bind'
[[ "$PWD" == /grapheneos ]] || die 'working directory must be /grapheneos'
[[ "$device" == frankel ]] || die 'only the reviewed Frankel target is supported'
[[ "$yarn_bin" == /usr/bin/yarnpkg && -x "$yarn_bin" ]] || die 'pinned yarn path differs'
[[ "$ADEVTOOL_IMG_DOWNLOAD_DIR" == /adevtool-images ]] || die 'factory cache bind differs'
[[ "$expected_adevtool_commit" =~ ^[0-9a-f]{40}$ ]] || die 'adevtool commit pin is malformed'
[[ $(node --version) == v24.21.0 ]] || die 'Node.js version differs'
[[ $("$yarn_bin" --version) == 1.22.19 ]] || die 'Yarn version differs'

for path in vendor/adevtool vendor/adevtool/yarn.lock vendor/adevtool/bin/run; do
    [[ -e "$path" && ! -L "$path" ]] || die "missing or symlinked input: $path"
done
[[ ! -e vendor/google_devices/frankel && ! -L vendor/google_devices/frankel ]] ||
    die 'Frankel output must be absent before generation'

mkdir -m 0700 -- /tmp/wonad-vendor-home /tmp/wonad-vendor-yarn-cache
"$yarn_bin" --cwd vendor/adevtool install --frozen-lockfile --non-interactive
vendor/adevtool/bin/run generate-all -d "$device"

vendor=vendor/google_devices/frankel
[[ -d "$vendor" && ! -L "$vendor" ]] || die 'adevtool did not create the Frankel vendor directory'
for path in Android.mk AndroidProducts.mk BoardConfig.mk README.md frankel.mk \
            adevtool-version-check.mk; do
    [[ -f "$vendor/$path" && ! -L "$vendor/$path" ]] ||
        die "adevtool output is missing an ordinary $path"
done
for path in proprietary firmware; do
    [[ -d "$vendor/$path" && ! -L "$vendor/$path" ]] ||
        die "adevtool output is missing an ordinary $path directory"
done

expected_version=$(printf '%s\n%s\n%s' \
    "ifneq (\$(shell git -C vendor/adevtool rev-parse HEAD),$expected_adevtool_commit)" \
    '  $(error frankel vendor module is outdated. Run `adevtool generate-all -d frankel` to update it)' \
    'endif')
cmp -s -- "$vendor/adevtool-version-check.mk" <(printf '%s' "$expected_version") ||
    die 'generated adevtool version guard differs from the pinned revision'

echo 'PASS: immutable builder generated the pinned Frankel vendor module'
