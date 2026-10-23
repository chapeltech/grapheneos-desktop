#!/usr/bin/env bash
# Build and sign the pinned Pixel 10 (frankel) Phase-1 OS release.
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage: release-build.sh preflight|prepare-vendor|build|sign|delta|receipt|verify|verify-delta

Required for every action:
  WONAD_GRAPHENEOS_RELEASE_SOURCE  dedicated repo-synced GrapheneOS checkout

Required for build:
  WONAD_APK_CERTIFICATE            ordinary public Wonad release X.509 certificate
  WONAD_UPDATE_URL                 project-owned HTTPS update base URL ending in /
  WONAD_BUILD_NUMBER               ten decimal digits, monotonically increasing
  WONAD_BUILDER_PROVENANCE         immutable capture-builder JSON
  WONAD_SOURCE_PROVENANCE          new external path for the complete source freeze
  WONAD_BUILD_OUT                  new external Android OUT_DIR
  WONAD_BUILD_LOG                  new external container build log
  WONAD_BUILD_CONTAINER            fresh wonad-phase1-frankel-release-<build>-* name
  WONAD_BUILD_EXECUTION_PROVENANCE new external successful-execution JSON path

Required for sign:
  WONAD_BUILD_NUMBER               build produced by the build action
  WONAD_RELEASE_KEY_DIR            external frankel GrapheneOS release-key directory
  WONAD_BUILDER_PROVENANCE         same immutable builder record used by build
  WONAD_SOURCE_PROVENANCE          source record created immediately before build
  WONAD_BUILD_OUT                  retained external OUT_DIR used by build
  WONAD_BUILD_LOG                  retained external container build log
  WONAD_BUILD_EXECUTION_PROVENANCE successful execution JSON created by build
  WONAD_BUILD_CONSUMPTION_PROVENANCE new external container-removal JSON path
  WONAD_CLIENT_PROVENANCE          production create-clients record
  WONAD_SDK_PUBLICATION            frozen API-v3 Maven publication directory
  WONAD_CONFORMANCE_APK            release-signed conformance APK
  WONAD_CONFORMANCE_SOURCE_RECEIPT fresh build-receipt.json for that APK/SDK source
  WONAD_APK_CERTIFICATE            public certificate matching APK and staged OS
  WONAD_APKSIGNER                  apksigner executable used to verify the APK

Required for delta:
  WONAD_PREDECESSOR_BUILD_NUMBER   exact ten-digit signed predecessor build
  WONAD_BUILD_NUMBER               exact ten-digit signed successor build
  WONAD_RELEASE_KEY_DIR            external frankel GrapheneOS release-key directory

Required for verify:
  WONAD_AVB_PUBLIC_KEY             exported avb_pkmd.bin / AVB public blob
  WONAD_OTA_CERTIFICATE            exported releasekey.x509.pem
  WONAD_FACTORY_PUBLIC_KEY         exported Ed25519 SSH public key
  WONAD_EXPECTED_RECEIPT_SHA256    authenticated release-receipt.json SHA-256
  WONAD_TRUSTED_OTATOOLS_MANIFEST  independent JSON hashes for verifier tools
  WONAD_EXPECTED_OTATOOLS_MANIFEST_SHA256  authenticated manifest SHA-256
  WONAD_VERIFICATION_EVIDENCE      new JSON output path outside the release tree

Required for verify-delta:
  WONAD_PREDECESSOR_BUILD_NUMBER   exact ten-digit predecessor build
  WONAD_BUILD_NUMBER               exact ten-digit successor build
  WONAD_EXPECTED_PAIR_RECEIPT_SHA256  authenticated incremental receipt SHA-256
  The public keys, trusted otatools manifest/digest and evidence path listed
  for verify are also required. WONAD_EXPECTED_RECEIPT_SHA256 is not used.

Optional:
  WONAD_BUILD_JOBS                 normal build concurrency (default 8)
  WONAD_BUILD_HIGHMEM_JOBS         Android high-memory pool depth (default 1)
  WONAD_BUILD_DATETIME             reproducible Unix timestamp (default manifest time)

The build action uses a fresh external OUT_DIR and retains its named Docker
container, log, preflight and execution record. It never runs Android build
commands on the host. The sign and delta actions refuse existing
destinations and active swap by default; set
WONAD_SIGN_WITH_ACTIVE_SWAP=I_UNDERSTAND only after reviewing the release-key
exposure trade-off.
EOF
}

die() { echo "release-build.sh: $*" >&2; exit 2; }

action=${1:-}
case "$action" in
    preflight|prepare-vendor|build|sign|delta|receipt|verify|verify-delta) ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
esac

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
source_arg=${WONAD_GRAPHENEOS_RELEASE_SOURCE:-}
[[ -n "$source_arg" ]] || die 'set WONAD_GRAPHENEOS_RELEASE_SOURCE'
[[ -d "$source_arg" ]] || die 'release source directory does not exist'
source_dir=$(realpath -e -- "$source_arg")
case "$source_dir" in
    /|/sources|"$root"|"$root"/*) die 'use a dedicated source directory outside Wonad' ;;
esac
[[ -d "$source_dir/.repo" ]] || die 'release source is not a repo checkout'
[[ -f "$source_dir/build/envsetup.sh" ]] || die 'complete the pinned source sync first'

lock=$root/android/grapheneos.lock.json
read_lock() {
    python3 -c 'import json,sys; value=json.load(open(sys.argv[1]));
for part in sys.argv[2].split("."): value=value[part]
print(value)' "$lock" "$1"
}
release=$(read_lock release)
device=$(read_lock release_pipeline.device)
lunch_target=$(read_lock release_pipeline.lunch_target)
[[ "$device" == frankel && "$lunch_target" == frankel-cur-user ]] ||
    die 'lock file is not the reviewed Pixel 10 user release plan'

jobs=${WONAD_BUILD_JOBS:-8}
highmem_jobs=${WONAD_BUILD_HIGHMEM_JOBS:-1}
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || die 'invalid WONAD_BUILD_JOBS'
[[ "$highmem_jobs" =~ ^[1-9][0-9]*$ ]] || die 'invalid WONAD_BUILD_HIGHMEM_JOBS'
((jobs <= 256 && highmem_jobs <= 64)) || die 'job limits exceed reviewed bounds'

verify_baseline() {
    python3 "$root/android/tools/checkout_health.py" --source "$source_dir"
    python3 "$root/android/tools/verify_sources.py" \
        --manifest "$source_dir/.repo/manifests" \
        --frameworks "$source_dir/frameworks/base" \
        --allowed-signers "$root/android/platform/allowed_signers"
    local actual expected pair
    for pair in 'packages/apps/Launcher3:launcher3' 'packages/apps/Updater:updater' \
                'device/generic/goldfish:emulator_goldfish'; do
        actual=$(git -C "$source_dir/${pair%%:*}" rev-parse HEAD)
        expected=$(read_lock "${pair##*:}.commit")
        [[ "$actual" == "$expected" ]] || die "${pair%%:*} differs from the authenticated source pin"
    done
}

resolve_public_file() {
    local variable=$1 value=${!1:-}
    [[ -n "$value" && -f "$value" && ! -L "$value" ]] ||
        die "set $variable to an ordinary public provenance input"
    realpath -e -- "$value"
}

resolve_source_provenance() {
    builder_provenance=$(resolve_public_file WONAD_BUILDER_PROVENANCE)
    local value=${WONAD_SOURCE_PROVENANCE:-} parent
    [[ -n "$value" ]] || die 'set WONAD_SOURCE_PROVENANCE to the external source record path'
    parent=$(realpath -e -- "$(dirname -- "$value")")
    source_provenance="$parent/$(basename -- "$value")"
    case "$source_provenance" in
        "$source_dir"|"$source_dir"/*) die 'source provenance must remain outside the OS checkout' ;;
    esac
}

validate_build_number() {
    build_number=${WONAD_BUILD_NUMBER:-}
    [[ "$build_number" =~ ^[0-9]{10}$ ]] || die 'WONAD_BUILD_NUMBER must be exactly ten decimal digits'
}

validate_build_pair() {
    predecessor_build_number=${WONAD_PREDECESSOR_BUILD_NUMBER:-}
    [[ "$predecessor_build_number" =~ ^[0-9]{10}$ ]] ||
        die 'WONAD_PREDECESSOR_BUILD_NUMBER must be exactly ten decimal digits'
    ((10#$build_number > 10#$predecessor_build_number)) ||
        die 'WONAD_BUILD_NUMBER must be monotonically greater than its predecessor'
}

verify_baseline

case "$action" in
    preflight|prepare-vendor|build)
        python3 "$root/android/tools/verify_checkout.py" --source "$source_dir" --jobs 32
        ;;
esac

if [[ "$action" == preflight ]]; then
    echo "PASS: authenticated GrapheneOS $release source for $lunch_target"
    exit 0
fi

if [[ "$action" == prepare-vendor ]]; then
    cd -- "$source_dir"
    yarn_bin=${WONAD_YARN_BIN:-}
    if [[ -z "$yarn_bin" ]]; then
        yarn_bin=$(command -v yarnpkg || command -v yarn || true)
    fi
    [[ -n "$yarn_bin" && -x "$yarn_bin" ]] || die 'Node.js 24 and yarn/yarnpkg are required for adevtool'
    clean_vendor_cache() {
        python3 "$root/android/tools/phase1_provenance.py" clean-vendor-cache --source "$source_dir"
    }
    clean_vendor_cache
    trap clean_vendor_cache EXIT
    "$yarn_bin" --cwd vendor/adevtool install --frozen-lockfile --non-interactive
    vendor/adevtool/bin/run generate-all -d "$device"
    [[ -f vendor/google_devices/frankel/AndroidProducts.mk ]] ||
        die 'adevtool completed without the frankel vendor tree'
    clean_vendor_cache
    trap - EXIT
    echo 'PASS: frankel vendor files generated; adevtool downloads and modules removed'
    exit 0
fi

validate_build_number
build_number=$WONAD_BUILD_NUMBER
case "$action" in
    delta|verify-delta) validate_build_pair ;;
esac

if [[ "$action" == build ]]; then
    resolve_source_provenance
    [[ ! -e "$source_provenance" && ! -L "$source_provenance" ]] ||
        die 'source provenance destination already exists; refusing overwrite'
    signer_certificate_arg=${WONAD_APK_CERTIFICATE:-}
    update_url=${WONAD_UPDATE_URL:-}
    [[ -n "$signer_certificate_arg" && -f "$signer_certificate_arg" && ! -L "$signer_certificate_arg" ]] ||
        die 'set WONAD_APK_CERTIFICATE to the ordinary public Wonad release X.509 certificate'
    signer_certificate=$(realpath -e -- "$signer_certificate_arg")
    case "$signer_certificate" in
        "$source_dir"|"$source_dir"/*) die 'Wonad public signer certificate must remain outside the OS source checkout' ;;
    esac
    [[ -n "$update_url" ]] || die 'set WONAD_UPDATE_URL to the project update endpoint'
    [[ -f "$source_dir/vendor/google_devices/frankel/AndroidProducts.mk" ]] ||
        die 'run prepare-vendor before the Pixel 10 build'
    if [[ -d "$source_dir/out" ]] && [[ -n "$(find "$source_dir/out" -mindepth 1 -print -quit)" ]]; then
        die 'production build requires an absent or empty out/ tree; archive it explicitly first'
    fi
    [[ ! -e "$source_dir/releases/$build_number" ]] ||
        die 'release build-number directory already exists; refusing overwrite'
    python3 "$root/android/platform/stage-os.py" --source "$source_dir" \
        --signer-certificate "$signer_certificate" --input-profile pixel10
    python3 "$root/android/platform/configure-updater.py" --source "$source_dir" --url "$update_url"
    python3 "$root/android/platform/stage-os.py" --source "$source_dir" --verify-only
    python3 "$root/android/tools/release_receipt.py" verify-source --source "$source_dir"
    python3 "$root/android/tools/phase1_provenance.py" clean-vendor-cache --source "$source_dir"
    python3 "$root/android/tools/phase1_provenance.py" create-source \
        --source "$source_dir" --builder-record "$builder_provenance" \
        --output "$source_provenance" --jobs 32
    build_out=${WONAD_BUILD_OUT:-}
    build_log=${WONAD_BUILD_LOG:-}
    build_container=${WONAD_BUILD_CONTAINER:-}
    build_execution=${WONAD_BUILD_EXECUTION_PROVENANCE:-}
    [[ -n "$build_out" ]] || die 'set WONAD_BUILD_OUT to a fresh external OUT_DIR'
    [[ -n "$build_log" ]] || die 'set WONAD_BUILD_LOG to a fresh external build log'
    [[ -n "$build_container" ]] || die 'set WONAD_BUILD_CONTAINER to a fresh retained container name'
    [[ -n "$build_execution" ]] ||
        die 'set WONAD_BUILD_EXECUTION_PROVENANCE to a fresh external evidence path'
    if [[ -n "${WONAD_BUILD_DATETIME:-}" ]]; then
        [[ "$WONAD_BUILD_DATETIME" =~ ^[1-9][0-9]{8,10}$ ]] || die 'invalid WONAD_BUILD_DATETIME'
        build_datetime=$WONAD_BUILD_DATETIME
    else
        build_datetime=$(git -C "$source_dir/.repo/manifests" show -s --format=%ct HEAD)
    fi
    python3 "$root/android/tools/run_release_build.py" run \
        --source "$source_dir" --out "$build_out" --log "$build_log" \
        --container-name "$build_container" --builder-record "$builder_provenance" \
        --source-record "$source_provenance" --evidence "$build_execution" \
        --build-number "$build_number" --build-datetime "$build_datetime" \
        --jobs "$jobs" --highmem-jobs "$highmem_jobs"
    python3 "$root/android/tools/phase1_provenance.py" verify-source \
        --source "$source_dir" --builder-record "$builder_provenance" \
        --record "$source_provenance" --jobs 32 --allow-build-outputs
    echo "PASS: unsigned target-files and OTA tools finalized under releases/$build_number"
    exit 0
fi

if [[ "$action" == sign ]]; then
    resolve_source_provenance
    [[ -f "$source_provenance" && ! -L "$source_provenance" ]] ||
        die 'source provenance record is missing or not an ordinary file'
    client_provenance=$(resolve_public_file WONAD_CLIENT_PROVENANCE)
    build_execution=$(resolve_public_file WONAD_BUILD_EXECUTION_PROVENANCE)
    build_bind_proof="$build_execution.bind-proof.json"
    [[ -f "$build_bind_proof" && ! -L "$build_bind_proof" ]] ||
        die 'live build bind-identity proof is missing'
    build_consumption=${WONAD_BUILD_CONSUMPTION_PROVENANCE:-}
    [[ -n "$build_consumption" ]] ||
        die 'set WONAD_BUILD_CONSUMPTION_PROVENANCE to an external removal-evidence path'
    build_log=$(resolve_public_file WONAD_BUILD_LOG)
    build_out_arg=${WONAD_BUILD_OUT:-}
    [[ -n "$build_out_arg" && -d "$build_out_arg" && ! -L "$build_out_arg" ]] ||
        die 'set WONAD_BUILD_OUT to the retained external OUT_DIR'
    build_out=$(realpath -e -- "$build_out_arg")
    signer_certificate=$(resolve_public_file WONAD_APK_CERTIFICATE)
    conformance_apk=$(resolve_public_file WONAD_CONFORMANCE_APK)
    conformance_receipt=$(resolve_public_file WONAD_CONFORMANCE_SOURCE_RECEIPT)
    sdk_arg=${WONAD_SDK_PUBLICATION:-}
    [[ -n "$sdk_arg" && -d "$sdk_arg" && ! -L "$sdk_arg" ]] ||
        die 'set WONAD_SDK_PUBLICATION to the frozen ordinary Maven publication directory'
    sdk_publication=$(realpath -e -- "$sdk_arg")
    apksigner_arg=${WONAD_APKSIGNER:-}
    [[ -n "$apksigner_arg" && -f "$apksigner_arg" && ! -L "$apksigner_arg" && -x "$apksigner_arg" ]] ||
        die 'set WONAD_APKSIGNER to the ordinary executable used for client provenance'
    apksigner=$(realpath -e -- "$apksigner_arg")
    python3 "$root/android/tools/phase1_provenance.py" verify-source \
        --source "$source_dir" --builder-record "$builder_provenance" \
        --record "$source_provenance" --jobs 32 --allow-build-outputs
    python3 "$root/android/tools/run_release_build.py" verify \
        --source "$source_dir" --out "$build_out" --log "$build_log" \
        --builder-record "$builder_provenance" --source-record "$source_provenance" \
        --evidence "$build_execution" --build-number "$build_number" \
        --consumption "$build_consumption"
    [[ -f "$build_consumption" && ! -L "$build_consumption" ]] ||
        die 'container-consumption evidence was not created'
    build_consumption=$(realpath -e -- "$build_consumption")
    python3 "$root/android/tools/phase1_provenance.py" verify-clients \
        --sdk-publication "$sdk_publication" --conformance-apk "$conformance_apk" \
        --source-receipt "$conformance_receipt" --signer-certificate "$signer_certificate" \
        --apksigner "$apksigner" --record "$client_provenance"
    key_arg=${WONAD_RELEASE_KEY_DIR:-}
    [[ -n "$key_arg" && -d "$key_arg" ]] || die 'set WONAD_RELEASE_KEY_DIR to the external frankel key directory'
    key_dir=$(realpath -e -- "$key_arg")
    [[ "$key_dir" != "$source_dir" && "$key_dir" != "$source_dir"/* &&
       "$source_dir" != "$key_dir"/* && "$key_dir" != "$root" &&
       "$key_dir" != "$root"/* && "$root" != "$key_dir"/* ]] ||
        die 'release keys must remain outside both the OS checkout and Wonad repository'
    os_certificate_args=()
    for key in bluetooth gmscompat_lib media networkstack nfc platform releasekey sdk_sandbox shared; do
        [[ -f "$key_dir/$key.pk8" && ! -L "$key_dir/$key.pk8" &&
           -f "$key_dir/$key.x509.pem" && ! -L "$key_dir/$key.x509.pem" ]] ||
            die "release key pair is incomplete: $key"
        os_certificate_args+=(--os-certificate "$key_dir/$key.x509.pem")
    done
    [[ -f "$key_dir/avb.pem" && ! -L "$key_dir/avb.pem" &&
       -f "$key_dir/avb_pkmd.bin" && ! -L "$key_dir/avb_pkmd.bin" ]] ||
        die 'AVB key material is incomplete'
    [[ -f "$key_dir/id_ed25519" && ! -L "$key_dir/id_ed25519" &&
       -f "$key_dir/id_ed25519.pub" && ! -L "$key_dir/id_ed25519.pub" ]] ||
        die 'factory-image signing key pair is incomplete'
    python3 "$root/android/tools/phase1_provenance.py" assert-distinct-os-signers \
        --signer-certificate "$signer_certificate" "${os_certificate_args[@]}"
    [[ -f "$source_dir/external/wonad/.wonad-stage.json" &&
       -f "$source_dir/.wonad-updater-stage.json" ]] ||
        die 'owned Wonad and Updater staging records are missing'
    python3 "$root/android/platform/stage-os.py" --source "$source_dir" --verify-only
    python3 "$root/android/tools/release_receipt.py" verify-source --source "$source_dir"
    input="$source_dir/releases/$build_number/$device-target_files.zip"
    tools="$source_dir/releases/$build_number/$device-otatools.zip"
    [[ -f "$input" && -f "$tools" ]] || die 'build/finalize artifacts are missing'
    destination="$source_dir/releases/$build_number/release-$device-$build_number"
    [[ ! -e "$destination" ]] || die 'signed release destination already exists; refusing overwrite'
    if [[ $(awk 'END { print NR-1 }' /proc/swaps) -gt 0 ]] &&
       [[ ${WONAD_SIGN_WITH_ACTIVE_SWAP:-} != I_UNDERSTAND ]]; then
        die 'active swap may retain decrypted signing material; disable it before signing'
    fi
    link="$source_dir/keys/$device"
    mkdir -p -- "$source_dir/keys"
    if [[ -e "$link" || -L "$link" ]]; then
        [[ -L "$link" && $(realpath -e -- "$link") == "$key_dir" ]] ||
            die 'source keys/frankel already exists and is not the selected external key directory'
        owned_link=0
    else
        ln -s -- "$key_dir" "$link"
        owned_link=1
    fi
    cleanup_key_link() {
        if [[ ${owned_link:-0} == 1 ]] && [[ -L "$link" ]] &&
           [[ $(realpath -e -- "$link") == "$key_dir" ]]; then
            unlink -- "$link"
        fi
    }
    trap cleanup_key_link EXIT
    cd -- "$source_dir"
    script/generate-release.sh "$device" "$build_number"
    cleanup_key_link
    owned_link=0
    python3 "$root/android/tools/phase1_provenance.py" stage-client-evidence \
        --sdk-publication "$sdk_publication" --conformance-apk "$conformance_apk" \
        --source-receipt "$conformance_receipt" --signer-certificate "$signer_certificate" \
        --apksigner "$apksigner" --client-record "$client_provenance" \
        --source-record "$source_provenance" --destination "$destination/wonad-provenance"
    [[ ! -e "$destination/wonad-provenance/build-execution.json" ]] ||
        die 'build-execution evidence destination already exists'
    install -m 0644 -- "$build_execution" \
        "$destination/wonad-provenance/build-execution.json"
    install -m 0644 -- "$build_bind_proof" \
        "$destination/wonad-provenance/build-bind-proof.json"
    install -m 0644 -- "$build_consumption" \
        "$destination/wonad-provenance/build-container-consumption.json"
    install -m 0644 -- "$build_log" \
        "$destination/wonad-provenance/build.log"
    python3 "$root/android/tools/release_receipt.py" create \
        --source "$source_dir" --build-number "$build_number"
    python3 "$root/android/tools/release_receipt.py" verify \
        --receipt "$destination/release-receipt.json"
    echo "PASS: signed Pixel 10 factory and full OTA release generated for $build_number"
    exit 0
fi

if [[ "$action" == delta ]]; then
    key_arg=${WONAD_RELEASE_KEY_DIR:-}
    [[ -n "$key_arg" && -d "$key_arg" ]] ||
        die 'set WONAD_RELEASE_KEY_DIR to the external frankel key directory'
    key_dir=$(realpath -e -- "$key_arg")
    [[ "$key_dir" != "$source_dir" && "$key_dir" != "$source_dir"/* &&
       "$source_dir" != "$key_dir"/* && "$key_dir" != "$root" &&
       "$key_dir" != "$root"/* && "$root" != "$key_dir"/* ]] ||
        die 'release keys must remain outside both the OS checkout and Wonad repository'
    for key in bluetooth gmscompat_lib media networkstack nfc platform releasekey sdk_sandbox shared; do
        [[ -f "$key_dir/$key.pk8" && ! -L "$key_dir/$key.pk8" &&
           -f "$key_dir/$key.x509.pem" && ! -L "$key_dir/$key.x509.pem" ]] ||
            die "release key pair is incomplete: $key"
    done
    [[ -f "$key_dir/avb.pem" && ! -L "$key_dir/avb.pem" &&
       -f "$key_dir/avb_pkmd.bin" && ! -L "$key_dir/avb_pkmd.bin" ]] ||
        die 'AVB key material is incomplete'
    [[ -f "$key_dir/id_ed25519" && ! -L "$key_dir/id_ed25519" &&
       -f "$key_dir/id_ed25519.pub" && ! -L "$key_dir/id_ed25519.pub" ]] ||
        die 'factory-image signing key pair is incomplete'
    if [[ $(awk 'END { print NR-1 }' /proc/swaps) -gt 0 ]] &&
       [[ ${WONAD_SIGN_WITH_ACTIVE_SWAP:-} != I_UNDERSTAND ]]; then
        die 'active swap may retain decrypted signing material; disable it before signing'
    fi

    delta="$source_dir/releases/$build_number/$device-incremental-$predecessor_build_number-$build_number.zip"
    pair_receipt="$source_dir/releases/$build_number/$device-incremental-$predecessor_build_number-$build_number-receipt.json"
    pair_lock="$source_dir/releases/$build_number/.wonad-incremental-$predecessor_build_number-$build_number.lock"
    [[ ! -e "$delta" && ! -L "$delta" ]] ||
        die 'incremental OTA destination already exists; refusing overwrite'
    [[ ! -e "$pair_receipt" && ! -L "$pair_receipt" ]] ||
        die 'incremental pair receipt already exists; refusing overwrite'
    mkdir -- "$pair_lock" 2>/dev/null ||
        die 'incremental pair is already being generated or has a stale lock'
    owned_pair_lock=1
    link="$source_dir/keys/$device"
    owned_link=0
    cleanup_delta() {
        if [[ ${owned_link:-0} == 1 ]] && [[ -L "$link" ]] &&
           [[ $(realpath -e -- "$link") == "$key_dir" ]]; then
            unlink -- "$link"
        fi
        if [[ ${owned_pair_lock:-0} == 1 ]] && [[ -d "$pair_lock" ]]; then
            rmdir -- "$pair_lock" 2>/dev/null || true
        fi
    }
    trap cleanup_delta EXIT

    # Revalidate exact target source and both immutable signed endpoints as the
    # final operation before invoking the pinned GrapheneOS signing script.
    python3 "$root/android/platform/stage-os.py" --source "$source_dir" --verify-only
    python3 "$root/android/tools/release_pair_receipt.py" verify-endpoints \
        --source "$source_dir" \
        --predecessor "$predecessor_build_number" --successor "$build_number"
    mkdir -p -- "$source_dir/keys"
    if [[ -e "$link" || -L "$link" ]]; then
        [[ -L "$link" && $(realpath -e -- "$link") == "$key_dir" ]] ||
            die 'source keys/frankel already exists and is not the selected external key directory'
    else
        ln -s -- "$key_dir" "$link"
        owned_link=1
    fi
    cd -- "$source_dir"
    script/generate-delta.sh "$device" "$predecessor_build_number" "$build_number"
    [[ -f "$delta" && ! -L "$delta" ]] ||
        die 'official delta generator did not produce an ordinary incremental OTA'

    # Remove the temporary key link before any receipt tool inventories source
    # or artifacts. Private signing material is never receipt input.
    if [[ ${owned_link:-0} == 1 ]]; then
        unlink -- "$link"
    fi
    owned_link=0
    python3 "$root/android/tools/release_pair_receipt.py" create \
        --source "$source_dir" \
        --predecessor "$predecessor_build_number" --successor "$build_number"
    python3 "$root/android/tools/release_pair_receipt.py" verify --receipt "$pair_receipt"
    rmdir -- "$pair_lock" || die 'cannot remove incremental generation lock after success'
    owned_pair_lock=0
    trap - EXIT
    echo "PASS: signed frankel incremental OTA pair generated for $predecessor_build_number -> $build_number"
    exit 0
fi

if [[ "$action" == verify-delta ]]; then
    pair_receipt="$source_dir/releases/$build_number/$device-incremental-$predecessor_build_number-$build_number-receipt.json"
    avb_public=${WONAD_AVB_PUBLIC_KEY:-}
    ota_certificate=${WONAD_OTA_CERTIFICATE:-}
    factory_public=${WONAD_FACTORY_PUBLIC_KEY:-}
    expected_pair=${WONAD_EXPECTED_PAIR_RECEIPT_SHA256:-}
    trusted_otatools=${WONAD_TRUSTED_OTATOOLS_MANIFEST:-}
    expected_otatools=${WONAD_EXPECTED_OTATOOLS_MANIFEST_SHA256:-}
    evidence_arg=${WONAD_VERIFICATION_EVIDENCE:-}
    for input in "$avb_public" "$ota_certificate" "$factory_public"; do
        [[ -n "$input" && -f "$input" && ! -L "$input" ]] ||
            die 'verify-delta requires ordinary public-key files in WONAD_AVB_PUBLIC_KEY, WONAD_OTA_CERTIFICATE and WONAD_FACTORY_PUBLIC_KEY'
    done
    [[ "$expected_pair" =~ ^[0-9a-f]{64}$ ]] ||
        die 'verify-delta requires authenticated WONAD_EXPECTED_PAIR_RECEIPT_SHA256'
    [[ -n "$trusted_otatools" && -f "$trusted_otatools" && ! -L "$trusted_otatools" ]] ||
        die 'verify-delta requires an ordinary WONAD_TRUSTED_OTATOOLS_MANIFEST'
    [[ "$expected_otatools" =~ ^[0-9a-f]{64}$ ]] ||
        die 'verify-delta requires authenticated WONAD_EXPECTED_OTATOOLS_MANIFEST_SHA256'
    [[ -n "$evidence_arg" ]] || die 'verify-delta requires WONAD_VERIFICATION_EVIDENCE'
    trusted_otatools=$(realpath -e -- "$trusted_otatools")
    case "$trusted_otatools" in
        "$source_dir"|"$source_dir"/*)
            die 'trusted otatools manifest must remain outside the release source tree' ;;
    esac
    evidence_parent=$(realpath -e -- "$(dirname -- "$evidence_arg")")
    evidence="$evidence_parent/$(basename -- "$evidence_arg")"
    case "$evidence" in
        "$source_dir"|"$source_dir"/*)
            die 'pair verification evidence must be written outside the release source tree' ;;
    esac
    [[ ! -e "$evidence" && ! -L "$evidence" ]] ||
        die 'pair verification evidence destination already exists'
    temporary=$(mktemp --tmpdir="$evidence_parent" .wonad-pair-verification.XXXXXXXX)
    cleanup_evidence() { rm -f -- "$temporary"; }
    trap cleanup_evidence EXIT
    python3 "$root/android/tools/verify_release_pair.py" \
        --receipt "$pair_receipt" \
        --avb-public-key "$avb_public" \
        --ota-certificate "$ota_certificate" \
        --factory-public-key "$factory_public" \
        --expected-pair-receipt-sha256 "$expected_pair" \
        --trusted-otatools-manifest "$trusted_otatools" \
        --expected-otatools-manifest-sha256 "$expected_otatools" > "$temporary"
    chmod 0644 "$temporary"
    mv -- "$temporary" "$evidence"
    trap - EXIT
    echo "PASS: offline predecessor/successor and incremental verification recorded at $evidence"
    exit 0
fi

receipt="$source_dir/releases/$build_number/release-$device-$build_number/release-receipt.json"
if [[ "$action" == receipt ]]; then
    python3 "$root/android/tools/release_receipt.py" verify --receipt "$receipt"
    exit 0
fi

avb_public=${WONAD_AVB_PUBLIC_KEY:-}
ota_certificate=${WONAD_OTA_CERTIFICATE:-}
factory_public=${WONAD_FACTORY_PUBLIC_KEY:-}
expected_receipt=${WONAD_EXPECTED_RECEIPT_SHA256:-}
trusted_otatools=${WONAD_TRUSTED_OTATOOLS_MANIFEST:-}
expected_otatools=${WONAD_EXPECTED_OTATOOLS_MANIFEST_SHA256:-}
evidence_arg=${WONAD_VERIFICATION_EVIDENCE:-}
for input in "$avb_public" "$ota_certificate" "$factory_public"; do
    [[ -n "$input" && -f "$input" && ! -L "$input" ]] ||
        die 'verify requires ordinary public-key files in WONAD_AVB_PUBLIC_KEY, WONAD_OTA_CERTIFICATE and WONAD_FACTORY_PUBLIC_KEY'
done
[[ "$expected_receipt" =~ ^[0-9a-f]{64}$ ]] || die 'verify requires authenticated WONAD_EXPECTED_RECEIPT_SHA256'
[[ -n "$trusted_otatools" && -f "$trusted_otatools" && ! -L "$trusted_otatools" ]] ||
    die 'verify requires an ordinary WONAD_TRUSTED_OTATOOLS_MANIFEST'
[[ "$expected_otatools" =~ ^[0-9a-f]{64}$ ]] ||
    die 'verify requires authenticated WONAD_EXPECTED_OTATOOLS_MANIFEST_SHA256'
[[ -n "$evidence_arg" ]] || die 'verify requires WONAD_VERIFICATION_EVIDENCE'
evidence_parent=$(realpath -e -- "$(dirname -- "$evidence_arg")")
evidence="$evidence_parent/$(basename -- "$evidence_arg")"
release_directory=$(realpath -e -- "$(dirname -- "$receipt")")
case "$evidence" in
    "$release_directory"|"$release_directory"/*)
        die 'verification evidence must be written outside the receipted release directory' ;;
esac
[[ ! -e "$evidence" && ! -L "$evidence" ]] || die 'verification evidence destination already exists'
temporary=$(mktemp --tmpdir="$evidence_parent" .wonad-verification.XXXXXXXX)
cleanup_evidence() { rm -f -- "$temporary"; }
trap cleanup_evidence EXIT
python3 "$root/android/tools/verify_release_artifacts.py" \
    --receipt "$receipt" \
    --avb-public-key "$avb_public" \
    --ota-certificate "$ota_certificate" \
    --factory-public-key "$factory_public" \
    --expected-receipt-sha256 "$expected_receipt" \
    --trusted-otatools-manifest "$trusted_otatools" \
    --expected-otatools-manifest-sha256 "$expected_otatools" > "$temporary"
chmod 0644 "$temporary"
mv -- "$temporary" "$evidence"
trap - EXIT
echo "PASS: offline artifact and signature verification recorded at $evidence"
