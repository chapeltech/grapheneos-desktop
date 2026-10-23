#!/bin/bash
set -euo pipefail

# Create-only preparation for the packet7/native4 full matrix input bundle.
# Native4 and wrong-signer identities deliberately remain unresolved.  This
# script must fail before invoking any external program until root replaces
# both literals with independently authenticated publications.
if (( $# != 0 )); then
    echo "usage: $0" >&2
    exit 64
fi

readonly matrix_image=PENDING_ACTUAL_NATIVE4_IMMUTABLE_IMAGE_ID
readonly matrix_repo=/u/elric/tree/wonad
readonly matrix_packet=$matrix_repo/android/out/phase1-emulator-client-packet-20261011-7
readonly matrix_wrong=$matrix_repo/android/out/phase1-wrong-signer-bundle-20261011-7
readonly matrix_product=/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-5/target/product/emu64x
readonly matrix_output=$matrix_repo/android/out/phase1-native-matrix-custom7-5-packet7-inputs-5
readonly matrix_python=/srv/wonad-os37-pending-permission-3/wonad-styx-live.0DimSmO9/x11-test-venv/bin/python3
readonly matrix_built_id=$matrix_repo/android/out/phase1-native-candidate-custom7-5-4/built-image.id
readonly matrix_packet_sha=5d5737ebe26048152fccfb4881cd89fb4b583ca2df0cfc84fbe8d023799cc459
readonly matrix_wrong_sha=PENDING_ACTUAL_WRONG7_SIGNING_RECEIPT_SHA256
readonly matrix_update_sha=1eef12a24e976bf4711c8c2e2872096436f28621c6ebe07c0151dd37aa29e177
readonly matrix_tool_sha=f29b136a2ea62c02c7c722f2746a4ce92b8ea666e87ba1c0656d028d7d68be8e

sha_re='^[0-9a-f]{64}$'
image_re='^sha256:[0-9a-f]{64}$'
[[ $matrix_image =~ $image_re && $matrix_packet_sha =~ $sha_re &&
   $matrix_wrong_sha =~ $sha_re && $matrix_update_sha =~ $sha_re ]] || {
    echo "packet7/native4 matrix publication pins are unresolved; no input freeze was attempted" >&2
    exit 78
}

[[ -f $matrix_built_id && ! -L $matrix_built_id ]] || {
    echo "strict native4 packaging has not published an ordinary built-image.id" >&2
    exit 66
}
[[ $(< "$matrix_built_id") == "$matrix_image" ]] || {
    echo "selected image is not the newly built strict custom7 packet7 native4 candidate" >&2
    exit 65
}
[[ $(docker image inspect --format '{{.Id}}' "$matrix_image") == "$matrix_image" ]] || {
    echo "selected immutable Docker image is absent" >&2
    exit 69
}
[[ ! -e $matrix_output && ! -L $matrix_output ]] || {
    echo "preserving existing matrix freeze: $matrix_output" >&2
    exit 73
}

cd "$matrix_repo"
sha256sum --check --strict - <<MATRIX_SHA256
$matrix_packet_sha  android/out/phase1-emulator-client-packet-20261011-7/receipt.json
$matrix_wrong_sha  android/out/phase1-wrong-signer-bundle-20261011-7/signing-receipt.json
$matrix_update_sha  android/out/phase1-emulator-client-packet-20261011-7/version-update/preparation-receipt.json
$matrix_tool_sha  android/tools/run_native_matrix.py
MATRIX_SHA256

# This producer authenticates and seals inputs only.  It never starts a guest.
# The later run must consume the exact resulting inputs.json and execute all 23
# backend gates followed by all four serialized GUI gates.
exec env PYTHONDONTWRITEBYTECODE=1 "$matrix_python" -B \
    android/tools/run_native_matrix.py freeze \
    --image "$matrix_image" \
    --product "$matrix_product" \
    --apk "$matrix_packet/wonad.apk" \
    --fixture-apk "$matrix_packet/fixture.apk" \
    --security-apk "$matrix_packet/security.apk" \
    --fault-apk "$matrix_packet/fault.apk" \
    --reuse-apk "$matrix_packet/task-reuse.apk" \
    --ime-apk "$matrix_packet/ime.apk" \
    --probe-apk "$matrix_packet/probe.apk" \
    --prerequisite-apk "$matrix_packet/prerequisites.apk" \
    --wrong-artifacts "$matrix_wrong/signing-receipt.json" \
    --update-preparation "$matrix_packet/version-update/preparation-receipt.json" \
    --browser-cache "$matrix_repo/android/out/browser-tests" \
    --linux-reference "$matrix_repo/android/out/native-linux-full-float-oracle-6" \
    --output "$matrix_output"
