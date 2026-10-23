#!/bin/bash
set -euo pipefail

if (( $# != 1 )) || [[ ! $1 =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "usage: $0 IMMUTABLE_NATIVE_CANDIDATE_IMAGE_ID" >&2
    exit 64
fi

readonly matrix_image=$1
readonly matrix_repo=/u/elric/tree/wonad
readonly matrix_packet=$matrix_repo/android/out/phase1-emulator-client-packet-20261011-6
readonly matrix_wrong=$matrix_repo/android/out/phase1-wrong-signer-bundle-20261011-6
readonly matrix_product=/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-5/target/product/emu64x
readonly matrix_output=$matrix_repo/android/out/phase1-native-matrix-custom7-5-packet6-inputs-3
readonly matrix_python=/srv/wonad-os37-pending-permission-3/wonad-styx-live.0DimSmO9/x11-test-venv/bin/python3
readonly matrix_built_id=$matrix_repo/android/out/phase1-native-candidate-custom7-5-3/built-image.id
readonly matrix_packet_sha=09f786a9e86ada4576be8ace27997959bca7c959f45651d5376afa7aeaab4211
readonly matrix_wrong_sha=85bda8783d4dab246e9180c08125684f914f8d6bd9bf81f76acbe31c27743594
readonly matrix_update_sha=87ea67558d99c8ca2f698a3e86dbac961444bc1af8d262ed8f697170620ef741
readonly matrix_tool_sha=f29b136a2ea62c02c7c722f2746a4ce92b8ea666e87ba1c0656d028d7d68be8e

sha_re='^[0-9a-f]{64}$'
[[ $matrix_packet_sha =~ $sha_re && $matrix_wrong_sha =~ $sha_re && $matrix_update_sha =~ $sha_re ]] || {
    echo "packet6 matrix receipt pins are unresolved; this prepared freeze driver cannot run" >&2
    exit 78
}

[[ -f $matrix_built_id && ! -L $matrix_built_id ]] || {
    echo "strict native packaging has not published an ordinary built-image.id" >&2
    exit 66
}
[[ $(< "$matrix_built_id") == "$matrix_image" ]] || {
    echo "selected image is not the newly built strict custom7 packet6 candidate" >&2
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
$matrix_packet_sha  android/out/phase1-emulator-client-packet-20261011-6/receipt.json
$matrix_wrong_sha  android/out/phase1-wrong-signer-bundle-20261011-6/signing-receipt.json
$matrix_update_sha  android/out/phase1-emulator-client-packet-20261011-6/version-update/preparation-receipt.json
$matrix_tool_sha  android/tools/run_native_matrix.py
MATRIX_SHA256

# This producer only authenticates and seals inputs. It never starts guests.
# Later backend23 and serialized GUI4 runs must consume its exact inputs.json.
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
