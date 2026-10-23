#!/bin/bash
set -euo pipefail

if (( $# != 1 )) || [[ ! $1 =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "usage: $0 IMMUTABLE_NATIVE_CANDIDATE_IMAGE_ID" >&2
    exit 64
fi

readonly matrix_image=$1
readonly matrix_repo=/u/elric/tree/wonad
readonly matrix_packet=$matrix_repo/android/out/phase1-emulator-client-packet-20261011-4
readonly matrix_wrong=$matrix_repo/android/out/phase1-wrong-signer-bundle-20261011-4
readonly matrix_product=/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-5/target/product/emu64x
readonly matrix_output=$matrix_repo/android/out/phase1-native-matrix-custom7-5-packet4-inputs-1
readonly matrix_python=/srv/wonad-os37-pending-permission-3/wonad-styx-live.0DimSmO9/x11-test-venv/bin/python3
readonly matrix_built_id=$matrix_repo/android/out/phase1-native-candidate-custom7-5-1/built-image.id

[[ -f $matrix_built_id && ! -L $matrix_built_id ]] || {
    echo "strict native packaging has not published an ordinary built-image.id" >&2
    exit 66
}
[[ $(< "$matrix_built_id") == "$matrix_image" ]] || {
    echo "selected image is not the newly built strict custom7 candidate" >&2
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
sha256sum --check --strict - <<'MATRIX_SHA256'
fd0775d9569f1baf014e0ef9106471ebf8d45ddfa158c88304a75df308596671  android/out/phase1-emulator-client-packet-20261011-4/receipt.json
633a4cb4ea2b87bec046167b05cb31099c3185a6774846bc4c8c070c6945afbc  android/out/phase1-wrong-signer-bundle-20261011-4/signing-receipt.json
e9128255a370f8d16cb358592de20935f2943ded435fb46b14a81e3874635263  android/out/phase1-emulator-client-packet-20261011-4/version-update/preparation-receipt.json
f29b136a2ea62c02c7c722f2746a4ce92b8ea666e87ba1c0656d028d7d68be8e  android/tools/run_native_matrix.py
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
