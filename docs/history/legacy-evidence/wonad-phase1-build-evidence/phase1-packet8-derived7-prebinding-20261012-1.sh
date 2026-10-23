#!/bin/bash
set -euo pipefail

if (( $# != 1 )) || [[ ! $1 =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "usage: $0 NATIVE_CANDIDATE_IMAGE_SHA256" >&2
    exit 64
fi

readonly image=$1
# Fill this only from the terminal, independently audited native5 publication.
readonly native_image=PENDING
[[ $native_image =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo "NOT READY: native5 immutable image ID remains PENDING" >&2
    exit 78
}
[[ $image == "$native_image" ]] || {
    echo "only the authenticated native5 image is authorized for derived7" >&2
    exit 65
}
readonly repo=/u/elric/tree/wonad
readonly python=/usr/bin/python3
readonly python_target=/usr/bin/python3.14
readonly python_sha=0d64bd6d66d68dac91cdadafc46e22d4f09f22bdc997aaae870f42865b024a3e
readonly builder=$repo/android/container/build-phase1-conformance-candidate.py
readonly builder_sha=c2719ce245bd68651401e46f92d09ecf2614629aa3eb07760f4fad24fd2dbebc
readonly native_builder=$repo/android/container/build-native-candidate.py
readonly native_builder_sha=70ccf59510dfcf11217e640c180016c7fb5d2d22b1da9adb38bd59c100cd226d
readonly packet_tool=$repo/android/tools/phase1_emulator_client_packet.py
readonly packet_tool_sha=defd7f981ee6ff4317c57730bfeeaa0ab84f39aa1585b446ed4db92f250a60d2
readonly smoke_source=$repo/android/tools/conformance_smoke.py
readonly smoke_source_sha=d193c2641d3ceebb7bc498308181a4d0b02b0d0701544e343ad059b4917b3dd5
readonly common_source=$repo/android/tools/phase1_conformance_common.py
readonly common_source_sha=731d79dbe9818d94a00c10146035109b9b1e0d1fe7ce8b546b575424164e4a94
readonly guest_source=$repo/android/tools/phase1_conformance_guest.py
readonly guest_source_sha=b111174b10a735dc7bd9f6256604fe3961974bc064aff04d058b61b45d2ebfd5
readonly api_auditor=$repo/android/tools/phase1_conformance_acceptance.py
readonly api_auditor_sha=ede7566d7227a014bd984678d5e5c39a090824edfb0b250f2392728014da99af
readonly product=/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-5/target/product/emu64x
readonly packet=$repo/android/out/phase1-emulator-client-packet-20261012-8
readonly packet_sha=PENDING
readonly packet_wonad_sha=PENDING
readonly packet_update_sha=PENDING
readonly packet_conformance_update_sha=PENDING
readonly packet_wonad_cert_sha=PENDING
readonly packet_platform_cert_sha=PENDING
readonly native_output=$repo/android/out/phase1-native-candidate-custom7-5-5
readonly native_tag=wonad:native-v3-candidate-phase1-custom7-5-5
readonly output=$repo/android/out/phase1-conformance-candidate-custom7-5-7
readonly tag=wonad:phase1-conformance-candidate-custom7-5-7

[[ $packet_sha =~ ^[0-9a-f]{64}$ && $packet_wonad_sha =~ ^[0-9a-f]{64}$ &&
   $packet_update_sha =~ ^[0-9a-f]{64}$ &&
   $packet_conformance_update_sha =~ ^[0-9a-f]{64}$ &&
   $packet_wonad_cert_sha =~ ^[0-9a-f]{64}$ &&
   $packet_platform_cert_sha =~ ^[0-9a-f]{64}$ &&
   $smoke_source_sha =~ ^[0-9a-f]{64}$ &&
   $common_source_sha =~ ^[0-9a-f]{64}$ &&
   $guest_source_sha =~ ^[0-9a-f]{64}$ &&
   $api_auditor_sha =~ ^[0-9a-f]{64}$ ]] || {
    echo "NOT READY: packet8/bundled-host source pins remain PENDING or invalid" >&2
    exit 78
}

exec 9>/tmp/wonad-phase1-native-candidate-packaging.lock
/usr/bin/flock -n 9 || { echo "another Phase-1 candidate packager owns the lock" >&2; exit 75; }

ordinary_file() {
    local path=$1
    [[ -f $path && ! -L $path && $(/usr/bin/realpath -e -- "$path") == "$path" ]] || {
        echo "not one canonical ordinary file: $path" >&2
        exit 66
    }
}

ordinary_directory() {
    local path=$1
    [[ -d $path && ! -L $path && $(/usr/bin/realpath -e -- "$path") == "$path" ]] || {
        echo "not one canonical ordinary directory: $path" >&2
        exit 66
    }
}

exact_sha() {
    local path=$1 expected=$2 actual
    ordinary_file "$path"
    actual=$(/usr/bin/sha256sum -- "$path")
    actual=${actual%% *}
    [[ $actual == "$expected" ]] || {
        echo "SHA-256 mismatch: $path expected=$expected actual=$actual" >&2
        exit 65
    }
}

[[ -L $python && $(/usr/bin/readlink -f -- "$python") == "$python_target" ]] || {
    echo "required /usr/bin/python3 interpreter link changed" >&2
    exit 69
}
exact_sha "$python_target" "$python_sha"
exact_sha "$builder" "$builder_sha"
exact_sha "$native_builder" "$native_builder_sha"
exact_sha "$packet_tool" "$packet_tool_sha"
exact_sha "$smoke_source" "$smoke_source_sha"
exact_sha "$common_source" "$common_source_sha"
exact_sha "$guest_source" "$guest_source_sha"
exact_sha "$api_auditor" "$api_auditor_sha"
ordinary_directory "$product"
ordinary_directory "$packet"
ordinary_directory "$native_output"
exact_sha "$packet/receipt.json" "$packet_sha"
exact_sha "$packet/wonad.apk" "$packet_wonad_sha"
exact_sha "$packet/version-update/preparation-receipt.json" "$packet_update_sha"
exact_sha "$packet/conformance-version-update/preparation-receipt.json" "$packet_conformance_update_sha"
exact_sha "$packet/evidence/certificates/wonad.x509.pem" "$packet_wonad_cert_sha"
exact_sha "$packet/evidence/certificates/platform.x509.pem" "$packet_platform_cert_sha"
ordinary_file "$native_output/manifest.json"
ordinary_file "$native_output/built-image.id"
[[ $(/usr/bin/tr -d '\r\n' < "$native_output/built-image.id") == "$image" ]] || {
    echo "native candidate ID differs from its fresh staging record" >&2
    exit 65
}
[[ $(/usr/bin/docker image inspect --format '{{.Id}}' "$image") == "$image" ]] || {
    echo "native candidate immutable image is unavailable" >&2
    exit 69
}
[[ $(/usr/bin/docker image inspect --format '{{.Id}}' "$native_tag") == "$image" ]] || {
    echo "native candidate tag does not resolve to its immutable image" >&2
    exit 69
}
[[ ! -e $output && ! -L $output && $(/usr/bin/realpath -e -- "$(/usr/bin/dirname -- "$output")") == "$repo/android/out" ]] || {
    echo "preserving non-fresh or non-literal derived output: $output" >&2
    exit 73
}
[[ -z $(/usr/bin/docker image ls -q --filter "reference=$tag") ]] || {
    echo "preserving populated derived tag: $tag" >&2
    exit 73
}

mapfile -t competing < <(/usr/bin/pgrep -f '/android/container/build-(native|phase1-conformance)-candidate[.]py' || true)
if (( ${#competing[@]} != 0 )); then
    echo "another native/conformance candidate packager is running: ${competing[*]}" >&2
    exit 75
fi

readonly gib=$((1024 * 1024 * 1024))
mem_kib=$(/usr/bin/awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
u_free=$(/usr/bin/df -B1 --output=avail "$repo/android/out" | /usr/bin/tail -n 1 | /usr/bin/tr -d ' ')
tmp_free=$(/usr/bin/df -B1 --output=avail /tmp | /usr/bin/tail -n 1 | /usr/bin/tr -d ' ')
docker_root=$(/usr/bin/docker info --format '{{.DockerRootDir}}')
docker_free=$(/usr/bin/df -B1 --output=avail "$docker_root" | /usr/bin/tail -n 1 | /usr/bin/tr -d ' ')
(( mem_kib >= 8 * 1024 * 1024 )) || { echo "need at least 8 GiB MemAvailable" >&2; exit 75; }
(( u_free >= 12 * gib )) || { echo "need at least 12 GiB free for derived output" >&2; exit 75; }
(( tmp_free >= 4 * gib )) || { echo "need at least 4 GiB free on /tmp" >&2; exit 75; }
(( docker_free >= 12 * gib )) || { echo "need at least 12 GiB free in Docker root" >&2; exit 75; }
printf 'derived-preflight mem_available_kib=%s u_free_bytes=%s tmp_free_bytes=%s docker_free_bytes=%s\n' \
    "$mem_kib" "$u_free" "$tmp_free" "$docker_free"

"$python" -B "$packet_tool" verify --packet "$packet" --expected-receipt-sha256 "$packet_sha"
exact_sha "$packet/receipt.json" "$packet_sha"
exact_sha "$packet/wonad.apk" "$packet_wonad_sha"
exact_sha "$packet/version-update/preparation-receipt.json" "$packet_update_sha"
exact_sha "$packet/conformance-version-update/preparation-receipt.json" "$packet_conformance_update_sha"
exact_sha "$packet/evidence/certificates/wonad.x509.pem" "$packet_wonad_cert_sha"
exact_sha "$packet/evidence/certificates/platform.x509.pem" "$packet_platform_cert_sha"
[[ $(/usr/bin/docker image inspect --format '{{.Id}}' "$image") == "$image" ]] || exit 69
[[ ! -e $output && ! -L $output ]] || { echo "derived output appeared during authentication" >&2; exit 73; }
[[ -z $(/usr/bin/docker image ls -q --filter "reference=$tag") ]] || {
    echo "derived tag appeared during authentication" >&2
    exit 73
}

# Bind every current builder SOURCE_FILES member immediately before staging.
exact_sha "$smoke_source" "$smoke_source_sha"
exact_sha "$common_source" "$common_source_sha"
exact_sha "$guest_source" "$guest_source_sha"
exact_sha "$api_auditor" "$api_auditor_sha"

printf 'launching unqualified derived conformance candidate with /usr/bin/python3 -B\n'
exec "$python" -B "$builder" \
    --product "$product" \
    --packet "$packet" \
    --expected-receipt-sha256 "$packet_sha" \
    --base-image "$image" \
    --output "$output" \
    --tag "$tag"
