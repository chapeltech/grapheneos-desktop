#!/bin/bash
set -euo pipefail

if (( $# != 2 )); then
    echo "usage: $0 BASELINE_RECEIPT_SHA256 COMPARISON_SHA256" >&2
    exit 64
fi

baseline_sha=$1
comparison_sha=$2
sha_re='^[0-9a-f]{64}$'
[[ $baseline_sha =~ $sha_re ]] || { echo "invalid baseline receipt SHA-256" >&2; exit 64; }
[[ $comparison_sha =~ $sha_re ]] || { echo "invalid comparison SHA-256" >&2; exit 64; }

readonly repo=/u/elric/tree/wonad
readonly python=/usr/bin/python3
readonly python_target=/usr/bin/python3.14
readonly python_sha=0d64bd6d66d68dac91cdadafc46e22d4f09f22bdc997aaae870f42865b024a3e
readonly builder=$repo/android/container/build-native-candidate.py
readonly builder_sha=70ccf59510dfcf11217e640c180016c7fb5d2d22b1da9adb38bd59c100cd226d
readonly x86=$repo/android/tools/x86_build_comparison.py
readonly x86_sha=1959d10d2d62dd121f09360d7b2385323de03f1f6402bc10ad987e5ad8985dbc
readonly packet_tool=$repo/android/tools/phase1_emulator_client_packet.py
readonly packet_tool_sha=defd7f981ee6ff4317c57730bfeeaa0ab84f39aa1585b446ed4db92f250a60d2
readonly product=/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-5/target/product/emu64x
readonly packet=$repo/android/out/phase1-emulator-client-packet-20261011-6
readonly packet_sha=09f786a9e86ada4576be8ace27997959bca7c959f45651d5376afa7aeaab4211
readonly packet_wonad_sha=7494132416df3b4957ca944bdf5657be3d6e1df2a6eca74833462702d4d1e2ac
readonly baseline=$repo/android/out/phase1-x86-baseline-2026100600-receipt-9.json
readonly custom=$repo/android/out/phase1-x86-custom-2026100600-receipt-custom7-5.json
readonly custom_sha=9be626e4a21d8bfa30b18052174b6bad0310689e8f60b64dee3c20ed3d0b4b32
readonly comparison=$repo/android/out/phase1-x86-source-matched-comparison-2026100600-custom7-5-baseline9.json
readonly output=$repo/android/out/phase1-native-candidate-custom7-5-3
readonly base=sha256:0bf80454dbaa59bacd955d3e0140d8c91c4dcbd4d6e3e941274cdf10cb374b3f
readonly tag=wonad:native-v3-candidate-phase1-custom7-5-3

[[ $packet_sha =~ $sha_re && $packet_wonad_sha =~ $sha_re ]] || {
    echo "packet6 publication pins are unresolved; this prepared driver cannot run" >&2
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
exact_sha "$x86" "$x86_sha"
exact_sha "$packet_tool" "$packet_tool_sha"
ordinary_directory "$product"
ordinary_directory "$packet"
exact_sha "$packet/receipt.json" "$packet_sha"
exact_sha "$packet/wonad.apk" "$packet_wonad_sha"
exact_sha "$baseline" "$baseline_sha"
exact_sha "$custom" "$custom_sha"
exact_sha "$comparison" "$comparison_sha"

[[ ! -e $output && ! -L $output && $(/usr/bin/realpath -e -- "$(/usr/bin/dirname -- "$output")") == "$repo/android/out" ]] || {
    echo "preserving non-fresh or non-literal candidate output: $output" >&2
    exit 73
}
[[ -z $(/usr/bin/docker image ls -q --filter "reference=$tag") ]] || {
    echo "preserving populated candidate tag: $tag" >&2
    exit 73
}
[[ $(/usr/bin/docker image inspect --format '{{.Id}}' "$base") == "$base" ]] || {
    echo "immutable predecessor image identity changed" >&2
    exit 69
}

mapfile -t competing < <(/usr/bin/pgrep -f '/android/container/build-(native|phase1-conformance)-candidate[.]py' || true)
if (( ${#competing[@]} != 0 )); then
    echo "another native/conformance candidate packager is running: ${competing[*]}" >&2
    /usr/bin/ps -o pid,ppid,etime,args -p "$(IFS=,; echo "${competing[*]}")" >&2 || true
    exit 75
fi

readonly gib=$((1024 * 1024 * 1024))
mem_kib=$(/usr/bin/awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
u_free=$(/usr/bin/df -B1 --output=avail "$repo/android/out" | /usr/bin/tail -n 1 | /usr/bin/tr -d ' ')
tmp_free=$(/usr/bin/df -B1 --output=avail /tmp | /usr/bin/tail -n 1 | /usr/bin/tr -d ' ')
docker_root=$(/usr/bin/docker info --format '{{.DockerRootDir}}')
[[ $docker_root == /* && -d $docker_root && ! -L $docker_root ]] || {
    echo "Docker root is not one literal directory" >&2
    exit 69
}
docker_free=$(/usr/bin/df -B1 --output=avail "$docker_root" | /usr/bin/tail -n 1 | /usr/bin/tr -d ' ')
(( mem_kib >= 12 * 1024 * 1024 )) || { echo "need at least 12 GiB MemAvailable" >&2; exit 75; }
(( u_free >= 16 * gib )) || { echo "need at least 16 GiB free for candidate output" >&2; exit 75; }
(( tmp_free >= 4 * gib )) || { echo "need at least 4 GiB free on /tmp" >&2; exit 75; }
(( docker_free >= 16 * gib )) || { echo "need at least 16 GiB free in Docker root" >&2; exit 75; }

printf 'preflight mem_available_kib=%s u_free_bytes=%s tmp_free_bytes=%s docker_free_bytes=%s\n' \
    "$mem_kib" "$u_free" "$tmp_free" "$docker_free"
printf 'authenticating baseline=%s custom=%s comparison=%s packet=%s\n' \
    "$baseline_sha" "$custom_sha" "$comparison_sha" "$packet_sha"

"$python" -B "$x86" verify --receipt "$baseline" --expected-sha256 "$baseline_sha"
"$python" -B "$x86" verify --receipt "$custom" --expected-sha256 "$custom_sha"
"$python" -B "$x86" verify-comparison \
    --comparison "$comparison" --expected-sha256 "$comparison_sha" \
    --baseline "$baseline" --baseline-sha256 "$baseline_sha" \
    --custom "$custom" --custom-sha256 "$custom_sha"
"$python" -B "$packet_tool" verify --packet "$packet" --expected-receipt-sha256 "$packet_sha"

exact_sha "$baseline" "$baseline_sha"
exact_sha "$custom" "$custom_sha"
exact_sha "$comparison" "$comparison_sha"
exact_sha "$packet/receipt.json" "$packet_sha"
[[ ! -e $output && ! -L $output ]] || { echo "candidate output appeared during authentication" >&2; exit 73; }
[[ -z $(/usr/bin/docker image ls -q --filter "reference=$tag") ]] || {
    echo "candidate tag appeared during authentication" >&2
    exit 73
}

printf 'launching strict unqualified native candidate with /usr/bin/python3 -B\n'
exec "$python" -B "$builder" \
    --product "$product" \
    --apk "$packet/wonad.apk" \
    --output "$output" \
    --base-image "$base" \
    --phase1-build-evidence \
    --phase1-comparison "$comparison" \
    --phase1-comparison-sha256 "$comparison_sha" \
    --phase1-baseline-receipt "$baseline" \
    --phase1-baseline-receipt-sha256 "$baseline_sha" \
    --phase1-custom-receipt "$custom" \
    --phase1-custom-receipt-sha256 "$custom_sha" \
    --phase1-client-packet "$packet" \
    --phase1-client-packet-receipt-sha256 "$packet_sha" \
    --tag "$tag"
