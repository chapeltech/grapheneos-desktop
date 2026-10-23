#!/usr/bin/env bash
set -euo pipefail

export PATH=/usr/bin:/bin
export LANG=C
export LC_ALL=C
umask 077

workspace=/u/elric/tree/wonad
evidence=/u/elric/tree/wonad-phase1-build-evidence

baseline_receipt="$workspace/android/out/phase1-x86-baseline-2026100600-receipt-8.json"

custom_source=/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-4
custom_out=/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-2
custom_log="$evidence/phase1-x86-custom-2026100600-build-2.log"
custom_preflight="$custom_log.preflight.json"
custom_container=wonad-phase1-x86-custom-2026100600-2
custom_receipt="$workspace/android/out/phase1-x86-custom-2026100600-receipt-custom4-2.json"
custom_plan="$workspace/android/out/phase1-x86-custom-2026100600-prune-plan-custom4-2.json"
custom_prune_result="$workspace/android/out/phase1-x86-custom-2026100600-prune-result-custom4-2.json"
custom_quarantine="$evidence/custom-2-phase1-custom4-transient-specials-quarantine"

certificate="$workspace/android/out/phase1-emulator-client-packet-20261011-2/evidence/certificates/wonad.x509.pem"
staged_certificate="$custom_source/external/wonad/WonadReleaseCertificate.der"
comparison="$workspace/android/out/phase1-x86-source-matched-comparison-2026100600-custom4-2.json"

sha256_re='^[0-9a-f]{64}$'

usage() {
  cat <<EOF
Usage: $0 BASELINE_RECEIPT_8_SHA256

Continue only the fresh Phase-1 custom x86 build.  The argument must be the
separately recorded lowercase SHA-256 of:
  $baseline_receipt

This script never stages the OS and never prunes the baseline OUT_DIR.
EOF
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

require_canonical_directory() {
  local path=$1
  local label=$2
  [[ "$path" == /* ]] || die "$label is not an absolute path: $path"
  [[ -d "$path" && ! -L "$path" ]] || die "$label is absent, not a directory, or symlinked: $path"
  [[ "$(/usr/bin/realpath -e -- "$path")" == "$path" ]] ||
    die "$label is not canonical: $path"
}

require_canonical_file() {
  local path=$1
  local label=$2
  [[ "$path" == /* ]] || die "$label is not an absolute path: $path"
  [[ -f "$path" && ! -L "$path" ]] || die "$label is absent, not a regular file, or symlinked: $path"
  [[ "$(/usr/bin/realpath -e -- "$path")" == "$path" ]] ||
    die "$label is not canonical: $path"
}

require_fresh_path() {
  local path=$1
  local label=$2
  local parent=${path%/*}
  [[ "$path" == /* && "$parent" != "$path" ]] || die "$label is not a safe absolute path: $path"
  require_canonical_directory "$parent" "$label parent"
  [[ ! -e "$path" && ! -L "$path" ]] || die "$label is not fresh: $path"
}

require_sha256() {
  local value=$1
  local label=$2
  [[ "$value" =~ $sha256_re ]] || die "$label is not exactly 64 lowercase hexadecimal characters"
}

require_fresh_container() {
  local output status
  set +e
  output="$(/usr/bin/docker --host unix:///var/run/docker.sock container inspect \
    --format '{{.Id}}' "$custom_container" 2>&1)"
  status=$?
  set -e
  if [[ $status -eq 0 ]]; then
    die "custom build container name is already in use: $custom_container"
  fi
  [[ $status -eq 1 && -z "${output%%*No such container: $custom_container*}" ]] ||
    die "Docker could not prove that the custom container name is fresh: $output"
}

require_future_outputs_fresh() {
  require_fresh_path "$custom_out" "custom OUT_DIR"
  require_fresh_path "$custom_log" "custom build log"
  require_fresh_path "$custom_preflight" "custom launcher preflight record"
  require_fresh_path "$custom_receipt" "custom build receipt"
  require_fresh_path "$custom_plan" "custom prune manifest"
  require_fresh_path "$custom_prune_result" "custom prune result"
  require_fresh_path "$custom_quarantine" "custom transient quarantine"
  require_fresh_path "$comparison" "baseline/custom comparison"
  require_fresh_container
}

validate_digest_output() {
  local value=$1
  local label=$2
  require_sha256 "$value" "$label"
  printf '%s' "$value"
}

quarantine_custom_specials() {
  local out=$1
  local quarantine=$2
  local row name kind path status metadata moved_metadata out_device
  local -a actual expected after source_remaining
  declare -A before_metadata

  require_canonical_directory "$out" "custom OUT_DIR"
  require_fresh_path "$quarantine" "custom transient quarantine"
  out_device="$(/usr/bin/stat -c '%d' -- "$out")"
  [[ "$(/usr/bin/stat -c '%d' -- "$evidence")" == "$out_device" ]] ||
    die "custom transient quarantine and OUT_DIR are on different filesystems"

  mapfile -t actual < <(/usr/bin/find "$out" -xdev ! -type f ! -type d ! -type l \
    -printf '%P|%y\n' | /usr/bin/sort)
  expected=(
    '.ninja_fifo|p'
    '.path_interposer_log|s'
  )
  if ((${#actual[@]} != ${#expected[@]})); then
    printf 'Unexpected custom OUT_DIR special-entry inventory:\n' >&2
    printf '  %s\n' "${actual[@]}" >&2
    return 1
  fi
  for ((status = 0; status < ${#expected[@]}; status++)); do
    [[ "${actual[$status]}" == "${expected[$status]}" ]] || {
      printf 'Unexpected custom OUT_DIR special-entry inventory:\n' >&2
      printf '  %s\n' "${actual[@]}" >&2
      return 1
    }
  done

  for row in "${expected[@]}"; do
    name=${row%|*}
    kind=${row##*|}
    path="$out/$name"
    [[ ! -L "$path" ]] || die "custom build transient is symlinked: $path"
    if [[ "$kind" == p ]]; then
      [[ -p "$path" ]] || die "custom build transient is not the expected FIFO: $path"
    else
      [[ "$kind" == s && -S "$path" ]] ||
        die "custom build transient is not the expected socket: $path"
    fi
    metadata="$(/usr/bin/stat -c '%d|%i|%f|%u|%g|%s|%h' -- "$path")"
    before_metadata[$name]=$metadata
    [[ "$metadata" == "$out_device|"*'|1000|1000|0|1' ]] ||
      die "custom build transient metadata differs: $path: $metadata"
    set +e
    /usr/bin/fuser -- "$path" >/dev/null 2>&1
    status=$?
    set -e
    [[ $status -eq 1 ]] ||
      die "custom build transient is in use or could not be audited: $path (fuser status $status)"
    [[ "$(/usr/bin/stat -c '%d|%i|%f|%u|%g|%s|%h' -- "$path")" == "$metadata" ]] ||
      die "custom build transient changed while it was audited: $path"
  done

  mapfile -t after < <(/usr/bin/find "$out" -xdev ! -type f ! -type d ! -type l \
    -printf '%P|%y\n' | /usr/bin/sort)
  [[ "${after[*]}" == "${expected[*]}" ]] ||
    die "custom OUT_DIR special-entry inventory changed before quarantine"

  /usr/bin/mkdir -m 0700 -- "$quarantine"
  [[ "$(/usr/bin/stat -c '%d|%u|%g|%a' -- "$quarantine")" == "$out_device|1000|1000|700" ]] ||
    die "custom transient quarantine has unexpected filesystem, owner, or mode"
  for row in "${expected[@]}"; do
    name=${row%|*}
    /usr/bin/mv -T -- "$out/$name" "$quarantine/$name"
    moved_metadata="$(/usr/bin/stat -c '%d|%i|%f|%u|%g|%s|%h' -- "$quarantine/$name")"
    [[ "$moved_metadata" == "${before_metadata[$name]}" ]] ||
      die "custom build transient identity changed during quarantine: $name"
  done

  mapfile -t source_remaining < <(/usr/bin/find "$out" -xdev ! -type f ! -type d ! -type l \
    -printf '%P|%y\n' | /usr/bin/sort)
  ((${#source_remaining[@]} == 0)) || die "a special entry remains in custom OUT_DIR after quarantine"
  mapfile -t after < <(/usr/bin/find "$quarantine" -mindepth 1 -maxdepth 1 \
    -printf '%P|%y\n' | /usr/bin/sort)
  [[ "${after[*]}" == "${expected[*]}" ]] ||
    die "custom transient quarantine does not contain exactly the audited FIFO and socket"
  echo "Quarantined the exact unused custom build FIFO/socket in $quarantine"
}

if [[ $# -eq 1 && ( "$1" == -h || "$1" == --help ) ]]; then
  usage
  exit 0
fi
if [[ $# -ne 1 ]]; then
  usage >&2
  exit 64
fi
baseline_sha=$1
require_sha256 "$baseline_sha" "baseline receipt SHA-256 argument"

[[ $(id -u) -eq 1000 && $(id -g) -eq 1000 ]] ||
  die "the Phase-1 x86 build must run as UID/GID 1000"
require_canonical_directory "$workspace" "Wonad workspace"
require_canonical_directory "$evidence" "Phase-1 build evidence directory"
require_canonical_directory "$custom_source" "custom GrapheneOS source"
require_canonical_directory "$custom_source/.repo" "custom GrapheneOS repo metadata"
require_canonical_file "$certificate" "selected public development certificate"
require_canonical_file "$baseline_receipt" "baseline receipt 8"
require_future_outputs_fresh

cd "$workspace"

# This is verification only: staging is intentionally outside this continuation.
/usr/bin/python3 android/platform/stage-os.py \
  --source "$custom_source" \
  --verify-only
require_canonical_file "$staged_certificate" "staged Wonad public certificate"
selected_certificate_sha="$(/usr/bin/openssl x509 -in "$certificate" -outform DER | \
  /usr/bin/sha256sum | { read -r digest _; printf '%s' "$digest"; })"
staged_certificate_sha="$(/usr/bin/sha256sum -- "$staged_certificate" | \
  { read -r digest _; printf '%s' "$digest"; })"
require_sha256 "$selected_certificate_sha" "selected certificate DER SHA-256"
require_sha256 "$staged_certificate_sha" "staged certificate DER SHA-256"
[[ "$selected_certificate_sha" == "$staged_certificate_sha" ]] ||
  die "staged OS signer differs from the selected client-packet certificate"
echo "Custom schema-4 stage and public certificate binding verified: $selected_certificate_sha"

/usr/bin/python3 android/tools/x86_build_comparison.py verify \
  --receipt "$baseline_receipt" \
  --expected-sha256 "$baseline_sha"
echo "Baseline receipt 8 reverified; the baseline OUT_DIR was not pruned or changed: $baseline_sha"

# The launcher repeats freshness, stage, source, certificate, builder, Docker,
# and filesystem-locality checks immediately before its only build launch.
/usr/bin/python3 android/tools/run_x86_build.py \
  --role custom \
  --source "$custom_source" \
  --out "$custom_out" \
  --log "$custom_log" \
  --container-name "$custom_container" \
  --certificate "$certificate"
echo "Custom build completed cleanly"

require_fresh_path "$custom_receipt" "custom build receipt"
require_fresh_path "$custom_plan" "custom prune manifest"
require_fresh_path "$custom_prune_result" "custom prune result"
require_fresh_path "$custom_quarantine" "custom transient quarantine"
require_fresh_path "$comparison" "baseline/custom comparison"

custom_sha="$(/usr/bin/python3 android/tools/x86_build_comparison.py capture \
  --role custom \
  --source "$custom_source" \
  --out-dir "$custom_out" \
  --build-log "$custom_log" \
  --container "$custom_container" \
  --development-certificate "$certificate" \
  --jobs 16 \
  --output "$custom_receipt")"
custom_sha="$(validate_digest_output "$custom_sha" "custom receipt SHA-256")"
/usr/bin/python3 android/tools/x86_build_comparison.py verify \
  --receipt "$custom_receipt" \
  --expected-sha256 "$custom_sha"
echo "Custom receipt verified: $custom_sha"

quarantine_custom_specials "$custom_out" "$custom_quarantine"
/usr/bin/python3 android/tools/x86_build_comparison.py verify \
  --receipt "$custom_receipt" \
  --expected-sha256 "$custom_sha"

require_fresh_path "$custom_plan" "custom prune manifest"
require_fresh_path "$custom_prune_result" "custom prune result"
custom_plan_sha="$(/usr/bin/python3 android/tools/prune_x86_out.py \
  --role custom \
  --out-dir "$custom_out" \
  --receipt "$custom_receipt" \
  --expected-receipt-sha256 "$custom_sha" \
  --manifest "$custom_plan")"
custom_plan_sha="$(validate_digest_output "$custom_plan_sha" "custom prune manifest SHA-256")"
custom_prune_sha="$(/usr/bin/python3 android/tools/prune_x86_out.py \
  --role custom \
  --out-dir "$custom_out" \
  --receipt "$custom_receipt" \
  --expected-receipt-sha256 "$custom_sha" \
  --manifest "$custom_plan" \
  --execute \
  --expected-manifest-sha256 "$custom_plan_sha" \
  --result "$custom_prune_result")"
custom_prune_sha="$(validate_digest_output "$custom_prune_sha" "custom prune result SHA-256")"
/usr/bin/python3 android/tools/x86_build_comparison.py verify \
  --receipt "$custom_receipt" \
  --expected-sha256 "$custom_sha"
echo "Custom authenticated prune completed and receipt reverified: $custom_prune_sha"

require_fresh_path "$comparison" "baseline/custom comparison"
comparison_sha="$(/usr/bin/python3 android/tools/x86_build_comparison.py compare \
  --baseline "$baseline_receipt" \
  --baseline-sha256 "$baseline_sha" \
  --custom "$custom_receipt" \
  --custom-sha256 "$custom_sha" \
  --output "$comparison")"
comparison_sha="$(validate_digest_output "$comparison_sha" "baseline/custom comparison SHA-256")"
/usr/bin/python3 android/tools/x86_build_comparison.py verify-comparison \
  --comparison "$comparison" \
  --expected-sha256 "$comparison_sha" \
  --baseline "$baseline_receipt" \
  --baseline-sha256 "$baseline_sha" \
  --custom "$custom_receipt" \
  --custom-sha256 "$custom_sha"
echo "Source-matched x86 comparison verified: $comparison_sha"
