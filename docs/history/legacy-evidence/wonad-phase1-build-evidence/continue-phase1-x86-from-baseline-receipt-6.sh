#!/usr/bin/env bash
set -euo pipefail

workspace=/u/elric/tree/wonad
evidence=/u/elric/tree/wonad-phase1-build-evidence

baseline_source=/u/elric/tree/wonad-grapheneos-2026100600
baseline_out=/u/elric/tree/wonad-grapheneos-x86-baseline-out-2026100600-6
baseline_receipt="$workspace/android/out/phase1-x86-baseline-2026100600-receipt-6.json"
baseline_sha=3b611c282e9df4bb28255afd136f2e64cb3b335c90a1fedfcdc33b1487dec782
baseline_plan="$workspace/android/out/phase1-x86-baseline-2026100600-prune-plan-6.json"
baseline_prune_result="$workspace/android/out/phase1-x86-baseline-2026100600-prune-result-6.json"

custom_source=/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-2
custom_out=/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-1
custom_log="$evidence/phase1-x86-custom-2026100600-build-1.log"
custom_container=wonad-phase1-x86-custom-2026100600-1
custom_receipt="$workspace/android/out/phase1-x86-custom-2026100600-receipt-1.json"
custom_plan="$workspace/android/out/phase1-x86-custom-2026100600-prune-plan-1.json"
custom_prune_result="$workspace/android/out/phase1-x86-custom-2026100600-prune-result-1.json"
custom_quarantine="$evidence/custom-1-transient-specials-quarantine"

certificate="$workspace/android/out/phase1-emulator-client-packet-20261010-7/evidence/certificates/wonad.x509.pem"
comparison="$workspace/android/out/phase1-x86-source-matched-comparison-2026100600-1.json"

quarantine_custom_specials() {
  local out=$1
  local quarantine=$2
  local row
  local -a actual expected

  mapfile -t actual < <(find "$out" -xdev ! -type f ! -type d ! -type l \
    -printf '%P|%y\n' | LC_ALL=C sort)
  expected=(
    '.ninja_fifo|p'
    '.path_interposer_log|s'
  )
  if [[ "${actual[*]}" != "${expected[*]}" ]]; then
    printf 'Unexpected custom OUT_DIR special-entry inventory:\n' >&2
    printf '  %s\n' "${actual[@]}" >&2
    return 1
  fi
  if [[ -e "$quarantine" || -L "$quarantine" ]]; then
    echo "Custom special-entry quarantine is not fresh: $quarantine" >&2
    return 1
  fi
  for row in "${expected[@]}"; do
    local name=${row%|*}
    local kind=${row##*|}
    local path="$out/$name"
    local metadata
    metadata="$(stat -c '%u %g %s %d' "$path")"
    if [[ "$metadata" != "1000 1000 0 $(stat -c '%d' "$out")" ]]; then
      echo "Unexpected custom build transient metadata: $path: $metadata" >&2
      return 1
    fi
    if [[ "$kind" == p && ! -p "$path" ]] || [[ "$kind" == s && ! -S "$path" ]]; then
      echo "Custom build transient changed type: $path" >&2
      return 1
    fi
    set +e
    fuser "$path" >/dev/null 2>&1
    local fuser_status=$?
    set -e
    if [[ $fuser_status -ne 1 ]]; then
      echo "Custom build transient is in use or could not be audited: $path" >&2
      return 1
    fi
  done

  install -d -m 0700 "$quarantine"
  mv -T -- "$out/.ninja_fifo" "$quarantine/.ninja_fifo"
  mv -T -- "$out/.path_interposer_log" "$quarantine/.path_interposer_log"
  local -a remaining
  mapfile -t remaining < <(find "$out" -xdev ! -type f ! -type d ! -type l -print)
  if ((${#remaining[@]} != 0)); then
    echo "A special entry remains in the custom OUT_DIR after quarantine" >&2
    return 1
  fi
  echo "Quarantined exact unused custom build transients in $quarantine"
}

cd "$workspace"

python3 android/tools/x86_build_comparison.py verify \
  --receipt "$baseline_receipt" \
  --expected-sha256 "$baseline_sha"
echo "Baseline receipt reverified: $baseline_sha"

baseline_plan_sha="$(python3 android/tools/prune_x86_out.py \
  --role baseline \
  --out-dir "$baseline_out" \
  --receipt "$baseline_receipt" \
  --expected-receipt-sha256 "$baseline_sha" \
  --manifest "$baseline_plan")"
baseline_prune_sha="$(python3 android/tools/prune_x86_out.py \
  --role baseline \
  --out-dir "$baseline_out" \
  --receipt "$baseline_receipt" \
  --expected-receipt-sha256 "$baseline_sha" \
  --manifest "$baseline_plan" \
  --execute \
  --expected-manifest-sha256 "$baseline_plan_sha" \
  --result "$baseline_prune_result")"
echo "Baseline authenticated prune completed: $baseline_prune_sha"

python3 android/tools/run_x86_build.py \
  --role custom \
  --source "$custom_source" \
  --out "$custom_out" \
  --log "$custom_log" \
  --container-name "$custom_container" \
  --certificate "$certificate"
echo "Custom build completed cleanly"

custom_sha="$(python3 android/tools/x86_build_comparison.py capture \
  --role custom \
  --source "$custom_source" \
  --out-dir "$custom_out" \
  --build-log "$custom_log" \
  --container "$custom_container" \
  --development-certificate "$certificate" \
  --jobs 16 \
  --output "$custom_receipt")"
python3 android/tools/x86_build_comparison.py verify \
  --receipt "$custom_receipt" \
  --expected-sha256 "$custom_sha"
echo "Custom receipt verified: $custom_sha"

quarantine_custom_specials "$custom_out" "$custom_quarantine"
python3 android/tools/x86_build_comparison.py verify \
  --receipt "$custom_receipt" \
  --expected-sha256 "$custom_sha"

custom_plan_sha="$(python3 android/tools/prune_x86_out.py \
  --role custom \
  --out-dir "$custom_out" \
  --receipt "$custom_receipt" \
  --expected-receipt-sha256 "$custom_sha" \
  --manifest "$custom_plan")"
custom_prune_sha="$(python3 android/tools/prune_x86_out.py \
  --role custom \
  --out-dir "$custom_out" \
  --receipt "$custom_receipt" \
  --expected-receipt-sha256 "$custom_sha" \
  --manifest "$custom_plan" \
  --execute \
  --expected-manifest-sha256 "$custom_plan_sha" \
  --result "$custom_prune_result")"
echo "Custom authenticated prune completed: $custom_prune_sha"

comparison_sha="$(python3 android/tools/x86_build_comparison.py compare \
  --baseline "$baseline_receipt" \
  --baseline-sha256 "$baseline_sha" \
  --custom "$custom_receipt" \
  --custom-sha256 "$custom_sha" \
  --output "$comparison")"
python3 android/tools/x86_build_comparison.py verify-comparison \
  --comparison "$comparison" \
  --expected-sha256 "$comparison_sha" \
  --baseline "$baseline_receipt" \
  --baseline-sha256 "$baseline_sha" \
  --custom "$custom_receipt" \
  --custom-sha256 "$custom_sha"
echo "Source-matched x86 comparison verified: $comparison_sha"
