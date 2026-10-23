#!/usr/bin/env bash
set -euo pipefail

workspace=/u/elric/tree/wonad
evidence=/u/elric/tree/wonad-phase1-build-evidence

baseline_pid=1845404
baseline_source=/u/elric/tree/wonad-grapheneos-2026100600
baseline_out=/u/elric/tree/wonad-grapheneos-x86-baseline-out-2026100600-6
baseline_log="$evidence/phase1-x86-baseline-2026100600-build-6.log"
baseline_container=wonad-phase1-x86-baseline-2026100600-6
baseline_receipt="$workspace/android/out/phase1-x86-baseline-2026100600-receipt-6.json"
baseline_plan="$workspace/android/out/phase1-x86-baseline-2026100600-prune-plan-6.json"
baseline_prune_result="$workspace/android/out/phase1-x86-baseline-2026100600-prune-result-6.json"

custom_source=/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-2
custom_out=/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-1
custom_log="$evidence/phase1-x86-custom-2026100600-build-1.log"
custom_container=wonad-phase1-x86-custom-2026100600-1
custom_receipt="$workspace/android/out/phase1-x86-custom-2026100600-receipt-1.json"
custom_plan="$workspace/android/out/phase1-x86-custom-2026100600-prune-plan-1.json"
custom_prune_result="$workspace/android/out/phase1-x86-custom-2026100600-prune-result-1.json"

certificate="$workspace/android/out/phase1-emulator-client-packet-20261010-7/evidence/certificates/wonad.x509.pem"
comparison="$workspace/android/out/phase1-x86-source-matched-comparison-2026100600-1.json"

cd "$workspace"

echo "Waiting for baseline launcher PID $baseline_pid"
while kill -0 "$baseline_pid" 2>/dev/null; do
  sleep 20
done

baseline_state="$(docker inspect -f '{{.State.Status}} {{.State.Running}} {{.State.OOMKilled}} {{.State.ExitCode}}' "$baseline_container")"
if [[ "$baseline_state" != "exited false false 0" ]]; then
  echo "Baseline did not terminate cleanly: $baseline_state" >&2
  exit 1
fi
echo "Baseline launcher and container completed cleanly"

baseline_sha="$(python3 android/tools/x86_build_comparison.py capture \
  --role baseline \
  --source "$baseline_source" \
  --out-dir "$baseline_out" \
  --build-log "$baseline_log" \
  --container "$baseline_container" \
  --jobs 16 \
  --output "$baseline_receipt")"
python3 android/tools/x86_build_comparison.py verify \
  --receipt "$baseline_receipt" \
  --expected-sha256 "$baseline_sha"
echo "Baseline receipt verified: $baseline_sha"

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
