#!/usr/bin/env bash
# Runs six native credentials and six one-to-one VOLEith Setup profiles.
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${HOME}/.cache/sedaa-risc0-shared-target}"
unset FSPHINCS_SECURITY FSPHINCS_K
params_list="${FSPHINCS_PARAMS_LIST:-128s 128f 192s 192f 256s 256f}"
iterations="${ITERATIONS:-1}"
run_setup="${RUN_SETUP:-1}"
if [[ "$run_setup" != 0 && "$run_setup" != 1 ]]; then
  echo "RUN_SETUP must be 0 or 1" >&2
  exit 2
fi
log_dir="${project_dir}/benchmarks/fsphincs_h1_v6"
mkdir -p "$log_dir"
stamp="$(date +%Y%m%d_%H%M%S)"
log="${LOG_FILE:-${log_dir}/native_setup_${stamp}.log}"
{
  echo "suite=fsphincs-h1-v6-native-setup H1_nodes=16/24/32B H1_address=16B padded_pubseed=64B leaf_prf_version=4 date=$(date --iso-8601=seconds)"
  echo "shared_cache=$CARGO_TARGET_DIR iterations=$iterations"
  echo "native timings exclude capability tests and compilation; deterministic inputs are test-only"
  for parameter in $params_list; do
    for ((run=1; run<=iterations; run++)); do
      echo "===== native parameter=$parameter run=$run ====="
      make -C host_proof/methods/guest/c_src/fsphincs_ref benchmark FSPHINCS_PARAMS="$parameter"
    done
    echo "===== KAT parameter=$parameter ====="
    make -C host_proof/methods/guest/c_src/fsphincs_ref kat FSPHINCS_PARAMS="$parameter"
  done
  if [[ "$run_setup" == 1 ]]; then
    paired_params=""
    for parameter in $params_list; do paired_params+="sha2-${parameter} "; done
    CREDENTIALS=fsphincs ANCHOR_MODE=seed-anchor PARAMS_LIST="$paired_params" \
      ITERATIONS="$iterations" LOG_FILE="${log_dir}/setup_detail_${stamp}.log" \
      bash ./scripts/benchmark_issuer_anchors.sh
  else
    echo "setup_proof=skipped RUN_SETUP=0"
  fi
  echo "benchmark_complete=1"
} 2>&1 | tee "$log"
echo "wrote $log"
