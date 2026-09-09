#!/usr/bin/env bash
# Benchmarks six F-SPHINCS+ credentials, each with the Ours-3F one-SHA hook.
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${HOME}/.cache/sedaa-risc0-shared-target}"
unset FSPHINCS_SECURITY FSPHINCS_K RISC0_SKIP_BUILD
export DAA_TPM_BACKEND=sha2 DAA_TPM_SHA_SCHEME=ours DAA_CREDENTIAL_SCHEME=fsphincs
export RISC0_BACKEND_HASH=sha-256 RISC0_IDENTITY_WRAP=0 RISC0_DEV_MODE=0
params_list="${FSPHINCS_PARAMS_LIST:-128s 128f 192s 192f 256s 256f}"
segments="${SEGMENT_PO2_LIST:-22}"
receipts="${RECEIPT_LIST:-composite succinct}"
iterations="${ITERATIONS:-1}"
log_dir="${project_dir}/benchmarks/fsphincs_v3"
mkdir -p "$log_dir"
log="${LOG_FILE:-${log_dir}/host_$(date +%Y%m%d_%H%M%S).log}"
{
  echo "suite=fsphincs-v3-host hook=ours-one-SHA backend=sha-256 identity=0"
  echo "execution_only=${FSPHINCS_EXECUTE_ONLY:-0}"
  echo "shared_cache=$CARGO_TARGET_DIR date=$(date --iso-8601=seconds)"
  for parameter in $params_list; do
    for segment in $segments; do
      for receipt in $receipts; do
        for ((run=1; run<=iterations; run++)); do
          echo "===== parameter=$parameter receipt=$receipt segment_po2=$segment run=$run ====="
          FSPHINCS_PARAMS="$parameter" SPHINCS_PARAMS="sphincs-sha2-${parameter}" \
            RISC0_SEGMENT_LIMIT_PO2="$segment" RISC0_RECEIPT_KIND="$receipt" \
            bash host_proof/scripts/bench_fsphincs_risc0_gpu.sh
        done
      done
    done
  done
  echo "benchmark_complete=1"
} 2>&1 | tee "$log"
echo "wrote $log"
