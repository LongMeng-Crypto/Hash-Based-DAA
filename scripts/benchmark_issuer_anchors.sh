#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "${script_dir}/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${HOME}/.cache/sedaa-risc0-shared-target}"
anchor_mode="${ANCHOR_MODE:-seed-dual}"
case "$anchor_mode" in
  seed-dual) export RISC0_SKIP_BUILD="${RISC0_SKIP_BUILD:-1}" ;;
  fixed-top-wots|all) unset RISC0_SKIP_BUILD ;;
  *) echo "ANCHOR_MODE must be seed-dual, fixed-top-wots, or all" >&2; exit 2 ;;
esac
export RISC0_PROVER=local
export RISC0_DEV_MODE=0
export RISC0_BACKEND_HASH="${RISC0_BACKEND_HASH:-sha-256}"
export RISC0_RECEIPT_KIND="${RISC0_RECEIPT_KIND:-composite}"
export RISC0_SEGMENT_LIMIT_PO2="${SEGMENT_PO2:-20}"
export SPHINCS_OPT_LEVEL="${SPHINCS_OPT_LEVEL:-4}"
export DAA_DETERMINISTIC=1
recursion_zip="${HOME}/RISC0-SHA256/vendor/risc0_sha256_backend/crates/risc0-circuit-recursion/src/recursion_zkr.zip"
if [[ -z "${RECURSION_SRC_PATH:-}" && -f "$recursion_zip" ]]; then
  export RECURSION_SRC_PATH="$recursion_zip"
fi
iterations="${ITERATIONS:-1}"
params_list="${PARAMS_LIST:-sha2-128s sha2-128f sha2-192s sha2-192f sha2-256s sha2-256f}"
if [[ "$anchor_mode" == fixed-top-wots ]]; then
  credentials="${CREDENTIALS:-sphincs}"
else
  credentials="${CREDENTIALS:-sphincs fsphincs}"
fi
log_dir="${project_dir}/benchmarks/issuer_anchor"
mkdir -p "$log_dir"
log_file="${LOG_FILE:-${log_dir}/issuer_anchor_${anchor_mode}_${RISC0_RECEIPT_KIND}_$(date +%Y%m%d_%H%M%S).log}"
: >"$log_file"
echo "shared_cache=${CARGO_TARGET_DIR}; build/startup/test time excluded from pi_I timings" | tee -a "$log_file"

# Benchmarks one credential, SPHINCS+ parameter set, and independent Setup proof mode.
run_one() {
  local credential="$1" params="$2" mode="$3"
  echo "===== credential=${credential} params=${params} mode=${mode} =====" | tee -a "$log_file"
  cargo run --quiet --release -p daa_cli -- bench-issuer-anchor \
    --params "$params" --credential-scheme "$credential" --issuer-anchor-mode "$mode" \
    --backend "$RISC0_BACKEND_HASH" --segment-po2 "$RISC0_SEGMENT_LIMIT_PO2" \
    --proof-mode real-tpm --iterations "$iterations" 2>&1 | tee -a "$log_file"
  echo | tee -a "$log_file"
}

cd "$project_dir"
for credential in $credentials; do
  for params in $params_list; do
    if [[ "$anchor_mode" == seed-dual || "$anchor_mode" == all ]]; then
      run_one "$credential" "$params" seed-dual
    fi
    if [[ "$anchor_mode" == fixed-top-wots || ( "$anchor_mode" == all && "$credential" == sphincs ) ]]; then
      run_one "$credential" "$params" fixed-top-wots
    fi
  done
done
echo "benchmark_complete=1" | tee -a "$log_file"
echo "wrote ${log_file}"
