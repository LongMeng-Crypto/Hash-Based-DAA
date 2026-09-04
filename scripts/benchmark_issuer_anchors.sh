#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "${script_dir}/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${HOME}/.cache/sedaa-risc0-shared-target}"
export RISC0_SKIP_BUILD="${RISC0_SKIP_BUILD:-1}"

iterations="${ITERATIONS:-1}"
log_dir="${project_dir}/benchmarks/issuer_anchor"
mkdir -p "${log_dir}"
log_file="${LOG_FILE:-${log_dir}/issuer_anchor_latest.log}"
: >"${log_file}"

# Benchmarks one credential and VOLEith parameter combination.
run_one() {
  local credential="$1"
  local params="$2"
  echo "===== credential=${credential} params=${params} =====" | tee -a "${log_file}"
  cargo run --quiet --release -p daa_cli -- \
    bench-issuer-anchor \
    --params "${params}" \
    --credential-scheme "${credential}" \
    --proof-mode real-tpm \
    --iterations "${iterations}" 2>&1 | tee -a "${log_file}"
  echo | tee -a "${log_file}"
}

cd "${project_dir}"
for params in sha2-128s sha2-128f sha2-192s sha2-192f sha2-256s sha2-256f; do
  run_one sphincs "${params}"
done
for params in sha2-128s sha2-128f sha2-192s sha2-192f sha2-256s sha2-256f; do
  run_one fsphincs "${params}"
done

echo "wrote ${log_file}"
