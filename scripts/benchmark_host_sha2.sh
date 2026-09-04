#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
workspace_dir="$(cd -- "${script_dir}/.." && pwd)"
cd "${workspace_dir}"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${HOME}/.cache/sedaa-risc0-shared-target}"
export RISC0_PROVER="${RISC0_PROVER:-local}"
export RISC0_BACKEND_HASH="${RISC0_BACKEND_HASH:-sha-256}"
export DAA_DETERMINISTIC="${DAA_DETERMINISTIC:-1}"

local_recursion_zkr="${HOME}/RISC0-SHA256/vendor/risc0_sha256_backend/crates/risc0-circuit-recursion/src/recursion_zkr.zip"
if [[ -z "${RECURSION_SRC_PATH:-}" && -f "${local_recursion_zkr}" ]]; then
  export RECURSION_SRC_PATH="${local_recursion_zkr}"
fi

iterations="${ITERATIONS:-1}"
segment_po2="${SEGMENT_PO2:-20}"
timestamp="$(date +%Y%m%d-%H%M%S)"
log_dir="${HOST_BENCH_LOG_DIR:-${workspace_dir}/benchmarks/host_sha2}"
case_dir="${HOST_BENCH_CASE_DIR:-${workspace_dir}/results/host_sha2/${timestamp}}"
log_file="${HOST_BENCH_LOG:-${log_dir}/host_sha2_all_${timestamp}.log}"
summary_file="${HOST_BENCH_SUMMARY:-${log_dir}/host_sha2_all_${timestamp}.tsv}"

mkdir -p "${CARGO_TARGET_DIR}" "${log_dir}" "${case_dir}"
printf '%s\n' $'family\trelation\tcredential\tparameter\treceipt\tidentity\tsegment_po2\trun\tprover_us\tverifier_us\tproof_bytes\tseal_bytes' >"${summary_file}"

security_k() {
  case "$1" in
    128) printf '%s' 22 ;;
    192) printf '%s' 33 ;;
    256) printf '%s' 43 ;;
    *)
      printf 'unsupported security level: %s\n' "$1" >&2
      return 1
      ;;
  esac
}

metric() {
  local key="$1"
  local file="$2"
  sed -n "s/^${key}=//p" "${file}" | tail -n 1
}

run_host_case() {
  local family="$1"
  local relation="$2"
  local credential="$3"
  local parameter="$4"
  local opt_level="$5"
  local receipt="$6"
  local identity="$7"
  local binary="$8"
  local security="${parameter%[sf]}"
  local fs_k
  fs_k="$(security_k "${security}")"

  local run
  for ((run = 1; run <= iterations; run++)); do
    local case_name="${family}_${relation}_${parameter}_${receipt}_identity${identity}_seg${segment_po2}_run${run}"
    local case_log="${case_dir}/${case_name}.log"

    printf '\n%s\n' '================================================================'
    printf 'CASE=%s\n' "${case_name}"
    printf 'family=%s relation=%s credential=%s parameter=%s\n' \
      "${family}" "${relation}" "${credential}" "${parameter}"
    printf 'opt=%s receipt=%s identity=%s segment_po2=%s\n' \
      "${opt_level}" "${receipt}" "${identity}" "${segment_po2}"
    printf '%s\n' '================================================================'

    env \
      DAA_TPM_BACKEND=sha2 \
      DAA_TPM_SHA_SCHEME="${relation}" \
      DAA_CREDENTIAL_SCHEME="${credential}" \
      SPHINCS_PARAMS="sphincs-sha2-${parameter}" \
      SPHINCS_THASH=simple \
      SPHINCS_OPT_LEVEL="${opt_level}" \
      FSPHINCS_SECURITY="${security}" \
      FSPHINCS_K="${fs_k}" \
      RISC0_RECEIPT_KIND="${receipt}" \
      RISC0_IDENTITY_WRAP="${identity}" \
      RISC0_SEGMENT_LIMIT_PO2="${segment_po2}" \
      cargo run \
        -p daa_sha256_backend_host \
        --bin "${binary}" \
        --release \
        --features cuda \
        2>&1 | tee "${case_log}"

    local prover_us verifier_us proof_bytes seal_bytes
    prover_us="$(metric prover_us "${case_log}")"
    verifier_us="$(metric verifier_us "${case_log}")"
    proof_bytes="$(metric proof_bytes "${case_log}")"
    seal_bytes="$(metric seal_bytes "${case_log}")"

    if [[ -z "${prover_us}" || -z "${verifier_us}" || -z "${proof_bytes}" || -z "${seal_bytes}" ]]; then
      printf 'missing machine-readable metrics in %s\n' "${case_log}" >&2
      return 1
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "${family}" "${relation}" "${credential}" "${parameter}" \
      "${receipt}" "${identity}" "${segment_po2}" "${run}" \
      "${prover_us}" "${verifier_us}" "${proof_bytes}" "${seal_bytes}" \
      >>"${summary_file}"
  done
}

{
  printf '%s\n' 'Complete SHA-2 Host proof benchmark'
  printf 'date             : %s\n' "$(date --iso-8601=seconds)"
  printf 'DAA commit       : %s\n' "$(git rev-parse --short HEAD)"
  if [[ -d "${HOME}/RISC0-SHA256/.git" ]]; then
    printf 'backend commit   : %s\n' "$(git -C "${HOME}/RISC0-SHA256" rev-parse --short HEAD)"
  fi
  printf 'cargo target     : %s\n' "${CARGO_TARGET_DIR}"
  printf 'segment_po2      : %s\n' "${segment_po2}"
  printf 'iterations       : %s\n' "${iterations}"
  printf 'combined log     : %s\n' "${log_file}"
  printf 'summary TSV      : %s\n' "${summary_file}"
  printf 'per-case logs    : %s\n' "${case_dir}"

  # Existing Direct SPHINCS+ relation: opt2 verification followed by the
  # already-supported SHA-256 Succinct and Identity recursion layers.
  for parameter in 128s 128f 192s 192f 256s 256f; do
    run_host_case \
      direct ours sphincs "${parameter}" 2 succinct 1 \
      daa_sha256_backend_host
  done

  # Existing ZK-WOTS+ relation: opt4, with no Identity wrapper.
  for parameter in 128s 128f 192s 192f 256s 256f; do
    run_host_case \
      zkwots ours sphincs "${parameter}" 4 composite 0 \
      daa_sha256_backend_host
    run_host_case \
      zkwots ours sphincs "${parameter}" 4 succinct 0 \
      daa_sha256_backend_host
  done

  # Existing constant-structure F-SPHINCS+ relation with k=22/33/43.
  # Ours-3F and CDENW'23--Ours-5F differ only in the SHA-2 hook relation.
  for relation in ours chen23; do
    for security in 128 192 256; do
      run_host_case \
        fsphincs "${relation}" fsphincs "${security}s" 2 composite 0 \
        bench_fsphincs_risc0
      run_host_case \
        fsphincs "${relation}" fsphincs "${security}s" 2 succinct 0 \
        bench_fsphincs_risc0
    done
  done

  printf '\n%s\n' 'All 30 existing Host benchmark cases completed.'
  printf 'Combined log: %s\n' "${log_file}"
  printf 'Summary TSV : %s\n' "${summary_file}"
  printf 'Per-case log: %s\n' "${case_dir}"
} 2>&1 | tee "${log_file}"
