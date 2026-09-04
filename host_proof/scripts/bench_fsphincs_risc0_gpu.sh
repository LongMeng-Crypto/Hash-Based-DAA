#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAA_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${DAA_ROOT}"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${HOME}/.cache/sedaa-risc0-shared-target}"
LOCAL_RECURSION_ZKR="${HOME}/RISC0-SHA256/vendor/risc0_sha256_backend/crates/risc0-circuit-recursion/src/recursion_zkr.zip"
if [[ -z "${RECURSION_SRC_PATH:-}" && -f "${LOCAL_RECURSION_ZKR}" ]]; then
  export RECURSION_SRC_PATH="${LOCAL_RECURSION_ZKR}"
fi
export FSPHINCS_SECURITY="${FSPHINCS_SECURITY:-128}"
# Optional independent M-FORS width: 22, 33, 35, 43, or 70. When omitted,
# historical defaults remain 128->35, 192->33, and 256->70.
export DAA_DETERMINISTIC="${DAA_DETERMINISTIC:-1}"
export DAA_TPM_BACKEND="${DAA_TPM_BACKEND:-aes}"
export DAA_TPM_SHA_SCHEME="${DAA_TPM_SHA_SCHEME:-ours}"
export RISC0_PROVER="${RISC0_PROVER:-local}"
export RISC0_BACKEND_HASH="${RISC0_BACKEND_HASH:-sha-256}"
export RISC0_RECEIPT_KIND="${RISC0_RECEIPT_KIND:-composite}"
export RISC0_SEGMENT_LIMIT_PO2="${RISC0_SEGMENT_LIMIT_PO2:-22}"
export SPHINCS_OPT_LEVEL="${SPHINCS_OPT_LEVEL:-2}"
export SPHINCS_PARAMS="${SPHINCS_PARAMS:-sphincs-sha2-128s}"
export SPHINCS_THASH="${SPHINCS_THASH:-simple}"

cargo run \
  -p daa_sha256_backend_host \
  --bin bench_fsphincs_risc0 \
  --release \
  --features cuda
