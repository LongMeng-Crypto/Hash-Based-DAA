#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAA_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${DAA_ROOT}"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${HOME}/.cache/sedaa-risc0-shared-target}"
export FSPHINCS_SECURITY="${FSPHINCS_SECURITY:-128}"
export DAA_DETERMINISTIC="${DAA_DETERMINISTIC:-1}"
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
