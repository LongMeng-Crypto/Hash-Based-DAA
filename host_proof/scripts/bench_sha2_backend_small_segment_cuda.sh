#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORK_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${FORK_ROOT}"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${HOME}/.cache/sedaa-risc0-shared-target}"

variants=(
  sphincs-sha2-128s
  sphincs-sha2-128f
  sphincs-sha2-192s
  sphincs-sha2-192f
  sphincs-sha2-256s
  sphincs-sha2-256f
)

for variant in "${variants[@]}"; do
  echo
  echo "=== ${variant} | RISC0 backend=sha-256 | opt2 | seg_po2=20 ==="
  RISC0_PROVER=local \
  RISC0_BACKEND_HASH=sha-256 \
  DAA_DETERMINISTIC=1 \
  RISC0_SEGMENT_LIMIT_PO2=20 \
  SPHINCS_OPT_LEVEL=2 \
  SPHINCS_PARAMS="${variant}" \
  SPHINCS_THASH=simple \
  cargo run -p daa_sha256_backend_host --bin daa_sha256_backend_host --release --features cuda
 done
