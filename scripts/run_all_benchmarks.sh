#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${HOME}/.cache/daa-full-target}"
export RISC0_PROVER=local RISC0_DEV_MODE=0 RISC0_BACKEND_HASH=sha-256
export RISC0_RECEIPT_KIND=succinct
iterations="${ITERATIONS:-1}"
params_list="${PARAMS_LIST:-128s 128f 192s 192f 256s 256f}"
for primitive in aes rijndael sha2; do
  for host in recursive-zk zk-wots fsphincs; do
    if [[ "$host" == recursive-zk ]]; then export RISC0_IDENTITY_WRAP=1; else export RISC0_IDENTITY_WRAP=0; fi
    for param in $params_list; do
      if [[ "$primitive" == rijndael && "$param" != 128s && "$param" != 128f ]]; then continue; fi
      cargo run --locked --release -p daa_cli -- bench --params "sha2-$param" \
        --tpm-backend "$primitive" --host-scheme "$host" --proof-mode real \
        --segment-po2 "${SEGMENT_PO2:-20}" --iterations "$iterations"
    done
  done
done
