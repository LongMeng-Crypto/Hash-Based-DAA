#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "${script_dir}/.." && pwd)"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${HOME}/.cache/sedaa-risc0-shared-target}"
iterations="${ITERATIONS:-10}"

cd "${project_dir}"
cargo run --release -p daa_cli -- \
  bench-tpm-sha --params all --iterations "${iterations}"
