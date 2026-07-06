#!/usr/bin/env bash
set -euo pipefail

backend="poseidon2"
iterations="${ITERATIONS:-1}"
result_prefix=""

usage() {
  cat <<'EOF'
Usage: scripts/run_all_benchmarks.sh [--backend NAME] [--iterations N] [--prefix NAME]

Runs all 12 real DAA host-proof benchmarks:
  sha2-128s/f, sha2-192s/f, sha2-256s/f
  times RISC0 segment setting 1/default and 2/--segment-po2 20.

Defaults:
  --backend poseidon2
  --iterations 1
  CARGO_TARGET_DIR=/tmp/sedaa-risc0-shared-target unless already set

Examples:
  scripts/run_all_benchmarks.sh
  scripts/run_all_benchmarks.sh --backend sha-256
  scripts/run_all_benchmarks.sh --backend poseidon2 --prefix bench_poseidon2
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend)
      backend="${2:?missing value for --backend}"
      shift 2
      ;;
    --iterations)
      iterations="${2:?missing value for --iterations}"
      shift 2
      ;;
    --prefix)
      result_prefix="${2:?missing value for --prefix}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
workspace_dir="$(cd -- "${script_dir}/.." && pwd)"
cd "${workspace_dir}"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/sedaa-risc0-shared-target}"
mkdir -p results

if [[ -z "${result_prefix}" ]]; then
  safe_backend="${backend//-/_}"
  result_prefix="bench_${safe_backend}"
fi

echo "DAA_FULL benchmark sweep"
echo "  backend          : ${backend}"
echo "  iterations       : ${iterations}"
echo "  CARGO_TARGET_DIR : ${CARGO_TARGET_DIR}"
echo "  result prefix    : ${result_prefix}"
echo

for p in 128s 128f 192s 192f 256s 256f; do
  echo "=== sha2-${p} | RISC0 segments=1/default | backend=${backend} ==="
  cargo run -p daa_cli -- bench \
    --params "sha2-${p}" \
    --backend "${backend}" \
    --proof-mode real-128s \
    --iterations "${iterations}" \
    --json "results/${result_prefix}_${p}_default.json"

  echo
  echo "=== sha2-${p} | RISC0 segments=2/seg20 | backend=${backend} ==="
  cargo run -p daa_cli -- bench \
    --params "sha2-${p}" \
    --backend "${backend}" \
    --proof-mode real-128s \
    --segment-po2 20 \
    --iterations "${iterations}" \
    --json "results/${result_prefix}_${p}_seg20.json"
  echo
done

echo "All benchmark runs completed."
