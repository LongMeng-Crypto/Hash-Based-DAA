#!/bin/bash
# Run all four FAEST-TPM benchmarks and print a combined summary table.
# Usage: ./bench_all.sh [-i <iterations>] [-d <builddir>]

set -euo pipefail

ITER=100
BUILD_DIR="builddir_rel"
export PATH="/c/msys64/mingw64/bin:$PATH"

while getopts "i:d:" opt; do
  case $opt in
    i) ITER="$OPTARG" ;;
    d) BUILD_DIR="$OPTARG" ;;
    *) echo "Usage: $0 [-i iterations] [-d builddir]"; exit 1 ;;
  esac
done

PARAMS="faest_128s faest_128f faest_192s faest_192f faest_256s faest_256f"

# Print header once
echo "------------------------------------------------------------------------------------"
printf "%-12s %14s %14s %14s %14s %16s\n" \
  "Scheme" "KeyGen (us)" "Sign (ms)" "Verify (ms)" "SigSize (B)" "SigSize (KB)"
echo "------------------------------------------------------------------------------------"

for p in $PARAMS; do
  bench="${BUILD_DIR}/${p}/${p}_bench.exe"
  if [ ! -f "$bench" ]; then
    echo "  [skipped: $bench not found]"
    continue
  fi
  # Extract the data row (4th line of the 5-line output)
  "$bench" -i "$ITER" 2>/dev/null | sed -n '4p'
done

echo "------------------------------------------------------------------------------------"
