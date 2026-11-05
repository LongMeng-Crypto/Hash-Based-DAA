#!/bin/bash

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
  "$bench" -i "$ITER" 2>/dev/null | sed -n '4p'
done

echo "------------------------------------------------------------------------------------"
