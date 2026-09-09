#!/usr/bin/env bash
# Native/KAT regression suite; only disposable test binaries are removed.
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="${project_dir}/host_proof/methods/guest/c_src/fsphincs_ref"
test_dir="$(mktemp -d /tmp/daa-fsphincs-v3-test.XXXXXX)"
cleanup() { rm -f -- "$test_dir/native" "$test_dir/kat"; rmdir -- "$test_dir"; }
trap cleanup EXIT
flags=(-O2 -g -std=c11 -Wall -Wextra -Werror)
if [[ "${SANITIZE:-0}" == 1 ]]; then
  flags+=(-fsanitize=address,undefined -fno-omit-frame-pointer)
  export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1}"
  export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1}"
fi
cd "$source_dir"
for parameter in ${FSPHINCS_PARAMS_LIST:-128s 128f 192s 192f 256s 256f}; do
  echo "===== regression parameter=$parameter sanitizer=${SANITIZE:-0} ====="
  "${CC:-cc}" "${flags[@]}" -DFSPHINCS_PROFILE -DFSPHINCS_PARAMS="$parameter" \
    -DPARAMS=sphincs-sha2-128s -I. -I../sphincs_ref \
    fsphincs.c issuer_anchor.c benchmark.c ../sphincs_ref/sha2.c -o "$test_dir/native"
  "$test_dir/native"
  "${CC:-cc}" "${flags[@]}" -DFSPHINCS_PARAMS="$parameter" \
    -DPARAMS=sphincs-sha2-128s -I. -I../sphincs_ref \
    fsphincs.c issuer_anchor.c kat.c ../sphincs_ref/sha2.c -o "$test_dir/kat"
  "$test_dir/kat" | python3 test_reference.py --params "$parameter"
done
