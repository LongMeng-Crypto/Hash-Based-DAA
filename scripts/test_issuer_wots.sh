#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
test_dir="$(mktemp -d /tmp/daa-wots-test.XXXXXX)"
# Removes only this test's disposable binary; persistent Cargo caches are never touched.
cleanup() { rm -f -- "$test_dir/native"; rmdir -- "$test_dir"; }
trap cleanup EXIT
flags=(-O2 -g -std=c11 -Wall -Wextra)
if [[ "${SANITIZE:-0}" == 1 ]]; then flags+=(-fsanitize=address,undefined); fi
cd "$project_dir/host_proof/methods/guest/c_src/sphincs_ref"
for param in 128s 128f 192s 192f 256s 256f; do
  "${CC:-cc}" "${flags[@]}" -DDAA_WOTS_SUPPORTED -DPARAMS=sphincs-sha2-"$param" -I. \
    "$project_dir/host_proof/tests/issuer_wots_native.c" \
    sign.c address.c fors.c merkle.c wots.c wotsx1.c utils.c utilsx1.c \
    sha2.c hash_sha2.c thash_sha2_simple.c issuer_wots.c issuer_wots_verify.c \
    -o "$test_dir/native"
  "$test_dir/native"
done
