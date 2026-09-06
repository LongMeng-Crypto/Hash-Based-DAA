#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
test_dir="$(mktemp -d /tmp/daa-seed-anchor-test.XXXXXX)"
trap 'rm -f -- "$test_dir/native"; rmdir -- "$test_dir"' EXIT
cd "$project_dir/host_proof/methods/guest/c_src/sphincs_ref"
flags=(-O2 -g -std=c11 -Wall -Wextra -Werror)
if [[ "${SANITIZE:-0}" == 1 ]]; then flags+=(-fsanitize=address,undefined); fi
for param in 128s 128f 192s 192f 256s 256f; do
  "${CC:-cc}" "${flags[@]}" -DPARAMS=sphincs-sha2-"$param" -I. \
    "$project_dir/host_proof/tests/issuer_seed_anchor_native.c" \
    sign.c address.c fors.c merkle.c wots.c wotsx1.c utils.c utilsx1.c \
    sha2.c hash_sha2.c thash_sha2_simple.c issuer_anchor.c -o "$test_dir/native"
  "$test_dir/native"
done
