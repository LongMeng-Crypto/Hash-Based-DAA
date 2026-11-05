#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
test_dir="$(mktemp -d /tmp/daa-host-verifiers.XXXXXX)"
cleanup() { rm -f -- "$test_dir/verifier.o" "$test_dir/native"; rmdir -- "$test_dir"; }
trap cleanup EXIT
cd "$project_dir/host_proof/methods/guest/c_src/sphincs_ref"
for param in 128s 128f 192s 192f 256s 256f; do
  for scheme in recursive-zk zk-wots; do
    flags=(-O2 -std=c11 -I. -DPARAMS=sphincs-sha2-"$param" -DDAA_SPHINCS_VERIFY -DDAA_SHA256_SYSCALL)
    if [[ "$scheme" == zk-wots ]]; then flags+=(-DDAA_ZK_WOTS); fi
    "${CC:-cc}" "${flags[@]}" -Dcrypto_sign_verify=daa_guest_verify -c verify_recursive.c -o "$test_dir/verifier.o"
    "${CC:-cc}" "${flags[@]}" "$project_dir/host_proof/tests/host_verifier_native.c" "$test_dir/verifier.o" \
      sign.c address.c fors.c merkle.c wots.c wotsx1.c utils.c utilsx1.c \
      sha2.c hash_sha2.c thash_sha2_simple.c -o "$test_dir/native"
    printf '%s %s: ' "$param" "$scheme"
    "$test_dir/native"
  done
done
