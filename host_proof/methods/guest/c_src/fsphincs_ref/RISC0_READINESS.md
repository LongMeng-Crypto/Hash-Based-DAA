# RISC0 guest readiness audit

## Verdict

The verification path is wired into the `fsphincs_guest` RISC0 binary. Key
generation and signing remain host-only operations.

## Work completed before guest integration

- Removed per-hash `malloc/free` from the verifier hot path. Hash preimages now
  use bounded stack buffers.
- Replaced the dynamically concatenated `H3(msg || gr)` input with incremental
  SHA-256.
- Kept all verification loop bounds compile-time fixed (`h`, `k`, and `d`).
- Streams and reuses one M-FORS layer buffer; verification never copies or
  retains the complete signature.
- Made profiling optional. Guest builds without `FSPHINCS_PROFILE` do not pay
  for counter updates.
- Reused the existing `sha2.c` entry points, so the guest can use the existing
  `RISC0_SHA_SYSCALL` SHA-256 acceleration.

Verifier working memory, excluding the input signature, is only a few KiB.
For `k=70`, the largest live local arrays are the 4,096-byte M-FORS root
accumulator and the 2,240-byte set of recovered roots.

## Exact native verifier workload

For `n=256, d=16, k=35, q=1024, h=6`:

```text
logical SHA-256 calls       4,841
SHA-256 compression blocks 14,043
```

Each of the seven M-FORS recoveries performs 691 logical SHA-256 calls:

```text
35 selected leaf hashes
560 authentication-path internal hashes
29 deterministic padding-root hashes
63 aggregation-tree internal hashes
4 H2 calls (one seed hash plus three expansion blocks)
```

The remaining four calls are H3: one message seed hash and three expansion
calls.

For `k=70`, verification uses 9,673 logical SHA-256 calls and 28,075
compression blocks. Each layer performs 1,381 logical calls; H3 uses six.

## Guest integration

- `FSPHINCS_VERIFY_ONLY` removes key generation, signing, secret derivation,
  and full-tree construction from the guest archive.
- The guest streams one M-FORS layer at a time. Its reusable `.bss` buffer is
  19,040 bytes for `k=35` or 38,080 bytes for `k=70`, rather than retaining the
  complete 133,312/266,592-byte signature.
- The host writes public key, signature, message, and commitment separately,
  avoiding a second concatenated witness buffer.
- The public journal binds success, parameter identifier `FSPX1281`, the
  102-byte issuer public key, and SHA-256 commitment to the private message.
- Guest profiling counters are disabled; the native profile remains the source
  of the exact logical SHA workload.
- Aligned SHA input blocks go directly to `sys_sha_buffer`; only unaligned
  callers use the fallback aligned copy.
- Fixed-size leaf/node hashes construct their final preimages directly.
  Authentication paths swap state buffers, and address templates are reused.
- `bench_fsphincs_risc0_gpu.sh` reports user, paging, reserved, and total
  cycles plus segment count for composite or succinct receipts.

## Optimized SHA-256 composite baseline (`segment_po2=22`)

```text
configuration  user cycles  total cycles  paging  segments  receipt bytes
k=35             4,749,081     5,242,880   62,216         2        601,644
k=70             9,397,101    10,485,760  123,741         3        946,232
```

These figures include the DAA AES hook and verification of the credential
message `et_u || issuer_nonce`.

The authentication-path left/right branch depends on the H3-derived index but
does not change loop counts or hash counts. If a future threat model requires
identical instruction traces in addition to zero-knowledge receipts, it can be
replaced by constant-time selection without changing the wire format.
