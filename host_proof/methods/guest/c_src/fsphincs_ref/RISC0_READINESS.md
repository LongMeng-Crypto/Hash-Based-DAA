# RISC0 guest readiness audit

## Verdict

The verification path is structurally suitable for a RISC0 guest, but it has
not yet been wired into the guest binary. Key generation and signing remain
host-only operations.

## Work completed before guest integration

- Removed per-hash `malloc/free` from the verifier hot path. Hash preimages now
  use bounded stack buffers.
- Replaced the dynamically concatenated `H3(msg || gr)` input with incremental
  SHA-256.
- Kept all verification loop bounds compile-time fixed (`h`, `k`, and `d`).
- Kept the signature as an input buffer; verification does not copy its
  133,312 bytes.
- Made profiling optional. Guest builds without `FSPHINCS_PROFILE` do not pay
  for counter updates.
- Reused the existing `sha2.c` entry points, so the guest can use the existing
  `RISC0_SHA_SYSCALL` SHA-256 acceleration.

Verifier working memory, excluding the input signature, is only a few KiB.
The largest live local arrays are the 2,048-byte M-FORS root accumulator and
the 1,120-byte set of recovered roots.

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

## Items to handle while wiring the guest

1. Add `fsphincs.c` to `methods/guest/build.rs` and link it against `sha2.c`
   with `RISC0_SHA_SYSCALL`.
2. Compile only verification into the guest, or rely on function-section
   garbage collection to discard host-only tree generation/signing.
3. Read the 133,312-byte signature as private guest input without an extra
   full-size copy.
4. Bind the public journal to the issuer F-SPHINCS+ public key, protocol
   parameter identifier, and the same DAA message/commitment used by the TPM
   side.
5. Measure user cycles with profiling disabled; use the native counter build
   only to explain the SHA workload.
6. Check segment counts for both composite SHA-256 and Poseidon2 succinct
   backends. The fixed loop bounds give fixed logical work, but paging from the
   large signature input must still be measured.

The authentication-path left/right branch depends on the H3-derived index but
does not change loop counts or hash counts. If a future threat model requires
identical instruction traces in addition to zero-knowledge receipts, it can be
replaced by constant-time selection without changing the wire format.
