# DAA TPM SHA

This is a minimal source snapshot of the VOLEith binary-circuit backend at
commit `a721500`, extended with the DAA-specific SHA-2 relations.

The SHA mode uses fixed, one-byte domain tags:

```text
slt = SHA2(0x01 || sk || lid)
et  = SHA2(0x02 || sk || gid)
hk  = SHA2(0x03 || s  || et)
```

The Join proof exposes `(gid, et)` and proves knowledge of `sk`. The joint TPM
signing proof exposes `(lid, gid, slt, hk)` and proves knowledge of `(sk, s)`;
`et` is an internal digest wire from the second SHA invocation to the third.
The same `sk` input wires are used by the first two invocations.

The 128/192/256 levels use SHA-256/SHA-384/SHA-512. Each level supports both
FAEST S (smaller proof) and F (faster proof) VOLE profiles. Proof format v3
binds the level and profile in the serialized header, circuit identifier, and
Fiat--Shamir transcript, so an S proof cannot be verified as F or conversely.

All randomness enters the proof API as 32 caller-provided bytes. Applications
must use OS randomness; tests use fixed bytes only for six deterministic
known-answer vectors. The tests lock GF(2^64/128/192/256) arithmetic against
fixed KATs and independent scalar references, including full-width,
mixed-width, and batched products. The optimized backend uses aligned
runtime-dispatched PCLMUL/Karatsuba paths at all three security levels,
2/3/4-lane AVX2 VOLE-matrix transposition, batched QuickSilver universal
hashing, a reusable-scratch streaming ConvertToVOLE tree fold, and eight-way
AES-CTR generation. These paths do not change the relation, proof format,
transcript, or generated PRG stream.

The vendored FAEST symbols are force-prefixed with `daa_tpm_sha_faest_` so this
library can be linked alongside the existing `TPM_AES` implementation.

Build and test independently:

```sh
meson setup build-release --buildtype=release
meson compile -C build-release
meson test -C build-release --print-errorlogs
./build-release/tpm_sha_benchmark --profile all --iterations 10
```
