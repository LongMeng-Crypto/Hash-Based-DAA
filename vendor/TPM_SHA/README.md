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

The 128/192/256 levels use SHA-256/SHA-384/SHA-512 and the corresponding
FAEST-128S/192S/256S VOLEith parameters. All randomness enters the proof API
as 32 caller-provided bytes. Applications must use OS randomness; tests use a
fixed string only to make deterministic known-answer vectors possible.

The vendored FAEST symbols are force-prefixed with `daa_tpm_sha_faest_` so this
library can be linked alongside the existing `TPM_AES` implementation.

Build and test independently:

```sh
meson setup build-release --buildtype=release
meson compile -C build-release
meson test -C build-release --print-errorlogs
./build-release/tpm_sha_benchmark --iterations 10
```
