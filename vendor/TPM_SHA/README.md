# SHA-2 TPM Proof Backend

VOLEith proofs support SHA-256/384/512 Join, three-function and five-function
signing relations, and issuer seed anchors, with s/f profiles. The proof format
binds the circuit, context, security level and profile.

```sh
meson setup /tmp/daa-tpm-sha-tests . --buildtype=release
meson test -C /tmp/daa-tpm-sha-tests --print-errorlogs
/tmp/daa-tpm-sha-tests/tpm_sha_benchmark --scheme all --profile all --iterations 10
```
