# DAA Host-Side Proof on the RISC0 SHA-256 Backend

This directory ports the RISC0-friendly SPHINCS+ DAA host-side proof into the
vendored RISC0 SHA-256 backend fork inside `DAA_FULL`.

The guest verifies a credential signature over `et_u || gr_u`, keeps the
credential and hook preimages private, checks the selected TPM-to-Host hook,
and binds its public outputs and issuer key in the journal. The historical AES
hook remains available; select the SHA path at build time with:

```text
DAA_TPM_BACKEND=sha2
```

The SHA path has two separately compiled Host relations:

```text
DAA_TPM_SHA_SCHEME=ours    (default)
  hk  = SHA2(0x03 || s || et_u)
  journal = ok || hk || issuer_pk

DAA_TPM_SHA_SCHEME=chen23
  hk  = SHA2(0x05 || sst)
  cet = SHA2(0x06 || sst || et_u)
  journal = ok || hk || cet || issuer_pk
```

The first is `Ours-3F + one-SHA-2 hook`; the second is the
`CDENW'23--Ours-5F + two-SHA-2 hook` comparison relation. At the 128-, 192-,
and 256-bit levels they use SHA-256, SHA-384, and SHA-512 respectively. Full
digest outputs and `et_u` are 32/48/64 bytes. Ours uses a 16/24/32-byte `s`;
CDENW'23 uses the 32/48/64-byte hidden `sst`. SHA-256 goes through RISC0's
guest SHA implementation and syscall; SHA-384/512 use the no-std software
path. `DAA_TPM_SHA_SCHEME=chen23` is rejected unless
`DAA_TPM_BACKEND=sha2`.

The proof-system backend hash suite defaults to `sha-256` through:

```text
RISC0_BACKEND_HASH=sha-256
```

## Native F-SPHINCS+-SHA256 benchmark

An experimental implementation of the F-SPHINCS+/M-FORS construction from
the PQCrypto 2023 hash-based DAA paper is maintained next to `sphincs_ref`:

```text
methods/guest/c_src/fsphincs_ref/
```

It keeps the paper's historical `k=35,70` configurations and also supports
the recalibrated `k=22,33,43` credential-security points used for the current
128/192/256 comparison. All use `n=256, d=16, q=1024, h=6` and instantiate
the abstract hash/PRF interfaces with domain-separated SHA-256.
Run its native key-generation, signing, and verification benchmark without
building the RISC0 prover:

```bash
make -C methods/guest/c_src/fsphincs_ref benchmark FSPHINCS_SECURITY=128
make -C methods/guest/c_src/fsphincs_ref benchmark FSPHINCS_SECURITY=256
```

The benchmark also requires a one-bit signature mutation, a changed message,
a changed public key, and a truncated signature to be rejected.

Run the deterministic known-answer and full native regression tests with:

```bash
make -C methods/guest/c_src/fsphincs_ref kat
make -C methods/guest/c_src/fsphincs_ref test
```

## F-SPHINCS+ RISC0 GPU benchmark

The verification-only guest streams one M-FORS layer at a time and uses the
existing SHA-256 syscalls. Key generation and signing remain native host
operations. Run the default SHA-256/composite GPU benchmark from `DAA_FULL`:

```bash
FSPHINCS_SECURITY=128 bash host_proof/scripts/bench_fsphincs_risc0_gpu.sh
FSPHINCS_SECURITY=256 bash host_proof/scripts/bench_fsphincs_risc0_gpu.sh
```

The runner reports native key-generation/signing time, RISC0 prover and
verifier time, serialized receipt size, seal size, guest cycles, paging
cycles, and segment count.

Select a different supported proof mode with environment variables. For
example, a Poseidon2 succinct receipt is:

```bash
RISC0_BACKEND_HASH=poseidon2 \
RISC0_RECEIPT_KIND=succinct \
bash host_proof/scripts/bench_fsphincs_risc0_gpu.sh
```

`RISC0_SEGMENT_LIMIT_PO2` defaults to the CUDA-safe maximum of 22 and may be
lowered to profile segmentation and paging.

Full DAA benchmark commands are documented in `../README.md`.

To benchmark F-SPHINCS+ with the one-SHA Ours relation, select `ours`. The
example uses the recalibrated 128-bit credential parameter `k=22`:

```bash
DAA_TPM_BACKEND=sha2 DAA_TPM_SHA_SCHEME=ours \
  FSPHINCS_SECURITY=128 FSPHINCS_K=22 \
  bash host_proof/scripts/bench_fsphincs_risc0_gpu.sh
```

For the CDENW'23 comparison, change only the relation selector. This proves
both SHA-2 hooks and publicly binds both `hk` and `cet`:

```bash
DAA_TPM_BACKEND=sha2 DAA_TPM_SHA_SCHEME=chen23 \
  FSPHINCS_SECURITY=128 FSPHINCS_K=22 \
  bash host_proof/scripts/bench_fsphincs_risc0_gpu.sh
```

The intended paper comparison uses CDENW'23 only with F-SPHINCS+ (`k=22,33,43`).
Ours supports Direct SPHINCS+, ZK-WOTS+, and F-SPHINCS+. Omitting
`DAA_TPM_BACKEND=sha2` retains the legacy AES hook.

## One-Variant CUDA Benchmark

```bash
cd DAA_FULL

CARGO_TARGET_DIR="${HOME}/.cache/sedaa-risc0-shared-target" \
RISC0_PROVER=local \
RISC0_BACKEND_HASH=sha-256 \
DAA_DETERMINISTIC=1 \
SPHINCS_OPT_LEVEL=2 \
SPHINCS_PARAMS=sphincs-sha2-128s \
SPHINCS_THASH=simple \
cargo run -p daa_sha256_backend_host --release --features cuda --bin daa_sha256_backend_host
```

## Six-Variant CUDA Benchmarks

```bash
bash host_proof/scripts/bench_sha2_backend_cuda.sh
bash host_proof/scripts/bench_sha2_backend_small_segment_cuda.sh
```
