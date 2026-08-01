# DAA Host-Side Proof on the RISC0 SHA-256 Backend

This directory ports the RISC0-friendly SPHINCS+ DAA host-side proof into the
vendored RISC0 SHA-256 backend fork inside `DAA_FULL`.

The guest statement is unchanged from `risc0_sphincs_risc0_friendly`: the guest
verifies a SPHINCS+ signature over `et_u || gr_u`, keeps `et_u` private, checks
the AES hook output `hk`, and commits `ok || hk` to the journal.

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

It supports the paper's two concrete configurations
`n=256, d=16, q=1024, h=6` with `k=35` (128) or `k=70` (256), and
instantiates the abstract hash/PRF interfaces with domain-separated SHA-256.
Here 128/256 names the paper's two concrete MPCitH-soundness configurations;
it is not by itself a new concrete EU-CMA proof for the SHA-256 credential
instantiation.
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

The verification-only guest reads the 133,312-byte signature directly into
guest static memory, verifies it in place, and uses the existing SHA-256
syscalls. Key generation and signing remain native host operations. Run the
default SHA-256/composite GPU benchmark from `DAA_FULL`:

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
