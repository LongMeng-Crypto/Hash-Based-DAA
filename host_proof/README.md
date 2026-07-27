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

It uses the paper's concrete `n=256, d=16, k=35, q=1024, h=6` parameters and
instantiates the abstract hash/PRF interfaces with domain-separated SHA-256.
Run its native key-generation, signing, and verification benchmark without
building the RISC0 prover:

```bash
make -C methods/guest/c_src/fsphincs_ref benchmark
```

The benchmark also requires a one-bit signature mutation, a changed message,
a changed public key, and a truncated signature to be rejected.

Run the deterministic known-answer and full native regression tests with:

```bash
make -C methods/guest/c_src/fsphincs_ref kat
make -C methods/guest/c_src/fsphincs_ref test
```

Full DAA benchmark commands are documented in `../README.md`.

## One-Variant CUDA Benchmark

```bash
cd DAA_FULL

CARGO_TARGET_DIR=/tmp/risc0-sha256-daa-cuda \
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
