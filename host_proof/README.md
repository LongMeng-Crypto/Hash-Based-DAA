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
