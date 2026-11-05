# SwfitDAA Proof-of-Concept demo

This repository implements a single-machine Direct Anonymous Attestation (DAA)
demo: issuer Setup, TPM Join, TPM/host signing, verification, and basename linking.
**The TPM is simulated by ordinary software on the host CPU. No code runs on a
physical TPM, and this is not a production deployment.** Revocation is limited
to empty revocation lists. Deterministic demo inputs are for reproducibility.

Benchmarks cover SHA-2 and AES TPM Join/signing proofs, issuer extraction proofs,
SPHINCS+ and F-SPHINCS+ credentials, and RISC0 host proofs using Direct SPHINCS+,
ZK-WOTS+, or F-SPHINCS+. SHA-2 signing supports the 3F and 5F relations. Each
security level (128/192/256) has small-proof (`s`) and fast-prover (`f`) profiles.
F-SPHINCS+ parameter labels describe this experimental construction.

## 1. Hardware and software

Use x86-64 Linux; Ubuntu 24.04 is the reference platform. WSL2 requires working
CUDA passthrough for GPU proving. Native benchmarks run on the CPU; AES-NI,
PCLMULQDQ, and AVX2 accelerate supported paths.

| Workload | CPU / GPU requirements |
| --- | --- |
| Simulated protocol, native credentials, VOLEith TPM and seed-anchor proofs | CPU only; no CUDA or RISC0 toolchain required |
| RISC0 host proofs on CPU | Multicore CPU; at least 16 GB RAM, preferably 32 GB; substantially slower than GPU proving |
| RISC0 host proofs on GPU | NVIDIA CUDA-capable GPU, compatible driver and CUDA toolkit; 16 GB VRAM and 32 GB host RAM are the reference configuration |

Use segment exponent 20 for the host benchmarks below; larger segments can
require more memory. Reserve tens of GB of disk space for Cargo/CUDA builds.

Install native dependencies and Rust:

```sh
sudo apt-get update
sudo apt-get install -y build-essential clang cmake ninja-build meson \
  pkg-config libssl-dev python3 curl git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
```

Rust/Cargo 1.96, GCC/G++ 13, CMake 3.28, Meson 1.3, and OpenSSL 3 are the
reference versions. Native C++ sources require C++20.

For RISC0 proofs, install the RISC0 3.0.4 tools and guest compilers using
[the RISC0 installation instructions](https://dev.risczero.com/zkvm/quickstart):

```sh
curl -L https://risczero.com/install | bash
. "$HOME/.bashrc"
rzup install cargo-risczero 3.0.4
rzup install r0vm 3.0.4
rzup install rust 1.91.1
rzup install cpp 2024.1.5
rzup show
```

GPU commands additionally require a working CUDA toolkit (`nvcc`) and NVIDIA
driver (`nvidia-smi`); CUDA 12.6 is the reference toolkit. CPU host commands omit
`--features cuda`. The full-protocol CLI enables CUDA by default; set
`DAA_HOST_CUDA=0` for its CPU host runner. GPU benchmark scripts enable CUDA.

VOLEith/FAEST sources and the four modified RISC0-SHA256 crates are included in
`vendor/`. Cargo uses local paths for the modified backend. Its checksummed
recursion programs are included as three resource parts, each below GitHub's
file-size limit, and assembled by the build script. Keep all three parts.
Standard Rust dependencies, RISC0 toolchains and GPU kernels require network
access on the first build; this is not a fully offline dependency bundle.

## 2. Run and benchmark

Run commands from this directory. Keep build products outside the source tree:

```sh
export CARGO_TARGET_DIR="${HOME}/.cache/daa-full-target"
export RISC0_PROVER=local
export RISC0_DEV_MODE=0
```

### CPU correctness checks and protocol demo

```sh
cargo check --locked -p daa_cli
cargo test --locked -p daa_core --lib
cargo run --locked --release -p daa_cli -- run-full --proof-mode simulated
DAA_HOST_CUDA=0 RISC0_SKIP_BUILD=1 \
cargo run --locked --release -p daa_cli -- run-full \
  --params sha2-128s --tpm-backend sha2 --proof-mode real-tpm
```

`simulated` uses simulated proofs. `real-tpm` uses real TPM proofs and a
simulated host proof. Successful runs accept the signature, link equal
basenames, and reject linking different basenames.

### Full protocol with real RISC0 proofs (GPU)

```sh
RISC0_RECEIPT_KIND=succinct RISC0_IDENTITY_WRAP=0 \
cargo run --locked --release -p daa_cli -- run-full \
  --params sha2-128s --tpm-backend sha2 --tpm-sha-scheme ours \
  --credential-scheme fsphincs --backend sha-256 \
  --proof-mode real-128s --segment-po2 20
```

`real-128s` selects real proofs for every supported parameter label. Use
`--params sha2-128f`, `sha2-192s`, `sha2-192f`, `sha2-256s`, or `sha2-256f`
for another set. `--tpm-sha-scheme chen23` selects the 5F comparison relation.
For Direct SPHINCS+, use `--credential-scheme sphincs` together with
`SPHINCS_OPT_LEVEL=2 RISC0_IDENTITY_WRAP=1 RISC0_RECEIPT_KIND=succinct`.

### Standalone host proof on CPU or GPU

This command proves the SPHINCS+ ZK-WOTS+ relation on the CPU:

```sh
DAA_TPM_BACKEND=sha2 DAA_TPM_SHA_SCHEME=ours \
SPHINCS_PARAMS=sphincs-sha2-128s SPHINCS_OPT_LEVEL=4 \
RISC0_BACKEND_HASH=sha-256 RISC0_RECEIPT_KIND=composite \
RISC0_IDENTITY_WRAP=0 RISC0_SEGMENT_LIMIT_PO2=20 \
cargo run --locked --release -p daa_sha256_backend_host \
  --bin daa_sha256_backend_host
```

Add `--features cuda` to the Cargo command for GPU proving. Use
`--bin bench_fsphincs_risc0` and set `FSPHINCS_PARAMS=128s` for F-SPHINCS+.
Use `RISC0_RECEIPT_KIND=succinct` to measure recursive compression.

### Component benchmark suites

```sh
# SHA-2 Join (1F), Sign (3F and 5F), all six VOLEith profiles; CPU.
ITERATIONS=10 bash scripts/benchmark_tpm_sha_relations.sh

# AES Join and Sign, all six profiles; CPU.
ITERATIONS=10 bash scripts/benchmark_tpm_aes_vole.sh

# SPHINCS+ issuer extraction with VOLEith; native credential operations; CPU.
CREDENTIALS=sphincs ANCHOR_MODE=seed-anchor ITERATIONS=3 \
  bash scripts/benchmark_issuer_anchors.sh

# F-SPHINCS+ native keygen/sign/verify and VOLEith issuer extraction; CPU.
RUN_SETUP=1 ITERATIONS=3 bash scripts/benchmark_fsphincs_native_setup.sh

# SPHINCS+ fixed-top-WOTS issuer extraction with RISC0; GPU.
CREDENTIALS=sphincs ANCHOR_MODE=fixed-top-wots ITERATIONS=3 \
  bash scripts/benchmark_issuer_anchors.sh

# Direct SPHINCS+, ZK-WOTS+ and F-SPHINCS+ host proofs; 30 GPU cases.
SEGMENT_PO2=20 ITERATIONS=1 bash scripts/benchmark_host_sha2.sh

# F-SPHINCS+ host proofs only; GPU.
SEGMENT_PO2_LIST=20 ITERATIONS=1 bash scripts/benchmark_fsphincs_host.sh
```

Benchmark output includes proving/verifying times and serialized proof sizes.
Host runners also report guest cycles and segment counts. Compare the internal
proof timings; initial compilation and outer Cargo startup are separate costs.
Generated output goes to ignored `benchmarks/` and `results/` directories.

Native regression checks:

```sh
bash scripts/test_fsphincs.sh
bash scripts/test_issuer_seed_anchor.sh
bash scripts/test_issuer_wots.sh
meson setup /tmp/daa-tpm-sha-tests vendor/TPM_SHA --buildtype=release
meson test -C /tmp/daa-tpm-sha-tests --print-errorlogs
```

Third-party license and copyright notices are retained with their source files.
