# SwiftDAA

A proof-of-concept implementation of hash-based Direct Anonymous Attestation
(DAA), with issuer Setup, TPM Join, TPM/Host Signing, Verification, and basename
linking. **The TPM is simulated in software on the CPU; this demo does not run
on a physical TPM and is not a production implementation.** Demo inputs are
deterministic for reproducibility. Revocation supports empty lists only.

The implementation includes:

| Component | Constructions |
| --- | --- |
| Issuer credentials | SPHINCS+ and F-SPHINCS+, SHA-2 parameter sets 128s/f, 192s/f, 256s/f |
| Setup: seed-based proof on SPHINCS+ | VOLEith proof of two PRFs; a separate signature supplies the bottom FORS certificate |
| Setup: seed-based proof on F-SPHINCS+ | VOLEith proof of two PRFs; KeyGen captures the top M-FORS certificate and witness |
| Setup: fixed WOTS+ leaf | RISC0 proof of a complete WOTS+ leaf; KeyGen captures the top XMSS certificate and witness |
| TPM Join / Signing | VOLEith proofs of 1F / 3F using AES, Rijndael-256 Davies–Meyer, or SHA-256/384/512; SHA-2 also has a 5F comparison relation |
| Host Signing | Recursive ZK verification, ZK-WOTS+, and F-SPHINCS+, using the bundled RISC0-SHA256 backend |

AES and SHA-2 proofs support six security/profile combinations. Rijndael-256
uses a 256-bit block and key with 128s/f VOLEith proof parameters. All three TPM
primitives connect to the complete DAA protocol. The SHA-2 5F comparison uses
F-SPHINCS+ credentials. F-SPHINCS+ is the construction implemented in this demo.

## 1. Hardware and software

Use x86-64 Linux; the reference platform is Ubuntu 24.04. Native credential and
VOLEith benchmarks use the CPU. AES-NI, PCLMULQDQ, and AVX2 accelerate supported
paths. RISC0 has two execution options:

| RISC0 prover | Environment |
| --- | --- |
| CPU | Multicore CPU; 16 GB RAM minimum, 32 GB preferred; slower than GPU proving |
| GPU | NVIDIA CUDA-capable GPU, compatible driver and CUDA toolkit; reference configuration: 16 GB VRAM, 32 GB host RAM, CUDA 12.6 |

Use segment exponent 20 for the commands below. Larger segments require more
memory. Reserve tens of GB of disk space for compilation. WSL2 GPU proving
requires working CUDA passthrough.

Native dependencies and Rust:

```sh
sudo apt-get update
sudo apt-get install -y build-essential clang cmake ninja-build meson \
  pkg-config libssl-dev python3 curl git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
```

Reference versions: Rust/Cargo 1.96, GCC/G++ 13, CMake 3.28, Meson 1.3, OpenSSL 3.
The native C++ backend requires C++20. For RISC0 proofs, install the guest
compilers and matching tools:

```sh
curl -L https://risczero.com/install | bash
. "$HOME/.bashrc"
rzup install cargo-risczero 3.0.4
rzup install r0vm 3.0.4
rzup install rust 1.91.1
rzup install cpp 2024.1.5
rzup show
```

GPU proving additionally requires `nvcc` and a working `nvidia-smi`. The full
protocol runner enables CUDA by default; set `DAA_HOST_CUDA=0` for CPU proving.
Standalone Host commands enable GPU proving with Cargo's `--features cuda`.
Native TPM benchmarks do not need CUDA or the RISC0 guest toolchains.

The modified VOLEith/FAEST and RISC0-SHA256 sources are included in `vendor/` and
are required to reproduce the proofs. The four RISC0 crates form one backend;
Cargo patches select these local sources. Its checksummed recursion resource
is split into three parts and assembled during the build. Keep all parts.
Standard Cargo dependencies, toolchains, and prover kernels are downloaded on
the first build; the repository is not a fully offline dependency bundle.

## 2. Run and benchmark

Run commands from this directory:

```sh
export CARGO_TARGET_DIR="${HOME}/.cache/daa-full-target"
export RISC0_PROVER=local
export RISC0_DEV_MODE=0
```

Run the complete `Setup -> Join -> Signing -> Verification` protocol with real
TPM and Host proofs on the GPU:

```sh
RISC0_RECEIPT_KIND=succinct RISC0_IDENTITY_WRAP=0 \
cargo run --locked --release -p daa_cli -- run-full \
  --params sha2-128f --tpm-backend rijndael --host-scheme fsphincs \
  --proof-mode real --segment-po2 20
```

Choose `--tpm-backend aes|rijndael|sha2` and
`--host-scheme recursive-zk|zk-wots|fsphincs`. The Host choice selects the
matching credential family. `recursive-zk` uses succinct receipts with
`RISC0_IDENTITY_WRAP=1`; the other two constructions use identity wrapping 0
and support composite or succinct receipts. Set `--issuer-anchor-mode
fixed-top-wots` for the fixed WOTS+ Setup baseline with SPHINCS+ credentials;
the default is `seed-anchor`. Set `--tpm-sha-scheme chen23` for SHA-2 5F with
`--host-scheme fsphincs`.

`run-full` (also named `demo`) shares state across the protocol algorithms and
checks verification and basename linking. Component benchmarks are optional.
Replace `run-full` with `bench --iterations 3` to repeat the complete protocol.
KeyGen and ZK preparation, proving, and verification are reported separately.
F-SPHINCS+ and fixed WOTS+ certificate/witness generation is included in KeyGen;
SPHINCS+ seed-based certificate generation is reported separately.

CPU checks and lighter protocol modes:

```sh
cargo test --locked -p daa_core --lib
cargo run --locked --release -p daa_cli -- run-full --proof-mode simulated
DAA_HOST_CUDA=0 RISC0_SKIP_BUILD=1 \
cargo run --locked --release -p daa_cli -- run-full \
  --params sha2-128f --tpm-backend sha2 --proof-mode real-tpm
```

`simulated` simulates all proofs. `real-tpm` uses real Setup/TPM proofs and a
simulated Host proof; fixed WOTS+ Setup still needs RISC0 proving.

Component benchmarks (native suites use CPU; Host and fixed WOTS+ suites use GPU):

```sh
ITERATIONS=10 bash scripts/benchmark_tpm_aes_vole.sh
ITERATIONS=10 bash scripts/benchmark_tpm_rijndael_dm.sh
ITERATIONS=10 bash scripts/benchmark_tpm_sha_relations.sh
CREDENTIALS=sphincs ANCHOR_MODE=seed-anchor ITERATIONS=3 \
  bash scripts/benchmark_issuer_anchors.sh
RUN_SETUP=1 ITERATIONS=3 bash scripts/benchmark_fsphincs_native_setup.sh
CREDENTIALS=sphincs ANCHOR_MODE=fixed-top-wots ITERATIONS=3 \
  bash scripts/benchmark_issuer_anchors.sh
HOST_HOOK_MODE=sha2-3f SEGMENT_PO2=20 ITERATIONS=1 \
  bash scripts/benchmark_host_sha2.sh
```

`HOST_HOOK_MODE` also accepts `aes-3f`, `rijndael-3f`, or `sha2-5f` (F-SPHINCS+
Host only). The Host suite compares all three constructions and receipt forms.
Benchmark output includes prover/verifier time and serialized proof size;
Host proofs also report guest cycles and segment counts. Compilation and outer
Cargo startup are excluded from internal timings. Generated logs and results
are ignored by Git.

Native regression checks:

```sh
bash scripts/test_fsphincs.sh
bash scripts/test_issuer_seed_anchor.sh
bash scripts/test_issuer_wots.sh
bash scripts/test_host_verifiers.sh
meson setup /tmp/daa-tpm-sha-tests vendor/TPM_SHA --buildtype=release
meson test -C /tmp/daa-tpm-sha-tests --print-errorlogs
```

Third-party license and copyright notices are retained with their sources.
