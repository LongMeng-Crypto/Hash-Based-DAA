# SwiftDAA

A proof-of-concept implementation of hash-based Direct Anonymous Attestation
(DAA), with issuer Setup, TPM Join, TPM/Host Signing, Verification, and basename
linking. **The TPM is simulated in software on the CPU; this demo does not run
on a physical TPM and is not a production implementation.** Demo inputs are
deterministic for reproducibility; they are not production key generation.
Roles share local in-memory state. Endorsement-key attestation, authenticated
transport, and a full revocation protocol are outside this demo. Revocation
benchmarks use empty lists only.

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

The 128/192/256 labels select credential and TPM proof parameters. The RISC0
backend keeps its bundled `Legacy97` profile, with 50 FRI queries and inverse
rate 4; selecting a credential profile does not change those proof parameters
or establish matching end-to-end security bits.

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
is split into 23 parts of at most 6 MiB and assembled during the build. Keep all parts.
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
matching credential family. The full protocol runner automatically applies succinct receipts and identity
wrapping for `recursive-zk`; the other two constructions use identity wrapping
0 and support composite or succinct receipts. Standalone Host binaries use
`RISC0_RECEIPT_KIND` and `RISC0_IDENTITY_WRAP` explicitly. Set `--issuer-anchor-mode
fixed-top-wots` for the fixed WOTS+ Setup baseline with SPHINCS+ credentials;
the default is `seed-anchor`. Set `--tpm-sha-scheme chen23` for SHA-2 5F with
`--host-scheme fsphincs`.

`run-full` (also named `demo`) shares state across the protocol algorithms and
proves and verifies one complete signature. Its linking smoke check computes
additional same/different-basename tokens without generating extra proofs.
The public `link` operation compares tokens from signatures already verified
by its caller. Component benchmarks are optional.
Replace `run-full` with `bench --iterations 3` to repeat the complete protocol.
Join independently verifies the public issuer certificate and issuer proof,
rejects duplicate member IDs, and binds its proof to an issuer challenge.
Both TPM and Host proofs bind the randomized message digest; Host RISC0 journals
include this public context. Protocol hashes use domain-separated SHA-2, and
protocol proof randomness uses the OS random source. KeyGen and ZK preparation, proving, and verification are
reported separately; protocol trace timings retain microsecond resolution.
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
simulated Host proof and checks credentials with the native verifier.
Fixed WOTS+ Setup needs RISC0 proving and is unavailable in `simulated` mode.
Fallible Rust protocol operations, including `setup`, return `Result`.

The benchmark entrypoints are:

| Script in `scripts/` | Default coverage |
| --- | --- |
| `benchmark_credentials.sh` | Both native credential schemes, all six parameters; 12 cases |
| `benchmark_issuer_anchors.sh` | All three Setup methods; 12 native seed cases and 12 fixed-WOTS receipt cases |
| `benchmark_tpm_aes_vole.sh` | Six AES profiles, Join 1F and Signing 3F |
| `benchmark_tpm_rijndael_dm.sh` | Two Rijndael profiles, Join 1F and Signing 3F |
| `benchmark_tpm_sha_relations.sh` | Six SHA-2 profiles, Join 1F and Signing 3F/5F |
| `benchmark_host.sh` | All supported TPM hooks, three Host constructions and receipt forms; 82 cases |
| `benchmark_protocol.sh` | Complete protocols including fixed-WOTS Setup and SHA-2 5F; 124 cases |
| `run_all_benchmarks.sh` | The credential, Setup, TPM and Host suites |

The full protocol sweep is separate from the default paper component sweep.
The native TPM suites contain 34 proof relations in total. Counts above are
configurations before repetitions; they do not multiply CPU and GPU choices.
Recursive ZK verification uses succinct receipts with identity wrapping; the
other Host constructions and fixed-WOTS Setup cover composite and succinct
receipts. Unsupported combinations are excluded from the matrices.

Preview the matrices without compiling or proving:

```sh
DRY_RUN=1 bash scripts/run_all_benchmarks.sh
DRY_RUN=1 bash scripts/benchmark_protocol.sh
```

Run the paper component suites, or select an individual suite:

```sh
ITERATIONS=3 bash scripts/run_all_benchmarks.sh
ITERATIONS=3 bash scripts/benchmark_credentials.sh
SETUP_MODES="sphincs-seed fsphincs-seed" DAA_HOST_CUDA=0 \
  ITERATIONS=3 bash scripts/benchmark_issuer_anchors.sh
SETUP_MODES=fixed-wots ITERATIONS=3 bash scripts/benchmark_issuer_anchors.sh
ITERATIONS=10 bash scripts/benchmark_tpm_aes_vole.sh
ITERATIONS=10 bash scripts/benchmark_tpm_rijndael_dm.sh
ITERATIONS=10 bash scripts/benchmark_tpm_sha_relations.sh
```

Common selectors for the credential, Setup, Host, protocol and combined runners:

| Variable | Default / accepted values |
| --- | --- |
| `PARAMS_LIST` | `128s 128f 192s 192f 256s 256f`; `sha2-` prefixes also accepted |
| `CREDENTIALS` | `sphincs fsphincs`; native credential suite |
| `SETUP_MODES` | `sphincs-seed fsphincs-seed fixed-wots` |
| `HOOK_MODES` | `aes-3f rijndael-3f sha2-3f sha2-5f`; Host/protocol suites |
| `HOST_SCHEMES` | `recursive-zk zk-wots fsphincs` |
| `RECEIPTS` | `composite succinct` |
| `DAA_HOST_CUDA` | `1`; set `0` for CPU RISC0 proving |
| `SEGMENT_PO2` | `20` |
| `ITERATIONS` | `1` for combined runners; repetitions are honored by every suite |
| `SUITES` | `credentials setup tpm host`; combined runner only; `all` also includes the protocol sweep |
| `BENCH_OUTPUT_DIR` | A new directory under ignored `results/benchmarks/` |

For example, benchmark SHA-2 5F with the F-SPHINCS+ Host and its matching Setup:

```sh
PARAMS_LIST=128f HOOK_MODES=sha2-5f HOST_SCHEMES=fsphincs \
SETUP_MODES=fsphincs-seed RECEIPTS=succinct ITERATIONS=3 \
  bash scripts/benchmark_protocol.sh
```

The native AES/Rijndael scripts additionally accept `PARAMETERS` and `PHASES`;
filtering excludes unselected proof computations. The SHA-2 script accepts
`PARAMS_LIST`, `SECURITY`, `PROFILE`, and `SCHEME=all|ours|chen23`.
Native Meson build directories default to this checkout's ignored `target/`;
override them with `TPM_AES_BUILD_DIR`, `TPM_RDM_BUILD_DIR`, or `TPM_SHA_BUILD_DIR`.
Use separate build directories for separate checkouts.

Combined runners save a case manifest, raw logs and a machine-readable
`summary.tsv`; full protocol cases also save JSON traces. KeyGen and ZK timings
remain separate. Compilation and outer Cargo startup are excluded from the
reported internal timings. Native credential benchmarks time only KeyGen,
signing and verification on a 3-lambda-bit message fixture and print its byte
length. Full protocols use the selected primitive's actual token/nonce widths.
Negative tests and known-answer tests run through
the regression entrypoints below. Generated results are ignored by Git.

Native regression checks:

```sh
bash scripts/test_fsphincs.sh
bash scripts/test_issuer_seed_anchor.sh
bash scripts/test_issuer_wots.sh
bash scripts/test_host_verifiers.sh
python3 -m unittest discover -s host_proof/tests -p test_benchmark_matrix.py
meson setup /tmp/daa-tpm-aes-tests vendor/TPM_AES --buildtype=release
meson test -C /tmp/daa-tpm-aes-tests --print-errorlogs
meson setup /tmp/daa-tpm-sha-tests vendor/TPM_SHA --buildtype=release
meson test -C /tmp/daa-tpm-sha-tests --print-errorlogs
```

A real end-to-end negative regression checks modified issuer proofs,
certificates, credentials, messages, basenames, and malformed signatures.
It needs the RISC0 toolchains and a working CPU or GPU prover:

```sh
cargo test --locked --release -p daa_core --lib real_protocol_rejects_tampering -- --ignored --test-threads=1
```

Third-party license and copyright notices are retained with their sources.
