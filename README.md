# Hash-Based DAA Prototype

`DAA_FULL` is the complete single-machine implementation of the hash-based
Direct Anonymous Attestation (DAA) protocol. It connects issuer Setup, TPM
Join and signing, host-side credential proving, verification, linking, and
revocation through one shared protocol state. The repository contains both
the protocol implementation and the scripts used to generate the paper's
current benchmark tables.

## Protocol and Implementations

### Protocol flow

The implemented protocol has five main stages:

1. **Setup.** The issuer generates a credential keypair `(mpk, msk)`. The
   current implementation can additionally generate a deterministic public
   anchor certificate and the one-time extraction proof `pi_I`.
2. **Join.** The TPM derives `gid` and the private entry token `et`, proves the
   corresponding SHA-2 relation, and obtains an issuer credential on
   `et || issuer_nonce`.
3. **Sign.** The TPM produces the link token and TPM proof. The host proves
   knowledge of a valid issuer credential and the private values opening the
   TPM-to-host hook.
4. **Verify.** The verifier checks the revocation state, TPM proof, public hook
   values, and RISC0 host receipt.
5. **Link.** Two accepted signatures are linked exactly when their public
   `slt` values match for the same basename.

The SHA-2 TPM path uses SHA-256, SHA-384, and SHA-512 at the 128-, 192-, and
256-bit parameter levels. Each level supports a VOLEith `s` profile for a
smaller proof and an `f` profile for faster proving.

### Evaluated variants

Both variants are implemented in this repository. Variant-1 follows the
five-function TPM and F-SPHINCS+ structure of CDENW'23, but its SHA-2
instantiation, VOLEith proof, F-SPHINCS+-SHA256 implementation, and RISC0
host proof are all implementations from this project rather than results
reported by CDENW'23.

| Variant | TPM relation | Credential | TPM proof | Host relation | Host proof |
|---|---|---|---|---|---|
| Variant-1 | CDENW'23-style 5F instantiated with SHA-2 | F-SPHINCS+-SHA256 | VOLEith | Credential verification plus two SHA-2 hooks | RISC0 SHA-256 |
| Variant-2 | Ours-3F instantiated with SHA-2 | SPHINCS+-SHA2 | VOLEith | Direct SPHINCS+ or ZK-WOTS+ plus one SHA-2 hook | RISC0 SHA-256 |

Variant-2 evaluates the following relation:

```text
slt = SHA2(0x01 || sk || lid)
et  = SHA2(0x02 || sk || gid)
hk  = SHA2(0x03 || s  || et)
```

The Join proof publishes `(gid, et)` and proves knowledge of `sk`. The joint
TPM-signing proof publishes `(lid, gid, slt, hk)` and proves knowledge of
`(sk, s)` while carrying `et` directly between the second and third SHA
circuits.

Variant-1 evaluates:

```text
slt = SHA2(0x01 || sk  || lid)
sst = SHA2(0x04 || sk  || msg')
et  = SHA2(0x02 || sk  || gid)
hk  = SHA2(0x05 || sst)
cet = SHA2(0x06 || sst || et)
```

Its TPM proof publishes `(slt, hk, cet)` and keeps `(sk, sst, et)` private.
The RISC0 host guest receives the same public `hk` and `cet`, proves their two
openings using the same private `(sst, et)`, and verifies an F-SPHINCS+
credential on that `et`.

### Issuer extraction proof

The optional `pi_I` construction is a separate Setup-time building block
under the **global issuer-seed consistency assumption**. It is not repeated
during Join or signing.

- For SPHINCS+, a deterministic certificate fixes one top-layer WOTS+ leaf
  and exposes two independently addressed chain starts. Public WOTS/XMSS
  verification connects them to `PK.root`; `pi_I` proves two secret-dependent
  SHA-256 compression blocks from the same `SK.seed`.
- For F-SPHINCS+, the certificate uses the distinct M-FORS nodes
  `(layer=1,node=0)` and `(layer=0,node=0)`. It retains only the selected
  secrets and authentication paths plus the remaining public roots; `pi_I`
  proves eight SHA-256 compression blocks from the same master seed.

The two anchors strengthen the binding of the extracted witness. The global
seed-consistency assumption separately states that the registered root and
all issuer credentials use the prescribed derivation from that same seed.

### Host proof modes

The host implementation supports:

| Construction | SPHINCS optimization | Receipts | Identity wrapper |
|---|---:|---|---|
| Direct SPHINCS+ | opt2 | Succinct | Required by the evaluated ZK configuration |
| ZK-WOTS+ | opt4 | Composite or Succinct | Not used |
| F-SPHINCS+ | constant-structure verifier | Composite or Succinct | Not used |

The SHA-256 RISC0 backend is pinned in `Cargo.toml` to one revision of the
standalone `RISC0-SHA256` repository. Composite, lift, join, Succinct, and
Identity artifacts must come from that same revision because receipts bind to
its recursion control IDs. The stock Poseidon2 path and the historical
AES/FAEST TPM path remain available for compatibility, but they are not the
source of the current tables below.

## Repository Layout

```text
Cargo.toml                         workspace and pinned RISC0 backend patches
Cargo.lock                         reproducible Rust dependency graph
crates/daa_core/                   protocol state machine, FFI, and metrics
crates/daa_cli/                    full-protocol and component benchmark CLI
host_proof/host/                   native RISC0 host runner
host_proof/methods/guest/          guest and SPHINCS+/F-SPHINCS+ C sources
vendor/TPM_AES/                    preserved AES/FAEST TPM implementation
vendor/TPM_SHA/                    SHA-2 circuits and VOLEith proof backend
scripts/                           reproducible benchmark entry points
benchmarks/                        consolidated current benchmark logs
results/                           generated JSON and per-case logs
```

`vendor/TPM_AES/builddir_rel/` contains only the generated FAEST C/header
sources needed by `daa_core/build.rs`. Cargo, Meson, Ninja, CUDA, and RISC0
build products belong in persistent external caches and must not be committed.

## Environment and Reproducible Commands

### Tested environment

The latest measurements were produced on Linux/x86-64 with:

- Rust stable; the current development machine reports Rust/Cargo 1.96.0.
- GCC/G++ 13.3 with AVX2 and PCLMUL support.
- Meson 1.3.2 and Ninja 1.11.1.
- OpenSSL 3.0.13 development libraries.
- NVIDIA CUDA 12.6 for RISC0 GPU proving.
- The RISC0 v3.0.4 SHA-256 fork pinned by the workspace lockfile.

A CPU-only simulated protocol run does not require CUDA. Real host proof
benchmarks require an NVIDIA GPU, a working CUDA toolkit, and the local RISC0
prover. A fresh checkout must also be able to fetch the pinned
`LongMeng-Crypto/RISC0-SHA256` Git revision.

### Persistent shared caches

Use the same cache directories for all parameter sets and future sessions:

```sh
cd ~/SEDAA/DAA_FULL

export CARGO_TARGET_DIR="${HOME}/.cache/sedaa-risc0-shared-target"
export TPM_SHA_BUILD_DIR="${HOME}/.cache/sedaa-tpm-sha-relations"
export RISC0_PROVER=local
```

These locations survive terminal closure and reboot. Do not put either cache
inside the Git repository. The first CUDA build is still expensive, but later
runs reuse the common RISC0, recursion, CUDA, and Cargo artifacts. Each
SPHINCS+ parameter set needs its own first guest build.

If a local backend checkout exists at `~/RISC0-SHA256`, the host benchmark
script automatically reuses its matching `recursion_zkr.zip` through
`RECURSION_SRC_PATH`.

### Quick correctness checks

```sh
cargo check -p daa_cli
cargo test -p daa_core --lib
cargo run -p daa_cli -- run-full --proof-mode simulated
```

A successful simulated run reports `verify accepted: true`, links two
signatures with the same basename, and does not link different basenames.

### Complete connected protocol

Run Variant-2 with the direct SPHINCS+ Succinct/Identity host proof:

```sh
RISC0_RECEIPT_KIND=succinct \
RISC0_IDENTITY_WRAP=1 \
SPHINCS_OPT_LEVEL=2 \
cargo run --release -p daa_cli -- run-full \
  --params sha2-128s \
  --tpm-backend sha2 \
  --tpm-sha-scheme ours \
  --credential-scheme sphincs \
  --backend sha-256 \
  --proof-mode real-128s \
  --segment-po2 20
```

Run Variant-1 with the F-SPHINCS+ Succinct host proof:

```sh
RISC0_RECEIPT_KIND=succinct \
RISC0_IDENTITY_WRAP=0 \
cargo run --release -p daa_cli -- run-full \
  --params sha2-128s \
  --tpm-backend sha2 \
  --tpm-sha-scheme chen23 \
  --credential-scheme fsphincs \
  --backend sha-256 \
  --proof-mode real-128s \
  --segment-po2 20
```

The historical CLI name `real-128s` selects real TPM and RISC0 proofs for all
six `128/192/256-s/f` parameter labels. Use `real-tpm` to run real VOLEith
proofs with a simulated host proof, or `simulated` for protocol plumbing only.

### TPM SHA-2 benchmarks

Benchmark the normalized Variant-1 5F relation and Variant-2 3F relation for
all SHA-2 security levels and both VOLEith profiles:

```sh
ITERATIONS=10 scripts/benchmark_tpm_sha_relations.sh \
  | tee benchmarks/tpm_sha_ours3h_vs_chen23_5h.log
```

Benchmark only the connected Variant-2 Join and TPM-signing path through the
Rust CLI:

```sh
ITERATIONS=10 scripts/benchmark_tpm_sha.sh
```

The preparation cost is reported separately and is not included in the warm
per-proof averages.

### Issuer Setup anchor benchmark

Run both credential schemes, all security levels, and both VOLEith profiles:

```sh
ITERATIONS=1 scripts/benchmark_issuer_anchors.sh
```

The script overwrites the consolidated current log:

```text
benchmarks/issuer_anchor/issuer_anchor_latest.log
```

It checks the public certificate, real `pi_I`, and mutation rejection before
reporting anchor generation, proof preparation/proving/verification, proof
size, certificate size, and circuit statistics.

### Complete host-proof benchmark

Run the 30 current SHA-2 host cases at segment size `2^20`:

```sh
SEGMENT_PO2=20 ITERATIONS=1 scripts/benchmark_host_sha2.sh
```

This covers:

- six Direct SPHINCS+ Succinct/Identity cases;
- six ZK-WOTS+ Composite and six ZK-WOTS+ Succinct cases; and
- three F-SPHINCS+ security levels in Composite/Succinct mode for both the
  one-hook and two-hook SHA-2 relations.

Use `SEGMENT_PO2=22` or another supported exponent for segmentation studies.
Every invocation writes a timestamped combined log, a machine-readable TSV,
and per-case logs under:

```text
benchmarks/host_sha2/
results/host_sha2/<timestamp>/
```

Paper timings use the emitted `prover_us` and `verifier_us`, not the outer
Cargo wall-clock time, because the latter can include compilation and process
startup.

### Native F-SPHINCS+ checks

Run native key generation, signing, verification, profiling, and deterministic
KATs without RISC0:

```sh
make -C host_proof/methods/guest/c_src/fsphincs_ref \
  benchmark FSPHINCS_SECURITY=128

make -C host_proof/methods/guest/c_src/fsphincs_ref \
  benchmark FSPHINCS_SECURITY=192

make -C host_proof/methods/guest/c_src/fsphincs_ref \
  benchmark FSPHINCS_SECURITY=256

make -C host_proof/methods/guest/c_src/fsphincs_ref test \
  FSPHINCS_SECURITY=128
```

The Makefile removes generated benchmark and KAT binaries after each run. The
current credential-security parameters are `k=22,33,43`; historical `k=35,70`
remain available through an explicit `FSPHINCS_K` override.

### Compatibility sweeps

`scripts/run_all_benchmarks.sh` retains the older monolithic 12-case full-DAA
sweep and accepts `--backend sha-256` or `--backend poseidon2`. The current
paper tables should instead be regenerated with the dedicated TPM, anchor,
and host scripts above because those scripts select the connected SHA-2 hook
relations explicitly.

## Current Benchmark Results

The tables below are the canonical README copy of the measurements used by the
companion paper. Times are seconds. Sizes marked KB use `bytes / 1024`.
Sub-millisecond host verification is retained rather than rounded to zero.
Host measurements use SHA-256 RISC0 receipts with segment size `2^20`.

### Credential setup

| Variant | Credential | Parameter | Keygen (s) | PK (B) | SK (B) |
|---|---|---|---:|---:|---:|
| Variant-1 | F-SPHINCS+ | 128 | 1.32 | 76 | 108 |
| Variant-1 | F-SPHINCS+ | 192 | 2.03 | 98 | 130 |
| Variant-1 | F-SPHINCS+ | 256 | 2.67 | 118 | 150 |
| Variant-2 | SPHINCS+ | 128s | 0.050 | 32 | 64 |
| Variant-2 | SPHINCS+ | 128f | 0.001 | 32 | 64 |
| Variant-2 | SPHINCS+ | 192s | 0.062 | 48 | 96 |
| Variant-2 | SPHINCS+ | 192f | 0.001 | 48 | 96 |
| Variant-2 | SPHINCS+ | 256s | 0.038 | 64 | 128 |
| Variant-2 | SPHINCS+ | 256f | 0.002 | 64 | 128 |

### Setup-time issuer extraction proof

This is a separately replaceable Setup building block; credential key
generation is excluded from `Anchor gen.`.

| Variant | Credential | Credential parameter | VOLEith | SHA-256 comp. | Anchor gen. (s) | Cert. verify (s) | `pi_I` prepare (s) | `pi_I` prove (s) | `pi_I` verify (s) | `pi_I` proof (KB) | Public cert. (KB) |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Variant-1 | F-SPHINCS+ | 128 | 128s | 8 | 2.52 | 0.00004 | 0.110 | 0.072 | 0.064 | 217.68 | 2.39 |
| Variant-1 | F-SPHINCS+ | 128 | 128f | 8 | 2.62 | 0.00004 | 0.111 | 0.030 | 0.021 | 316.01 | 2.39 |
| Variant-1 | F-SPHINCS+ | 192 | 192s | 8 | 3.93 | 0.00007 | 0.111 | 0.130 | 0.125 | 318.85 | 3.08 |
| Variant-1 | F-SPHINCS+ | 192 | 192f | 8 | 3.80 | 0.00010 | 0.106 | 0.041 | 0.034 | 476.37 | 3.08 |
| Variant-1 | F-SPHINCS+ | 256 | 256s | 8 | 5.09 | 0.00008 | 0.110 | 0.207 | 0.192 | 441.87 | 3.70 |
| Variant-1 | F-SPHINCS+ | 256 | 256f | 8 | 5.08 | 0.00007 | 0.112 | 0.061 | 0.052 | 639.25 | 3.70 |
| Variant-2 | SPHINCS+ | 128s | 128s | 2 | 0.042 | 0.00007 | 0.030 | 0.029 | 0.024 | 61.70 | 0.70 |
| Variant-2 | SPHINCS+ | 128f | 128f | 2 | 0.001 | 0.00007 | 0.031 | 0.010 | 0.007 | 89.12 | 0.61 |
| Variant-2 | SPHINCS+ | 192s | 192s | 2 | 0.058 | 0.00010 | 0.031 | 0.045 | 0.039 | 93.05 | 1.42 |
| Variant-2 | SPHINCS+ | 192f | 192f | 2 | 0.001 | 0.00010 | 0.031 | 0.014 | 0.010 | 137.68 | 1.28 |
| Variant-2 | SPHINCS+ | 256s | 256s | 2 | 0.039 | 0.00014 | 0.033 | 0.078 | 0.071 | 132.93 | 2.36 |
| Variant-2 | SPHINCS+ | 256f | 256f | 2 | 0.002 | 0.00014 | 0.031 | 0.020 | 0.016 | 189.87 | 2.23 |

### Join protocol

The one-SHA-2 Join proof is shared by both variants. A complete Join combines
one row below with the matching credential-issuance row.

| VOLEith | Hash | Prove (s) | Verify (s) | Proof (KB) |
|---|---|---:|---:|---:|
| 128s | SHA-256 | 0.018 | 0.015 | 32.42 |
| 128f | SHA-256 | 0.004 | 0.003 | 46.54 |
| 192s | SHA-384 | 0.056 | 0.044 | 115.71 |
| 192f | SHA-384 | 0.012 | 0.010 | 171.66 |
| 256s | SHA-512 | 0.079 | 0.078 | 165.07 |
| 256f | SHA-512 | 0.019 | 0.016 | 236.62 |

| Variant | Credential | Parameter | Credential sign (s) | Credential verify (s) | Credential (KB) |
|---|---|---|---:|---:|---:|
| Variant-1 | F-SPHINCS+ | 128 | 9.11 | 0.001 | 81.84 |
| Variant-1 | F-SPHINCS+ | 192 | 13.69 | 0.002 | 122.75 |
| Variant-1 | F-SPHINCS+ | 256 | 17.75 | 0.002 | 159.94 |
| Variant-2 | SPHINCS+ | 128s | 0.286 | 0.001 | 7.69 |
| Variant-2 | SPHINCS+ | 128f | 0.014 | 0.001 | 16.70 |
| Variant-2 | SPHINCS+ | 192s | 0.516 | 0.001 | 15.88 |
| Variant-2 | SPHINCS+ | 192f | 0.022 | 0.001 | 34.86 |
| Variant-2 | SPHINCS+ | 256s | 0.455 | 0.001 | 29.12 |
| Variant-2 | SPHINCS+ | 256f | 0.046 | 0.002 | 48.72 |

### TPM signing proof

| VOLEith | Variant-1 prove (s) | Variant-1 verify (s) | Variant-1 proof (KB) | Variant-2 prove (s) | Variant-2 verify (s) | Variant-2 proof (KB) | Prove reduction | Proof reduction |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 128s | 0.064 | 0.053 | 178.63 | 0.033 | 0.030 | 91.73 | 48.1% | 48.6% |
| 128f | 0.021 | 0.016 | 259.20 | 0.010 | 0.008 | 132.81 | 52.1% | 48.8% |
| 192s | 0.247 | 0.223 | 552.82 | 0.134 | 0.119 | 334.46 | 45.9% | 39.5% |
| 192f | 0.073 | 0.062 | 827.32 | 0.036 | 0.030 | 499.79 | 51.0% | 39.6% |
| 256s | 0.449 | 0.432 | 920.80 | 0.206 | 0.192 | 470.75 | 54.1% | 48.9% |
| 256f | 0.120 | 0.105 | 1335.87 | 0.059 | 0.045 | 681.25 | 50.9% | 49.0% |

### Host proof at segment size `2^20`

Direct SPHINCS+ uses Succinct plus Identity. ZK-WOTS+ and F-SPHINCS+ do not
use the extra Identity wrapper.

| Variant | Host construction | Credential | Composite prove (s) | Composite verify (s) | Composite proof (KB) | Succinct prove (s) | Succinct verify (s) | Succinct proof (KB) |
|---|---|---|---:|---:|---:|---:|---:|---:|
| Variant-1 | F-SPHINCS+ | 128 | 10.952 | 0.004 | 825.37 | 27.812 | 0.00079 | 268.04 |
| Variant-1 | F-SPHINCS+ | 192 | 17.915 | 0.006 | 1375.22 | 48.320 | 0.00080 | 268.46 |
| Variant-1 | F-SPHINCS+ | 256 | 21.449 | 0.007 | 1650.34 | 58.626 | 0.00079 | 268.86 |
| Variant-2 | Direct SPHINCS+ | 128s | N/A | N/A | N/A | 9.712 | 0.00077 | 267.44 |
| Variant-2 | Direct SPHINCS+ | 128f | N/A | N/A | N/A | 18.619 | 0.00077 | 267.44 |
| Variant-2 | Direct SPHINCS+ | 192s | N/A | N/A | N/A | 71.022 | 0.00082 | 267.69 |
| Variant-2 | Direct SPHINCS+ | 192f | N/A | N/A | N/A | 112.685 | 0.00078 | 267.69 |
| Variant-2 | Direct SPHINCS+ | 256s | N/A | N/A | N/A | 101.234 | 0.00078 | 267.94 |
| Variant-2 | Direct SPHINCS+ | 256f | N/A | N/A | N/A | 141.167 | 0.00081 | 267.94 |
| Variant-2 | ZK-WOTS+ | 128s | 4.545 | 0.002 | 513.75 | 14.626 | 0.00079 | 267.44 |
| Variant-2 | ZK-WOTS+ | 128f | 11.416 | 0.005 | 1063.18 | 35.234 | 0.00080 | 267.44 |
| Variant-2 | ZK-WOTS+ | 192s | 28.106 | 0.010 | 2198.60 | 78.629 | 0.00080 | 267.69 |
| Variant-2 | ZK-WOTS+ | 192f | 49.584 | 0.018 | 4062.79 | 147.892 | 0.00078 | 267.69 |
| Variant-2 | ZK-WOTS+ | 256s | 40.508 | 0.015 | 3284.77 | 118.326 | 0.00084 | 267.94 |
| Variant-2 | ZK-WOTS+ | 256f | 61.119 | 0.022 | 4933.06 | 180.533 | 0.00079 | 267.94 |

### Benchmark artifacts

The current tables were transcribed from the following local benchmark
artifacts. Timestamped host logs may be kept outside Git even though their
canonical values are preserved in the tables above.

```text
benchmarks/tpm_sha_ours3h_vs_chen23_5h.log
benchmarks/issuer_anchor/issuer_anchor_latest.log
benchmarks/host_sha2/host_sha2_all_20260904-012627.log
benchmarks/host_sha2/host_sha2_all_20260904-012627.tsv
```

For reproducibility, record the DAA commit, pinned RISC0 backend commit, GPU,
CUDA version, segment exponent, receipt type, Identity setting, and iteration
count alongside every new result. Do not average outer build time into prover
time.
