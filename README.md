> VOLEith SHA-based Join/Sign/setup proofs use the [corrected v4 constraint encoding](docs/voleith_soundness_v1.md). Rebuild and regenerate old proofs; previous wire versions are rejected.

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
2. **Join.** The TPM derives `gid` and the entry token `et` (revealed to the issuer), proves the
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

### Current constructions

The current host evaluation uses **Ours-3F plus one SHA-2 hook** with either
standard SPHINCS+ or F-SPHINCS+ as its credential. The separately implemented
CDENW'23-style 5F TPM relation is a comparison baseline, not a requirement
of F-SPHINCS+. Its SHA-2 and VOLEith measurements are our reimplementation,
not measurements reported in CDENW'23.

| TPM construction | Credential / host verifier | TPM proof | Host hook | Host proof |
|---|---|---|---|---|
| Ours-3F | Standard SPHINCS+: Direct (opt2) or ZK-WOTS+ (opt4) | VOLEith SHA-2, s/f | One SHA-2 | RISC0 SHA-256 |
| Ours-3F | F-SPHINCS+, six parameter sets | VOLEith SHA-2, s/f | One SHA-2 | RISC0 SHA-256 |
| CDENW'23--Ours-5F | Comparison/compatibility path | VOLEith SHA-2, s/f | Two SHA-2 evaluations | Supported, not used in the new v3 host tables |

Ours-3F evaluates:

```text
slt = SHA2(0x01 || sk || lid)
et  = SHA2(0x02 || sk || gid)
hk  = SHA2(0x03 || s  || et)
```

The Join proof publishes `(gid, et)` and proves knowledge of `sk`. The joint
TPM-signing proof publishes `(lid, gid, slt, hk)` and proves knowledge of
`(sk, s)`: both first hashes share the same `sk`, and the second hash's
`et` output is wired into the third hash as a private intermediate value.
The host proves credential verification on that same `et || issuer_nonce`
and the opening `hk = SHA2(0x03 || s || et)`. These are connected protocol
values, not independent benchmark inputs.

The 5F comparison evaluates:

```text
slt = SHA2(0x01 || sk  || lid)
sst = SHA2(0x04 || sk  || msg')
et  = SHA2(0x02 || sk  || gid)
hk  = SHA2(0x05 || sst)
cet = SHA2(0x06 || sst || et)
```

Its joint TPM proof exposes `(slt, hk, cet)`, with the corresponding public
identifiers and message context, while `(sk, sst, et)` remain private.
The compatible host relation verifies both `hk` and `cet` using the same
`(sst, et)`, together with the credential. The legacy AES/FAEST path is
preserved but is not used for the current SHA-2 tables.

### F-SPHINCS+ parameter sets and format

[parameter_sets.h](host_proof/methods/guest/c_src/fsphincs_ref/parameter_sets.h)
is the shared C/Rust source of truth. All six sets keep 32-byte master/node
seeds, `q=1024`, and `h=6` (seven M-FORS signature layers).
Leaf PRF v7 outputs are 16/24/32 bytes at 128/192/256, respectively; all six
Setup relations prove two distinct-address outputs under one shared node seed.
H1/tree nodes are 16/24/32 bytes for the 128/192/256 families. H1 version 6
uses a lossless 16-byte address and reuses the full SHA-256 state after
absorbing the 64-byte padded public-seed prefix.

| Parameter | Inner-tree height `d` | Tree count `k` | H3 |
|---|---:|---:|---|
| 128s | 16 | 22 | SHA-256 |
| 128f | 12 | 61 | SHA-256 |
| 192s | 16 | 33 | SHA-256 |
| 192f | 12 | 92 | SHA-256 |
| 256s | 16 | 43 | SHA-512 |
| 256f | 12 | 120 | SHA-512 |

Select `FSPHINCS_PARAMS=128s|128f|192s|192f|256s|256f`; independent
`FSPHINCS_SECURITY`/`FSPHINCS_K` selectors and legacy `k=35/70` are rejected.
Each credential is paired with the same VOLEith security/profile label.

H1, H2, and seed derivation use SHA-256. The 256-labelled sets use SHA-512
for H3 and retain its complete 64-byte intermediate digest; every H3
expansion binds `R` and the full public key. M-FORS indices consume exactly
`d` bits, and the 60-bit node index starts immediately after the `k*d`
digest bits, without byte-rounding. Generate fresh keys, credentials and
certificates and rebuild the matching guest for v7. Raw credentials are not
self-describing: especially at 256 bits, equal lengths do not identify the
derivation version. Certificates carry version 7; applications must also pin
the intended credential/key version rather than use signature length as a tag.

These are experimental target-security labels, not standardized SPHINCS+
parameter sets or a complete unforgeability theorem. A TPM/credential label
does not raise the pinned RISC0 backend's knowledge-soundness level.
See [DESIGN.md](host_proof/methods/guest/c_src/fsphincs_ref/DESIGN.md) for
the byte format, H3 construction, and KAT checks.

### Issuer extraction proof

The optional `pi_I` is generated once at Setup as a replaceable building
block. Select `--issuer-anchor-mode seed-anchor` for the VOLEith implementation
with SPHINCS+ or F-SPHINCS+, or `--issuer-anchor-mode fixed-top-wots` for the
alternative RISC0 implementation with standard SPHINCS+. The construction
and security arguments are described in the paper.

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

### Experimental environment

The following environment was inspected on the benchmark machine on
2026-10-30. RAM and CPU counts are those visible inside WSL2. Older logs do
not contain a complete environment snapshot, so this inventory does not
assert identical toolchain versions for every historical measurement.

| Component | Configuration |
| --- | --- |
| CPU | Intel Core i9-14900; 32 logical CPUs visible to WSL2; AES-NI, PCLMULQDQ and AVX2 available |
| Memory | 31.19 GiB RAM and 8 GiB swap visible to WSL2 |
| GPU | NVIDIA RTX 2000 Ada Generation; 16,380 MiB VRAM |
| OS | Ubuntu 24.04.3 LTS, x86-64, under WSL2 |
| Kernel | Linux 6.6.87.2-microsoft-standard-WSL2 |
| NVIDIA driver / CUDA toolkit | 596.71 / CUDA 12.6, nvcc 12.6.85 |
| Host Rust / Cargo | 1.96.0 / 1.96.0 |
| RISC0 toolchain | cargo-risczero 3.0.4; guest Rust 1.91.1-dev; C/C++ toolchain 2024.1.5 |
| Host C/C++ compiler | GCC/G++ 13.3.0 |
| Build tools / crypto library | CMake 3.28.3; Meson 1.3.2; Ninja 1.11.1; OpenSSL 3.0.13 |
| RISC0 backend | v3.0.4 SHA-256 fork, pinned to `0079fe1882b123ff7239e0356ce5d8fb47f63795` in `Cargo.toml` and `Cargo.lock` |

Native F-SPHINCS+ uses `-O3`; host benchmarks use Cargo release builds
with LTO and the local CUDA prover. The latest F-SPHINCS+ native and Setup
results average ten iterations; host results use one run per parameter
and receipt mode, `segment_po2=20`, a one-function SHA-2 hook, and no
Identity wrapper. Compilation is excluded from the reported proof timings.
Setup circuit preparation is reported separately and averages the first
construction together with subsequent cache reuse. Persistent build-cache
locations and the benchmark commands are listed below.

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

Run Ours-3F with the direct SPHINCS+ Succinct/Identity host proof:

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

Run the current Ours-3F F-SPHINCS+ alternative with one SHA-2 hook:

```sh
RISC0_RECEIPT_KIND=succinct \
RISC0_IDENTITY_WRAP=0 \
cargo run --release -p daa_cli -- run-full \
  --params sha2-128s \
  --tpm-backend sha2 \
  --tpm-sha-scheme ours \
  --credential-scheme fsphincs \
  --backend sha-256 \
  --proof-mode real-128s \
  --segment-po2 20
```

Use `--params sha2-128f`, `sha2-192s`, etc. to select another paired set.
The old two-hook comparison is still selected with `--tpm-sha-scheme chen23`;
it is not the configuration measured in the new F-SPHINCS+ tables.

The historical CLI name `real-128s` selects real TPM and RISC0 proofs for all
six `128/192/256-s/f` parameter labels. Use `real-tpm` to run real VOLEith
proofs with a simulated host proof, or `simulated` for protocol plumbing only.

### TPM SHA-2 benchmarks

Benchmark the normalized CDENW'23--Ours-5F and Ours-3F relations for
all SHA-2 security levels and both VOLEith profiles:

```sh
ITERATIONS=10 scripts/benchmark_tpm_sha_relations.sh \
  | tee benchmarks/tpm_sha_ours3h_vs_chen23_5h.log
```

Benchmark only the connected Ours-3F Join and TPM-signing path through the
Rust CLI:

```sh
ITERATIONS=10 scripts/benchmark_tpm_sha.sh
```

The preparation cost is reported separately and is not included in the warm
per-proof averages.

### Optimized AES Join and TPM-signing proofs

The vendored `TPM_AES` backend supports the six `128/192/256-s/f` profiles
for both the one-AES Join relation and the linked three-function TPM signing
relation.  Run the complete matrix with the persistent Meson cache:

```sh
ITERATIONS=20 scripts/benchmark_tpm_aes_vole.sh
```

Select either phase or a subset of profiles without rebuilding:

```sh
PHASES=join PARAMETERS="128s 128f" ITERATIONS=100 \
  scripts/benchmark_tpm_aes_vole.sh

PHASES=sign PARAMETERS="192s 192f 256s 256f" ITERATIONS=20 \
  scripts/benchmark_tpm_aes_vole.sh
```

`TPM_AES_BUILD_DIR` defaults to `~/.cache/sedaa-tpm-aes-vole`; it is not
deleted by the script. Timestamped logs are written under
`benchmarks/tpm_aes_vole/`. The Host proof remains independently selectable:
`DAA_TPM_BACKEND=aes` uses the one-AES hook, while
`DAA_TPM_BACKEND=sha2 DAA_TPM_SHA_SCHEME=ours` and `chen23` select the
one- and two-SHA-2 hook relations respectively.

### Issuer Setup anchor benchmark

Run all six SPHINCS+ parameters with either Setup proof mode:

```sh
ANCHOR_MODE=seed-anchor CREDENTIALS=sphincs ITERATIONS=3 \
  bash scripts/benchmark_issuer_anchors.sh

ANCHOR_MODE=fixed-top-wots CREDENTIALS=sphincs ITERATIONS=3 \
  bash scripts/benchmark_issuer_anchors.sh
```

Use `CREDENTIALS=fsphincs ANCHOR_MODE=seed-anchor` for the six matching
F-SPHINCS+ profiles, or use the combined native/Setup script below.
Fixed-WOTS defaults to SHA-256 Composite with segment exponent 20;
`RISC0_RECEIPT_KIND=succinct` selects Succinct without Identity.
`PARAMS_LIST` filters parameter sets and `SEGMENT_PO2` changes the segment limit.

Logs are written to `benchmarks/issuer_anchor/`; `LOG_FILE` selects an
explicit output file. All runs reuse the persistent shared cache.
Preparation is reported separately; proving times exclude compilation and startup.

Correctness checks:

```sh
bash scripts/test_issuer_seed_anchor.sh
bash scripts/test_issuer_wots.sh
```

The scripts clean up temporary test binaries, not shared compilation data.

### Complete host-proof benchmark

Run the 30 current SHA-2 host cases at segment size `2^20`:

```sh
SEGMENT_PO2=20 ITERATIONS=1 scripts/benchmark_host_sha2.sh
```

Select the compiled TPM-to-Host hook without changing the credential or RISC0
verification relation:

```sh
HOST_HOOK_MODE=aes-3f  SEGMENT_PO2=20 ITERATIONS=1 scripts/benchmark_host_sha2.sh
HOST_HOOK_MODE=sha2-3f SEGMENT_PO2=20 ITERATIONS=1 scripts/benchmark_host_sha2.sh
HOST_HOOK_MODE=sha2-5f SEGMENT_PO2=20 ITERATIONS=1 scripts/benchmark_host_sha2.sh
```

This covers:

- six Direct SPHINCS+ Succinct/Identity cases;
- six ZK-WOTS+ Composite and six ZK-WOTS+ Succinct cases; and
- six F-SPHINCS+ Composite and six F-SPHINCS+ Succinct cases,
  all using Ours-3F and one SHA-2 hook.

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

### F-SPHINCS+ leaf-PRF-v7 checks and benchmarks

The new F-SPHINCS+ credential is an alternative under **Ours-3F plus one SHA-2
hook**. Select one of `128s,128f,192s,192f,256s,256f`, paired with the same
VOLEith parameter. Old independent k/security selectors and k=35/70 are removed.
H1 version 6 uses 16/24/32-byte nodes, lossless 16-byte addresses, and a
cached, block-padded public-seed prefix. Leaf PRF v7 now uses 16/24/32-byte
outputs and two same-seed anchors at all levels. Master/node seeds remain
32 bytes; H2/H3 are unchanged. Regenerate keys,
credentials, certificates and guest images for all six sets.

```sh
# Changed native credentials and deterministic KATs; RUN_SETUP=1 also measures pi_I:
RUN_SETUP=1 FSPHINCS_PARAMS_LIST="128s 128f 192s 192f 256s 256f" ITERATIONS=3 \
  bash scripts/benchmark_fsphincs_native_setup.sh

# Changed credentials x Composite/Succinct x the requested segment sizes:
FSPHINCS_EXECUTE_ONLY=0 FSPHINCS_PARAMS_LIST="128s 128f 192s 192f 256s 256f" \
  SEGMENT_PO2_LIST="22 21 20" RECEIPT_LIST="composite succinct" \
  bash scripts/benchmark_fsphincs_host.sh

# One native test, with automatic binary cleanup:
make -C host_proof/methods/guest/c_src/fsphincs_ref test FSPHINCS_PARAMS=128f
```

New logs go to `benchmarks/fsphincs_leaf_prf_v7/`; historical logs are preserved.
Both scripts reuse `~/.cache/sedaa-risc0-shared-target`. Omit the parameter list
to run all six sets. Native targets automatically remove their test binaries.
See [DESIGN.md](host_proof/methods/guest/c_src/fsphincs_ref/DESIGN.md) for the
new layout, exact compression counts, compatibility and security assumptions.

### Compatibility sweeps

`scripts/run_all_benchmarks.sh` retains the older monolithic 12-case full-DAA
sweep and accepts `--backend sha-256` or `--backend poseidon2`. The current
paper tables should instead be regenerated with the dedicated TPM, anchor,
and host scripts above because those scripts select the connected SHA-2 hook
relations explicitly.

## Engineering Optimization Inventory

This inventory records the implementations inspected on 2026-10-30. It
distinguishes equivalent execution optimizations from circuit encodings and
cryptographic parameter choices. A faster benchmark or a passing KAT does
not establish a security bound. Existing upstream techniques are identified
as reused techniques, not claimed as new cryptographic contributions.

### RISC0 SHA-256 backend and recursion

- **SHA-native recursion on RISC Zero 3.0.4:** The standalone backend provides
  SHA-256 lift, join and identity programs, allowing SHA-256 Composite receipts
  to become SHA-256 Succinct receipts without switching the recursive proof
  hash to Poseidon2. This is backend implementation work, not a reduction in
  the guest's credential-verification algorithm. The existing Composite and
  Poseidon2 paths remain selectable.
- **Reproducible recursion artifacts and verifier dispatch:** The ZKR generator,
  bundled artifacts, SHA-specific control IDs, digest encodings and verifier
  context are kept together. A consumer must use the matching backend revision
  and control parameters; changing only a host-side hash-name string is not
  sufficient to implement SHA recursion. DAA currently pins all four patched
  crates to `0079fe1882b123ff7239e0356ce5d8fb47f63795` in [Cargo.toml](Cargo.toml).
- **Reusable CUDA recursion prover:** The pinned SHA-256 path retains per-thread
  recursion prover objects instead of constructing the
  CUDA prover infrastructure again for each lift/join/identity operation.
  Proof-specific state is still generated for each invocation. This reduces
  setup overhead; it does not remove any recursive verification constraint.
- **Decoded recursion-program cache:** Programs are cached by name and recursion
  domain size. Repeated calls avoid reopening the archive, decompressing the
  ZKR and decoding its instruction data. Shared program storage makes cache
  retrieval inexpensive; the cache is process-local, not a persistent proof cache.
- **Borrowed programs and moved input tapes:** The recursion prover borrows its
  program and transfers the assembled input with `mem::take` instead of cloning
  both large objects before preflight. A segmented input tape avoids repeatedly
  relocating a growing concatenation of seals. Individual input chunks are
  still copied into owned storage: this is not an entirely zero-copy pipeline.
- **Explicit identity and receipt selection:** Scripts expose Composite,
  Succinct and optional identity separately. This prevents paying for an
  unwanted wrapper and keeps measurements comparable. Identity selection is a
  proof-configuration choice, not an optimization that can be silently removed
  from an experiment whose privacy argument requires it.
- **Persistent build and artifact caches:** Cargo/CUDA products are reused under
  `~/.cache/sedaa-risc0-shared-target`, rather than a reboot-sensitive `/tmp`
  target. The shared-cache scripts also locate the pinned recursion archive.
  This saves compilation time, not cryptographic prover work.
- **Scope of the recorded backend:** The standalone RISC0 repository has since
  added SHA resolve/union and optional adaptive recursion domains. Those newer
  features are not automatically present in the DAA-pinned revision above.
  Experimental fixed-size SHA row/fold kernel paths that were rolled back
  are not counted as retained DAA optimizations.

### VOLE-in-the-head / FAEST-derived proof implementation

The generic SHA proof code is in [TPM_SHA](vendor/TPM_SHA); the specialized
AES/Rijndael relations are in [TPM_AES](vendor/TPM_AES). Their relation kernels
are different, so sharing an optimization technique does not imply identical
code or identical constraint counts.

- **Hardware carry-less multiplication:** PCLMUL replaces bit-serial binary-field
  multiplication in the hot paths, including GF(2^64) hashing and the
  128/192/256-bit field operations. Public CPU-feature dispatch selects the
  accelerated implementation, with portable fallbacks retained. The field
  polynomials and byte representations remain unchanged.
- **Karatsuba full-width multiplication:** The generic TPM_SHA backend uses
  3, 6 and 9 carry-less limb products for 128-, 192- and 256-bit products,
  respectively, instead of schoolbook 4, 9 and 16. Fixed-width reductions fold
  the product with the original modulus. This changes arithmetic scheduling,
  not the field or the QuickSilver equations.
- **Mixed-width multiplication at every level:** Full-width-by-64-bit products
  also use PCLMUL, including `bf128_mul_64_inplace`. Optimizing only full-width
  multiplication had left this frequently called SHA-256/QuickSilver path
  bit-serial. The corresponding 192/256-bit operations use the same technique.
- **BAVC extended-field hot paths:** TPM_AES additionally accelerates the
  asymmetric extended-field products used by 192/256-bit BAVC leaf hashing.
  It replaces their bit-serial products with carry-less limb products and
  reduction, while retaining the original commitment equations. Optimizing
  the main proof field alone would miss these costs.
- **Batched QuickSilver universal hashing:** TPM_SHA updates its three Horner
  accumulators through three-lane multiplication helpers. They share multiplier
  loads and dispatch overhead but remain three distinct logical accumulators
  with the same update order and transcript inputs.
- **Eight-way AES-CTR expansion:** Long VOLE PRG streams expand one AES key
  schedule and interleave eight independent counter blocks. Tail processing
  preserves the original counter sequence and requested byte length. This is
  acceleration of the backend PRG, not a change from SHA credentials to AES.
- **Streaming ConvertToVOLE:** An online binary-fold stack replaces the large
  two-row leaf buffer. Leaves are generated and folded in their original order;
  the correlation and correction strings are unchanged. Commit/reconstruct
  allocate scratch once per operation and reuse it across trees, rather than
  allocating scratch inside every tree conversion.
- **SIMD VOLE matrix transposition:** The generic backend uses a 64-by-64
  butterfly transpose and packs independent column groups into AVX2 lanes.
  The 128/192/256-bit cases process two/three/four 64-column groups, respectively.
  Scalar fallback and bit-order checks preserve the exact matrix represented.
- **QuickSilver buffer reuse and public-data branches:** Packed transpose
  buffers are reused across row batches. Verification skips masked-witness
  additions when the corresponding public proof bit is zero; this does not
  introduce a branch on a prover's secret witness bit.
- **Prepared-circuit caching:** Relations and their prepared gate/linear-wire
  layouts are constructed once and reused by later proofs. Repeated circuit
  allocation and analysis are removed from the timed proving loop. Circuit
  preparation remains a real one-time cost and is not included in steady-state
  prover/verification timings.
- **Exact low-AND SHA circuits:** SHA-256 and SHA-384/512 use wire permutations
  for rotations/shifts, constant padding/round constants, one-AND-per-bit
  choice/majority identities and one-AND carry propagation. The final unused
  carry is omitted. These are algebraically equivalent implementations of
  SHA, not reduced-round hashes. A changed gate layout can change the circuit
  ID and proof bytes even when the hash function remains identical.
- **FAEST-style AES constraints:** AES/Rijndael proofs retain the specialized
  extension-field constraint representation rather than expanding every S-box
  into a large generic Boolean circuit. Shared key material and intermediate
  outputs are wired into the joint relation; they are not proved as unrelated
  encryptions. The GF(2^8) S-box arithmetic is distinct from the larger VOLE
  authentication fields accelerated above.
- **Shared AES key schedules and linear DM constraints:** The joint three-call
  relation constrains the TPM key expansion once for the slt/et calls and the
  hook key expansion once for the hk call. AES-128-DM and Rijndael-256-DM
  feed-forward XORs are represented in the affine output constraints, including
  the hidden et connection, rather than being checked only outside the proof.
  These linear operations do not require extra S-box constraints. Selecting
  DM or a wider Rijndael block is a primitive choice; efficiently expressing
  the already selected relation is the implementation optimization.
- **Profile-aware proof packaging:** Both small-proof and fast-proof VOLE
  profiles are exposed at each supported level. TPM_SHA's v3 header, circuit
  identifier and transcript bind the selection and reject cross-profile use.
  Adding S/F profiles is a parameter/format feature, not a format-preserving
  arithmetic speedup.
- **Differential tests and deterministic proof vectors:** Field products,
  mixed-width operations, batch hashes, AES-CTR streams and streaming VOLE
  conversion are checked against scalar/reference calculations. End-to-end
  tests also reject modified statements, contexts, proofs and wrong profiles.
  These protect implementation equivalence; they are not new security proofs.

Source entry points: [fields](vendor/TPM_SHA/third_party/faest/fields.c),
[universal hashing](vendor/TPM_SHA/third_party/faest/universal_hashing.c),
[VOLE](vendor/TPM_SHA/third_party/faest/vole.c),
[AES-CTR](vendor/TPM_SHA/third_party/faest/aes.c),
[transpose](vendor/TPM_SHA/backend/vole/bit_matrix_transpose.cpp),
[QuickSilver](vendor/TPM_SHA/backend/generic_quicksilver.cpp), and
[tests](vendor/TPM_SHA/tests/tpm_sha_tests.cpp).

### SPHINCS+ native and RISC0 verification

- **Reused upstream public-seed state:** SHA2-simple already precomputes the
  state after absorbing the padded `PK.seed` block. The specialized verifier
  preserves and reuses this state instead of restarting the public prefix at
  every addressed hash. This is reuse of a SPHINCS+ reference technique, not a
  new signature construction.
- **SHA-256 syscall batching and aligned-input bypass:** Contiguous compression
  blocks are submitted through the existing RISC0 SHA syscall in batches.
  Aligned caller buffers are passed directly; only unaligned inputs need a
  temporary aligned copy. Hash block order and final length encoding are unchanged.
- **Fixed-length SHA2-simple paths:** Known address and payload sizes allow
  direct construction of padded blocks, avoiding repeated generic incremental
  hash setup and finalization. Compression states and output truncation still
  match the reference implementation.
- **Direct variable-WOTS fast path for opt2:** The verifier retains the standard
  message-dependent chain lengths, but shares a padding template, seeded state
  and address template across the WOTS instance. Each round updates the chain
  state and hash address and invokes the compression path directly, avoiding
  a generic `thash` call and repeated state serialization.
- **Direct fixed-chain fast path for opt4:** Within the already selected
  ZK-WOTS+ dummy-padding method, every chain executes 15 steps. Real/dummy
  selection is performed in 4/6/8 unsigned 32-bit words for n=16/24/32, and the
  hash output updates those states directly. The optimization removes temporary
  input/hashed/selected arrays and repeated padding/address reconstruction; the
  choice of fixed dummy work itself is a separate verification strategy.
- **Correct SHA-family dispatch:** WOTS single-node hashes use SHA-256 for all
  six SHA2 sets, so the direct syscall path also benefits 192/256. Their
  multi-node hashes and public-key compression use SHA-512 where required by
  the reference parameters. There is no SHA-512 syscall in this RISC0 v3 guest;
  those operations remain software SHA-512. A SHA-512 WOTS-chain fast path is
  not part of the current implementation.
- **Compact address updates and parameter specialization:** The optimized
  verification path copies invariant subtree/keypair fields once and modifies
  only the changing chain/tree fields. Compile-time n, tree height and chain
  count eliminate unnecessary generic dispatch without changing any address
  encoded by the original SPHINCS+ instance.
- **Verification-only guest builds and hash accounting:** Signing/tree-generation
  code is kept outside the verification guest where applicable. Profiling
  distinguishes logical hashes, SHA-256/SHA-512 compression blocks and syscall
  chunks, so fewer guest instructions are not misreported as fewer hashes.

Source entry points: [optimized verifier](host_proof/methods/guest/c_src/sphincs_ref/sign_verify_128s_opt.c),
[SHA implementation](host_proof/methods/guest/c_src/sphincs_ref/sha2.c), and
[SHA2-simple dispatch](host_proof/methods/guest/c_src/sphincs_ref/thash_sha2_simple.c).

### F-SPHINCS+ implementation and verification

- **Layer-streaming verification:** The guest consumes one M-FORS layer at a
  time and reuses its buffer instead of retaining the whole credential in
  `.bss`. Memory scales with one layer, not all seven. Secret-tree generation
  and heap tree construction are excluded from the verification guest.
- **Explicit per-operation public-prefix context:** H1 v6 absorbs
  `PUB_SEED[32] || zero[32]` once and shares the full 256-bit SHA state through
  all layers. For a fixed v6 preimage definition, this saves N-1 repeated public
  prefix compressions across N H1 invocations. The final SHA bit length still
  includes the prefix, and contexts are not reused across different keys.
- **Fixed-size H1 suffix buffers:** Address, payload position, SHA padding and
  message length are prepared once per path/aggregation loop. Only changing
  address fields and child values are written at each step. Aligned suffixes
  reach the RISC0 SHA syscall directly, in one batch even when two compression
  blocks are needed.
- **Ping-pong states and in-place aggregation:** Authentication paths alternate
  two node buffers instead of copying the newly computed node back every
  round. Aggregation overwrites nodes whose children have been consumed.
  Preallocated address/preimage buffers avoid building multiple intermediate
  concatenations of the same data.
- **Streaming H3 and expansion-prefix reuse:** Message hashing uses bounded
  64/128-byte buffers instead of materializing long concatenations. MGF-style
  expansion clones the common prefix state and appends the counter for each
  digest, preserving the full intermediate digest and exact output stream.
- **One parameter registry and exact bit parsing:** Native C and Rust host/guest
  build constants come from the same six-set registry. Index parsing consumes
  exactly d bits, handles the 128f half-byte boundary, and checks canonical
  unused bits. This is a correctness/reproducibility measure, not an extra
  cryptographic assumption or a claim of higher security.
- **Reference-mode KATs and per-layer profiles:** The optimized H1 path is
  compared with ordinary hashing of its full preimage; Python/hashlib checks
  the deterministic credential, paths, PRF derivations and recovered layer
  values independently. Actual compression counts include the shared prefix
  once and report SHA-512 separately from SHA-256.

The following performance-relevant choices are implemented, but **are not
bit-for-bit engineering optimizations of the previous format**:

- **SHA-2 instantiation and six parameter sets:** Implementing the paper's
  M-FORS hierarchy with standard SHA-2 and selecting the six d/k tradeoffs
  defines concrete experimental instances. These choices must be distinguished
  from accelerating an already fixed instance. The parameter table above is
  authoritative; its target-security labels are not themselves a full security
  proof.
- **16/24/32-byte H1 nodes:** SHA-256 tree/leaf hash outputs are truncated to
  128/192 bits or retained at 256 bits. This shrinks authentication paths and
  can reduce compression work, but changes public roots and credentials.
  It is an instantiation choice requiring the appropriate addressed-hash
  assumptions, not a byte-preserving optimization or full-width collision claim.
- **Lossless 16-byte address encodings:** Leaf-PRF v7 and H1 v6 encode bounded
  fields directly rather than hashing/truncating a larger address. Range checks
  preserve injectivity and type/set separation. Shorter preimages reduce
  padding blocks, but changing the serialized encoding changes hash outputs
  and requires fresh credentials/KATs. Adding the padded H1 public prefix is
  likewise a format change; caching that fixed prefix afterward is equivalent.
- **Security-sized leaf secrets and paired anchors:** Leaf PRF v7 keeps the
  first 16/24/32 digest bytes throughout native signing, certificate recovery
  and guest verification, while master/node seeds remain 32 bytes. All six
  Setup relations now prove two outputs with one shared private seed. This is
  a coordinated instantiation/format change, not just truncating the ZK check.
  Certificate version 7 and VOLE relation kind 5 reject obsolete Setup formats;
  old KATs are archived, and fresh keys/credentials/guest images are required.
- **H3 SHA-512 and context binding:** The 256 sets use SHA-512 with its complete
  512-bit intermediate digest, and expansion explicitly binds randomizer and
  public key. This is a security-relevant hash-definition change, not merely a
  faster SHA implementation.
- **Compact setup authentication certificates:** Selected leaf paths share an
  aggregation authentication path rather than exposing every other tree root.
  This reduces certificate storage and public checking. It changes certificate
  encoding, not the credential's native verification algorithm, and does not
  establish root-seed consistency by itself.

Source entry points: [parameters](host_proof/methods/guest/c_src/fsphincs_ref/params.h),
[implementation](host_proof/methods/guest/c_src/fsphincs_ref/fsphincs.c),
[format and KAT description](host_proof/methods/guest/c_src/fsphincs_ref/DESIGN.md),
and [independent checker](host_proof/methods/guest/c_src/fsphincs_ref/test_reference.py).

### Setup anchor width audit

The current relation uses SHA-256 in both credential families. The
SPHINCS+ seed anchor is a FORS PRF output, not a SHA-384/512 digest; its
SHA-256 output is truncated to the scheme's n bytes. F-SPHINCS+ proves the
leaf PRF under the top M-FORS node seed, not the master-to-node derivation.

| Family / level | Merkle node (B) | Private anchor seed (B) | Each public PRF output (B) | Anchors | Secret-dependent SHA-256 compressions |
|---|---:|---:|---:|---:|---:|
| SPHINCS+ 128 | 16 | 16 | 16 | 2 | 2 |
| SPHINCS+ 192 | 24 | 24 | 24 | 2 | 2 |
| SPHINCS+ 256 | 32 | 32 | 32 | 2 | 2 |
| F-SPHINCS+ 128 | 16 | 32 | 16 | 2 | 2 |
| F-SPHINCS+ 192 | 24 | 32 | 24 | 2 | 2 |
| F-SPHINCS+ 256 | 32 | 32 | 32 | 2 | 2 |

For SPHINCS+, public inputs contain the authenticated public-prefix SHA state
and two distinct compressed addresses. The private seed is shared by both
compression circuits. F-SPHINCS+ uses `Trunc_n(SHA256(S_root[32] || ADRS[16]))` with
distinct fixed addresses and a shared private `S_root`; padding fits one
compression per anchor. Outputs and addresses are derived from the public
certificate, whose verification links them to the registered public key.

Truncating only the ZK output check while retaining full 32-byte secrets in
the certificate is not equivalent: a seed matching the disclosed prefixes
need not generate the remaining authenticated bytes. A consistent truncated
leaf-PRF variant must also change leaf hashing, credential serialization,
certificate recovery, host/guest constants and KATs. Two same-seed,
distinct-address anchors can align the number of proved compressions, but
do not by themselves establish tree-wide seed consistency or a concrete
128/192/256-bit extraction guarantee. Equal compression counts also need
not give identical VOLE gate counts or proof sizes because input widths and
public SHA initial states differ. Leaf-PRF truncation is explicitly versioned
separately from H1 node truncation. The separate SPHINCS+ fixed-top-WOTS mode
proves the complete WOTS key-to-public-key relation, not this two-PRF relation.

### Integration and measurement discipline

- **Connected witnesses rather than independent subproofs:** The TPM SHA
  relation shares sk wires and connects the et digest directly into the hook.
  Host verification uses the matching credential, et and hook opening. This
  implements the intended relation without redundant equality subproofs; the
  choice between 3F and 5F remains a protocol choice, not an engineering speedup.
- **Native adapters and bounded guest data movement:** C cryptographic routines
  are reused through narrow interfaces; fixed-size inputs and reusable buffers
  avoid repeatedly serializing the same witness inside the guest. Public
  journals bind the selected issuer key and hook, while the image ID binds the
  verifier program and parameter set.
- **Versioned artifacts and separate benchmark modes:** Native credential,
  setup certificate/proof, TPM proof and host receipt costs are reported
  separately. Warmups and circuit preparation are outside steady-state proof
  timings; receipt serialization size and seal size are distinguished. Saved
  logs retain parameter, profile and backend settings, and generated native
  benchmark executables are cleaned up without deleting persistent caches.

## Current Benchmark Results

The following tables collect the performance results from `Paper/main.tex`.
The F-SPHINCS+ rows use the completed **H1-v6 / leaf-PRF-v7** reruns from
2026-10-30, not the earlier smoke tests. Other rows retain their results.
Times are seconds; KB means 1024 bytes.

All six F-SPHINCS+ sets expose 16/24/32-byte leaf-PRF outputs and use two
distinct-address anchors sharing one 32-byte root-node seed. Each Setup
proof covers two SHA-256 compressions. Native and Setup-proof timings are
ten-run means; host timings use one run per receipt mode at segment size
`2^20`, with one SHA-2 hook and no Identity wrapper.

In the TPM panels, SHA2-5F is the CDENW'23-style relation and SHA2-3F is
Ours-3F; their reductions isolate the benefit of reducing the number of
functions under the same primitive. AES-3F is reported separately as an
alternative concrete instantiation and is not included in those reductions.
All host panels use **one SHA-2 hook**; there, Variant-1 identifies the
F-SPHINCS+ credential family. Host measurements use the SHA-256 RISC0 backend
with segment size `2^20`.

### Credential-scheme setup

| Variant | Credential scheme | Parameters | Keygen (s) | Public key (B) | Secret key (B) |
| --- | --- | --- | --- | --- | --- |
| Variant-1 | F-SPHINCS+ | 128s | 0.570 | 76 | 108 |
| Variant-1 | F-SPHINCS+ | 128f | 0.102 | 124 | 156 |
| Variant-1 | F-SPHINCS+ | 192s | 1.13 | 98 | 130 |
| Variant-1 | F-SPHINCS+ | 192f | 0.194 | 170 | 202 |
| Variant-1 | F-SPHINCS+ | 256s | 1.47 | 118 | 150 |
| Variant-1 | F-SPHINCS+ | 256f | 0.256 | 212 | 244 |
| Variant-2 | SPHINCS+ | 128s | 0.050 | 32 | 64 |
| Variant-2 | SPHINCS+ | 128f | 0.001 | 32 | 64 |
| Variant-2 | SPHINCS+ | 192s | 0.062 | 48 | 96 |
| Variant-2 | SPHINCS+ | 192f | 0.001 | 48 | 96 |
| Variant-2 | SPHINCS+ | 256s | 0.038 | 64 | 128 |
| Variant-2 | SPHINCS+ | 256f | 0.002 | 64 | 128 |

### Setup-time issuer-extraction proof

A separate, replaceable Setup building block; credential key generation
is excluded. Variant-2 Solution 1 uses VOLEith and Solution 2 uses RISC0
Composite. Compression counts include the work counted in the paper.

| Variant / solution | Credential scheme | Credential parameter | Proof parameter | SHA-2 comp. | Anchor generation (s) | Certificate verification (s) | Preparation (s) | Prove (s) | Verify (s) | Proof (KB) | Public cert. (KB) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Variant-1 | F-SPHINCS+ | 128s | 128s | 2 | 0.549 | 0.000006 | 0.004 | 0.026 | 0.022 | 62.10 | 0.609 |
| Variant-1 | F-SPHINCS+ | 128f | 128f | 2 | 0.096 | 0.000005 | 0.003 | 0.008 | 0.006 | 89.71 | 0.500 |
| Variant-1 | F-SPHINCS+ | 192s | 192s | 2 | 1.10 | 0.000011 | 0.003 | 0.042 | 0.037 | 92.55 | 0.930 |
| Variant-1 | F-SPHINCS+ | 192f | 192f | 2 | 0.187 | 0.000009 | 0.003 | 0.011 | 0.009 | 136.93 | 0.766 |
| Variant-1 | F-SPHINCS+ | 256s | 256s | 2 | 1.42 | 0.000011 | 0.003 | 0.073 | 0.067 | 130.71 | 1.234 |
| Variant-1 | F-SPHINCS+ | 256f | 256f | 2 | 0.248 | 0.000010 | 0.003 | 0.016 | 0.014 | 186.65 | 1.016 |
| Variant-2 / Solution 1 | SPHINCS+ | 128s | 128s | 2 | 0.296 | 0.00027 | 0.010 | 0.028 | 0.023 | 61.70 | 5.43 |
| Variant-2 / Solution 1 | SPHINCS+ | 128f | 128f | 2 | 0.015 | 0.00086 | 0.010 | 0.008 | 0.006 | 89.12 | 13.79 |
| Variant-2 / Solution 1 | SPHINCS+ | 192s | 192s | 2 | 0.554 | 0.00043 | 0.010 | 0.048 | 0.038 | 93.05 | 10.92 |
| Variant-2 / Solution 1 | SPHINCS+ | 192f | 192f | 2 | 0.026 | 0.00128 | 0.010 | 0.012 | 0.009 | 137.68 | 29.02 |
| Variant-2 / Solution 1 | SPHINCS+ | 256s | 256s | 2 | 0.482 | 0.00059 | 0.010 | 0.074 | 0.069 | 132.93 | 20.34 |
| Variant-2 / Solution 1 | SPHINCS+ | 256f | 256f | 2 | 0.050 | 0.00120 | 0.010 | 0.017 | 0.014 | 189.87 | 39.40 |
| Variant-2 / Solution 2 | SPHINCS+ | 128s | RISC0 | 536 | 0.040 | 0.000001 | 0.000 | 1.23 | 0.00163 | 251.73 | 0.172 |
| Variant-2 / Solution 2 | SPHINCS+ | 128f | RISC0 | 536 | 0.001 | 0.000001 | 0.000 | 1.20 | 0.00161 | 250.98 | 0.078 |
| Variant-2 / Solution 2 | SPHINCS+ | 192s | RISC0 | 777 | 0.057 | 0.000002 | 0.000 | 2.08 | 0.00176 | 264.42 | 0.250 |
| Variant-2 / Solution 2 | SPHINCS+ | 192f | RISC0 | 777 | 0.001 | 0.000001 | 0.000 | 2.13 | 0.00172 | 263.30 | 0.109 |
| Variant-2 / Solution 2 | SPHINCS+ | 256s | RISC0 | 1025 | 0.037 | 0.000002 | 0.000 | 3.47 | 0.00191 | 277.86 | 0.297 |
| Variant-2 / Solution 2 | SPHINCS+ | 256f | RISC0 | 1025 | 0.003 | 0.000001 | 0.000 | 3.60 | 0.00189 | 276.86 | 0.172 |

### Join protocol

Panel A gives AES and SHA-2 instantiations of the shared one-function Join
relation. The evaluated implementation variants select the SHA-2 rows; AES
is an alternative concrete instantiation. A complete Join selects the
matching security level and s/f profile from both panels.

#### Panel A: TPM joining proof

| VOLEith parameter | F instance | Prove (s) | Verify (s) | Proof (KB) |
| --- | --- | --- | --- | --- |
| 128s | AES-128-DM | 0.009 | 0.008 | 4.40 |
| 128f | AES-128-DM | 0.002 | 0.001 | 5.79 |
| 192s | AES-192 | 0.024 | 0.012 | 11.00 |
| 192f | AES-192 | 0.003 | 0.002 | 14.60 |
| 256s | AES-256 | 0.027 | 0.026 | 20.21 |
| 256f | AES-256 | 0.005 | 0.005 | 25.93 |
| 128s | SHA-256 | 0.018 | 0.015 | 32.42 |
| 128f | SHA-256 | 0.004 | 0.003 | 46.54 |
| 192s | SHA-384 | 0.056 | 0.044 | 115.71 |
| 192f | SHA-384 | 0.012 | 0.010 | 171.66 |
| 256s | SHA-512 | 0.079 | 0.078 | 165.07 |
| 256f | SHA-512 | 0.019 | 0.016 | 236.62 |

#### Panel B: credential issuance

| Variant | Credential scheme | Parameters | Sign (s) | Verify (s) | Credential (KB) |
| --- | --- | --- | --- | --- | --- |
| Variant-1 | F-SPHINCS+ | 128s | 3.93 | <0.001 | 40.94 |
| Variant-1 | F-SPHINCS+ | 128f | 0.689 | <0.001 | 86.77 |
| Variant-1 | F-SPHINCS+ | 192s | 7.86 | 0.001 | 92.07 |
| Variant-1 | F-SPHINCS+ | 192f | 1.37 | 0.002 | 196.25 |
| Variant-1 | F-SPHINCS+ | 256s | 10.11 | 0.001 | 159.94 |
| Variant-1 | F-SPHINCS+ | 256f | 1.79 | 0.003 | 341.28 |
| Variant-2 | SPHINCS+ | 128s | 0.286 | 0.001 | 7.69 |
| Variant-2 | SPHINCS+ | 128f | 0.014 | 0.001 | 16.70 |
| Variant-2 | SPHINCS+ | 192s | 0.516 | 0.001 | 15.88 |
| Variant-2 | SPHINCS+ | 192f | 0.022 | 0.001 | 34.86 |
| Variant-2 | SPHINCS+ | 256s | 0.455 | 0.001 | 29.12 |
| Variant-2 | SPHINCS+ | 256f | 0.046 | 0.002 | 48.72 |

### Signing protocol

#### Panel A: TPM signing

The prove/proof reductions compare SHA2-3F with SHA2-5F. AES-3F is an
alternative concrete instantiation and is not part of the reduction.
The AES columns use AES-128-DM for 128s/128f (100-run means);
192/256 retain the historical plain-AES measurements.

| VOLEith parameter | SHA2-5F prove (s) | SHA2-5F proof (KB) | SHA2-3F prove (s) | SHA2-3F proof (KB) | Prove reduction | Proof reduction | AES-3F prove (s) | AES-3F proof (KB) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 128s | 0.064 | 178.63 | 0.033 | 91.73 | 48.1% | 48.6% | 0.012 | 7.41 |
| 128f | 0.021 | 259.20 | 0.010 | 132.81 | 52.1% | 48.8% | 0.003 | 10.16 |
| 192s | 0.247 | 552.82 | 0.134 | 334.46 | 45.9% | 39.5% | 0.024 | 20.37 |
| 192f | 0.073 | 827.32 | 0.036 | 499.79 | 51.0% | 39.6% | 0.005 | 28.66 |
| 256s | 0.449 | 920.80 | 0.206 | 470.75 | 54.1% | 48.9% | 0.034 | 35.77 |
| 256f | 0.120 | 1335.87 | 0.059 | 681.25 | 50.9% | 49.0% | 0.010 | 48.55 |

#### Panel B: host signing

Direct SPHINCS+ uses Succinct with Identity. ZK-WOTS+ and F-SPHINCS+
Succinct do not use an additional Identity wrapper.

| Variant | Host construction | Credential | Composite prove (s) | Composite proof (KB) | Succinct prove (s) | Succinct proof (KB) |
| --- | --- | --- | --- | --- | --- | --- |
| Variant-1 | F-SPHINCS+ | 128s | 3.75 | 275.69 | 6.60 | 267.79 |
| Variant-1 | F-SPHINCS+ | 128f | 5.85 | 537.84 | 15.77 | 268.16 |
| Variant-1 | F-SPHINCS+ | 192s | 5.83 | 537.76 | 15.76 | 268.08 |
| Variant-1 | F-SPHINCS+ | 192f | 10.88 | 825.98 | 27.93 | 268.64 |
| Variant-1 | F-SPHINCS+ | 256s | 7.60 | 550.98 | 17.38 | 268.36 |
| Variant-1 | F-SPHINCS+ | 256f | 14.82 | 1101.14 | 37.72 | 269.10 |
| Variant-2 | Direct SPHINCS+ | 128s | Not applicable | Not applicable | 9.712 | 267.44 |
| Variant-2 | Direct SPHINCS+ | 128f | Not applicable | Not applicable | 18.619 | 267.44 |
| Variant-2 | Direct SPHINCS+ | 192s | Not applicable | Not applicable | 71.022 | 267.69 |
| Variant-2 | Direct SPHINCS+ | 192f | Not applicable | Not applicable | 112.685 | 267.69 |
| Variant-2 | Direct SPHINCS+ | 256s | Not applicable | Not applicable | 101.234 | 267.94 |
| Variant-2 | Direct SPHINCS+ | 256f | Not applicable | Not applicable | 141.167 | 267.94 |
| Variant-2 | ZK-WOTS+ | 128s | 4.545 | 513.75 | 14.626 | 267.44 |
| Variant-2 | ZK-WOTS+ | 128f | 11.416 | 1063.18 | 35.234 | 267.44 |
| Variant-2 | ZK-WOTS+ | 192s | 28.106 | 2198.60 | 78.629 | 267.69 |
| Variant-2 | ZK-WOTS+ | 192f | 49.584 | 4062.79 | 147.892 | 267.69 |
| Variant-2 | ZK-WOTS+ | 256s | 40.508 | 3284.77 | 118.326 | 267.94 |
| Variant-2 | ZK-WOTS+ | 256f | 61.119 | 4933.06 | 180.533 | 267.94 |

### Verification algorithm

#### Panel A: TPM verification

The reduction compares SHA2-3F with SHA2-5F; AES-3F is reported only as
an alternative instantiation.
The AES verifier rows use AES-128-DM for 128s/128f (100-run means)
and historical plain AES for 192/256. The new 128s/128f verifier means
round to the same three-decimal values as the previous measurements.

| VOLEith parameter | SHA2-5F verify (s) | SHA2-3F verify (s) | Reduction | AES-3F verify (s) |
| --- | --- | --- | --- | --- |
| 128s | 0.053 | 0.030 | 42.7% | 0.010 |
| 128f | 0.016 | 0.008 | 47.6% | 0.002 |
| 192s | 0.223 | 0.119 | 46.7% | 0.016 |
| 192f | 0.062 | 0.030 | 51.0% | 0.004 |
| 256s | 0.432 | 0.192 | 55.6% | 0.033 |
| 256f | 0.105 | 0.045 | 57.3% | 0.008 |

#### Panel B: host verification

| Variant | Host construction | Credential | Composite verify (s) | Succinct verify (s) |
| --- | --- | --- | --- | --- |
| Variant-1 | F-SPHINCS+ | 128s | 0.001 | 0.00078 |
| Variant-1 | F-SPHINCS+ | 128f | 0.002 | 0.00079 |
| Variant-1 | F-SPHINCS+ | 192s | 0.002 | 0.00077 |
| Variant-1 | F-SPHINCS+ | 192f | 0.004 | 0.00081 |
| Variant-1 | F-SPHINCS+ | 256s | 0.002 | 0.00077 |
| Variant-1 | F-SPHINCS+ | 256f | 0.005 | 0.00079 |
| Variant-2 | Direct SPHINCS+ | 128s | Not applicable | 0.00077 |
| Variant-2 | Direct SPHINCS+ | 128f | Not applicable | 0.00077 |
| Variant-2 | Direct SPHINCS+ | 192s | Not applicable | 0.00082 |
| Variant-2 | Direct SPHINCS+ | 192f | Not applicable | 0.00078 |
| Variant-2 | Direct SPHINCS+ | 256s | Not applicable | 0.00078 |
| Variant-2 | Direct SPHINCS+ | 256f | Not applicable | 0.00081 |
| Variant-2 | ZK-WOTS+ | 128s | 0.002 | 0.00079 |
| Variant-2 | ZK-WOTS+ | 128f | 0.005 | 0.00080 |
| Variant-2 | ZK-WOTS+ | 192s | 0.010 | 0.00080 |
| Variant-2 | ZK-WOTS+ | 192f | 0.018 | 0.00078 |
| Variant-2 | ZK-WOTS+ | 256s | 0.015 | 0.00084 |
| Variant-2 | ZK-WOTS+ | 256f | 0.022 | 0.00079 |

### Source logs

- [SHA-2 TPM Join and signing](benchmarks/tpm_sha_ours3h_vs_chen23_5h.log).
- [AES-128-DM TPM Join and signing, 100-run means](benchmarks/tpm_aes_dm_v1/tpm_aes_20261023-212221.log).
- [Historical plain-AES TPM Join and signing (192/256 rows)](benchmarks/tpm_aes_vole/tpm_aes_20260920-185834.log); the 192s Join row uses the [100-run rerun](benchmarks/tpm_aes_vole/tpm_aes_20260920-190152.log).
- [SPHINCS+ Setup Solution 1](benchmarks/issuer_anchor/issuer_anchor_seed-anchor_composite_20260906_191550.log)
  and [Solution 2](benchmarks/issuer_anchor/issuer_anchor_fixed-top-wots_composite_20260906_000205.log).
- [SPHINCS+ host results](benchmarks/host_sha2/host_sha2_all_20260904-012627.tsv).
- [F-SPHINCS+ native, ten-run means](benchmarks/fsphincs_leaf_prf_v7/native_setup_20261030_152407.log),
  [Setup, ten-run means](benchmarks/fsphincs_leaf_prf_v7/setup_detail_20261030_152407.log), and
  [host results](benchmarks/fsphincs_leaf_prf_v7/host_20261030_165221.log).
