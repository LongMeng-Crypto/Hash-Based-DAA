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
| Ours-3F | F-SPHINCS+ format v3, six parameter sets | VOLEith SHA-2, s/f | One SHA-2 | RISC0 SHA-256 |
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
is the shared C/Rust source of truth. All six sets keep 32-byte internal
seeds/nodes, `q=1024`, and `h=6` (seven M-FORS signature layers).

| Parameter | Inner-tree height `d` | Tree count `k` | H3 | Root anchors | Setup SHA-256 compressions |
|---|---:|---:|---|---:|---:|
| 128s | 16 | 22 | SHA-256 | 1 | 2 |
| 128f | 12 | 61 | SHA-256 | 1 | 2 |
| 192s | 16 | 33 | SHA-256 | 2 | 4 |
| 192f | 12 | 92 | SHA-256 | 2 | 4 |
| 256s | 16 | 43 | SHA-512 | 2 | 4 |
| 256f | 12 | 120 | SHA-512 | 2 | 4 |

Select `FSPHINCS_PARAMS=128s|128f|192s|192f|256s|256f`; independent
`FSPHINCS_SECURITY`/`FSPHINCS_K` selectors and legacy `k=35/70` are rejected.
Each credential is paired with the same VOLEith security/profile label.

H1, H2, and seed derivation use SHA-256. The 256-labelled sets use SHA-512
for H3 and retain its complete 64-byte intermediate digest; every H3
expansion binds `R` and the full public key. M-FORS indices consume exactly
`d` bits, and the 60-bit node index starts immediately after the `k*d`
digest bits, without byte-rounding. Previous-format keys, credentials,
certificates, and guest images cannot be reused.

These are experimental target-security labels, not standardized SPHINCS+
parameter sets or a complete unforgeability theorem. A TPM/credential label
does not raise the pinned RISC0 backend's knowledge-soundness level.
See [DESIGN.md](host_proof/methods/guest/c_src/fsphincs_ref/DESIGN.md) for
the byte format, H3 construction, and KAT checks.

### Issuer extraction proof

The optional `pi_I` is a separate Setup-time building block, not repeated
during Join or signing. `--issuer-anchor-mode` selects its implementation
without changing the credential, TPM, or host-signature relation:

| Setup mode | Credential | Private witness | Proof system | Extra seed-consistency condition |
|---|---|---|---|---|
| `seed-anchor` (default) | Standard SPHINCS+ | One `SK.seed` opening FORS secrets 0 and 1 | VOLEith SHA-256, s/f | Certified seed must regenerate the top XMSS tree |
| `seed-anchor` | F-SPHINCS+ v3 | One root M-FORS seed `S_root` | VOLEith SHA-256, s/f | Certified seed must regenerate the whole root M-FORS node |
| `fixed-top-wots` | Standard SHA2-simple SPHINCS+ | Complete secret key of one top WOTS+ leaf | RISC0 Composite / Succinct | Not required |

**Signature-Derived Seed Anchor (SDSA)** uses a fixed double-FORS certificate.
It signs the reserved one-byte Setup message `49` (hex) once with the ordinary
SPHINCS+ signer. This message is outside the fixed-length
`et || issuer_nonce` credential domain. The certificate takes the revealed
secrets and authentication paths from FORS trees **zero and one in that same
signature**, publicly reconstructs the other `k-2` FORS roots, and retains
one shared hypertree signature suffix. These two trees exist in every valid
signature for all six parameter sets, so anchor selection always succeeds.

The certificate is deterministic public post-processing of one ordinary
signature. The credential EUF-CMA reduction counts that single Setup query
and simulates the seed proof using the assumed ZK interface. Both exposed
secrets and paths already appear in the signature. The public verifier
reconstructs the two FORS roots, compresses all `k` roots in order, and checks
the shared hypertree suffix from that FORS public key to `PK.root`.
Setup does not add a credential message to the membership ledger.

The private relation jointly proves two SHA-256 compressions using **one
shared private seed**, after the public `PK.seed` prefix state. Its public
inputs contain two distinct 22-byte addresses and its two outputs are each
truncated to 16/24/32 bytes. For fixed public seed and addresses, a different
seed satisfying both equations is a collision in the concatenated output.
In the domain-separated random-oracle model, this 256/384/512-bit joint
output targets 128/192/256-bit **classical** chosen-seed collision binding.
The multi-instance bound must include adversarial address/public-seed choices.
Ordinary PRF security alone does not establish this joint chosen-key property.
The top-tree consistency assumption and anchor binding are separate:
consistency links a designated seed to both anchors and the registered top
XMSS tree; binding links the extracted witness to that seed. Full global
consistency is sufficient but stronger than necessary; the issuer's lower
layers need not share that seed. A collision reduction must specify how it
obtains the designated seed, or explicitly assume the extracted-seed
capability. The local proof alone does not establish whole-tree consistency.
Under these conditions, the extracted seed supports standard credential
generation with fresh lower layers, without grinding or recovering `SK.prf`. This is not an
assignment of those security bits to the complete UC protocol or to quantum
attacks.

A version-5, 26-byte header encodes the fixed FORS certificate type,
parameters, both selected within-tree leaf indices, keypair index, and tree
address. The public verifier checks exact lengths and ranges and reconstructs
both PRF statements. FORS tree offsets distinguish the two addresses even
when the within-tree leaf indices coincide. The proof context binds the full
certificate and issuer public key. The certificate has a fixed size for each
parameter set:

`26 + n * (2 * fors_height + fors_trees + d * wots_len + full_height)` bytes.

This includes two secrets, two FORS paths, `k-2` roots, and **one** hypertree
suffix. The private proof always contains two SHA-256 compression blocks.

**F-SPHINCS+ root-seed anchor** proves
`x_i = SHA256(S_root || ADRS_i)`, not the derivation of `S_root` from the
original master seed. Addresses select leaf zero in root signing tree zero,
and also tree one for double anchors. The only private input is the shared
32-byte `S_root`; addresses and full 32-byte outputs are public.

The 64-byte preimage needs two compressions including padding. Although the
padding block is fixed, its chaining state depends on the secret and must
also be proved. This gives 2/4/4 compressions at 128/192/256, whereas
SPHINCS+ uses two separate single-compression anchors at every level.
SPHINCS+ truncates its PRF to its standard 16/24/32-byte secret/node width;
F-SPHINCS+ keeps 32-byte PRF outputs in all sets. Thus a single SPHINCS+
anchor would not provide the same joint-binding target as a single full
F-SPHINCS+ anchor. Only seed-derived internal wires remain private; the
verifier reconstructs the public statement from the authenticated certificate.

The compact F-SPHINCS+ certificate contains the selected outputs, their
inner authentication paths, and one shared aggregation path, followed
publicly through H2 to the registered root. It does not list all other
tree roots. With `t=1/2` anchors and `L=ceil(log2(k))`, its size is
`16 + 32 * (t*(d+1) + L-(t-1))` bytes: 720/624/1264/1040/1264/1040
for 128s/128f/192s/192f/256s/256f.

Root-node consistency and addressed-anchor binding remain explicit
assumptions. No consistency with lower-node seeds is required:
`fsphincs_sign_with_root_seed` builds lower layers from an independent seed
and signs the final value using `S_root`. Tests erase the original master
and verify two fresh credentials. This tests the signing capability, not a
cryptographic extractor. Unlike SPHINCS+ SDSA, the direct root certificate
has not been reduced here to one ordinary signing-oracle response; its
exposure needs a separate reduction or a certificate-augmented
unforgeability assumption.

**Authenticated Top-WOTS Capability (ATWC)** is selected by `fixed-top-wots`.
In `fixed-top-wots`, Setup uses the public top-tree index zero. The private
witness contains **all** 35/51/67 WOTS chain starts; the guest runs all
15 steps of every chain using opt4's existing
`sha256_zk_wots_fixed_chain(..., start=0)`. These 525/765/1005 chain steps
all use SHA-256. WOTS public-key compression and XMSS path hashing use
SHA-256 at n=16 and SHA-512 at n=24/32, exactly as the reference implementation.
Including WOTS public-key compression and shared public-seed preprocessing,
the complete guest hash counts are 536, 777, and 1025 compressions:
536 SHA-256; 766 SHA-256 + 11 SHA-512; and 1006 SHA-256 + 19 SHA-512,
respectively. Public XMSS path checking is outside the guest and is not
included in those totals.

The public certificate contains a versioned parameter header, top index,
compressed WOTS public leaf and top XMSS authentication path:
`16 + (1 + top_height) * n` bytes. No chain starts, intermediate chain values,
or signature are published. The guest proves the complete WOTS-key relation
and binds the full issuer public key and certificate in its journal.
The mandatory outer verifier checks the public XMSS path to `PK.root`,
matches the full journal to that same public statement, and verifies the
correct guest image. Thus `pi_I.Verify = PathCheck AND WOTS-key-PoK`;
checking only `Receipt::verify` is not sufficient. Public path hashing is
not duplicated inside the guest. Fake/development receipts are rejected.

This extracts a **signing capability**, not the master seed: in the security
simulation, randomness can be ground to the certified top index and the
extracted WOTS key signs the root reconstructed from the hidden lower
layers. A native regression test constructs two verifying credentials without
using `SK.seed`. It does not publish them. This capability is for the
simulator's hidden credential witnesses, not a new public signing API or a
claim that publishing repeated WOTS signatures is safe.

The s/f labels in this mode select SPHINCS+ parameters, not VOLE profiles.
The proof inherits the pinned RISC0 backend's security assumptions and limits;
choosing a 192/256-bit credential does not raise RISC0's knowledge soundness.

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

### Issuer Setup anchor benchmark

Native regression tests cover all six parameters, fixed selection of FORS
trees zero and one, exactly one signing randomizer, shared-seed derivation
at distinct addresses, wrong seeds, public statement reconstruction, fixed
lengths, insufficient capacity, wrong public keys, and every certificate-byte
mutation:

```sh
bash scripts/test_issuer_seed_anchor.sh
```


Run double-FORS SDSA for all six standard SPHINCS+ parameter sets (three samples each):

```sh
ANCHOR_MODE=seed-anchor CREDENTIALS=sphincs ITERATIONS=3 bash scripts/benchmark_issuer_anchors.sh
```

Run the alternative full-WOTS proof for all six standard SPHINCS+ parameter sets:

```sh
ANCHOR_MODE=fixed-top-wots CREDENTIALS=sphincs ITERATIONS=3 scripts/benchmark_issuer_anchors.sh
```

The default is SHA-256 Composite with segment exponent 20. To use Succinct,
add `RISC0_RECEIPT_KIND=succinct`; no Identity wrapper is applied to this
fixed-workload Setup relation. To compare both Setup choices, use
`ANCHOR_MODE=all`. F-SPHINCS+ supports only `seed-anchor` and is selected explicitly.
Optional filters are `PARAMS_LIST="sha2-128s sha2-256s"` and
`CREDENTIALS=sphincs`; `SEGMENT_PO2` changes the segment exponent.

The SPHINCS+ seed-anchor log reports `anchor_construction=double-fors` and
`compression_blocks=2`. Every invocation writes a timestamped log under
`benchmarks/issuer_anchor/`;
`LOG_FILE` can select an explicit file (which is overwritten).
The persistent `~/.cache/sedaa-risc0-shared-target` is reused, never cleaned.
Fixed-WOTS mode builds the real guest even if `RISC0_SKIP_BUILD` was set.
Only changed guests/native code need rebuilding; CUDA/backend artifacts remain cached.
Compilation, process startup and negative tests are excluded from the
dedicated `pi_i_prover_ms`/`pi_i_verifier_ms` measurements. The seed-anchor
benchmark checks both outputs and both addresses against the native proof
verifier, and rejects an attempted proof with only the second output changed.
SDSA uses the
Rust proof wrapper timings; ATWC uses the in-process RISC0 timings. Reported
times are arithmetic means over `ITERATIONS`; proof/certificate sizes refer
to the first sample. The prepared circuit cache is reused across samples,
so `pi_i_prepare_ms` amortizes its first construction across those samples.
Proof size is the serialized VOLEith proof for SDSA, or the RISC0 receipt
including its public journal for ATWC;
certificate size is reported separately and excludes the already registered
issuer public key.

Select the same mode in a complete SHA protocol run:

```sh
export CARGO_TARGET_DIR="${HOME}/.cache/sedaa-risc0-shared-target"
SPHINCS_OPT_LEVEL=4 RISC0_RECEIPT_KIND=composite cargo run --release -p daa_cli -- \
  run-full --params sha2-128s --tpm-backend sha2 --proof-mode real \
  --issuer-anchor-mode fixed-top-wots --segment-po2 20
```

For a Setup/Join/TPM smoke test without a real host-signature proof, change
`--proof-mode real` to `--proof-mode real-tpm`; the selected Setup `pi_I`
still uses a real RISC0 proof. Benchmark randomness is deterministic and is
not a production key-generation configuration.

Run native reference, mutation and seed-free WOTS-capability tests for all six sets:

```sh
scripts/test_issuer_wots.sh
# Optional memory/undefined-behaviour checks:
SANITIZE=1 scripts/test_issuer_wots.sh
```

The test script automatically removes its temporary binaries without touching
any shared compilation cache.

### Complete host-proof benchmark

Run the 30 current SHA-2 host cases at segment size `2^20`:

```sh
SEGMENT_PO2=20 ITERATIONS=1 scripts/benchmark_host_sha2.sh
```

This covers:

- six Direct SPHINCS+ Succinct/Identity cases;
- six ZK-WOTS+ Composite and six ZK-WOTS+ Succinct cases; and
- six F-SPHINCS+ v3 Composite and six F-SPHINCS+ v3 Succinct cases,
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

### F-SPHINCS+ format-v3 checks and benchmarks

The new F-SPHINCS+ credential is an alternative under **Ours-3F plus one SHA-2
hook**. Select one of `128s,128f,192s,192f,256s,256f`, paired with the same
VOLEith parameter. Old independent k/security selectors and k=35/70 are removed.
The result tables below use the complete v3 measurements from 2026-09-09.

```sh
# Six native credentials, deterministic KATs, and six matching Setup proofs:
ITERATIONS=1 bash scripts/benchmark_fsphincs_native_setup.sh

# Six credentials x Composite/Succinct x the requested segment sizes:
SEGMENT_PO2_LIST="22 21 20" bash scripts/benchmark_fsphincs_host.sh

# One native test, with automatic binary cleanup:
make -C host_proof/methods/guest/c_src/fsphincs_ref test FSPHINCS_PARAMS=128f
```

Logs go to `benchmarks/fsphincs_v3/`; both scripts reuse
`~/.cache/sedaa-risc0-shared-target`. Root extraction proves `S_root` directly:
one anchor/two SHA-256 compressions at 128, two anchors/four compressions at
192/256. The compact public certificate uses shared aggregation paths.
Only H3 in the 256 sets changes to SHA-512, preserving its full intermediate
digest; all H3 expansions bind R and the full public key. Keys, credentials
and Setup certificates from previous formats must be regenerated.
See [the format specification](host_proof/methods/guest/c_src/fsphincs_ref/DESIGN.md)
for lengths, assumptions, bit indexing and independent-reference KAT coverage.

### Compatibility sweeps

`scripts/run_all_benchmarks.sh` retains the older monolithic 12-case full-DAA
sweep and accepts `--backend sha-256` or `--backend poseidon2`. The current
paper tables should instead be regenerated with the dedicated TPM, anchor,
and host scripts above because those scripts select the connected SHA-2 hook
relations explicitly.

## Current Benchmark Results

Times are **seconds**; KB means `bytes / 1024`. Host proof size is the
serialized receipt including its journal, not only the seal. Verification
uses the emitted microsecond measurements: Composite is displayed to three
decimal places and Succinct to five. Tiny public certificate checks retain
six decimals. Display rounding does not change the raw logs.

The F-SPHINCS+ v3 native/Setup and host measurements are complete single
runs from 2026-09-09. SPHINCS+ SDSA uses the latest three-iteration run from
2026-09-06; fixed-WOTS uses its latest single-sample run from that date.
Existing TPM and SPHINCS+ host results are retained from their respective
logs. These are different runs, not a fresh simultaneous benchmark of every
component. Compilation, startup, and negative/capability tests are excluded
from the reported per-proof/native timings.

### Credential setup

F-SPHINCS+ values come from the native v3 run. Existing SPHINCS+ credential
key-generation measurements are retained. These are credential keys only,
not TPM keys, proof parameters, or Setup extraction certificates.

| Credential | Parameter | Keygen (s) | PK (B) | SK (B) |
| --- | ---: | ---: | ---: | ---: |
| F-SPHINCS+ v3 | 128s | 1.34 | 76 | 108 |
| F-SPHINCS+ v3 | 128f | 0.248 | 124 | 156 |
| F-SPHINCS+ v3 | 192s | 2.08 | 98 | 130 |
| F-SPHINCS+ v3 | 192f | 0.391 | 170 | 202 |
| F-SPHINCS+ v3 | 256s | 2.77 | 118 | 150 |
| F-SPHINCS+ v3 | 256f | 0.477 | 212 | 244 |
| SPHINCS+ | 128s | 0.050 | 32 | 64 |
| SPHINCS+ | 128f | 0.001 | 32 | 64 |
| SPHINCS+ | 192s | 0.062 | 48 | 96 |
| SPHINCS+ | 192f | 0.001 | 48 | 96 |
| SPHINCS+ | 256s | 0.038 | 64 | 128 |
| SPHINCS+ | 256f | 0.002 | 64 | 128 |

### Setup-time issuer extraction proof

This is a separately replaceable building block. `Anchor gen.` excludes
credential key generation; SPHINCS+ includes its one reserved-message
signature, while F-SPHINCS+ constructs the root-node certificate directly.
Preparation is separate from proving; the prepared circuit is reused across
iterations. Certificate size excludes the registered issuer public key.

| Credential / seed anchor | Parameter = VOLEith | SHA-256 comp. | Anchor gen. (s) | Cert. verify (s) | Prepare (s) | Prove (s) | Verify (s) | Proof (KB) | Public cert. (KB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| F-SPHINCS+ / root-seed | 128s | 2 | 1.25 | 0.000009 | 0.026 | 0.027 | 0.021 | 56.70 | 0.703 |
| F-SPHINCS+ / root-seed | 128f | 2 | 0.220 | 0.000008 | 0.027 | 0.008 | 0.006 | 81.86 | 0.609 |
| F-SPHINCS+ / root-seed | 192s | 4 | 1.90 | 0.000016 | 0.053 | 0.071 | 0.060 | 162.74 | 1.234 |
| F-SPHINCS+ / root-seed | 192f | 4 | 0.327 | 0.000013 | 0.052 | 0.022 | 0.017 | 242.21 | 1.016 |
| F-SPHINCS+ / root-seed | 256s | 4 | 2.49 | 0.000016 | 0.052 | 0.113 | 0.108 | 227.22 | 1.234 |
| F-SPHINCS+ / root-seed | 256f | 4 | 0.431 | 0.000014 | 0.054 | 0.033 | 0.024 | 327.03 | 1.016 |
| SPHINCS+ / double-FORS | 128s | 2 | 0.296 | 0.000268 | 0.010 | 0.028 | 0.023 | 61.70 | 5.43 |
| SPHINCS+ / double-FORS | 128f | 2 | 0.015 | 0.000855 | 0.010 | 0.008 | 0.006 | 89.12 | 13.79 |
| SPHINCS+ / double-FORS | 192s | 2 | 0.554 | 0.000434 | 0.010 | 0.048 | 0.038 | 93.05 | 10.92 |
| SPHINCS+ / double-FORS | 192f | 2 | 0.026 | 0.001278 | 0.010 | 0.012 | 0.009 | 137.68 | 29.02 |
| SPHINCS+ / double-FORS | 256s | 2 | 0.482 | 0.000588 | 0.010 | 0.074 | 0.069 | 132.93 | 20.34 |
| SPHINCS+ / double-FORS | 256f | 2 | 0.050 | 0.001201 | 0.010 | 0.017 | 0.014 | 189.87 | 39.40 |

Sources: [F-SPHINCS+ root anchors](benchmarks/fsphincs_v3/setup_detail_20260909_014043.log)
and [SPHINCS+ double-FORS anchors](benchmarks/issuer_anchor/issuer_anchor_seed-anchor_composite_20260906_191550.log).

Equal compression counts do not imply equal Boolean circuits or proof sizes.
At 128, the F-SPHINCS+ two-compression circuit has 39,963 AND gates, versus
43,810 for the two SPHINCS+ compressions: their constant/public inputs,
chaining states and output constraints differ. The matching s/f profiles
change VOLE parameters, not which seed relation is proved.

#### Alternative fixed-top WOTS+ `pi_I` (SPHINCS+)

NVIDIA RTX 2000 Ada Generation, SHA-256 Composite, segment limit `2^20`,
backend revision `0079fe1882b123ff7239e0356ce5d8fb47f63795`.
All six cases use one segment. The outer verifier additionally checks the
public XMSS path and the journal; the private guest relation contains the
complete WOTS chains and WOTS public-key compression.

| SPHINCS+ | SHA-2 comp. | Anchor gen. (s) | Prove (s) | Verify (s) | Proof (KB) | Public cert. (KB) | User cycles | Total cycles |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 128s | 536 | 0.040 | 1.23 | 0.00163 | 251.73 | 0.172 | 136,567 | 262,144 |
| 128f | 536 | 0.001 | 1.20 | 0.00161 | 250.98 | 0.078 | 136,365 | 262,144 |
| 192s | 777 | 0.057 | 2.08 | 0.00176 | 264.42 | 0.250 | 399,124 | 524,288 |
| 192f | 777 | 0.001 | 2.13 | 0.00172 | 263.30 | 0.109 | 398,439 | 524,288 |
| 256s | 1025 | 0.037 | 3.47 | 0.00191 | 277.86 | 0.297 | 653,364 | 1,048,576 |
| 256f | 1025 | 0.003 | 3.60 | 0.00189 | 276.86 | 0.172 | 653,028 | 1,048,576 |

The totals include chain hashes, public-key compression and shared prefix
processing; at 192/256 they include both SHA-256 and SHA-512 blocks as
explained above. Public XMSS authentication-path hashes are excluded.
Source: [latest fixed-WOTS log](benchmarks/issuer_anchor/issuer_anchor_fixed-top-wots_composite_20260906_000205.log).
The s/f label selects the SPHINCS+ set, not a VOLE profile.

The retained [256f Succinct smoke test](benchmarks/issuer_anchor/fixed_top_wots_succinct_256f.log)
measured 6.884 s prove, 0.001453 s verify, 268.96 KB, and 653,028 user cycles,
without Identity. It is a separate single sample, not paired with the newest
Composite measurements. Composite remains the Setup script's default.

### Join protocol

The one-SHA-2 Join proof is shared by both TPM constructions and by both
credential schemes. Choose the same parameter label in the TPM and credential
tables; F-SPHINCS+ now has a one-to-one six-set mapping, not six VOLE profiles
crossed with six credential sets.

| VOLEith | Hash | Prove (s) | Verify (s) | Proof (KB) |
|---|---|---:|---:|---:|
| 128s | SHA-256 | 0.018 | 0.015 | 32.42 |
| 128f | SHA-256 | 0.004 | 0.003 | 46.54 |
| 192s | SHA-384 | 0.056 | 0.044 | 115.71 |
| 192f | SHA-384 | 0.012 | 0.010 | 171.66 |
| 256s | SHA-512 | 0.079 | 0.078 | 165.07 |
| 256f | SHA-512 | 0.019 | 0.016 | 236.62 |

| Credential | Parameter | Credential sign (s) | Credential verify (s) | Signature (KB) |
| --- | ---: | ---: | ---: | ---: |
| F-SPHINCS+ v3 | 128s | 9.35 | 0.001 | 81.84 |
| F-SPHINCS+ v3 | 128f | 1.69 | 0.002 | 173.50 |
| F-SPHINCS+ v3 | 192s | 14.48 | 0.002 | 122.75 |
| F-SPHINCS+ v3 | 192f | 2.60 | 0.003 | 261.66 |
| F-SPHINCS+ v3 | 256s | 18.14 | 0.002 | 159.94 |
| F-SPHINCS+ v3 | 256f | 3.13 | 0.004 | 341.28 |
| SPHINCS+ | 128s | 0.286 | 0.001 | 7.67 |
| SPHINCS+ | 128f | 0.014 | 0.001 | 16.69 |
| SPHINCS+ | 192s | 0.516 | 0.001 | 15.84 |
| SPHINCS+ | 192f | 0.022 | 0.001 | 34.83 |
| SPHINCS+ | 256s | 0.455 | 0.001 | 29.09 |
| SPHINCS+ | 256f | 0.046 | 0.002 | 48.69 |

F-SPHINCS+ values are from the [native v3 log](benchmarks/fsphincs_v3/native_setup_20260909_014043.log);
SPHINCS+ issuance timings are the retained paper measurements.
**Size basis:** this column consistently counts the raw credential signature
`sigma`, excluding `issuer_nonce` and transport metadata. Older SPHINCS+
tables included a nonce in the credential size. In the current SHA mode,
the complete credential also carries a 16/24/32-byte issuer nonce; the CLI
reports both `size.issuer_credential.sigma` and
`size.issuer_credential.total`.

### TPM signing proof

Both constructions use the same optimized SHA-2/VOLEith backend and matched
s/f profiles. These are joint proofs with shared witnesses and linked
intermediate wires, not five or three independent proofs.

| VOLEith | CDENW'23--Ours-5F prove (s) | CDENW'23--Ours-5F verify (s) | CDENW'23--Ours-5F proof (KB) | Ours-3F prove (s) | Ours-3F verify (s) | Ours-3F proof (KB) | Prove reduction | Proof reduction |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 128s | 0.064 | 0.053 | 178.63 | 0.033 | 0.030 | 91.73 | 48.1% | 48.6% |
| 128f | 0.021 | 0.016 | 259.20 | 0.010 | 0.008 | 132.81 | 52.1% | 48.8% |
| 192s | 0.247 | 0.223 | 552.82 | 0.134 | 0.119 | 334.46 | 45.9% | 39.5% |
| 192f | 0.073 | 0.062 | 827.32 | 0.036 | 0.030 | 499.79 | 51.0% | 39.6% |
| 256s | 0.449 | 0.432 | 920.80 | 0.206 | 0.192 | 470.75 | 54.1% | 48.9% |
| 256f | 0.120 | 0.105 | 1335.87 | 0.059 | 0.045 | 681.25 | 50.9% | 49.0% |

Source: [TPM comparison log](benchmarks/tpm_sha_ours3h_vs_chen23_5h.log).
At 128/192/256, the 5F relation requires 6/5/6 SHA compression blocks,
versus 3/3/3 for Ours-3F; the difference includes message padding, not only
the number of named functions.

### Host proof at segment size `2^20`

**Every row uses Ours-3F plus one SHA-2 hook.** F-SPHINCS+ is the credential
alternative, not the old two-hook 5F configuration. Direct SPHINCS+ uses
Succinct plus Identity; ZK-WOTS+ and F-SPHINCS+ use no Identity.
`Not applicable` is an intentionally unmeasured Direct Composite mode.

| Host construction | Parameter | Composite prove (s) | Composite verify (s) | Composite proof (KB) | Succinct prove (s) | Succinct verify (s) | Succinct proof (KB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| F-SPHINCS+ v3 | 128s | 10.96 | 0.004 | 825.12 | 27.25 | 0.00087 | 267.79 |
| F-SPHINCS+ v3 | 128f | 22.49 | 0.008 | 1899.48 | 66.39 | 0.00078 | 268.16 |
| F-SPHINCS+ v3 | 192s | 18.00 | 0.006 | 1374.84 | 48.76 | 0.00080 | 268.08 |
| F-SPHINCS+ v3 | 192f | 35.17 | 0.014 | 2748.98 | 100.97 | 0.00080 | 268.64 |
| F-SPHINCS+ v3 | 256s | 21.64 | 0.007 | 1649.84 | 59.31 | 0.00079 | 268.36 |
| F-SPHINCS+ v3 | 256f | 43.43 | 0.015 | 3548.70 | 128.53 | 0.00079 | 269.10 |
| Direct SPHINCS+ | 128s | Not applicable | Not applicable | Not applicable | 9.712 | 0.00077 | 267.44 |
| Direct SPHINCS+ | 128f | Not applicable | Not applicable | Not applicable | 18.619 | 0.00077 | 267.44 |
| Direct SPHINCS+ | 192s | Not applicable | Not applicable | Not applicable | 71.022 | 0.00081 | 267.69 |
| Direct SPHINCS+ | 192f | Not applicable | Not applicable | Not applicable | 112.685 | 0.00078 | 267.69 |
| Direct SPHINCS+ | 256s | Not applicable | Not applicable | Not applicable | 101.234 | 0.00078 | 267.94 |
| Direct SPHINCS+ | 256f | Not applicable | Not applicable | Not applicable | 141.167 | 0.00081 | 267.94 |
| ZK-WOTS+ | 128s | 4.545 | 0.002 | 513.75 | 14.626 | 0.00079 | 267.44 |
| ZK-WOTS+ | 128f | 11.416 | 0.005 | 1063.18 | 35.234 | 0.00080 | 267.44 |
| ZK-WOTS+ | 192s | 28.106 | 0.010 | 2198.60 | 78.629 | 0.00080 | 267.69 |
| ZK-WOTS+ | 192f | 49.584 | 0.018 | 4062.79 | 147.892 | 0.00078 | 267.69 |
| ZK-WOTS+ | 256s | 40.508 | 0.015 | 3284.77 | 118.326 | 0.00084 | 267.94 |
| ZK-WOTS+ | 256f | 61.119 | 0.022 | 4933.06 | 180.533 | 0.00079 | 267.94 |

Sources: [F-SPHINCS+ v3 host log](benchmarks/fsphincs_v3/host_20260909_015334.log)
and [SPHINCS+ host TSV](benchmarks/host_sha2/host_sha2_all_20260904-012627.tsv).
Only the `direct` and `zkwots` rows of the older TSV are used here; its
old-format F-SPHINCS+ rows are superseded.

### F-SPHINCS+ v3 segment-size sweep

The same six sets and one-hook relation were measured at all three segment
limits, with one Composite and one Succinct run per case (36 proofs total).
The `2^20` results above are repeated here to show the complete sweep.

| Segment limit | Parameter | Composite prove (s) | Composite verify (s) | Composite proof (KB) | Succinct prove (s) | Succinct verify (s) | Succinct proof (KB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2^22 | 128s | 93.28 | 0.001 | 312.75 | 99.52 | 0.00076 | 267.79 |
| 2^22 | 128f | 112.55 | 0.002 | 611.90 | 122.42 | 0.00087 | 268.16 |
| 2^22 | 192s | 99.61 | 0.002 | 574.82 | 108.20 | 0.00079 | 268.08 |
| 2^22 | 192f | 166.07 | 0.003 | 924.16 | 189.33 | 0.00077 | 268.64 |
| 2^22 | 256s | 120.43 | 0.002 | 612.11 | 130.72 | 0.00078 | 268.36 |
| 2^22 | 256f | 225.62 | 0.003 | 937.62 | 243.18 | 0.00079 | 269.10 |
| 2^21 | 128s | 33.08 | 0.002 | 574.46 | 51.03 | 0.00076 | 267.79 |
| 2^21 | 128f | 60.87 | 0.003 | 897.68 | 77.92 | 0.00078 | 268.16 |
| 2^21 | 192s | 50.53 | 0.003 | 873.54 | 66.54 | 0.00080 | 268.08 |
| 2^21 | 192f | 103.68 | 0.005 | 1495.72 | 134.46 | 0.00080 | 268.64 |
| 2^21 | 256s | 68.77 | 0.003 | 897.88 | 85.40 | 0.00079 | 268.36 |
| 2^21 | 256f | 122.84 | 0.006 | 1794.95 | 161.13 | 0.00089 | 269.10 |
| 2^20 | 128s | 10.96 | 0.004 | 825.12 | 27.25 | 0.00087 | 267.79 |
| 2^20 | 128f | 22.49 | 0.008 | 1899.48 | 66.39 | 0.00078 | 268.16 |
| 2^20 | 192s | 18.00 | 0.006 | 1374.84 | 48.76 | 0.00080 | 268.08 |
| 2^20 | 192f | 35.17 | 0.014 | 2748.98 | 100.97 | 0.00080 | 268.64 |
| 2^20 | 256s | 21.64 | 0.007 | 1649.84 | 59.31 | 0.00079 | 268.36 |
| 2^20 | 256f | 43.43 | 0.015 | 3548.70 | 128.53 | 0.00079 | 269.10 |

Guest execution is shared by the Composite and Succinct cases. Total cycles
include padding/paging/reserved work; they are not the recursion-circuit
workload. Each cell below reports `total cycles / segment count`.

| Parameter | Guest user cycles | 2^22 total / segments | 2^21 total / segments | 2^20 total / segments |
| --- | ---: | ---: | ---: | ---: |
| 128s | 2,886,285 | 4,194,304 / 1 | 3,145,728 / 2 | 3,145,728 / 3 |
| 128f | 6,091,031 | 6,291,456 / 2 | 6,291,456 / 3 | 6,553,600 / 7 |
| 192s | 4,572,815 | 4,718,592 / 2 | 5,242,880 / 3 | 5,242,880 / 5 |
| 192f | 9,538,295 | 10,485,760 / 3 | 10,485,760 / 5 | 10,485,760 / 10 |
| 256s | 5,782,144 | 6,291,456 / 2 | 6,291,456 / 3 | 6,291,456 / 6 |
| 256f | 11,903,761 | 12,582,912 / 3 | 12,582,912 / 6 | 12,845,056 / 13 |

The Succinct **seal** is 272,780 bytes in all these F-SPHINCS+ runs.
Serialized receipt size varies with the public journal/parameter, but is
constant across segment limits for a fixed set. Smaller segments reduce
Composite proving time here but add lift/join work; this sweep does not
establish that further segmentation will always be faster.

### Benchmark artifacts and checks

Canonical inputs for the tables above:

- [TPM Join and 5F/3F comparison](benchmarks/tpm_sha_ours3h_vs_chen23_5h.log).
- [SPHINCS+ SDSA, latest three-iteration run](benchmarks/issuer_anchor/issuer_anchor_seed-anchor_composite_20260906_191550.log).
- [SPHINCS+ fixed-WOTS, latest six-case run](benchmarks/issuer_anchor/issuer_anchor_fixed-top-wots_composite_20260906_000205.log).
- [SPHINCS+ host log](benchmarks/host_sha2/host_sha2_all_20260904-012627.log)
  and [TSV](benchmarks/host_sha2/host_sha2_all_20260904-012627.tsv).
- [F-SPHINCS+ v3 native, KAT and capability tests](benchmarks/fsphincs_v3/native_setup_20260909_014043.log).
- [F-SPHINCS+ v3 Setup details](benchmarks/fsphincs_v3/setup_detail_20260909_014043.log).
- [F-SPHINCS+ v3 all host cases](benchmarks/fsphincs_v3/host_20260909_015334.log).

Use complete logs with all expected rows and successful proof verification;
incomplete or failed trial logs are not measurement sources. Deterministic
KAT manifests live in
[`fsphincs_ref/kat/`](host_proof/methods/guest/c_src/fsphincs_ref/kat/).
For new measurements, record the DAA commit, pinned backend revision, GPU,
CUDA version, segment exponent, receipt kind, Identity setting, and iteration
count. Never average compilation time into prover time or use deterministic
benchmark randomness for production keys.
