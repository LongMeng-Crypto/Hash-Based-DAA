# F-SPHINCS+ SHA-2 reference, format v3

This is an experimental instantiation of the M-FORS hierarchy in *Hash-Based
Direct Anonymous Attestation* (PQCrypto 2023), not a standardized SPHINCS+ set.
The six names are target-security benchmark labels, not a claim that testing
establishes a complete concrete unforgeability bound.

## Canonical parameter sets

| Set | d | k | H3 | Root anchors | Secret SHA-256 compressions |
|---|---:|---:|---|---:|---:|
| 128s | 16 | 22 | SHA-256 | 1 | 2 |
| 128f | 12 | 61 | SHA-256 | 1 | 2 |
| 192s | 16 | 33 | SHA-256 | 2 | 4 |
| 192f | 12 | 92 | SHA-256 | 2 | 4 |
| 256s | 16 | 43 | SHA-512 | 2 | 4 |
| 256f | 12 | 120 | SHA-512 | 2 | 4 |

All sets use n=32 bytes, q=1024, h=6. `parameter_sets.h` is the source
for both C and the Host/Guest Rust build helper. Select `FSPHINCS_PARAMS`;
the old independent security/k selectors, including k=35/70, are rejected.
DAA pairs each credential with the same VOLEith security/profile label.

## Encoding and H3

Let b=k*d and m=ceil(b/8). Integers in addresses and counters are big endian.
Every 32-byte address includes domain, format version, security/profile, d, k,
layer, node, inner-tree index, height and position. The format is incompatible
with previous credentials/certificates; keys and signatures must be regenerated.

- Public key: PUB_SEED[32] || root_MFORS_public_value[m].
- Secret key: MASTER_SEED[32] || public_key.
- Signature: R[32] || seven M-FORS signatures, each k*(d+1)*32 bytes.
- M-FORS indices: consecutive MSB-first groups of exactly d bits.
- The unused low bits of the final public-value byte are zero and checked.
- The 60-bit H3 node index starts at bit b, **not** at byte m. Thus 128f
  uses the low nibble of the last digest byte as the start of its node index.

For SHA-X chosen above, define the nine-byte context as
`07 || 03 || BE16(security) || fast || d || k || h || log2(q)`.
Compute:

```text
digest = SHA-X(context || R || full_public_key || message)
prefix = 08 || context[1:] || R || full_public_key || digest
stream = SHA-X(prefix || BE32(0)) || SHA-X(prefix || BE32(1)) || ...
```

Use the first b bits as the M-FORS message, then the next 60 as the node index.
The 256 sets preserve **all 64 digest bytes** in prefix. SHA-512 is not truncated
to 32 bytes before expansion. The expansion reuses a public-prefix hash state
without changing the result. H1, H2, and seed derivation still use SHA-256.

## Setup root-seed capability

The witness is the 32-byte seed S_root of layer 0, node 0. Its derivation from
MASTER_SEED happens outside the proof. The proof enforces
`x_i = SHA-256(S_root || ADRS_i)` using one shared S_root and distinct fixed
addresses: tree 0, leaf 0; additionally tree 1, leaf 0 for double anchors.
A 64-byte preimage requires **two SHA-256 compressions**, including padding.

The public certificate contains a 16-byte versioned, parameter-bound header,
each selected x_i and its d sibling nodes, then a shared aggregation path.
For two anchors the roots of trees 0/1 are combined first, saving one sibling
per individual path. Other tree roots are not published individually.
Public verification hashes x_i to its leaf, follows both paths, applies H2,
and checks the registered root public value.

Certificate sizes are respectively 720, 624, 1264, 1040, 1264, 1040 bytes.
VOLEith's relation kind is 3; old F-SPHINCS+ kind 2 proofs are rejected.
The proof context binds the complete certificate and issuer public key.
The adapter also reconstructs the fixed PRF addresses and disclosed endpoints
from that authenticated certificate before checking the VOLEith proof, so an
unrelated seed proof cannot be attached to a valid certificate.

This small proof does not enforce that *every* secret in the top M-FORS node
was derived from the proved seed. The root-node seed-consistency assumption
and the relevant jointly addressed PRF-binding assumption remain part of the
security argument. No consistency with seeds of lower nodes is required:
`fsphincs_sign_with_root_seed` constructs lower layers from an independent
seed and completes the last layer with S_root. The test clears the original
master and verifies two fresh credentials. This tests the capability, not
an implementation of a cryptographic extractor.

## Tests and benchmarks

From this directory:

```sh
make benchmark FSPHINCS_PARAMS=128f
make kat FSPHINCS_PARAMS=256f
```

The benchmark includes positive/negative verification and root-capability tests
outside measured intervals. Each Make target removes its generated executable.
`kat.c` emits deterministic full fixtures; `test_reference.py` independently
checks H3 with hashlib, exact bit parsing, all seven signature layers and the
compact certificate, then compares committed manifests in `kat/`.
KAT fingerprints lock keys, signature, certificate, root seed, anchor outputs,
node index and all recovered layer values. `KAT_ARGS=--emit` prints reviewed
candidate fingerprints but never overwrites committed vectors.

From DAA_FULL:

```sh
ITERATIONS=1 bash scripts/benchmark_fsphincs_native_setup.sh
SEGMENT_PO2_LIST="22 21 20" bash scripts/benchmark_fsphincs_host.sh
```

Native/Setup has six paired rows, not 36 combinations. Host has six rows for
each receipt kind and segment size, with Ours-3F and one SHA-2 hook throughout.
Both scripts retain timestamped logs in `benchmarks/fsphincs_v3`; Host reuses
`~/.cache/sedaa-risc0-shared-target`. Benchmark randomness is deterministic
for reproducibility and must not be used for production key generation.
