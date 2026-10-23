# F-SPHINCS+ SHA-2 reference, cached-prefix H1 v6 / leaf PRF v4

This is an experimental instantiation of the M-FORS hierarchy in *Hash-Based
Direct Anonymous Attestation* (PQCrypto 2023), not a standardized SPHINCS+ set.
The six names are target-security benchmark labels, not a claim that testing
establishes a complete concrete unforgeability bound.

## Canonical parameter sets

| Set | d | k | H3 | Root anchors | Secret SHA-256 compressions |
|---|---:|---:|---|---:|---:|
| 128s | 16 | 22 | SHA-256 | 1 | 1 |
| 128f | 12 | 61 | SHA-256 | 1 | 1 |
| 192s | 16 | 33 | SHA-256 | 2 | 2 |
| 192f | 12 | 92 | SHA-256 | 2 | 2 |
| 256s | 16 | 43 | SHA-512 | 2 | 2 |
| 256f | 12 | 120 | SHA-512 | 2 | 2 |

All sets retain 32-byte seeds, leaf secrets and randomizers, q=1024, h=6.
H1 outputs and authentication nodes are 16/24/32 bytes for 128/192/256.
`parameter_sets.h` is the source
for both C and the Host/Guest Rust build helper. Select `FSPHINCS_PARAMS`;
the old independent security/k selectors, including k=35/70, are rejected.
DAA pairs each credential with the same VOLEith security/profile label.

## Encoding and H3

Let b=k*d and m=ceil(b/8). Integers in addresses and counters are big endian.
The node PRF and H2 retain their 32-byte address encodings. H1 uses an injective
16-byte address: `domain || 06 || parameter_id || layer || node_be[8] || tree ||
height || index_be[2]`. The fixed parameter registry binds security/profile/d/k.
Bounds are layer <= 6, node < 1024^layer, tree < aggregation capacity,
height <= d and index <= 65535; these fields are not truncated digests.

H1 is the first node_bytes of
`SHA256(PUB_SEED[32] || zero[32] || H1_address[16] || payload)`.
An explicit per-operation context absorbs the first 64 bytes once. Each hash
then starts from that cached state; SHA's final bit length includes those 64
bytes. Padding is prepared once per verification path/aggregation loop.
The aligned suffix reaches the guest SHA syscall directly in one batch:
one block for leaf hashes, one/two/two for binary nodes at 128/192/256.
Native and streaming guest verification share the same code and precomputed
context, with no mutable cross-key cache. `FSPHINCS_H1_REFERENCE` instead hashes
the complete preimage through ordinary SHA for differential KAT testing.

Node PRF, H2 and H3 algorithms remain unchanged; leaf expansion retains v4.
For identical master/public seeds, PRF-derived seeds and secrets stay identical.
H2 accepts the selected node width but retains its full output and expansion.
Regenerate keys, credentials and certificates for all six sets: H1 v6 changes
public roots even where serialized lengths stay equal. Certificates use version
6, and guest images must match. Previous KAT manifests remain in legacy_pre_v6.

- Public key: PUB_SEED[32] || root_MFORS_public_value[m].
- Secret key: MASTER_SEED[32] || public_key.
- Signature: R[32] || seven M-FORS signatures, each k*(32+d*node_bytes) bytes.
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

## Compact leaf PRF

`PRF_node` is unchanged: SHA-256(master[32] || old_address[32]), retaining all
32 output bytes. `PRF_leaf` is SHA-256(node_seed[32] || leaf_address[16]), also
retaining all 32 output bytes. The 16-byte address is:

```text
02 || 04 || parameter_id[1] || layer[1] || node_be[8] || tree[1] || leaf_be[2] || 00
```

Parameter IDs 0..5 correspond to 128s, 128f, 192s, 192f, 256s, 256f.
Each ID binds a complete entry in the fixed registry. The leaf PRF's old height
field was always zero and is omitted. The encoder rejects layer > 6,
node >= 1024^layer, tree >= k, or leaf >= 2^d before narrowing any integer.
These bounds make the encoding injective on all supported leaf positions;
it is not truncation of an address digest. Node index needs at most 60 bits,
tree at most 7 bits, and leaf at most 16 bits. The type/version/set fields retain
domain and parameter separation. The 48-byte preimage, 0x80, seven zero bytes
and the 8-byte bit length fit exactly one standard SHA-256 compression block.
This changes the concrete PRF input encoding, not its key/output widths or the
existing PRF/binding assumptions; testing does not constitute a security proof.

## Setup root-seed capability

The witness is the 32-byte seed S_root of layer 0, node 0. Its derivation from
MASTER_SEED happens outside the proof. The proof enforces
`x_i = SHA-256(S_root || ADRS_i)` using one shared S_root and distinct fixed
addresses: tree 0, leaf 0; additionally tree 1, leaf 0 for double anchors.
Each 48-byte preimage requires **one SHA-256 compression**, including padding.

The public certificate contains a 16-byte versioned, parameter-bound header,
each selected x_i and its d sibling nodes, then a shared aggregation path.
For two anchors the roots of trees 0/1 are combined first, saving one sibling
per individual path. Other tree roots are not published individually.
Public verification hashes x_i to its leaf, follows both paths, applies H2,
and checks the registered root public value.

Certificate sizes are respectively 384, 336, 968, 800, 1264, 1040 bytes.
The certificate version is 6 for all profiles (kind remains 3).
VOLEith's relation kind is 4; old F-SPHINCS+ kind 2/3 proofs are rejected.
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
H1 truncation targets ordinary signature unforgeability under addressed-target
hash assumptions; it is not a claim of 128/192/256-bit collision resistance for H1.
In particular, malicious-issuer Setup-certificate binding is a separate proof
obligation, not established by a shorter signature or a passing capability test.

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
KAT fingerprints lock keys, signature, certificate, root seed, compact addresses,
anchor outputs, node index and all recovered layer values. Tests pin the old node
PRF root-seed fingerprints, check every signature secret against independent
hashlib derivation, exhaust local address positions and reject out-of-range fields.
Historical 128-bit manifests in `kat/legacy_h1_v3/` also check that root seeds,
anchor outputs and addresses remain unchanged while public artifacts change.
`KAT_ARGS=--emit` prints reviewed
candidate fingerprints but never overwrites committed vectors.

From DAA_FULL:

```sh
RUN_SETUP=1 ITERATIONS=3 \
  bash scripts/benchmark_fsphincs_native_setup.sh
SEGMENT_PO2_LIST="22 21 20" \
  RECEIPT_LIST="composite succinct" bash scripts/benchmark_fsphincs_host.sh
```

Native/Setup has six paired rows, not 36 combinations. Host has six rows for
each receipt kind and segment size, with Ours-3F and one SHA-2 hook throughout.
Both scripts retain new timestamped logs in `benchmarks/fsphincs_h1_v6`;
historical results are not overwritten. Host reuses
`~/.cache/sedaa-risc0-shared-target`. Benchmark randomness is deterministic
for reproducibility and must not be used for production key generation.

Rerun all six native, Setup and Host configurations. For the native benchmark's
48-byte message, the six SHA-256 compression counts are respectively
2955, 6081, 8788, 18228, 11019, 22933, including one public-prefix compression.
The last two also execute 6 and 8 SHA-512 compressions in H3. Signature sizes
are 44384, 95680, 96128, 206112, 163776, 349472 bytes. Key sizes are unchanged.
The secret-dependent leaf PRF still requires one compression per anchor.

Set `RUN_SETUP=1` to also rerun the paired Setup benchmarks. Certificate size and
its public verification cost change; the VOLEith relation/circuit and proof length
do not. Fresh proofs must nevertheless bind the new certificate and public key.
