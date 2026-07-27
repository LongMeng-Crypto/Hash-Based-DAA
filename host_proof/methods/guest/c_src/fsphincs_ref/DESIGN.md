# F-SPHINCS+-SHA256 experimental reference implementation

This directory implements Section 3.1 (`F-SPHINCS+ and M-FORS`) of
*Hash-Based Direct Anonymous Attestation* (PQCrypto 2023).

The protocol parameters follow the paper's two concrete configurations:

| symbol | value |
|---|---:|
| `n` | 256 bits |
| `d` | 16 |
| `k` | 35 (`FSPHINCS_SECURITY=128`) or 70 (`=256`) |
| `q` | 1024 |
| `h` | 6 |
| leaf space | `q^h = 2^60` |

The 128/256 build labels track the paper's two concrete MPCitH-soundness
configurations. They do not replace a separate concrete EU-CMA analysis of
this SHA-256 credential instantiation.

The paper describes tweakable `H1`, expanding `H2`, message hash `H3`, and a
PRF abstractly, and its prototype instantiates symmetric primitives with
LowMC. This implementation substitutes SHA-256:

- all calls are domain separated and include a canonical 32-byte address;
- `H2` and `H3` use counter-mode SHA-256 expansion;
- `H2` emits exactly `k*d = 560/1120` bits, as required for a child M-FORS public
  key to be signed by its parent;
- `H3(msg || gr)` emits `k*d + h*log2(q) = 620/1180` bits, matching the
  paper's `mHash` definition;
- the M-FORS roots are accumulated in a 64/128-leaf binary tree; unused
  leaves are deterministic domain-separated padding leaves.

Those byte-level choices are implementation conventions because the paper
abstracts them away. They are not claimed as a standardized parameter set.

## Encodings

- Integers in hash addresses are big endian.
- M-FORS message indices are consecutive 16-bit big-endian values.
- The H3 leaf index is the first 60 bits following the 560-bit message digest.
- `pk = PUB_SEED[32] || root_MFORS_public_value[70/140]`.
- `sk = MASTER_SEED[32] || PUB_SEED[32] || root_public_value[70/140]`.
- `signature = randomizer[32] || sigma_0 || ... || sigma_h`.
- Each M-FORS signature is 35/70 repetitions of
  `revealed_secret[32] || authentication_path[16][32]`.

The implementation generates nodes on demand from `MASTER_SEED`; it never
materializes the `2^60`-leaf hypertree.

## Native benchmark

From this directory run:

```sh
make benchmark FSPHINCS_SECURITY=128
make benchmark FSPHINCS_SECURITY=256
```

The benchmark measures key generation, signing, and verification separately,
then flips one signature bit and requires verification to reject it. The
generated benchmark executable is removed automatically when the command
finishes, including when the test exits with an error.

Enable and run all native regression checks with:

```sh
make test FSPHINCS_SECURITY=128
make test FSPHINCS_SECURITY=256
```

`make kat` uses a fixed 64-byte seed, fixed 32-byte signature randomizer, and
fixed message. It pins SHA-256 digests of the complete public key, secret key,
133,312/266,592-byte signature, the selected 60-bit leaf index, and all seven
recovered M-FORS public values. Its generated executable is also removed
automatically.

See `RISC0_READINESS.md` for the guest-integration audit and exact verifier
hash workload.
