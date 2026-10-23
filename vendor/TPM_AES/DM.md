# DAA AES-128-DM relation (v1)

Only the 128s/128f DAA profiles use the updated relation:

```text
Join: et  = AES_sk(gid) XOR gid
Sign: slt = AES_sk(lid) XOR lid
      et  = AES_sk(gid) XOR gid
      hk  = AES_s(et)   XOR et
```

Join discloses gid and et and proves knowledge of sk. Sign discloses gid, lid,
slt and hk; sk, s and et are witnesses. Both occurrences of sk share one
witness, and the hidden et is shared by its derivation and the hook relation.
The existing DAA Host AES-128 hook verifies the same hk relation.

The AES constraints receive the raw ciphertext (DM output XOR input).
The prover and verifier apply the same XOR to the authenticated values:
the hidden et contribution to the hk output is included, not treated as a
public constant. These are linear operations, so the nonlinear constraints
and serialized proof lengths are unchanged. The Fiat--Shamir transcript
binds the `DAA-AES128-DM-v1` label and the relation dimensions/profile;
old plain-AES proofs are not interchangeable with these proofs.

`daa_aes128_dm` wraps the unchanged raw AES implementation. Internal AES-CTR,
VOLE generation, AES-192/256 DAA profiles, Rijndael-256-DM and TPM_SHA are
unchanged. Cargo renders the current C templates into OUT_DIR rather than
compiling stale Meson-generated C snapshots.

## Tests and measurements

From DAA_FULL:

```sh
PARAMETERS="128s,128f" PHASES="join,sign" ITERATIONS=20 \
  bash scripts/benchmark_tpm_aes_vole.sh
meson compile -C "$HOME/.cache/sedaa-tpm-aes-vole" daa_aes_dm_test
meson test -C "$HOME/.cache/sedaa-tpm-aes-vole" daa-aes128-dm --print-errorlogs
```

The test checks the AES known-answer vector, the DM XOR and aliasing behavior,
both s/f profiles, altered public outputs, hidden-et consistency, and rejection
of proofs constructed using the old plain-AES output relation.

Timestamped results go to `benchmarks/tpm_aes_dm_v1`; previous measurements are
not replaced. The persistent build directory is reused. This change defines
and tests the DM relation; it is not a claim that a 128-bit-block DM function
has 128-bit collision resistance or establishes full DAA security.
