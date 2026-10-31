# VOLEith soundness correction (v1)

The Boolean QuickSilver adapters in vendor/TPM_SHA had the same degree/mask
mismatch as the standalone VOLEith repository: a malicious prover could fold
an invalid quadratic residual into the transmitted a2 coefficient. The fix
raises quadratic checks by X into the degree-3 FAEST envelope; the verifier
raises the aggregated constraint hash by delta before adding the masks.

Coverage of real proof paths:

| Component | Path | Action |
| --- | --- | --- |
| TPM Join, one F | TPM_SHA generic backend | corrected v4 |
| TPM Sign, Ours-3H | same backend, shared secret wires | corrected v4 |
| TPM Sign, Chen23-5H comparison | same backend | corrected v4 |
| SPHINCS+ issuer setup seed anchors | issuer_anchor_nizk -> same backend | corrected v4 |
| F-SPHINCS+ issuer setup seed anchors | issuer_anchor_nizk -> same backend | corrected v4 |
| Legacy SHA-256 adapter | independent source snapshot | corrected, VSH256 v3 |
| AES-128-DM Join/Sign; legacy AES-192/256 | TPM_AES native FAEST constraints | already raises quadratic checks; arithmetic retained and retested |
| Rijndael-256-DM experiment | same native FAEST template | arithmetic retained and retested |

The C API, Rust FFI, standalone benchmark, and DAA_FULL experiments all link
the vendored sources. Cargo's existing rerun-if-changed directory dependency
rebuilds the Rust static libraries, so updating only ~/VOLEith is not sufficient.
VBCZK v1/v2/v3 proofs are rejected; there is no compatibility fallback.
Regenerate old SHA-based Join/Sign/setup proofs. Host-only RISC0 computation
and native AES measurements are not affected by this particular adapter bug.

The standalone regression suite has 195 assertions: it tests malicious a2
absorption against the actual Join/3H/5H and both setup circuits at every
security/profile; setup C-API positive/negative/version-binding cases; and
historical forgeries. Existing Join/Sign/Chen23 deterministic KATs are
regenerated from v4 proofs after successful independent verification.

Commands (from DAA_FULL):

```bash
meson setup --reconfigure ~/.cache/sedaa-tpm-sha-relations vendor/TPM_SHA --buildtype=release
meson test -C ~/.cache/sedaa-tpm-sha-relations --print-errorlogs
CARGO_TARGET_DIR=$HOME/.cache/sedaa-risc0-shared-target cargo test --offline -p daa_core --lib -- --test-threads=1
ITERATIONS=20 bash scripts/benchmark_tpm_sha_relations.sh
```

The task's validation logs and corrected smoke measurements are in
../benchmarks/voleith_soundness_v1/. Historical SHA-based benchmark logs
predating this fix are performance records only, not corrected soundness
baselines. They are preserved rather than silently overwritten.
