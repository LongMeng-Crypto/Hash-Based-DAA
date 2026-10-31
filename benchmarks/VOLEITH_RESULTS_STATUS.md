# VOLEith result status

Corrected validation and smoke outputs: `voleith_soundness_v1/`.
Existing TPM-SHA, SHA-backed issuer-anchor, and complete-DAA logs created
before this correction contain the vulnerable Boolean encoding and are
historical only. Regenerate their VOLEith proofs and rerun measurements
before using them as corrected baselines. Native TPM_AES/DM and Host-only
RISC0 measurements are separate paths and are not invalidated by this bug.
See ../docs/voleith_soundness_v1.md for coverage and rebuild commands.
