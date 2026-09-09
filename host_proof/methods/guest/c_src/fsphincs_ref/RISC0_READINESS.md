# RISC0 guest, format v3

The six sets in DESIGN.md share one streaming verification implementation.
All tree verification uses the existing SHA-256 syscall path. Only H3 in the
256 sets and the 192/256 SHA hooks use software SHA-512-family operations;
RISC0 v3 has no SHA-512 syscall. No backend fork or shared-cache change is needed.

The largest per-layer signature buffer is 49,920 bytes (256f), not a complete
credential. Verification allocates no heap tree, keeps fixed k/d/h loop bounds,
reuses hash/address buffers and swaps 32-byte states. H3 streams message data
through a 64/128-byte buffer, retains its full digest, and reuses expansion
prefix state. Host and Guest use the same generated constants, including
ceil(k*d/8). Setup, secret derivation and signing are excluded from the Guest.

The journal binds success, hk and the issuer public key; the parameter-specific
image ID binds the verification program. Ours-3F checks the SHA-2 hook over the
same et and s as the TPM relation and verifies the credential over et || nonce.
Historical AES and CDENW'23 two-hook code paths remain available explicitly;
the new six-set benchmark selects only the one-SHA hook.

Native profiling reports SHA-256 and SHA-512 compression counts separately.
Prefix reuse is counted as actual executed work, not repeated logical input
length. For one M-FORS layer, A=next_power_of_two(k), m=ceil(k*d/8):

- k leaf hashes (2 SHA-256 compressions each);
- k*d + A-1 tree hashes (3 each);
- A-k deterministic padding roots (2 each);
- 1+ceil(m/32) H2 hashes (2 each).

H3 is counted separately because its work depends on message/key length.
The old k=35/70 AES-hook measurements do not describe this format.

Execution-only smoke test, without GPU proving:

```sh
FSPHINCS_EXECUTE_ONLY=1 RECEIPT_LIST=composite \
  bash scripts/benchmark_fsphincs_host.sh
```

A normal Host run proves and verifies the receipt and checks the entire public
journal. Exact execution/proof times must be remeasured for the new images.
