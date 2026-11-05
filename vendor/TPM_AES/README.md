# TPM Block-Cipher Proof Backend

FAEST-derived VOLEith proofs support AES Join (1F) and Signing (3F) for
128s/f, 192s/f, and 256s/f, plus Rijndael-256 Davies–Meyer Join and Signing
for 128s/f. Rijndael uses 256-bit keys and blocks with 128-bit proof parameters.
The Cargo build compiles this backend; Meson provides native benchmark targets.
Cargo uses the headers in `include/` and generates C sources from the templates
into its build output directory. Meson generates its own headers and C sources.
See the [main README](../../README.md) for commands.
