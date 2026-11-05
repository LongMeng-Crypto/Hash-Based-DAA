# F-SPHINCS+ Format

The parameter registry in `parameter_sets.h` is shared by native and guest builds.
All profiles use 32-byte master/node seeds, q=1024, h=6, and seven M-FORS layers.

| Profile | d | k | Leaf/node bytes | H3 |
| --- | ---: | ---: | ---: | --- |
| 128s | 16 | 22 | 16 | SHA-256 |
| 128f | 12 | 61 | 16 | SHA-256 |
| 192s | 16 | 33 | 24 | SHA-256 |
| 192f | 12 | 92 | 24 | SHA-256 |
| 256s | 16 | 43 | 32 | SHA-512 |
| 256f | 12 | 120 | 32 | SHA-512 |

H1 caches the SHA-256 state after the 64-byte public-seed prefix and uses an
injective 16-byte address. Leaf PRFs hash a 32-byte node seed and a 16-byte
address, retaining the selected leaf width. Node-seed derivation retains
32-byte outputs. H3 binds the randomizer and complete public key, consumes
exactly k*d message bits followed immediately by a 60-bit node index, and
retains the complete SHA-512 intermediate digest for 256-bit profiles.

Public keys encode the 32-byte public seed and the root M-FORS public value.
Secret keys prepend the 32-byte master seed. Credentials encode a 32-byte
randomizer and seven M-FORS layers. Certificates carry format version 7; H1
addresses carry version 6 and leaf-PRF addresses carry version 7. Applications
must pin these formats because credential lengths alone do not identify them.

Issuer certificates authenticate two distinct-address leaf PRF endpoints under
one root-node seed. The VOLEith proof checks the two PRFs and binds the full
certificate and issuer key. Tree-wide seed consistency and concrete
malicious-issuer binding remain security assumptions; passing implementation
tests does not establish an extractor or a complete unforgeability theorem.

`make test FSPHINCS_PARAMS=128s` runs native negative tests and deterministic
vectors checked against an independent Python implementation.
