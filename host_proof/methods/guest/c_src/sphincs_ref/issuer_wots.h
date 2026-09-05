#ifndef DAA_ISSUER_WOTS_H
#define DAA_ISSUER_WOTS_H
#include <stddef.h>
#include <stdint.h>

/* All buffers have compile-time SPHINCS+ parameter-dependent sizes. */
size_t sphincs_issuer_wots_certificate_bytes(void);
size_t sphincs_issuer_wots_witness_bytes(void);
int sphincs_issuer_wots_generate(uint8_t *cert, size_t cert_len,
    uint8_t *witness, size_t witness_len, const uint8_t *pk, const uint8_t *sk);
int sphincs_issuer_wots_verify(const uint8_t *cert, size_t cert_len, const uint8_t *pk);
int sphincs_issuer_wots_relation(const uint8_t *cert, size_t cert_len,
    const uint8_t *pk, const uint8_t *witness, size_t witness_len);
int sphincs_issuer_wots_capability_test(const uint8_t *cert, const uint8_t *pk,
    const uint8_t *witness);
#endif
