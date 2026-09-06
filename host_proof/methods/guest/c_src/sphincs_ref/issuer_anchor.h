#ifndef SPX_ISSUER_ANCHOR_H
#define SPX_ISSUER_ANCHOR_H
#include "params.h"
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Maximum capacity; generate replaces *len with the actual encoded size. */
size_t sphincs_issuer_anchor_certificate_bytes(void);
/* Public post-processing of one ordinary signature on the one-byte Setup
 * message. */
int sphincs_issuer_anchor_generate(uint8_t *certificate, size_t *len,
                                   const uint8_t *pk, const uint8_t *sk);
/* Builds the certificate using only PK and a normal signature on message 0x49.
 */
int sphincs_issuer_anchor_from_signature(uint8_t *certificate, size_t *len,
                                         const uint8_t *pk,
                                         const uint8_t *signature,
                                         size_t signature_len);
int sphincs_issuer_anchor_verify(const uint8_t *certificate, size_t len,
                                 const uint8_t *pk);
/* Derives the unique public one-compression statement without a secret key. */
int sphincs_issuer_anchor_statement(uint8_t state[32], uint8_t address[22],
                                    uint8_t value[SPX_N],
                                    const uint8_t *certificate, size_t len,
                                    const uint8_t *pk);
int sphincs_issuer_anchor_relation(uint8_t seed[SPX_N], uint8_t state[32],
                                   uint8_t address[22], uint8_t value[SPX_N],
                                   const uint8_t *certificate, size_t len,
                                   const uint8_t *pk, const uint8_t *sk);
#ifdef __cplusplus
}
#endif
#endif
