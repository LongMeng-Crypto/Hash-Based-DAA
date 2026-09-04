#ifndef SPX_ISSUER_ANCHOR_H
#define SPX_ISSUER_ANCHOR_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Deterministic Setup certificate for two independent chains of a fixed
 * top-layer WOTS+ leaf.  It contains the WOTS+ signature on the all-zero
 * n-byte message and the XMSS authentication path to PK.root.
 */
size_t sphincs_issuer_anchor_certificate_bytes(void);

/* Generates the deterministic certificate for an existing issuer keypair. */
int sphincs_issuer_anchor_generate(uint8_t *certificate,
                                   size_t certificate_len,
                                   const uint8_t *pk,
                                   const uint8_t *sk);

/* Verifies the public certificate against the registered SPHINCS+ root. */
int sphincs_issuer_anchor_verify(const uint8_t *certificate,
                                 size_t certificate_len,
                                 const uint8_t *pk);

/*
 * Export the exact two-compression relation proved by pi_I.  Both public
 * WOTS+ secret elements are derived from the same private SK.seed under two
 * distinct chain addresses.  The first two digits of the fixed all-zero
 * WOTS+ message are zero, so both elements appear directly in the signature.
 */
int sphincs_issuer_anchor_relation(uint8_t seed[SPX_N],
                                   uint8_t seeded_state[32],
                                   uint8_t compressed_addresses[44],
                                   uint8_t anchor_values[2 * SPX_N],
                                   const uint8_t *certificate,
                                   size_t certificate_len,
                                   const uint8_t *pk,
                                   const uint8_t *sk);

#ifdef __cplusplus
}
#endif

#endif
