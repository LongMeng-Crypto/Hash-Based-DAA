#ifndef FSPHINCS_ISSUER_ANCHOR_H
#define FSPHINCS_ISSUER_ANCHOR_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Returns the serialized two-node M-FORS certificate size. */
size_t fsphincs_issuer_anchor_certificate_bytes(void);

/* Generates the deterministic certificate for an existing issuer keypair. */
int fsphincs_issuer_anchor_generate(uint8_t *certificate,
                                    size_t certificate_len,
                                    const uint8_t *pk,
                                    const uint8_t *sk);

/* Verifies both public M-FORS components against the registered root. */
int fsphincs_issuer_anchor_verify(const uint8_t *certificate,
                                  size_t certificate_len,
                                  const uint8_t *pk);

/* Eight-compression relation over two distinct M-FORS nodes:
 *   node_seed[i] = SHA256(master_seed || node_address[i])
 *   anchor[i]    = SHA256(node_seed[i] || leaf_address[i]), i in {0,1}.
 * The two address arrays and two anchor values are concatenated in node order.
 */
int fsphincs_issuer_anchor_relation(uint8_t master_seed[FS_N],
                                    uint8_t node_addresses[64],
                                    uint8_t leaf_addresses[64],
                                    uint8_t anchor_values[2 * FS_N],
                                    const uint8_t *certificate,
                                    size_t certificate_len,
                                    const uint8_t *pk,
                                    const uint8_t *sk);

#ifdef __cplusplus
}
#endif

#endif
