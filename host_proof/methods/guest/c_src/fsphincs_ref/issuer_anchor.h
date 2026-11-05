#ifndef FSPHINCS_ISSUER_ANCHOR_H
#define FSPHINCS_ISSUER_ANCHOR_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

#ifdef __cplusplus
extern "C" {
#endif

size_t fsphincs_issuer_anchor_certificate_bytes(void);

int fsphincs_issuer_anchor_generate(uint8_t *certificate,
                                    size_t certificate_len,
                                    const uint8_t *pk,
                                    const uint8_t *sk);

int fsphincs_issuer_anchor_verify(const uint8_t *certificate,
                                  size_t certificate_len,
                                  const uint8_t *pk);

int fsphincs_issuer_anchor_statement(uint8_t addresses[FS_ANCHORS * FS_LEAF_ADDR_BYTES],
                                    uint8_t anchors[FS_ANCHORS * FS_LEAF_BYTES],
                                    const uint8_t *certificate, size_t len,
                                    const uint8_t *pk);

int fsphincs_issuer_anchor_relation(uint8_t root_seed[FS_N],
                                    uint8_t leaf_addresses[FS_ANCHORS * FS_LEAF_ADDR_BYTES],
                                    uint8_t anchor_values[FS_ANCHORS * FS_LEAF_BYTES],
                                    const uint8_t *certificate,
                                    size_t certificate_len,
                                    const uint8_t *pk,
                                    const uint8_t *sk);

#ifdef __cplusplus
}
#endif

#endif
