#ifndef FSPHINCS_API_H
#define FSPHINCS_API_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t total;
    uint64_t compression_blocks;
    uint64_t node_seed;
    uint64_t leaf_secret;
    uint64_t leaf_hash;
    uint64_t tree_node;
    uint64_t padding_root;
    uint64_t h2;
    uint64_t h3;
    uint64_t key_seed;
    uint64_t mfors_layer[FS_H + 1u];
} fsphincs_profile;

size_t fsphincs_publickeybytes(void);
size_t fsphincs_secretkeybytes(void);
size_t fsphincs_signaturebytes(void);
size_t fsphincs_seedbytes(void);

int fsphincs_seed_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int fsphincs_keypair(uint8_t *pk, uint8_t *sk);
int fsphincs_sign_signature(uint8_t *sig, size_t *siglen,
                            const uint8_t *msg, size_t msglen,
                            const uint8_t *sk);
int fsphincs_sign_signature_with_randomizer(uint8_t *sig, size_t *siglen,
                            const uint8_t *msg, size_t msglen,
                            const uint8_t *sk, const uint8_t randomizer[FS_N]);
int fsphincs_verify(const uint8_t *sig, size_t siglen,
                    const uint8_t *msg, size_t msglen,
                    const uint8_t *pk);
/* Streaming verifier API for constrained guests. begin() derives the first
 * M-FORS message and leaf index; layer() consumes exactly one M-FORS layer
 * and updates value in place; finish() checks the recovered root key. */
void fsphincs_verify_begin(uint8_t value[FS_MFORS_MSG_BYTES],
                           uint64_t *leaf_index,
                           const uint8_t randomizer[FS_N],
                           const uint8_t *msg, size_t msglen);
int fsphincs_verify_layer(uint8_t value[FS_MFORS_MSG_BYTES],
                          const uint8_t layer_sig[FS_MFORS_SIG_BYTES],
                          const uint8_t pub_seed[FS_N],
                          uint32_t layer, uint64_t node);
int fsphincs_verify_finish(const uint8_t value[FS_MFORS_MSG_BYTES],
                           const uint8_t pk[FS_PK_BYTES]);
void fsphincs_profile_reset(void);
void fsphincs_profile_get(fsphincs_profile *out);
int fsphincs_trace_signature(uint8_t layer_values[(FS_H + 1u) *
                              FS_MFORS_MSG_BYTES],
                             uint64_t *leaf_index,
                             const uint8_t *sig, size_t siglen,
                             const uint8_t *msg, size_t msglen,
                             const uint8_t *pk);

/* Exposed for deterministic unit/benchmark coverage of the paper's M-FORS. */
int fs_mfors_sign(uint8_t *sig, uint8_t pk_value[FS_MFORS_MSG_BYTES],
                  const uint8_t md[FS_MFORS_MSG_BYTES],
                  const uint8_t master_seed[FS_N],
                  const uint8_t pub_seed[FS_N],
                  uint32_t layer, uint64_t node);
int fs_mfors_recover(uint8_t pk_value[FS_MFORS_MSG_BYTES],
                     const uint8_t *sig,
                     const uint8_t md[FS_MFORS_MSG_BYTES],
                     const uint8_t pub_seed[FS_N],
                     uint32_t layer, uint64_t node);
int fs_mfors_verify(const uint8_t *sig,
                    const uint8_t expected_pk[FS_MFORS_MSG_BYTES],
                    const uint8_t md[FS_MFORS_MSG_BYTES],
                    const uint8_t pub_seed[FS_N],
                    uint32_t layer, uint64_t node);

#ifdef __cplusplus
}
#endif
#endif
