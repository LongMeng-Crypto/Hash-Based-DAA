#ifndef FSPHINCS_API_H
#define FSPHINCS_API_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t pub_seed[FS_N];
    uint32_t state[10]; /* SHA-256 bytes and counter; aligned for the guest syscall. */
} fsphincs_hash_context;

/* Absorbs the padded public seed once per operation, without global mutable state. */
void fsphincs_hash_init(fsphincs_hash_context *ctx, const uint8_t pub_seed[FS_N]);
/* Streaming layer entry point sharing the caller's precomputed public state. */
int fsphincs_verify_layer_ctx(uint8_t value[FS_MFORS_MSG_BYTES],
    const uint8_t layer_sig[FS_MFORS_SIG_BYTES], const fsphincs_hash_context *ctx,
    uint32_t layer, uint64_t node);

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
    uint64_t sha512_calls;
    uint64_t sha512_compression_blocks;
} fsphincs_profile;

/* Returns the 32-byte public seed plus the canonical M-FORS public-value length. */
size_t fsphincs_publickeybytes(void);
/* Returns the 32-byte master seed plus the serialized public-key length. */
size_t fsphincs_secretkeybytes(void);
/* Counts the randomizer and seven layers with security-sized leaves and nodes. */
size_t fsphincs_signaturebytes(void);
/* Returns the combined master/public-seed entropy length for key generation. */
size_t fsphincs_seedbytes(void);

/* Generates a keypair deterministically from caller-supplied seed entropy. */
int fsphincs_seed_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
/* Generates a keypair using the caller's randombytes implementation. */
int fsphincs_keypair(uint8_t *pk, uint8_t *sk);
/* Signs using a fresh randomizer and the v7 leaf-PRF serialization. */
int fsphincs_sign_signature(uint8_t *sig, size_t *siglen,
                            const uint8_t *msg, size_t msglen,
                            const uint8_t *sk);
/* Signs with an explicit randomizer for deterministic testing and simulation. */
int fsphincs_sign_signature_with_randomizer(uint8_t *sig, size_t *siglen,
                            const uint8_t *msg, size_t msglen,
                            const uint8_t *sk, const uint8_t randomizer[FS_N]);
/* Verifies the exact-length detached signature against a canonical public key. */
int fsphincs_verify(const uint8_t *sig, size_t siglen,
                    const uint8_t *msg, size_t msglen,
                    const uint8_t *pk);
/* Streaming verifier API for constrained guests. begin() derives the first
 * M-FORS message and leaf index; layer() consumes exactly one M-FORS layer
 * and updates value in place; finish() checks the recovered root key. */
void fsphincs_verify_begin(uint8_t value[FS_MFORS_MSG_BYTES],
                           uint64_t *leaf_index,
                           const uint8_t randomizer[FS_N],
                           const uint8_t *msg, size_t msglen,
                           const uint8_t pk[FS_PK_BYTES]);
/* Recovers one layer, constructing a local public-prefix state for this call. */
int fsphincs_verify_layer(uint8_t value[FS_MFORS_MSG_BYTES],
                          const uint8_t layer_sig[FS_MFORS_SIG_BYTES],
                          const uint8_t pub_seed[FS_N],
                          uint32_t layer, uint64_t node);
/* Checks that the recovered root value matches the canonical public key. */
int fsphincs_verify_finish(const uint8_t value[FS_MFORS_MSG_BYTES],
                           const uint8_t pk[FS_PK_BYTES]);
/* Clears hash-workload counters without modifying any cryptographic state. */
void fsphincs_profile_reset(void);
/* Copies workload counters, or zeroes when profiling is disabled. */
void fsphincs_profile_get(fsphincs_profile *out);
/* Verifies a signature and optionally exports all seven recovered layer values. */
int fsphincs_trace_signature(uint8_t layer_values[(FS_H + 1u) *
                              FS_MFORS_MSG_BYTES],
                             uint64_t *leaf_index,
                             const uint8_t *sig, size_t siglen,
                             const uint8_t *msg, size_t msglen,
                             const uint8_t *pk);

/* Signs one M-FORS node from its master-derived seed for unit/benchmark coverage. */
int fs_mfors_sign(uint8_t *sig, uint8_t pk_value[FS_MFORS_MSG_BYTES],
                  const uint8_t md[FS_MFORS_MSG_BYTES],
                  const uint8_t master_seed[FS_N],
                  const uint8_t pub_seed[FS_N],
                  uint32_t layer, uint64_t node);
/* Recovers one M-FORS public value from the selected secrets and inner paths. */
int fs_mfors_recover(uint8_t pk_value[FS_MFORS_MSG_BYTES],
                     const uint8_t *sig,
                     const uint8_t md[FS_MFORS_MSG_BYTES],
                     const uint8_t pub_seed[FS_N],
                     uint32_t layer, uint64_t node);
/* Verifies one complete M-FORS signature against its expected public value. */
int fs_mfors_verify(const uint8_t *sig,
                    const uint8_t expected_pk[FS_MFORS_MSG_BYTES],
                    const uint8_t md[FS_MFORS_MSG_BYTES],
                    const uint8_t pub_seed[FS_N],
                    uint32_t layer, uint64_t node);

/* Parses consecutive MSB-first d-bit indices, including half-byte boundaries. */
uint32_t fsphincs_md_index(const uint8_t md[FS_MFORS_MSG_BYTES], uint32_t tree);
/* Derives the root-node capability without exposing the master seed. */
void fsphincs_derive_root_seed(uint8_t out[FS_N], const uint8_t master[FS_N]);
/* Constructs fixed tree-0 and tree-1 leaf-0 anchors and a shared aggregation path. */
int fsphincs_root_anchor_generate(uint8_t payload[FS_ANCHOR_PAYLOAD_BYTES],
    uint8_t root_pk[FS_MFORS_MSG_BYTES], const uint8_t root_seed[FS_N],
    const uint8_t pub_seed[FS_N]);
/* Recovers the root public value using only the compact public certificate. */
void fsphincs_root_anchor_recover(uint8_t root_pk[FS_MFORS_MSG_BYTES],
    const uint8_t payload[FS_ANCHOR_PAYLOAD_BYTES], const uint8_t pub_seed[FS_N]);
/* Encodes one fixed root PRF address, independent of messages or signatures. */
void fsphincs_root_anchor_address(uint8_t out[FS_LEAF_ADDR_BYTES], uint32_t anchor);
/* Encodes a leaf-PRF position without truncation; returns -1 on invalid fields. */
int fsphincs_leaf_prf_address(uint8_t out[FS_LEAF_ADDR_BYTES], uint32_t layer,
                              uint64_t node, uint32_t tree, uint32_t leaf);
/* Signs with only a root capability plus independently chosen lower-node seeds.
 * This simulation/test helper does not reconstruct an issuer master secret. */
int fsphincs_sign_with_root_seed(uint8_t *sig, size_t *siglen,
    const uint8_t *msg, size_t msglen, const uint8_t pk[FS_PK_BYTES],
    const uint8_t root_seed[FS_N], const uint8_t lower_seed[FS_N],
    const uint8_t randomizer[FS_N]);

#ifdef __cplusplus
}
#endif
#endif
