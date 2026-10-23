#ifndef FSPHINCS_PARAMS_H
#define FSPHINCS_PARAMS_H

#include "parameter_sets.h"

#if defined(FSPHINCS_SECURITY) || defined(FSPHINCS_K)
#error "Use one named FSPHINCS_PARAMS set; independent legacy selectors are unsupported"
#endif

/* Only the six named experimental configurations are supported. */
#ifndef FSPHINCS_PARAMS
#define FSPHINCS_PARAMS 128s
#endif
#define FS_JOIN_(a, b) a##b
#define FS_JOIN(a, b) FS_JOIN_(a, b)
#define FS_VALUES FS_JOIN(FS_PARAMS_, FSPHINCS_PARAMS)
#define FS_SECURITY_(security, fast, d, k) security
#define FS_FAST_(security, fast, d, k) fast
#define FS_D_(security, fast, d, k) d
#define FS_K_(security, fast, d, k) k
#define FS_SELECT_(field, ...) field(__VA_ARGS__)
#define FS_SELECT(field, values) FS_SELECT_(field, values)
#define FS_SECURITY FS_SELECT(FS_SECURITY_, FS_VALUES)
#define FS_FAST FS_SELECT(FS_FAST_, FS_VALUES)
#define FS_D FS_SELECT(FS_D_, FS_VALUES)
#define FS_K FS_SELECT(FS_K_, FS_VALUES)
#define FS_STRING_(s) #s
#define FS_STRING(s) FS_STRING_(s)
#define FS_NAME FS_STRING(FSPHINCS_PARAMS)

#define FS_FORMAT_VERSION 3u
/* Keep node PRF/H2/H3 v3 and the full-width compact leaf PRF v4. */
#define FS_LEAF_PRF_VERSION 4u
#define FS_LEAF_ADDR_BYTES 16u
/* H1 v6 uses compact addresses and a cached, block-padded public seed. */
#define FS_NODE_BYTES (FS_SECURITY / 8u)
#define FS_H1_VERSION 6u
#define FS_H1_ADDR_BYTES 16u
#define FS_CERTIFICATE_VERSION 6u
#define FS_PARAMETER_ID ((FS_SECURITY / 64u - 2u) * 2u + FS_FAST)
#if FS_K <= 32
#define FS_AGG_LOG 5u
#elif FS_K <= 64
#define FS_AGG_LOG 6u
#else
#define FS_AGG_LOG 7u
#endif
#define FS_AGG_LEAVES (1u << FS_AGG_LOG)
#define FS_ANCHORS (FS_SECURITY == 128 ? 1u : 2u)
#define FS_ANCHOR_PATH_LEVELS (FS_AGG_LOG - (FS_ANCHORS == 2u ? 1u : 0u))
#define FS_ANCHOR_PAYLOAD_BYTES \
    (FS_ANCHORS * FS_TREE_SIG_BYTES + FS_ANCHOR_PATH_LEVELS * FS_NODE_BYTES)

/* Seeds, randomizers, disclosed secrets and H2 digests stay 256 bits. */
#define FS_N 32u
#define FS_Q 1024u
#define FS_H 6u
#define FS_LOGQ 10u

#define FS_MFORS_MSG_BITS (FS_K * FS_D)
#define FS_MFORS_MSG_BYTES ((FS_MFORS_MSG_BITS + 7u) / 8u)
#define FS_INDEX_BITS (FS_H * FS_LOGQ)
#define FS_H3_BYTES ((FS_MFORS_MSG_BITS + FS_INDEX_BITS + 7u) / 8u)
#define FS_H3_DIGEST_BYTES (FS_SECURITY == 256 ? 64u : 32u)
#define FS_H3_BLOCK_BYTES (2u * FS_H3_DIGEST_BYTES)

#define FS_TREE_SIG_BYTES (FS_N + FS_D * FS_NODE_BYTES)
#define FS_MFORS_SIG_BYTES (FS_K * FS_TREE_SIG_BYTES)
#define FS_SIG_BYTES (FS_N + (FS_H + 1u) * FS_MFORS_SIG_BYTES)
#define FS_PK_BYTES (FS_N + FS_MFORS_MSG_BYTES)
#define FS_SK_BYTES (FS_N + FS_N + FS_MFORS_MSG_BYTES)
#define FS_SEED_BYTES (2u * FS_N)

#endif
