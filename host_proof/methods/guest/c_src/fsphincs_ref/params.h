#ifndef FSPHINCS_PARAMS_H
#define FSPHINCS_PARAMS_H

/* PQCrypto 2023, Hash-Based Direct Anonymous Attestation. FSPHINCS_SECURITY
 * selects the DAA/AES security level. FSPHINCS_K independently selects the
 * M-FORS width. Omitting FSPHINCS_K preserves the historical paper sets. */
#ifndef FSPHINCS_SECURITY
#define FSPHINCS_SECURITY 128
#endif

#if FSPHINCS_SECURITY != 128 && FSPHINCS_SECURITY != 192 && \
    FSPHINCS_SECURITY != 256
#error "FSPHINCS_SECURITY must be 128, 192, or 256"
#endif

#ifndef FSPHINCS_K
#if FSPHINCS_SECURITY == 128
#define FSPHINCS_K 35
#elif FSPHINCS_SECURITY == 192
#define FSPHINCS_K 33
#else
#define FSPHINCS_K 70
#endif
#endif

#if FSPHINCS_K != 22 && FSPHINCS_K != 33 && FSPHINCS_K != 35 && \
    FSPHINCS_K != 43 && FSPHINCS_K != 70
#error "FSPHINCS_K must be 22, 33, 35, 43, or 70"
#endif

#define FS_K FSPHINCS_K
#if FS_K <= 32
#define FS_AGG_LEAVES 32u
#elif FS_K <= 64
#define FS_AGG_LEAVES 64u
#else
#define FS_AGG_LEAVES 128u
#endif

#define FS_N 32u
#define FS_D 16u
#define FS_Q 1024u
#define FS_H 6u
#define FS_LOGQ 10u

#define FS_MFORS_MSG_BITS (FS_K * FS_D)
#define FS_MFORS_MSG_BYTES ((FS_MFORS_MSG_BITS + 7u) / 8u)
#define FS_INDEX_BITS (FS_H * FS_LOGQ)
#define FS_H3_BYTES ((FS_MFORS_MSG_BITS + FS_INDEX_BITS + 7u) / 8u)

#define FS_MFORS_SIG_BYTES (FS_K * (FS_D + 1u) * FS_N)
#define FS_SIG_BYTES (FS_N + (FS_H + 1u) * FS_MFORS_SIG_BYTES)
#define FS_PK_BYTES (FS_N + FS_MFORS_MSG_BYTES)
#define FS_SK_BYTES (FS_N + FS_N + FS_MFORS_MSG_BYTES)
#define FS_SEED_BYTES (2u * FS_N)

#endif
