#ifndef FSPHINCS_PARAMS_H
#define FSPHINCS_PARAMS_H

/* PQCrypto 2023, Hash-Based Direct Anonymous Attestation, concrete
 * 128-bit F-SPHINCS+ example: d=16, k=35, q=1024, h=6.
 * SHA-256 replaces the paper implementation's LowMC instantiation. */
#define FS_N 32u
#define FS_D 16u
#define FS_K 35u
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
