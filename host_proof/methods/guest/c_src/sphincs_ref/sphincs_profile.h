#ifndef SPHINCS_PROFILE_H
#define SPHINCS_PROFILE_H

#include <stdint.h>

#define SPX_PROFILE_WORDS 16

enum {
    SPX_PROF_VERIFY = 0,
    SPX_PROF_HASH_MESSAGE = 1,
    SPX_PROF_FORS = 2,
    SPX_PROF_WOTS = 3,
    SPX_PROF_COMPUTE_ROOT = 4,
    SPX_PROF_THASH = 5,
    SPX_PROF_THASH_INBLOCKS = 6,
    SPX_PROF_THASH_1 = 7,
    SPX_PROF_THASH_2 = 8,
    SPX_PROF_THASH_LONG = 9,
    SPX_PROF_SHA256_FINALIZE = 10,
    SPX_PROF_SHA256_COMPRESS_BLOCKS = 11,
    SPX_PROF_SHA256_SYSCALL_CHUNKS = 12,
    SPX_PROF_MGF1_256 = 13,
    SPX_PROF_SEED_STATE = 14,
    SPX_PROF_OPT_THASH_128S = 15
};

#ifdef SPHINCS_PROFILE
void spx_profile_inc(unsigned int idx, uint64_t amount);
#define SPX_PROFILE_INC(idx, amount) spx_profile_inc((idx), (amount))
#else
#define SPX_PROFILE_INC(idx, amount) ((void)0)
#endif

void spx_profile_snapshot(uint64_t *out);

#endif
