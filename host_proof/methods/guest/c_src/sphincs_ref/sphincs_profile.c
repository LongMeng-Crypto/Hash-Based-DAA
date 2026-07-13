#include "sphincs_profile.h"

#ifdef SPHINCS_PROFILE
static uint64_t counters[SPX_PROFILE_WORDS];

void spx_profile_inc(unsigned int idx, uint64_t amount)
{
    if (idx < SPX_PROFILE_WORDS) {
        counters[idx] += amount;
    }
}

void spx_profile_snapshot(uint64_t *out)
{
    for (unsigned int i = 0; i < SPX_PROFILE_WORDS; i++) {
        out[i] = counters[i];
    }
}
#else
void spx_profile_snapshot(uint64_t *out)
{
    for (unsigned int i = 0; i < SPX_PROFILE_WORDS; i++) {
        out[i] = 0;
    }
}
#endif
