#include <stdint.h>
#include <string.h>

#include "hash.h"
#include "params.h"
#include "thash.h"

#if !defined(SPX_SHA2)
#error "wots_extreme diagnostic currently expects SHA2 parameters"
#endif

#include "sha2_offsets.h"

#define SPX_ADDR_TYPE_WOTS 0
#define SPX_ADDR_TYPE_WOTSPK 1

static void base_w(unsigned int *output, const int out_len,
                   const unsigned char *input) {
    int in = 0;
    int out = 0;
    unsigned char total = 0;
    int bits = 0;

    for (int consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in++];
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out++] = (total >> bits) & (SPX_WOTS_W - 1);
    }
}

static void ull_to_bytes(unsigned char *out, unsigned int outlen,
                         unsigned long long in) {
    for (int i = (int)outlen - 1; i >= 0; i--) {
        out[i] = (unsigned char)in;
        in >>= 8;
    }
}

static void chain_lengths_diag(unsigned int *lengths, const unsigned char *msg) {
    unsigned int csum = 0;
    unsigned char csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];

    base_w(lengths, SPX_WOTS_LEN1, msg);
    for (unsigned int i = 0; i < SPX_WOTS_LEN1; i++) {
        csum += SPX_WOTS_W - 1 - lengths[i];
    }
    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w(lengths + SPX_WOTS_LEN1, SPX_WOTS_LEN2, csum_bytes);
}

// Diagnostic-only WOTS workload runner.
// mode=0: root bytes are 0xff, giving the minimum WOTS verify chain work.
// mode=1: root bytes are 0x00, giving the maximum WOTS verify chain work.
// It runs SPX_D WOTS verifications plus the fixed WOTS-pk compression thash per
// layer, matching the WOTS-related work shape of SPHINCS+ verification. It does
// not verify a valid SPHINCS+ signature and must not be used as a protocol proof.
uint64_t sphincs_wots_extreme(uint32_t mode) {
    spx_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    initialize_hash_function(&ctx);

    unsigned char root[SPX_N];
    unsigned char sig_elem[SPX_N];
    unsigned char wots_pk[SPX_WOTS_BYTES];
    unsigned char leaf[SPX_N];
    unsigned int lengths[SPX_WOTS_LEN];
    uint32_t addr[8];
    uint64_t thash1_calls = 0;

    memset(root, mode ? 0x00 : 0xff, sizeof(root));
    memset(sig_elem, 0x42, sizeof(sig_elem));

    for (unsigned int layer = 0; layer < SPX_D; layer++) {
        chain_lengths_diag(lengths, root);
        memset(addr, 0, sizeof(addr));
        ((unsigned char *)addr)[SPX_OFFSET_LAYER] = (unsigned char)layer;
        ((unsigned char *)addr)[SPX_OFFSET_TYPE] = SPX_ADDR_TYPE_WOTS;

        for (unsigned int i = 0; i < SPX_WOTS_LEN; i++) {
            unsigned char out[SPX_N];
            memcpy(out, sig_elem, SPX_N);
            ((unsigned char *)addr)[SPX_OFFSET_CHAIN_ADDR] = (unsigned char)i;

            for (unsigned int j = lengths[i]; j < SPX_WOTS_W - 1; j++) {
                ((unsigned char *)addr)[SPX_OFFSET_HASH_ADDR] = (unsigned char)j;
                thash(out, out, 1, &ctx, addr);
                thash1_calls++;
            }
            memcpy(wots_pk + i * SPX_N, out, SPX_N);
        }

        memset(addr, 0, sizeof(addr));
        ((unsigned char *)addr)[SPX_OFFSET_LAYER] = (unsigned char)layer;
        ((unsigned char *)addr)[SPX_OFFSET_TYPE] = SPX_ADDR_TYPE_WOTSPK;
        thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, addr);
        memcpy(root, leaf, SPX_N);

        // Keep subsequent layers pinned to the selected extreme root. This
        // measures the theoretical per-layer min/max envelope rather than a
        // hash-evolved valid SPHINCS+ path.
        memset(root, mode ? 0x00 : 0xff, sizeof(root));
    }

    return thash1_calls;
}
