#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "params.h"
#include "issuer_wots.h"

/* Supplies deterministic test-only randomness to otherwise unused signing entry points. */
void randombytes(unsigned char *out, unsigned long long len) {
    for (unsigned long long i=0; i<len; ++i) out[i]=(unsigned char)i;
}

/* Differential-tests full-chain reconstruction against reference keygen for each compiled parameter. */
int main(void) {
    unsigned char pk[SPX_PK_BYTES], sk[SPX_SK_BYTES], seed[3*SPX_N];
    for (unsigned int i=0; i<sizeof(seed); ++i) seed[i]=(unsigned char)(i+7);
    if (crypto_sign_seed_keypair(pk, sk, seed)) return 1;
    size_t clen=sphincs_issuer_wots_certificate_bytes();
    size_t wlen=sphincs_issuer_wots_witness_bytes();
    unsigned char *cert=malloc(clen), *witness=malloc(wlen);
    if (!cert || !witness) return 2;
    if (sphincs_issuer_wots_generate(cert,clen,witness,wlen,pk,sk)) return 3;
    if (sphincs_issuer_wots_capability_test(cert,pk,witness)) return 4;
    for (unsigned int i=0; i<SPX_WOTS_LEN; ++i) {
        witness[i*SPX_N]^=1;
        int accepted=sphincs_issuer_wots_relation(cert,clen,pk,witness,wlen)==0;
        witness[i*SPX_N]^=1;
        if (accepted) return 5;
    }
    if (!sphincs_issuer_wots_verify(cert,clen-1,pk)) return 6;
    if (!sphincs_issuer_wots_relation(cert,clen,pk,witness,wlen-1)) return 7;
    /* The relation only proves the leaf; the mandatory public check rejects a wrong path. */
    cert[clen-1]^=1;
    if (sphincs_issuer_wots_relation(cert,clen,pk,witness,wlen) != 0
        || sphincs_issuer_wots_verify(cert,clen,pk) == 0) return 9;
    cert[clen-1]^=1;
    for (size_t i=0; i<clen; ++i) {
        cert[i]^=1;
        int accepted=sphincs_issuer_wots_verify(cert,clen,pk)==0;
        cert[i]^=1;
        if (accepted) return 8;
    }
    printf("n=%u d=%u height=%u chains=%u certificate=%zu witness=%zu: reference, full-key mutation, every certificate byte, seed-free capability OK\n",
        SPX_N,SPX_D,SPX_TREE_HEIGHT,SPX_WOTS_LEN,clen,wlen);
    free(cert); free(witness);
    return 0;
}
