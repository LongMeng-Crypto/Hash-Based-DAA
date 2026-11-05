#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "api.h"
#include "params.h"
// Supplies deterministic randomness for the reference signer.
void randombytes(unsigned char *out, size_t n) { for(size_t i=0;i<n;i++) out[i]=(unsigned char)i; }
int daa_guest_verify(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
// Compares the guest verifier to the reference signer and checks altered inputs.
int main(void) {
    unsigned char seed[3*SPX_N], pk[SPX_PK_BYTES], sk[SPX_SK_BYTES], msg[40];
    unsigned char *sig=malloc(SPX_BYTES); size_t len=0;
    for(size_t i=0;i<sizeof(seed);i++) seed[i]=(unsigned char)(i*7+3);
    memset(msg,0x69,sizeof(msg));
    if(crypto_sign_seed_keypair(pk,sk,seed) || crypto_sign_signature(sig,&len,msg,sizeof(msg),sk)) return 1;
    if(crypto_sign_verify(sig,len,msg,sizeof(msg),pk) || daa_guest_verify(sig,len,msg,sizeof(msg),pk)) return 2;
    for(size_t i=0;i<SPX_BYTES;i+=SPX_BYTES/9) {
        sig[i]^=1;
        if(daa_guest_verify(sig,len,msg,sizeof(msg),pk)==0) return 3;
        sig[i]^=1;
    }
    if(daa_guest_verify(sig,len-1,msg,sizeof(msg),pk)==0) return 4;
    msg[0]^=1; if(daa_guest_verify(sig,len,msg,sizeof(msg),pk)==0) return 5;
    free(sig); puts("guest verifier agrees with reference and rejects mutations"); return 0;
}
