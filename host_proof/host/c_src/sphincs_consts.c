#include <stddef.h>
#include <stdint.h>

#include "api.h"

// These macros come from api.h + params (selected by PARAMS at compile time).
size_t sphincs_sig_bytes(void) { return (size_t)CRYPTO_BYTES; }
size_t sphincs_pk_bytes(void)  { return (size_t)CRYPTO_PUBLICKEYBYTES; }
size_t sphincs_sk_bytes(void)  { return (size_t)CRYPTO_SECRETKEYBYTES; }