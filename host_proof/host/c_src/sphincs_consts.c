#include <stddef.h>
#include <stdint.h>

#include "api.h"

// Implements sig bytes.
size_t sphincs_sig_bytes(void) { return (size_t)CRYPTO_BYTES; }
// Implements pk bytes.
size_t sphincs_pk_bytes(void)  { return (size_t)CRYPTO_PUBLICKEYBYTES; }
// Implements sk bytes.
size_t sphincs_sk_bytes(void)  { return (size_t)CRYPTO_SECRETKEYBYTES; }
