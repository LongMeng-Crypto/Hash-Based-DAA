#include <stddef.h>
#include "api.h"

// Implements sig bytes.
size_t fsphincs_sig_bytes(void) { return FS_SIG_BYTES; }

// Implements pk bytes.
size_t fsphincs_pk_bytes(void) { return FS_PK_BYTES; }

// Implements sk bytes.
size_t fsphincs_sk_bytes(void) { return FS_SK_BYTES; }
