#include <stddef.h>
#include "api.h"

/* Exports the selected v7 signature length to the Rust native benchmark. */
size_t fsphincs_sig_bytes(void) { return FS_SIG_BYTES; }
/* Exports the selected public-seed/root-value encoding length to Rust. */
size_t fsphincs_pk_bytes(void) { return FS_PK_BYTES; }
/* Exports the selected master-seed/public-key encoding length to Rust. */
size_t fsphincs_sk_bytes(void) { return FS_SK_BYTES; }
