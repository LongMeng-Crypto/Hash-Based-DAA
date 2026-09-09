#ifndef FSPHINCS_PARAMETER_SETS_H
#define FSPHINCS_PARAMETER_SETS_H

/* Canonical registry: target label, fast flag, tree height, forest width.
 * The Rust build helper reads these same rows; labels are not security proofs. */
#define FS_PARAMS_128s 128, 0, 16, 22
#define FS_PARAMS_128f 128, 1, 12, 61
#define FS_PARAMS_192s 192, 0, 16, 33
#define FS_PARAMS_192f 192, 1, 12, 92
#define FS_PARAMS_256s 256, 0, 16, 43
#define FS_PARAMS_256f 256, 1, 12, 120

#endif
