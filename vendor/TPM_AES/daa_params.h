/*
 * daa_params.h — Original single-AES FAEST parameter defines for the DAA protocol
 *
 * These are the FAEST v2 reference parameter sets with:
 *   OWF_INPUT_SIZE  = 16  (gid is always one 16-byte block)
 *   OWF_OUTPUT_SIZE = 16 (lambda=128) or 32 (lambda=192/256)
 *   ELL             = Lke + beta*Lenc  (original FAEST, not TPM-AES)
 *
 * All other fields (R, Nst, tau, k, Lke, Lenc) are identical to the
 * TPM-AES variants at the same security level.
 */

#ifndef DAA_PARAMS_H
#define DAA_PARAMS_H

/* ---- FAEST-128S (original) ---- */
#define DAA_FAEST_128S_LAMBDA         128
#define DAA_FAEST_128S_TAU            11
#define DAA_FAEST_128S_W_GRIND        7
#define DAA_FAEST_128S_T_OPEN         102
#define DAA_FAEST_128S_ELL            1280   /* 448 + 1*832 */
#define DAA_FAEST_128S_Nst            4
#define DAA_FAEST_128S_Ske            40
#define DAA_FAEST_128S_R              10
#define DAA_FAEST_128S_Senc           160
#define DAA_FAEST_128S_Lke            448
#define DAA_FAEST_128S_Lenc           832
#define DAA_FAEST_128S_SIG_SIZE       4506
#define DAA_FAEST_128S_OWF_INPUT_SIZE  16
#define DAA_FAEST_128S_OWF_OUTPUT_SIZE 16

/* ---- FAEST-128F (original) ---- */
#define DAA_FAEST_128F_LAMBDA         128
#define DAA_FAEST_128F_TAU            16
#define DAA_FAEST_128F_W_GRIND        8
#define DAA_FAEST_128F_T_OPEN         110
#define DAA_FAEST_128F_ELL            1280   /* 448 + 1*832 */
#define DAA_FAEST_128F_Nst            4
#define DAA_FAEST_128F_Ske            40
#define DAA_FAEST_128F_R              10
#define DAA_FAEST_128F_Senc           160
#define DAA_FAEST_128F_Lke            448
#define DAA_FAEST_128F_Lenc           832
#define DAA_FAEST_128F_SIG_SIZE       5924
#define DAA_FAEST_128F_OWF_INPUT_SIZE  16
#define DAA_FAEST_128F_OWF_OUTPUT_SIZE 16

/* ---- FAEST-192S (original) ---- */
#define DAA_FAEST_192S_LAMBDA         192
#define DAA_FAEST_192S_TAU            16
#define DAA_FAEST_192S_W_GRIND        12
#define DAA_FAEST_192S_T_OPEN         162
#define DAA_FAEST_192S_ELL            2496   /* 448 + 2*1024 */
#define DAA_FAEST_192S_Nst            4
#define DAA_FAEST_192S_Ske            32
#define DAA_FAEST_192S_R              12
#define DAA_FAEST_192S_Senc           192
#define DAA_FAEST_192S_Lke            448
#define DAA_FAEST_192S_Lenc           1024
#define DAA_FAEST_192S_SIG_SIZE       11260
#define DAA_FAEST_192S_OWF_INPUT_SIZE  16
#define DAA_FAEST_192S_OWF_OUTPUT_SIZE 32

/* ---- FAEST-192F (original) ---- */
#define DAA_FAEST_192F_LAMBDA         192
#define DAA_FAEST_192F_TAU            24
#define DAA_FAEST_192F_W_GRIND        8
#define DAA_FAEST_192F_T_OPEN         163
#define DAA_FAEST_192F_ELL            2496   /* 448 + 2*1024 */
#define DAA_FAEST_192F_Nst            4
#define DAA_FAEST_192F_Ske            32
#define DAA_FAEST_192F_R              12
#define DAA_FAEST_192F_Senc           192
#define DAA_FAEST_192F_Lke            448
#define DAA_FAEST_192F_Lenc           1024
#define DAA_FAEST_192F_SIG_SIZE       14948
#define DAA_FAEST_192F_OWF_INPUT_SIZE  16
#define DAA_FAEST_192F_OWF_OUTPUT_SIZE 32

/* ---- FAEST-256S (original) ---- */
#define DAA_FAEST_256S_LAMBDA         256
#define DAA_FAEST_256S_TAU            22
#define DAA_FAEST_256S_W_GRIND        6
#define DAA_FAEST_256S_T_OPEN         245
#define DAA_FAEST_256S_ELL            3104   /* 672 + 2*1216 */
#define DAA_FAEST_256S_Nst            4
#define DAA_FAEST_256S_Ske            52
#define DAA_FAEST_256S_R              14
#define DAA_FAEST_256S_Senc           224
#define DAA_FAEST_256S_Lke            672
#define DAA_FAEST_256S_Lenc           1216
#define DAA_FAEST_256S_SIG_SIZE       20696
#define DAA_FAEST_256S_OWF_INPUT_SIZE  16
#define DAA_FAEST_256S_OWF_OUTPUT_SIZE 32

/* ---- FAEST-256F (original) ---- */
#define DAA_FAEST_256F_LAMBDA         256
#define DAA_FAEST_256F_TAU            32
#define DAA_FAEST_256F_W_GRIND        8
#define DAA_FAEST_256F_T_OPEN         246
#define DAA_FAEST_256F_ELL            3104   /* 672 + 2*1216 */
#define DAA_FAEST_256F_Nst            4
#define DAA_FAEST_256F_Ske            52
#define DAA_FAEST_256F_R              14
#define DAA_FAEST_256F_Senc           224
#define DAA_FAEST_256F_Lke            672
#define DAA_FAEST_256F_Lenc           1216
#define DAA_FAEST_256F_SIG_SIZE       26548
#define DAA_FAEST_256F_OWF_INPUT_SIZE  16
#define DAA_FAEST_256F_OWF_OUTPUT_SIZE 32

#endif /* DAA_PARAMS_H */
