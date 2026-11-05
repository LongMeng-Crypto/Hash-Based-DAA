/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef FAEST_256F_H
#define FAEST_256F_H

#include "faest_defines.h"

#include <stddef.h>
#include <stdint.h>

FAEST_BEGIN_C_DECL

#define FAEST_256F_PUBLIC_KEY_SIZE 96

#define FAEST_256F_PRIVATE_KEY_SIZE 96

#define FAEST_256F_SIGNATURE_SIZE 49716

typedef struct {
  uint8_t owf_input[32];

  uint8_t owf_key[2 * (256 / 8) + 2 * 16];
  uint8_t owf_output[64];
  uint8_t witness[8896 / 8];
} faest_256f_unpacked_private_key_t;

FAEST_EXPORT int FAEST_CALLING_CONVENTION faest_256f_keygen(uint8_t* pk, uint8_t* sk);

FAEST_EXPORT int FAEST_CALLING_CONVENTION faest_256f_unpack_private_key(faest_256f_unpacked_private_key_t* unpacked_sk, const uint8_t* sk);

FAEST_EXPORT int FAEST_CALLING_CONVENTION faest_256f_sign(const uint8_t* sk, const uint8_t* message, size_t message_len, uint8_t* signature, size_t* signature_len);

FAEST_EXPORT int FAEST_CALLING_CONVENTION faest_256f_sign_with_randomness(const uint8_t* sk, const uint8_t* message, size_t message_len, const uint8_t* rho, size_t rho_len, uint8_t* signature, size_t* signature_len);

FAEST_EXPORT int FAEST_CALLING_CONVENTION faest_256f_unpacked_sign(const faest_256f_unpacked_private_key_t* unpacked_sk, const uint8_t* message, size_t message_len, uint8_t* signature, size_t* signature_len);

FAEST_EXPORT int FAEST_CALLING_CONVENTION faest_256f_unpacked_sign_with_randomness(const faest_256f_unpacked_private_key_t* unpacked_sk, const uint8_t* message, size_t message_len, const uint8_t* rho, size_t rho_len, uint8_t* signature, size_t* signature_len);

FAEST_EXPORT int FAEST_CALLING_CONVENTION faest_256f_verify(const uint8_t* pk, const uint8_t* message, size_t message_len, const uint8_t* signature, size_t signature_len);

FAEST_EXPORT int FAEST_CALLING_CONVENTION faest_256f_validate_keypair(const uint8_t* pk, const uint8_t* sk);

FAEST_EXPORT void FAEST_CALLING_CONVENTION faest_256f_clear_private_key(uint8_t* key);

FAEST_EXPORT void FAEST_CALLING_CONVENTION faest_256f_clear_unpacked_private_key(faest_256f_unpacked_private_key_t* unpacked_sk);

FAEST_END_C_DECL

#endif
