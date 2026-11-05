/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef CPU_H
#define CPU_H

#include "macros.h"

#if !defined(OQS)

#if (defined(__GNUC__) || __has_builtin(__builtin_cpu_supports)) && !defined(__APPLE__) &&         \
    !defined(__MINGW32__) && !defined(__MINGW64__) && !defined(WITHOUT_BUILTIN_CPU_SUPPORTS)
#define BUILTIN_CPU_SUPPORTED
#endif

#if defined(BUILTIN_CPU_SUPPORTED) && GNUC_CHECK(4, 9) && !GNUC_CHECK(5, 0)

#define BUILTIN_CPU_SUPPORTED_BROKEN_BMI2
#endif

#if !defined(BUILTIN_CPU_SUPPORTED) || defined(BUILTIN_CPU_SUPPORTED_BROKEN_BMI2)
#include <stdbool.h>

#define CPU_CAP_SSE2 0x00000001

#define CPU_CAP_AVX2 0x00000004

#define CPU_CAP_BMI2 0x00000010

#define CPU_CAP_NEON 0x00000008

#define CPU_CAP_AESNI 0x00000040

bool cpu_supports(unsigned int caps);
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#if defined(BUILTIN_CPU_SUPPORTED) && !defined(BUILTIN_CPU_SUPPORTED_BROKEN_BMI2)
#define CPU_SUPPORTS_AVX2 (__builtin_cpu_supports("avx2") && __builtin_cpu_supports("bmi2"))
#else
#define CPU_SUPPORTS_AVX2 cpu_supports(CPU_CAP_AVX2 | CPU_CAP_BMI2)
#endif
#endif

#if defined(__x86_64__) || defined(_M_X64)

#define CPU_SUPPORTS_SSE2 1
#elif defined(__i386__) || defined(_M_IX86)
#if defined(BUILTIN_CPU_SUPPORTED)
#define CPU_SUPPORTS_SSE2 __builtin_cpu_supports("sse2")
#else
#define CPU_SUPPORTS_SSE2 cpu_supports(CPU_CAP_SSE2)
#endif
#else
#define CPU_SUPPORTS_SSE2 0
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#if defined(BUILTIN_CPU_SUPPORTED)
#define CPU_SUPPORTS_AESNI (CPU_SUPPORTS_SSE2 && __builtin_cpu_supports("aes"))
#define CPU_SUPPORTS_AESNI_AVX2 (CPU_SUPPORTS_AVX2 && __builtin_cpu_supports("aes"))
#else
#define CPU_SUPPORTS_AESNI cpu_supports(CPU_CAP_SSE2 | CPU_CAP_AESNI)
#define CPU_SUPPORTS_AESNI_AVX2 cpu_supports(CPU_CAP_AVX2 | CPU_CAP_BMI2 | CPU_CAP_AESNI)
#endif
#else
#define CPU_SUPPORTS_AESNI 0
#define CPU_SUPPORTS_AESNI_AVX2 0
#endif

#if defined(__aarch64__)
#define CPU_SUPPORTS_NEON 1
#elif defined(__arm__)
#define CPU_SUPPRTS_NEON cpu_supports(CPU_CAP_NEON)
#else
#define CPU_SUPPORTS_NEON 0
#endif
#else

#include <oqs/common.h>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#define CPU_SUPPORTS_AVX2                                                                          \
  (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2))
#else
#define CPU_SUPPORTS_AVX2 0
#endif

#if defined(__x86_64__) || defined(_M_X64)

#define CPU_SUPPORTS_SSE2 1
#elif defined(__i386__) || defined(_M_IX86)
#define CPU_SUPPORTS_SSE2 OQS_CPU_has_extension(OQS_CPU_EXT_SSE2)
#else
#define CPU_SUPPORTS_SSE2 0
#endif

#if defined(__aarch64__)
#define CPU_SUPPORTS_NEON 1
#elif defined(__arm__)
#define CPU_SUPPORTS_NEON OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)
#else
#define CPU_SUPPORTS_NEON 0
#endif
#endif

#endif
