/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#else
#include "macros.h"

#if !defined(HAVE_POSIX_MEMALIGN) &&                                                               \
    ((defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L) || defined(__APPLE__))

#define HAVE_POSIX_MEMALIGN
#endif

#if !defined(HAVE_MEMALIGN) && defined(__linux__)

#define HAVE_MEMALIGN
#endif

#if !defined(HAVE_CONSTTIME_MEMEQUAL) && NETBSD_CHECK(7, 0)

#define HAVE_CONSTTIME_MEMEQUAL
#endif
#endif

#include "compat.h"

#if !defined(HAVE_ALIGNED_ALLOC)
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#if !defined(HAVE_POSIX_MEMALIGN) || defined(__MING32__) || defined(__MING64__) || defined(_MSC_VER)
#include <malloc.h>
#endif

#if defined(HAVE_POSIX_MEMALIGN)
static_assert((sizeof(void*) & (sizeof(void*) - 1)) == 0, "sizeof void* is not a power of 2");
#endif

// Implements faest aligned alloc.
void* faest_aligned_alloc(size_t alignment, size_t size) {

  if (alignment & (alignment - 1) || size & (alignment - 1)) {
    errno = EINVAL;
    return NULL;
  }

#if defined(HAVE_POSIX_MEMALIGN)

  if (alignment < sizeof(void*)) {
    alignment = sizeof(void*);

    size = (size + sizeof(void*) - 1) & ~(sizeof(void*) - 1);
  }

  void* ptr     = NULL;
  const int err = posix_memalign(&ptr, alignment, size);
  if (err) {
    errno = err;
  }
  return ptr;
#elif defined(HAVE_MEMALIGN)
  return memalign(alignment, size);
#elif defined(__MINGW32__) || defined(__MINGW64__)
  return __mingw_aligned_malloc(size, alignment);
#elif defined(_MSC_VER)
  return _aligned_malloc(size, alignment);
#else
  if (!size) {
    return NULL;
  }
  const size_t offset = alignment - 1 + sizeof(uint8_t);
  uint8_t* buffer     = malloc(size + offset);
  if (!buffer) {
    return NULL;
  }

  uint8_t* ptr   = (uint8_t*)(((uintptr_t)(buffer) + offset) & ~(alignment - 1));
  ptrdiff_t diff = ptr - buffer;
  if (diff > UINT8_MAX) {

    free(buffer);
    errno = EINVAL;
    return NULL;
  }
  ptr[-1] = diff;
  return ptr;
#endif
}

// Implements faest aligned free.
void faest_aligned_free(void* ptr) {
#if defined(HAVE_POSIX_MEMALIGN) || defined(HAVE_MEMALIGN)
  free(ptr);
#elif defined(__MINGW32__) || defined(__MINGW64__)
  __mingw_aligned_free(ptr);
#elif defined(_MSC_VER)
  _aligned_free(ptr);
#else
  if (ptr) {
    uint8_t* u8ptr = ptr;
    free(u8ptr - u8ptr[-1]);
  }
#endif
}
#endif

#if !defined(HAVE_TIMINGSAFE_BCMP)
// Implements faest timingsafe bcmp.
int faest_timingsafe_bcmp(const void* a, const void* b, size_t len) {
#if defined(HAVE_CONSTTIME_MEMEQUAL)
  return !consttime_memequal(a, b, len);
#else
  const unsigned char* p1 = a;
  const unsigned char* p2 = b;

  unsigned int res = 0;
  for (; len; --len, ++p1, ++p2) {
    res |= *p1 ^ *p2;
  }
  return res;
#endif
}
#endif

#if !defined(HAVE_EXPLICIT_BZERO)
#if defined(_WIN32)
#include <windows.h>
#endif

// Implements faest explicit bzero.
void faest_explicit_bzero(void* a, size_t len) {
#if defined(_WIN32)
  SecureZeroMemory(a, len);
#else
  volatile char* p = a;
  for (; len; ++p, --len) {
    *p = 0;
  }
#endif
}
#endif
