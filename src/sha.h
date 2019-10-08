/* public api for steve reid's public domain SHA-1 implementation */
/* this file is in the public domain */

/** @file
 *  SHA-1 hash API.
 */

#ifndef __LIBSTROPHE_SHA_H__
#define __LIBSTROPHE_SHA_H__

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* make sure the stdint.h types are available */
#include "ostypes.h"

#if defined(__BIG_ENDIAN__) ||                                   \
    (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
     __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#define STORE32H(x, y)      \
    do {                    \
        uint32_t __t = (x); \
        memcpy(y, &__t, 4); \
    } while (0)

#define LOAD32H(x, y)       \
    do {                    \
        memcpy(&(x), y, 4); \
        x &= 0xFFFFFFFF;    \
    } while (0)

#define STORE64H(x, y)      \
    do {                    \
        uint64_t __t = (x); \
        memcpy(y, &__t, 8); \
    } while (0)

#define LOAD64H(x, y)       \
    do {                    \
        memcpy(&(x), y, 8); \
    } while (0)

#elif defined(__LITTLE_ENDIAN__) ||                                 \
    (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
     __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)

#define STORE32H(x, y)                         \
    do {                                       \
        (y)[0] = (uint8_t)(((x) >> 24) & 255); \
        (y)[1] = (uint8_t)(((x) >> 16) & 255); \
        (y)[2] = (uint8_t)(((x) >> 8) & 255);  \
        (y)[3] = (uint8_t)((x)&255);           \
    } while (0)

#define LOAD32H(x, y)                                                     \
    do {                                                                  \
        x = ((uint32_t)((y)[0] & 255) << 24) |                            \
            ((uint32_t)((y)[1] & 255) << 16) |                            \
            ((uint32_t)((y)[2] & 255) << 8) | ((uint32_t)((y)[3] & 255)); \
    } while (0)

#define STORE64H(x, y)                         \
    do {                                       \
        (y)[0] = (uint8_t)(((x) >> 56) & 255); \
        (y)[1] = (uint8_t)(((x) >> 48) & 255); \
        (y)[2] = (uint8_t)(((x) >> 40) & 255); \
        (y)[3] = (uint8_t)(((x) >> 32) & 255); \
        (y)[4] = (uint8_t)(((x) >> 24) & 255); \
        (y)[5] = (uint8_t)(((x) >> 16) & 255); \
        (y)[6] = (uint8_t)(((x) >> 8) & 255);  \
        (y)[7] = (uint8_t)((x)&255);           \
    } while (0)

#define LOAD64H(x, y)                                                         \
    do {                                                                      \
        x = (((uint64_t)((y)[0] & 255)) << 56) |                              \
            (((uint64_t)((y)[1] & 255)) << 48) |                              \
            (((uint64_t)((y)[2] & 255)) << 40) |                              \
            (((uint64_t)((y)[3] & 255)) << 32) |                              \
            (((uint64_t)((y)[4] & 255)) << 24) |                              \
            (((uint64_t)((y)[5] & 255)) << 16) |                              \
            (((uint64_t)((y)[6] & 255)) << 8) | (((uint64_t)((y)[7] & 255))); \
    } while (0)

#else
#error Unknown endianness not supported
#endif

#ifdef _MSC_VER
#define CONST64(n) n##ui64
#else
#define CONST64(n) n##ULL
#endif

#define RORc(x, y)                                           \
    (((((uint32_t)(x)&0xFFFFFFFFUL) >> (uint32_t)((y)&31)) | \
      ((uint32_t)(x) << (uint32_t)((32 - ((y)&31)) & 31))) & \
     0xFFFFFFFFUL)
#define ROR64c(x, y)                                                       \
    (((((x)&CONST64(0xFFFFFFFFFFFFFFFF)) >> ((uint64_t)(y)&CONST64(63))) | \
      ((x) << (((uint64_t)64 - ((y)&63)) & 63))) &                         \
     CONST64(0xFFFFFFFFFFFFFFFF))

#ifdef __cplusplus
}
#endif

#endif /* __LIBSTROPHE_SHA_H__ */
