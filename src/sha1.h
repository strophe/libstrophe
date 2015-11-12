/* public api for steve reid's public domain SHA-1 implementation */
/* this file is in the public domain */

/** @file
 *  SHA-1 hash API.
 */

#ifndef __LIBSTROPHE_SHA1_H__
#define __LIBSTROPHE_SHA1_H__

#ifdef __cplusplus
extern "C" {
#endif

/* make sure the stdint.h types are available */
#include "ostypes.h"

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t  buffer[64];
} SHA1_CTX;

#define SHA1_DIGEST_SIZE 20

void crypto_SHA1_Init(SHA1_CTX* context);
void crypto_SHA1_Update(SHA1_CTX* context, const uint8_t* data,
                        const size_t len);
void crypto_SHA1_Final(SHA1_CTX* context, uint8_t* digest);
void crypto_SHA1(const uint8_t* data, size_t len, uint8_t* digest);

#ifdef __cplusplus
}
#endif

#endif /* __LIBSTROPHE_SHA1_H__ */
