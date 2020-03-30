/* public api for LibTomCrypt SHA-512 implementation */

/** @file
 *  SHA-512 hash API.
 */

#ifndef __LIBSTROPHE_SHA512_H__
#define __LIBSTROPHE_SHA512_H__

#ifdef __cplusplus
extern "C" {
#endif

/* make sure the stdint.h types are available */
#include "ostypes.h"

typedef struct {
    uint64_t length, state[8];
    uint8_t curlen;
    uint8_t buf[128];
} sha512_context;

#define SHA512_DIGEST_SIZE 64

void sha512_init(sha512_context *cc);
void sha512_process(sha512_context *cc, const uint8_t *data, size_t len);
void sha512_done(sha512_context *cc, uint8_t *dst);

void sha512_hash(const uint8_t *data, size_t len, uint8_t *digest);
#ifdef __cplusplus
}
#endif

#endif /* __LIBSTROPHE_SHA512_H__ */
