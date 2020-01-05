/* scram.h
 * strophe XMPP client library -- SCRAM helper functions
 *
 * Copyright (C) 2013 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/** @file
 *  SCRAM helper functions.
 */

#ifndef __LIBSTROPHE_SCRAM_H__
#define __LIBSTROPHE_SCRAM_H__

/* make sure the stdint.h types are available */
#include "ostypes.h"

/* Maximum possible digest size. Used for buffers allocation. */
#include "sha512.h"
#define SCRAM_DIGEST_SIZE SHA512_DIGEST_SIZE

struct hash_alg {
    const char *scram_name;
    int mask;
    size_t digest_size;
    void (*hash)(const uint8_t *, size_t, uint8_t *);
    void (*init)(void *);
    void (*update)(void *, const uint8_t *, size_t);
    void (*final)(void *, uint8_t *);
};

extern const struct hash_alg scram_sha1;
extern const struct hash_alg scram_sha256;
extern const struct hash_alg scram_sha512;

void SCRAM_ClientKey(const struct hash_alg *alg,
                     const uint8_t *password,
                     size_t len,
                     const uint8_t *salt,
                     size_t salt_len,
                     uint32_t i,
                     uint8_t *key);

void SCRAM_ClientSignature(const struct hash_alg *alg,
                           const uint8_t *ClientKey,
                           const uint8_t *AuthMessage,
                           size_t len,
                           uint8_t *sign);

void SCRAM_ClientProof(const struct hash_alg *alg,
                       const uint8_t *ClientKey,
                       const uint8_t *ClientSignature,
                       uint8_t *proof);

#endif /* __LIBSTROPHE_SCRAM_H__ */
