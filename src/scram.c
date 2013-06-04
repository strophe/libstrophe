/* scram.c
 * libcouplet - fork of libstrophe, XMPP client library
 * SCRAM-SHA1 helper functions according to RFC5802
 * HMAC-SHA1 implementation according to RFC2104
 *
 * Copyright (C) 2013 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This software is distributed under license and may not be copied,
 *  modified or distributed except as expressly authorized under the
 *  terms of the license contained in the file LICENSE.txt in this
 *  distribution.
 */

/** @file
 *  SCRAM-SHA1 helper functions.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "sha1.h"

#include "scram.h"

/* block size for HMAC */
#define BLOCK_SIZE 64
#if BLOCK_SIZE < SHA1_DIGEST_SIZE
#error BLOCK_SIZE must not be less than SHA1_DIGEST_SIZE
#endif

static const uint64_t ipad = 0x3636363636363636;
static const uint64_t opad = 0x5C5C5C5C5C5C5C5C;

static inline void SHA1(const uint8_t* data, size_t len,
                        uint8_t digest[SHA1_DIGEST_SIZE])
{
    SHA1_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data, len);
    SHA1_Final(&ctx, digest);
}

static void HMAC_SHA1(const uint8_t *key, size_t key_len,
                      const uint8_t *text, size_t len,
                      uint8_t digest[SHA1_DIGEST_SIZE])
{
    uint64_t key_pad[BLOCK_SIZE / sizeof(uint64_t)];
    uint64_t key_ipad[BLOCK_SIZE / sizeof(uint64_t)];
    uint64_t key_opad[BLOCK_SIZE / sizeof(uint64_t)];
    uint8_t sha_digest[SHA1_DIGEST_SIZE];
    int i;
    SHA1_CTX ctx;

    memset(key_pad, 0, sizeof(key_pad));
    if (key_len <= BLOCK_SIZE) {
        memcpy(key_pad, key, key_len);
    } else {
        /* according to RFC2104 */
        SHA1(key, key_len, (uint8_t *)key_pad);
    }

    for (i = 0; i < (BLOCK_SIZE / sizeof(uint64_t)); i++) {
        key_ipad[i] = key_pad[i] ^ ipad;
        key_opad[i] = key_pad[i] ^ opad;
    }

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, (uint8_t *)key_ipad, BLOCK_SIZE);
    SHA1_Update(&ctx, text, len);
    SHA1_Final(&ctx, sha_digest);

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, (uint8_t *)key_opad, BLOCK_SIZE);
    SHA1_Update(&ctx, sha_digest, SHA1_DIGEST_SIZE);
    SHA1_Final(&ctx, digest);
}

static void SCRAM_SHA1_Hi(const uint8_t *text, size_t len,
                          const uint8_t *salt, size_t salt_len, uint32_t i,
                          uint8_t digest[SHA1_DIGEST_SIZE])
{
    int j, k;
    uint8_t tmp[128];

    static uint8_t int1[] = {0x0, 0x0, 0x0, 0x1};

    /* assume salt + INT(1) isn't longer than sizeof(tmp) */
    assert(salt_len <= sizeof(tmp) - sizeof(int1));

    memset(digest, 0, SHA1_DIGEST_SIZE);
    if (i == 0) {
        return;
    }

    memcpy(tmp, salt, salt_len);
    memcpy(&tmp[salt_len], int1, sizeof(int1));

    /* 'text' for Hi is a 'key' for HMAC */
    HMAC_SHA1(text, len, tmp, salt_len + sizeof(int1), digest);
    memcpy(tmp, digest, SHA1_DIGEST_SIZE);

    for (j = 1; j < i; j++) {
        HMAC_SHA1(text, len, tmp, SHA1_DIGEST_SIZE, tmp);
        for (k = 0; k < SHA1_DIGEST_SIZE; k++) {
            /* TODO: optimize */
            digest[k] ^= tmp[k];
        }
    }
}

void SCRAM_SHA1_ClientKey(const uint8_t *password, size_t len,
                          const uint8_t *salt, size_t salt_len, uint32_t i,
                          uint8_t key[SHA1_DIGEST_SIZE])
{
    uint8_t salted[SHA1_DIGEST_SIZE];

    /* XXX: Normalize(password) is omitted */

    SCRAM_SHA1_Hi(password, len, salt, salt_len, i, salted);
    HMAC_SHA1(salted, SHA1_DIGEST_SIZE, (uint8_t *)"Client Key",
              strlen("Client Key"), key);
}

void SCRAM_SHA1_ClientSignature(const uint8_t ClientKey[SHA1_DIGEST_SIZE],
                                const uint8_t *AuthMessage, size_t len,
                                uint8_t sign[SHA1_DIGEST_SIZE])
{
    uint8_t stored[SHA1_DIGEST_SIZE];

    SHA1(ClientKey, SHA1_DIGEST_SIZE, stored);
    HMAC_SHA1(stored, SHA1_DIGEST_SIZE, AuthMessage, len, sign);
}

void SCRAM_SHA1_ClientProof(const uint8_t ClientKey[SHA1_DIGEST_SIZE],
                            const uint8_t ClientSignature[SHA1_DIGEST_SIZE],
                            uint8_t proof[SHA1_DIGEST_SIZE])
{
    int i;
    for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
        /* TODO: optimize */
        proof[i] = ClientKey[i] ^ ClientSignature[i];
    }
}
