/* scram.c
 * strophe XMPP client library
 *
 * SCRAM-SHA1 helper functions according to RFC5802
 * HMAC-SHA1 implementation according to RFC2104
 *
 * Copyright (C) 2013 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/** @file
 *  SCRAM-SHA1 helper functions.
 */

#include <assert.h>
#include <string.h>

#include "sha1.h"
#include "ostypes.h"

#include "scram.h"

#define HMAC_BLOCK_SIZE 64

static const uint8_t ipad = 0x36;
static const uint8_t opad = 0x5C;

static void crypto_HMAC_SHA1(const uint8_t *key, size_t key_len,
                             const uint8_t *text, size_t len,
                             uint8_t *digest)
{
    uint8_t key_pad[HMAC_BLOCK_SIZE];
    uint8_t key_ipad[HMAC_BLOCK_SIZE];
    uint8_t key_opad[HMAC_BLOCK_SIZE];
    uint8_t sha_digest[SHA1_DIGEST_SIZE];
    int i;
    SHA1_CTX ctx;

    memset(key_pad, 0, sizeof(key_pad));
    if (key_len <= HMAC_BLOCK_SIZE) {
        memcpy(key_pad, key, key_len);
    } else {
        /* according to RFC2104 */
        crypto_SHA1(key, key_len, key_pad);
    }

    for (i = 0; i < HMAC_BLOCK_SIZE; i++) {
        key_ipad[i] = key_pad[i] ^ ipad;
        key_opad[i] = key_pad[i] ^ opad;
    }

    crypto_SHA1_Init(&ctx);
    crypto_SHA1_Update(&ctx, key_ipad, HMAC_BLOCK_SIZE);
    crypto_SHA1_Update(&ctx, text, len);
    crypto_SHA1_Final(&ctx, sha_digest);

    crypto_SHA1_Init(&ctx);
    crypto_SHA1_Update(&ctx, key_opad, HMAC_BLOCK_SIZE);
    crypto_SHA1_Update(&ctx, sha_digest, SHA1_DIGEST_SIZE);
    crypto_SHA1_Final(&ctx, digest);
}

static void SCRAM_SHA1_Hi(const uint8_t *text, size_t len,
                          const uint8_t *salt, size_t salt_len, uint32_t i,
                          uint8_t *digest)
{
    int  k;
    uint32_t j;
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
    crypto_HMAC_SHA1(text, len, tmp, salt_len + sizeof(int1), digest);
    memcpy(tmp, digest, SHA1_DIGEST_SIZE);

    for (j = 1; j < i; j++) {
        crypto_HMAC_SHA1(text, len, tmp, SHA1_DIGEST_SIZE, tmp);
        for (k = 0; k < SHA1_DIGEST_SIZE; k++) {
            digest[k] ^= tmp[k];
        }
    }
}

void SCRAM_SHA1_ClientKey(const uint8_t *password, size_t len,
                          const uint8_t *salt, size_t salt_len, uint32_t i,
                          uint8_t *key)
{
    uint8_t salted[SHA1_DIGEST_SIZE];

    /* XXX: Normalize(password) is omitted */

    SCRAM_SHA1_Hi(password, len, salt, salt_len, i, salted);
    crypto_HMAC_SHA1(salted, SHA1_DIGEST_SIZE, (uint8_t *)"Client Key",
                     strlen("Client Key"), key);
}

void SCRAM_SHA1_ClientSignature(const uint8_t *ClientKey,
                                const uint8_t *AuthMessage, size_t len,
                                uint8_t *sign)
{
    uint8_t stored[SHA1_DIGEST_SIZE];

    crypto_SHA1(ClientKey, SHA1_DIGEST_SIZE, stored);
    crypto_HMAC_SHA1(stored, SHA1_DIGEST_SIZE, AuthMessage, len, sign);
}

void SCRAM_SHA1_ClientProof(const uint8_t *ClientKey,
                            const uint8_t *ClientSignature,
                            uint8_t *proof)
{
    int i;
    for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
        proof[i] = ClientKey[i] ^ ClientSignature[i];
    }
}
