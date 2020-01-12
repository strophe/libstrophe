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

#include "common.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "ostypes.h"

#include "scram.h"

#define HMAC_BLOCK_SIZE_MAX 128

static const uint8_t ipad = 0x36;
static const uint8_t opad = 0x5C;

const struct hash_alg scram_sha1 = {
    "SCRAM-SHA-1",
    SASL_MASK_SCRAMSHA1,
    SHA1_DIGEST_SIZE,
    (void (*)(const uint8_t *, size_t, uint8_t *))crypto_SHA1,
    (void (*)(void *))crypto_SHA1_Init,
    (void (*)(void *, const uint8_t *, size_t))crypto_SHA1_Update,
    (void (*)(void *, uint8_t *))crypto_SHA1_Final};

const struct hash_alg scram_sha256 = {
    "SCRAM-SHA-256",
    SASL_MASK_SCRAMSHA256,
    SHA256_DIGEST_SIZE,
    (void (*)(const uint8_t *, size_t, uint8_t *))sha256_hash,
    (void (*)(void *))sha256_init,
    (void (*)(void *, const uint8_t *, size_t))sha256_process,
    (void (*)(void *, uint8_t *))sha256_done};

const struct hash_alg scram_sha512 = {
    "SCRAM-SHA-512",
    SASL_MASK_SCRAMSHA512,
    SHA512_DIGEST_SIZE,
    (void (*)(const uint8_t *, size_t, uint8_t *))sha512_hash,
    (void (*)(void *))sha512_init,
    (void (*)(void *, const uint8_t *, size_t))sha512_process,
    (void (*)(void *, uint8_t *))sha512_done};

union common_hash_ctx {
    SHA1_CTX sha1;
    sha256_context sha256;
    sha512_context sha512;
};

static void crypto_HMAC(const struct hash_alg *alg,
                        const uint8_t *key,
                        size_t key_len,
                        const uint8_t *text,
                        size_t len,
                        uint8_t *digest)
{
    uint8_t key_pad[HMAC_BLOCK_SIZE_MAX];
    uint8_t key_ipad[HMAC_BLOCK_SIZE_MAX];
    uint8_t key_opad[HMAC_BLOCK_SIZE_MAX];
    uint8_t sha_digest[SCRAM_DIGEST_SIZE];
    size_t blocksize;
    size_t i;
    union common_hash_ctx ctx;

    assert(alg->digest_size <= HMAC_BLOCK_SIZE_MAX);
    blocksize = alg->digest_size < 48 ? 64 : 128;

    memset(key_pad, 0, blocksize);
    if (key_len <= blocksize) {
        memcpy(key_pad, key, key_len);
    } else {
        /* according to RFC2104 */
        alg->hash(key, key_len, key_pad);
    }

    for (i = 0; i < blocksize; i++) {
        key_ipad[i] = key_pad[i] ^ ipad;
        key_opad[i] = key_pad[i] ^ opad;
    }

    alg->init((void *)&ctx);
    alg->update((void *)&ctx, key_ipad, blocksize);
    alg->update((void *)&ctx, text, len);
    alg->final((void *)&ctx, sha_digest);

    alg->init((void *)&ctx);
    alg->update((void *)&ctx, key_opad, blocksize);
    alg->update((void *)&ctx, sha_digest, alg->digest_size);
    alg->final((void *)&ctx, digest);
}

static void SCRAM_Hi(const struct hash_alg *alg,
                     const uint8_t *text,
                     size_t len,
                     const uint8_t *salt,
                     size_t salt_len,
                     uint32_t i,
                     uint8_t *digest)
{
    size_t k;
    uint32_t j;
    uint8_t tmp[128];

    static uint8_t int1[] = {0x0, 0x0, 0x0, 0x1};

    /* assume salt + INT(1) isn't longer than sizeof(tmp) */
    assert(salt_len <= sizeof(tmp) - sizeof(int1));

    memset(digest, 0, alg->digest_size);
    if (i == 0) {
        return;
    }

    memcpy(tmp, salt, salt_len);
    memcpy(&tmp[salt_len], int1, sizeof(int1));

    /* 'text' for Hi is a 'key' for HMAC */
    crypto_HMAC(alg, text, len, tmp, salt_len + sizeof(int1), digest);
    memcpy(tmp, digest, alg->digest_size);

    for (j = 1; j < i; j++) {
        crypto_HMAC(alg, text, len, tmp, alg->digest_size, tmp);
        for (k = 0; k < alg->digest_size; k++) {
            digest[k] ^= tmp[k];
        }
    }
}

void SCRAM_ClientKey(const struct hash_alg *alg,
                     const uint8_t *password,
                     size_t len,
                     const uint8_t *salt,
                     size_t salt_len,
                     uint32_t i,
                     uint8_t *key)
{
    uint8_t salted[SCRAM_DIGEST_SIZE];

    /* XXX: Normalize(password) is omitted */

    SCRAM_Hi(alg, password, len, salt, salt_len, i, salted);
    crypto_HMAC(alg, salted, alg->digest_size, (uint8_t *)"Client Key",
                strlen("Client Key"), key);
}

void SCRAM_ClientSignature(const struct hash_alg *alg,
                           const uint8_t *ClientKey,
                           const uint8_t *AuthMessage,
                           size_t len,
                           uint8_t *sign)
{
    uint8_t stored[SCRAM_DIGEST_SIZE];

    alg->hash(ClientKey, alg->digest_size, stored);
    crypto_HMAC(alg, stored, alg->digest_size, AuthMessage, len, sign);
}

void SCRAM_ClientProof(const struct hash_alg *alg,
                       const uint8_t *ClientKey,
                       const uint8_t *ClientSignature,
                       uint8_t *proof)
{
    size_t i;
    for (i = 0; i < alg->digest_size; i++) {
        proof[i] = ClientKey[i] ^ ClientSignature[i];
    }
}
