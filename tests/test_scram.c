/* test_scram.c
 * strophe XMPP client library -- test vectors for SCRAM-SHA1
 *
 * Copyright (C) 2014 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/* gcc -o test_scram -I./src tests/test_scram.c tests/test.c src/sha1.c */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "test.h"

/* include scram.c to access static functions */
#include "scram.c"

/*
 * Test vectors for derivation function (RFC6070).
 */
static const struct {
    char *P; /* text */
    char *S; /* salt */
    size_t P_len;
    size_t S_len;
    uint32_t c; /* i */
    char *DK;   /* resulting digest */
} df_vectors[] = {
    {
        .P = "password",
        .S = "salt",
        .P_len = 8,
        .S_len = 4,
        .c = 1,
        .DK = "0c60c80f961f0e71f3a9b524af6012062fe037a6",
    },
    {
        .P = "password",
        .S = "salt",
        .P_len = 8,
        .S_len = 4,
        .c = 2,
        .DK = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
    },
    {
        .P = "password",
        .S = "salt",
        .P_len = 8,
        .S_len = 4,
        .c = 4096,
        .DK = "4b007901b765489abead49d926f721d065a429c1",
    },
};

static void test_df(const struct hash_alg *alg)
{
    size_t i;
    const char *s;
    uint8_t dk[SCRAM_DIGEST_SIZE];

    printf("Derivation function SCRAM_Hi tests for %s.\n", alg->scram_name);
    for (i = 0; i < ARRAY_SIZE(df_vectors); ++i) {
        printf("Test #%d: ", (int)i + 1);
        SCRAM_Hi(alg, (uint8_t *)df_vectors[i].P, df_vectors[i].P_len,
                 (uint8_t *)df_vectors[i].S, df_vectors[i].S_len,
                 df_vectors[i].c, dk);
        s = test_bin_to_hex(dk, alg->digest_size);
        COMPARE(df_vectors[i].DK, s);
        printf("ok\n");
    }
}

/* RFC6120 */
static const struct {
    char *password;
    char *initial;
    char *challenge;
    char *response;
    char *salt;
    uint32_t i;
    char *sign;
} scram_vectors[] = {
    {
        .password = "r0m30myr0m30",
        .initial = "n,,n=juliet,r=oMsTAAwAAAAMAAAANP0TAAAAAABPU0AA",
        .challenge = "r=oMsTAAwAAAAMAAAANP0TAAAAAABPU0AAe124695b-69a9-4de6-9c30"
                     "-b51b3808c59e,s=NjhkYTM0MDgtNGY0Zi00NjdmLTkxMmUtNDlmNTNmN"
                     "DNkMDMz,i=4096",
        .response = "c=biws,r=oMsTAAwAAAAMAAAANP0TAAAAAABPU0AAe124695b-69a9-4de"
                    "6-9c30-b51b3808c59e",
        .salt = "36386461333430382d346634662d34363766"
                "2d393132652d343966353366343364303333",
        .i = 4096,
        .sign = "500e7bb4cfd2be90130641f6157b345835ef258c",
    },
};

static void test_scram(const struct hash_alg *alg)
{
    uint8_t key[SCRAM_DIGEST_SIZE];
    uint8_t sign[SCRAM_DIGEST_SIZE];
    uint8_t salt[256];
    size_t salt_len;
    char auth[512];
    const char *s;
    size_t i;
    size_t j;

    printf("SCRAM_ClientKey and SCRAM_ClientSignature tests for %s.\n",
           alg->scram_name);
    for (i = 0; i < ARRAY_SIZE(scram_vectors); ++i) {
        printf("Test #%d: ", (int)i + 1);
        snprintf(auth, sizeof(auth), "%s,%s,%s", scram_vectors[i].initial + 3,
                 scram_vectors[i].challenge, scram_vectors[i].response);
        test_hex_to_bin(scram_vectors[i].salt, salt, &salt_len);

        SCRAM_ClientKey(alg, (uint8_t *)scram_vectors[i].password,
                        strlen(scram_vectors[i].password), salt, salt_len,
                        scram_vectors[i].i, key);
        SCRAM_ClientSignature(alg, key, (uint8_t *)auth, strlen(auth), sign);
        for (j = 0; j < alg->digest_size; j++) {
            sign[j] ^= key[j];
        }
        s = test_bin_to_hex(sign, alg->digest_size);
        COMPARE(scram_vectors[i].sign, s);
        printf("ok\n");
    }
}

/*
 * Test vectors for HMAC (RFC2202, RFC4231).
 */
static const uint8_t hmac_key1[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
static const uint8_t hmac_data1[] = {0x48, 0x69, 0x20, 0x54,
                                     0x68, 0x65, 0x72, 0x65};
static const struct {
    const uint8_t *key;
    size_t key_len;
    const uint8_t *data;
    size_t data_len;
    const uint8_t sha1[SHA1_DIGEST_SIZE];
    const uint8_t sha256[SHA256_DIGEST_SIZE];
    const uint8_t sha512[SHA512_DIGEST_SIZE];
} hmac_vectors[] = {
    {
        .key = hmac_key1,
        .key_len = sizeof(hmac_key1),
        .data = hmac_data1,
        .data_len = sizeof(hmac_data1),
        .sha1 = {0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b,
                 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00},
        .sha256 = {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
                   0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
                   0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
                   0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7},
        .sha512 = {0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0,
                   0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2,
                   0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1,
                   0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02,
                   0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d,
                   0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70, 0x2e, 0x69, 0x6c, 0x20,
                   0x3a, 0x12, 0x68, 0x54},
    },
};

static void test_hmac(const struct hash_alg *alg)
{
    size_t i;
    uint8_t digest[SCRAM_DIGEST_SIZE];

    printf("HMAC tests for %s.\n", alg->scram_name);
    for (i = 0; i < ARRAY_SIZE(hmac_vectors); ++i) {
        printf("Test #%d: ", (int)i + 1);
        memset(digest, 0, sizeof(digest));
        crypto_HMAC(alg, hmac_vectors[i].key, hmac_vectors[i].key_len,
                    hmac_vectors[i].data, hmac_vectors[i].data_len, digest);
        switch (alg->digest_size) {
        case SHA1_DIGEST_SIZE:
            COMPARE_BUF(hmac_vectors[i].sha1, alg->digest_size, digest,
                        alg->digest_size);
            break;
        case SHA256_DIGEST_SIZE:
            COMPARE_BUF(hmac_vectors[i].sha256, alg->digest_size, digest,
                        alg->digest_size);
            break;
        case SHA512_DIGEST_SIZE:
            COMPARE_BUF(hmac_vectors[i].sha512, alg->digest_size, digest,
                        alg->digest_size);
            break;
        default:
            printf("Unknown digest size: %zu\n", alg->digest_size);
            exit(1);
        }
        printf("ok\n");
    }
}

int main()
{
    test_df(&scram_sha1);
    test_scram(&scram_sha1);
    test_hmac(&scram_sha1);
    test_hmac(&scram_sha256);
    test_hmac(&scram_sha512);

    return 0;
}
