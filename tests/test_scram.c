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
    char *P;      /* text */
    char *S;      /* salt */
    size_t P_len;
    size_t S_len;
    uint32_t c;   /* i */
    char *DK;     /* resulting digest */
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

static void test_df(void)
{
    size_t i;
    const char *s;
    uint8_t dk[SHA1_DIGEST_SIZE];

    printf("Derivation function tests (SCRAM_SHA1_Hi).\n");
    for (i = 0; i < ARRAY_SIZE(df_vectors); ++i) {
        printf("Test #%d: ", (int)i + 1);
        SCRAM_SHA1_Hi((uint8_t *)df_vectors[i].P, df_vectors[i].P_len,
                      (uint8_t *)df_vectors[i].S, df_vectors[i].S_len,
                      df_vectors[i].c, dk);
        s = test_bin_to_hex(dk, sizeof(dk));
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

static void test_scram(void)
{
    uint8_t key[SHA1_DIGEST_SIZE];
    uint8_t sign[SHA1_DIGEST_SIZE];
    uint8_t salt[256];
    size_t salt_len;
    char auth[512];
    const char *s;
    size_t i;
    int j;

    printf("SCRAM_SHA1_ClientKey and SCRAM_SHA1_ClientSignature tests.\n");
    for (i = 0; i < ARRAY_SIZE(scram_vectors); ++i) {
        printf("Test #%d: ", (int)i + 1);
        snprintf(auth, sizeof(auth), "%s,%s,%s",
                 scram_vectors[i].initial + 3, scram_vectors[i].challenge,
                 scram_vectors[i].response);
        test_hex_to_bin(scram_vectors[i].salt, salt, &salt_len);

        SCRAM_SHA1_ClientKey((uint8_t *)scram_vectors[i].password,
                             strlen(scram_vectors[i].password),
                             salt, salt_len, scram_vectors[i].i, key);
        SCRAM_SHA1_ClientSignature(key, (uint8_t *)auth, strlen(auth), sign);
        for (j = 0; j < SHA1_DIGEST_SIZE; j++) {
            sign[j] ^= key[j];
        }
        s = test_bin_to_hex(sign, SHA1_DIGEST_SIZE);
        COMPARE(scram_vectors[i].sign, s);
        printf("ok\n");
    }
}

int main(int argc, char **argv)
{
    test_df();
    test_scram();

    return 0;
}
