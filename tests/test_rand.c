/* check_rand.c
 * strophe XMPP client library -- test vectors for Hash_DRBG
 *
 * Copyright (C) 2014 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/* gcc -o test_rand -I./src tests/test_rand.c tests/test.c src/sha1.c */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "test.h"

/* include rand.c to access private structures and functions */
#include "rand.c"

/* stubs to build test without whole libstrophe */
void *xmpp_alloc(const xmpp_ctx_t * const ctx, const size_t size) {
    return NULL;
}
void xmpp_free(const xmpp_ctx_t * const ctx, void *p) { }
int xmpp_snprintf (char *str, size_t count, const char *fmt, ...) {
    return 0;
}
uint64_t time_stamp(void) {
    return 0;
}

static struct {
    const char *entropy_input;
    const char *nonce;
    size_t returned_bytes;
    /* after instantiate */
    const char *V1;
    const char *C1;
    /* after first generate */
    const char *V2;
    const char *C2;
    /* after second generate */
    const char *V3;
    const char *C3;
    const char *output;
} test_vectors[] = {
    {
        .entropy_input = "136cf1c174e5a09f66b962d994396525",
        .nonce = "fff1c6645f19231f",
        .returned_bytes = 80,
        .V1 = "a884a83fa40bcf730e7395dd5800ea7101b48"
              "77aaa29da9b7bc0bd2bd052b9b4022f83bae3"
              "8064134a233835845fdd1442bf3a0221bdc8",
        .C1 = "4977fb1268c1f6286b5b3969d416fb8ca7e4e"
              "aab7fd2edefc239202baa033f8b44e9145148"
              "ad24ce83d597176a0bacc84c99246f15e088",
        .V2 = "f1fca3520ccdc59b79cecf472c17e5fda9997"
              "22629fcc88b3df9dd577a55f93f47189892b1"
              "8e1c5f39dfc077ae256588eecec7bbd0323c",
        .C2 = "4977fb1268c1f6286b5b3969d416fb8ca7e4e"
              "aab7fd2edefc239202baa033f8b44e9145148"
              "ad24ce83d597176a0bacc84c99246f15e088",
        .V3 = "3b749e64758fbbc3e52a08b1002ee18a517e5"
              "cd1a9cfb67b0032fd83245938ca8c01add770"
              "68515bde248c75adea10bbaaf0bc18e66a2c",
        .C3 = "4977fb1268c1f6286b5b3969d416fb8ca7e4e"
              "aab7fd2edefc239202baa033f8b44e9145148"
              "ad24ce83d597176a0bacc84c99246f15e088",
        .output = "0e28130fa5ca11edd3293ca26fdb8ae1810611f7"
                  "8715082ed3841e7486f16677b28e33ffe0b93d98"
                  "ba57ba358c1343ab2a26b4eb7940f5bc63938464"
                  "1ee80a25140331076268bd1ce702ad534dda0ed8",
    },

    {
        .entropy_input = "dfed69b08902fcfb795d5d35dbe23f6b",
        .nonce = "37258e820432e392",
        .returned_bytes = 80,
        .V1 = "2708022f0f6d13cd8bc139ceb86ee237ee124"
              "e17029ac4f053d41526285599d4eac5029972"
              "7d83a0df0d5fa9824d5f14d7e7e9c8bdb165",
        .C1 = "fdb1a827c30e436c997261da6dc31ae7c27ee"
              "28e5c29b2ee0ca57b44ab78b7b0d1e8b459ba"
              "7285f5d93abf218d16d834a803c2330321cd",
        .V2 = "24b9aa56d27b573a25339ba92631fd1fb0913"
              "0a55ec477de6079906ad3ce5185bcadb7b047"
              "627060f80afb8529c18b46567e6b79dffb01",
        .C2 = "fdb1a827c30e436c997261da6dc31ae7c27ee"
              "28e5c29b2ee0ca57b44ab78b7b0d1e8b459ba"
              "7285f5d93abf218d16d834a803c2330321cd",
        .V3 = "226b527e95899aa6bea5fd8393f5180773101"
              "333baee2acc6d1f0baf7f4709368e966c945c"
              "d4a0d86093183375443379b09c08e4381fa8",
        .C3 = "fdb1a827c30e436c997261da6dc31ae7c27ee"
              "28e5c29b2ee0ca57b44ab78b7b0d1e8b459ba"
              "7285f5d93abf218d16d834a803c2330321cd",
        .output = "adcb8e2cbbc5957d538a20db18b5e7fe350a90a2"
                  "01359fab9e0f154c53aa146bc6af1fcc7ff8f330"
                  "b8d9f3d7b038488ba627e6fa21d0147377b13404"
                  "22b22634b412dac69ac82c35b5fb411a4e42a133",
    },
};

int main()
{
    size_t i;
    uint8_t entropy_input[1024];
    size_t entropy_input_len;
    uint8_t nonce[1024];
    size_t nonce_len;
    uint8_t output[1024];
    Hash_DRBG_CTX ctx;

    printf("Hash_DRBG tests.\n");
    for (i = 0; i < ARRAY_SIZE(test_vectors); ++i) {
        printf("Test #%d: ", (int)i + 1);
        test_hex_to_bin(test_vectors[i].entropy_input, entropy_input,
                        &entropy_input_len);
        test_hex_to_bin(test_vectors[i].nonce, nonce, &nonce_len);

        Hash_DRBG_Instantiate(&ctx, entropy_input, entropy_input_len,
                              nonce, nonce_len);
        COMPARE(test_vectors[i].V1, test_bin_to_hex(ctx.V, sizeof(ctx.V)));
        COMPARE(test_vectors[i].C1, test_bin_to_hex(ctx.C, sizeof(ctx.C)));
        assert(ctx.reseed_counter == 1);

        Hash_DRBG_Generate(&ctx, output, test_vectors[i].returned_bytes);
        COMPARE(test_vectors[i].V2, test_bin_to_hex(ctx.V, sizeof(ctx.V)));
        COMPARE(test_vectors[i].C2, test_bin_to_hex(ctx.C, sizeof(ctx.C)));
        assert(ctx.reseed_counter == 2);

        Hash_DRBG_Generate(&ctx, output, test_vectors[i].returned_bytes);
        COMPARE(test_vectors[i].V3, test_bin_to_hex(ctx.V, sizeof(ctx.V)));
        COMPARE(test_vectors[i].C3, test_bin_to_hex(ctx.C, sizeof(ctx.C)));
        COMPARE(test_vectors[i].output,
                test_bin_to_hex(output, test_vectors[i].returned_bytes));
        assert(ctx.reseed_counter == 3);
        printf("ok\n");
    }

    return 0;
}
