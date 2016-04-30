/* test_base64.c
** libstrophe XMPP client library -- test routines for the base64 codec
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "strophe.h"

#include "test.h"

static const unsigned char test_2_raw[] =
    {0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e, 0x00};
static const unsigned char test_4_raw[] =
    {0xd6, 0x2f, 0x27, 0x49,  0x7e, 0xdd, 0xf3, 0xd5,
     0x41, 0xbc, 0x1b, 0xe9,  0xdf, 0xe9, 0xb3, 0x08, 0x00};

static const struct {
    char *raw;
    char *base64;
} tests[] = {
    {
        .raw = "How now brown cow?",
        .base64 = "SG93IG5vdyBicm93biBjb3c/",
    },
    {
        .raw = (char *)test_2_raw,
        .base64 = "FPucA9l+",
    },
    {
        .raw =
            "From rest and sleep, which but thy pictures be, "
            "Much pleasure; then from thee much more must flow, "
            "And soonest our best men with thee do go, "
            "Rest of their bones, and soul's delivery.",
        .base64 =
            "RnJvbSByZXN0IGFuZCBzbGVlcCwgd2hpY2ggYnV0IHRoeSBwaWN0dXJl"
            "cyBiZSwgTXVjaCBwbGVhc3VyZTsgdGhlbiBmcm9tIHRoZWUgbXVjaCBt"
            "b3JlIG11c3QgZmxvdywgQW5kIHNvb25lc3Qgb3VyIGJlc3QgbWVuIHdp"
            "dGggdGhlZSBkbyBnbywgUmVzdCBvZiB0aGVpciBib25lcywgYW5kIHNv"
            "dWwncyBkZWxpdmVyeS4=",
    },
    {
        .raw = (char *)test_4_raw,
        .base64 = "1i8nSX7d89VBvBvp3+mzCA==",
    },
    {
        .raw =
            "realm=\"chesspark.com\",nonce=\"b243c0d663257a9149999cef2f83"
            "a22116559e93\",qop=\"auth\",charset=utf-8,algorithm=md5-sess",
        .base64 =
            "cmVhbG09ImNoZXNzcGFyay5jb20iLG5vbmNlPSJiMjQzYzBkNjYzMjU3"
            "YTkxNDk5OTljZWYyZjgzYTIyMTE2NTU5ZTkzIixxb3A9ImF1dGgiLGNo"
            "YXJzZXQ9dXRmLTgsYWxnb3JpdGhtPW1kNS1zZXNz",
    },

    /* RFC4648 test vectors */
    {
        .raw = "",
        .base64 = "",
    },
    {
        .raw = "f",
        .base64 = "Zg==",
    },
    {
        .raw = "fo",
        .base64 = "Zm8=",
    },
    {
        .raw = "foo",
        .base64 = "Zm9v",
    },
    {
        .raw = "foob",
        .base64 = "Zm9vYg==",
    },
    {
        .raw = "fooba",
        .base64 = "Zm9vYmE=",
    },
    {
        .raw = "foobar",
        .base64 = "Zm9vYmFy",
    },
};

static const unsigned char bin_data[] = {
    0xda, 0xa8, 0x81, 0x80, 0x00, 0x01, 0x00, 0x05,
    0x00, 0x00, 0x00, 0x00, 0x0c, 0x5f, 0x78, 0x6d,
    0x70, 0x70, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e,
    0x74, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x67,
    0x6d, 0x61, 0x69, 0x6c, 0x03, 0x63, 0x6f, 0x6d,
    0x00, 0x00, 0x21, 0x00, 0x01, 0xc0, 0x0c, 0x00,
    0x21, 0x00, 0x01, 0x00, 0x00, 0x02, 0x43, 0x00,
    0x1e, 0x00, 0x14, 0x00, 0x00, 0x14, 0x66, 0x04,
    0x61, 0x6c, 0x74, 0x31, 0x04, 0x78, 0x6d, 0x70,
    0x70, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f, 0x67,
    0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0xc0,
    0x0c, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x02,
    0x43, 0x00, 0x1e, 0x00, 0x14, 0x00, 0x00, 0x14,
    0x66, 0x04, 0x61, 0x6c, 0x74, 0x34, 0x04, 0x78,
    0x6d, 0x70, 0x70, 0x01, 0x6c, 0x06, 0x67, 0x6f,
    0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
    0x00, 0xc0, 0x0c, 0x00, 0x21, 0x00, 0x01, 0x00,
    0x00, 0x02, 0x43, 0x00, 0x1e, 0x00, 0x14, 0x00,
    0x00, 0x14, 0x66, 0x04, 0x61, 0x6c, 0x74, 0x32,
    0x04, 0x78, 0x6d, 0x70, 0x70, 0x01, 0x6c, 0x06,
    0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63,
    0x6f, 0x6d, 0x00, 0xc0, 0x0c, 0x00, 0x21, 0x00,
    0x01, 0x00, 0x00, 0x02, 0x43, 0x00, 0x19, 0x00,
    0x05, 0x00, 0x00, 0x14, 0x66, 0x04, 0x78, 0x6d,
    0x70, 0x70, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f,
    0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
    0xc0, 0x0c, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00,
    0x02, 0x43, 0x00, 0x1e, 0x00, 0x14, 0x00, 0x00,
    0x14, 0x66, 0x04, 0x61, 0x6c, 0x74, 0x33, 0x04,
    0x78, 0x6d, 0x70, 0x70, 0x01, 0x6c, 0x06, 0x67,
    0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f,
    0x6d, 0x00,
};

int main(int argc, char *argv[])
{
    xmpp_ctx_t *ctx;
    unsigned char *udec;
    char *dec;
    char *enc;
    size_t len;
    int i;

    printf("BASE64 tests.\n");

    ctx = xmpp_ctx_new(NULL, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "failed to create context\n");
        return 1;
    }

    for (i = 0; i < ARRAY_SIZE(tests); ++i) {
        printf("Test #%d: ", (int)i + 1);
        enc = xmpp_base64_encode(ctx, (unsigned char *)tests[i].raw,
                                 strlen(tests[i].raw));
        assert(enc != NULL);
        COMPARE(tests[i].base64, enc);
        xmpp_free(ctx, enc);

        dec = xmpp_base64_decode_str(ctx, tests[i].base64,
                                     strlen(tests[i].base64));
        assert(dec != NULL);
        COMPARE_BUF(tests[i].raw, strlen(tests[i].raw), dec, strlen(dec));
        xmpp_free(ctx, dec);
        printf("ok\n");
    }

    printf("Test with binary data: ");
    enc = xmpp_base64_encode(ctx, bin_data, sizeof(bin_data));
    assert(enc != NULL);
    xmpp_base64_decode_bin(ctx, enc, strlen(enc), &udec, &len);
    assert(udec != NULL);
    assert(len != 0);
    assert(len == sizeof(bin_data));
    COMPARE_BUF(bin_data, sizeof(bin_data), udec, len);
    xmpp_free(ctx, udec);
    xmpp_free(ctx, enc);
    printf("ok\n");

    xmpp_ctx_free(ctx);

    return 0;
}
