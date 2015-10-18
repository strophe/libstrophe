/* test_md5.c
 * strophe XMPP client library -- test vectors for MD5
 *
 * Copyright (C) 2015 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/* gcc -o test_md5 -I./src tests/test_md5.c tests/test.c src/md5.c */

#include <stdio.h>
#include <string.h>

#include "test.h"
#include "md5.h"

/*
 * Test vectors for MD5 (RFC1321).
 */
static const struct {
    const char *data;
    const char *md5;
} tests[] = {
    {
        .data = "",
        .md5 = "d41d8cd98f00b204e9800998ecf8427e",
    },
    {
        .data = "a",
        .md5 = "0cc175b9c0f1b6a831c399e269772661",
    },
    {
        .data = "abc",
        .md5 = "900150983cd24fb0d6963f7d28e17f72",
    },
    {
        .data = "message digest",
        .md5 = "f96b697d7cb7938d525a2f31aaf161d0",
    },
    {
        .data = "abcdefghijklmnopqrstuvwxyz",
        .md5 = "c3fcd3d76192e4007dfb496cca67e13b",
    },
    {
        .data = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcde"
                "fghijklmnopqrstuvwxyz0123456789",
        .md5 = "d174ab98d277d9f5a5611c2c9f419d9f",
    },
    {
        .data = "1234567890123456789012345678901"
                "2345678901234567890123456789012"
                "345678901234567890",
        .md5 = "57edf4a22be3c955ac49da2e2107b67a",
    },
};

int main(int argc, char **argv)
{
    struct MD5Context ctx;
    unsigned char digest[16];
    size_t i;

    printf("MD5 tests.\n");

    for (i = 0; i < ARRAY_SIZE(tests); ++i) {
        printf("Test #%zu: ", i + 1);
        MD5Init(&ctx);
        MD5Update(&ctx, (unsigned char *)tests[i].data, strlen(tests[i].data));
        MD5Final(digest, &ctx);
        COMPARE(tests[i].md5, test_bin_to_hex(digest, sizeof(digest)));
        printf("ok\n");
    }
    return 0;
}
