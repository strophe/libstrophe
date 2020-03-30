/* Tests for SHA-256 from LibTomCrypt */
/* This file is in the public domain */

/* gcc -o test_sha256 -I./src tests/test_sha256.c tests/test.c src/sha256.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "test.h"

int main()
{
    static const struct {
        const char *msg;
        unsigned char hash[SHA256_DIGEST_SIZE];
    } tests[] = {
        {"abc",
         {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
          0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
          0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad}},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26,
          0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff,
          0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1}},
    };

    int i;
    unsigned char tmp[SHA256_DIGEST_SIZE];
    sha256_context md;

    for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
        sha256_init(&md);
        sha256_process(&md, (unsigned char *)tests[i].msg,
                       (unsigned long)strlen(tests[i].msg));
        sha256_done(&md, tmp);
        COMPARE_BUF(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash));
    }

    /* success */
    fprintf(stdout, "ok\n");
    return (0);
}
