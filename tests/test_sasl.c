/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* test_sasl.c
** libstrophe XMPP client library -- test routines for the SASL implementation
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT or GPLv3 licenses.
*/

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "test.h"

#include "strophe.h"
#include "common.h"
#include "sasl.h"

static const unsigned char jid[] = "foo@bar.com";
static const char password[] = "secret";
static const char response_plain[] = "AGZvb0BiYXIuY29tAHNlY3JldA==";

static const char challenge_md5[] =
    "cmVhbG09InNvbWVyZWFsbSIsbm9uY2U9Ik9BNk1HOXRFUUdtMmhoIixxb3A9ImF1dGgi"
    "LGNoYXJzZXQ9dXRmLTgsYWxnb3JpdGhtPW1kNS1zZXNzCg==";
static const char response_md5[] =
    "dXNlcm5hbWU9InNvbWVub2RlIixyZWFsbT0ic29tZXJlYWxtIixub25jZT0i"
    "T0E2TUc5dEVRR20yaGgiLGNub25jZT0iMDBERUFEQkVFRjAwIixuYz0wMDAw"
    "MDAwMSxxb3A9YXV0aCxkaWdlc3QtdXJpPSJ4bXBwL3NvbWVyZWFsbSIscmVz"
    "cG9uc2U9NGVhNmU4N2JjMDkzMzUwNzQzZGIyOGQ3MDIwOGNhZmIsY2hhcnNl"
    "dD11dGYtOA==";

/* stubs to build test without whole libstrophe */
void *strophe_alloc(const xmpp_ctx_t *ctx, size_t size)
{
    (void)ctx;
    return malloc(size);
}
void *strophe_realloc(const xmpp_ctx_t *ctx, void *p, size_t size)
{
    (void)ctx;
    return realloc(p, size);
}

void strophe_free(const xmpp_ctx_t *ctx, void *p)
{
    (void)ctx;
    free(p);
}

xmpp_ctx_t *xmpp_ctx_new(const xmpp_mem_t *mem, const xmpp_log_t *log)
{
    return calloc(1, sizeof(struct _xmpp_ctx_t));
}

void xmpp_ctx_free(xmpp_ctx_t *ctx)
{
    free(ctx);
}

void xmpp_rand_nonce(xmpp_rand_t *rand, char *output, size_t len)
{
    const char *nonce = "00DEADBEEF00";
    memcpy(output, nonce, len);
}

void xmpp_disconnect(xmpp_conn_t *conn) {}

void strophe_error(const xmpp_ctx_t *ctx,
                   const char *area,
                   const char *fmt,
                   ...)
{
    (void)ctx;
    (void)area;
    (void)fmt;
}

static int test_plain(xmpp_ctx_t *ctx)
{
    char *result;

    result = sasl_plain(ctx, jid, password);
    if (result == NULL) {
        /* SASL PLAIN internal failure! */
        return 1;
    }
    if (strncmp(response_plain, result, strlen(response_plain))) {
        /* SASL PLAIN returned incorrect string! */
        return 2;
    }
    strophe_free(ctx, result);

    return 0;
}

static int test_digest_md5(xmpp_ctx_t *ctx)
{
    int ret = 0;
    char *result =
        sasl_digest_md5(ctx, challenge_md5, "somenode@somerealm", "secret");
    assert(result != NULL);
    if (strcmp(response_md5, result)) {
        /* generated incorrect response to challenge */
        size_t n = 0;
        char *should, *is;
        printf("\nshould: %s\n", response_md5);
        printf("    is: %s\n", result);
        printf("        ");
        while (response_md5[n] == result[n]) {
            putchar(' ');
            n++;
        }
        printf("^\n");
        should =
            xmpp_base64_decode_str(ctx, response_md5, strlen(response_md5));
        is = xmpp_base64_decode_str(ctx, result, strlen(result));
        printf("\nshould: %s\n", should);
        printf("    is: %s\n", is);
        printf("        ");
        n = 0;
        while (should[n] == is[n]) {
            putchar(' ');
            n++;
        }
        strophe_free(ctx, is);
        strophe_free(ctx, should);
        printf("^\n");
        ret = 1;
    }
    strophe_free(ctx, result);

    return ret;
}

int main()
{
    xmpp_ctx_t *ctx;
    int ret;

    printf("allocating context... ");
    ctx = xmpp_ctx_new(NULL, NULL);
    if (ctx == NULL)
        printf("failed to create context\n");
    if (ctx == NULL)
        return -1;
    printf("ok.\n");

    printf("testing SASL PLAIN... ");
    ret = test_plain(ctx);
    if (ret)
        printf("failed!\n");
    if (ret)
        return ret;
    printf("ok.\n");

    printf("testing SASL DIGEST-MD5... ");
    ret = test_digest_md5(ctx);
    if (ret)
        printf("failed!\n");
    if (ret)
        return ret;
    printf("ok.\n");

    printf("freeing context... ");
    xmpp_ctx_free(ctx);
    printf("ok.\n");

    return ret;
}
