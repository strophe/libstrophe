/* test_sasl.c
** libstrophe XMPP client library -- test routines for the SASL implementation
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

#include <stdio.h>
#include <string.h>

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

int test_plain(xmpp_ctx_t *ctx)
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

int test_digest_md5(xmpp_ctx_t *ctx)
{
    char *result;

    result =
        sasl_digest_md5(ctx, challenge_md5, "somenode@somerealm", "secret");
    printf("response:\n%s\n", result);
    if (strcmp(response_md5, result)) {
        /* generated incorrect response to challenge */
        return 1;
    }

    return 0;
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
