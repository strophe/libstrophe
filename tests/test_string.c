/* test_string.c
 * strophe XMPP client library -- tests for re-implemented string functions
 *
 * Copyright (C) 2016 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "strophe.h"
#include "common.h"
#include "util.h"

#include "test.h" /* ARRAY_SIZE */

static int test_strtok_r(void)
{
    const char *test = "-abc-=-def--";
    char *s1, *s2, *sub1, *sub2;
    char *sp1, *sp2;

    s1 = strdup(test);
    s2 = strdup(test);
    assert(strcmp(s1, s2) == 0);

    sub1 = strtok_r(s1, "-", &sp1);
    sub2 = xmpp_strtok_r(s2, "-", &sp2);
    if (strcmp(sub1, sub2) != 0) {
        printf("1st token is '%s', must be '%s'\n", sub2, sub1);
        return -1;
    }
    sub1 = strtok_r(NULL, "-=", &sp1);
    sub2 = xmpp_strtok_r(NULL, "-=", &sp2);
    if (strcmp(sub1, sub2) != 0) {
        printf("2nd token is '%s', must be '%s'\n", sub2, sub1);
        return -1;
    }
    sub1 = strtok_r(NULL, "-", &sp1);
    sub2 = xmpp_strtok_r(NULL, "-", &sp2);
    if (sub1 != sub2) {
        printf("3rd call returns %p instead of NULL\n", sub2);
        return -1;
    }

    free(s1);
    free(s2);

    return 0;
}

static int test_strdup_one(xmpp_ctx_t *ctx, const char *s)
{
    char *s1, *s2;
    int rc = 0;

    s1 = strdup(s);
    s2 = xmpp_strdup(ctx, s);

    if (!s1 || !s2 || strcmp(s1, s2) != 0) {
        rc = -1;
        printf("strdup: '%s', xmpp_strdup: '%s'\n",
               s1 ? s1 : "<NULL>", s2 ? s2 : "<NULL>");
    }

    free(s1);
    if (s2)
        xmpp_free(ctx, s2);

    return rc;
}

static int test_strdup(void)
{
    xmpp_ctx_t *ctx;
    int i;
    int rc = 0;

    static const char *tests[] = { "", "\0", "test", "s p a c e", "\n\r" };

    ctx = xmpp_ctx_new(NULL, NULL);
    assert(ctx != NULL);
    for (i = 0; i < ARRAY_SIZE(tests); ++i) {
        rc = test_strdup_one(ctx, tests[i]);
        if (rc != 0)
            break;
    }
    xmpp_ctx_free(ctx);

    return rc;
}

int main()
{
    int rc;

    printf("xmpp_strtok_r() tests... ");
    rc = test_strtok_r();
    if (rc != 0)
        return 1;
    printf("ok\n");

    printf("xmpp_strdup() tests... ");
    rc = test_strdup();
    if (rc != 0)
        return 1;
    printf("ok\n");

    return 0;
}
