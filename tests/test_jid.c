/* test_jid.c
** libstrophe XMPP client library -- test routines for the jid utils
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

#include "test.h"

static const char *_s(const char *s)
{
    return s == NULL ? "<NULL>" : s;
}

static int test_jid(xmpp_ctx_t *ctx)
{
    char *bare;
    char *node;
    char *domain;
    char *resource;
    size_t n;
    struct {
        const char *jid;
        const char *bare;
        const char *node;
        const char *domain;
        const char *resource;
    } testcases[] = {
        {"foo@bar.com", "foo@bar.com", "foo", "bar.com", NULL},
        {
            "anyone@example.com/hullo",
            "anyone@example.com",
            "anyone",
            "example.com",
            "hullo",
        },
        {
            "a.example.com/b@example.net",
            "a.example.com",
            NULL,
            "a.example.com",
            "b@example.net",
        },
        {
            "manic.porter@xyz.net/frob",
            "manic.porter@xyz.net",
            "manic.porter",
            "xyz.net",
            "frob",
        },
        {
            "domain.tld",
            "domain.tld",
            NULL,
            "domain.tld",
            NULL,
        },
    };

    for (n = 0; n < sizeof(testcases) / sizeof(testcases[0]); ++n) {
        bare = xmpp_jid_bare(ctx, testcases[n].jid);
        node = xmpp_jid_node(ctx, testcases[n].jid);
        domain = xmpp_jid_domain(ctx, testcases[n].jid);
        resource = xmpp_jid_resource(ctx, testcases[n].jid);
        printf("jid '%s' parsed to %s, %s, %s\n", testcases[n].jid, _s(node),
               _s(domain), _s(resource));
        COMPARE(testcases[n].bare, bare);
        COMPARE(testcases[n].node, node);
        COMPARE(testcases[n].domain, domain);
        COMPARE(testcases[n].resource, resource);
        if (bare)
            strophe_free(ctx, bare);
        if (node)
            strophe_free(ctx, node);
        if (domain)
            strophe_free(ctx, domain);
        if (resource)
            strophe_free(ctx, resource);
    }

    printf("test_jid() finished successfully\n");

    return 0;
}

int test_jid_new(xmpp_ctx_t *ctx)
{
    char *jid;

    jid = xmpp_jid_new(ctx, "node", "domain", "resource");
    printf("new jid: '%s'\n", jid);
    if (strcmp(jid, "node@domain/resource"))
        return 1;
    strophe_free(ctx, jid);

    jid = xmpp_jid_new(ctx, "foo", "bar.com", NULL);
    printf("new jid: '%s'\n", jid);
    if (strcmp(jid, "foo@bar.com"))
        return 1;
    strophe_free(ctx, jid);

    const char *invalid_chars = "\"&'/:<>@";
    char localpart[] = "localpart";
    do {
        localpart[1] = *invalid_chars;
        jid = xmpp_jid_new(ctx, localpart, "bar.com", NULL);
        if (jid != NULL) {
            printf("Shouldn't have created JID with localpart=\"%s\"\n",
                   localpart);
            return 1;
        }
        invalid_chars++;
    } while (*invalid_chars != '\0');

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

    printf("testing jid routines...\n");
    ret = test_jid(ctx);
    if (ret)
        printf("testing jid routines... failed!\n");
    if (ret)
        return ret;
    printf("testing jid routines... ok.\n");

    printf("testing jid new routines...\n");
    ret = test_jid_new(ctx);
    if (ret)
        printf("testing jid new routines... failed!\n");
    if (ret)
        return ret;
    printf("testing jid new routines... ok.\n");

    printf("freeing context... ");
    xmpp_ctx_free(ctx);
    printf("ok.\n");

    return ret;
}
