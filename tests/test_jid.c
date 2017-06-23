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

static const char jid1[] = "foo@bar.com";
static const char jid2[] = "anyone@example.com/hullo";
static const char jid3[] = "manic.porter@xyz.net/frob";
static const char jid4[] = "domain.tld";

static const char *_s(const char *s)
{
    return s == NULL ? "<NULL>" : s;
}

int test_jid(xmpp_ctx_t *ctx)
{
    char *bare;
    char *node;
    char *domain;
    char *resource;

    bare = xmpp_jid_bare(ctx, jid1);
    node = xmpp_jid_node(ctx, jid1);
    domain = xmpp_jid_domain(ctx, jid1);
    resource = xmpp_jid_resource(ctx, jid1);
    printf("jid '%s' parsed to %s, %s, %s\n",
           jid1, _s(node), _s(domain), _s(resource));
    if (bare == NULL || strcmp(bare, "foo@bar.com")) return 1;
    if (node == NULL || strcmp(node, "foo")) return 1;
    if (domain == NULL || strcmp(domain, "bar.com")) return 1;
    if (resource != NULL) return 1;
    if (bare) xmpp_free(ctx, bare);
    if (node) xmpp_free(ctx, node);
    if (domain) xmpp_free(ctx, domain);
    if (resource) xmpp_free(ctx, resource);

    bare = xmpp_jid_bare(ctx, jid2);
    node = xmpp_jid_node(ctx, jid2);
    domain = xmpp_jid_domain(ctx, jid2);
    resource = xmpp_jid_resource(ctx, jid2);
    printf("jid '%s' parsed to %s, %s, %s\n",
           jid2, _s(node), _s(domain), _s(resource));
    if (bare == NULL || strcmp(bare, "anyone@example.com")) return 1;
    if (node == NULL || strcmp(node, "anyone")) return 1;
    if (domain == NULL || strcmp(domain, "example.com")) return 1;
    if (resource == NULL || strcmp(resource, "hullo")) return 1;
    if (bare) xmpp_free(ctx, bare);
    if (node) xmpp_free(ctx, node);
    if (domain) xmpp_free(ctx, domain);
    if (resource) xmpp_free(ctx, resource);

    bare = xmpp_jid_bare(ctx, jid3);
    node = xmpp_jid_node(ctx, jid3);
    domain = xmpp_jid_domain(ctx, jid3);
    resource = xmpp_jid_resource(ctx, jid3);
    printf("jid '%s' parsed to %s, %s, %s\n",
           jid3, _s(node), _s(domain), _s(resource));
    if (bare == NULL || strcmp(bare, "manic.porter@xyz.net")) return 1;
    if (node == NULL || strcmp(node, "manic.porter")) return 1;
    if (domain == NULL || strcmp(domain, "xyz.net")) return 1;
    if (resource == NULL || strcmp(resource, "frob")) return 1;
    if (bare) xmpp_free(ctx, bare);
    if (node) xmpp_free(ctx, node);
    if (domain) xmpp_free(ctx, domain);
    if (resource) xmpp_free(ctx, resource);

    bare = xmpp_jid_bare(ctx, jid4);
    node = xmpp_jid_node(ctx, jid4);
    domain = xmpp_jid_domain(ctx, jid4);
    resource = xmpp_jid_resource(ctx, jid4);
    printf("jid '%s' parsed to %s, %s, %s\n",
           jid4, _s(node), _s(domain), _s(resource));
    if (bare == NULL || strcmp(bare, "domain.tld")) return 1;
    if (node != NULL) return 1;
    if (domain == NULL || strcmp(domain, "domain.tld")) return 1;
    if (resource != NULL) return 1;
    if (bare) xmpp_free(ctx, bare);
    if (node) xmpp_free(ctx, node);
    if (domain) xmpp_free(ctx, domain);
    if (resource) xmpp_free(ctx, resource);

    return 0;
}

int test_jid_new(xmpp_ctx_t *ctx)
{
    char *jid;

    jid = xmpp_jid_new(ctx, "node", "domain", "resource");
    printf("new jid: '%s'\n", jid);
    if (strcmp(jid, "node@domain/resource")) return 1;
    xmpp_free(ctx, jid);

    jid = xmpp_jid_new(ctx, "foo", "bar.com", NULL);
    printf("new jid: '%s'\n", jid);
    if (strcmp(jid, "foo@bar.com")) return 1;
    xmpp_free(ctx, jid);

    return 0;
}

int main(int argc, char *argv[])
{
    xmpp_ctx_t *ctx;
    int ret;

    printf("allocating context... ");
    ctx = xmpp_ctx_new(NULL, NULL);
    if (ctx == NULL) printf("failed to create context\n");
    if (ctx == NULL) return -1;
    printf("ok.\n");

    printf("testing jid routines...\n");
    ret = test_jid(ctx);
    if (ret) printf("testing jid routines... failed!\n");
    if (ret) return ret;
    printf("testing jid routines... ok.\n");

    printf("testing jid new routines...\n");
    ret = test_jid_new(ctx);
    if (ret) printf("testing jid new routines... failed!\n");
    if (ret) return ret;
    printf("testing jid new routines... ok.\n");

    printf("freeing context... ");
    xmpp_ctx_free(ctx);
    printf("ok.\n");

    return ret;
}
