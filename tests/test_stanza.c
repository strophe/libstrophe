/* test_stanza.c
 * libstrophe XMPP client library -- test routines for stanza functions
 *
 * Copyright (C) 2020 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/* gcc -o test_stanza -I./src tests/test_stanza.c -lstrophe */

#include <strophe.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define MAGICPTR ((void *)0xfeedbeef)
static unsigned long used_blocks = 0;

static void *stanza_alloc(size_t size, void *userdata)
{
    assert(userdata == MAGICPTR);

    ++used_blocks;
    return malloc(size);
}

static void stanza_free(void *ptr, void *userdata)
{
    assert(userdata == MAGICPTR);

    if (ptr != NULL) {
        assert(used_blocks > 0);
        --used_blocks;
    }
    free(ptr);
}

static void *stanza_realloc(void *ptr, size_t size, void *userdata)
{
    assert(userdata == MAGICPTR);

    if (ptr != NULL && size == 0) {
        /* equivalent to free(ptr) */
        assert(used_blocks > 0);
        --used_blocks;
    } else if (ptr == NULL) {
        /* equivalent to malloc(size) */
        ++used_blocks;
    }
    return realloc(ptr, size);
}

static const xmpp_mem_t stanza_mem = {
    .alloc = &stanza_alloc,
    .free = &stanza_free,
    .realloc = &stanza_realloc,
    .userdata = MAGICPTR,
};

static void test_stanza_add_child(xmpp_ctx_t *ctx)
{
    xmpp_stanza_t *stanza;
    xmpp_stanza_t *child;
    unsigned long baseline = used_blocks;

    /* xmpp_stanza_add_child */

    stanza = xmpp_stanza_new(ctx);
    child = xmpp_stanza_new(ctx);
    assert(stanza != NULL);
    assert(child != NULL);
    xmpp_stanza_add_child(stanza, child);
    xmpp_stanza_release(stanza);
    assert(used_blocks > baseline);
    xmpp_stanza_release(child);
    assert(used_blocks == baseline);

    /* xmpp_stanza_add_child_ex */

    stanza = xmpp_stanza_new(ctx);
    child = xmpp_stanza_new(ctx);
    assert(stanza != NULL);
    assert(child != NULL);
    xmpp_stanza_add_child_ex(stanza, child, 0);
    xmpp_stanza_release(stanza);
    assert(used_blocks == baseline);
}

static void test_stanza_from_string(xmpp_ctx_t *ctx)
{
    xmpp_stanza_t *stanza;
    char *buf;
    size_t buflen;
    int ret;

    static const char *str =
        "<signcrypt xmlns=\"urn:xmpp:openpgp:0\"><to "
        "jid=\"user@domain.com\"/><time "
        "stamp=\"2020-06-03T21:26:24+0200\"/><rpad/><payload><body "
        "xmlns=\"jabber:client\">Hello World!</body></payload></signcrypt>";

    stanza = xmpp_stanza_new_from_string(ctx, str);
    assert(stanza != NULL);
    ret = xmpp_stanza_to_text(stanza, &buf, &buflen);
    assert(ret == XMPP_EOK);
    assert(strcmp(buf, str) == 0);
    xmpp_free(ctx, buf);
    xmpp_stanza_release(stanza);

    /* Error path. */
    stanza = xmpp_stanza_new_from_string(ctx, "<uu><uu>tt");
    assert(stanza == NULL);
}

int main()
{
    xmpp_ctx_t *ctx;

    xmpp_initialize();
    ctx = xmpp_ctx_new(&stanza_mem, NULL);
    assert(ctx != NULL);

    test_stanza_add_child(ctx);
    test_stanza_from_string(ctx);

    xmpp_ctx_free(ctx);
    xmpp_shutdown();

    /* All allocated blocks must be freed. */
    assert(used_blocks == 0);
}
