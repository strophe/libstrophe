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

    --used_blocks;
    free(ptr);
}

static void *stanza_realloc(void *ptr, size_t size, void *userdata)
{
    assert(userdata == MAGICPTR);

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

int main()
{
    xmpp_ctx_t *ctx;

    xmpp_initialize();
    ctx = xmpp_ctx_new(&stanza_mem, NULL);
    assert(ctx != NULL);

    test_stanza_add_child(ctx);

    xmpp_ctx_free(ctx);
    xmpp_shutdown();

    /* All allocated blocks must be freed. */
    assert(used_blocks == 0);
}
