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

#include "test.h"

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

    const char *str =
        "<signcrypt xmlns=\"urn:xmpp:openpgp:0\"><to "
        "jid=\"user@domain.com\"/><time "
        "stamp=\"2020-06-03T21:26:24+0200\"/><rpad/><payload><body "
        "xmlns=\"jabber:client\">Hello World!</body></payload></signcrypt>";

    stanza = xmpp_stanza_new_from_string(ctx, str);
    assert(stanza != NULL);
    ret = xmpp_stanza_to_text(stanza, &buf, &buflen);
    assert(ret == XMPP_EOK);
    COMPARE(str, buf);
    xmpp_free(ctx, buf);
    xmpp_stanza_release(stanza);

    /* create a string with two stanzas to make sure we don't
     * leak any memory when we convert them to a xmpp_stanza_t
     */
    buf = malloc(strlen(str) * 2 + 1);
    assert(buf != NULL);
    memcpy(buf, str, strlen(str) + 1);
    memcpy(&buf[strlen(str)], str, strlen(str) + 1);
    stanza = xmpp_stanza_new_from_string(ctx, buf);
    assert(stanza != NULL);
    free(buf);
    ret = xmpp_stanza_to_text(stanza, &buf, &buflen);
    assert(ret == XMPP_EOK);
    COMPARE(str, buf);
    xmpp_free(ctx, buf);
    xmpp_stanza_release(stanza);

    /* Error path. */
    stanza = xmpp_stanza_new_from_string(ctx, "<uu><uu>tt");
    assert(stanza == NULL);
}

static void test_stanza_error(xmpp_ctx_t *ctx)
{
    xmpp_stanza_t *stanza;
    xmpp_stanza_t *error;
    xmpp_stanza_t *item;
    xmpp_stanza_t *mood;
    char *buf;
    size_t buflen;
    const char *attr[10];
    int attrlen = ARRAY_SIZE(attr);
    int ret;

    static const char *str =
        "<iq from='romeo@montague.lit/home' to='juliet@capulet.lit/chamber' "
        "type='get' id='e2e1'><ping xmlns='urn:xmpp:ping'/></iq>";
    static const char *str_error =
        "<error type=\"cancel\"><service-unavailable "
        "xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\"/></error>";
    // clang-format off
    static const char *str_mood =
        "<iq from='juliet@capulet.lit/balcony' id='publish1' type='set'>"
          "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
            "<publish node='http://jabber.org/protocol/mood'>"
              "<item>"
                "<mood xmlns='http://jabber.org/protocol/mood'>"
                  "<annoyed/>"
                  "<text>curse my nurse!</text>"
                "</mood>"
              "</item>"
            "</publish>"
          "</pubsub>"
        "</iq>";
    // clang-format on

    stanza = xmpp_stanza_new_from_string(ctx, str);
    assert(stanza != NULL);
    error =
        xmpp_stanza_reply_error(stanza, "cancel", "service-unavailable", NULL);
    assert(error != NULL);
    mood = xmpp_stanza_new_from_string(ctx, str_mood);
    assert(stanza != NULL);

    assert(xmpp_stanza_get_to(error) != NULL);
    COMPARE("romeo@montague.lit/home", xmpp_stanza_get_to(error));
    assert(xmpp_stanza_get_from(error) != NULL);
    COMPARE("juliet@capulet.lit/chamber", xmpp_stanza_get_from(error));
    assert(xmpp_stanza_get_id(error) != NULL);
    COMPARE("e2e1", xmpp_stanza_get_id(error));
    assert(xmpp_stanza_get_type(error) != NULL);
    COMPARE("error", xmpp_stanza_get_type(error));

    /* FAIL - no list given */
    item = xmpp_stanza_get_child_by_path(mood, NULL);
    assert(item == NULL);

    /* FAIL - first entry doesn't match */
    item = xmpp_stanza_get_child_by_path(mood, "foo", NULL);
    assert(item == NULL);

    /* FAIL - 'iq' has no namespace */
    item = xmpp_stanza_get_child_by_path(
        mood, XMPP_STANZA_NAME_IN_NS("iq", "foobar"),
        XMPP_STANZA_NAME_IN_NS("pubsub", "http://jabber.org/protocol/pubsub"),
        "publish", "item", "mood", NULL);
    assert(item == NULL);

    /* FAIL - 'pubsub' is in another namespace */
    item = xmpp_stanza_get_child_by_path(
        mood, "iq",
        XMPP_STANZA_NAME_IN_NS("pubsub", "http://jabber.org/protocol/foobar"),
        "publish", "item", "mood", NULL);
    assert(item == NULL);

    item = xmpp_stanza_get_child_by_path(mood, "iq", "pubsub", "publish",
                                         "item", "mood", NULL);
    assert(item != NULL);
    assert(xmpp_stanza_get_children(item) != NULL);
    assert(xmpp_stanza_get_name(xmpp_stanza_get_children(item)) != NULL);
    COMPARE("annoyed", xmpp_stanza_get_name(xmpp_stanza_get_children(item)));

    item = xmpp_stanza_get_child_by_path(
        mood, "iq",
        XMPP_STANZA_NAME_IN_NS("pubsub", "http://jabber.org/protocol/pubsub"),
        "publish", "item",
        XMPP_STANZA_NAME_IN_NS("mood", "http://jabber.org/protocol/mood"),
        NULL);
    assert(item != NULL);
    assert(xmpp_stanza_get_children(item) != NULL);
    assert(xmpp_stanza_get_name(xmpp_stanza_get_children(item)) != NULL);
    COMPARE("annoyed", xmpp_stanza_get_name(xmpp_stanza_get_children(item)));

    ret = xmpp_stanza_get_attributes(error, attr, attrlen);
    /* attr contains both attribute name and value. */
    assert(ret == 8);

    item = xmpp_stanza_get_child_by_name(error, "error");
    assert(item != NULL);

    ret = xmpp_stanza_to_text(item, &buf, &buflen);
    assert(ret == XMPP_EOK);
    COMPARE(str_error, buf);

    xmpp_free(ctx, buf);
    xmpp_stanza_release(mood);
    xmpp_stanza_release(stanza);
    xmpp_stanza_release(error);
}

int main()
{
    xmpp_ctx_t *ctx;

    xmpp_initialize();
    ctx = xmpp_ctx_new(&stanza_mem, NULL);
    assert(ctx != NULL);

    test_stanza_add_child(ctx);
    test_stanza_from_string(ctx);
    test_stanza_error(ctx);

    xmpp_ctx_free(ctx);
    xmpp_shutdown();

    /* All allocated blocks must be freed. */
    assert(used_blocks == 0);
}
