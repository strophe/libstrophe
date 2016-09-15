/* check_parser.h
** strophe XMPP client library -- parser tests
**
** Copyright (C) 2005-2009 Collecta, Inc. 
**
**  This software is provided AS-IS with no warranty, either express or
**  implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "strophe.h"
#include "parser.h"

#include "test.h"

#define fail_unless(expr) do {                  \
    int result = (expr);                        \
    if (!result) {                              \
        printf("%s:%d: Assertion failed: %s\n", \
               __FILE__, __LINE__, #expr);      \
        exit(1);                                \
    }                                           \
} while (0)

static void create_destroy(void)
{
    xmpp_ctx_t *ctx;
    parser_t *parser;

    ctx = xmpp_ctx_new(NULL, NULL);
    parser = parser_new(ctx, NULL, NULL, NULL, NULL);
    fail_unless(parser != NULL);
    parser_free(parser);
    xmpp_ctx_free(ctx);
}

int cbtest_got_start = 0;
void cbtest_handle_start(char *name, char **attrs, void *userdata)
{
    if (strcmp(name, "stream") == 0)
        cbtest_got_start = 1;
}

int cbtest_got_end = 0;
void cbtest_handle_end(char *name, void *userdata)
{
    if (strcmp(name, "stream") == 0)
        cbtest_got_end = 1;
}

int cbtest_got_stanza = 0;
void cbtest_handle_stanza(xmpp_stanza_t *stanza, void *userdata)
{
    if (strcmp(xmpp_stanza_get_name(stanza), "message") == 0)
        cbtest_got_stanza = 1;
}

static void callbacks(void)
{
    xmpp_ctx_t *ctx;
    parser_t *parser;
    int ret;

    ctx = xmpp_ctx_new(NULL, NULL);
    parser = parser_new(ctx, 
                        cbtest_handle_start, 
                        cbtest_handle_end,
                        cbtest_handle_stanza, NULL);

    ret = parser_feed(parser, "<stream>", 8);
    fail_unless(ret != 0);
    ret = parser_feed(parser, "<message/>", 10);
    fail_unless(ret != 0);
    ret = parser_feed(parser, "</stream>", 9);
    fail_unless(ret != 0);

    fail_unless(cbtest_got_start == 1);
    fail_unless(cbtest_got_end == 1);
    fail_unless(cbtest_got_stanza == 1);

    parser_free(parser);
    xmpp_ctx_free(ctx);
}

int main()
{
    printf("XML parser tests.\n");

    printf("create-destroy: ");
    create_destroy();
    printf("ok\n");

    printf("callbacks: ");
    callbacks();
    printf("ok\n");

    return 0;
}
