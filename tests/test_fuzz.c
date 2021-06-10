#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "strophe.h"
#include "parser.h"

void xmpp_initialize(void);

void cbtest_handle_start(char *name, char **attrs, void *userdata)
{
    (void)name;
    (void)attrs;
    (void)userdata;
}

void cbtest_handle_end(char *name, void *userdata)
{
    (void)name;
    (void)userdata;
}

void cbtest_handle_stanza(xmpp_stanza_t *stanza, void *userdata)
{
    (void)stanza;
    (void)userdata;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    xmpp_ctx_t *ctx;
    parser_t *parser;

    char *dup = malloc(Size);
    memcpy(dup, Data, Size);

    ctx = xmpp_ctx_new(NULL, NULL);
    parser = parser_new(ctx, cbtest_handle_start, cbtest_handle_end,
                        cbtest_handle_stanza, NULL);

    parser_feed(parser, dup, Size);

    free(dup);
    parser_free(parser);
    xmpp_ctx_free(ctx);

    return 0;
}
