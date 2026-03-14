/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* test_sasl2_syntax.c
** libstrophe XMPP client library -- test routines for SASL2 syntax
**
** Copyright (C) 2024-2026 libstrophe contributors
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT or GPLv3 licenses.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "strophe.h"
#include "common.h"
#include "sasl.h"
#include "scram.h"
#include "test.h"

/* stubs to build test without whole libstrophe */

static xmpp_stanza_t *last_sent_stanza = NULL;

void send_stanza(xmpp_conn_t *conn,
                 xmpp_stanza_t *stanza,
                 xmpp_send_queue_owner_t owner)
{
    (void)conn;
    (void)owner;
    if (last_sent_stanza)
        xmpp_stanza_release(last_sent_stanza);
    last_sent_stanza = xmpp_stanza_copy(stanza);
    xmpp_stanza_release(stanza);
}

void handler_add(xmpp_conn_t *conn,
                 xmpp_handler handler,
                 const char *ns,
                 const char *name,
                 const char *type,
                 void *userdata)
{
    (void)conn;
    (void)handler;
    (void)ns;
    (void)name;
    (void)type;
    (void)userdata;
}

void conn_disconnect(xmpp_conn_t *conn)
{
    (void)conn;
}

int xmpp_conn_is_secured(xmpp_conn_t *conn)
{
    (void)conn;
    return 0;
}

tls_t *tls_new(xmpp_conn_t *conn)
{
    (void)conn;
    return NULL;
}

void tls_free(tls_t *tls)
{
    (void)tls;
}

void tls_clear_password_cache(xmpp_conn_t *conn)
{
    (void)conn;
}

int tls_init_channel_binding(tls_t *tls,
                             const char **binding_prefix,
                             size_t *binding_prefix_len)
{
    (void)tls;
    (void)binding_prefix;
    (void)binding_prefix_len;
    return 0;
}

const void *tls_get_channel_binding_data(tls_t *tls, size_t *size)
{
    (void)tls;
    (void)size;
    return NULL;
}

char *tls_id_on_xmppaddr(xmpp_conn_t *conn, unsigned int n)
{
    (void)conn;
    (void)n;
    return NULL;
}

unsigned int tls_id_on_xmppaddr_num(xmpp_conn_t *conn)
{
    (void)conn;
    return 0;
}

void handler_reset_timed(xmpp_conn_t *conn, int user_only)
{
    (void)conn;
    (void)user_only;
}

void handler_add_timed(xmpp_conn_t *conn,
                       xmpp_timed_handler handler,
                       unsigned long period,
                       void *userdata)
{
    (void)conn;
    (void)handler;
    (void)period;
    (void)userdata;
}

void handler_add_id(xmpp_conn_t *conn,
                    xmpp_handler handler,
                    const char *id,
                    void *userdata)
{
    (void)conn;
    (void)handler;
    (void)id;
    (void)userdata;
}

void xmpp_timed_handler_delete(xmpp_conn_t *conn, xmpp_timed_handler handler)
{
    (void)conn;
    (void)handler;
}

void xmpp_disconnect(xmpp_conn_t *conn)
{
    (void)conn;
}

void conn_prepare_reset(xmpp_conn_t *conn, xmpp_open_handler handler)
{
    (void)conn;
    (void)handler;
    puts("should not reset connection in SASL2");
    assert(0);
}

void conn_open_stream(xmpp_conn_t *conn)
{
    (void)conn;
    puts("should not reset connection in SASL2");
    assert(0);
}
void send_raw_string(xmpp_conn_t *conn, const char *fmt, ...)
{
    (void)conn;
    (void)fmt;
}

#define strophe_warn(x, ...) (void)x
#define strophe_debug(x, ...) (void)x

void strophe_error(const xmpp_ctx_t *ctx,
                   const char *area,
                   const char *fmt,
                   ...)
{
    (void)ctx;
    (void)area;
    (void)fmt;
}

void *strophe_alloc(const xmpp_ctx_t *ctx, size_t size)
{
    (void)ctx;
    return malloc(size);
}

void strophe_free(const xmpp_ctx_t *ctx, void *p)
{
    (void)ctx;
    free(p);
}

void *strophe_realloc(const xmpp_ctx_t *ctx, void *p, size_t size)
{
    (void)ctx;
    return realloc(p, size);
}

xmpp_conn_t *xmpp_conn_new(xmpp_ctx_t *ctx)
{
    xmpp_conn_t *conn = malloc(sizeof(*conn));
    conn->ctx = ctx;
    return conn;
}

int xmpp_conn_release(xmpp_conn_t *conn)
{
    free(conn);
    return 0;
}

/* include auth.c to access static functions */
#include "src/auth.c"

/* If SASL2 isn't set, it shouldn't be used */
static int test_make_sasl_auth()
{
    xmpp_conn_t conn = {.sasl_support = SASL_MASK_PLAIN};
    xmpp_stanza_t *auth =
        _make_sasl_auth(&conn, "PLAIN", "AGZvb0BiYXIuY29tAHNlY3JldA==");

    COMPARE(xmpp_stanza_get_name(auth), "auth");
    COMPARE(xmpp_stanza_get_ns(auth), XMPP_NS_SASL);
    COMPARE(xmpp_stanza_get_attribute(auth, "mechanism"), "PLAIN");

    xmpp_stanza_release(auth);
    return 0;
}

static int test_make_sasl_auth_v2()
{
    xmpp_conn_t conn = {.sasl_support = SASL_MASK_SASL2 | SASL_MASK_PLAIN};
    xmpp_stanza_t *auth =
        _make_sasl_auth(&conn, "PLAIN", "AGZvb0BiYXIuY29tAHNlY3JldA==");
    xmpp_stanza_t *initial_response =
        xmpp_stanza_get_child_by_name(auth, "initial-response");

    assert(initial_response != NULL);
    COMPARE(xmpp_stanza_get_name(auth), "authenticate");
    COMPARE(xmpp_stanza_get_ns(auth), XMPP_NS_SASL2);
    COMPARE(xmpp_stanza_get_attribute(auth, "mechanism"), "PLAIN");
    COMPARE(xmpp_stanza_get_ns(initial_response), XMPP_NS_SASL2);

    xmpp_stanza_release(auth);
    return 0;
}

static int test_scram_challenge_v2(xmpp_ctx_t *ctx)
{
    extern const struct hash_alg scram_sha1;
    xmpp_conn_t conn = {.jid = "foo@bar.com",
                        .pass = "secret",
                        .sasl_support = SASL_MASK_SASL2 | SASL_MASK_SCRAMSHA1};
    struct scram_user_data scram_ctx = {.alg = &scram_sha1,
                                        .first_bare = "n=foo,r=random-nonce",
                                        .channel_binding =
                                            strophe_strdup(ctx, "biws")};
    struct scram_user_data *scram_ctx_heap = malloc(sizeof(*scram_ctx_heap));
    xmpp_stanza_t *stanza = xmpp_stanza_new(ctx);
    xmpp_stanza_t *tstanza = xmpp_stanza_new(ctx);

    *scram_ctx_heap = scram_ctx;
    xmpp_stanza_set_name(stanza, "challenge");
    xmpp_stanza_set_ns(stanza, XMPP_NS_SASL2);
    xmpp_stanza_set_text(tstanza, "cj1meWtvK2QycGJiRmdITkRyOXBRdG16aHZ1U2EzeTg4"
                                  "dDBkcGNjOVU3LHM9UVNYQ1IrUTZz"
                                  "ZWs4YmY5MixpPTQwOTY=");
    xmpp_stanza_add_child(stanza, tstanza);
    xmpp_stanza_release(tstanza);

    _handle_scram_challenge(&conn, stanza, scram_ctx_heap);

    assert(last_sent_stanza != NULL);
    COMPARE(xmpp_stanza_get_name(last_sent_stanza), "response");
    COMPARE(xmpp_stanza_get_ns(last_sent_stanza), XMPP_NS_SASL2);
    COMPARE(xmpp_stanza_get_text(last_sent_stanza),
            "Yz1iaXdzLHI9ZnlrbytkMnBiYkZnSE5EcjlwUXRtemh2dVNhM3k4OHQwZHBjYzlVNy"
            "xwPTZCY2VjL3kyM1N1RlhkS1VucFpZTnRSRHJIQT0=");

    xmpp_stanza_release(last_sent_stanza);
    last_sent_stanza = NULL;
    xmpp_stanza_release(stanza);

    return 0;
}

static int test_sasl_result_v2_success(xmpp_ctx_t *ctx)
{
    xmpp_conn_t conn = {.sasl_support = SASL_MASK_SASL2};
    xmpp_stanza_t *stanza;

    stanza = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(stanza, "success");
    xmpp_stanza_set_ns(stanza, XMPP_NS_SASL2);

    _handle_sasl_result(&conn, stanza, "SCRAM-SHA-1");

    /* If connection resets, the reset stub will assert failure */

    xmpp_stanza_release(stanza);

    return 0;
}

int main()
{
    int ret;

    printf("testing _make_sasl_auth (SASL 1.0)... ");
    ret = test_make_sasl_auth();
    if (ret) {
        printf("failed!\n");
        return ret;
    }
    printf("ok.\n");

    printf("testing _make_sasl_auth (SASL 2.0)... ");
    ret = test_make_sasl_auth_v2();
    if (ret) {
        printf("failed!\n");
        return ret;
    }
    printf("ok.\n");

    printf("testing _handle_scram_challenge (SASL 2.0)... ");
    ret = test_scram_challenge_v2(NULL);
    if (ret) {
        printf("failed!\n");
        return ret;
    }
    printf("ok.\n");

    printf("testing _handle_sasl_result success (SASL 2.0)... ");
    ret = test_sasl_result_v2_success(NULL);
    if (ret) {
        printf("failed!\n");
        return ret;
    }
    printf("ok.\n");

    return ret;
}
