/* register.c
 * strophe XMPP client library -- In-band registration (XEP-0077)
 *
 * Copyright (C) 2020 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/*
 * This example uses a "raw" connection to establish connection to a server
 * without account. Then it queries server to register new account according
 * to XEP-0077.
 *
 * How to use it. After the application connects and receives instructions
 * from the server, user will be prompted to type information such as
 * username, password, etc. Press enter without typing if you want to skip
 * a field and not to send it to the server.
 *
 * Notice, the example doesn't implement forms. Therefore, it won't work
 * in complicated scenarios.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <strophe.h>

typedef struct {
    xmpp_ctx_t *ctx;
    const char *jid;
} xmpp_reg_t;

#define FEATURES_TIMEOUT 5000 /* 5 seconds */

static void
iq_reg_send_form(xmpp_reg_t *reg, xmpp_conn_t *conn, xmpp_stanza_t *stanza)
{
    xmpp_ctx_t *ctx = reg->ctx;
    xmpp_stanza_t *query;
    xmpp_stanza_t *next;
    xmpp_stanza_t *elem;
    xmpp_stanza_t *text;
    xmpp_stanza_t *iq;
    const char *name;
    size_t len;
    char buf[256];
    char *s;

    query = xmpp_stanza_get_child_by_name(stanza, "query");
    if (!query) {
        xmpp_disconnect(conn);
        return;
    }

    next = xmpp_stanza_get_children(query);
    query = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(query, "query");
    xmpp_stanza_set_ns(query, XMPP_NS_REGISTER);
    while (next) {
        name = xmpp_stanza_get_name(next);
        if (name && strcmp(name, "instructions") == 0) {
            s = xmpp_stanza_get_text(next);
            printf("instructions: %s\n", s);
            xmpp_free(ctx, s);
        } else {
            printf("%s: ", name);
            s = fgets(buf, sizeof(buf), stdin);
            if (s != NULL) {
                len = strlen(s);
                if (len > 0 && s[len - 1] == '\n') {
                    s[len - 1] = '\0';
                    --len;
                }
                if (len > 0) {
                    elem = xmpp_stanza_new(ctx);
                    text = xmpp_stanza_new(ctx);
                    xmpp_stanza_set_text(text, s);
                    xmpp_stanza_set_name(elem, name);
                    xmpp_stanza_add_child(elem, text);
                    xmpp_stanza_add_child(query, elem);
                    xmpp_stanza_release(text);
                    xmpp_stanza_release(elem);
                }
            }
        }
        next = xmpp_stanza_get_next(next);
    }

    if (xmpp_stanza_get_children(query) == NULL) {
        fprintf(stderr, "DEBUG: nothing to send\n");
        xmpp_disconnect(conn);
    } else {
        iq = xmpp_iq_new(ctx, "set", "reg2");
        xmpp_stanza_add_child(iq, query);
        xmpp_stanza_release(query);
        xmpp_send(conn, iq);
        xmpp_stanza_release(iq);
    }
}

static int iq_reg2_cb(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    const char *type;

    (void)userdata;

    type = xmpp_stanza_get_type(stanza);
    if (!type || strcmp(type, "error") == 0) {
        fprintf(stderr, "DEBUG: error during registration\n");
        goto quit;
    }

    if (strcmp(type, "result") != 0) {
        fprintf(stderr, "DEBUG: expected type 'result', but got %s\n", type);
        goto quit;
    }

    fprintf(stderr, "DEBUG: successful registration\n");

quit:
    xmpp_disconnect(conn);

    return 0;
}

static int iq_reg_cb(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    xmpp_reg_t *reg = (xmpp_reg_t *)userdata;
    xmpp_stanza_t *registered = NULL;
    xmpp_stanza_t *query;
    const char *type;

    type = xmpp_stanza_get_type(stanza);
    if (!type || strcmp(type, "error") == 0) {
        fprintf(stderr, "DEBUG: error during registration\n");
        xmpp_disconnect(conn);
        goto quit;
    }

    if (strcmp(type, "result") != 0) {
        fprintf(stderr, "DEBUG: expected type 'result', but got %s\n", type);
        xmpp_disconnect(conn);
        goto quit;
    }

    query = xmpp_stanza_get_child_by_name(stanza, "query");
    if (query)
        registered = xmpp_stanza_get_child_by_name(query, "registered");
    if (registered != NULL) {
        fprintf(stderr, "DEBUG: already registered\n");
        xmpp_disconnect(conn);
        goto quit;
    }
    xmpp_id_handler_add(conn, iq_reg2_cb, "reg2", reg);
    iq_reg_send_form(reg, conn, stanza);

quit:
    return 0;
}

static int
_handle_error(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    (void)stanza;
    (void)userdata;

    fprintf(stderr, "DEBUG: received stream error\n");
    xmpp_disconnect(conn);

    return 0;
}

static int _handle_proceedtls_default(xmpp_conn_t *conn,
                                      xmpp_stanza_t *stanza,
                                      void *userdata)
{
    const char *name = xmpp_stanza_get_name(stanza);

    (void)userdata;

    if (strcmp(name, "proceed") == 0) {
        fprintf(stderr, "DEBUG: proceeding with TLS\n");
        if (xmpp_conn_tls_start(conn) == 0) {
            xmpp_handler_delete(conn, _handle_error);
            xmpp_conn_open_stream_default(conn);
        } else {
            fprintf(stderr, "DEBUG: TLS failed\n");
            /* failed tls spoils the connection, so disconnect */
            xmpp_disconnect(conn);
        }
    }
    return 0;
}

static int _handle_missing_features(xmpp_conn_t *conn, void *userdata)
{
    (void)userdata;

    fprintf(stderr, "DEBUG: timeout\n");
    xmpp_disconnect(conn);

    return 0;
}

static int
_handle_features(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    xmpp_reg_t *reg = (xmpp_reg_t *)userdata;
    xmpp_ctx_t *ctx = reg->ctx;
    xmpp_stanza_t *child;
    xmpp_stanza_t *iq;
    char *domain;

    xmpp_timed_handler_delete(conn, _handle_missing_features);

    /* secure connection if possible */
    child = xmpp_stanza_get_child_by_name(stanza, "starttls");
    if (child && (strcmp(xmpp_stanza_get_ns(child), XMPP_NS_TLS) == 0)) {
        fprintf(stderr, "DEBUG: server supports TLS, try to establish\n");
        child = xmpp_stanza_new(ctx);
        xmpp_stanza_set_name(child, "starttls");
        xmpp_stanza_set_ns(child, XMPP_NS_TLS);
        xmpp_handler_add(conn, _handle_proceedtls_default, XMPP_NS_TLS, NULL,
                         NULL, NULL);
        xmpp_send(conn, child);
        xmpp_stanza_release(child);
        return 0;
    }

    /* check whether server supports in-band registration */
    child = xmpp_stanza_get_child_by_name(stanza, "register");
    if (child && strcmp(xmpp_stanza_get_ns(child), XMPP_NS_REGISTER) == 0) {
        fprintf(stderr, "DEBUG: server doesn't support in-band registration\n");
        xmpp_disconnect(conn);
        return 0;
    }

    fprintf(stderr, "DEBUG: server supports in-band registration\n");
    domain = xmpp_jid_domain(ctx, reg->jid);
    iq = xmpp_iq_new(ctx, "get", "reg1");
    xmpp_stanza_set_to(iq, domain);
    child = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(child, "query");
    xmpp_stanza_set_ns(child, XMPP_NS_REGISTER);
    xmpp_stanza_add_child(iq, child);

    xmpp_handler_add(conn, iq_reg_cb, XMPP_NS_REGISTER, "iq", NULL, reg);
    xmpp_send(conn, iq);

    xmpp_free(ctx, domain);
    xmpp_stanza_release(child);
    xmpp_stanza_release(iq);

    return 0;
}

static void conn_handler(xmpp_conn_t *conn,
                         xmpp_conn_event_t status,
                         int error,
                         xmpp_stream_error_t *stream_error,
                         void *userdata)
{
    xmpp_reg_t *reg = (xmpp_reg_t *)userdata;
    int secured;

    (void)error;
    (void)stream_error;

    if (status == XMPP_CONN_RAW_CONNECT) {
        fprintf(stderr, "DEBUG: raw connection established\n");
        xmpp_conn_open_stream_default(conn);
    } else if (status == XMPP_CONN_CONNECT) {
        fprintf(stderr, "DEBUG: stream opened\n");
        secured = xmpp_conn_is_secured(conn);
        fprintf(stderr, "DEBUG: connection is %s.\n",
                secured ? "secured" : "NOT secured");

        /* setup handler for stream:error */
        xmpp_handler_add(conn, _handle_error, XMPP_NS_STREAMS, "error", NULL,
                         NULL);

        /* setup handlers for incoming <stream:features> */
        xmpp_handler_add(conn, _handle_features, XMPP_NS_STREAMS, "features",
                         NULL, reg);
        xmpp_timed_handler_add(conn, _handle_missing_features, FEATURES_TIMEOUT,
                               NULL);
    } else {
        fprintf(stderr, "DEBUG: disconnected\n");
        xmpp_stop(reg->ctx);
    }
}

xmpp_reg_t *xmpp_reg_new(void)
{
    xmpp_reg_t *reg;

    reg = malloc(sizeof(*reg));
    if (reg != NULL) {
        memset(reg, 0, sizeof(*reg));
    }
    return reg;
}

void xmpp_reg_release(xmpp_reg_t *reg)
{
    free(reg);
}

int main(int argc, char **argv)
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t *log;
    xmpp_reg_t *reg;
    const char *jid;
    const char *host = NULL;
    char *domain;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <jid> [<host>]\n", argv[0]);
        return 1;
    }

    jid = argv[1];
    if (argc > 2)
        host = argv[2];

    /*
     * Note, this example doesn't handle errors. Applications should check
     * return values of non-void functions.
     */

    xmpp_initialize();
    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG);
    ctx = xmpp_ctx_new(NULL, log);
    conn = xmpp_conn_new(ctx);

    /* jid can be a jid or domain for "raw" connection */
    domain = xmpp_jid_domain(ctx, jid);
    xmpp_conn_set_jid(conn, domain);
    xmpp_free(ctx, domain);

    /* private data */
    reg = xmpp_reg_new();
    reg->ctx = ctx;
    reg->jid = jid;

    xmpp_connect_raw(conn, host, 0, conn_handler, reg);
    xmpp_run(ctx);

    /* release private data */
    xmpp_reg_release(reg);

    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);
    xmpp_shutdown();

    return 0;
}
