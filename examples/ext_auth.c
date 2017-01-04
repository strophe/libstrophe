/* ext_auth.c
 * strophe XMPP client library -- PLAIN mechanism example with a raw connection
 *
 * Copyright (C) 2016 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <strophe.h>

typedef struct {
    xmpp_ctx_t *ctx;
    const char *jid;
    const char *pass;
    char *domain;
    int authenticated;
} xmpp_auth_t;

#define FEATURES_TIMEOUT 5000 /* 5 seconds */

static int _handle_error(xmpp_conn_t * const conn,
                         xmpp_stanza_t * const stanza,
                         void * const userdata)
{
    fprintf(stderr, "DEBUG: received stream error\n");
    xmpp_disconnect(conn);

    return 0;
}

static int _handle_proceedtls_default(xmpp_conn_t * const conn,
                                      xmpp_stanza_t * const stanza,
                                      void * const userdata)
{
    xmpp_auth_t *auth = (xmpp_auth_t *)userdata;
    const char *name = xmpp_stanza_get_name(stanza);

    (void)auth;
    if (strcmp(name, "proceed") == 0) {
        if (xmpp_conn_tls_start(conn) == 0) {
            xmpp_handler_delete(conn, _handle_error);
            xmpp_conn_open_stream_default(conn);
        } else {
            /* failed tls spoils the connection, so disconnect */
            xmpp_disconnect(conn);
        }
    } else
        xmpp_disconnect(conn);

    return 0;
}

static int _plain_mechanim_exists(xmpp_ctx_t *ctx, xmpp_stanza_t *features)
{
    xmpp_stanza_t *mechanisms;
    xmpp_stanza_t *child;
    char *text;
    int found = 0;

    mechanisms = xmpp_stanza_get_child_by_name(features, "mechanisms");
    child = mechanisms ? xmpp_stanza_get_children(mechanisms) : NULL;
    while (!found && mechanisms && child) {
        /* TODO xmpp_stanza_get_name(child) is "mechanism" */
        text = xmpp_stanza_get_text(child);
        found = text && strcmp(text, "PLAIN") == 0;
        xmpp_free(ctx, text);
        child = xmpp_stanza_get_next(child);
    }
    return found;
}

static char *_plain_mechanism_authdata(xmpp_auth_t *auth)
{
    char *node, *b64;
    unsigned char *msg;
    size_t node_len, pass_len;

    node = xmpp_jid_node(auth->ctx, auth->jid);
    node_len = strlen(node);
    pass_len = strlen(auth->pass);
    msg = malloc(node_len + pass_len + 2);
    msg[0] = '\0';
    memcpy(msg + 1, node, node_len);
    msg[node_len + 1] = '\0';
    memcpy(msg + node_len + 2, auth->pass, pass_len);
    b64 = xmpp_base64_encode(auth->ctx, msg, node_len + pass_len + 2);

    free(msg);
    xmpp_free(auth->ctx, node);

    return b64;
}

static int _plain_mechanism_handle_result(xmpp_conn_t * const conn,
                                          xmpp_stanza_t * const stanza,
                                          void * const userdata)
{
    xmpp_auth_t *auth = (xmpp_auth_t *)userdata;
    const char *name;

    name = xmpp_stanza_get_name(stanza);

    if (strcmp(name, "success") == 0) {
        /* SASL PLAIN auth successful, we need to restart the stream */
        fprintf(stderr, "DEBUG: SASL PLAIN auth successful\n");
        auth->authenticated = 1;
        xmpp_handler_delete(conn, _handle_error);
        xmpp_conn_open_stream_default(conn);
    } else {
        fprintf(stderr, "DEBUG: SASL authentication failed: %s\n", name);
        xmpp_disconnect(conn);
    }
    return 0;
}

static int _handle_missing_features(xmpp_conn_t * const conn,
                                    void * const userdata)
{
    fprintf(stderr, "DEBUG: timeout\n");
    xmpp_disconnect(conn);

    return 0;
}

static int _handle_features(xmpp_conn_t * const conn,
                            xmpp_stanza_t * const stanza,
                            void * const userdata)
{
    xmpp_auth_t *auth = (xmpp_auth_t *)userdata;
    xmpp_ctx_t *ctx = auth->ctx;
    xmpp_stanza_t *plain, *child;
    char *str;

    xmpp_timed_handler_delete(conn, _handle_missing_features);

    if (auth->authenticated) {
        /* after successful SASL authentication */
        /* TODO bind, session and we'are done */
        xmpp_disconnect(conn); /* XXX */
        return 0;
    }

    /* secure connection if possible */
    child = xmpp_stanza_get_child_by_name(stanza, "starttls");
    if (child && (strcmp(xmpp_stanza_get_ns(child), XMPP_NS_TLS) == 0)) {
        child = xmpp_stanza_new(ctx);
        xmpp_stanza_set_name(child, "starttls");
        xmpp_stanza_set_ns(child, XMPP_NS_TLS);
        xmpp_handler_add(conn, _handle_proceedtls_default,
                         XMPP_NS_TLS, NULL, NULL, userdata);
        xmpp_send(conn, child);
        xmpp_stanza_release(child);
        return 0;
    }

    /* check if PLAIN mechanism is supported */
    if (!_plain_mechanim_exists(ctx, stanza)) {
        fprintf(stderr, "DEBUG: PLAIN mechanism is NOT supported\n");
        xmpp_disconnect(conn);
        return 0;
    }

    /* perform authentication */
    plain = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(plain, "auth");
    xmpp_stanza_set_ns(plain, XMPP_NS_SASL);
    xmpp_stanza_set_attribute(plain, "mechanism", "PLAIN");
    str = _plain_mechanism_authdata(auth);
    child = xmpp_stanza_new(ctx);
    xmpp_stanza_set_text(child, str);
    xmpp_free(ctx, str);
    xmpp_stanza_add_child(plain, child);
    xmpp_stanza_release(child);

    xmpp_handler_add(conn, _plain_mechanism_handle_result,
                     XMPP_NS_SASL, NULL, NULL, userdata);
    xmpp_send(conn, plain);
    xmpp_stanza_release(plain);

    return 0;
}

static void conn_handler(xmpp_conn_t * const conn,
                         const xmpp_conn_event_t status,
                         const int error,
                         xmpp_stream_error_t * const stream_error,
                         void * const userdata)
{
    xmpp_auth_t *auth = (xmpp_auth_t *)userdata;
    xmpp_ctx_t *ctx = auth->ctx;
    int secured;

    if (status == XMPP_CONN_RAW_CONNECT) {
        fprintf(stderr, "DEBUG: raw connection established\n");
        xmpp_conn_open_stream_default(conn);
    } else if (status == XMPP_CONN_CONNECT) {
        fprintf(stderr, "DEBUG: stream opened\n");
        secured = xmpp_conn_is_secured(conn);
        fprintf(stderr, "DEBUG: connection is %s.\n",
                secured ? "secured" : "NOT secured");

        /* setup handler for stream:error */
        xmpp_handler_add(conn, _handle_error, XMPP_NS_STREAMS,
                         "error", NULL, NULL);

        /* setup handlers for incoming <stream:features> */
        xmpp_handler_add(conn, _handle_features, XMPP_NS_STREAMS,
                         "features", NULL, auth);
        xmpp_timed_handler_add(conn, _handle_missing_features,
                               FEATURES_TIMEOUT, NULL);
    } else {
        fprintf(stderr, "DEBUG: disconnected\n");
        xmpp_stop(ctx);
    }
}

static xmpp_auth_t *xmpp_auth_new(void)
{
    xmpp_auth_t *auth;

    auth = malloc(sizeof(*auth));
    if (auth != NULL) {
        memset(auth, 0, sizeof(*auth));
    }
    return auth;
}

static void xmpp_auth_release(xmpp_auth_t *auth)
{
    free(auth);
}

int main(int argc, char **argv)
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t *log;
    xmpp_auth_t *auth;
    const char *jid;
    const char *pass;
    const char *host = NULL;

    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s <jid> <pass> [<host>]\n", argv[0]);
        return 1;
    }

    jid = argv[1];
    pass = argv[2];
    if (argc > 3)
        host = argv[3];

    /*
     * Note, this example doesn't handle errors. Applications should check
     * return values of non-void functions.
     */

    xmpp_initialize();
    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG);
    ctx = xmpp_ctx_new(NULL, log);
    conn = xmpp_conn_new(ctx);

    xmpp_conn_set_jid(conn, jid);

    /* private data */
    auth = xmpp_auth_new();
    auth->ctx = ctx;
    auth->jid = jid;
    auth->pass = pass;
    auth->domain = xmpp_jid_domain(ctx, jid);

    xmpp_connect_raw(conn, host, 0, conn_handler, auth);
    xmpp_run(ctx);

    /* release private data */
    xmpp_auth_release(auth);

    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);
    xmpp_shutdown();

    return 0;
}
