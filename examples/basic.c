/* basic.c
** libstrophe XMPP client library -- basic usage example
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
** This program is dual licensed under the MIT and GPLv3 licenses.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <strophe.h>

/* hardcoded TCP keepalive timeout and interval */
#define KA_TIMEOUT 60
#define KA_INTERVAL 1

/* define a handler for connection events */
void conn_handler(xmpp_conn_t *conn,
                  xmpp_conn_event_t status,
                  int error,
                  xmpp_stream_error_t *stream_error,
                  void *userdata)
{
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;
    int secured;

    (void)error;
    (void)stream_error;

    if (status == XMPP_CONN_CONNECT) {
        fprintf(stderr, "DEBUG: connected\n");
        secured = xmpp_conn_is_secured(conn);
        fprintf(stderr, "DEBUG: connection is %s.\n",
                secured ? "secured" : "NOT secured");
        xmpp_disconnect(conn);
    } else {
        fprintf(stderr, "DEBUG: disconnected\n");
        xmpp_stop(ctx);
    }
}

int main(int argc, char **argv)
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t *log;
    char *jid = NULL, *password = NULL, *cert = NULL, *key = NULL, *host = NULL;
    long flags = 0;
    int tcp_keepalive = 0;
    int i;
    unsigned long port = 0;

    /* take a jid and password on the command line */
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--disable-tls") == 0)
            flags |= XMPP_CONN_FLAG_DISABLE_TLS;
        else if (strcmp(argv[i], "--mandatory-tls") == 0)
            flags |= XMPP_CONN_FLAG_MANDATORY_TLS;
        else if (strcmp(argv[i], "--trust-tls") == 0)
            flags |= XMPP_CONN_FLAG_TRUST_TLS;
        else if (strcmp(argv[i], "--legacy-ssl") == 0)
            flags |= XMPP_CONN_FLAG_LEGACY_SSL;
        else if (strcmp(argv[i], "--legacy-auth") == 0)
            flags |= XMPP_CONN_FLAG_LEGACY_AUTH;
        else if (strcmp(argv[i], "--tcp-keepalive") == 0)
            tcp_keepalive = 1;
        else if ((strcmp(argv[i], "--jid") == 0) && (++i < argc))
            jid = argv[i];
        else if ((strcmp(argv[i], "--pass") == 0) && (++i < argc))
            password = argv[i];
        else if ((strcmp(argv[i], "--tls-cert") == 0) && (++i < argc))
            cert = argv[i];
        else if ((strcmp(argv[i], "--tls-key") == 0) && (++i < argc))
            key = argv[i];
        else
            break;
    }
    if ((argc - i) == 0 || (argc - i) > 2) {
        fprintf(stderr,
                "Usage: basic [options] [<host> [<port>]]\n\n"
                "Options:\n"
                "  --jid <jid>              The JID to use to authenticate.\n"
                "  --pass <pass>            The password of the JID.\n"
                "  --tls-cert <cert>        Path to client certificate.\n"
                "  --tls-key <key>          Path to private key.\n\n"
                "  --disable-tls            Disable TLS.\n"
                "  --mandatory-tls          Deny plaintext connection.\n"
                "  --trust-tls              Trust TLS certificate.\n"
                "  --legacy-ssl             Use old style SSL.\n"
                "  --legacy-auth            Allow legacy authentication.\n"
                "  --tcp-keepalive          Configure TCP keepalive.\n\n"
                "Note: --disable-tls conflicts with --mandatory-tls or "
                "--legacy-ssl\n");
        return 1;
    }

    if (i < argc)
        host = argv[i];
    if (i + 1 < argc)
        port = strtoul(argv[i + 1], NULL, 0);

    /*
     * Note, this example doesn't handle errors. Applications should check
     * return values of non-void functions.
     */

    /* init library */
    xmpp_initialize();

    /* pass NULL instead to silence output */
    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG);
    /* create a context */
    ctx = xmpp_ctx_new(NULL, log);

    /* create a connection */
    conn = xmpp_conn_new(ctx);

    /* configure connection properties (optional) */
    xmpp_conn_set_flags(conn, flags);
    /* configure TCP keepalive (optional) */
    if (tcp_keepalive)
        xmpp_conn_set_keepalive(conn, KA_TIMEOUT, KA_INTERVAL);

    /* setup authentication information */
    if (cert && key) {
        xmpp_conn_set_client_cert(conn, cert, key);
    }
    if (jid)
        xmpp_conn_set_jid(conn, jid);
    if (password)
        xmpp_conn_set_pass(conn, password);

    /* initiate connection */
    if (xmpp_connect_client(conn, host, port, conn_handler, ctx) == XMPP_EOK) {

        /* enter the event loop -
           our connect handler will trigger an exit */
        xmpp_run(ctx);
    }

    /* release our connection and context */
    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);

    /* final shutdown of the library */
    xmpp_shutdown();

    return 0;
}
