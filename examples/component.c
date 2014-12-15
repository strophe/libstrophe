/* component.c
** libstrophe XMPP client library -- external component (XEP-0114) example
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
** This program is dual licensed under the MIT and GPLv3 licenses.
*/

/* This example demonstrates simple connection to a server
** as an external component. See XEP-0114 for more details.
** This program requires correctly configured server to run.
*/

#include <stdio.h>
#include <stdlib.h>

#include <strophe.h>


/* define a handler for connection events */
void conn_handler(xmpp_conn_t * const conn, const xmpp_conn_event_t status,
                  const int error, xmpp_stream_error_t * const stream_error,
                  void * const userdata)
{
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;

    if (status == XMPP_CONN_CONNECT) {
        fprintf(stderr, "DEBUG: connected\n");
        xmpp_disconnect(conn);
    }
    else {
        fprintf(stderr, "DEBUG: disconnected\n");
        xmpp_stop(ctx);
    }
}

int main(int argc, char **argv)
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t *log;
    char *jid, *pass, *host, *port_err = NULL;
    unsigned short port = 0;

    /* take a jid and password on the command line */
    if (argc < 4 || argc > 5) {
        fprintf(stderr, "Usage: component <jid> <pass> <host> [<port>]\n\n");
        return 1;
    }

    jid = argv[1];
    pass = argv[2];
    host = argv[3];

    if (argc == 5) {
        short tmp_port = (short) strtol(argv[4], &port_err, 10);
        if (tmp_port < 0 || *port_err != '\0') {
            fprintf(stderr, "Invalid value of <port> [%s].\n", argv[4]);
            return 1;
        }
        port = (unsigned short) tmp_port;
    }

    /* init library */
    xmpp_initialize();

    /* create a context */
    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG); /* pass NULL instead to silence output */
    ctx = xmpp_ctx_new(NULL, log);

    /* create a connection */
    conn = xmpp_conn_new(ctx);

    /* setup authentication information */
    xmpp_conn_set_jid(conn, jid);
    xmpp_conn_set_pass(conn, pass);

    /* initiate connection */
    xmpp_connect_component(conn, host, port, conn_handler, ctx);

    /* enter the event loop -
       our connect handler will trigger an exit */
    xmpp_run(ctx);

    /* release our connection and context */
    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);

    /* final shutdown of the library */
    xmpp_shutdown();

    return 0;
}

