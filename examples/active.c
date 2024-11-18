/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* active.c
** libstrophe XMPP client library -- basic usage example
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
** This program is dual licensed under the MIT or GPLv3 licenses.
*/

/* This example demonstrates basic handler functions by printing out
** active resources on a jabberd 2.x server.  This program requires
** an admin account on a jabberd 2.x account in order to run.
*/

#include <stdio.h>
#include <string.h>

#include <strophe.h>

int handle_reply(xmpp_conn_t *conn, xmpp_stanza_t *stanza, void *userdata)
{
    xmpp_stanza_t *query, *item;
    const char *type;

    (void)userdata;

    type = xmpp_stanza_get_type(stanza);
    if (strcmp(type, "error") == 0)
        fprintf(stderr, "ERROR: query failed\n");
    else {
        query = xmpp_stanza_get_child_by_name(stanza, "query");
        printf("Active Sessions:\n");
        for (item = xmpp_stanza_get_children(query); item;
             item = xmpp_stanza_get_next(item))
            printf("\t %s\n", xmpp_stanza_get_attribute(item, "jid"));
        printf("END OF LIST\n");
    }

    /* disconnect */
    xmpp_disconnect(conn);

    return 0;
}

void conn_handler(xmpp_conn_t *conn,
                  xmpp_conn_event_t status,
                  int error,
                  xmpp_stream_error_t *stream_error,
                  void *userdata)
{
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;
    xmpp_stanza_t *iq, *query;

    (void)error;
    (void)stream_error;

    if (status == XMPP_CONN_CONNECT) {
        fprintf(stderr, "DEBUG: connected\n");

        /* create iq stanza for request */
        iq = xmpp_iq_new(ctx, "get", "active1");
        xmpp_stanza_set_to(iq, "xxxxxxxxx.com");

        query = xmpp_stanza_new(ctx);
        xmpp_stanza_set_name(query, "query");
        xmpp_stanza_set_ns(query, XMPP_NS_DISCO_ITEMS);
        xmpp_stanza_set_attribute(query, "node", "sessions");

        xmpp_stanza_add_child(iq, query);

        /* we can release the stanza since it belongs to iq now */
        xmpp_stanza_release(query);

        /* set up reply handler */
        xmpp_id_handler_add(conn, handle_reply, "active1", ctx);

        /* send out the stanza */
        xmpp_send(conn, iq);

        /* release the stanza */
        xmpp_stanza_release(iq);
    } else {
        fprintf(stderr, "DEBUG: disconnected\n");
        xmpp_stop(ctx);
    }
}

int main(int argc, char **argv)
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;

    if (argc != 3) {
        fprintf(stderr, "Usage: active <jid> <pass>\n\n");
        return 1;
    }

    /* initialize lib */
    xmpp_initialize();

    /* create a context */
    ctx = xmpp_ctx_new(NULL, NULL);

    /* create a connection */
    conn = xmpp_conn_new(ctx);

    /*
     * also you can disable TLS support or force legacy SSL
     * connection without STARTTLS
     *
     * see xmpp_conn_set_flags() or examples/basic.c
     */

    /* setup authentication information */
    xmpp_conn_set_string(conn, XMPP_SETTING_JID, argv[1]);
    xmpp_conn_set_string(conn, XMPP_SETTING_PASS, argv[2]);

    /* initiate connection */
    xmpp_connect_client(conn, NULL, 0, conn_handler, ctx);

    /* start the event loop */
    xmpp_run(ctx);

    /* release our connection and context */
    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);

    /* shutdown lib */
    xmpp_shutdown();

    return 0;
}
