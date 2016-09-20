/* server.c
 * strophe XMPP client library -- server object functions
 *
 * Copyright (C) 2016 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/** @file
 *  Server management.
 */

/** @defgroup Server Server management
 */

#include <string.h>

#include "common.h"
#include "strophe.h"

static xmpp_server_t *conn2srv(xmpp_conn_t *conn);
static void _server_conn_handler(xmpp_conn_t * const conn,
                                 const xmpp_conn_event_t status,
                                 const int error,
                                 xmpp_stream_error_t * const stream_error,
                                 void * const userdata);

xmpp_server_t *xmpp_server_new(xmpp_ctx_t * const ctx)
{
    xmpp_server_t *srv;
    xmpp_serverlist_t *item;

    srv = xmpp_alloc(ctx, sizeof(*srv));
    item = xmpp_alloc(ctx, sizeof(*item));
    if (srv == NULL || item == NULL) {
        xmpp_error(ctx, "xmpp", "Failed to allocate memory.");
        xmpp_free(ctx, srv);
        xmpp_free(ctx, item);
        srv = NULL;
        item = NULL;
    }

    if (srv != NULL) {
        memset(srv, 0, sizeof(*srv));
        srv->state = XMPP_STATE_STOPPED;
        srv->ctx = ctx;
        srv->sock = -1;

        item->server = srv;
        item->next = ctx->serverlist;
        ctx->serverlist = item;
    }
    return srv;
}

void xmpp_server_free(xmpp_server_t * const srv)
{
    xmpp_ctx_t *ctx = srv->ctx;
    xmpp_serverlist_t *item, *prev = NULL;

    item = ctx->serverlist;
    while (item != NULL) {
        if (item->server == srv) {
            if (prev == NULL) ctx->serverlist = item->next;
            if (prev != NULL) prev->next = item->next;
            xmpp_free(ctx, item);
        }
        prev = item;
        item = item->next;
    }

    xmpp_free(ctx, srv);
}

int xmpp_server_listen(xmpp_server_t * const srv, unsigned short port,
                       xmpp_server_handler callback, void * const userdata)
{
    int rc = 0;

    if (port == 0) port = XMPP_PORT_CLIENT;
    srv->callback = callback;
    srv->userdata = userdata;
    srv->port = port;
    srv->sock = sock_listen(port);
    if (srv->sock >= 0) {
        srv->state = XMPP_STATE_LISTENING;
        xmpp_debug(srv->ctx, "xmpp", "Listening on port %u.", port);
    } else
        rc = XMPP_EINT;

    return rc;
}

void xmpp_server_stop(xmpp_server_t * const srv)
{
    srv->state = XMPP_STATE_STOPPED;
    sock_stop_listen(srv->sock);
    xmpp_debug(srv->ctx, "xmpp", "Server stopped on %u.", srv->port);
}

void server_accept(xmpp_server_t * const srv)
{
    xmpp_conn_t *conn;
    sock_t fd;

    fd = sock_accept(srv->sock);
    if (fd >= 0) {
        xmpp_debug(srv->ctx, "xmpp", "New incoming connection on port %u.",
                   srv->port);

        conn = xmpp_conn_new(srv->ctx);
        conn->type = XMPP_INCOMING;
        conn->state = XMPP_STATE_CONNECTED;
        conn->sock = fd;
        conn->conn_handler = _server_conn_handler;
        conn->userdata = (void *)srv;
        conn->authenticated = 1; /* don't ignore handlers */
        conn_prepare_reset(conn, server_handle_open);

        srv->callback(srv, conn, XMPP_SERVER_ACCEPT, 0, srv->userdata);
    }
}

void server_handle_open(xmpp_conn_t * const conn)
{
    xmpp_server_t *srv = conn2srv(conn);

    /* XXX need to reset parser and re-open stream after authentication */

    srv->callback(srv, conn, XMPP_SERVER_OPEN_STREAM, 0, srv->userdata);
}

static xmpp_server_t *conn2srv(xmpp_conn_t *conn)
{
    xmpp_server_t *srv;

    /* XXX dirty hack */
    if (conn->ctx->serverlist != NULL)
        srv = conn->ctx->serverlist->server;
    else
        srv = NULL;

    return srv;
}

static void _server_conn_handler(xmpp_conn_t * const conn,
                                 const xmpp_conn_event_t status,
                                 const int error,
                                 xmpp_stream_error_t * const stream_error,
                                 void * const userdata)
{
    xmpp_server_t *srv = (xmpp_server_t *)userdata;

    if (status == XMPP_CONN_DISCONNECT) {
        /* remove conn from the list */
        /* XXX when client sends </stream> first, server should close stream too */
        srv->callback(srv, conn, XMPP_SERVER_DISCONNECT, error, srv->userdata);
    }
}
