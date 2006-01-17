/* event.c
** libstrophe XMPP client library -- event loop and management
**
** Copyright (C) 2005 OGG, LCC. All rights reserved.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This software is distributed under license and may not be copied,
**  modified or distributed except as expressly authorized under the
**  terms of the license contained in the file LICENSE.txt in this
**  distribution.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/select.h>
#include <errno.h>
#else
#include <winsock2.h>
#define ETIMEDOUT WSAETIMEDOUT
#define ECONNRESET WSAECONNRESET
#define ECONNABORTED WSAECONNABORTED
#endif

#include "strophe.h"
#include "common.h"

#define DEFAULT_TIMEOUT 1

/* send data and check all connections for their events 
 * and call event handlers.  timeout is in milliseconds */
void xmpp_run_once(xmpp_ctx_t *ctx, const unsigned long timeout)
{
    xmpp_connlist_t *connitem;
    xmpp_conn_t *conn;
    fd_set rfds, wfds;
    sock_t max = 0;
    int ret;
    struct timeval tv;
    xmpp_send_queue_t *sq, *tsq;
    size_t towrite;
    char buf[4096];
    uint64_t next;

    if (ctx->loop_status == XMPP_LOOP_QUIT) return;
    ctx->loop_status = XMPP_LOOP_RUNNING;

    /* send queued data */
    connitem = ctx->connlist;
    while (connitem) {
	conn = connitem->conn;
	if (conn->state != XMPP_STATE_CONNECTED) {
	    connitem = connitem->next;
	    continue;
	}

	sq = conn->send_queue_head;
	while (sq) {
	    towrite = sq->len - sq->written;
	    ret = sock_write(conn->sock, &sq->data[sq->written], towrite);

	    if (ret < 0 && !sock_is_recoverable(sock_error())) {
		/* an error occured */
		conn->error = sock_error();
		break;
	    } else if (ret < towrite) {
		/* not all data could be sent now */
	        if (ret >= 0) sq->written += ret;
		break;
	    }

	    /* all data for this queue item written, delete and move on */
	    xmpp_free(ctx, sq->data);
	    tsq = sq;
	    sq = sq->next;
	    xmpp_free(ctx, tsq);

	    /* pop the top item */
	    conn->send_queue_head = sq;
	    /* if we've sent everything update the tail */
	    if (!sq) conn->send_queue_tail = NULL;
	}

	/* tear down connection on error */
	if (conn->error) {
	    /* FIXME: need to tear down send queues and random other things
	     * maybe this should be abstracted */
	    xmpp_debug(ctx, "xmpp", "Send error occured, disconnecting.");
	    conn->error = ECONNABORTED;
	    conn_disconnect(conn);
	}
	
	connitem = connitem->next;
    }

    /* reset parsers if needed */
    for (connitem = ctx->connlist; connitem; connitem = connitem->next) {
	if (connitem->conn->reset_parser)
	    parser_reset(connitem->conn);
    }


    /* fire any ready timed handlers, then
       make sure we don't wait past the time when timed handlers need 
       to be called */
    next = handler_fire_timed(ctx);

    tv.tv_sec = 0;
    tv.tv_usec = ((next < timeout) ? next : timeout) * 1000;

    FD_ZERO(&rfds); 
    FD_ZERO(&wfds);

    /* find events to watch */
    connitem = ctx->connlist;
    while (connitem) {
	conn = connitem->conn;
	
	switch (conn->state) {
	case XMPP_STATE_CONNECTING:
	    /* connect has been called and we're waiting for it to complete */
	    /* connection will give us write or error events */
	    
	    /* make sure the timeout hasn't expired */
	    if (time_elapsed(conn->timeout_stamp, time_stamp()) <= 
		conn->connect_timeout)
		FD_SET(conn->sock, &wfds);
	    else {
		conn->error = ETIMEDOUT;
		xmpp_info(ctx, "xmpp", "Connection attempt timed out.");
		conn_disconnect(conn);
	    }
	    break;
	case XMPP_STATE_CONNECTED:
	    FD_SET(conn->sock, &rfds);
	    break;
	case XMPP_STATE_DISCONNECTED:
	    /* do nothing */
	default:
	    break;
	}
	
	if (conn->sock > max) max = conn->sock;

	connitem = connitem->next;
    }

    /* check for events */
    ret = select(max + 1, &rfds,  &wfds, NULL, &tv);

    /* select errored */
    if (ret < 0) {
	xmpp_error(ctx, "xmpp", "event watcher internal error %d", 
                   sock_error());
	return;
    }
    
    /* no events happened */
    if (ret == 0) return;

    /* process events */
    connitem = ctx->connlist;
    while (connitem) {
	conn = connitem->conn;

	switch (conn->state) {
	case XMPP_STATE_CONNECTING:
	    if (FD_ISSET(conn->sock, &wfds)) {
		/* connection complete */

		/* check for error */
		if (sock_connect_error(conn->sock) != 0) {
		    /* connection failed */
		    xmpp_debug(ctx, "xmpp", "connection failed");
		    conn_disconnect(conn);
		    break;
		}

		conn->state = XMPP_STATE_CONNECTED;
		xmpp_debug(ctx, "xmpp", "connection successful");

		
		/* send stream init */
		conn_open_stream(conn);
	    }

	    break;
	case XMPP_STATE_CONNECTED:
	    if (FD_ISSET(conn->sock, &rfds)) {
		ret = sock_read(conn->sock, buf, 4096);
		if (ret > 0) {
		    ret = XML_Parse(conn->parser, buf, ret, 0);
		    if (!ret) {
			/* parse error, we need to shut down */
			/* FIXME */
			xmpp_debug(ctx, "xmpp", "parse error, disconnecting");
			conn_disconnect(conn);
		    }
		} else {
		    /* return of 0 means socket closed by server */
		    xmpp_debug(ctx, "xmpp", "Socket closed by remote host.");
		    conn->error = ECONNRESET;
		    conn_disconnect(conn);
		}
	    }

	    break;
	case XMPP_STATE_DISCONNECTED:
	    /* do nothing */
	default:
	    break;
	}

	connitem = connitem->next;
    }

    /* fire any ready handlers */
    handler_fire_timed(ctx);
}

void xmpp_run(xmpp_ctx_t *ctx)
{
    if (ctx->loop_status != XMPP_LOOP_NOTSTARTED) return;

    ctx->loop_status = XMPP_LOOP_RUNNING;
    while (ctx->loop_status == XMPP_LOOP_RUNNING) {
	xmpp_run_once(ctx, DEFAULT_TIMEOUT);
    }

    xmpp_debug(ctx, "event", "Event loop completed.");
}

void xmpp_stop(xmpp_ctx_t *ctx)
{
    xmpp_debug(ctx, "event", "Stopping event loop.");

    if (ctx->loop_status == XMPP_LOOP_RUNNING)
	ctx->loop_status = XMPP_LOOP_QUIT;
}
