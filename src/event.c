/* event.c
** strophe XMPP client library -- event loop and management
**
** Copyright (C) 2005-2009 Collecta, Inc. 
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
** This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  Event loop and management.
 */

/** @defgroup EventLoop Event loop
 *  These functions manage the Strophe event loop.  
 *  
 *  Simple tools can use xmpp_run() and xmpp_stop() to manage the life
 *  cycle of the program.  A common idiom is to set up a few initial
 *  event handers, call xmpp_run(), and then respond and react to
 *  events as they come in.  At some point, one of the handlers will
 *  call xmpp_stop() to quit the event loop which leads to the program
 *  terminating.
 * 
 *  More complex programs will have their own event loops, and should
 *  ensure that xmpp_run_once() is called regularly from there.  For
 *  example, a GUI program will already include an event loop to
 *  process UI events from users, and xmpp_run_once() would be called
 *  from an idle function.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/select.h>
#include <errno.h>
#include <unistd.h>
#define _sleep(x) usleep(x*1000)
#else
#include <winsock2.h>
#define ETIMEDOUT WSAETIMEDOUT
#define ECONNRESET WSAECONNRESET
#define ECONNABORTED WSAECONNABORTED
#define _sleep(x) Sleep(x)
#endif

#include <strophe.h>
#include "common.h"
#include "parser.h"

#ifndef DEFAULT_TIMEOUT
/** @def DEFAULT_TIMEOUT
 *  The default timeout in milliseconds for the event loop.
 *  This is set to 1 millisecond.
 */
#define DEFAULT_TIMEOUT 1
#endif

/** Run the event loop once.
 *  This function will run send any data that has been queued by
 *  xmpp_send and related functions and run through the Strophe even
 *  loop a single time, and will not wait more than timeout
 *  milliseconds for events.  This is provided to support integration
 *  with event loops outside the library, and if used, should be
 *  called regularly to achieve low latency event handling.
 *
 *  @param ctx a Strophe context object
 *  @param timeout time to wait for events in milliseconds
 *
 *  @ingroup EventLoop
 */
void xmpp_run_once(xmpp_ctx_t *ctx, const unsigned long timeout)
{
    xmpp_connlist_t *connitem;
    xmpp_conn_t *conn;
    fd_set rfds, wfds;
    sock_t max = 0;
    int ret;
    struct timeval tv;
    xmpp_send_queue_t *sq, *tsq;
    int towrite;
    char buf[4096];
    uint64_t next;
    long usec;
    int tls_read_bytes = 0;

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

	/* if we're running tls, there may be some remaining data waiting to
	 * be sent, so push that out */
	if (conn->tls) {
	    ret = tls_clear_pending_write(conn->tls);

	    if (ret < 0 && !tls_is_recoverable(tls_error(conn->tls))) {
		/* an error occured */
		xmpp_debug(ctx, "xmpp", "Send error occured, disconnecting.");
		conn->error = ECONNABORTED;
		conn_disconnect(conn);
	    }
	}

	/* write all data from the send queue to the socket */
	sq = conn->send_queue_head;
	while (sq) {
	    towrite = sq->len - sq->written;

	    if (conn->tls) {
		ret = tls_write(conn->tls, &sq->data[sq->written], towrite);

		if (ret < 0 && !tls_is_recoverable(tls_error(conn->tls))) {
		    /* an error occured */
		    conn->error = tls_error(conn->tls);
		    if( conn->error == 5 )
			xmpp_debug(ctx, "xmpp", "Unrecoverable TLS write error, syscall %s.", strerror(errno));
		    else
			xmpp_debug(ctx, "xmpp", "Unrecoverable TLS write error, %d.", conn->error);
		    break;
		} else if (ret < towrite) {
		    /* not all data could be sent now */
		    if (ret >= 0) sq->written += ret;
		    break;
		}

	    } else {
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
	    conn_parser_reset(connitem->conn);
    }


    /* fire any ready timed handlers, then
       make sure we don't wait past the time when timed handlers need 
       to be called */
    next = handler_fire_timed(ctx);

    usec = ((next < timeout) ? next : timeout) * 1000;
    tv.tv_sec = usec / 1000000;
    tv.tv_usec = usec % 1000000;

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
	
	/* Check if there is something in the SSL buffer. */
	if (conn->tls) {
	    tls_read_bytes += tls_pending(conn->tls);
	}
	
	if (conn->state != XMPP_STATE_DISCONNECTED && conn->sock > max)
	    max = conn->sock;

	connitem = connitem->next;
    }

    /* check for events */
    if (max > 0)
        ret = select(max + 1, &rfds,  &wfds, NULL, &tv);
    else {
        if (timeout > 0)
            _sleep(timeout);
        return;
    }

    /* select errored */
    if (ret < 0) {
	if (!sock_is_recoverable(sock_error()))
	    xmpp_error(ctx, "xmpp", "event watcher internal error %d", 
		       sock_error());
	return;
    }
    
    /* no events happened */
    if (ret == 0 && tls_read_bytes == 0) return;

    /* process events */
    connitem = ctx->connlist;
    while (connitem) {
	conn = connitem->conn;

	switch (conn->state) {
	case XMPP_STATE_CONNECTING:
	    if (FD_ISSET(conn->sock, &wfds)) {
		/* connection complete */

		/* check for error */
                ret = sock_connect_error(conn->sock);
		if (ret != 0) {
		    /* connection failed */
		    xmpp_debug(ctx, "xmpp", "connection failed, error %d", ret);
		    conn_disconnect(conn);
		    break;
		}

		conn->state = XMPP_STATE_CONNECTED;
		xmpp_debug(ctx, "xmpp", "connection successful");

                if (conn->tls_legacy_ssl) {
                    xmpp_debug(ctx, "xmpp", "using legacy SSL connection");
                    ret = conn_tls_start(conn);
                    if (ret != 0) {
                        conn_disconnect(conn);
                        break;
                    }
                }

		/* send stream init */
		conn_open_stream(conn);
	    }

	    break;
	case XMPP_STATE_CONNECTED:
	    if (FD_ISSET(conn->sock, &rfds) || (conn->tls && tls_pending(conn->tls))) {
		if (conn->tls) {
		    ret = tls_read(conn->tls, buf, 4096);
		} else {
		    ret = sock_read(conn->sock, buf, 4096);
		}

		if (ret > 0) {
		    ret = parser_feed(conn->parser, buf, ret);
		    if (!ret) {
			/* parse error, we need to shut down */
			/* FIXME */
			xmpp_debug(ctx, "xmpp", "parse error, disconnecting");
			conn_disconnect(conn);
		    }
		} else {
		    if (conn->tls) {
			if (!tls_is_recoverable(tls_error(conn->tls)))
			{
			    conn->error = tls_error(conn->tls);
			    if( conn->error == 5 )
				xmpp_debug(ctx, "xmpp", "Unrecoverable TLS read error, syscall %s.", strerror(errno));
			    else
				xmpp_debug(ctx, "xmpp", "Unrecoverable TLS read error, %d.", conn->error);
			    conn_disconnect(conn);
			}
		    } else {
			/* return of 0 means socket closed by server */
			xmpp_debug(ctx, "xmpp", "Socket closed by remote host.");
			conn->error = ECONNRESET;
			conn_disconnect(conn);
		    }
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

/** Start the event loop.
 *  This function continuously calls xmpp_run_once and does not return
 *  until xmpp_stop has been called.
 *
 *  @param ctx a Strophe context object
 *
 *  @ingroup EventLoop
 */
void xmpp_run(xmpp_ctx_t *ctx)
{
    if (ctx->loop_status != XMPP_LOOP_NOTSTARTED) return;

    ctx->loop_status = XMPP_LOOP_RUNNING;
    while (ctx->loop_status == XMPP_LOOP_RUNNING) {
	xmpp_run_once(ctx, DEFAULT_TIMEOUT);
    }

    xmpp_debug(ctx, "event", "Event loop completed.");
}

/** Stop the event loop.
 *  This will stop the event loop after the current iteration and cause
 *  xmpp_run to exit.
 *
 *  @param ctx a Strophe context object
 *
 *  @ingroup EventLoop
 */
void xmpp_stop(xmpp_ctx_t *ctx)
{
    xmpp_debug(ctx, "event", "Stopping event loop.");

    if (ctx->loop_status == XMPP_LOOP_RUNNING)
	ctx->loop_status = XMPP_LOOP_QUIT;
}
