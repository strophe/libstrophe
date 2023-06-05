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
#define _sleep(x) usleep((x)*1000)
#else
#include <winsock2.h>
#ifndef ETIMEDOUT
#define ETIMEDOUT WSAETIMEDOUT
#endif
#ifndef ECONNRESET
#define ECONNRESET WSAECONNRESET
#endif
#ifndef ECONNABORTED
#define ECONNABORTED WSAECONNABORTED
#endif
#define _sleep(x) Sleep(x)
#endif

#include "strophe.h"
#include "common.h"
#include "parser.h"

/** Max buffer size for receiving messages. */
#define STROPE_MESSAGE_BUFFER_SIZE 4096

static int _connect_next(xmpp_conn_t *conn)
{
    sock_close(conn->sock);
    conn->sock = sock_connect(conn->xsock);
    if (conn->sock == INVALID_SOCKET)
        return -1;

    conn->timeout_stamp = time_stamp();

    return 0;
}

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
void xmpp_run_once(xmpp_ctx_t *ctx, unsigned long timeout)
{
    xmpp_connlist_t *connitem;
    xmpp_conn_t *conn;
    fd_set rfds, wfds;
    sock_t max = 0;
    int ret;
    struct timeval tv;
    xmpp_send_queue_t *sq, *tsq;
    int towrite;
    char buf[STROPE_MESSAGE_BUFFER_SIZE];
    uint64_t next;
    uint64_t usec;
    int tls_read_bytes = 0;

    if (ctx->loop_status == XMPP_LOOP_QUIT)
        return;

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
                /* an error occurred */
                strophe_debug(ctx, "xmpp",
                              "Send error occurred, disconnecting.");
                conn->error = ECONNABORTED;
                conn_disconnect(conn);
                goto next_item;
            }
        }

        /* write all data from the send queue to the socket */
        sq = conn->send_queue_head;
        while (sq) {
            towrite = sq->len - sq->written;

            if (conn->tls) {
                ret = tls_write(conn->tls, &sq->data[sq->written], towrite);
                if (ret < 0 && !tls_is_recoverable(tls_error(conn->tls)))
                    conn->error = tls_error(conn->tls);
            } else {
                ret = sock_write(conn->sock, &sq->data[sq->written], towrite);
                if (ret < 0 && !sock_is_recoverable(sock_error()))
                    conn->error = sock_error();
            }
            if (ret > 0 && ret < towrite)
                sq->written += ret; /* not all data could be sent now */
            sq->wip = 1;
            if (ret != towrite)
                break; /* partial write or an error */

            /* all data for this queue item written, delete and move on */
            strophe_debug(conn->ctx, "conn", "SENT: %s", sq->data);
            strophe_debug_verbose(1, ctx, "xmpp", "Q_SENT: %p", sq);
            tsq = sq;
            sq = sq->next;
            conn->send_queue_len--;
            if (tsq->owner & XMPP_QUEUE_USER)
                conn->send_queue_user_len--;
            if (!(tsq->owner & XMPP_QUEUE_SM) && conn->sm_state->sm_enabled) {
                tsq->sm_h = conn->sm_state->sm_sent_nr;
                conn->sm_state->sm_sent_nr++;
                strophe_debug_verbose(1, ctx, "xmpp", "SM_Q_MOVE: %p", tsq);
                add_queue_back(&conn->sm_state->sm_queue, tsq);
                tsq = NULL;
            }
            if (tsq) {
                strophe_debug_verbose(2, ctx, "xmpp", "Q_FREE: %p", tsq);
                strophe_debug_verbose(3, ctx, "conn", "Q_CONTENT: %s",
                                      tsq->data);
                strophe_free(ctx, tsq->data);
                strophe_free(ctx, tsq);
            }

            /* pop the top item */
            conn->send_queue_head = sq;
            /* if we've sent everything update the tail */
            if (!sq)
                conn->send_queue_tail = NULL;
        }

        /* tear down connection on error */
        if (conn->error) {
            /* FIXME: need to tear down send queues and random other things
             * maybe this should be abstracted */
            strophe_debug(ctx, "xmpp", "Send error occurred, disconnecting.");
            conn->error = ECONNABORTED;
            conn_disconnect(conn);
        }
next_item:
        connitem = connitem->next;
    }

    /* reset parsers if needed */
    for (connitem = ctx->connlist; connitem; connitem = connitem->next) {
        if (connitem->conn->reset_parser)
            conn_parser_reset(connitem->conn);
    }

    /* fire any ready timed handlers, then make sure we don't wait past
       the time when timed handlers need to be called */
    next = handler_fire_timed(ctx);

    usec = ((next < timeout) ? next : timeout) * 1000;
    tv.tv_sec = (long)(usec / 1000000);
    tv.tv_usec = (long)(usec % 1000000);

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
                strophe_info(ctx, "xmpp", "Connection attempt timed out.");
                ret = _connect_next(conn);
                if (ret != 0) {
                    conn->error = ETIMEDOUT;
                    conn_disconnect(conn);
                } else {
                    FD_SET(conn->sock, &wfds);
                }
            }
            break;
        case XMPP_STATE_CONNECTED:
            FD_SET(conn->sock, &rfds);
            if (conn->send_queue_len > 0)
                FD_SET(conn->sock, &wfds);
            break;
        case XMPP_STATE_DISCONNECTED:
            /* do nothing */
        default:
            break;
        }

        /* Check if there is something in the SSL buffer. */
        if (conn->tls)
            tls_read_bytes += tls_pending(conn->tls);

        if (conn->state != XMPP_STATE_DISCONNECTED && conn->sock > max)
            max = conn->sock;

        connitem = connitem->next;
    }

    /* check for events */
    if (max > 0)
        ret = select(max + 1, &rfds, &wfds, NULL, &tv);
    else {
        if (timeout > 0)
            _sleep(timeout);
        return;
    }

    /* select errored */
    if (ret < 0) {
        if (!sock_is_recoverable(sock_error()))
            strophe_error(ctx, "xmpp", "event watcher internal error %d",
                          sock_error());
        return;
    }

    /* no events happened */
    if (ret == 0 && tls_read_bytes == 0)
        return;

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
                    strophe_debug(ctx, "xmpp", "connection failed, error %d",
                                  ret);
                    ret = _connect_next(conn);
                    if (ret != 0) {
                        conn->error = ret;
                        conn_disconnect(conn);
                    }
                    break;
                }

                conn->state = XMPP_STATE_CONNECTED;
                strophe_debug(ctx, "xmpp", "connection successful");
                conn_established(conn);
            }

            break;
        case XMPP_STATE_CONNECTED:
            if (FD_ISSET(conn->sock, &rfds) ||
                (conn->tls && tls_pending(conn->tls))) {
                if (conn->tls) {
                    ret = tls_read(conn->tls, buf, STROPE_MESSAGE_BUFFER_SIZE);
                } else {
                    ret =
                        sock_read(conn->sock, buf, STROPE_MESSAGE_BUFFER_SIZE);
                }

                if (ret > 0) {
                    ret = parser_feed(conn->parser, buf, ret);
                    if (!ret) {
                        strophe_debug(ctx, "xmpp", "parse error [%s]", buf);
                        xmpp_send_error(conn, XMPP_SE_INVALID_XML,
                                        "parse error");
                    }
                } else {
                    if (conn->tls) {
                        if (!tls_is_recoverable(tls_error(conn->tls))) {
                            strophe_debug(ctx, "xmpp",
                                          "Unrecoverable TLS error, %d.",
                                          tls_error(conn->tls));
                            conn->error = tls_error(conn->tls);
                            conn_disconnect(conn);
                        }
                    } else {
                        /* return of 0 means socket closed by server */
                        strophe_debug(ctx, "xmpp",
                                      "Socket closed by remote host.");
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
    if (ctx->loop_status != XMPP_LOOP_NOTSTARTED)
        return;

    ctx->loop_status = XMPP_LOOP_RUNNING;
    while (ctx->loop_status == XMPP_LOOP_RUNNING) {
        xmpp_run_once(ctx, ctx->timeout);
    }

    /* make it possible to start event loop again */
    ctx->loop_status = XMPP_LOOP_NOTSTARTED;

    strophe_debug(ctx, "event", "Event loop completed.");
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
    strophe_debug(ctx, "event", "Stopping event loop.");

    if (ctx->loop_status == XMPP_LOOP_RUNNING)
        ctx->loop_status = XMPP_LOOP_QUIT;
}

/** Set the timeout to use when calling xmpp_run().
 *
 *  @param ctx a Strophe context object
 *  @param timeout the time to wait for events in milliseconds
 *
 *  @ingroup EventLoop
 */
void xmpp_ctx_set_timeout(xmpp_ctx_t *ctx, unsigned long timeout)
{
    ctx->timeout = timeout;
}
