/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* event.c
** strophe XMPP client library -- event loop and management
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
** This program is dual licensed under the MIT or GPLv3 licenses.
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

#ifndef STROPHE_MESSAGE_BUFFER_SIZE
/** Max buffer size for receiving messages. */
#define STROPHE_MESSAGE_BUFFER_SIZE 4096
#endif

static int _connect_next(xmpp_conn_t *conn)
{
    sock_close(conn->sock);
    conn->sock = sock_connect(conn->xsock);
    if (conn->sock == INVALID_SOCKET)
        return -1;

    conn->timeout_stamp = time_stamp();

    return 0;
}

static int
_conn_write_to_network(xmpp_conn_t *conn, const void *buff, size_t len)
{
    int ret;
    if (conn->tls) {
        ret = tls_write(conn->tls, buff, len);
        if (ret < 0 && !tls_is_recoverable(tls_error(conn->tls)))
            conn->error = tls_error(conn->tls);
    } else {
        ret = sock_write(conn->sock, buff, len);
        if (ret < 0 && !sock_is_recoverable(sock_error()))
            conn->error = sock_error();
    }
    return ret;
}

static int _try_compressed_write_to_network(xmpp_conn_t *conn, int force)
{
    int ret = 0;
    size_t len =
        conn->compression.stream.next_out - (Bytef *)conn->compression.buffer;
    int buffer_full =
        conn->compression.stream.next_out == conn->compression.buffer_end;
    if ((buffer_full || force) && len) {
        ret = _conn_write_to_network(conn, conn->compression.buffer, len);
        if (ret < 0)
            return ret;
        //        print_hex(xmpp_base64_encode(conn->ctx,
        //        conn->compression.buffer, len),
        //                  conn->compression.buffer, len);
        char *b = xmpp_base64_encode(conn->ctx, conn->compression.buffer, len);
        printf("Sent: %s\n", b);
        xmpp_free(conn->ctx, b);

        conn->compression.stream.next_out = conn->compression.buffer;
        conn->compression.stream.avail_out = STROPHE_MESSAGE_BUFFER_SIZE;
    }
    return ret;
}

static int _conn_compress(xmpp_conn_t *conn, void *buff, size_t len, int flush)
{
    int ret;
    void *buff_end = buff + len;
    conn->compression.stream.next_in = buff;
    conn->compression.stream.avail_in = len;
    do {
        ret = _try_compressed_write_to_network(conn, 0);
        if (ret < 0) {
            return ret;
        }

        ret = deflate(&conn->compression.stream, flush);
        if (ret == Z_STREAM_END) {
            break;
        }
        if (flush && ret == Z_BUF_ERROR) {
            break;
        }
        if (ret != Z_OK) {
            strophe_error(conn->ctx, "zlib", "deflate error %d", ret);
            conn->error = EBADFD;
            conn_disconnect(conn);
            return ret;
        }
        ret = conn->compression.stream.next_in - (const Bytef *)buff;
    } while (conn->compression.stream.next_in < (const Bytef *)buff_end);
    if (flush) {
        ret = _try_compressed_write_to_network(conn, 1);
        if (ret < 0) {
            return ret;
        }
    }
    return ret;
}

static void *_zlib_alloc(void *opaque, unsigned int items, unsigned int size)
{
    size_t sz = items * size;
    if (sz < items || sz < size)
        return NULL;
    return strophe_alloc(opaque, sz);
}

static void _init_zlib_compression(xmpp_ctx_t *ctx, struct zlib_compression *s)
{
    s->buffer = strophe_alloc(ctx, STROPHE_MESSAGE_BUFFER_SIZE);
    s->buffer_end = s->buffer + STROPHE_MESSAGE_BUFFER_SIZE;

    s->stream.opaque = ctx;
    s->stream.zalloc = _zlib_alloc;
    s->stream.zfree = (free_func)strophe_free;
}

static int _conn_write(xmpp_conn_t *conn, void *buff, size_t len)
{
    if (conn->compress) {
        if (conn->compression.buffer == NULL) {
            _init_zlib_compression(conn->ctx, &conn->compression);

            conn->compression.stream.next_out = conn->compression.buffer;
            conn->compression.stream.avail_out = STROPHE_MESSAGE_BUFFER_SIZE;
            int err =
                deflateInit(&conn->compression.stream, Z_DEFAULT_COMPRESSION);
            if (err != Z_OK) {
                strophe_free_and_null(conn->ctx, conn->compression.buffer);
                conn->error = EBADFD;
                conn_disconnect(conn);
                return err;
            }
        }
        return _conn_compress(conn, buff, len, Z_NO_FLUSH);
    } else {
        return _conn_write_to_network(conn, buff, len);
    }
}

static int _conn_read_from_network(xmpp_conn_t *conn, void *buff, size_t len)
{
    if (conn->tls) {
        return tls_read(conn->tls, buff, len);
    } else {
        return sock_read(conn->sock, buff, len);
    }
}

static int
_conn_decompress(xmpp_conn_t *conn, size_t c_len, void *buff, size_t len)
{
    if (conn->decompression.stream.next_in == NULL) {
        conn->decompression.stream.next_in = conn->decompression.buffer;
        conn->decompression.buffer_end =
            conn->decompression.stream.next_in + c_len;
        conn->decompression.stream.avail_in = c_len;
    } else if (c_len) {
        strophe_error(conn->ctx, "zlib",
                      "_conn_decompress() called with c_len=%zu", c_len);
    }
    conn->decompression.stream.next_out = buff;
    conn->decompression.stream.avail_out = len;
    int ret = inflate(&conn->decompression.stream, Z_SYNC_FLUSH);
    switch (ret) {
    case Z_STREAM_END:
    case Z_OK:
        if (conn->decompression.buffer_end ==
            conn->decompression.stream.next_in)
            conn->decompression.stream.next_in = NULL;
        /* -fallthrough */
        return conn->decompression.stream.next_out - (Bytef *)buff;
    case Z_BUF_ERROR:
        break;
    default:
        strophe_error(conn->ctx, "zlib", "inflate error %d", ret);
        conn->error = EBADFD;
        conn_disconnect(conn);
        break;
    }
    return 0;
}

static int _conn_read(xmpp_conn_t *conn, void *buff, size_t len)
{
    void *dbuff = buff;
    size_t dlen = len;
    if (conn->compress) {
        if (conn->decompression.buffer == NULL) {
            _init_zlib_compression(conn->ctx, &conn->decompression);

            int err = inflateInit(&conn->decompression.stream);
            if (err != Z_OK) {
                strophe_free_and_null(conn->ctx, conn->decompression.buffer);
                return err;
            }
        }
        if (conn->decompression.stream.next_in != NULL) {
            return _conn_decompress(conn, 0, buff, len);
        }
        dbuff = conn->decompression.buffer;
        dlen = STROPHE_MESSAGE_BUFFER_SIZE;
    }
    int ret = _conn_read_from_network(conn, dbuff, dlen);
    if (ret > 0 && conn->compress) {
        char *b = xmpp_base64_encode(conn->ctx, dbuff, ret);
        printf("Read: %s\n", b);
        xmpp_free(conn->ctx, b);
        return _conn_decompress(conn, ret, buff, len);
    }
    return ret;
}

static int _conn_pending(xmpp_conn_t *conn)
{
    return (conn->compress && conn->decompression.stream.next_in != NULL) ||
           (conn->tls && tls_pending(conn->tls));
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
    char buf[STROPHE_MESSAGE_BUFFER_SIZE];
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
                strophe_debug(
                    ctx, "xmpp",
                    "Send error of pending data occurred, disconnecting.");
                conn->error = ECONNABORTED;
                conn_disconnect(conn);
                goto next_item;
            }
        }

        /* write all data from the send queue to the socket */
        sq = conn->send_queue_head;
        while (sq) {
            towrite = sq->len - sq->written;

            ret = _conn_write(conn, &sq->data[sq->written], towrite);
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
                strophe_debug_verbose(1, ctx, "xmpp", "SM_Q_MOVE: %p, h=%lu",
                                      tsq, tsq->sm_h);
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
        if (conn->compress) {
            _conn_compress(conn, conn->compression.buffer, 0,
                           conn->compression_dont_flush ? Z_SYNC_FLUSH
                                                        : Z_FULL_FLUSH);
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
            if (FD_ISSET(conn->sock, &rfds) || _conn_pending(conn)) {

                ret = _conn_read(conn, buf, STROPHE_MESSAGE_BUFFER_SIZE);

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
