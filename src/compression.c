/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* compression.c
** strophe XMPP client library -- XEP-0138 Stream Compression
**
** Copyright (C) 2024 Steffen Jaeckel <jaeckel-floss@eyet-services.de>
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT or GPLv3 licenses.
*/

/** @file
 *  XEP-0138 Stream Compression.
 */
#include <zlib.h>
#include <string.h>
#include <errno.h>

#include "common.h"
#ifdef _MSC_VER
#define strcasecmp _stricmp
#endif

#ifndef STROPHE_COMPRESSION_BUFFER_SIZE
/** Max buffer size for compressed data (send & receive). */
#define STROPHE_COMPRESSION_BUFFER_SIZE 4096
#endif

struct zlib_compression {
    void *buffer, *buffer_end;
    z_stream stream;
};

struct xmpp_compression {
    xmpp_conn_t *conn;
    struct zlib_compression compression, decompression;
    struct conn_interface next;
};

static int _conn_decompress(struct xmpp_compression *comp,
                            size_t c_len,
                            void *buff,
                            size_t len)
{
    if (comp->decompression.stream.next_in == NULL) {
        comp->decompression.stream.next_in = comp->decompression.buffer;
        comp->decompression.buffer_end =
            comp->decompression.stream.next_in + c_len;
        comp->decompression.stream.avail_in = c_len;
    } else if (c_len) {
        strophe_error(comp->conn->ctx, "zlib",
                      "_conn_decompress() called with c_len=%zu", c_len);
    }
    comp->decompression.stream.next_out = buff;
    comp->decompression.stream.avail_out = len;
    int ret = inflate(&comp->decompression.stream, Z_SYNC_FLUSH);
    switch (ret) {
    case Z_STREAM_END:
    case Z_OK:
        if (comp->decompression.buffer_end ==
            comp->decompression.stream.next_in)
            comp->decompression.stream.next_in = NULL;
        return comp->decompression.stream.next_out - (Bytef *)buff;
    case Z_BUF_ERROR:
        break;
    default:
        strophe_error(comp->conn->ctx, "zlib", "inflate error %d", ret);
        comp->conn->error = ret;
        conn_disconnect(comp->conn);
        break;
    }
    return 0;
}

static int compression_read(struct conn_interface *intf, void *buff, size_t len)
{
    xmpp_conn_t *conn = intf->conn;
    struct xmpp_compression *comp = conn->compression.state;
    void *dbuff = buff;
    size_t dlen = len;
    if (comp->decompression.stream.next_in != NULL) {
        return _conn_decompress(comp, 0, buff, len);
    }
    dbuff = comp->decompression.buffer;
    dlen = STROPHE_COMPRESSION_BUFFER_SIZE;
    int ret = comp->next.read(intf, dbuff, dlen);
    if (ret > 0) {
        return _conn_decompress(comp, ret, buff, len);
    }
    return ret;
}

static int _try_compressed_write_to_network(xmpp_conn_t *conn, int force)
{
    struct xmpp_compression *comp = conn->compression.state;
    int ret = 0;
    ptrdiff_t len =
        comp->compression.stream.next_out - (Bytef *)comp->compression.buffer;
    int buffer_full =
        comp->compression.stream.next_out == comp->compression.buffer_end;
    if ((buffer_full || force) && len > 0) {
        ret = conn_interface_write(&comp->next, comp->compression.buffer, len);
        if (ret < 0)
            return ret;
        comp->compression.stream.next_out = comp->compression.buffer;
        comp->compression.stream.avail_out = STROPHE_COMPRESSION_BUFFER_SIZE;
    }
    return ret;
}

static int
_compression_write(xmpp_conn_t *conn, const void *buff, size_t len, int flush)
{
    int ret;
    const void *buff_end = (const char *)buff + len;
    struct xmpp_compression *comp = conn->compression.state;
    comp->compression.stream.next_in = (Bytef *)buff;
    comp->compression.stream.avail_in = len;
    do {
        ret = _try_compressed_write_to_network(conn, 0);
        if (ret < 0) {
            return ret;
        }

        ret = deflate(&comp->compression.stream, flush);
        if (ret == Z_STREAM_END) {
            break;
        }
        if (flush && ret == Z_BUF_ERROR) {
            break;
        }
        if (ret != Z_OK) {
            strophe_error(conn->ctx, "zlib", "deflate error %d", ret);
            conn->error = ret;
            conn_disconnect(conn);
            return ret;
        }
        ret = comp->compression.stream.next_in - (Bytef *)buff;
    } while (comp->compression.stream.next_in < (Bytef *)buff_end);
    if (flush) {
        ret = _try_compressed_write_to_network(conn, 1);
        if (ret < 0) {
            return ret;
        }
    }
    return ret;
}

static int
compression_write(struct conn_interface *intf, const void *buff, size_t len)
{
    return _compression_write(intf->conn, buff, len, Z_NO_FLUSH);
}

static int compression_flush(struct conn_interface *intf)
{
    xmpp_conn_t *conn = intf->conn;
    struct xmpp_compression *comp = conn->compression.state;
    return _compression_write(conn, comp->compression.buffer, 0,
                              conn->compression.dont_reset ? Z_SYNC_FLUSH
                                                           : Z_FULL_FLUSH);
}

static int compression_pending(struct conn_interface *intf)
{
    xmpp_conn_t *conn = intf->conn;
    struct xmpp_compression *comp = conn->compression.state;
    return comp->decompression.stream.next_in != NULL ||
           comp->next.pending(intf);
}

static int compression_get_error(struct conn_interface *intf)
{
    struct conn_interface *next = &intf->conn->compression.state->next;
    return next->get_error(next);
}

static int compression_is_recoverable(struct conn_interface *intf, int err)
{
    struct conn_interface *next = &intf->conn->compression.state->next;
    return next->error_is_recoverable(next, err);
}

static const struct conn_interface compression_intf = {
    compression_read,
    compression_write,
    compression_flush,
    compression_pending,
    compression_get_error,
    compression_is_recoverable,
    NULL,
};

static void *_zlib_alloc(void *opaque, unsigned int items, unsigned int size)
{
    size_t sz = items * size;
    /* Poor man's multiplication overflow check */
    if (sz < items || sz < size)
        return NULL;
    return strophe_alloc(opaque, sz);
}

static void _init_zlib_compression(xmpp_ctx_t *ctx, struct zlib_compression *s)
{
    s->buffer = strophe_alloc(ctx, STROPHE_COMPRESSION_BUFFER_SIZE);
    s->buffer_end = (char *)s->buffer + STROPHE_COMPRESSION_BUFFER_SIZE;

    s->stream.opaque = ctx;
    s->stream.zalloc = _zlib_alloc;
    s->stream.zfree = (free_func)strophe_free;
}

int compression_init(xmpp_conn_t *conn)
{
    if (!conn->compression.allowed || !conn->compression.supported)
        return -1;
    conn->compression.state =
        strophe_alloc(conn->ctx, sizeof(*conn->compression.state));
    struct xmpp_compression *comp = conn->compression.state;
    memset(comp, 0, sizeof(*comp));

    comp->conn = conn;

    comp->next = conn->intf;
    conn->intf = compression_intf;
    conn->intf.conn = conn;

    _init_zlib_compression(conn->ctx, &comp->compression);

    comp->compression.stream.next_out = comp->compression.buffer;
    comp->compression.stream.avail_out = STROPHE_COMPRESSION_BUFFER_SIZE;
    int ret = deflateInit(&comp->compression.stream, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        strophe_free_and_null(conn->ctx, comp->compression.buffer);
        conn->error = ret;
        conn_disconnect(conn);
        return ret;
    }

    _init_zlib_compression(conn->ctx, &comp->decompression);

    ret = inflateInit(&comp->decompression.stream);
    if (ret != Z_OK) {
        strophe_free_and_null(conn->ctx, comp->decompression.buffer);
        conn->error = ret;
        conn_disconnect(conn);
        return ret;
    }
    return 0;
}

void compression_free(xmpp_conn_t *conn)
{
    struct xmpp_compression *comp = conn->compression.state;
    if (!comp)
        return;
    if (comp->compression.buffer) {
        deflateEnd(&comp->compression.stream);
        strophe_free_and_null(conn->ctx, comp->compression.buffer);
    }
    if (comp->decompression.buffer) {
        inflateEnd(&comp->decompression.stream);
        strophe_free_and_null(conn->ctx, comp->decompression.buffer);
    }
}

void compression_handle_feature_children(xmpp_conn_t *conn, const char *text)
{
    if (strcasecmp(text, "zlib") == 0) {
        conn->compression.supported = 1;
    }
}
