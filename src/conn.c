/* conn.c
** libstrophe XMPP client library -- connection object functions
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

#include "strophe.h"
#include "common.h"
#include "util.h"

#define DEFAULT_SEND_QUEUE_MAX 64
#define DISCONNECT_TIMEOUT 2000 /* 2 seconds */
#define CONNECT_TIMEOUT 5000 /* 5 seconds */

static int _disconnect_cleanup(xmpp_conn_t * const conn, 
			       void * const userdata);


xmpp_conn_t *xmpp_conn_new(xmpp_ctx_t * const ctx)
{
    xmpp_conn_t *conn = NULL;
    xmpp_connlist_t *tail, *item;

    if (ctx == NULL) return NULL;
	conn = xmpp_alloc(ctx, sizeof(xmpp_conn_t));
    
    if (conn != NULL) {
	conn->ctx = ctx;

	conn->type = XMPP_UNKNOWN;
	conn->sock = -1;
	conn->timeout_stamp = 0;
	conn->error = 0;
	conn->stream_error = NULL;

	/* default send parameters */
	conn->blocking_send = 0;
	conn->send_queue_max = DEFAULT_SEND_QUEUE_MAX;
	conn->send_queue_len = 0;
	conn->send_queue_head = NULL;
	conn->send_queue_tail = NULL;

	/* default timeouts */
	conn->connect_timeout = CONNECT_TIMEOUT;

	conn->lang = xmpp_strdup(conn->ctx, "en");
	if (!conn->lang) {
	    xmpp_free(conn->ctx, conn);
	    return NULL;
	}
	conn->domain = NULL;
	conn->jid = NULL;
	conn->pass = NULL;
	conn->stream_id = NULL;

	conn->tls_support = 0;
	conn->sasl_support = 0;

	conn->bind_required = 0;
	conn->session_required = 0;

	conn->parser = NULL;
	conn->stanza = NULL;
	parser_prepare_reset(conn, auth_handle_open);

	conn->authenticated = 0;
	conn->conn_handler = NULL;
	conn->userdata = NULL;
	conn->timed_handlers = NULL;
	/* we own (and will free) the hash values */
	conn->id_handlers = hash_new(conn->ctx, 32, NULL);
	conn->handlers = NULL;

	/* give the caller a reference to connection */
	conn->ref = 1;

	/* add connection to ctx->connlist */
	tail = conn->ctx->connlist;
	while (tail && tail->next) tail = tail->next;

	item = xmpp_alloc(conn->ctx, sizeof(xmpp_connlist_t));
	if (!item) {
	    xmpp_error(conn->ctx, "xmpp", "failed to allocate memory");
	    xmpp_free(conn->ctx, conn->lang);
	    XML_ParserFree(conn->parser);
	    xmpp_free(conn->ctx, conn);
	    conn = NULL;
	} else {
	    item->conn = conn;
	    item->next = NULL;

	    if (tail) tail->next = item;
	    else conn->ctx->connlist = item;
	}
    }
    
    return conn;
}

xmpp_conn_t * xmpp_conn_clone(xmpp_conn_t * const conn)
{
    conn->ref++;
    return conn;
}

int xmpp_conn_release(xmpp_conn_t * const conn)
{
    xmpp_ctx_t *ctx;
    xmpp_connlist_t *item, *prev;
    xmpp_handlist_t *hlitem, *thli;
    hash_iterator_t *iter;
    const char *key;
    int released = 0;

    if (conn->ref > 1) 
	conn->ref--;
    else {
	ctx = conn->ctx;

	/* remove connection from context's connlist */
	if (ctx->connlist->conn == conn) {
	    item = ctx->connlist;
	    ctx->connlist = item->next;
	    xmpp_free(ctx, item);
	} else {
	    prev = NULL;
	    item = ctx->connlist;
	    while (item && item->conn != conn) {
		prev = item;
		item = item->next;
	    }

	    if (!item) {
		xmpp_error(ctx, "xmpp", "Connection not in context's list\n");
	    } else {
		prev->next = item->next;
		xmpp_free(ctx, item);
	    }
	}

	/* free handler stuff
	 * note that userdata is the responsibility of the client
	 * and the handler pointers don't need to be freed since they
	 * are pointers to functions */

	hlitem = conn->timed_handlers;
	while (hlitem) {
	    thli = hlitem;
	    hlitem = hlitem->next;

	    xmpp_free(ctx, thli);
	}

	/* id handlers
	 * we have to traverse the hash table freeing list elements 
	 * then release the hash table */
	iter = hash_iter_new(conn->id_handlers);
	while ((key = hash_iter_next(iter))) {
	    hlitem = (xmpp_handlist_t *)hash_get(conn->id_handlers, key);
	    while (hlitem) {
		thli = hlitem;
		hlitem = hlitem->next;
		xmpp_free(conn->ctx, thli->id);
		xmpp_free(conn->ctx, thli);
	    }
	}
	hash_iter_release(iter);
	hash_release(conn->id_handlers);

	hlitem = conn->handlers;
	while (hlitem) {
	    thli = hlitem;
	    hlitem = hlitem->next;

	    if (thli->ns) xmpp_free(ctx, thli->ns);
	    if (thli->name) xmpp_free(ctx, thli->name);
	    if (thli->type) xmpp_free(ctx, thli->type);
	    xmpp_free(ctx, thli);
	}

	if (conn->stream_error) {
	    xmpp_stanza_release(conn->stream_error->stanza);
	    xmpp_free(ctx, conn->stream_error);
	}

	XML_ParserFree(conn->parser);
	
	if (conn->domain) xmpp_free(ctx, conn->domain);
	if (conn->jid) xmpp_free(ctx, conn->jid);
	if (conn->pass) xmpp_free(ctx, conn->pass);
	if (conn->stream_id) xmpp_free(ctx, conn->stream_id);
	xmpp_free(ctx, conn);
	released = 1;
    }

    return released;
}

const char *xmpp_conn_get_jid(const xmpp_conn_t * const conn)
{
    return conn->jid;
}

/* set the jid of the user or the component name.  in the first case,
 * this can be a full jid, or a bare jid.  in the second case, this will
 * probably be a domain only.
 */
void xmpp_conn_set_jid(xmpp_conn_t * const conn, const char * const jid)
{
    if (conn->jid) xmpp_free(conn->ctx, conn->jid);
    conn->jid = xmpp_strdup(conn->ctx, jid);
}

const char *xmpp_conn_get_pass(const xmpp_conn_t * const conn)
{
    return conn->pass;
}

void xmpp_conn_set_pass(xmpp_conn_t * const conn, const char * const pass)
{
    if (conn->pass) xmpp_free(conn->ctx, conn->pass);
    conn->pass = xmpp_strdup(conn->ctx, pass);
}

int xmpp_connect_client(xmpp_conn_t * const conn, 
			  const char * const domain,
			  xmpp_conn_handler callback,
			  void * const userdata)
{
    conn->type = XMPP_CLIENT;

    if (domain) {
        conn->domain = xmpp_strdup(conn->ctx, domain);
    } else {
        conn->domain = xmpp_jid_domain(conn->ctx, conn->jid);
    }
    if (!conn->domain) return -1;

    /* TODO: look up SRV record for actual host and port */
    conn->sock = sock_connect(conn->domain, 5222);
    if (conn->sock < 0) return -1;

    /* setup handler */
    conn->conn_handler = callback;
    conn->userdata = userdata;

    /* FIXME: it could happen that the connect returns immediately as
     * successful, though this is pretty unlikely.  This would be a little
     * hard to fix, since we'd have to detect and fire off the callback
     * from within the event loop */

    conn->state = XMPP_STATE_CONNECTING;
    conn->timeout_stamp = time_stamp();
    xmpp_debug(conn->ctx, "xmpp", "attempting to connect to %s", conn->domain);

    return 0;
}

/* this function is only called by the end tag handler.  it is
 * the only place where a conn_disconnect would be called during a clean
 * disconnect sequence */
void conn_disconnect_clean(xmpp_conn_t * const conn)
{
    /* remove the timed handler */
    xmpp_timed_handler_delete(conn, _disconnect_cleanup);

    conn_disconnect(conn);
}

void conn_disconnect(xmpp_conn_t * const conn) 
{
    xmpp_debug(conn->ctx, "xmpp", "Closing socket.");
    conn->state = XMPP_STATE_DISCONNECTED;
    sock_close(conn->sock);

    /* fire off connection handler */
    conn->conn_handler(conn, XMPP_CONN_DISCONNECT, conn->error,
		       conn->stream_error, conn->userdata);
}

/* timed handler for cleanup if normal disconnect procedure takes too long */
static int _disconnect_cleanup(xmpp_conn_t * const conn, 
			       void * const userdata)
{
    xmpp_debug(conn->ctx, "xmpp",
	       "disconnection forced by cleanup timeout");

    conn_disconnect(conn);

    return 0;
}

/* terminates the XMPP stream, closing the underlying socket,
 * and calls the conn_handler.  this function returns immediately
 * without calling the handler if the connection is not active */
void xmpp_disconnect(xmpp_conn_t * const conn)
{
    if (conn->state != XMPP_STATE_CONNECTING &&
	conn->state != XMPP_STATE_CONNECTED)
	return;

    /* close the stream */
    xmpp_send_raw_string(conn, "</stream:stream>");

    /* setup timed handler in case disconnect takes too long */
    handler_add_timed(conn, _disconnect_cleanup,
		      DISCONNECT_TIMEOUT, NULL);
}

/* convinience function for sending data to a connection */
void xmpp_send_raw_string(xmpp_conn_t * const conn, 
			  const char * const fmt, ...)
{
    va_list ap;
    size_t len;
    char buf[1024]; /* small buffer for common case */
    char *bigbuf;

    va_start(ap, fmt);
    len = xmpp_vsnprintf(buf, 1024, fmt, ap);
    va_end(ap);

    if (len >= 1024) {
	/* we need more space for this data, so we allocate a big 
	 * enough buffer and print to that */
	len++; /* account for trailing \0 */
	bigbuf = xmpp_alloc(conn->ctx, len);
	if (!bigbuf) {
	    xmpp_debug(conn->ctx, "xmpp", "Could not allocate memory for send_raw_string");
	    return;
	}
	va_start(ap, fmt);
	xmpp_vsnprintf(bigbuf, len, fmt, ap);
	va_end(ap);

	xmpp_debug(conn->ctx, "conn", "SENT: %s", bigbuf);

	/* len - 1 so we don't send trailing \0 */
	xmpp_send_raw(conn, bigbuf, len - 1);

	xmpp_free(conn->ctx, bigbuf);
    } else {
	xmpp_debug(conn->ctx, "conn", "SENT: %s", buf);

	xmpp_send_raw(conn, buf, len);
    }
}

/* adds data to the send queue for a connection */
void xmpp_send_raw(xmpp_conn_t * const conn,
		   const char * const data, const size_t len)
{
    xmpp_send_queue_t *item;

    if (conn->state != XMPP_STATE_CONNECTED) return;

    /* create send queue item for queue */
    item = xmpp_alloc(conn->ctx, sizeof(xmpp_send_queue_t));
    if (!item) return;

    item->data = xmpp_alloc(conn->ctx, len);
    if (!item->data) {
	xmpp_free(conn->ctx, item);
	return;
    }
    memcpy(item->data, data, len);
    item->len = len;
    item->next = NULL;
    item->written = 0;

    /* add item to the send queue */
    if (!conn->send_queue_tail) {
	/* first item, set head and tail */
	conn->send_queue_head = item;
	conn->send_queue_tail = item;
    } else {
	/* add to the tail */
	conn->send_queue_tail->next = item;
	conn->send_queue_tail = item;
    }
    conn->send_queue_len++;
}

void xmpp_send(xmpp_conn_t * const conn,
	       xmpp_stanza_t * const stanza)
{
    char *buf;
    size_t len;
    int ret;

    if (conn->state == XMPP_STATE_CONNECTED) {
	if ((ret = xmpp_stanza_to_text(stanza, &buf, &len)) == 0) {
	    xmpp_send_raw(conn, buf, len);
	    xmpp_debug(conn->ctx, "conn", "SENT: %s", buf);
	    xmpp_free(conn->ctx, buf);
	}
    }
}

void conn_open_stream(xmpp_conn_t * const conn)
{
    xmpp_send_raw_string(conn, 
			 "<?xml version=\"1.0\"?>"			\
			 "<stream:stream to=\"%s\" "			\
			 "xml:lang=\"%s\" "				\
			 "version=\"1.0\" "				\
			 "xmlns=\"%s\" "				\
			 "xmlns:stream=\"%s\">", 
			 conn->domain,
			 conn->lang,
			 conn->type == XMPP_CLIENT ? XMPP_NS_CLIENT : XMPP_NS_COMPONENT,
			 XMPP_NS_STREAMS);
}
