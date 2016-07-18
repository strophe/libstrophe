/* conn.c
** strophe XMPP client library -- connection object functions
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  Connection management.
 */

/** @defgroup Connections Connection management
 */

#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include "strophe.h"

#include "common.h"
#include "util.h"
#include "parser.h"
#include "resolver.h"

#ifndef DEFAULT_SEND_QUEUE_MAX
/** @def DEFAULT_SEND_QUEUE_MAX
 *  The default maximum send queue size.  This is currently unused.
 */
#define DEFAULT_SEND_QUEUE_MAX 64
#endif
#ifndef DISCONNECT_TIMEOUT
/** @def DISCONNECT_TIMEOUT 
 *  The time to wait (in milliseconds) for graceful disconnection to
 *  complete before the connection is reset.  The default is 2 seconds.
 */
#define DISCONNECT_TIMEOUT 2000 /* 2 seconds */
#endif
#ifndef CONNECT_TIMEOUT
/** @def CONNECT_TIMEOUT
 *  The time to wait (in milliseconds) for a connection attempt to succeed
 * or error.  The default is 5 seconds.
 */
#define CONNECT_TIMEOUT 5000 /* 5 seconds */
#endif

static int _disconnect_cleanup(xmpp_conn_t * const conn,
                               void * const userdata);

static void _handle_stream_start(char *name, char **attrs,
                                 void * const userdata);
static void _handle_stream_end(char *name,
                               void * const userdata);
static void _handle_stream_stanza(xmpp_stanza_t *stanza,
                                  void * const userdata);
static unsigned short _conn_default_port(xmpp_conn_t * const conn,
                                         xmpp_conn_type_t type);
static void _conn_reset(xmpp_conn_t * const conn);
static int _conn_connect(xmpp_conn_t * const conn,
                         const char * const domain,
                         const char * const host,
                         unsigned short port,
                         xmpp_conn_type_t type,
                         xmpp_conn_handler callback,
                         void * const userdata);

/** Create a new Strophe connection object.
 *
 *  @param ctx a Strophe context object
 *
 *  @return a Strophe connection object or NULL on an error
 *
 *  @ingroup Connections
 */
xmpp_conn_t *xmpp_conn_new(xmpp_ctx_t * const ctx)
{
    xmpp_conn_t *conn = NULL;
    xmpp_connlist_t *tail, *item;

    if (ctx == NULL) return NULL;

    conn = xmpp_alloc(ctx, sizeof(xmpp_conn_t));
    if (conn != NULL) {
        conn->ctx = ctx;

        conn->type = XMPP_UNKNOWN;
        conn->state = XMPP_STATE_DISCONNECTED;
        conn->sock = -1;
        conn->ka_timeout = 0;
        conn->ka_interval = 0;
        conn->tls = NULL;
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
        conn->bound_jid = NULL;

        conn->tls_support = 0;
        conn->tls_disabled = 0;
        conn->tls_mandatory = 0;
        conn->tls_legacy_ssl = 0;
        conn->tls_failed = 0;
        conn->sasl_support = 0;
        conn->secured = 0;

        conn->bind_required = 0;
        conn->session_required = 0;

        conn->parser = parser_new(conn->ctx,
                                  _handle_stream_start,
                                  _handle_stream_end,
                                  _handle_stream_stanza,
                                  conn);
        conn->reset_parser = 0;

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
            parser_free(conn->parser);
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

/** Clone a Strophe connection object.
 *  
 *  @param conn a Strophe connection object
 *
 *  @return the same conn object passed in with its reference count
 *      incremented by 1
 *
 *  @ingroup Connections
 */
xmpp_conn_t *xmpp_conn_clone(xmpp_conn_t * const conn)
{
    conn->ref++;
    return conn;
}

/** Set TCP keepalive parameters
 *  Turn on TCP keepalive and set timeout and interval. Zero timeout
 *  disables TCP keepalives. The parameters are applied immediately for
 *  a non disconnected object. Also, they are applied when the connection
 *  object connects successfully.
 *
 *  @param conn a Strophe connection object
 *  @param timeout TCP keepalive timeout in seconds
 *  @param interval TCP keepalive interval in seconds
 *
 *  @ingroup Connections
 */
void xmpp_conn_set_keepalive(xmpp_conn_t * const conn, int timeout, int interval)
{
    int ret = 0;

    conn->ka_timeout = timeout;
    conn->ka_interval = interval;

    if (conn->state != XMPP_STATE_DISCONNECTED)
        ret = sock_set_keepalive(conn->sock, timeout, interval);

    if (ret < 0) {
        xmpp_error(conn->ctx, "xmpp", "Setting TCP keepalive (%d,%d) error: %d",
                   timeout, interval, sock_error());
    }
}

/** Release a Strophe connection object.
 *  Decrement the reference count by one for a connection, freeing the
 *  connection object if the count reaches 0.
 *
 *  @param conn a Strophe connection object
 *
 *  @return TRUE if the connection object was freed and FALSE otherwise
 *
 *  @ingroup Connections
 */
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

        parser_free(conn->parser);
        _conn_reset(conn);

        if (conn->jid) xmpp_free(ctx, conn->jid);
        if (conn->pass) xmpp_free(ctx, conn->pass);
        if (conn->lang) xmpp_free(ctx, conn->lang);
        xmpp_free(ctx, conn);
        released = 1;
    }

    return released;
}

/** Get the JID which is or will be bound to the connection.
 *  
 *  @param conn a Strophe connection object
 *
 *  @return a string containing the full JID or NULL if it has not been set
 *
 *  @ingroup Connections
 */
const char *xmpp_conn_get_jid(const xmpp_conn_t * const conn)
{
    return conn->jid;
}

/**
 * Get the JID discovered during binding time.
 *
 * This JID will contain the resource used by the current connection.
 * This is useful in the case where a resource was not specified for
 * binding.
 *
 * @param conn a Strophe connection object.
 *
 * @return a string containing the full JID or NULL if it's not been discovered
 *
 * @ingroup Connections
 */
const char *xmpp_conn_get_bound_jid(const xmpp_conn_t * const conn)
{
    return conn->bound_jid;
}

/** Set the JID of the user that will be bound to the connection.
 *  If any JID was previously set, it will be discarded.  This should not be
 *  be used after a connection is created.  The function will make a copy of
 *  the JID string.  If the supplied JID is missing the node, SASL
 *  ANONYMOUS authentication will be used.
 *
 *  @param conn a Strophe connection object
 *  @param jid a full or bare JID
 *
 *  @ingroup Connections
 */
void xmpp_conn_set_jid(xmpp_conn_t * const conn, const char * const jid)
{
    if (conn->jid) xmpp_free(conn->ctx, conn->jid);
    conn->jid = xmpp_strdup(conn->ctx, jid);
}

/** Get the password used for authentication of a connection.
 *
 *  @param conn a Strophe connection object
 *
 *  @return a string containing the password or NULL if it has not been set
 *
 *  @ingroup Connections
 */
const char *xmpp_conn_get_pass(const xmpp_conn_t * const conn)
{
    return conn->pass;
}

/** Set the password used to authenticate the connection.
 *  If any password was previously set, it will be discarded.  The function
 *  will make a copy of the password string.
 * 
 *  @param conn a Strophe connection object
 *  @param pass the password
 *
 *  @ingroup Connections
 */
void xmpp_conn_set_pass(xmpp_conn_t * const conn, const char * const pass)
{
    if (conn->pass) xmpp_free(conn->ctx, conn->pass);
    conn->pass = xmpp_strdup(conn->ctx, pass);
}

/** Get the strophe context that the connection is associated with.
*  @param conn a Strophe connection object
* 
*  @return a Strophe context
* 
*  @ingroup Connections
*/
xmpp_ctx_t* xmpp_conn_get_context(xmpp_conn_t * const conn)
{
        return conn->ctx;
}

/** Initiate a connection to the XMPP server.
 *  This function returns immediately after starting the connection
 *  process to the XMPP server, and notifications of connection state changes
 *  will be sent to the callback function.  The domain and port to connect to
 *  are usually determined by an SRV lookup for the xmpp-client service at
 *  the domain specified in the JID.  If SRV lookup fails, altdomain and 
 *  altport will be used instead if specified.
 *
 *  @param conn a Strophe connection object
 *  @param altdomain a string with domain to use if SRV lookup fails.  If this
 *      is NULL, the domain from the JID will be used.
 *  @param altport an integer port number to use if SRV lookup fails.  If this
 *      is 0, the default port will be assumed.
 *  @param callback a xmpp_conn_handler callback function that will receive
 *      notifications of connection status
 *  @param userdata an opaque data pointer that will be passed to the callback
 *
 *  @return 0 on success and -1 on an error
 *
 *  @ingroup Connections
 */
int xmpp_connect_client(xmpp_conn_t * const conn,
                        const char * const altdomain,
                        unsigned short altport,
                        xmpp_conn_handler callback,
                        void * const userdata)
{
    resolver_srv_rr_t *srv_rr_list = NULL;
    char *domain;
    const char *host;
    unsigned short port;
    int found = XMPP_DOMAIN_NOT_FOUND;
    int rc;

    domain = xmpp_jid_domain(conn->ctx, conn->jid);
    if (!domain) return -1;

    if (altdomain != NULL) {
        xmpp_debug(conn->ctx, "xmpp", "Connecting via altdomain.");
        host = altdomain;
        port = altport ? altport : _conn_default_port(conn, XMPP_CLIENT);
        found = XMPP_DOMAIN_ALTDOMAIN;

    /* SSL tunneled connection on 5223 port is legacy and doesn't
     * have an SRV record. */
    } else if (!conn->tls_legacy_ssl) {
        host = xmpp_alloc(conn->ctx, MAX_DOMAIN_LEN);
        srv_rr_list = xmpp_alloc(conn->ctx, sizeof(resolver_srv_rr_t));
        if (srv_rr_list != NULL) {
            srv_rr_list->next = NULL;
            found = resolver_srv_lookup(conn->ctx, "xmpp-client", "tcp", domain,
                                        &srv_rr_list);

             /* Try DNS-SRV list connection*/
            if (found == XMPP_DOMAIN_FOUND) {
                resolver_srv_rr_t *srv_rr_p = srv_rr_list;
                sock_t sock_try;
                while(srv_rr_p != NULL) {
                    xmpp_debug(conn->ctx, "xmpp", "Try sock_connect %s:%d ",srv_rr_p->target, srv_rr_p->port);
                    sock_try = sock_connect(srv_rr_p->target, srv_rr_p->port);
                    if (sock_try == 0){
                        host = srv_rr_p->target;
                        port = srv_rr_p->port;
                        found = XMPP_DOMAIN_FOUND;
                        break;
                    }
                    srv_rr_p = srv_rr_p->next;
                    found = XMPP_DOMAIN_NOT_FOUND;
                }
            }
        }
    }

    if (XMPP_DOMAIN_NOT_FOUND == found) {
        xmpp_debug(conn->ctx, "xmpp", "SRV lookup failed, "
                                      "connecting via domain.");
        host = domain;
        port = altport ? altport : _conn_default_port(conn, XMPP_CLIENT);
    }

    rc = _conn_connect(conn, domain, host, port, XMPP_CLIENT,
                       callback, userdata);
    xmpp_free(conn->ctx, domain);
    while (srv_rr_list!=NULL) {
        resolver_srv_rr_t *rr_next = srv_rr_list->next;
        xmpp_free(conn->ctx, srv_rr_list);
        srv_rr_list = rr_next;
    }

    return rc;
}

/** Initiate a component connection to server.
 *  This function returns immediately after starting the connection
 *  process to the XMPP server, and notifications of connection state changes
 *  will be sent to the internal callback function that will set up handler
 *  for the component handshake as defined in XEP-0114.
 *  The domain and port to connect to must be provided in this case as the JID
 *  provided to the call serves as component identifier to the server and is
 *  not subject to DNS resolution.
 *
 *  @param conn a Strophe connection object
 *  @param server a string with domain to use directly as the domain can't be
 *      extracted from the component name/JID. If this is not set, the call
 *      will fail.
 *  @param port an integer port number to use to connect to server expecting
 *      an external component.  If this is 0, the port 5347 will be assumed.
 *  @param callback a xmpp_conn_handler callback function that will receive
 *      notifications of connection status
 *  @param userdata an opaque data pointer that will be passed to the callback
 *
 *  @return 0 on success and -1 on an error
 *
 *  @ingroup Connections
 */
int xmpp_connect_component(xmpp_conn_t * const conn, const char * const server,
                           unsigned short port, xmpp_conn_handler callback,
                           void * const userdata)
{
    /*  The server domain, jid and password MUST be specified. */
    if (!(server && conn->jid && conn->pass)) return -1;

    /* XEP-0114 does not support TLS */
    xmpp_conn_disable_tls(conn);
    if (!conn->tls_disabled) {
        xmpp_error(conn->ctx, "conn", "Failed to disable TLS. "
                                      "XEP-0114 does not support TLS");
        return -1;
    }

    port = port ? port : _conn_default_port(conn, XMPP_COMPONENT);
    /* JID serves as an identifier here and will be used as "to" attribute
       of the stream */
    return _conn_connect(conn, conn->jid, server, port, XMPP_COMPONENT,
                         callback, userdata);
}

/** Cleanly disconnect the connection.
 *  This function is only called by the stream parser when </stream:stream>
 *  is received, and it not intended to be called by code outside of Strophe.
 *
 *  @param conn a Strophe connection object
 */
void conn_disconnect_clean(xmpp_conn_t * const conn)
{
    /* remove the timed handler */
    xmpp_timed_handler_delete(conn, _disconnect_cleanup);

    conn_disconnect(conn);
}

/** Disconnect from the XMPP server.
 *  This function immediately disconnects from the XMPP server, and should
 *  not be used outside of the Strophe library.
 *
 *  @param conn a Strophe connection object
 */
void conn_disconnect(xmpp_conn_t * const conn) 
{
    xmpp_debug(conn->ctx, "xmpp", "Closing socket.");
    conn->state = XMPP_STATE_DISCONNECTED;
    if (conn->tls) {
        tls_stop(conn->tls);
        tls_free(conn->tls);
        conn->tls = NULL;
    }
    sock_close(conn->sock);

    /* fire off connection handler */
    conn->conn_handler(conn, XMPP_CONN_DISCONNECT, conn->error,
                       conn->stream_error, conn->userdata);
}

/* prepares a parser reset.  this is called from handlers. we can't
 * reset the parser immediately as it is not re-entrant. */
void conn_prepare_reset(xmpp_conn_t * const conn, xmpp_open_handler handler)
{
    conn->reset_parser = 1;
    conn->open_handler = handler;
}

/* reset the parser */
void conn_parser_reset(xmpp_conn_t * const conn)
{
    conn->reset_parser = 0;
    parser_reset(conn->parser);
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

/** Initiate termination of the connection to the XMPP server.
 *  This function starts the disconnection sequence by sending
 *  </stream:stream> to the XMPP server.  This function will do nothing
 *  if the connection state is CONNECTING or CONNECTED.
 *
 *  @param conn a Strophe connection object
 *
 *  @ingroup Connections
 */
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

/** Send a raw string to the XMPP server.
 *  This function is a convenience function to send raw string data to the
 *  XMPP server.  It is used by Strophe to send short messages instead of
 *  building up an XML stanza with DOM methods.  This should be used with care
 *  as it does not validate the data; invalid data may result in immediate
 *  stream termination by the XMPP server.
 *
 *  @param conn a Strophe connection object
 *  @param fmt a printf-style format string followed by a variable list of
 *      arguments to format
 *
 *  @ingroup Connections
 */
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

/** Send raw bytes to the XMPP server.
 *  This function is a convenience function to send raw bytes to the
 *  XMPP server.  It is used primarily by xmpp_send_raw_string().  This
 *  function should be used with care as it does not validate the bytes and
 *  invalid data may result in stream termination by the XMPP server.
 *
 *  @param conn a Strophe connection object
 *  @param data a buffer of raw bytes
 *  @param len the length of the data in the buffer
 *
 *  @ingroup Connections
 */
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

/** Send an XML stanza to the XMPP server.
 *  This is the main way to send data to the XMPP server.  The function will
 *  terminate without action if the connection state is not CONNECTED.
 *
 *  @param conn a Strophe connection object
 *  @param stanza a Strophe stanza object
 *
 *  @ingroup Connections
 */
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

/** Send the opening &lt;stream:stream&gt; tag to the server.
 *  This function is used by Strophe to begin an XMPP stream.  It should
 *  not be used outside of the library.
 *
 *  @param conn a Strophe connection object
 */
void conn_open_stream(xmpp_conn_t * const conn)
{
    xmpp_send_raw_string(conn, 
                         "<?xml version=\"1.0\"?>"                     \
                         "<stream:stream to=\"%s\" "                   \
                         "xml:lang=\"%s\" "                            \
                         "version=\"1.0\" "                            \
                         "xmlns=\"%s\" "                               \
                         "xmlns:stream=\"%s\">",
                         conn->domain,
                         conn->lang,
                         conn->type == XMPP_CLIENT ? XMPP_NS_CLIENT :
                                                     XMPP_NS_COMPONENT,
                         XMPP_NS_STREAMS);
}

int conn_tls_start(xmpp_conn_t * const conn)
{
    int rc;

    if (conn->tls_disabled) {
        conn->tls = NULL;
        rc = -ENOSYS;
    } else {
        conn->tls = tls_new(conn->ctx, conn->sock);
        rc = conn->tls == NULL ? -ENOMEM : 0;
    }

    if (conn->tls != NULL) {
        if (tls_start(conn->tls)) {
            conn->secured = 1;
            conn_prepare_reset(conn, auth_handle_open);
        } else {
            rc = tls_error(conn->tls);
            conn->error = rc;
            tls_free(conn->tls);
            conn->tls = NULL;
            conn->tls_failed = 1;
        }
    }
    if (rc != 0)
        xmpp_debug(conn->ctx, "conn", "Couldn't start TLS! error %d", rc);

    return rc;
}

/** Return applied flags for the connection.
 *
 *  @param conn a Strophe connection object
 *
 *  @return ORed connection flags that are applied for the connection.
 *
 *  @ingroup Connections
 */
long xmpp_conn_get_flags(const xmpp_conn_t * const conn)
{
    long flags;

    flags = XMPP_CONN_FLAG_DISABLE_TLS * conn->tls_disabled |
            XMPP_CONN_FLAG_MANDATORY_TLS * conn->tls_mandatory |
            XMPP_CONN_FLAG_LEGACY_SSL * conn->tls_legacy_ssl;

    return flags;
}

/** Set flags for the connection.
 *  This function applies set flags and resets unset ones. Default connection
 *  configuration is all flags unset. Flags can be applied only for a connection
 *  in disconnected state.
 *  All unsupported flags are ignored. If a flag is unset after successful set
 *  operation then the flag is not supported by current version.
 *
 *  Supported flags are:
 *
 *    - XMPP_CONN_FLAG_DISABLE_TLS
 *    - XMPP_CONN_FLAG_MANDATORY_TLS
 *    - XMPP_CONN_FLAG_LEGACY_SSL
 *
 *  @param conn a Strophe connection object
 *  @param flags ORed connection flags
 *
 *  @return 0 on success or -1 if flags can't be applied.
 *
 *  @ingroup Connections
 */
int xmpp_conn_set_flags(xmpp_conn_t * const conn, long flags)
{
    if (conn->state != XMPP_STATE_DISCONNECTED) {
        xmpp_error(conn->ctx, "conn", "Flags can be set only "
                                      "for disconnected connection");
        return -1;
    }
    if (flags & XMPP_CONN_FLAG_DISABLE_TLS &&
        flags & (XMPP_CONN_FLAG_MANDATORY_TLS | XMPP_CONN_FLAG_LEGACY_SSL)) {
        xmpp_error(conn->ctx, "conn", "Flags 0x%04lx conflict", flags);
        return -1;
    }

    conn->tls_disabled = (flags & XMPP_CONN_FLAG_DISABLE_TLS) ? 1 : 0;
    conn->tls_mandatory = (flags & XMPP_CONN_FLAG_MANDATORY_TLS) ? 1 : 0;
    conn->tls_legacy_ssl = (flags & XMPP_CONN_FLAG_LEGACY_SSL) ? 1 : 0;

    return 0;
}

/** Disable TLS for this connection, called by users of the library.
 *  Occasionally a server will be misconfigured to send the starttls
 *  feature, but will not support the handshake.
 *
 *  @param conn a Strophe connection object
 *
 *  @note this function is deprecated
 *  @see xmpp_conn_set_flags()
 *
 *  @ingroup Connections
 */
void xmpp_conn_disable_tls(xmpp_conn_t * const conn)
{
    long flags = xmpp_conn_get_flags(conn);

    flags |= XMPP_CONN_FLAG_DISABLE_TLS;
    (void)xmpp_conn_set_flags(conn, flags);
}

/** Return whether TLS session is established or not.
 *
 *  @return TRUE if TLS session is established and FALSE otherwise
 *
 *  @ingroup Connections
 */
int xmpp_conn_is_secured(xmpp_conn_t * const conn)
{
    return conn->secured && !conn->tls_failed && conn->tls != NULL ? 1 : 0;
}

static void _log_open_tag(xmpp_conn_t *conn, char **attrs)
{
    char buf[4096];
    size_t pos;
    int len;
    int i;
    char *attr;

    if (!attrs) return;

    pos = 0;
    len = xmpp_snprintf(buf, 4096, "<stream:stream");
    if (len < 0) return;

    pos += len;
    for (i = 0; attrs[i]; i += 2) {
        attr = parser_attr_name(conn->ctx, attrs[i]);
        len = xmpp_snprintf(&buf[pos], 4096 - pos, " %s='%s'",
                            attr, attrs[i+1]);
        xmpp_free(conn->ctx, attr);
        if (len < 0) return;
        pos += len;
    }

    len = xmpp_snprintf(&buf[pos], 4096 - pos, ">");
    if (len < 0) return;

    xmpp_debug(conn->ctx, "xmpp", "RECV: %s", buf);
}

static char *_get_stream_attribute(char **attrs, char *name)
{
    int i;

    if (!attrs) return NULL;

    for (i = 0; attrs[i]; i += 2)
        if (strcmp(name, attrs[i]) == 0)
            return attrs[i+1];

    return NULL;
}

static void _handle_stream_start(char *name, char **attrs,
                                 void * const userdata)
{
    xmpp_conn_t *conn = (xmpp_conn_t *)userdata;
    char *id;

    if (conn->stream_id) xmpp_free(conn->ctx, conn->stream_id);
    conn->stream_id = NULL;

    if (strcmp(name, "stream") == 0) {
        _log_open_tag(conn, attrs);
        id = _get_stream_attribute(attrs, "id");
        if (id)
            conn->stream_id = xmpp_strdup(conn->ctx, id);

        /* check and log errors */
        if (!id)
            xmpp_error(conn->ctx, "conn", "No id attribute.");
        else if (!conn->stream_id)
            xmpp_error(conn->ctx, "conn", "Memory allocation failed.");
    } else {
        xmpp_error(conn->ctx, "conn", "Server did not open valid stream."
                                      " name = %s.", name);
    }

    if (conn->stream_id) {
        /* call stream open handler */
        conn->open_handler(conn);
    } else {
        conn_disconnect(conn);
    }
}

static void _handle_stream_end(char *name,
                               void * const userdata)
{
    xmpp_conn_t *conn = (xmpp_conn_t *)userdata;

    /* stream is over */
    xmpp_debug(conn->ctx, "xmpp", "RECV: </stream:stream>");
    conn_disconnect_clean(conn);
}

static void _handle_stream_stanza(xmpp_stanza_t *stanza,
                                  void * const userdata)
{
    xmpp_conn_t *conn = (xmpp_conn_t *)userdata;
    char *buf;
    size_t len;

    if (xmpp_stanza_to_text(stanza, &buf, &len) == 0) {
        xmpp_debug(conn->ctx, "xmpp", "RECV: %s", buf);
        xmpp_free(conn->ctx, buf);
    }

    handler_fire_stanza(conn, stanza);
}

static unsigned short _conn_default_port(xmpp_conn_t * const conn,
                                         xmpp_conn_type_t type)
{
    switch (type) {
    case XMPP_CLIENT:
        return conn->tls_legacy_ssl ? XMPP_PORT_CLIENT_LEGACY_SSL :
                                      XMPP_PORT_CLIENT;
    case XMPP_COMPONENT:
        return XMPP_PORT_COMPONENT;
    default:
        return 0;
    };
}

static void _conn_reset(xmpp_conn_t * const conn)
{
    xmpp_ctx_t *ctx = conn->ctx;
    xmpp_send_queue_t *sq, *tsq;

    if (conn->state != XMPP_STATE_DISCONNECTED) {
        xmpp_debug(ctx, "conn", "Can't reset connected object.");
        return;
    }

    /* free queued */
    sq = conn->send_queue_head;
    while (sq) {
        tsq = sq;
        sq = sq->next;
        xmpp_free(ctx, tsq->data);
        xmpp_free(ctx, tsq);
    }

    if (conn->stream_error) {
        xmpp_stanza_release(conn->stream_error->stanza);
        if (conn->stream_error->text)
            xmpp_free(ctx, conn->stream_error->text);
        xmpp_free(ctx, conn->stream_error);
        conn->stream_error = NULL;
    }

    if (conn->domain) xmpp_free(ctx, conn->domain);
    if (conn->bound_jid) xmpp_free(ctx, conn->bound_jid);
    if (conn->stream_id) xmpp_free(ctx, conn->stream_id);
    conn->domain = NULL;
    conn->bound_jid = NULL;
    conn->stream_id = NULL;
    conn->secured = 0;
    conn->tls_failed = 0;
    conn->error = 0;
}

static int _conn_connect(xmpp_conn_t * const conn,
                         const char * const domain,
                         const char * const host,
                         unsigned short port,
                         xmpp_conn_type_t type,
                         xmpp_conn_handler callback,
                         void * const userdata)
{
    if (conn->state != XMPP_STATE_DISCONNECTED) return -1;
    if (type != XMPP_CLIENT && type != XMPP_COMPONENT) return -1;

    _conn_reset(conn);

    conn->type = type;
    conn->domain = xmpp_strdup(conn->ctx, domain);
    if (!conn->domain) return -1;

    conn->sock = sock_connect(host, port);
    xmpp_debug(conn->ctx, "xmpp", "sock_connect() to %s:%u returned %d",
               host, port, conn->sock);
    if (conn->sock == -1) return -1;
    if (conn->ka_timeout || conn->ka_interval)
        sock_set_keepalive(conn->sock, conn->ka_timeout, conn->ka_interval);

    /* setup handler */
    conn->conn_handler = callback;
    conn->userdata = userdata;

    conn_prepare_reset(conn, type == XMPP_CLIENT ? auth_handle_open :
                                                   auth_handle_component_open);

    /* FIXME: it could happen that the connect returns immediately as
     * successful, though this is pretty unlikely.  This would be a little
     * hard to fix, since we'd have to detect and fire off the callback
     * from within the event loop */

    conn->state = XMPP_STATE_CONNECTING;
    conn->timeout_stamp = time_stamp();
    xmpp_debug(conn->ctx, "xmpp", "Attempting to connect to %s", host);

    return 0;
}
