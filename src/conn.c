/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* conn.c
** strophe XMPP client library -- connection object functions
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT or GPLv3 licenses.
*/

/** @file
 *  Connection management.
 */

/** @defgroup Connections Connection management
 *  These functions manage a connection object.
 *
 *  A part of those functions is listed under the \ref TLS section.
 */

#include <errno.h>
#ifndef _MSC_VER
#include <netinet/in.h>
#endif
#include <stdarg.h>
#include <string.h>
#include <limits.h>

#include "strophe.h"

#include "common.h"
#include "util.h"
#include "parser.h"

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
 *  or error.  The default is 5 seconds.
 */
#define CONNECT_TIMEOUT 5000 /* 5 seconds */
#endif

#ifndef KEEPALIVE_TIMEOUT
/** @def KEEPALIVE_TIMEOUT
 *  The time (in seconds) the connection needs to remain idle before TCP starts
 *  sending keepalive probes, if the socket option SO_KEEPALIVE has been set on
 *  this socket.
 *  c.f. `TCP_KEEPIDLE` in `man 7 tcp` for linux, FreeBSD and some others or
 *  `TCP_KEEPALIVE` on MacOS.
 */
#define KEEPALIVE_TIMEOUT 60
#endif
#ifndef KEEPALIVE_INTERVAL
/** @def KEEPALIVE_INTERVAL
 *  The time (in seconds) between individual keepalive probes.
 *  c.f. `TCP_KEEPINTVL` in `man 7 tcp`
 */
#define KEEPALIVE_INTERVAL 30
#endif
#ifndef KEEPALIVE_COUNT
/** @def KEEPALIVE_COUNT
 *  The maximum number of keepalive probes TCP should send before dropping the
 *  connection.
 *  c.f. `TCP_KEEPCNT` in `man 7 tcp`
 */
#define KEEPALIVE_COUNT 3
#endif

static int _is_connected(xmpp_conn_t *conn, xmpp_send_queue_owner_t owner);
static int _disconnect_cleanup(xmpp_conn_t *conn, void *userdata);
static void _reset_sm_state_for_reconnect(xmpp_conn_t *conn);
static char *_conn_build_stream_tag(xmpp_conn_t *conn,
                                    char **attributes,
                                    size_t attributes_len);
static int _conn_open_stream_with_attributes(xmpp_conn_t *conn,
                                             char **attributes,
                                             size_t attributes_len);
static void _conn_attributes_new(xmpp_conn_t *conn,
                                 char **attrs,
                                 char ***attributes,
                                 size_t *attributes_len);
static void _conn_attributes_destroy(xmpp_conn_t *conn,
                                     char **attributes,
                                     size_t attributes_len);
static void _handle_stream_start(char *name, char **attrs, void *userdata);
static void _handle_stream_end(char *name, void *userdata);
static void _handle_stream_stanza(xmpp_stanza_t *stanza, void *userdata);
static void _conn_sm_handle_stanza(xmpp_conn_t *const conn,
                                   xmpp_stanza_t *stanza);
static unsigned short _conn_default_port(xmpp_conn_t *conn,
                                         xmpp_conn_type_t type);
static void _conn_reset(xmpp_conn_t *conn);
static int _conn_connect(xmpp_conn_t *conn,
                         const char *domain,
                         xmpp_conn_type_t type,
                         xmpp_conn_handler callback,
                         void *userdata);
static void _send_valist(xmpp_conn_t *conn,
                         const char *fmt,
                         va_list ap,
                         xmpp_send_queue_owner_t owner);
static int _send_raw(xmpp_conn_t *conn,
                     char *data,
                     size_t len,
                     xmpp_send_queue_owner_t owner,
                     void *userdata);

void xmpp_send_error(xmpp_conn_t *conn, xmpp_error_type_t type, char *text)
{
    xmpp_stanza_t *error = xmpp_error_new(conn->ctx, type, text);

    send_stanza(conn, error, XMPP_QUEUE_STROPHE);
}

/** Create a new Strophe connection object.
 *
 *  @param ctx a Strophe context object
 *
 *  @return a Strophe connection object or NULL on an error
 *
 *  @ingroup Connections
 */
xmpp_conn_t *xmpp_conn_new(xmpp_ctx_t *ctx)
{
    xmpp_conn_t *conn = NULL;
    xmpp_connlist_t *tail, *item;

    if (ctx == NULL)
        return NULL;

    conn = strophe_alloc(ctx, sizeof(xmpp_conn_t));
    if (conn != NULL) {
        memset(conn, 0, sizeof(xmpp_conn_t));
        conn->ctx = ctx;

        conn->type = XMPP_UNKNOWN;
        conn->state = XMPP_STATE_DISCONNECTED;

        conn->sock = INVALID_SOCKET;
        conn->ka_timeout = KEEPALIVE_TIMEOUT;
        conn->ka_interval = KEEPALIVE_INTERVAL;
        conn->ka_count = KEEPALIVE_COUNT;

        /* default send parameters */
        conn->send_queue_max = DEFAULT_SEND_QUEUE_MAX;

        /* default timeouts */
        conn->connect_timeout = CONNECT_TIMEOUT;

        conn->lang = strophe_strdup(conn->ctx, "en");
        if (!conn->lang) {
            strophe_free(conn->ctx, conn);
            return NULL;
        }
        tls_clear_password_cache(conn);
        conn->password_retries = 1;

        conn->parser =
            parser_new(conn->ctx, _handle_stream_start, _handle_stream_end,
                       _handle_stream_stanza, conn);
        /* we own (and will free) the hash values */
        conn->id_handlers = hash_new(conn->ctx, 32, NULL);

        /* give the caller a reference to connection */
        conn->ref = 1;

        /* add connection to ctx->connlist */
        tail = conn->ctx->connlist;
        while (tail && tail->next)
            tail = tail->next;

        item = strophe_alloc(conn->ctx, sizeof(xmpp_connlist_t));
        if (!item) {
            strophe_error(conn->ctx, "xmpp", "failed to allocate memory");
            strophe_free(conn->ctx, conn->lang);
            parser_free(conn->parser);
            strophe_free(conn->ctx, conn);
            conn = NULL;
        } else {
            item->conn = conn;
            item->next = NULL;

            if (tail)
                tail->next = item;
            else
                conn->ctx->connlist = item;
        }
    }

    return conn;
}

/** Clone a Strophe connection object.
 *
 *  @param conn a Strophe connection object
 *
 *  @return the same conn object passed in with its reference count
 *          incremented by 1
 *
 *  @ingroup Connections
 */
xmpp_conn_t *xmpp_conn_clone(xmpp_conn_t *conn)
{
    conn->ref++;
    return conn;
}

/** Register sockopt callback
 *  Set function to be called when a new socket is created to allow setting
 *  socket options before connection is started.
 *
 *  If the connection is already connected, this callback will be called
 *  immediately.
 *
 *  To set options that can only be applied to disconnected sockets, the
 *  callback must be registered before connecting.
 *
 *  @param conn The Strophe connection object this callback is being registered
 * for
 *  @param callback a xmpp_sockopt_callback callback function that will receive
 *      notifications of connection status
 *
 *  @ingroup Connections
 */

void xmpp_conn_set_sockopt_callback(xmpp_conn_t *conn,
                                    xmpp_sockopt_callback callback)
{
    conn->sockopt_cb = callback;
    if (conn->state != XMPP_STATE_DISCONNECTED)
        callback(conn, &conn->sock);
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
int xmpp_conn_release(xmpp_conn_t *conn)
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

        if (conn->state == XMPP_STATE_CONNECTING ||
            conn->state == XMPP_STATE_CONNECTED) {
            conn_disconnect(conn);
        }

        /* remove connection from context's connlist */
        if (ctx->connlist->conn == conn) {
            item = ctx->connlist;
            ctx->connlist = item->next;
            strophe_free(ctx, item);
        } else {
            prev = NULL;
            item = ctx->connlist;
            while (item && item->conn != conn) {
                prev = item;
                item = item->next;
            }

            if (!item) {
                strophe_error(ctx, "xmpp",
                              "Connection not in context's list\n");
            } else {
                prev->next = item->next;
                strophe_free(ctx, item);
            }
        }

        _conn_reset(conn);

        /* free handler stuff
         * note that userdata is the responsibility of the client
         * and the handler pointers don't need to be freed since they
         * are pointers to functions */

        hlitem = conn->timed_handlers;
        while (hlitem) {
            thli = hlitem;
            hlitem = hlitem->next;

            strophe_free(ctx, thli);
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
                strophe_free(conn->ctx, thli->u.id);
                strophe_free(conn->ctx, thli);
            }
        }
        hash_iter_release(iter);
        hash_release(conn->id_handlers);

        hlitem = conn->handlers;
        while (hlitem) {
            thli = hlitem;
            hlitem = hlitem->next;

            if (thli->u.ns)
                strophe_free(ctx, thli->u.ns);
            if (thli->u.name)
                strophe_free(ctx, thli->u.name);
            if (thli->u.type)
                strophe_free(ctx, thli->u.type);
            strophe_free(ctx, thli);
        }

        parser_free(conn->parser);

        if (conn->jid)
            strophe_free(ctx, conn->jid);
        if (conn->pass)
            strophe_free(ctx, conn->pass);
        if (conn->lang)
            strophe_free(ctx, conn->lang);
        if (conn->tls_client_cert)
            strophe_free(ctx, conn->tls_client_cert);
        if (conn->tls_client_key)
            strophe_free(ctx, conn->tls_client_key);
        if (conn->tls_cafile)
            strophe_free(ctx, conn->tls_cafile);
        if (conn->tls_capath)
            strophe_free(ctx, conn->tls_capath);
        if (conn->sm_state)
            xmpp_free_sm_state(conn->sm_state);
        tls_clear_password_cache(conn);
        sock_free(conn->xsock);
        strophe_free(ctx, conn);
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
const char *xmpp_conn_get_jid(const xmpp_conn_t *conn)
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
const char *xmpp_conn_get_bound_jid(const xmpp_conn_t *conn)
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
void xmpp_conn_set_jid(xmpp_conn_t *conn, const char *jid)
{
    if (conn->jid)
        strophe_free(conn->ctx, conn->jid);
    conn->jid = strophe_strdup(conn->ctx, jid);
}

/** Set the Handler function which will be called when the TLS stack can't
 *  verify the CA of the server we're trying to connect to.
 *
 *  @param conn a Strophe connection object
 *  @param hndl certfail Handler function
 *
 *  @ingroup TLS
 */
void xmpp_conn_set_certfail_handler(xmpp_conn_t *const conn,
                                    xmpp_certfail_handler hndl)
{
    conn->certfail_handler = hndl;
}

/** Set the CAfile
 *
 *  @param conn a Strophe connection object
 *  @param path path to a certificate file
 *
 *  @ingroup TLS
 */
void xmpp_conn_set_cafile(xmpp_conn_t *const conn, const char *path)
{
    if (conn->tls_cafile)
        strophe_free(conn->ctx, conn->tls_cafile);
    conn->tls_cafile = strophe_strdup(conn->ctx, path);
}

/** Set the CApath
 *
 *  @param conn a Strophe connection object
 *  @param path path to a folder containing certificates
 *
 *  @ingroup TLS
 */
void xmpp_conn_set_capath(xmpp_conn_t *const conn, const char *path)
{
    if (conn->tls_capath)
        strophe_free(conn->ctx, conn->tls_capath);
    conn->tls_capath = strophe_strdup(conn->ctx, path);
}

/** Retrieve the peer certificate
 *
 *  The returned Certificate object must be free'd by calling
 *  \ref xmpp_tlscert_free
 *
 *  @param conn a Strophe connection object
 *
 *  @return a Strophe Certificate object
 *
 *  @ingroup TLS
 */
xmpp_tlscert_t *xmpp_conn_get_peer_cert(xmpp_conn_t *const conn)
{
    return tls_peer_cert(conn);
}

/** Set the Callback function which will be called when the TLS stack can't
 *  decrypt a password protected key file.
 *
 *  @param conn a   Strophe connection object
 *  @param cb       The callback function that shall be called
 *  @param userdata An opaque data pointer that will be passed to the callback
 *
 *  @ingroup TLS
 */
void xmpp_conn_set_password_callback(xmpp_conn_t *conn,
                                     xmpp_password_callback cb,
                                     void *userdata)
{
    conn->password_callback = cb;
    conn->password_callback_userdata = userdata;
}

/** Set the number of retry attempts to decrypt a private key file.
 *
 *  In case the user enters the password manually it can be useful to
 *  directly retry if the decryption of the key file failed.
 *
 *  @param conn a   Strophe connection object
 *  @param retries  The number of retries that should be tried
 *
 *  @ingroup TLS
 */
void xmpp_conn_set_password_retries(xmpp_conn_t *conn, unsigned int retries)
{
    if (retries == 0)
        conn->password_retries = 1;
    else
        conn->password_retries = retries;
}

/** Retrieve the path of the key file that shall be unlocked.
 *
 *  This makes usually sense to be called from the
 *  \ref xmpp_password_callback .
 *
 *  @param conn a Strophe connection object
 *
 *  @return a String of the path to the key file
 *
 *  @ingroup TLS
 */
const char *xmpp_conn_get_keyfile(const xmpp_conn_t *conn)
{
    return conn->tls_client_key;
}

/** Set the Client Certificate and Private Key or PKCS#12 encoded file that
 *  will be bound to the connection. If any of them was previously set, it
 *  will be discarded. This should not be used after a connection is created.
 *  The function will make a copy of the strings passed in.
 *
 *  In case the Private Key is encrypted, a callback must be set via
 *  \ref xmpp_conn_set_password_callback so the TLS stack can retrieve the
 *  password.
 *
 *  In case one wants to use a PKCS#12 encoded file, it should be passed via
 *  the `cert` parameter and `key` should be NULL. Passing a PKCS#12 file in
 *  `key` is deprecated.
 *
 *  @param conn a Strophe connection object
 *  @param cert path to a certificate file or a P12 file
 *  @param key path to a private key file or a P12 file
 *
 *  @ingroup TLS
 */
void xmpp_conn_set_client_cert(xmpp_conn_t *const conn,
                               const char *const cert,
                               const char *const key)
{
    strophe_debug(conn->ctx, "conn", "set client cert %s %s", cert, key);
    if (conn->tls_client_cert)
        strophe_free(conn->ctx, conn->tls_client_cert);
    conn->tls_client_cert = NULL;
    if (conn->tls_client_key)
        strophe_free(conn->ctx, conn->tls_client_key);
    conn->tls_client_key = NULL;
    if (cert && key) {
        conn->tls_client_cert = strophe_strdup(conn->ctx, cert);
        conn->tls_client_key = strophe_strdup(conn->ctx, key);
    } else if (cert && !key) {
        conn->tls_client_cert = strophe_strdup(conn->ctx, cert);
    } else if (!cert && key) {
        strophe_warn(conn->ctx, "xmpp",
                     "xmpp_conn_set_client_cert: Passing PKCS#12 in 'key' "
                     "parameter is deprecated. Use 'cert' instead");
        conn->tls_client_cert = strophe_strdup(conn->ctx, key);
    }
}

/** Get the number of xmppAddr entries in the client certificate.
 *
 *  @param conn a Strophe connection object
 *
 *  @return the number of xmppAddr entries in the client certificate
 *
 *  @ingroup TLS
 */
unsigned int xmpp_conn_cert_xmppaddr_num(xmpp_conn_t *const conn)
{
    return tls_id_on_xmppaddr_num(conn);
}

/** Get a specific xmppAddr entry.
 *
 *  @param conn a Strophe connection object
 *  @param n the index of the entry, starting at 0
 *
 *  @return a string containing the xmppAddr or NULL if n is out of range
 *
 *  @ingroup TLS
 */
char *xmpp_conn_cert_xmppaddr(xmpp_conn_t *const conn, unsigned int n)
{
    return tls_id_on_xmppaddr(conn, n);
}

/** Get the password used for authentication of a connection.
 *
 *  @param conn a Strophe connection object
 *
 *  @return a string containing the password or NULL if it has not been set
 *
 *  @ingroup Connections
 */
const char *xmpp_conn_get_pass(const xmpp_conn_t *conn)
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
void xmpp_conn_set_pass(xmpp_conn_t *conn, const char *pass)
{
    if (conn->pass)
        strophe_free(conn->ctx, conn->pass);
    conn->pass = pass ? strophe_strdup(conn->ctx, pass) : NULL;
}

/** Get the strophe context that the connection is associated with.
 *  @param conn a Strophe connection object
 *
 *  @return a Strophe context
 *
 *  @ingroup Connections
 */
xmpp_ctx_t *xmpp_conn_get_context(xmpp_conn_t *conn)
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
 *  @return XMPP_EOK (0) on success or a number less than 0 on failure
 *
 *  @ingroup Connections
 */
int xmpp_connect_client(xmpp_conn_t *conn,
                        const char *altdomain,
                        unsigned short altport,
                        xmpp_conn_handler callback,
                        void *userdata)
{
    char *domain;
    int rc;

    if (!conn->jid && (conn->tls_client_cert || conn->tls_client_key)) {
        if (tls_id_on_xmppaddr_num(conn) != 1) {
            strophe_debug(conn->ctx, "xmpp",
                          "Client certificate contains multiple or no xmppAddr "
                          "and no JID was given to be used.");
            return XMPP_EINVOP;
        }
        conn->jid = tls_id_on_xmppaddr(conn, 0);
        if (!conn->jid)
            return XMPP_EMEM;
        strophe_debug(conn->ctx, "xmpp", "Use jid %s from id-on-xmppAddr.",
                      conn->jid);
    }

    if (!conn->jid) {
        strophe_error(conn->ctx, "xmpp", "JID is not set.");
        return XMPP_EINVOP;
    }

    domain = xmpp_jid_domain(conn->ctx, conn->jid);
    if (!domain)
        return XMPP_EMEM;

    if (!conn->sm_state) {
        conn->sm_state = strophe_alloc(conn->ctx, sizeof(*conn->sm_state));
        if (!conn->sm_state)
            goto err_mem;
        memset(conn->sm_state, 0, sizeof(*conn->sm_state));
        conn->sm_state->ctx = conn->ctx;
    }

    if (altdomain != NULL)
        strophe_debug(conn->ctx, "conn", "Connecting via altdomain.");

    if (conn->tls_legacy_ssl && !altdomain) {
        /* SSL tunneled connection on 5223 port is legacy and doesn't
         * have an SRV record. */
        altdomain = domain;
    }
    altport = altport ? altport : _conn_default_port(conn, XMPP_CLIENT);

    if (conn->xsock)
        sock_free(conn->xsock);
    conn->xsock = sock_new(conn, domain, altdomain, altport);
    if (!conn->xsock)
        goto err_mem;

    rc = _conn_connect(conn, domain, XMPP_CLIENT, callback, userdata);
    strophe_free(conn->ctx, domain);

    return rc;

err_mem:
    strophe_free(conn->ctx, domain);
    return XMPP_EMEM;
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
 *  @return XMPP_EOK (0) on success or a number less than 0 on failure
 *
 *  @ingroup Connections
 */
int xmpp_connect_component(xmpp_conn_t *conn,
                           const char *server,
                           unsigned short port,
                           xmpp_conn_handler callback,
                           void *userdata)
{
    /*  The server domain, jid and password MUST be specified. */
    if (!(server && conn->jid && conn->pass))
        return XMPP_EINVOP;

    /* XEP-0114 does not support TLS */
    (void)xmpp_conn_set_flags(conn, xmpp_conn_get_flags(conn) |
                                        XMPP_CONN_FLAG_DISABLE_TLS);
    if (!conn->tls_disabled) {
        strophe_error(conn->ctx, "conn",
                      "Failed to disable TLS. "
                      "XEP-0114 does not support TLS");
        return XMPP_EINT;
    }

    port = port ? port : _conn_default_port(conn, XMPP_COMPONENT);
    if (conn->xsock)
        sock_free(conn->xsock);
    conn->xsock = sock_new(conn, NULL, server, port);
    if (!conn->xsock)
        return XMPP_EMEM;

    /* JID serves as an identifier here and will be used as "to" attribute
       of the stream */
    return _conn_connect(conn, conn->jid, XMPP_COMPONENT, callback, userdata);
}

/** Initiate a raw connection to the XMPP server.
 *  Arguments and behaviour of the function are similar to
 *  xmpp_connect_client(), but it skips authentication process. In opposite to
 *  xmpp_connect_client() during connection process two events are generated
 *  instead of one. User's callback is called with event XMPP_CONN_RAW_CONNECT
 *  when the TCP connection with the server is established. At this point user
 *  might want to open an XMPP stream with xmpp_conn_open_stream() or establish
 *  TLS session with xmpp_conn_tls_start(). Event XMPP_CONN_CONNECT is generated
 *  when the XMPP stream is opened successfully and user may send stanzas over
 *  the connection.
 *
 *  This function doesn't use password nor node part of a jid. Therefore,
 *  the only required configuration is a domain (or full jid) passed via
 *  xmpp_conn_set_jid().
 *
 *  @see xmpp_connect_client()
 *
 *  @return XMPP_EOK (0) on success a number less than 0 on failure
 *
 *  @ingroup Connections
 */
int xmpp_connect_raw(xmpp_conn_t *conn,
                     const char *altdomain,
                     unsigned short altport,
                     xmpp_conn_handler callback,
                     void *userdata)
{
    conn->is_raw = 1;
    return xmpp_connect_client(conn, altdomain, altport, callback, userdata);
}

/* Called when tcp connection is established. */
void conn_established(xmpp_conn_t *conn)
{
    if (conn->tls_legacy_ssl && !conn->is_raw) {
        strophe_debug(conn->ctx, "xmpp", "using legacy SSL connection");
        if (conn_tls_start(conn) != 0) {
            conn_disconnect(conn);
            return;
        }
    }

    if (conn->is_raw) {
        handler_reset_timed(conn, 0);
        /* we skip all the mandatory steps of the stream negotiation for a "raw"
           connection, but the event loop ignores user's handlers when
           conn->stream_negotiation_completed is not set. */
        conn->stream_negotiation_completed = 1;
        conn->conn_handler(conn, XMPP_CONN_RAW_CONNECT, 0, NULL,
                           conn->userdata);
    } else {
        /* send stream init */
        conn_open_stream(conn);
    }
}

/** Send the default opening stream tag.
 *  The default tag is the one sent by xmpp_connect_client().
 *  User's connection handler is called with event XMPP_CONN_CONNECT when
 *  server replies with its opening tag.
 *
 *  @return XMPP_EOK (0) on success a number less than 0 on failure
 *
 *  @note The connection must be connected with xmpp_connect_raw().
 *
 *  @ingroup Connections
 */
int xmpp_conn_open_stream_default(xmpp_conn_t *conn)
{
    if (!conn->is_raw)
        return XMPP_EINVOP;

    conn_prepare_reset(conn, auth_handle_open_raw);
    conn_open_stream(conn);

    return XMPP_EOK;
}

/** Send an opening stream tag.
 *  User's connection handler is called with event XMPP_CONN_CONNECT when
 *  server replies with its opening tag.
 *
 *  @param conn a Strophe connection object
 *  @param attributes Array of strings in format: even index points to
 *      an attribute name and odd index points to its value
 *  @param attributes_len Number of elements in the attributes array, it
 *      should be number of attributes multiplied by 2
 *
 *  @return XMPP_EOK (0) on success a number less than 0 on failure
 *
 *  @note The connection must be connected with xmpp_connect_raw().
 *
 *  @ingroup Connections
 */
int xmpp_conn_open_stream(xmpp_conn_t *conn,
                          char **attributes,
                          size_t attributes_len)
{
    if (!conn->is_raw)
        return XMPP_EINVOP;

    conn_prepare_reset(conn, auth_handle_open_raw);

    return _conn_open_stream_with_attributes(conn, attributes, attributes_len);
}

/** Start synchronous TLS handshake with the server.
 *
 *  @return XMPP_EOK (0) on success a number less than 0 on failure
 *
 *  @ingroup Connections
 */
int xmpp_conn_tls_start(xmpp_conn_t *conn)
{
    return conn_tls_start(conn);
}

/** Cleanly disconnect the connection.
 *  This function is only called by the stream parser when </stream:stream>
 *  is received, and it not intended to be called by code outside of Strophe.
 *
 *  @param conn a Strophe connection object
 */
void conn_disconnect_clean(xmpp_conn_t *conn)
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
void conn_disconnect(xmpp_conn_t *conn)
{
    strophe_debug(conn->ctx, "xmpp", "Closing socket.");
    conn->state = XMPP_STATE_DISCONNECTED;
    conn->stream_negotiation_completed = 0;
    if (conn->tls) {
        tls_stop(conn->tls);
        tls_free(conn->tls);
        conn->tls = NULL;
    }
    if (conn->sock != INVALID_SOCKET)
        sock_close(conn->sock);
    _reset_sm_state_for_reconnect(conn);

    /* fire off connection handler */
    conn->conn_handler(conn, XMPP_CONN_DISCONNECT, conn->error,
                       conn->stream_error, conn->userdata);
}

/* prepares a parser reset.  this is called from handlers. we can't
 * reset the parser immediately as it is not re-entrant. */
void conn_prepare_reset(xmpp_conn_t *conn, xmpp_open_handler handler)
{
    conn->reset_parser = 1;
    conn->open_handler = handler;
}

/* reset the parser */
void conn_parser_reset(xmpp_conn_t *conn)
{
    conn->reset_parser = 0;
    parser_reset(conn->parser);
}

/** Initiate termination of the connection to the XMPP server.
 *  This function starts the disconnection sequence by sending
 *  </stream:stream> to the XMPP server.  This function will do nothing
 *  if the connection state is different from CONNECTING or CONNECTED.
 *
 *  @param conn a Strophe connection object
 *
 *  @ingroup Connections
 */
void xmpp_disconnect(xmpp_conn_t *conn)
{
    if (conn->state != XMPP_STATE_CONNECTING &&
        conn->state != XMPP_STATE_CONNECTED)
        return;

    /* close the stream */
    send_raw_string(conn, "</stream:stream>");

    /* setup timed handler in case disconnect takes too long */
    handler_add_timed(conn, _disconnect_cleanup, DISCONNECT_TIMEOUT, NULL);
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
void xmpp_send_raw_string(xmpp_conn_t *conn, const char *fmt, ...)
{
    va_list ap;

    if (!_is_connected(conn, XMPP_QUEUE_USER))
        return;

    va_start(ap, fmt);
    _send_valist(conn, fmt, ap, XMPP_QUEUE_USER);
    va_end(ap);
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
void xmpp_send_raw(xmpp_conn_t *conn, const char *data, size_t len)
{
    send_raw(conn, data, len, XMPP_QUEUE_USER, NULL);
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
void xmpp_send(xmpp_conn_t *conn, xmpp_stanza_t *stanza)
{
    send_stanza(conn, xmpp_stanza_clone(stanza), XMPP_QUEUE_USER);
}

/** Send the opening &lt;stream:stream&gt; tag to the server.
 *  This function is used by Strophe to begin an XMPP stream.  It should
 *  not be used outside of the library.
 *
 *  @param conn a Strophe connection object
 */
void conn_open_stream(xmpp_conn_t *conn)
{
    size_t attributes_len;
    int rc;
    char *from = NULL;
    char *ns = conn->type == XMPP_CLIENT ? XMPP_NS_CLIENT : XMPP_NS_COMPONENT;
    char *attributes[12] = {
        "to",           conn->domain,    "xml:lang", conn->lang,
        "version",      "1.0",           "xmlns",    ns,
        "xmlns:stream", XMPP_NS_STREAMS, "from",     NULL};

    attributes_len = ARRAY_SIZE(attributes);
    if (conn->tls && conn->jid && strchr(conn->jid, '@') != NULL)
        from = xmpp_jid_bare(conn->ctx, conn->jid);

    if (from)
        attributes[attributes_len - 1] = from;
    else
        attributes_len -= 2;

    rc = _conn_open_stream_with_attributes(conn, attributes, attributes_len);
    if (rc != XMPP_EOK) {
        strophe_error(conn->ctx, "conn",
                      "Cannot build stream tag: memory error");
        conn_disconnect(conn);
    }
    if (from)
        strophe_free(conn->ctx, from);
}

int conn_interface_write(struct conn_interface *intf,
                         const void *buff,
                         size_t len)
{
    int ret = intf->write(intf, buff, len);
    if (ret < 0 && !intf->error_is_recoverable(intf, intf->get_error(intf))) {
        intf->conn->error = intf->get_error(intf);
    }
    return ret;
}

int conn_int_nop(struct conn_interface *intf)
{
    UNUSED(intf);
    return 0;
}

int conn_tls_start(xmpp_conn_t *conn)
{
    int rc;

    if (conn->tls_disabled) {
        conn->tls = NULL;
        rc = XMPP_EINVOP;
    } else {
        conn->tls = tls_new(conn);
        rc = conn->tls == NULL ? XMPP_EMEM : 0;
    }

    if (conn->tls != NULL) {
        struct conn_interface old_intf = conn->intf;
        conn->intf = tls_intf;
        conn->intf.conn = conn;
        if (tls_start(conn->tls)) {
            conn->secured = 1;
        } else {
            rc = XMPP_EINT;
            conn->error = tls_error(&conn->intf);
            tls_free(conn->tls);
            conn->tls = NULL;
            conn->tls_failed = 1;
            conn->intf = old_intf;
        }
    }
    if (rc != 0) {
        strophe_debug(conn->ctx, "conn",
                      "Couldn't start TLS! "
                      "error %d tls_error %d",
                      rc, conn->error);
    }
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
long xmpp_conn_get_flags(const xmpp_conn_t *conn)
{
    long flags;

    flags =
        XMPP_CONN_FLAG_DISABLE_TLS * conn->tls_disabled |
        XMPP_CONN_FLAG_MANDATORY_TLS * conn->tls_mandatory |
        XMPP_CONN_FLAG_LEGACY_SSL * conn->tls_legacy_ssl |
        XMPP_CONN_FLAG_TRUST_TLS * conn->tls_trust |
        XMPP_CONN_FLAG_DISABLE_SM * conn->sm_disable |
        XMPP_CONN_FLAG_ENABLE_COMPRESSION * conn->compression.allowed |
        XMPP_CONN_FLAG_COMPRESSION_DONT_RESET * conn->compression.dont_reset |
        XMPP_CONN_FLAG_LEGACY_AUTH * conn->auth_legacy_enabled;

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
 *    - \ref XMPP_CONN_FLAG_DISABLE_TLS
 *    - \ref XMPP_CONN_FLAG_MANDATORY_TLS
 *    - \ref XMPP_CONN_FLAG_LEGACY_SSL
 *    - \ref XMPP_CONN_FLAG_TRUST_TLS
 *    - \ref XMPP_CONN_FLAG_LEGACY_AUTH
 *    - \ref XMPP_CONN_FLAG_DISABLE_SM
 *    - \ref XMPP_CONN_FLAG_ENABLE_COMPRESSION
 *    - \ref XMPP_CONN_FLAG_COMPRESSION_DONT_RESET
 *
 *  @param conn a Strophe connection object
 *  @param flags ORed connection flags
 *
 *  @return XMPP_EOK (0) on success or a number less than 0 on failure
 *
 *  @ingroup Connections
 */
int xmpp_conn_set_flags(xmpp_conn_t *conn, long flags)
{
    if (conn->state != XMPP_STATE_DISCONNECTED) {
        strophe_error(conn->ctx, "conn",
                      "Flags can be set only "
                      "for disconnected connection");
        return XMPP_EINVOP;
    }
    if ((flags & XMPP_CONN_FLAG_DISABLE_TLS) &&
        (flags & (XMPP_CONN_FLAG_MANDATORY_TLS | XMPP_CONN_FLAG_LEGACY_SSL |
                  XMPP_CONN_FLAG_TRUST_TLS))) {
        strophe_error(conn->ctx, "conn", "Flags 0x%04lx conflict", flags);
        return XMPP_EINVOP;
    }

    conn->tls_disabled = (flags & XMPP_CONN_FLAG_DISABLE_TLS) ? 1 : 0;
    conn->tls_mandatory = (flags & XMPP_CONN_FLAG_MANDATORY_TLS) ? 1 : 0;
    conn->tls_legacy_ssl = (flags & XMPP_CONN_FLAG_LEGACY_SSL) ? 1 : 0;
    conn->tls_trust = (flags & XMPP_CONN_FLAG_TRUST_TLS) ? 1 : 0;
    conn->auth_legacy_enabled = (flags & XMPP_CONN_FLAG_LEGACY_AUTH) ? 1 : 0;
    conn->sm_disable = (flags & XMPP_CONN_FLAG_DISABLE_SM) ? 1 : 0;
    conn->compression.allowed =
        (flags & XMPP_CONN_FLAG_ENABLE_COMPRESSION) ? 1 : 0;
    conn->compression.dont_reset =
        (flags & XMPP_CONN_FLAG_COMPRESSION_DONT_RESET) ? 1 : 0;
    flags &= ~(XMPP_CONN_FLAG_DISABLE_TLS | XMPP_CONN_FLAG_MANDATORY_TLS |
               XMPP_CONN_FLAG_LEGACY_SSL | XMPP_CONN_FLAG_TRUST_TLS |
               XMPP_CONN_FLAG_LEGACY_AUTH | XMPP_CONN_FLAG_DISABLE_SM |
               XMPP_CONN_FLAG_ENABLE_COMPRESSION |
               XMPP_CONN_FLAG_COMPRESSION_DONT_RESET);
    if (flags) {
        strophe_error(conn->ctx, "conn", "Flags 0x%04lx unknown", flags);
        return XMPP_EINVOP;
    }

    return 0;
}

/** Return whether TLS session is established or not.
 *
 *  @return TRUE if TLS session is established and FALSE otherwise
 *
 *  @ingroup Connections
 */
int xmpp_conn_is_secured(xmpp_conn_t *conn)
{
    return conn->secured && !conn->tls_failed && conn->tls != NULL;
}

/**
 *  @return TRUE if connection is in connecting state and FALSE otherwise
 *
 *  @ingroup Connections
 */
int xmpp_conn_is_connecting(xmpp_conn_t *conn)
{
    return conn->state == XMPP_STATE_CONNECTING ||
           (conn->state == XMPP_STATE_CONNECTED &&
            conn->stream_negotiation_completed == 0);
}

static int _is_connected(xmpp_conn_t *conn, xmpp_send_queue_owner_t owner)
{
    return conn->state == XMPP_STATE_CONNECTED &&
           (owner != XMPP_QUEUE_USER ||
            conn->stream_negotiation_completed == 1);
}

/**
 *  @return TRUE if connection is established and FALSE otherwise
 *
 *  @ingroup Connections
 */
int xmpp_conn_is_connected(xmpp_conn_t *conn)
{
    return _is_connected(conn, XMPP_QUEUE_USER);
}

/**
 *  @return TRUE if connection is in disconnected state and FALSE otherwise
 *
 *  @ingroup Connections
 */
int xmpp_conn_is_disconnected(xmpp_conn_t *conn)
{
    return conn->state == XMPP_STATE_DISCONNECTED;
}

/**
 *  This sets the Stream Management callback function
 *
 *  After setting this API, the library will call the given callback function
 *  each time when the internal SM state is updated.
 *
 *  This can be used in conjunction with \ref xmpp_conn_restore_sm_state to
 *  e.g. implement a mechanism that retains an SM state over potential
 *  application terminations.
 *
 *  @param conn   a Strophe connection object
 *  @param cb     a callback function or NULL to disable
 *  @param ctx    a context that will be passed on invocation of the callback
 *                function
 *
 *  @ingroup Connections
 */
void xmpp_conn_set_sm_callback(xmpp_conn_t *conn,
                               xmpp_sm_callback cb,
                               void *ctx)
{
    conn->sm_callback = cb;
    conn->sm_callback_ctx = ctx;
}

struct sm_restore {
    xmpp_conn_t *conn;
    const unsigned char *state;
    const unsigned char *const state_end, *const orig;
};

static int sm_load_u32(struct sm_restore *sm, uint8_t type, uint32_t *val)
{
    if (*sm->state != type) {
        strophe_error(
            sm->conn->ctx, "conn",
            "Invalid CBOR type at position %u: 0x%02x, expected: 0x%02x",
            sm->state - sm->orig, *sm->state, type);
        return XMPP_EINVOP;
    }
    sm->state++;
    if ((sm->state + 4) > sm->state_end) {
        strophe_error(sm->conn->ctx, "conn",
                      "Provided sm_state data is too short");
        return XMPP_EINVOP;
    }
    uint32_t v;
    memcpy(&v, sm->state, 4);
    sm->state += 4;
    *val = ntohl(v);
    return 0;
}

static int sm_load_string(struct sm_restore *sm, char **val, size_t *len)
{
    uint32_t l;
    int ret = sm_load_u32(sm, 0x7a, &l);
    if (ret)
        return ret;
    if ((sm->state + l) > sm->state_end) {
        strophe_error(sm->conn->ctx, "conn",
                      "Provided sm_state data is too short");
        return XMPP_EINVOP;
    }
    *val = strophe_alloc(sm->conn->ctx, l + 1);
    if (!*val)
        return XMPP_EMEM;
    memcpy(*val, sm->state, l);
    (*val)[l] = '\0';
    sm->state += l;
    *len = l;
    return 0;
}

/**
 *  This restores the serialized Stream Management state
 *
 *  After setting this API, the library will call the given callback function
 *  each time when the internal SM state is updated.
 *
 *  This can be used in conjunction with \ref xmpp_conn_restore_sm_state to
 *  e.g. implement a mechanism that retains an SM state over potential
 *  application terminations.
 *
 *  @param conn            a Strophe connection object
 *  @param sm_state        a buffer as passed to the SM callback
 *  @param sm_state_len    the length of `sm_state`
 *
 *  @ingroup Connections
 */
int xmpp_conn_restore_sm_state(xmpp_conn_t *conn,
                               const unsigned char *sm_state,
                               size_t sm_state_len)
{
    /* We can only set the SM state when we're disconnected */
    if (conn->state != XMPP_STATE_DISCONNECTED) {
        strophe_error(conn->ctx, "conn",
                      "SM state can only be set the when we're disconnected");
        return XMPP_EINVOP;
    }

    if (conn->sm_state) {
        strophe_error(conn->ctx, "conn", "SM state is already set!");
        return XMPP_EINVOP;
    }

    if (sm_state_len < 5 * 6) {
        strophe_error(conn->ctx, "conn", "Provided sm_state data is too short");
        return XMPP_EINVOP;
    }
    struct sm_restore sm = {.conn = conn,
                            .state = sm_state,
                            .state_end = sm_state + sm_state_len,
                            .orig = sm_state};
    /* Check for pointer wrap-around, which should never happen */
    if (sm.state_end < sm.state) {
        strophe_error(conn->ctx, "conn",
                      "Internal error, pointer wrapped around");
        return XMPP_EINVOP;
    }

    if (memcmp(sm.state, "\x1a\x00\x00\x00\x00", 5) != 0) {
        strophe_error(conn->ctx, "conn", "Unknown sm_state version");
        return XMPP_EINVOP;
    }
    sm.state += 5;

    conn->sm_state = strophe_alloc(conn->ctx, sizeof(*conn->sm_state));
    if (!conn->sm_state)
        return XMPP_EMEM;

    memset(conn->sm_state, 0, sizeof(*conn->sm_state));
    conn->sm_state->ctx = conn->ctx;

    conn->sm_state->sm_support = 1;
    conn->sm_state->sm_enabled = 1;
    conn->sm_state->can_resume = 1;
    conn->sm_state->resume = 1;

    int ret;
    ret = sm_load_u32(&sm, 0x1a, &conn->sm_state->sm_sent_nr);
    if (ret)
        goto err_reload;

    ret = sm_load_u32(&sm, 0x1a, &conn->sm_state->sm_handled_nr);
    if (ret)
        goto err_reload;

    size_t id_len;
    ret = sm_load_string(&sm, &conn->sm_state->id, &id_len);
    if (ret)
        goto err_reload;

    uint32_t len, i;
    ret = sm_load_u32(&sm, 0x9a, &len);
    if (ret)
        goto err_reload;
    conn->send_queue_user_len = conn->send_queue_len = len;
    for (i = 0; i < len; i++) {
        xmpp_send_queue_t *item = strophe_alloc(conn->ctx, sizeof(*item));
        if (!item) {
            ret = XMPP_EMEM;
            goto err_reload;
        }
        memset(item, 0, sizeof(*item));

        if (!conn->send_queue_tail) {
            conn->send_queue_head = item;
            conn->send_queue_tail = item;
        } else {
            conn->send_queue_tail->next = item;
            conn->send_queue_tail = item;
        }

        ret = sm_load_string(&sm, &item->data, &item->len);
        if (ret)
            goto err_reload;

        item->owner = XMPP_QUEUE_USER;
    }

    ret = sm_load_u32(&sm, 0xba, &len);
    if (ret)
        goto err_reload;
    for (i = 0; i < len; i++) {
        xmpp_send_queue_t *item = strophe_alloc(conn->ctx, sizeof(*item));
        if (!item) {
            ret = XMPP_EMEM;
            goto err_reload;
        }
        memset(item, 0, sizeof(*item));

        add_queue_back(&conn->sm_state->sm_queue, item);

        ret = sm_load_u32(&sm, 0x1a, &item->sm_h);
        if (ret)
            goto err_reload;
        ret = sm_load_string(&sm, &item->data, &item->len);
        if (ret)
            goto err_reload;

        item->owner = XMPP_QUEUE_USER;
    }

    return XMPP_EOK;

err_reload:
    xmpp_free_sm_state(conn->sm_state);
    return ret;
}

static int sm_store_u32(unsigned char **next_,
                        const unsigned char *const end,
                        uint8_t type,
                        uint32_t val)
{
    unsigned char *next = *next_;
    if (next + 5 > end)
        return 1;
    *next++ = type;
    uint32_t v = htonl(val);
    memcpy(next, &v, 4);
    next += 4;
    *next_ = next;
    return 0;
}

static size_t sm_state_serialize(xmpp_conn_t *conn, unsigned char **buf)
{
    if (!conn->sm_state->sm_support || !conn->sm_state->sm_enabled ||
        !conn->sm_state->can_resume) {
        *buf = NULL;
        return 0;
    }

    uint32_t id_len = strlen(conn->sm_state->id);
    xmpp_send_queue_t *peek = conn->sm_state->sm_queue.head;
    size_t sm_queue_len = 0;
    size_t sm_queue_size = 0;
    while (peek) {
        sm_queue_len++;
        sm_queue_size += 10 + peek->len;
        peek = peek->next;
    }

    uint32_t send_queue_len = 0;
    size_t send_queue_size = 0;
    peek = conn->send_queue_head;
    while (peek) {
        send_queue_len++;
        send_queue_size += 5 + peek->len;
        peek = peek->next;
    }

    size_t buf_size =
        5 + 5 + 5 + 5 + id_len + 5 + send_queue_size + 5 + sm_queue_size;
    *buf = strophe_alloc(conn->ctx, buf_size);
    if (*buf == NULL)
        return 0;
    unsigned char *next = *buf;
    const unsigned char *const end = next + buf_size;
    /* Check for pointer wrap-around, which should never happen */
    if (end < next) {
        strophe_error(conn->ctx, "conn",
                      "Internal error, pointer wrapped around");
        return 0;
    }

    memcpy(next, "\x1a\x00\x00\x00\x00", 5); // Version
    next += 5;

    if (sm_store_u32(&next, end, 0x1a, conn->sm_state->sm_sent_nr))
        goto err_serialize;
    if (sm_store_u32(&next, end, 0x1a, conn->sm_state->sm_handled_nr))
        goto err_serialize;

    if (sm_store_u32(&next, end, 0x7a, id_len))
        goto err_serialize;
    memcpy(next, conn->sm_state->id, id_len);
    next += id_len;

    if (sm_store_u32(&next, end, 0x9a, send_queue_len))
        goto err_serialize;

    peek = conn->send_queue_head;
    while (peek) {
        if (sm_store_u32(&next, end, 0x7a, (uint32_t)peek->len))
            goto err_serialize;
        if (next + peek->len > end)
            goto err_serialize;
        memcpy(next, peek->data, peek->len);
        next += peek->len;
        peek = peek->next;
    }

    if (sm_store_u32(&next, end, 0xba, sm_queue_len))
        goto err_serialize;

    peek = conn->sm_state->sm_queue.head;
    while (peek) {
        if (sm_store_u32(&next, end, 0x1a, peek->sm_h))
            goto err_serialize;

        if (sm_store_u32(&next, end, 0x7a, (uint32_t)peek->len))
            goto err_serialize;
        if (next + peek->len > end)
            goto err_serialize;
        memcpy(next, peek->data, peek->len);
        next += peek->len;
        peek = peek->next;
    }

    return buf_size;

err_serialize:
    strophe_error(conn->ctx, "conn", "Can't serialize more data, buffer full");
    strophe_free(conn->ctx, buf);
    return 0;
}

void trigger_sm_callback(xmpp_conn_t *conn)
{
    if (!conn || !conn->sm_callback)
        return;

    unsigned char *buf;
    size_t size = sm_state_serialize(conn, &buf);
    conn->sm_callback(conn, conn->sm_callback_ctx, buf, size);
    strophe_free(conn->ctx, buf);
}

static void _reset_sm_state_for_reconnect(xmpp_conn_t *conn)
{
    xmpp_sm_state_t *s = conn->sm_state;

    if (s->previd) {
        strophe_free(conn->ctx, s->previd);
        s->previd = NULL;
    }

    if (s->can_resume) {
        s->previd = s->id;
        s->id = NULL;

        s->bound_jid = conn->bound_jid;
        conn->bound_jid = NULL;
    } else if (s->id) {
        strophe_free(conn->ctx, s->id);
        s->id = NULL;
    }

    s->r_sent = s->sm_enabled = s->sm_support = s->resume = 0;

    if (s->bind) {
        xmpp_stanza_release(s->bind);
        s->bind = NULL;
    }
}

/**
 *  This returns the Stream Management state of a connection object after
 *  it has been disconnected.
 *  One can then initialise a fresh connection object and set this Stream
 *  Management state by calling \ref xmpp_conn_set_sm_state
 *
 *  In case one wants to dispose of the state w/o setting it into a fresh
 *  connection object, one can call \ref xmpp_free_sm_state
 *
 *  After calling this function to retrieve the state, only call one of the
 *  other two.
 *
 *  @param conn   a Strophe connection object
 *  @return The Stream Management state of the connection or NULL on error
 *
 *  @ingroup Connections
 */
xmpp_sm_state_t *xmpp_conn_get_sm_state(xmpp_conn_t *conn)
{
    xmpp_sm_state_t *ret;

    /* We can only return the SM state when we're disconnected */
    if (conn->state != XMPP_STATE_DISCONNECTED)
        return NULL;

    ret = conn->sm_state;
    conn->sm_state = NULL;

    return ret;
}

/**
 *  @param conn     a Strophe connection object
 *  @param sm_state A Stream Management state returned from a call to
 *                  `xmpp_conn_get_sm_state()`
 *
 *  @return XMPP_EOK (0) on success or a number less than 0 on failure
 *
 *  @ingroup Connections
 */
int xmpp_conn_set_sm_state(xmpp_conn_t *conn, xmpp_sm_state_t *sm_state)
{
    /* We can only set the SM state when we're disconnected */
    if (conn->state != XMPP_STATE_DISCONNECTED) {
        strophe_error(conn->ctx, "conn",
                      "SM state can only be set the when we're disconnected");
        return XMPP_EINVOP;
    }

    if (conn->sm_state) {
        strophe_error(conn->ctx, "conn", "SM state is already set!");
        return XMPP_EINVOP;
    }

    if (conn->ctx != sm_state->ctx) {
        strophe_error(
            conn->ctx, "conn",
            "SM state has to be assigned to connection that stems from "
            "the same context!");
        return XMPP_EINVOP;
    }

    conn->sm_state = sm_state;
    return XMPP_EOK;
}

void reset_sm_state(xmpp_sm_state_t *sm_state)
{
    xmpp_ctx_t *ctx = sm_state->ctx;

    strophe_free_and_null(ctx, sm_state->id);
    strophe_free_and_null(ctx, sm_state->previd);
    strophe_free_and_null(ctx, sm_state->bound_jid);
    if (sm_state->bind)
        xmpp_stanza_release(sm_state->bind);
    sm_state->bind = NULL;
    sm_state->sm_handled_nr = 0;
    sm_state->sm_sent_nr = 0;
    sm_state->r_sent = 0;
}

/**  c.f. \ref xmpp_conn_get_sm_state for usage documentation
 *
 *  @param sm_state   A Stream Management state returned from a call to
 *                  `xmpp_conn_get_sm_state()`
 *
 *  @ingroup Connections
 */
void xmpp_free_sm_state(xmpp_sm_state_t *sm_state)
{
    xmpp_send_queue_t *smq;
    xmpp_ctx_t *ctx;

    if (!sm_state || !sm_state->ctx)
        return;

    ctx = sm_state->ctx;

    while ((smq = pop_queue_front(&sm_state->sm_queue))) {
        strophe_free(ctx, queue_element_free(ctx, smq));
    }

    reset_sm_state(sm_state);
    strophe_free(ctx, sm_state);
}

/**
 *  @return The number of entries in the send queue
 *
 *  @ingroup Connections
 */
int xmpp_conn_send_queue_len(const xmpp_conn_t *conn)
{
    if (conn->send_queue_head && conn->send_queue_head->wip &&
        conn->send_queue_head->owner == XMPP_QUEUE_USER)
        return conn->send_queue_user_len - 1;
    else
        return conn->send_queue_user_len;
}

static char *_drop_send_queue_element(xmpp_conn_t *conn, xmpp_send_queue_t *e)
{
    if (e == conn->send_queue_head)
        conn->send_queue_head = e->next;
    if (e == conn->send_queue_tail)
        conn->send_queue_tail = e->prev;
    if (!conn->send_queue_head)
        conn->send_queue_tail = NULL;
    if (e->prev)
        e->prev->next = e->next;
    if (e->next)
        e->next->prev = e->prev;
    conn->send_queue_len--;
    if (e->owner == XMPP_QUEUE_USER)
        conn->send_queue_user_len--;
    return queue_element_free(conn->ctx, e);
}

/** Drop an element of the send queue.
 *  This can be used to manage the send queue in case a server
 *  isn't fast enough in processing the elements you're trying
 *  to send or your outgoing bandwidth isn't fast enough to transfer
 *  everything you want to send out.
 *
 *  @param conn a Strophe connection object
 *  @param which the element that shall be removed
 *
 *  @return The rendered stanza. The pointer returned has to be free'd by the
 *          caller of this function.
 *
 *  @ingroup Connections
 */
char *xmpp_conn_send_queue_drop_element(xmpp_conn_t *conn,
                                        xmpp_queue_element_t which)
{
    xmpp_send_queue_t *t;
    int disconnected = conn->state == XMPP_STATE_DISCONNECTED;

    /* Fast return paths */
    /* empty queue */
    if (!conn->send_queue_head)
        return NULL;
    /* one element in queue */
    if (conn->send_queue_head == conn->send_queue_tail) {
        /* head is already sent out partially */
        if (conn->send_queue_head->wip && !disconnected)
            return NULL;
        /* the element is no USER element */
        if (conn->send_queue_head->owner != XMPP_QUEUE_USER)
            return NULL;
    }

    /* Regular flow */
    if (which == XMPP_QUEUE_OLDEST) {
        t = conn->send_queue_head;
    } else if (which == XMPP_QUEUE_YOUNGEST) {
        t = conn->send_queue_tail;
        /* search backwards to find last USER element */
        while (t && t->owner != XMPP_QUEUE_USER)
            t = t->prev;
    } else {
        strophe_error(conn->ctx, "conn", "Unknown queue element %d", which);
        return NULL;
    }
    /* there was no USER element in the queue */
    if (!t)
        return NULL;

    /* head is already sent out partially */
    if (t == conn->send_queue_head && t->wip && !disconnected)
        t = t->next;

    /* search forward to find the first USER element */
    while (t && t->owner != XMPP_QUEUE_USER)
        t = t->next;

    /* there was no USER element in the queue we could drop */
    if (!t)
        return NULL;

    /* In case there exists a SM stanza that is linked to the
     * one we're currently dropping, also delete that one.
     */
    if (t->next && t->next->userdata == t) {
        strophe_free(conn->ctx, _drop_send_queue_element(conn, t->next));
        /* reset the flag, so we restart to send `<r>` stanzas */
        conn->sm_state->r_sent = 0;
    }
    /* Finally drop the element */
    char *r = _drop_send_queue_element(conn, t);
    trigger_sm_callback(conn);
    return r;
}

/* timed handler for cleanup if normal disconnect procedure takes too long */
static int _disconnect_cleanup(xmpp_conn_t *conn, void *userdata)
{
    UNUSED(userdata);

    strophe_debug(conn->ctx, "xmpp", "disconnection forced by cleanup timeout");

    conn_disconnect(conn);

    return 0;
}

static char *_conn_build_stream_tag(xmpp_conn_t *conn,
                                    char **attributes,
                                    size_t attributes_len)
{
    char *tag;
    size_t len;
    size_t i;

    static const char *tag_head = "<stream:stream";
    static const char *tag_tail = ">";

    /* ignore the last element unless number is even */
    attributes_len &= ~(size_t)1;

    len = strlen(tag_head) + strlen(tag_tail);
    for (i = 0; i < attributes_len; ++i)
        len += strlen(attributes[i]) + 2;
    tag = strophe_alloc(conn->ctx, len + 1);
    if (!tag)
        return NULL;

    strcpy(tag, tag_head);
    for (i = 0; i < attributes_len; ++i) {
        if ((i & 1) == 0) {
            strcat(tag, " ");
            strcat(tag, attributes[i]);
            strcat(tag, "=\"");
        } else {
            strcat(tag, attributes[i]);
            strcat(tag, "\"");
        }
    }
    strcat(tag, tag_tail);

    if (strlen(tag) != len) {
        strophe_error(conn->ctx, "xmpp",
                      "Internal error in "
                      "_conn_build_stream_tag().");
        strophe_free(conn->ctx, tag);
        tag = NULL;
    }

    return tag;
}

static int _conn_open_stream_with_attributes(xmpp_conn_t *conn,
                                             char **attributes,
                                             size_t attributes_len)
{
    char *tag;

    tag = _conn_build_stream_tag(conn, attributes, attributes_len);
    if (!tag)
        return XMPP_EMEM;

    send_raw_string(conn, "<?xml version=\"1.0\"?>%s", tag);
    strophe_free(conn->ctx, tag);

    return XMPP_EOK;
}

static void _conn_attributes_new(xmpp_conn_t *conn,
                                 char **attrs,
                                 char ***attributes,
                                 size_t *attributes_len)
{
    char **array = NULL;
    size_t nr = 0;
    size_t i;

    if (attrs) {
        for (; attrs[nr]; ++nr)
            ;
        array = strophe_alloc(conn->ctx, sizeof(*array) * nr);
        for (i = 0; array && i < nr; ++i) {
            array[i] = (i & 1) == 0 ? parser_attr_name(conn->ctx, attrs[i])
                                    : strophe_strdup(conn->ctx, attrs[i]);
            if (array[i] == NULL)
                break;
        }
        if (!array || i < nr) {
            strophe_error(conn->ctx, "xmpp", "Memory allocation error.");
            _conn_attributes_destroy(conn, array, i);
            array = NULL;
            nr = 0;
        }
    }
    *attributes = array;
    *attributes_len = nr;
}

static void _conn_attributes_destroy(xmpp_conn_t *conn,
                                     char **attributes,
                                     size_t attributes_len)
{
    size_t i;

    if (attributes) {
        for (i = 0; i < attributes_len; ++i)
            strophe_free(conn->ctx, attributes[i]);
        strophe_free(conn->ctx, attributes);
    }
}

static void _log_open_tag(xmpp_conn_t *conn, char **attrs)
{
    char **attributes;
    char *tag;
    size_t nr;

    _conn_attributes_new(conn, attrs, &attributes, &nr);
    tag = _conn_build_stream_tag(conn, attributes, nr);
    if (tag) {
        strophe_debug(conn->ctx, "xmpp", "RECV: %s", tag);
        strophe_free(conn->ctx, tag);
    }
    _conn_attributes_destroy(conn, attributes, nr);
}

static char *_get_stream_attribute(char **attrs, char *name)
{
    int i;

    if (!attrs)
        return NULL;

    for (i = 0; attrs[i]; i += 2)
        if (strcmp(name, attrs[i]) == 0)
            return attrs[i + 1];

    return NULL;
}

static void _handle_stream_start(char *name, char **attrs, void *userdata)
{
    xmpp_conn_t *conn = (xmpp_conn_t *)userdata;
    char *id;
    int failed = 0;

    if (conn->stream_id)
        strophe_free(conn->ctx, conn->stream_id);
    conn->stream_id = NULL;

    if (strcmp(name, "stream") == 0) {
        _log_open_tag(conn, attrs);
        id = _get_stream_attribute(attrs, "id");
        if (id)
            conn->stream_id = strophe_strdup(conn->ctx, id);

        if (id && !conn->stream_id) {
            strophe_error(conn->ctx, "conn", "Memory allocation failed.");
            failed = 1;
        }
    } else {
        strophe_error(conn->ctx, "conn",
                      "Server did not open valid stream."
                      " name = %s.",
                      name);
        failed = 1;
    }

    if (!failed) {
        /* call stream open handler */
        conn->open_handler(conn);
    } else {
        conn_disconnect(conn);
    }
}

static void _handle_stream_end(char *name, void *userdata)
{
    xmpp_conn_t *conn = (xmpp_conn_t *)userdata;

    UNUSED(name);

    /* stream is over */
    strophe_debug(conn->ctx, "xmpp", "RECV: </stream:stream>");
    /* the session has been terminated properly, i.e. it can't be resumed */
    conn->sm_state->can_resume = 0;
    trigger_sm_callback(conn);
    conn_disconnect_clean(conn);
}

static void _handle_stream_stanza(xmpp_stanza_t *stanza, void *userdata)
{
    xmpp_conn_t *conn = (xmpp_conn_t *)userdata;
    char *buf;
    size_t len;

    if (xmpp_stanza_to_text(stanza, &buf, &len) == 0) {
        strophe_debug(conn->ctx, "xmpp", "RECV: %s", buf);
        strophe_free(conn->ctx, buf);
    }

    handler_fire_stanza(conn, stanza);
    if (conn->sm_state->sm_enabled)
        _conn_sm_handle_stanza(conn, stanza);
}

/* XEP-0198 stream management */
static void _conn_sm_handle_stanza(xmpp_conn_t *const conn,
                                   xmpp_stanza_t *stanza)
{
    xmpp_stanza_t *a;
    xmpp_send_queue_t *e;
    char *c;
    const char *name, *ns, *attr_h;
    char h[11];
    unsigned long ul_h;

    ns = xmpp_stanza_get_ns(stanza);
    if (ns && strcmp(ns, XMPP_NS_SM) != 0)
        ++conn->sm_state->sm_handled_nr;
    else {
        name = xmpp_stanza_get_name(stanza);
        if (!name)
            return;
        if (strcmp(name, "r") == 0) {
            a = xmpp_stanza_new(conn->ctx);
            if (!a) {
                strophe_debug(conn->ctx, "conn", "Couldn't create <a> stanza.");
                return;
            }
            xmpp_stanza_set_name(a, "a");
            xmpp_stanza_set_ns(a, XMPP_NS_SM);
            strophe_snprintf(h, sizeof(h), "%u", conn->sm_state->sm_handled_nr);
            xmpp_stanza_set_attribute(a, "h", h);
            send_stanza(conn, a, XMPP_QUEUE_SM_STROPHE);
        } else if (strcmp(name, "a") == 0) {
            attr_h = xmpp_stanza_get_attribute(stanza, "h");
            if (!attr_h) {
                strophe_debug(conn->ctx, "conn", "Didn't find 'h' attribute.");
                return;
            }
            if (string_to_ul(attr_h, &ul_h)) {
                strophe_error(
                    conn->ctx, "conn",
                    "Error on strtoul() of '%s', returned value is %llu.",
                    attr_h, ul_h);
                /* We continue here and drop the complete SM queue instead of
                 * returning and letting the queue fill up.
                 */
                ul_h = ULONG_MAX;
            }
            while (conn->sm_state->sm_queue.head &&
                   conn->sm_state->sm_queue.head->sm_h < ul_h) {
                e = pop_queue_front(&conn->sm_state->sm_queue);
                strophe_debug_verbose(2, conn->ctx, "conn",
                                      "SM_Q_DROP: %p, h=%lu", e, e->sm_h);
                c = queue_element_free(conn->ctx, e);
                strophe_free(conn->ctx, c);
            }
            conn->sm_state->r_sent = 0;
        }
    }
    trigger_sm_callback(conn);
}

static unsigned short _conn_default_port(xmpp_conn_t *conn,
                                         xmpp_conn_type_t type)
{
    switch (type) {
    case XMPP_CLIENT:
        return conn->tls_legacy_ssl ? XMPP_PORT_CLIENT_LEGACY_SSL
                                    : XMPP_PORT_CLIENT;
    case XMPP_COMPONENT:
        return XMPP_PORT_COMPONENT;
    default:
        return 0;
    };
}

char *queue_element_free(xmpp_ctx_t *ctx, xmpp_send_queue_t *e)
{
    char *ret = e->data;
    strophe_debug_verbose(2, ctx, "conn", "Q_FREE: %p", e);
    memset(e, 0, sizeof(*e));
    strophe_free(ctx, e);
    strophe_debug_verbose(3, ctx, "conn", "Q_CONTENT: %s", ret);
    return ret;
}

static void _conn_reset(xmpp_conn_t *conn)
{
    xmpp_ctx_t *ctx = conn->ctx;
    xmpp_send_queue_t *sq, *tsq;

    if (conn->state != XMPP_STATE_DISCONNECTED) {
        strophe_debug(ctx, "conn", "Can't reset connected object.");
        return;
    }

    compression_free(conn);

    conn->intf = sock_intf;
    conn->intf.conn = conn;

    /* free queued */
    sq = conn->send_queue_head;
    while (sq) {
        tsq = sq;
        sq = sq->next;
        strophe_free(ctx, queue_element_free(ctx, tsq));
    }
    conn->send_queue_head = NULL;
    conn->send_queue_tail = NULL;
    conn->send_queue_len = 0;
    conn->send_queue_user_len = 0;

    if (conn->stream_error) {
        xmpp_stanza_release(conn->stream_error->stanza);
        strophe_free_and_null(ctx, conn->stream_error->text);
        strophe_free_and_null(ctx, conn->stream_error);
    }

    strophe_free_and_null(ctx, conn->domain);
    strophe_free_and_null(ctx, conn->bound_jid);
    strophe_free_and_null(ctx, conn->stream_id);
    conn->stream_negotiation_completed = 0;
    conn->secured = 0;
    conn->tls_failed = 0;
    conn->error = 0;

    conn->tls_support = 0;

    conn->bind_required = 0;
    conn->session_required = 0;

    handler_system_delete_all(conn);
}

static int _conn_connect(xmpp_conn_t *conn,
                         const char *domain,
                         xmpp_conn_type_t type,
                         xmpp_conn_handler callback,
                         void *userdata)
{
    xmpp_open_handler open_handler;

    if (conn->state != XMPP_STATE_DISCONNECTED)
        return XMPP_EINVOP;
    if (type != XMPP_CLIENT && type != XMPP_COMPONENT)
        return XMPP_EINVOP;

    _conn_reset(conn);

    conn->type = type;
    conn->domain = strophe_strdup(conn->ctx, domain);
    if (!conn->domain)
        return XMPP_EMEM;

    conn->sock = sock_connect(conn->xsock);
    if (conn->sock == INVALID_SOCKET)
        return XMPP_EINT;

    /* setup handler */
    conn->conn_handler = callback;
    conn->userdata = userdata;

    open_handler = conn->is_raw          ? auth_handle_open_stub
                   : type == XMPP_CLIENT ? auth_handle_open
                                         : auth_handle_component_open;
    conn_prepare_reset(conn, open_handler);

    /* FIXME: it could happen that the connect returns immediately as
     * successful, though this is pretty unlikely.  This would be a little
     * hard to fix, since we'd have to detect and fire off the callback
     * from within the event loop */

    conn->state = XMPP_STATE_CONNECTING;
    conn->timeout_stamp = time_stamp();

    return 0;
}

void send_raw(xmpp_conn_t *conn,
              const char *data,
              size_t len,
              xmpp_send_queue_owner_t owner,
              void *userdata)
{
    char *d;

    if (conn->state != XMPP_STATE_CONNECTED)
        return;

    d = strophe_strndup(conn->ctx, data, len);
    if (!d) {
        strophe_error(conn->ctx, "conn", "Failed to strndup");
        return;
    }

    _send_raw(conn, d, len, owner, userdata);
}

static void _send_valist(xmpp_conn_t *conn,
                         const char *fmt,
                         va_list ap,
                         xmpp_send_queue_owner_t owner)
{
    va_list apdup;
    size_t len;
    char buf[1024]; /* small buffer for common case */
    char *bigbuf;

    if (!_is_connected(conn, owner))
        return;

    va_copy(apdup, ap);
    len = strophe_vsnprintf(buf, sizeof(buf), fmt, apdup);
    va_end(apdup);

    if (len >= sizeof(buf)) {
        /* we need more space for this data, so we allocate a big
         * enough buffer and print to that */
        len++; /* account for trailing \0 */
        bigbuf = strophe_alloc(conn->ctx, len);
        if (!bigbuf) {
            strophe_debug(conn->ctx, "xmpp",
                          "Could not allocate memory for send_raw_string");
            return;
        }
        va_copy(apdup, ap);
        strophe_vsnprintf(bigbuf, len, fmt, apdup);
        va_end(apdup);

        /* len - 1 so we don't send trailing \0 */
        _send_raw(conn, bigbuf, len - 1, owner, NULL);
    } else {
        /* go through send_raw() which does the strdup() for us */
        send_raw(conn, buf, len, owner, NULL);
    }
}

void send_raw_string(xmpp_conn_t *conn, const char *fmt, ...)
{
    va_list ap;

    if (conn->state != XMPP_STATE_CONNECTED)
        return;

    va_start(ap, fmt);
    _send_valist(conn, fmt, ap, XMPP_QUEUE_SM_STROPHE);
    va_end(ap);
}

void send_stanza(xmpp_conn_t *conn,
                 xmpp_stanza_t *stanza,
                 xmpp_send_queue_owner_t owner)
{
    char *buf = NULL;
    size_t len;

    if (!_is_connected(conn, owner))
        goto out;

    if (xmpp_stanza_to_text(stanza, &buf, &len) != 0) {
        strophe_error(conn->ctx, "conn", "Failed to stanza_to_text");
        goto out;
    }

    _send_raw(conn, buf, len, owner, NULL);
out:
    xmpp_stanza_release(stanza);
}

void add_queue_back(xmpp_queue_t *queue, xmpp_send_queue_t *item)
{
    item->next = NULL;
    if (!queue->tail) {
        item->prev = NULL;
        queue->head = item;
        queue->tail = item;
    } else {
        item->prev = queue->tail;
        queue->tail->next = item;
        queue->tail = item;
    }
}

xmpp_send_queue_t *peek_queue_front(xmpp_queue_t *queue)
{
    return queue->head;
}

xmpp_send_queue_t *pop_queue_front(xmpp_queue_t *queue)
{
    xmpp_send_queue_t *ret = queue->head;
    if (queue->head) {
        queue->head = queue->head->next;
        if (!queue->head) {
            queue->tail = NULL;
        } else {
            queue->head->prev = NULL;
        }
        ret->prev = ret->next = NULL;
    }
    return ret;
}

static int _send_raw(xmpp_conn_t *conn,
                     char *data,
                     size_t len,
                     xmpp_send_queue_owner_t owner,
                     void *userdata)
{
    xmpp_send_queue_t *item;
    const char *req_ack = "<r xmlns='urn:xmpp:sm:3'/>";

    /* create send queue item for queue */
    item = strophe_alloc(conn->ctx, sizeof(xmpp_send_queue_t));
    if (!item) {
        strophe_error(conn->ctx, "conn", "DROPPED: %s", data);
        strophe_free(conn->ctx, data);
        return XMPP_EMEM;
    }

    item->data = data;
    item->len = len;
    item->next = NULL;
    item->prev = conn->send_queue_tail;
    item->written = 0;
    item->wip = 0;
    item->userdata = userdata;
    item->owner = owner;

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
    if (owner == XMPP_QUEUE_USER)
        conn->send_queue_user_len++;
    strophe_debug_verbose(3, conn->ctx, "conn", "QUEUED: %s", data);
    strophe_debug_verbose(1, conn->ctx, "conn", "Q_ADD: %p", item);
    if (!(owner & XMPP_QUEUE_SM) && conn->sm_state->sm_enabled &&
        !conn->sm_state->r_sent) {
        conn->sm_state->r_sent = 1;
        send_raw(conn, req_ack, strlen(req_ack), XMPP_QUEUE_SM_STROPHE, item);
    } else {
        trigger_sm_callback(conn);
    }
    return XMPP_EOK;
}
