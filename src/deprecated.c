/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* deprecated.c
** strophe XMPP client library -- File with deprecated API functions.
**
** Copyright (C) 2022 Steffen Jaeckel
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT or GPLv3 licenses.
*/

/** @file
 *  File with deprecated API functions.
 */

/** @defgroup Deprecated All deprecated functions
 *  These functions will be removed in the next release.
 */

#include "common.h"
#include <limits.h>

/** Allocate memory in a Strophe context.
 *  All Strophe functions will use this to allocate memory.
 *
 *  @param ctx a Strophe context object
 *  @param size the number of bytes to allocate
 *
 *  @return a pointer to the allocated memory or NULL on an error
 *
 *  @ingroup Deprecated
 */
void *xmpp_alloc(const xmpp_ctx_t *ctx, size_t size)
{
    return strophe_alloc(ctx, size);
}

/** Reallocate memory in a Strophe context.
 *  All Strophe functions will use this to reallocate memory.
 *
 *  @param ctx a Strophe context object
 *  @param p a pointer to previously allocated memory
 *  @param size the new size in bytes to allocate
 *
 *  @return a pointer to the reallocated memory or NULL on an error
 *
 *  @ingroup Deprecated
 */
void *xmpp_realloc(const xmpp_ctx_t *ctx, void *p, size_t size)
{
    return strophe_realloc(ctx, p, size);
}

/** implement our own strdup that uses the ctx allocator */
/** Duplicate a string.
 *  This function replaces the standard strdup library call with a version
 *  that uses the Strophe context object's allocator.
 *
 *  @param ctx a Strophe context object
 *  @param s a string
 *
 *  @return a newly allocated string with the same data as s or NULL on error
 *
 *  @ingroup Deprecated
 */
char *xmpp_strdup(const xmpp_ctx_t *ctx, const char *s)
{
    return strophe_strdup(ctx, s);
}

/** Duplicate a string with a maximum length.
 *  This function replaces the standard strndup library call with a version
 *  that uses the Strophe context object's allocator.
 *
 *  @param ctx a Strophe context object
 *  @param s a string
 *  @param len the maximum length of the string to copy
 *
 *  @return a newly allocated string that contains at most `len` symbols
 *             of the original string or NULL on error
 *
 *  @ingroup Deprecated
 */
char *xmpp_strndup(const xmpp_ctx_t *ctx, const char *s, size_t len)
{
    return strophe_strndup(ctx, s, len);
}

/** Write to the log.
 *
 *  @ingroup Deprecated
 */
void xmpp_log(const xmpp_ctx_t *ctx,
              xmpp_log_level_t level,
              const char *area,
              const char *fmt,
              va_list ap)
{
    strophe_log_internal(ctx, level, area, fmt, ap);
}

/** Write to the log at the ERROR level.
 *  This is a convenience function for writing to the log at the
 *  ERROR level.  It takes a printf-style format string followed by a
 *  variable list of arguments for formatting.
 *
 *  @param ctx a Strophe context object
 *  @param area the area to log for
 *  @param fmt a printf-style format string followed by a variable list of
 *      arguments to format
 *
 *  @ingroup Deprecated
 */
void xmpp_error(const xmpp_ctx_t *ctx, const char *area, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    strophe_log_internal(ctx, XMPP_LEVEL_ERROR, area, fmt, ap);
    va_end(ap);
}

/** Write to the log at the WARN level.
 *  This is a convenience function for writing to the log at the WARN level.
 *  It takes a printf-style format string followed by a variable list of
 *  arguments for formatting.
 *
 *  @param ctx a Strophe context object
 *  @param area the area to log for
 *  @param fmt a printf-style format string followed by a variable list of
 *      arguments to format
 *
 *  @ingroup Deprecated
 */
void xmpp_warn(const xmpp_ctx_t *ctx, const char *area, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    strophe_log_internal(ctx, XMPP_LEVEL_WARN, area, fmt, ap);
    va_end(ap);
}

/** Write to the log at the INFO level.
 *  This is a convenience function for writing to the log at the INFO level.
 *  It takes a printf-style format string followed by a variable list of
 *  arguments for formatting.
 *
 *  @param ctx a Strophe context object
 *  @param area the area to log for
 *  @param fmt a printf-style format string followed by a variable list of
 *      arguments to format
 *
 *  @ingroup Deprecated
 */
void xmpp_info(const xmpp_ctx_t *ctx, const char *area, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    strophe_log_internal(ctx, XMPP_LEVEL_INFO, area, fmt, ap);
    va_end(ap);
}

/** Write to the log at the DEBUG level.
 *  This is a convenience function for writing to the log at the DEBUG level.
 *  It takes a printf-style format string followed by a variable list of
 *  arguments for formatting.
 *
 *  @param ctx a Strophe context object
 *  @param area the area to log for
 *  @param fmt a printf-style format string followed by a variable list of
 *      arguments to format
 *
 *  @ingroup Deprecated
 */
void xmpp_debug(const xmpp_ctx_t *ctx, const char *area, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    strophe_log_internal(ctx, XMPP_LEVEL_DEBUG, area, fmt, ap);
    va_end(ap);
}

/** Write to the log at the DEBUG level if verbosity is enabled.
 *  This is a convenience function for writing to the log at the DEBUG level.
 *  It takes a printf-style format string followed by a variable list of
 *  arguments for formatting.
 *
 *  @param level the verbosity level
 *  @param ctx a Strophe context object
 *  @param area the area to log for
 *  @param fmt a printf-style format string followed by a variable list of
 *      arguments to format
 *
 *  @ingroup Deprecated
 */
void xmpp_debug_verbose(
    int level, const xmpp_ctx_t *ctx, const char *area, const char *fmt, ...)
{
    va_list ap;

    if (ctx->verbosity < level)
        return;

    va_start(ap, fmt);
    strophe_log_internal(ctx, XMPP_LEVEL_DEBUG, area, fmt, ap);
    va_end(ap);
}

/** strtok_r(3) implementation.
 *  This function has appeared in POSIX.1-2001, but not in C standard.
 *  For example, visual studio older than 2005 doesn't provide strtok_r()
 *  nor strtok_s().
 *
 *  @ingroup Deprecated
 */
char *xmpp_strtok_r(char *s, const char *delim, char **saveptr)
{
    return strophe_strtok_r(s, delim, saveptr);
}

/** snprintf(3) implementation.
 *
 *  @ingroup Deprecated
 */
int xmpp_snprintf(char *str, size_t count, const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = strophe_vsnprintf(str, count, fmt, ap);
    va_end(ap);
    return ret;
}

/** vsnprintf(3) implementation.
 *
 *  @ingroup Deprecated
 */
int xmpp_vsnprintf(char *str, size_t count, const char *fmt, va_list arg)
{
    return strophe_vsnprintf(str, count, fmt, arg);
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
 *  @ingroup Deprecated
 */
void xmpp_conn_set_jid(xmpp_conn_t *conn, const char *jid)
{
    xmpp_conn_set_string(conn, XMPP_SETTING_JID, jid);
}

/** Set the password used to authenticate the connection.
 *  If any password was previously set, it will be discarded.  The function
 *  will make a copy of the password string.
 *
 *  @param conn a Strophe connection object
 *  @param pass the password
 *
 *  @ingroup Deprecated
 */
void xmpp_conn_set_pass(xmpp_conn_t *conn, const char *pass)
{
    xmpp_conn_set_string(conn, XMPP_SETTING_PASS, pass);
}

/** Set the CAfile
 *
 *  @param conn a Strophe connection object
 *  @param path path to a certificate file
 *
 *  @ingroup Deprecated
 */
void xmpp_conn_set_cafile(xmpp_conn_t *const conn, const char *path)
{
    xmpp_conn_set_string(conn, XMPP_SETTING_CAFILE, path);
}

/** Set the CApath
 *
 *  @param conn a Strophe connection object
 *  @param path path to a folder containing certificates
 *
 *  @ingroup Deprecated
 */
void xmpp_conn_set_capath(xmpp_conn_t *const conn, const char *path)
{
    xmpp_conn_set_string(conn, XMPP_SETTING_CAPATH, path);
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
 *  @ingroup Deprecated
 */
void xmpp_conn_set_client_cert(xmpp_conn_t *const conn,
                               const char *const cert,
                               const char *const key)
{
    strophe_debug(conn->ctx, "conn", "set client cert %s %s", cert, key);
    if (!cert && key) {
        xmpp_conn_set_string(conn, XMPP_SETTING_CLIENT_CERT, key);
        strophe_warn(conn->ctx, "xmpp",
                     "xmpp_conn_set_client_cert: Passing PKCS#12 in 'key' "
                     "parameter is deprecated. Use 'cert' instead");
    } else {
        xmpp_conn_set_string(conn, XMPP_SETTING_CLIENT_CERT, cert);
        xmpp_conn_set_string(conn, XMPP_SETTING_CLIENT_KEY, key);
    }
}

/** Set the number of retry attempts to decrypt a private key file.
 *
 *  In case the user enters the password manually it can be useful to
 *  directly retry if the decryption of the key file failed.
 *
 *  @param conn a   Strophe connection object
 *  @param retries  The number of retries that should be tried
 *
 *  @ingroup Deprecated
 */
void xmpp_conn_set_password_retries(xmpp_conn_t *conn, unsigned int retries)
{
    int val;
    if (retries > INT_MAX) {
        val = INT_MAX;
        strophe_warn(conn->ctx, "xmpp", "retries capped from %u to %d", retries,
                     val);
    } else {
        val = (int)retries;
    }
    xmpp_conn_set_int(conn, XMPP_SETTING_PASSWORD_RETRIES, val);
}

/** Set the Callback function which will be called when the TLS stack can't
 *  decrypt a password protected key file.
 *
 *  @param conn a   Strophe connection object
 *  @param cb       The callback function that shall be called
 *  @param userdata An opaque data pointer that will be passed to the callback
 *
 *  @ingroup Deprecated
 */
void xmpp_conn_set_password_callback(xmpp_conn_t *conn,
                                     xmpp_password_callback cb,
                                     void *userdata)
{
    xmpp_conn_set_functionpointer(conn, XMPP_SETTING_PASSWORD_CALLBACK, cb);
    xmpp_conn_set_pointer(conn, XMPP_SETTING_PASSWORD_CALLBACK_USERDATA,
                          userdata);
}

/** Set the Handler function which will be called when the TLS stack can't
 *  verify the CA of the server we're trying to connect to.
 *
 *  @param conn a Strophe connection object
 *  @param hndl certfail Handler function
 *
 *  @ingroup Deprecated
 */
void xmpp_conn_set_certfail_handler(xmpp_conn_t *const conn,
                                    xmpp_certfail_handler hndl)
{
    xmpp_conn_set_functionpointer(conn, XMPP_SETTING_CERTFAIL_HANDLER, hndl);
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
 *  @ingroup Deprecated
 */

void xmpp_conn_set_sockopt_callback(xmpp_conn_t *conn,
                                    xmpp_sockopt_callback callback)
{
    xmpp_conn_set_functionpointer(conn, XMPP_SETTING_SOCKOPT_CALLBACK,
                                  callback);
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
 *  @note this function is deprecated
 *  @see xmpp_conn_set_sockopt_callback()
 *
 *  @ingroup Deprecated
 */
void xmpp_conn_set_keepalive(xmpp_conn_t *conn, int timeout, int interval)
{
    conn->ka_timeout = timeout;
    conn->ka_interval = interval;
    conn->ka_count = 0;
    xmpp_conn_set_functionpointer(conn, XMPP_SETTING_SOCKOPT_CALLBACK,
                                  xmpp_sockopt_cb_keepalive);
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
 *  @ingroup Deprecated
 */
void xmpp_conn_disable_tls(xmpp_conn_t *conn)
{
    long flags = xmpp_conn_get_flags(conn);

    flags |= XMPP_CONN_FLAG_DISABLE_TLS;
    (void)xmpp_conn_set_flags(conn, flags);
}
