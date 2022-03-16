/* deprecated.c
** strophe XMPP client library -- File with deprecated API functions.
**
** Copyright (C) 2022 Steffen Jaeckel
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  File with deprecated API functions.
 */

/** @defgroup Deprecated All deprecated functions
 *  These functions will be removed in the next release.
 */

#include "common.h"

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

int xmpp_snprintf(char *str, size_t count, const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = strophe_vsnprintf(str, count, fmt, ap);
    va_end(ap);
    return ret;
}

int xmpp_vsnprintf(char *str, size_t count, const char *fmt, va_list arg)
{
    return strophe_vsnprintf(str, count, fmt, arg);
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
    xmpp_conn_set_sockopt_callback(conn, xmpp_sockopt_cb_keepalive);
}
