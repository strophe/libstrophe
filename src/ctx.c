/* ctx.c
** strophe XMPP client library -- run-time context implementation
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  Runtime contexts, library initialization and shutdown, and versioning.
 */

/** @defgroup Context Context objects
 *  These functions create and manipulate Strophe context objects.
 *
 *  In order to support usage in a variety of environments, the
 *  Strophe library uses a runtime context object.  This object
 *  contains the information on how to do memory allocation and
 *  logging.  This allows the user to control how memory is allocated
 *  and what do to with log messages.
 *
 *  These issues do not affect programs in the common case, but many
 *  environments require special treatment.  Abstracting these into a runtime
 *  context object makes it easy to use Strophe on embedded platforms.
 *
 *  Objects in Strophe are reference counted to ease memory management issues,
 *  but the context objects are not.
 */

/** @defgroup Init Initialization, shutdown, and versioning
 *  These functions initialize and shutdown the library, and also allow
 *  for API version checking.  Failure to properly call these functions may
 *  result in strange (and platform dependent) behavior.
 *
 *  Specifically, the socket library on Win32 platforms must be initialized
 *  before use (although this is not the case on POSIX systems).  The TLS
 *  subsystem must also seed the random number generator.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "strophe.h"
#include "common.h"
#include "resolver.h"
#include "util.h"

#ifndef va_copy
#ifdef HAVE_VA_COPY
#define va_copy(dest, src) va_copy(dest, src)
#else
#ifdef HAVE___VA_COPY
#define va_copy(dest, src) __va_copy(dest, src)
#else
#ifndef VA_LIST_IS_ARRAY
#define va_copy(dest, src) (dest) = (src)
#else
#include <string.h>
#define va_copy(dest, src) \
    memcpy((char *)(dest), (char *)(src), sizeof(va_list))
#endif
#endif
#endif
#endif

/** Initialize the Strophe library.
 *  This function initializes subcomponents of the Strophe library and must
 *  be called for Strophe to operate correctly.
 *
 *  @ingroup Init
 */
void xmpp_initialize(void)
{
    sock_initialize();
    resolver_initialize();
    tls_initialize();
}

/** Shutdown the Strophe library.
 *
 *  @ingroup Init
 */
void xmpp_shutdown(void)
{
    tls_shutdown();
    resolver_shutdown();
    sock_shutdown();
}

/* version information */

#ifndef LIBXMPP_VERSION_MAJOR
/** @def LIBXMPP_VERSION_MAJOR
 *  The major version number of Strophe.
 */
#define LIBXMPP_VERSION_MAJOR (0)
#endif
#ifndef LIBXMPP_VERSION_MINOR
/** @def LIBXMPP_VERSION_MINOR
 *  The minor version number of Strophe.
 */
#define LIBXMPP_VERSION_MINOR (0)
#endif

#ifndef EVENT_LOOP_DEFAULT_TIMEOUT
/** @def EVENT_LOOP_DEFAULT_TIMEOUT
 *  The default timeout in milliseconds for the event loop.
 *  This is set to 1 second.
 */
#define EVENT_LOOP_DEFAULT_TIMEOUT 1000
#endif

/** Check that Strophe supports a specific API version.
 *
 *  @param major the major version number
 *  @param minor the minor version number
 *
 *  @return TRUE if the version is supported and FALSE if unsupported
 *
 *  @ingroup Init
 */
int xmpp_version_check(int major, int minor)
{
    return (major == LIBXMPP_VERSION_MAJOR) && (minor >= LIBXMPP_VERSION_MINOR);
}

/* We define the global default allocator, logger, and context here. */

/* Wrap stdlib routines malloc, free, and realloc for default memory
 * management.
 */
static void *_malloc(size_t size, void *userdata)
{
    UNUSED(userdata);
    return malloc(size);
}

static void _free(void *p, void *userdata)
{
    UNUSED(userdata);
    free(p);
}

static void *_realloc(void *p, size_t size, void *userdata)
{
    UNUSED(userdata);
    return realloc(p, size);
}

/* default memory function map */
static xmpp_mem_t xmpp_default_mem = {
    _malloc, /* use the thinly wrapped stdlib routines by default */
    _free, _realloc, NULL};

/* log levels and names */
static const char *_xmpp_log_level_name[4] = {"DEBUG", "INFO", "WARN", "ERROR"};
static const xmpp_log_level_t _xmpp_default_logger_levels[] = {
    XMPP_LEVEL_DEBUG, XMPP_LEVEL_INFO, XMPP_LEVEL_WARN, XMPP_LEVEL_ERROR};

/** Log a message.
 *  The default logger writes to stderr.
 *
 *  @param userdata the opaque data used by the default logger.  This contains
 *      the filter level in the default logger.
 *  @param level the level to log at
 *  @param area the area the log message is for
 *  @param msg the log message
 */
static void xmpp_default_logger(void *userdata,
                                xmpp_log_level_t level,
                                const char *area,
                                const char *msg)
{
    xmpp_log_level_t filter_level = *(xmpp_log_level_t *)userdata;
    if (level >= filter_level)
        fprintf(stderr, "%s %s %s\n", area, _xmpp_log_level_name[level], msg);
}

static const xmpp_log_t _xmpp_default_loggers[] = {
    {&xmpp_default_logger,
     (void *)&_xmpp_default_logger_levels[XMPP_LEVEL_DEBUG]},
    {&xmpp_default_logger,
     (void *)&_xmpp_default_logger_levels[XMPP_LEVEL_INFO]},
    {&xmpp_default_logger,
     (void *)&_xmpp_default_logger_levels[XMPP_LEVEL_WARN]},
    {&xmpp_default_logger,
     (void *)&_xmpp_default_logger_levels[XMPP_LEVEL_ERROR]}};

/** Get a default logger with filtering.
 *  The default logger provides a basic logging setup which writes log
 *  messages to stderr.  Only messages where level is greater than or
 *  equal to the filter level will be logged.
 *
 *  @param level the highest level the logger will log at
 *
 *  @return the log structure for the given level
 *
 *  @ingroup Context
 */
xmpp_log_t *xmpp_get_default_logger(xmpp_log_level_t level)
{
    /* clamp to the known range */
    if (level > XMPP_LEVEL_ERROR)
        level = XMPP_LEVEL_ERROR;

    return (xmpp_log_t *)&_xmpp_default_loggers[level];
}

static xmpp_log_t xmpp_default_log = {NULL, NULL};

/* convenience functions for accessing the context */

/** Allocate memory in a Strophe context.
 *  All Strophe functions will use this to allocate memory.
 *
 *  @param ctx a Strophe context object
 *  @param size the number of bytes to allocate
 *
 *  @return a pointer to the allocated memory or NULL on an error
 */
void *strophe_alloc(const xmpp_ctx_t *ctx, size_t size)
{
    return ctx->mem->alloc(size, ctx->mem->userdata);
}

/** Free memory in a Strophe context.
 *  All Strophe functions will use this to free allocated memory.
 *
 *  @param ctx a Strophe context object
 *  @param p a pointer referencing memory to be freed
 */
void strophe_free(const xmpp_ctx_t *ctx, void *p)
{
    ctx->mem->free(p, ctx->mem->userdata);
}

/** Trampoline to \ref strophe_free
 *
 *  @param ctx \ref strophe_free
 *  @param p \ref strophe_free
 */
void xmpp_free(const xmpp_ctx_t *ctx, void *p)
{
    strophe_free(ctx, p);
}

/** Reallocate memory in a Strophe context.
 *  All Strophe functions will use this to reallocate memory.
 *
 *  @param ctx a Strophe context object
 *  @param p a pointer to previously allocated memory
 *  @param size the new size in bytes to allocate
 *
 *  @return a pointer to the reallocated memory or NULL on an error
 */
void *strophe_realloc(const xmpp_ctx_t *ctx, void *p, size_t size)
{
    return ctx->mem->realloc(p, size, ctx->mem->userdata);
}

/** Write a log message to the logger.
 *  Write a log message to the logger for the context for the specified
 *  level and area.  This function takes a printf-style format string and a
 *  variable argument list (in va_list) format.  This function is not meant
 *  to be called directly, but is used via strophe_error, strophe_warn,
 * strophe_info, and strophe_debug.
 *
 *  @param ctx a Strophe context object
 *  @param level the level at which to log
 *  @param area the area to log for
 *  @param fmt a printf-style format string for the message
 *  @param ap variable argument list supplied for the format string
 */
static void _strophe_log(const xmpp_ctx_t *ctx,
                         xmpp_log_level_t level,
                         const char *area,
                         const char *fmt,
                         va_list ap)
{
    int oldret, ret;
    char smbuf[1024];
    char *buf;
    va_list copy;

    if (!ctx->log->handler)
        return;

    if (ctx->log->handler == xmpp_default_logger &&
        level < *(xmpp_log_level_t *)ctx->log->userdata)
        return;

    va_copy(copy, ap);
    ret = strophe_vsnprintf(smbuf, sizeof(smbuf), fmt, ap);
    if (ret >= (int)sizeof(smbuf)) {
        buf = (char *)strophe_alloc(ctx, ret + 1);
        if (!buf) {
            buf = NULL;
            strophe_error(ctx, "log",
                          "Failed allocating memory for log message.");
            va_end(copy);
            return;
        }
        oldret = ret;
        ret = strophe_vsnprintf(buf, ret + 1, fmt, copy);
        if (ret > oldret) {
            strophe_error(ctx, "log", "Unexpected error");
            strophe_free(ctx, buf);
            va_end(copy);
            return;
        }
    } else {
        buf = smbuf;
    }
    va_end(copy);

    ctx->log->handler(ctx->log->userdata, level, area, buf);

    if (buf != smbuf)
        strophe_free(ctx, buf);
}

/* Dummy trampoline, will be removed when deprecated.c is deleted */
void strophe_log_internal(const xmpp_ctx_t *ctx,
                          xmpp_log_level_t level,
                          const char *area,
                          const char *fmt,
                          va_list ap)
{
    _strophe_log(ctx, level, area, fmt, ap);
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
 */
void strophe_error(const xmpp_ctx_t *ctx,
                   const char *area,
                   const char *fmt,
                   ...)
{
    va_list ap;

    va_start(ap, fmt);
    _strophe_log(ctx, XMPP_LEVEL_ERROR, area, fmt, ap);
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
 */
void strophe_warn(const xmpp_ctx_t *ctx, const char *area, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _strophe_log(ctx, XMPP_LEVEL_WARN, area, fmt, ap);
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
 */
void strophe_info(const xmpp_ctx_t *ctx, const char *area, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _strophe_log(ctx, XMPP_LEVEL_INFO, area, fmt, ap);
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
 */
void strophe_debug(const xmpp_ctx_t *ctx,
                   const char *area,
                   const char *fmt,
                   ...)
{
    va_list ap;

    va_start(ap, fmt);
    _strophe_log(ctx, XMPP_LEVEL_DEBUG, area, fmt, ap);
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
 */
void strophe_debug_verbose(
    int level, const xmpp_ctx_t *ctx, const char *area, const char *fmt, ...)
{
    va_list ap;

    if (ctx->verbosity < level)
        return;

    va_start(ap, fmt);
    _strophe_log(ctx, XMPP_LEVEL_DEBUG, area, fmt, ap);
    va_end(ap);
}

/** Create and initialize a Strophe context object.
 *  If mem is NULL, a default allocation setup will be used which
 *  wraps malloc(), free(), and realloc() from the standard library.
 *  If log is NULL, a default logger will be used which does no
 *  logging.  Basic filtered logging to stderr can be done with the
 *  xmpp_get_default_logger() convenience function.
 *
 *  @param mem a pointer to an xmpp_mem_t structure or NULL
 *  @param log a pointer to an xmpp_log_t structure or NULL
 *
 *  @return the allocated Strophe context object or NULL on an error
 *
 *  @ingroup Context
 */
xmpp_ctx_t *xmpp_ctx_new(const xmpp_mem_t *mem, const xmpp_log_t *log)
{
    xmpp_ctx_t *ctx = NULL;

    if (mem == NULL)
        ctx = xmpp_default_mem.alloc(sizeof(xmpp_ctx_t), NULL);
    else
        ctx = mem->alloc(sizeof(xmpp_ctx_t), mem->userdata);

    if (ctx != NULL) {
        if (mem != NULL)
            ctx->mem = mem;
        else
            ctx->mem = &xmpp_default_mem;

        if (log == NULL)
            ctx->log = &xmpp_default_log;
        else
            ctx->log = log;

        ctx->connlist = NULL;
        ctx->timed_handlers = NULL;
        ctx->loop_status = XMPP_LOOP_NOTSTARTED;
        ctx->rand = xmpp_rand_new(ctx);
        ctx->timeout = EVENT_LOOP_DEFAULT_TIMEOUT;
        ctx->verbosity = 0;
        if (ctx->rand == NULL) {
            strophe_free(ctx, ctx);
            ctx = NULL;
        }
    }

    return ctx;
}

/** Free a Strophe context object that is no longer in use.
 *
 *  @param ctx a Strophe context object
 *
 *  @ingroup Context
 */
void xmpp_ctx_free(xmpp_ctx_t *ctx)
{
    /* mem and log are owned by their suppliers */
    xmpp_rand_free(ctx, ctx->rand);
    strophe_free(ctx, ctx); /* pull the hole in after us */
}

/** Set the verbosity level of a Strophe context.
 *
 *  @param ctx a Strophe context object
 *  @param level the verbosity level
 *
 *  @ingroup Context
 */
void xmpp_ctx_set_verbosity(xmpp_ctx_t *ctx, int level)
{
    ctx->verbosity = level;
}
