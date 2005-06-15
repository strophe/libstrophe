/* ctx.c
** libstrophe XMPP client library -- run-time context implementation
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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "strophe.h"
#include "common.h"
#include "util.h"

#ifdef _WIN32
#define vsnprintf _vsnprintf
#endif

/* initialization and shutdown */

void xmpp_initialize(void)
{
    sock_initialize();
}

void xmpp_shutdown(void)
{
    sock_shutdown();
}

/** version **/

/* TODO: update from the build system? */
#ifndef LIBXMPP_VERSION_MAJOR
#define LIBXMPP_VERSION_MAJOR (0)
#endif
#ifndef LIBXMPP_VERSION_MINOR
#define LIBXMPP_VERSION_MINOR (0)
#endif

int xmpp_version_check(int major, int minor)
{
    return (major == LIBXMPP_VERSION_MAJOR) &&
	   (minor >= LIBXMPP_VERSION_MINOR);
}

/** run-time contexts **/

/* define the global default allocator, logger and context here */

static xmpp_mem_t xmpp_default_mem = {
    malloc, /* use the stdlib routines by default */
    free,
    realloc
};

static const char * const xmpp_log_level_name[4] = {"DEBUG", "INFO", "WARN", "ERROR"};

void xmpp_default_logger(void * const userdata,
			 const xmpp_log_level_t level,
			 const char * const area,
			 const char * const msg)
{
    fprintf(stderr, "%s %s %s\n", area, xmpp_log_level_name[level], msg);
}

#ifdef _WIN32
static xmpp_log_t xmpp_default_log = { NULL, NULL };
#else
static xmpp_log_t xmpp_default_log = { xmpp_default_logger, NULL };
#endif


/** convenience functions for accessing the context **/

/* allocator */

void *xmpp_alloc(const xmpp_ctx_t * const ctx, const size_t size)
{
    return ctx->mem->alloc(size);
}

void xmpp_free(const xmpp_ctx_t * const ctx, void *p)
{
    ctx->mem->free(p);
}

void *xmpp_realloc(const xmpp_ctx_t * const ctx, void *p,
		   const size_t size)
{
    return ctx->mem->realloc(p, size);
}

/* logger */

void xmpp_log(const xmpp_ctx_t * const ctx,
	      const xmpp_log_level_t level,
	      const char * const area,
	      const char * const fmt,
	      va_list ap)
{
    char buf[1024];

    /* FIXME: we don't send log lines > 1024 chars */

    vsnprintf(buf, 1023, fmt, ap);

    ctx->log->handler(ctx->log->userdata, level, area, buf);
}

void xmpp_error(const xmpp_ctx_t * const ctx,
                const char * const area,
                const char * const fmt,
                ...)
{
    va_list ap;

    va_start(ap, fmt);
    xmpp_log(ctx, XMPP_LEVEL_ERROR, area, fmt, ap);
    va_end(ap);
}

void xmpp_warn(const xmpp_ctx_t * const ctx,
                const char * const area,
                const char * const fmt,
                ...)
{
    va_list ap;

    va_start(ap, fmt);
    xmpp_log(ctx, XMPP_LEVEL_WARN, area, fmt, ap);
    va_end(ap);
}

void xmpp_info(const xmpp_ctx_t * const ctx,
                const char * const area,
                const char * const fmt,
                ...)
{
    va_list ap;

    va_start(ap, fmt);
    xmpp_log(ctx, XMPP_LEVEL_INFO, area, fmt, ap);
    va_end(ap);
}

void xmpp_debug(const xmpp_ctx_t * const ctx,
                const char * const area,
                const char * const fmt,
                ...)
{
    va_list ap;

    va_start(ap, fmt);
    xmpp_log(ctx, XMPP_LEVEL_DEBUG, area, fmt, ap);
    va_end(ap);
}

/** allocate and initialize a new ctx object */
xmpp_ctx_t *xmpp_ctx_new(const xmpp_mem_t * const mem, 
			 const xmpp_log_t * const log)
{
    xmpp_ctx_t *ctx = NULL;

    if (mem == NULL)
	ctx = xmpp_default_mem.alloc(sizeof(xmpp_ctx_t));
    else
	ctx = mem->alloc(sizeof(xmpp_ctx_t));

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
	ctx->loop_status = XMPP_LOOP_NOTSTARTED;
    }

    return ctx;
}

/** free a ctx object no longer in use */
void xmpp_ctx_free(xmpp_ctx_t * const ctx)
{
    /* mem and log are owned by their suppliers */
    xmpp_free(ctx, ctx); /* pull the hole in after us */
}

