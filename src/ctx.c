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

/* wrap stdlib routines to deal with userdata pointer */
static void *_malloc(const size_t size, void * const userdata)
{
    return malloc(size);
}

static void _free(void *p, void * const userdata)
{
    free(p);
}

static void *_realloc(void *p, const size_t size, void * const userdata)
{
    return realloc(p, size);
}

static xmpp_mem_t xmpp_default_mem = {
    _malloc, /* use the thinly wrapped stdlib routines by default */
    _free,
    _realloc,
    NULL
};

static const char * const _xmpp_log_level_name[4] = {"DEBUG", "INFO", "WARN", "ERROR"};
static const xmpp_log_level_t _xmpp_default_logger_levels[] = {XMPP_LEVEL_DEBUG,
							       XMPP_LEVEL_INFO,
							       XMPP_LEVEL_WARN,
							       XMPP_LEVEL_ERROR};

void xmpp_default_logger(void * const userdata,
			 const xmpp_log_level_t level,
			 const char * const area,
			 const char * const msg)
{
    xmpp_log_level_t filter_level = * (xmpp_log_level_t*)userdata;
    if (level >= filter_level)
	fprintf(stderr, "%s %s %s\n", area, _xmpp_log_level_name[level], msg);
}

static const xmpp_log_t _xmpp_default_loggers[] = {
	{&xmpp_default_logger, (void*)&_xmpp_default_logger_levels[XMPP_LEVEL_DEBUG]},
	{&xmpp_default_logger, (void*)&_xmpp_default_logger_levels[XMPP_LEVEL_INFO]},
	{&xmpp_default_logger, (void*)&_xmpp_default_logger_levels[XMPP_LEVEL_WARN]},
	{&xmpp_default_logger, (void*)&_xmpp_default_logger_levels[XMPP_LEVEL_ERROR]}
};

xmpp_log_t *xmpp_get_default_logger(xmpp_log_level_t level)
{
    /* clamp to the known range */
    if (level > XMPP_LEVEL_ERROR) level = XMPP_LEVEL_ERROR;
    if (level < XMPP_LEVEL_DEBUG) level = XMPP_LEVEL_DEBUG;

    return (xmpp_log_t*)&_xmpp_default_loggers[level];
}

static xmpp_log_t xmpp_default_log = { NULL, NULL };

/** convenience functions for accessing the context **/

/* allocator */

void *xmpp_alloc(const xmpp_ctx_t * const ctx, const size_t size)
{
    return ctx->mem->alloc(size, ctx->mem->userdata);
}

void xmpp_free(const xmpp_ctx_t * const ctx, void *p)
{
    ctx->mem->free(p, ctx->mem->userdata);
}

void *xmpp_realloc(const xmpp_ctx_t * const ctx, void *p,
		   const size_t size)
{
    return ctx->mem->realloc(p, size, ctx->mem->userdata);
}

/* logger */

void xmpp_log(const xmpp_ctx_t * const ctx,
	      const xmpp_log_level_t level,
	      const char * const area,
	      const char * const fmt,
	      va_list ap)
{
    int oldret, ret;
    char smbuf[1024];
    char *buf;

    buf = smbuf;
    ret = xmpp_vsnprintf(buf, 1023, fmt, ap);
    if (ret > 1023) {
	buf = (char *)xmpp_alloc(ctx, ret + 1);
	if (!buf) {
	    buf = NULL;
	    xmpp_error(ctx, "log", "Failed allocating memory for log message.");
	    return;
	}
	oldret = ret;
	ret = xmpp_vsnprintf(buf, ret, fmt, ap);
	if (ret > oldret) {
	    xmpp_error(ctx, "log", "Unexpected error");
	    return;
	}
    }

    if (ctx->log->handler)
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

