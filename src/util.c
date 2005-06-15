/* util.c
** libstrophe XMPP client library -- various utility functions
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
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/time.h>
#include <time.h>
#include <stdint.h>
#endif

#include "strophe.h"
#include "common.h"
#include "util.h"

/** implement our own strdup that uses the ctx allocator */
char *xmpp_strdup(const xmpp_ctx_t * const ctx, const char * const s)
{
    size_t len;
    char *copy;

    len = strlen(s);
    copy = xmpp_alloc(ctx, len + 1);
    if (!copy) {
        xmpp_error(ctx, "xmpp", "failed to allocate required memory");
        return NULL;
    }

    memcpy(copy, s, len + 1);

    return copy;
}

uint64_t time_stamp(void)
{
#ifdef _WIN32
    return timeGetTime();
#else
    struct timeval tv;

    gettimeofday(&tv, NULL);

    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
#endif
}

uint64_t time_elapsed(uint64_t t1, uint64_t t2)
{
    return (uint64_t)(t2 - t1);
}

void disconnect_mem_error(xmpp_conn_t * const conn)
{
    xmpp_error(conn->ctx, "xmpp", "Memory allocation error");
    xmpp_disconnect(conn);
}
