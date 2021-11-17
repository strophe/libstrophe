/* util.c
** strophe XMPP client library -- various utility functions
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  Utility functions.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/time.h>
#include <time.h>
#endif

#include "strophe.h"
#include "common.h"
#include "ostypes.h"
#include "util.h"

/** implement our own strdup that uses the ctx allocator */
/** Duplicate a string.
 *  This function replaces the standard strdup library call with a version
 *  that uses the Strophe context object's allocator.
 *
 *  @param ctx a Strophe context object
 *  @param s a string
 *
 *  @return a newly allocated string with the same data as s or NULL on error
 */
char *strophe_strdup(const xmpp_ctx_t *ctx, const char *s)
{
    return strophe_strndup(ctx, s, SIZE_MAX);
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
 */
char *strophe_strndup(const xmpp_ctx_t *ctx, const char *s, size_t len)
{
    char *copy;
    size_t l;

    l = strlen(s);
    if (l > len)
        l = len;

    copy = strophe_alloc(ctx, l + 1);
    if (!copy) {
        strophe_error(ctx, "xmpp", "failed to allocate required memory");
        return NULL;
    }

    memcpy(copy, s, l);
    copy[l] = '\0';

    return copy;
}

/** strtok_r(3) implementation.
 *  This function has appeared in POSIX.1-2001, but not in C standard.
 *  For example, visual studio older than 2005 doesn't provide strtok_r()
 *  nor strtok_s().
 */
char *strophe_strtok_r(char *s, const char *delim, char **saveptr)
{
    size_t len;

    s = s ? s : *saveptr;
    len = strspn(s, delim);
    s += len;
    if (*s == '\0')
        return NULL;

    len = strcspn(s, delim);
    *saveptr = s[len] == '\0' ? &s[len] : &s[len + 1];
    s[len] = '\0';

    return s;
}

/** Return an integer based time stamp.
 *  This function uses gettimeofday or timeGetTime (on Win32 platforms) to
 *  compute an integer based time stamp.  This is used internally by the
 *  event loop and timed handlers.
 *
 *  @return an integer time stamp
 */
uint64_t time_stamp(void)
{
#if defined(_WIN32) || defined(_XBOX_ONE)

#ifndef __GNUC__
#define EPOCHFILETIME (116444736000000000i64)
#else
#define EPOCHFILETIME (116444736000000000LL)
#endif

    FILETIME ft;
    LARGE_INTEGER li;
    __int64 t;

    GetSystemTimeAsFileTime(&ft);
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    t = li.QuadPart;              /* In 100-nanosecond intervals */
    t -= EPOCHFILETIME;           /* Offset to the Epoch time */
    return (uint64_t)(t / 10000); /* Convert to milliseconds */
#else
    struct timeval tv;

    gettimeofday(&tv, NULL);

    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
#endif
}

/** Get the time elapsed between two time stamps.
 *  This function returns the time elapsed between t1 and t2 by subtracting
 *  t1 from t2.  If t2 happened before t1, the result will be negative.  This
 *  function is used internally by the event loop and timed handlers.
 *
 *  @param t1 first time stamp
 *  @param t2 second time stamp
 *
 *  @return number of milliseconds between the stamps
 */
uint64_t time_elapsed(uint64_t t1, uint64_t t2)
{
    return (uint64_t)(t2 - t1);
}

/** Disconnect the stream with a memory error.
 *  This is a convenience function used internally by various parts of
 *  the Strophe library for terminating the connection because of a
 *  memory error.
 *
 *  @param conn a Strophe connection object
 */
void disconnect_mem_error(xmpp_conn_t *conn)
{
    strophe_error(conn->ctx, "xmpp", "Memory allocation error");
    xmpp_disconnect(conn);
}

int string_to_ul(const char *s, unsigned long *ul)
{
    char *endptr;
    *ul = strtoul(s, &endptr, 10);
    return *endptr != '\0';
}

void hex_encode(char *writebuf, void *readbuf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        sprintf(writebuf, "%02x", ((unsigned char *)readbuf)[i]);
        writebuf += 2;
    }
}
