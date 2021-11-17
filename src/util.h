/* util.h
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
 *  Internally used utility functions.
 */

#ifndef __LIBSTROPHE_UTIL_H__
#define __LIBSTROPHE_UTIL_H__

#include "ostypes.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif /* ARRAY_SIZE */

/* TODO evaluate x and y only once */
#define xmpp_min(x, y) ((x) < (y) ? (x) : (y))

/* string functions */
char *strophe_strtok_r(char *s, const char *delim, char **saveptr);

/* timing functions */
uint64_t time_stamp(void);
uint64_t time_elapsed(uint64_t t1, uint64_t t2);

/* misc functions */
int string_to_ul(const char *s, unsigned long *ul);
void hex_encode(char *writebuf, void *readbuf, size_t len);

#endif /* __LIBSTROPHE_UTIL_H__ */
