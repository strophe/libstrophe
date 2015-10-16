/* snprintf.h
 * strophe XMPP client library -- stdarg wrappers
 *
 * Copyright (C) 2015 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express or
 *  implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/** @file
 *  Compatibility wrappers for OSes lacking snprintf(3) and/or vsnprintf(3).
 */

#ifndef __LIBSTROPHE_SNPRINTF_H__
#define __LIBSTROPHE_SNPRINTF_H__

#include <stddef.h>
#include <stdarg.h>

#if defined(HAVE_SNPRINTF) || defined(HAVE_VSNPRINTF)
#include <stdio.h>
#endif

#ifdef HAVE_SNPRINTF
#define xmpp_snprintf snprintf
#else
int xmpp_snprintf(char *str, size_t count, const char *fmt, ...);
#endif

#ifdef HAVE_VSNPRINTF
#define xmpp_vsnprintf vsnprintf
#else
int xmpp_vsnprintf(char *str, size_t count, const char *fmt, va_list arg);
#endif

#endif /* __LIBSTROPHE_SNPRINTF_H__ */
