/* ostypes.h
** strophe XMPP client library -- type definitions for platforms 
**     without stdint.h
**
** Copyright (C) 2005-2009 Collecta, Inc. 
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  Type definitions for platforms without stdint.h.
 */

#ifndef __LIBSTROPHE_OSTYPES_H__
#define __LIBSTROPHE_OSTYPES_H__

#include <stddef.h>     /* size_t */

#if defined (_MSC_VER) && _MSC_VER < 1600
typedef signed char int8_t;
typedef short int int16_t;
typedef int int32_t;
typedef __int64 int64_t;

typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;
typedef unsigned __int64 uint64_t; 

#ifndef UINT16_MAX
#define UINT16_MAX ((uint16_t)0xffff)
#endif /* UINT16_MAX */
#ifndef UINT32_MAX
#define UINT32_MAX ((uint32_t)0xffffffff)
#endif /* UINT32_MAX */
#ifndef SIZE_MAX
#define SIZE_MAX UINT32_MAX
#endif /* SIZE_MAX */

#else
#include <stdint.h>
#endif

#endif /* __LIBSTROPHE_OSTYPES_H__ */
