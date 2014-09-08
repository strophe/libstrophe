/* ostypes.h
** strophe XMPP client library -- type definitions for platforms 
**     without stdint.h
**
** Copyright (C) 2005-2009 Collecta, Inc. 
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This software is distributed under license and may not be copied,
**  modified or distributed except as expressly authorized under the
**  terms of the license contained in the file LICENSE.txt in this
**  distribution.
*/

/** @file
 *  Type definitions for platforms without stdint.h.
 */

#ifndef __LIBSTROPHE_OSTYPES_H__
#define __LIBSTROPHE_OSTYPES_H__

#if _MSC_VER < 1600
typedef signed char int8_t;
typedef short int int16_t;
typedef int int32_t;
typedef __int64 int64_t;
 
typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;
typedef unsigned __int64 uint64_t; 
#endif

#endif /* __LIBSTROPHE_OSTYPES_H__ */
