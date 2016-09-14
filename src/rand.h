/* rand.h
 * strophe XMPP client library -- pseudo-random number generator
 *
 * Copyright (C) 2014 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/** @file
 *  Pseudo-random number generator.
 */

#ifndef __LIBSTROPHE_RAND_H__
#define __LIBSTROPHE_RAND_H__

#include <stddef.h>     /* size_t */
#include "strophe.h"    /* xmpp_ctx_t */

typedef struct _xmpp_rand_t xmpp_rand_t;

/** Create new xmpp_rand_t object.
 *
 *  @param ctx A Strophe context object
 *
 *  @ingroup Random
 */
xmpp_rand_t *xmpp_rand_new(xmpp_ctx_t *ctx);
/** Destroy an xmpp_rand_t object.
 *
 *  @param ctx A Strophe context object
 *
 *  @ingroup Random
 */
void xmpp_rand_free(xmpp_ctx_t *ctx, xmpp_rand_t *rand);

/** Generate random integer
 *  Analogue of rand(3).
 *
 *  @ingroup Random
 */
int xmpp_rand(xmpp_rand_t *rand);

/** Generate random bytes.
 *  Generates len bytes and stores them to the output buffer.
 *
 *  @ingroup Random
 */
void xmpp_rand_bytes(xmpp_rand_t *rand, unsigned char *output, size_t len);

/** Generate a nonce that is printable randomized string.
 *  This function doesn't allocate memory and doesn't fail.
 *
 *  @param output A buffer where a NULL-terminated string will be placed.
 *                The string will contain len-1 printable symbols.
 *  @param len Number of bytes reserved for the output string, including
 *             end of line '\0'.
 *
 *  @ingroup Random
 */
void xmpp_rand_nonce(xmpp_rand_t *rand, char *output, size_t len);

#endif /* __LIBSTROPHE_RAND_H__ */
