/* uuid.c
 * strophe XMPP client library -- UUID generation
 *
 * Copyright (C) 2015 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/** @file
 *  Generation of UUID version 4 according to RFC4122.
 */

#include "strophe.h"
#include "common.h"
#include "rand.h"

/** @def XMPP_UUID_LEN
 *  UUID length in string representation excluding '\0'.
 */
#define XMPP_UUID_LEN 36

/** Generate UUID version 4 in pre-allocated buffer.
 *
 *  @param ctx a Strophe context object
 *  @param uuid pre-allocated buffer of size (XMPP_UUID_LEN + 1)
 */
static void crypto_uuid_gen(xmpp_ctx_t *ctx, char *uuid)
{
    unsigned char buf[16];
    int i = 0; /* uuid iterator */
    int j = 0; /* buf iterator */

    static const char hex[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    xmpp_rand_bytes(ctx->rand, buf, sizeof(buf));
    buf[8] &= 0x3f;
    buf[8] |= 0x80;
    buf[6] &= 0x0f;
    buf[6] |= 0x40;
    while (i < XMPP_UUID_LEN) {
        if (i == 8 || i == 13 || i == 18 || i == 23)
            uuid[i++] = '-';
        else {
            uuid[i++] = hex[buf[j] >> 4];
            uuid[i++] = hex[buf[j] & 0x0f];
            ++j;
        }
    }
    uuid[XMPP_UUID_LEN] = '\0';
}

/** Generate UUID version 4.
 *  This function allocates memory for the resulting string and must be freed
 *  with xmpp_free().
 *
 *  @param ctx a Strophe context object
 *
 *  @return ASCIIZ string
 */
char *xmpp_uuid_gen(xmpp_ctx_t *ctx)
{
    char *uuid;

    uuid = xmpp_alloc(ctx, XMPP_UUID_LEN + 1);
    if (uuid != NULL) {
        crypto_uuid_gen(ctx, uuid);
    }
    return uuid;
}
