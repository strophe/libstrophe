/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* compression_dummy.c
** strophe XMPP client library -- Dummy Compression
**
** Copyright (C) 2024 Steffen Jaeckel <jaeckel-floss@eyet-services.de>
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT or GPLv3 licenses.
*/

/** @file
 *  Dummy Compression.
 */
#include <strings.h>
#include <errno.h>

#include "common.h"

int compression_init(xmpp_conn_t *conn)
{
    conn->compression.supported = 0;
    return -1;
}

void compression_free(xmpp_conn_t *conn)
{
    UNUSED(conn);
}

void compression_handle_feature_children(xmpp_conn_t *conn, const char *text)
{
    UNUSED(text);
    conn->compression.supported = 0;
}
