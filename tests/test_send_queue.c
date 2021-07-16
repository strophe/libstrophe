/* test_xmppaddr.c
** libstrophe XMPP client library -- test routines for the send queue
**
** Copyright (C) 2021 Steffen Jaeckel
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "strophe.h"
#include "common.h"

#include "test.h"

#define ENSURE_EQ(v1, v2)                       \
    do {                                        \
        int __v1 = v1;                          \
        int __v2 = v2;                          \
        if (__v1 != __v2) {                     \
            printf("Error:    %s\n"             \
                   "Expected: %d\n"             \
                   "Got:      %d\n",            \
                   #v1 " != " #v2, __v2, __v1); \
            exit(1);                            \
        }                                       \
    } while (0)

int main()
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t *log;
    xmpp_conn_state_t state;

    unsigned int n;

    xmpp_initialize();
    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG);
    ctx = xmpp_ctx_new(NULL, log);
    conn = xmpp_conn_new(ctx);

    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 0);

    state = conn->state;
    conn->state = XMPP_STATE_CONNECTED;

    xmpp_send_raw(conn, "foo", 3);
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 1);

    xmpp_send_raw(conn, "bar", 3);
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 2);

    xmpp_send_raw(conn, "baz", 3);
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 3);

    xmpp_send_raw(conn, "baan", 4);
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 4);

    conn->send_queue_head->written = 1;
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 3);

    xmpp_conn_send_queue_drop_element(conn, XMPP_QUEUE_OLDEST);
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 2);

    conn->send_queue_head->written = 0;
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 3);

    xmpp_conn_send_queue_drop_element(conn, XMPP_QUEUE_OLDEST);
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 2);

    xmpp_conn_send_queue_drop_element(conn, XMPP_QUEUE_YOUNGEST);
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 1);

    xmpp_conn_send_queue_drop_element(conn, XMPP_QUEUE_YOUNGEST);
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 0);

    conn->state = state;

    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);
    xmpp_shutdown();

    return 0;
}
