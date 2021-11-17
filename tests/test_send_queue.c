/* test_send_queue.c
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

int main()
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t *log;
    xmpp_conn_state_t state;
    xmpp_sm_state_t *sm_state;
    char *ret;

    unsigned int n;

    xmpp_initialize();
    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG);
    ctx = xmpp_ctx_new(NULL, log);
    conn = xmpp_conn_new(ctx);
    sm_state = strophe_alloc(ctx, sizeof(*sm_state));
    memset(sm_state, 0, sizeof(*sm_state));
    sm_state->ctx = ctx;

    xmpp_conn_set_sm_state(conn, sm_state);

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

    conn->send_queue_head->wip = 1;
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 3);

    ret = xmpp_conn_send_queue_drop_element(conn, XMPP_QUEUE_OLDEST);
    COMPARE("bar", ret);
    xmpp_free(ctx, ret);
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 2);

    conn->send_queue_head->wip = 0;
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 3);

    ret = xmpp_conn_send_queue_drop_element(conn, XMPP_QUEUE_OLDEST);
    COMPARE("foo", ret);
    xmpp_free(ctx, ret);
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 2);

    ret = xmpp_conn_send_queue_drop_element(conn, XMPP_QUEUE_YOUNGEST);
    COMPARE("baan", ret);
    xmpp_free(ctx, ret);
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 1);

    ret = xmpp_conn_send_queue_drop_element(conn, XMPP_QUEUE_YOUNGEST);
    COMPARE("baz", ret);
    xmpp_free(ctx, ret);
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 0);

    conn->state = state;

    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);
    xmpp_shutdown();

    return 0;
}
