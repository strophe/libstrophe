/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* test_serialize_sm.c
** libstrophe XMPP client library -- test routines for the send queue
**
** Copyright (C) 2024 Stephen Paul Weber
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT or GPLv3 licenses.
*/

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "strophe.h"
#include "common.h"

#include "test.h"

void callback(xmpp_conn_t *conn,
              void *ctx,
              const unsigned char *sm_state,
              size_t sm_state_len)
{
    int *callback_count = ctx;
    (*callback_count)++;
    COMPARE_BUF("\x1a\x00\x00\x00\x00", 5, sm_state, 5);
    COMPARE_BUF("\x1a\x00\x00\x00\x00", 5, sm_state + 10, 5);
    COMPARE_BUF("\x7a\x00\x00\x00\x04SMID", 9, sm_state + 15, 9);
    if (*callback_count == 1) {
        COMPARE_BUF("\x1a\x00\x00\x00\x00", 5, sm_state + 5, 5);
        COMPARE_BUF("\x9a\x00\x00\x00\x02", 5, sm_state + 24, 5);
        COMPARE_BUF("\x7a\x00\x00\x00\x03"
                    "foo",
                    8, sm_state + 29, 8);
        COMPARE_BUF("\x7a\x00\x00\x00\x1a<r xmlns='urn:xmpp:sm:3'/>", 31,
                    sm_state + 37, 31);
        COMPARE_BUF("\xba\x00\x00\x00\x00", 5, sm_state + 68, 5);
        ENSURE_EQ(sm_state_len, 73);

        xmpp_conn_t *newconn = xmpp_conn_new(conn->ctx);
        xmpp_conn_restore_sm_state(newconn, sm_state, sm_state_len);
        ENSURE_EQ(newconn->sm_state->sm_sent_nr, 0);
        ENSURE_EQ(newconn->sm_state->sm_handled_nr, 0);
        COMPARE(newconn->sm_state->previd, "SMID");
        ENSURE_EQ(newconn->send_queue_len, 2);
        ENSURE_EQ(newconn->send_queue_user_len, 2);
        ENSURE_EQ((size_t)(newconn->sm_state->sm_queue.head), 0);
        xmpp_conn_release(newconn);
    }
    if (*callback_count == 2) {
        COMPARE_BUF("\x1a\x00\x00\x00\x01", 5, sm_state + 5, 5);
        COMPARE_BUF("\x9a\x00\x00\x00\x01", 5, sm_state + 24, 5);
        COMPARE_BUF("\x7a\x00\x00\x00\x1a<r xmlns='urn:xmpp:sm:3'/>", 31,
                    sm_state + 29, 31);
        COMPARE_BUF("\xba\x00\x00\x00\x01", 5, sm_state + 60, 5);
        COMPARE_BUF("\x1a\x00\x00\x00\x00", 5, sm_state + 65, 5);
        COMPARE_BUF("\x7a\x00\x00\x00\x03"
                    "foo",
                    8, sm_state + 70, 8);
        ENSURE_EQ(sm_state_len, 78);

        xmpp_conn_t *newconn = xmpp_conn_new(conn->ctx);
        xmpp_conn_restore_sm_state(newconn, sm_state, sm_state_len);
        ENSURE_EQ(newconn->sm_state->sm_sent_nr, 1);
        ENSURE_EQ(newconn->sm_state->sm_handled_nr, 0);
        COMPARE(newconn->sm_state->previd, "SMID");
        ENSURE_EQ(newconn->send_queue_len, 1);
        ENSURE_EQ(newconn->send_queue_user_len, 1);
        ENSURE_EQ(newconn->sm_state->sm_queue.head->sm_h, 0);
        xmpp_conn_release(newconn);
    }
    if (*callback_count == 3) {
        COMPARE_BUF("\x1a\x00\x00\x00\x01", 5, sm_state + 5, 5);
        COMPARE_BUF("\x9a\x00\x00\x00\x00", 5, sm_state + 24, 5);
        COMPARE_BUF("\xba\x00\x00\x00\x01", 5, sm_state + 29, 5);
        COMPARE_BUF("\x1a\x00\x00\x00\x00", 5, sm_state + 34, 5);
        COMPARE_BUF("\x7a\x00\x00\x00\x03"
                    "foo",
                    8, sm_state + 39, 8);
        ENSURE_EQ(sm_state_len, 47);

        xmpp_conn_t *newconn = xmpp_conn_new(conn->ctx);
        xmpp_conn_restore_sm_state(newconn, sm_state, sm_state_len);
        ENSURE_EQ(newconn->sm_state->sm_sent_nr, 1);
        ENSURE_EQ(newconn->sm_state->sm_handled_nr, 0);
        COMPARE(newconn->sm_state->previd, "SMID");
        ENSURE_EQ(newconn->send_queue_len, 0);
        ENSURE_EQ(newconn->send_queue_user_len, 0);
        ENSURE_EQ(newconn->sm_state->sm_queue.head->sm_h, 0);
        xmpp_conn_release(newconn);
    }
}

int fake_read(struct conn_interface *intf, void *buff, size_t len)
{
    return 0;
}

int fake_write(struct conn_interface *intf, const void *buff, size_t len)
{
    return len;
}

int fake_flush(struct conn_interface *intf)
{
    return 0;
}

int fake_error_is_recoverable(struct conn_interface *intf, int err)
{
    return 0;
}

int main()
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t *log;
    xmpp_conn_state_t state;
    xmpp_sm_state_t *sm_state;
    char *ret;
    unsigned int n;
    int callback_count = 0;

    xmpp_initialize();
    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG);
    ctx = xmpp_ctx_new(NULL, log);
    conn = xmpp_conn_new(ctx);
    sm_state = strophe_alloc(ctx, sizeof(*sm_state));
    memset(sm_state, 0, sizeof(*sm_state));
    sm_state->ctx = ctx;
    sm_state->sm_support = sm_state->sm_enabled = sm_state->can_resume = 1;
    sm_state->id = strophe_strdup(ctx, "SMID");

    xmpp_conn_set_sm_state(conn, sm_state);
    xmpp_conn_set_sm_callback(conn, callback, &callback_count);

    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 0);

    struct conn_interface intf = {fake_read,  fake_write,
                                  fake_flush, fake_flush,
                                  fake_flush, fake_error_is_recoverable,
                                  conn};
    conn->intf = intf;
    state = conn->state;
    conn->state = XMPP_STATE_CONNECTED;
    conn->sock = 123;

    xmpp_send_raw(conn, "foo", 3);
    ENSURE_EQ(xmpp_conn_send_queue_len(conn), 1);
    ENSURE_EQ(callback_count, 1);

    xmpp_run_once(ctx, 0);
    ENSURE_EQ(callback_count, 3);

    conn->state = state;

    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);
    xmpp_shutdown();

    return 0;
}
