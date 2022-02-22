/* test_xmppaddr.c
** libstrophe XMPP client library -- test routines for the xmppaddr
** certificate API's
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

#include "test.h"

static int
password_callback(char *pw, size_t pw_max, xmpp_conn_t *conn, void *userdata)
{
    (void)pw_max;
    (void)userdata;
    (void)conn;
    memcpy(pw, "abc123", 7);
    return 6;
}

int main()
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t *log;
    char *client_cert[][2] = {
        {"tests/cert.pem", "tests/key.pem"},
        {"tests/cert.pem", "tests/key_encrypted.pem"},
        {NULL, "tests/cert.pfx"},
    };

    char xmppaddr_num[] = "0";
    unsigned int m, n;

    xmpp_initialize();
    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG);
    ctx = xmpp_ctx_new(NULL, log);

    for (m = 0; m < sizeof(client_cert) / sizeof(client_cert[0]); ++m) {
        conn = xmpp_conn_new(ctx);

        xmpp_conn_set_password_callback(conn, password_callback, NULL);

        xmpp_conn_set_client_cert(conn, client_cert[m][0], client_cert[m][1]);

        xmppaddr_num[0] = '0' + xmpp_conn_cert_xmppaddr_num(conn);

        COMPARE("2", xmppaddr_num);

        for (n = 0; n < 3; ++n) {
            char *r = xmpp_conn_cert_xmppaddr(conn, n);
            switch (n) {
            case 0:
                COMPARE(
                    "very.long.username@so.the.asn1.length.is.a.valid.ascii."
                    "character",
                    r);
                break;
            case 1:
                COMPARE("second@xmpp.jid", r);
                break;
            default:
                if (r != NULL) {
                    printf("\nThere shall only be two id-on-xmppAddr SANs!\n"
                           "Found another one: %s\n",
                           r);
                    exit(1);
                }
                break;
            }
            free(r);
        }
        xmpp_conn_release(conn);
    }

    xmpp_ctx_free(ctx);
    xmpp_shutdown();

    return 0;
}
