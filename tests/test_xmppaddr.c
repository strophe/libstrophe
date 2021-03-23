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

int main()
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t *log;

    char xmppaddr_num[] = "0";
    unsigned int n;

    xmpp_initialize();
    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG);
    ctx = xmpp_ctx_new(NULL, log);
    conn = xmpp_conn_new(ctx);

    xmpp_conn_set_client_cert(conn, "tests/cert.pem", "tests/key.pem");

    xmppaddr_num[0] = xmppaddr_num[0] + xmpp_conn_cert_xmppaddr_num(conn);

    COMPARE("2", xmppaddr_num);

    for (n = 0; n < 3; ++n) {
        char *r = xmpp_conn_cert_xmppaddr(conn, n);
        switch (n) {
        case 0:
            COMPARE("very.long.username@so.the.asn1.length.is.a.valid.ascii."
                    "character",
                    r);
            break;
        case 1:
            COMPARE("second@xmpp.jid", r);
            break;
        default:
            if (r != NULL) {
                printf("\nThere shall only be two id-on-xmppAddr SANs!\nFound "
                       "another one: %s\n",
                       r);
                exit(1);
            }
            break;
        }
        free(r);
    }

    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);
    xmpp_shutdown();

    return 0;
}
