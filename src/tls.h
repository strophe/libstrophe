/* tls.h
** strophe XMPP client library -- TLS abstraction header
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  TLS abstraction API.
 */

#ifndef __LIBSTROPHE_TLS_H__
#define __LIBSTROPHE_TLS_H__

#include "common.h"
#include "sock.h"

typedef struct _tls tls_t;

typedef struct _dnsname_t dnsname_t;

struct _xmpp_tlscert_t {
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    char *pem;
    char *elements[XMPP_CERT_ELEMENT_MAX];
    dnsname_t *dnsnames;
};

/* provided by the real TLS implementation */

void tls_initialize(void);
void tls_shutdown(void);

tls_t *tls_new(xmpp_conn_t *conn);
void tls_free(tls_t *tls);

char *tls_id_on_xmppaddr(xmpp_conn_t *conn, unsigned int n);
unsigned int tls_id_on_xmppaddr_num(xmpp_conn_t *conn);

xmpp_tlscert_t *tls_peer_cert(xmpp_conn_t *conn);
int tls_set_credentials(tls_t *tls, const char *cafilename);

int tls_start(tls_t *tls);
int tls_stop(tls_t *tls);

int tls_error(tls_t *tls);

int tls_pending(tls_t *tls);
int tls_read(tls_t *tls, void *buff, size_t len);
int tls_write(tls_t *tls, const void *buff, size_t len);

int tls_clear_pending_write(tls_t *tls);
int tls_is_recoverable(int error);

/* provided by tls.c */

xmpp_tlscert_t *tlscert_new(xmpp_ctx_t *ctx);
int tlscert_add_dnsname(xmpp_tlscert_t *cert, const char *dnsname);

int tls_caching_password_callback(char *pw, size_t pw_max, xmpp_conn_t *conn);
void tls_clear_password_cache(xmpp_conn_t *conn);

#endif /* __LIBSTROPHE_TLS_H__ */
