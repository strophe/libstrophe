/* tls.c
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
 *  TLS implementation with GNUTLS
 */

#include <gnutls/gnutls.h>

#include "common.h"
#include "tls.h"
#include "sock.h"

/* FIXME this shouldn't be a constant string */
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"

struct _tls {
    xmpp_ctx_t *ctx; /* do we need this? */
    sock_t sock;
    gnutls_session_t session;
    gnutls_certificate_credentials_t cred;
    int lasterror;
};

void tls_initialize(void)
{
    /* initialize the GNU TLS global state */
    gnutls_global_init();

    /* TODO: wire in xmpp_ctx_t allocator somehow?
       unfortunately in gnutls it's global, so we can
       only do so much. */
}

void tls_shutdown(void)
{
    /* tear down the GNU TLS global state */
    gnutls_global_deinit();
}

tls_t *tls_new(xmpp_ctx_t *ctx, sock_t sock)
{
    tls_t *tls = xmpp_alloc(ctx, sizeof(tls_t));

    if (tls) {
        tls->ctx = ctx;
        tls->sock = sock;
        gnutls_init(&tls->session, GNUTLS_CLIENT);

        gnutls_certificate_allocate_credentials(&tls->cred);
        tls_set_credentials(tls, CAFILE);

        gnutls_set_default_priority(tls->session);

        /* fixme: this may require setting a callback on win32? */
        gnutls_transport_set_int(tls->session, sock);
    }

    return tls;
}

void tls_free(tls_t *tls)
{
    gnutls_deinit(tls->session);
    gnutls_certificate_free_credentials(tls->cred);
    xmpp_free(tls->ctx, tls);
}

int tls_set_credentials(tls_t *tls, const char *cafilename)
{
    int err;

    /* set trusted credentials -- takes a .pem filename */
    err = gnutls_certificate_set_x509_trust_file(tls->cred,
            cafilename, GNUTLS_X509_FMT_PEM);
    if (err >= 0) {
        err = gnutls_credentials_set(tls->session, GNUTLS_CRD_CERTIFICATE,
                                     tls->cred);
    }
    tls->lasterror = err;

    return err == GNUTLS_E_SUCCESS;
}

int tls_start(tls_t *tls)
{
    sock_set_blocking(tls->sock);
    tls->lasterror = gnutls_handshake(tls->session);
    sock_set_nonblocking(tls->sock);

    return tls->lasterror == GNUTLS_E_SUCCESS;
}

int tls_stop(tls_t *tls)
{
    tls->lasterror = gnutls_bye(tls->session, GNUTLS_SHUT_RDWR);
    return tls->lasterror == GNUTLS_E_SUCCESS;
}

int tls_error(tls_t *tls)
{
    return tls->lasterror;
}

int tls_is_recoverable(int error)
{
    return !gnutls_error_is_fatal(error);
}

int tls_pending(tls_t *tls)
{
    return gnutls_record_check_pending (tls->session);
}

int tls_read(tls_t *tls, void * const buff, const size_t len)
{
    int ret;

    ret = gnutls_record_recv(tls->session, buff, len);
    tls->lasterror = ret < 0 ? ret : 0;

    return ret;
}

int tls_write(tls_t *tls, const void * const buff, const size_t len)
{
    int ret;

    ret = gnutls_record_send(tls->session, buff, len);
    tls->lasterror = ret < 0 ? ret : 0;

    return ret;
}

int tls_clear_pending_write(tls_t *tls)
{
    return 0;
}
