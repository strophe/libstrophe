/* tls_openssl.c
** strophe XMPP client library -- TLS abstraction openssl impl.
**
** Copyright (C) 2005-008 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  TLS implementation with OpenSSL.
 */

#include <string.h>

#ifndef _WIN32
#include <sys/select.h>
#else
#include <winsock2.h>
#endif

#include <openssl/ssl.h>
#include "common.h"
#include "tls.h"
#include "sock.h"

struct _tls {
    xmpp_ctx_t *ctx;
    sock_t sock;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int lasterror;
};

void tls_initialize(void)
{
    SSL_library_init();
    SSL_load_error_strings();
}

void tls_shutdown(void)
{
    return;
}

int tls_error(tls_t *tls)
{
    return tls->lasterror;
}

static xmpp_ctx_t *xmppctx;

static int
verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    if (preverify_ok) {
        return 1;
    } else {
        xmpp_debug(xmppctx, "TLS", "VERIFY FAILED");
        int err = X509_STORE_CTX_get_error(x509_ctx);
        const char *errstr = X509_verify_cert_error_string(err);

        X509 *cert X509_STORE_CTX_get_current_cert(x509_ctx);

        xmpp_debug(xmppctx, "TLS", "ERROR: %d: %s", err, errstr);
        return 1;
    }
}

tls_t *tls_new(xmpp_ctx_t *ctx, sock_t sock)
{
    xmppctx = ctx;
    tls_t *tls = xmpp_alloc(ctx, sizeof(*tls));

    if (tls) {
        int ret;
        memset(tls, 0, sizeof(*tls));

        tls->ctx = ctx;
        tls->sock = sock;
        tls->ssl_ctx = SSL_CTX_new(SSLv23_client_method());

        SSL_CTX_set_client_cert_cb(tls->ssl_ctx, NULL);
        SSL_CTX_set_mode (tls->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
        SSL_CTX_set_verify (tls->ssl_ctx, SSL_VERIFY_PEER, verify_callback);

        tls->ssl = SSL_new(tls->ssl_ctx);

        ret = SSL_set_fd(tls->ssl, sock);
        if (ret <= 0) {
            tls->lasterror = SSL_get_error(tls->ssl, ret);
            tls_error(tls);
            tls_free(tls);
            tls = NULL;
        }
    }

    return tls;
}

void tls_free(tls_t *tls)
{
    SSL_free(tls->ssl);
    SSL_CTX_free(tls->ssl_ctx);
    xmpp_free(tls->ctx, tls);
    return;
}

int tls_set_credentials(tls_t *tls, const char *cafilename)
{
    return -1;
}

int tls_start(tls_t *tls)
{
    int ret = -1;

    /* Since we're non-blocking, loop the connect call until it
    succeeds or fails */
    while (ret < 0) {
        ret = SSL_connect(tls->ssl);
        int err = SSL_get_error(tls->ssl, ret);
        int recoverable = tls_is_recoverable(err);

        // continue if recoverable
        if (recoverable) {
            fd_set fds;
            struct timeval tv;

            tv.tv_sec = 0;
            tv.tv_usec = 1000;

            FD_ZERO(&fds);
            FD_SET(tls->sock, &fds);

            select(tls->sock + 1, &fds, &fds, NULL, &tv);
        } else {
            ret = 1;
        }
    }

    if (ret <= 0) {
        tls->lasterror = SSL_get_error(tls->ssl, ret);
        return 0;
    }

    return 1;
}

int tls_stop(tls_t *tls)
{
    int ret;

    ret = SSL_shutdown(tls->ssl);

    if (ret <= 0) {
        tls->lasterror = SSL_get_error(tls->ssl, ret);
        return 0;
    }

    return 1;
}

int tls_is_recoverable(int error)
{
    return (error == SSL_ERROR_NONE || error == SSL_ERROR_WANT_READ
        || error == SSL_ERROR_WANT_WRITE
        || error == SSL_ERROR_WANT_CONNECT
        || error == SSL_ERROR_WANT_ACCEPT);
}

int tls_pending(tls_t *tls)
{
    return SSL_pending(tls->ssl);
}

int tls_read(tls_t *tls, void * const buff, const size_t len)
{
    int ret = SSL_read(tls->ssl, buff, len);

    if (ret <= 0) {
        tls->lasterror = SSL_get_error(tls->ssl, ret);
    }

    return ret;
}

int tls_write(tls_t *tls, const void * const buff, const size_t len)
{
    int ret = SSL_write(tls->ssl, buff, len);

    if (ret <= 0) {
        tls->lasterror = SSL_get_error(tls->ssl, ret);
    }

    return ret;
}

int tls_clear_pending_write(tls_t *tls)
{
    return 0;
}
