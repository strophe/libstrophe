/* tls.c
** libstrophe XMPP client library -- TLS abstraction openssl impl.
**
** Copyright (C) 2005 OGG, LCC. All rights reserved.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This software is distributed under license and may not be copied,
**  modified or distributed except as expressly authorized under the
**  terms of the license contained in the file LICENSE.txt in this
**  distribution.
*/

#include <openssl/ssl.h>
#include <openssl/applink.c>

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
#ifdef _WIN32
    RAND_screen ();
#else
    {
        char filename[512];
	char *file;
	
	filename[0] = '\0';
	file = RAND_file_name(filename, 512);

	if (file && strlen(file) != 0) {
	    RAND_load_file(filename, /*It's over */9000);
	}
    }
#endif
    SSL_library_init();
    SSL_load_error_strings();
    return;
}

void tls_shutdown(void)
{
    return;
}

void tls_logerror(tls_t *tls)
{
    char *texterror = NULL;

    switch(tls->lasterror) {
	case SSL_ERROR_NONE:
	    texterror = "No error.";
	    break;
	case SSL_ERROR_ZERO_RETURN:
	    texterror = "Connection closed.";
	    break;
	case SSL_ERROR_WANT_READ:
	    texterror = "Data waiting to read.";
	    break;
	case SSL_ERROR_WANT_WRITE:
	    texterror = "Data waiting to write.";
	    break;
	case SSL_ERROR_WANT_CONNECT:
	    texterror = "Not yet connected.";
	    break;
	case SSL_ERROR_WANT_ACCEPT:
	    texterror = "Not yet accepted.";
	    break;
	case SSL_ERROR_WANT_X509_LOOKUP:
	    texterror = "No certification.";
	    break;
	case SSL_ERROR_SYSCALL:
	    texterror = "I/O error.";
	    break;
	case SSL_ERROR_SSL:
	    texterror = "SSL library internal error";
	    break;
	default:
	    texterror = "Unknown error";
	    break;
    }

    xmpp_debug(tls->ctx, "xmpp", "SSL error: %s", texterror);
}

tls_t *tls_new(xmpp_ctx_t *ctx, sock_t sock)
{
    tls_t *tls = xmpp_alloc(ctx, sizeof(*tls));

    if (tls) {
        int ret;
	memset(tls, 0, sizeof(*tls));

	tls->ctx = ctx;
	tls->sock = sock;
	tls->ssl_ctx = SSL_CTX_new(SSLv23_client_method());

	SSL_CTX_set_client_cert_cb(tls->ssl_ctx, NULL);
	SSL_CTX_set_mode (tls->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_CTX_set_verify (tls->ssl_ctx, SSL_VERIFY_NONE, NULL);

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
    while (ret == -1) {
	ret = SSL_connect(tls->ssl);

	/* wait for something to happen on the sock before looping back */
	if (ret == -1) {
	    fd_set fds;
	    struct timeval tv;

	    tv.tv_sec = 0;
	    tv.tv_usec = 1000;

	    FD_ZERO(&fds); 
	    FD_SET(tls->sock, &fds);
    
	    select(tls->sock + 1, &fds, &fds, NULL, &tv);
	}
    }

    if (ret <= 0) {
	tls->lasterror = SSL_get_error(tls->ssl, ret);
	tls_logerror(tls);
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
	tls_logerror(tls);
	return 0;
    }

    return 1;
}

int tls_error(tls_t *tls)
{
    return tls->lasterror;
}

int tls_is_recoverable(int error)
{
    return (error == SSL_ERROR_NONE || error == SSL_ERROR_WANT_READ
	    || error == SSL_ERROR_WANT_WRITE
	    || error == SSL_ERROR_WANT_CONNECT
	    || error == SSL_ERROR_WANT_ACCEPT);
}

int tls_read(tls_t *tls, void * const buff, const size_t len)
{
    int ret = SSL_read(tls->ssl, buff, len);

    if (ret <= 0) {
	tls->lasterror = SSL_get_error(tls->ssl, ret);
	tls_logerror(tls);
    }

    return ret;
}

int tls_write(tls_t *tls, const void * const buff, const size_t len)
{
    int ret = SSL_write(tls->ssl, buff, len);

    if (ret <= 0) {
	tls->lasterror = SSL_get_error(tls->ssl, ret);
	tls_logerror(tls);
    }

    return ret;
}
