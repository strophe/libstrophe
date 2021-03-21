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

#include <errno.h> /* EINTR */
#include <string.h>

#ifndef _WIN32
#include <sys/select.h>
#else
#include <winsock2.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/x509v3.h>

#include "common.h"
#include "tls.h"
#include "sock.h"

/*
 * Redefine OPENSSL_VERSION_NUMBER for LibreSSL.
 * LibreSSL and OpenSSL use different and incompatible version schemes. Solve
 * this issue in the way how nginx project did.
 */
#if (defined LIBRESSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER == 0x20000000L)
#undef OPENSSL_VERSION_NUMBER
#if (LIBRESSL_VERSION_NUMBER >= 0x2080000fL)
#define OPENSSL_VERSION_NUMBER 0x1010000fL
#elif (LIBRESSL_VERSION_NUMBER >= 0x2070000fL)
#define OPENSSL_VERSION_NUMBER 0x1000200fL
#else
#define OPENSSL_VERSION_NUMBER 0x1000107fL
#endif
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static const unsigned char *ASN1_STRING_get0_data(ASN1_STRING *asn1)
{
    return ASN1_STRING_data(asn1);
}
#endif

struct _tls {
    xmpp_ctx_t *ctx;
    sock_t sock;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    X509 *client_cert;
    int lasterror;
};

enum {
    TLS_SHUTDOWN_MAX_RETRIES = 10,
    TLS_TIMEOUT_SEC = 0,
    TLS_TIMEOUT_USEC = 100000,
};

static void _tls_sock_wait(tls_t *tls, int error);
static const char *_tls_error_str(int error, const char **tbl, size_t tbl_size);
static void _tls_set_error(tls_t *tls, int error);
static void _tls_log_error(xmpp_ctx_t *ctx);
static void _tls_dump_cert_info(tls_t *tls);
static X509 *_tls_cert_read(xmpp_conn_t *conn);
static int _tls_xaddr_nid(void);
static int _tls_name_to_xmppaddr(GENERAL_NAME *name, char **res);
static GENERAL_NAMES *_tls_cert_get_names(xmpp_conn_t *conn);

#define TLS_ERROR_STR(error, table) \
    _tls_error_str(error, table, ARRAY_SIZE(table))

#define TLS_ERROR_FIELD(x) [x] = #x
const char *tls_errors[] = {
    TLS_ERROR_FIELD(SSL_ERROR_NONE),
    TLS_ERROR_FIELD(SSL_ERROR_SSL),
    TLS_ERROR_FIELD(SSL_ERROR_WANT_READ),
    TLS_ERROR_FIELD(SSL_ERROR_WANT_WRITE),
    TLS_ERROR_FIELD(SSL_ERROR_WANT_X509_LOOKUP),
    TLS_ERROR_FIELD(SSL_ERROR_SYSCALL),
    TLS_ERROR_FIELD(SSL_ERROR_ZERO_RETURN),
    TLS_ERROR_FIELD(SSL_ERROR_WANT_CONNECT),
    TLS_ERROR_FIELD(SSL_ERROR_WANT_ACCEPT),
#ifndef LIBRESSL_VERSION_NUMBER
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    TLS_ERROR_FIELD(SSL_ERROR_WANT_ASYNC),
    TLS_ERROR_FIELD(SSL_ERROR_WANT_ASYNC_JOB),
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    TLS_ERROR_FIELD(SSL_ERROR_WANT_CLIENT_HELLO_CB),
#endif
#endif /* !LIBRESSL_VERSION_NUMBER */
};
const char *cert_errors[] = {
    TLS_ERROR_FIELD(X509_V_OK),
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    TLS_ERROR_FIELD(X509_V_ERR_UNSPECIFIED),
#endif
    TLS_ERROR_FIELD(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT),
    TLS_ERROR_FIELD(X509_V_ERR_UNABLE_TO_GET_CRL),
    TLS_ERROR_FIELD(X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE),
    TLS_ERROR_FIELD(X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE),
    TLS_ERROR_FIELD(X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY),
    TLS_ERROR_FIELD(X509_V_ERR_CERT_SIGNATURE_FAILURE),
    TLS_ERROR_FIELD(X509_V_ERR_CRL_SIGNATURE_FAILURE),
    TLS_ERROR_FIELD(X509_V_ERR_CERT_NOT_YET_VALID),
    TLS_ERROR_FIELD(X509_V_ERR_CERT_HAS_EXPIRED),
    TLS_ERROR_FIELD(X509_V_ERR_CRL_NOT_YET_VALID),
    TLS_ERROR_FIELD(X509_V_ERR_CRL_HAS_EXPIRED),
    TLS_ERROR_FIELD(X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD),
    TLS_ERROR_FIELD(X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD),
    TLS_ERROR_FIELD(X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD),
    TLS_ERROR_FIELD(X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD),
    TLS_ERROR_FIELD(X509_V_ERR_OUT_OF_MEM),
    TLS_ERROR_FIELD(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT),
    TLS_ERROR_FIELD(X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN),
    TLS_ERROR_FIELD(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY),
    TLS_ERROR_FIELD(X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE),
    TLS_ERROR_FIELD(X509_V_ERR_CERT_CHAIN_TOO_LONG),
    TLS_ERROR_FIELD(X509_V_ERR_CERT_REVOKED),
    TLS_ERROR_FIELD(X509_V_ERR_INVALID_CA),
    TLS_ERROR_FIELD(X509_V_ERR_PATH_LENGTH_EXCEEDED),
    TLS_ERROR_FIELD(X509_V_ERR_INVALID_PURPOSE),
    TLS_ERROR_FIELD(X509_V_ERR_CERT_UNTRUSTED),
    TLS_ERROR_FIELD(X509_V_ERR_CERT_REJECTED),
    TLS_ERROR_FIELD(X509_V_ERR_SUBJECT_ISSUER_MISMATCH),
    TLS_ERROR_FIELD(X509_V_ERR_AKID_SKID_MISMATCH),
    TLS_ERROR_FIELD(X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH),
    TLS_ERROR_FIELD(X509_V_ERR_KEYUSAGE_NO_CERTSIGN),
    TLS_ERROR_FIELD(X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER),
    TLS_ERROR_FIELD(X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION),
    TLS_ERROR_FIELD(X509_V_ERR_KEYUSAGE_NO_CRL_SIGN),
    TLS_ERROR_FIELD(X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION),
    TLS_ERROR_FIELD(X509_V_ERR_INVALID_NON_CA),
    TLS_ERROR_FIELD(X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED),
    TLS_ERROR_FIELD(X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE),
    TLS_ERROR_FIELD(X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED),
    TLS_ERROR_FIELD(X509_V_ERR_INVALID_EXTENSION),
    TLS_ERROR_FIELD(X509_V_ERR_INVALID_POLICY_EXTENSION),
    TLS_ERROR_FIELD(X509_V_ERR_NO_EXPLICIT_POLICY),
    TLS_ERROR_FIELD(X509_V_ERR_APPLICATION_VERIFICATION),
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    TLS_ERROR_FIELD(X509_V_ERR_DIFFERENT_CRL_SCOPE),
    TLS_ERROR_FIELD(X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE),
    TLS_ERROR_FIELD(X509_V_ERR_UNNESTED_RESOURCE),
    TLS_ERROR_FIELD(X509_V_ERR_PERMITTED_VIOLATION),
    TLS_ERROR_FIELD(X509_V_ERR_EXCLUDED_VIOLATION),
    TLS_ERROR_FIELD(X509_V_ERR_SUBTREE_MINMAX),
    TLS_ERROR_FIELD(X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE),
    TLS_ERROR_FIELD(X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX),
    TLS_ERROR_FIELD(X509_V_ERR_UNSUPPORTED_NAME_SYNTAX),
    TLS_ERROR_FIELD(X509_V_ERR_CRL_PATH_VALIDATION_ERROR),
#ifndef LIBRESSL_VERSION_NUMBER
    TLS_ERROR_FIELD(X509_V_ERR_SUITE_B_INVALID_VERSION),
    TLS_ERROR_FIELD(X509_V_ERR_SUITE_B_INVALID_ALGORITHM),
    TLS_ERROR_FIELD(X509_V_ERR_SUITE_B_INVALID_CURVE),
    TLS_ERROR_FIELD(X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM),
    TLS_ERROR_FIELD(X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED),
    TLS_ERROR_FIELD(X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256),
#endif /* !LIBRESSL_VERSION_NUMBER */
    TLS_ERROR_FIELD(X509_V_ERR_HOSTNAME_MISMATCH),
    TLS_ERROR_FIELD(X509_V_ERR_EMAIL_MISMATCH),
    TLS_ERROR_FIELD(X509_V_ERR_IP_ADDRESS_MISMATCH),
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    TLS_ERROR_FIELD(X509_V_ERR_INVALID_CALL),
    TLS_ERROR_FIELD(X509_V_ERR_STORE_LOOKUP),
#ifndef LIBRESSL_VERSION_NUMBER
    TLS_ERROR_FIELD(X509_V_ERR_PATH_LOOP),
    TLS_ERROR_FIELD(X509_V_ERR_DANE_NO_MATCH),
    TLS_ERROR_FIELD(X509_V_ERR_EE_KEY_TOO_SMALL),
    TLS_ERROR_FIELD(X509_V_ERR_CA_KEY_TOO_SMALL),
    TLS_ERROR_FIELD(X509_V_ERR_CA_MD_TOO_WEAK),
    TLS_ERROR_FIELD(X509_V_ERR_NO_VALID_SCTS),
    TLS_ERROR_FIELD(X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION),
    TLS_ERROR_FIELD(X509_V_ERR_OCSP_VERIFY_NEEDED),
    TLS_ERROR_FIELD(X509_V_ERR_OCSP_VERIFY_FAILED),
    TLS_ERROR_FIELD(X509_V_ERR_OCSP_CERT_UNKNOWN),
#endif /* !LIBRESSL_VERSION_NUMBER */
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
};
#undef TLS_ERROR_FIELD

void tls_initialize(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
#else
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
#endif
    /* init xmppAddr OID */
    _tls_xaddr_nid();
}

void tls_shutdown(void)
{
    /*
     * FIXME: Don't free global tables, program or other libraries may use
     * openssl after libstrophe finalization. Maybe better leak some fixed
     * memory rather than cause random crashes of the main program.
     */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OBJ_cleanup();
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    SSL_COMP_free_compression_methods();
#endif
#if OPENSSL_VERSION_NUMBER < 0x10000000L
    ERR_remove_state(0);
#else
    ERR_remove_thread_state(NULL);
#endif
#endif
}

int tls_error(tls_t *tls)
{
    return tls->lasterror;
}

/** Search through the SubjectAlternativeNames and return the next
 *  id-on-xmppAddr element starting from `n`.
 */
char *tls_id_on_xmppaddr(xmpp_conn_t *conn, unsigned int n)
{
    char *ret = NULL;
    int i, j;
    GENERAL_NAMES *names = _tls_cert_get_names(conn);
    if (!names)
        return NULL;
    int num_names = sk_GENERAL_NAME_num(names);
    for (i = j = 0; i < num_names; ++i) {
        char *res;
        GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
        if (name == NULL)
            break;
        if (_tls_name_to_xmppaddr(name, &res))
            continue;
        if (j == (int)n) {
            xmpp_debug(conn->ctx, "tls", "extracted jid %s from id-on-xmppAddr",
                       res);
            ret = xmpp_strdup(conn->ctx, res);
            OPENSSL_free(res);
            break;
        }
        j++;
        OPENSSL_free(res);
    }
    GENERAL_NAMES_free(names);
    return ret;
}

unsigned int tls_id_on_xmppaddr_num(xmpp_conn_t *conn)
{
    unsigned int ret = 0;
    GENERAL_NAMES *names = _tls_cert_get_names(conn);
    if (!names)
        return 0;
    int j, num_names = sk_GENERAL_NAME_num(names);
    for (j = 0; j < num_names; ++j) {
        GENERAL_NAME *name = sk_GENERAL_NAME_value(names, j);
        if (_tls_name_to_xmppaddr(name, NULL))
            continue;
        ret++;
    }
    GENERAL_NAMES_free(names);
    return ret;
}

tls_t *tls_new(xmpp_conn_t *conn)
{
    tls_t *tls = xmpp_alloc(conn->ctx, sizeof(*tls));
    int mode;

    if (tls) {
        int ret;
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        /* Hostname verification is supported in OpenSSL 1.0.2 and newer. */
        X509_VERIFY_PARAM *param;
#endif
        memset(tls, 0, sizeof(*tls));

        tls->ctx = conn->ctx;
        tls->sock = conn->sock;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        tls->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#else
        tls->ssl_ctx = SSL_CTX_new(TLS_client_method());
#endif
        if (tls->ssl_ctx == NULL)
            goto err;

        /* Enable bug workarounds. */
        SSL_CTX_set_options(tls->ssl_ctx, SSL_OP_ALL);

        /* Disable insecure SSL/TLS versions. */
        SSL_CTX_set_options(tls->ssl_ctx, SSL_OP_NO_SSLv2); /* DROWN */
        SSL_CTX_set_options(tls->ssl_ctx, SSL_OP_NO_SSLv3); /* POODLE */
        SSL_CTX_set_options(tls->ssl_ctx, SSL_OP_NO_TLSv1); /* BEAST */

        if (conn->tls_client_cert && conn->tls_client_key) {
            tls->client_cert = _tls_cert_read(conn);
            if (!tls->client_cert) {
                xmpp_error(tls->ctx, "tls",
                           "could not read client certificate");
                goto err_free_ctx;
            }

            SSL_CTX_use_certificate_file(tls->ssl_ctx, conn->tls_client_cert,
                                         SSL_FILETYPE_PEM);
            SSL_CTX_use_PrivateKey_file(tls->ssl_ctx, conn->tls_client_key,
                                        SSL_FILETYPE_PEM);
        } else {
            /* If the server asks for a client certificate, don't send one. */
            SSL_CTX_set_client_cert_cb(tls->ssl_ctx, NULL);
        }

        SSL_CTX_set_mode(tls->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

        ret = SSL_CTX_set_default_verify_paths(tls->ssl_ctx);
        if (ret == 0 && !conn->tls_trust) {
            /*
             * Returns 1 on success and 0 on failure. A missing default
             * location is still treated as a success.
             * Ignore errors when XMPP_CONN_FLAG_TRUST_TLS is set.
             */
            xmpp_error(tls->ctx, "tls",
                       "SSL_CTX_set_default_verify_paths() failed");
            goto err_free_cert;
        }

        tls->ssl = SSL_new(tls->ssl_ctx);
        if (tls->ssl == NULL)
            goto err_free_cert;

#if OPENSSL_VERSION_NUMBER >= 0x0908060L && !defined(OPENSSL_NO_TLSEXT)
        /* Enable SNI. */
        SSL_set_tlsext_host_name(tls->ssl, conn->domain);
#endif

        /* Trust server's certificate when user sets the flag explicitly. */
        mode = conn->tls_trust ? SSL_VERIFY_NONE : SSL_VERIFY_PEER;
        SSL_set_verify(tls->ssl, mode, NULL);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        /* Hostname verification is supported in OpenSSL 1.0.2 and newer. */
        param = SSL_get0_param(tls->ssl);

        /*
         * Allow only complete wildcards.  RFC 6125 discourages wildcard usage
         * completely, and lists internationalized domain names as a reason
         * against partial wildcards.
         * See https://tools.ietf.org/html/rfc6125#section-7.2 for more
         * information.
         */
        X509_VERIFY_PARAM_set_hostflags(param,
                                        X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        X509_VERIFY_PARAM_set1_host(param, conn->domain, 0);
#endif

        ret = SSL_set_fd(tls->ssl, conn->sock);
        if (ret <= 0)
            goto err_free_ssl;
    }

    return tls;

err_free_ssl:
    SSL_free(tls->ssl);
err_free_cert:
    X509_free(tls->client_cert);
err_free_ctx:
    SSL_CTX_free(tls->ssl_ctx);
err:
    xmpp_free(conn->ctx, tls);
    _tls_log_error(conn->ctx);
    return NULL;
}

void tls_free(tls_t *tls)
{
    SSL_free(tls->ssl);
    X509_free(tls->client_cert);
    SSL_CTX_free(tls->ssl_ctx);
    xmpp_free(tls->ctx, tls);
}

int tls_set_credentials(tls_t *tls, const char *cafilename)
{
    UNUSED(tls);
    UNUSED(cafilename);
    return -1;
}

int tls_start(tls_t *tls)
{
    int error;
    int ret;
    long x509_res;

    /* Since we're non-blocking, loop the connect call until it
       succeeds or fails */
    while (1) {
        ret = SSL_connect(tls->ssl);
        error = ret <= 0 ? SSL_get_error(tls->ssl, ret) : 0;

        if (ret == -1 && tls_is_recoverable(error)) {
            /* wait for something to happen on the sock before looping back */
            _tls_sock_wait(tls, error);
            continue;
        }

        /* success or fatal error */
        break;
    }

    x509_res = SSL_get_verify_result(tls->ssl);
    if (x509_res == X509_V_OK) {
        xmpp_debug(tls->ctx, "tls", "Certificate verification passed");
    } else {
        xmpp_debug(tls->ctx, "tls",
                   "Certificate verification FAILED, result=%s(%ld)",
                   TLS_ERROR_STR((int)x509_res, cert_errors), x509_res);
    }
    _tls_dump_cert_info(tls);

    _tls_set_error(tls, error);
    return ret <= 0 ? 0 : 1;
}

int tls_stop(tls_t *tls)
{
    int retries = 0;
    int error;
    int ret;

    /* According to OpenSSL.org, we must not call SSL_shutdown(3)
       if a previous fatal error has occurred on a connection. */
    if (tls->lasterror == SSL_ERROR_SYSCALL || tls->lasterror == SSL_ERROR_SSL)
        return 1;

    while (1) {
        ++retries;
        ret = SSL_shutdown(tls->ssl);
        error = ret < 0 ? SSL_get_error(tls->ssl, ret) : 0;
        if (ret == 1 || !tls_is_recoverable(error) ||
            retries >= TLS_SHUTDOWN_MAX_RETRIES) {
            break;
        }
        _tls_sock_wait(tls, error);
    }
    if (error == SSL_ERROR_SYSCALL && errno == 0) {
        /*
         * Handle special case when peer closes connection instead of
         * proper shutdown.
         */
        error = 0;
        ret = 1;
    }
    _tls_set_error(tls, error);

    return ret <= 0 ? 0 : 1;
}

int tls_is_recoverable(int error)
{
    return (error == SSL_ERROR_NONE || error == SSL_ERROR_WANT_READ ||
            error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_CONNECT ||
            error == SSL_ERROR_WANT_ACCEPT);
}

int tls_pending(tls_t *tls)
{
    return SSL_pending(tls->ssl);
}

int tls_read(tls_t *tls, void *buff, size_t len)
{
    int ret;

    ret = SSL_read(tls->ssl, buff, len);
    _tls_set_error(tls, ret <= 0 ? SSL_get_error(tls->ssl, ret) : 0);

    return ret;
}

int tls_write(tls_t *tls, const void *buff, size_t len)
{
    int ret;

    ret = SSL_write(tls->ssl, buff, len);
    _tls_set_error(tls, ret <= 0 ? SSL_get_error(tls->ssl, ret) : 0);

    return ret;
}

int tls_clear_pending_write(tls_t *tls)
{
    UNUSED(tls);
    return 0;
}

static void _tls_sock_wait(tls_t *tls, int error)
{
    struct timeval tv;
    fd_set rfds;
    fd_set wfds;
    int nfds;
    int ret;

    if (error == SSL_ERROR_NONE)
        return;

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    if (error == SSL_ERROR_WANT_READ)
        FD_SET(tls->sock, &rfds);
    if (error == SSL_ERROR_WANT_WRITE)
        FD_SET(tls->sock, &wfds);
    nfds = (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
               ? tls->sock + 1
               : 0;
    do {
        tv.tv_sec = TLS_TIMEOUT_SEC;
        tv.tv_usec = TLS_TIMEOUT_USEC;
        ret = select(nfds, &rfds, &wfds, NULL, &tv);
    } while (ret == -1 && errno == EINTR);
}

static const char *_tls_error_str(int error, const char **tbl, size_t tbl_size)
{
    return (error >= 0 && (size_t)error < tbl_size) ? tbl[error] : "UNKNOWN";
}

static void _tls_set_error(tls_t *tls, int error)
{
    if (error != 0 && !tls_is_recoverable(error)) {
        xmpp_debug(tls->ctx, "tls", "error=%s(%d) errno=%d",
                   TLS_ERROR_STR(error, tls_errors), error, errno);
        _tls_log_error(tls->ctx);
    }
    tls->lasterror = error;
}

static void _tls_log_error(xmpp_ctx_t *ctx)
{
    unsigned long e;
    char buf[256];

    do {
        e = ERR_get_error();
        if (e != 0) {
            ERR_error_string_n(e, buf, sizeof(buf));
            xmpp_debug(ctx, "tls", "%s", buf);
        }
    } while (e != 0);
}

static void _tls_dump_cert_info(tls_t *tls)
{
    X509 *cert;
    char *name;

    cert = SSL_get_peer_certificate(tls->ssl);
    if (cert == NULL)
        xmpp_debug(tls->ctx, "tls", "Certificate was not presented by peer");
    else {
        name = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
        if (name != NULL) {
            xmpp_debug(tls->ctx, "tls", "Subject=%s", name);
            OPENSSL_free(name);
        }
        name = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
        if (name != NULL) {
            xmpp_debug(tls->ctx, "tls", "Issuer=%s", name);
            OPENSSL_free(name);
        }
        X509_free(cert);
    }
}

static X509 *_tls_cert_read(xmpp_conn_t *conn)
{
    if (conn->tls && conn->tls->client_cert)
        return conn->tls->client_cert;
    BIO *f = BIO_new_file(conn->tls_client_cert, "r");
    if (!f) {
        xmpp_debug(conn->ctx, "tls", "f == NULL");
        return NULL;
    }
    X509 *c = PEM_read_bio_X509(f, NULL, NULL, NULL);
    BIO_free(f);
    if (!c) {
        unsigned long error;
        while ((error = ERR_get_error()) != 0) {
            xmpp_debug(conn->ctx, "tls", "c == NULL: %s",
                       ERR_error_string(error, NULL));
        }
    }
    return c;
}

static int _tls_xaddr_nid(void)
{
    static int xaddr_nid = NID_undef;
    if (xaddr_nid == NID_undef) {
        xaddr_nid = OBJ_create("1.3.6.1.5.5.7.8.5", "id-on-xmppAddr",
                               "XmppAddr Identifier");
    }
    return xaddr_nid;
}

static GENERAL_NAMES *_tls_cert_get_names(xmpp_conn_t *conn)
{
    X509 *client_cert;
    GENERAL_NAMES *names = NULL;
    client_cert = _tls_cert_read(conn);
    if (!client_cert)
        return NULL;
    int san = X509_get_ext_by_NID(client_cert, NID_subject_alt_name, 0);
    X509_EXTENSION *san_ext = X509_get_ext(client_cert, san);
    if (!san_ext)
        goto OUT;
    ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(san_ext);
    if (!data)
        goto OUT;
    const unsigned char *d = ASN1_STRING_get0_data(data);
    if (!d)
        goto OUT;
    names = d2i_GENERAL_NAMES(NULL, &d, ASN1_STRING_length(data));
OUT:
    if (!conn->tls || !conn->tls->client_cert)
        X509_free(client_cert);
    return names;
}

/** Convert GENERAL_NAME* to a string
 *
 *  This checks whether the GENERAL_NAME* that is given has the
 *  correct id-on-xmppAddr set and then optionally converts this
 *  form ASN.1 to a string/char*.
 *
 *  When `res` pointer is set to NULL this method doesn't allocate
 *  the result but only checks whether it is in the correct format.
 *
 *  @param name Pointer to the GENERAL_NAME that shall be converted
 *  @param res Result-pointer (optional, can be NULL)
 *
 *  @return classic Unix style - 0=success, 1=error
 */
static int _tls_name_to_xmppaddr(GENERAL_NAME *name, char **res)
{
    ASN1_OBJECT *oid;
    ASN1_TYPE *val;
    if (!name || name->type != GEN_OTHERNAME)
        return 1;
    if (GENERAL_NAME_get0_otherName(name, &oid, &val) == 0)
        return 1;
    if (OBJ_obj2nid(oid) != _tls_xaddr_nid() || !val)
        return 1;
    if (!res)
        return 0;
    if (ASN1_STRING_to_UTF8((unsigned char **)res, val->value.asn1_string) < 0)
        return 1;
    return 0;
}
