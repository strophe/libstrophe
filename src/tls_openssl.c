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
#include <openssl/pkcs12.h>

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

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#define STROPHE_ERR_func_error_string(e) ERR_func_error_string(e)
#else
#define STROPHE_ERR_func_error_string(e) ""
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static const unsigned char *ASN1_STRING_get0_data(ASN1_STRING *asn1)
{
    return ASN1_STRING_data(asn1);
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined LIBRESSL_VERSION_NUMBER
static int SSL_CTX_use_cert_and_key(SSL_CTX *ctx,
                                    X509 *x509,
                                    EVP_PKEY *privatekey,
                                    STACK_OF(X509) * chain,
                                    int override)
{
    UNUSED(override);
    if (!ctx)
        return 0;
    if (x509 && !SSL_CTX_use_certificate(ctx, x509))
        return 0;
    if (privatekey && !SSL_CTX_use_PrivateKey(ctx, privatekey))
        return 0;
#ifdef SSL_CTX_set1_chain
    if (chain && !SSL_CTX_set1_chain(ctx, chain))
        return 0;
#else
    UNUSED(chain);
#endif
    return 1;
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10000000L
static int GENERAL_NAME_get0_otherName(const GENERAL_NAME *gen,
                                       ASN1_OBJECT **poid,
                                       ASN1_TYPE **pvalue)
{
    if (gen->type != GEN_OTHERNAME)
        return 0;
    if (poid)
        *poid = gen->d.otherName->type_id;
    if (pvalue)
        *pvalue = gen->d.otherName->value;
    return 1;
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
static X509 *
_tls_cert_read_p12(xmpp_conn_t *conn, EVP_PKEY **pkey, STACK_OF(X509) * *ca);
static int _tls_xaddr_nid(void);
static int _tls_xmppaddr_to_string(GENERAL_NAME *name, char **res);
static int _tls_dnsname_to_string(GENERAL_NAME *name, char **res);
static GENERAL_NAMES *_tls_conn_get_names(xmpp_conn_t *conn);
static GENERAL_NAMES *_tls_cert_get_names(X509 *client_cert);

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
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    TLS_ERROR_FIELD(X509_V_ERR_OCSP_VERIFY_NEEDED),
    TLS_ERROR_FIELD(X509_V_ERR_OCSP_VERIFY_FAILED),
    TLS_ERROR_FIELD(X509_V_ERR_OCSP_CERT_UNKNOWN),
#endif /* OPENSSL_VERSION_NUMBER >= 0x10101000L */
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
    GENERAL_NAMES *names = _tls_conn_get_names(conn);
    if (!names) {
        _tls_log_error(conn->ctx);
        return NULL;
    }
    int num_names = sk_GENERAL_NAME_num(names);
    for (i = j = 0; i < num_names; ++i) {
        char *res;
        GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
        if (name == NULL)
            break;
        if (_tls_xmppaddr_to_string(name, &res))
            continue;
        if (j == (int)n) {
            strophe_debug(conn->ctx, "tls",
                          "extracted jid %s from id-on-xmppAddr", res);
            ret = strophe_strdup(conn->ctx, res);
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
    GENERAL_NAMES *names = _tls_conn_get_names(conn);
    if (!names) {
        _tls_log_error(conn->ctx);
        return 0;
    }
    int j, num_names = sk_GENERAL_NAME_num(names);
    for (j = 0; j < num_names; ++j) {
        GENERAL_NAME *name = sk_GENERAL_NAME_value(names, j);
        if (_tls_xmppaddr_to_string(name, NULL))
            continue;
        ret++;
    }
    GENERAL_NAMES_free(names);
    return ret;
}

static int _convert_ASN1TIME(ASN1_TIME *ansi_time, char *buf, size_t len)
{
    BIO *bio = BIO_new(BIO_s_mem());
    int rc = ASN1_TIME_print(bio, ansi_time);
    if (rc <= 0) {
        BIO_free(bio);
        return 0;
    }
    rc = BIO_gets(bio, buf, len);
    if (rc <= 0) {
        BIO_free(bio);
        return 0;
    }
    BIO_free(bio);
    return 1;
}

static char *_asn1_time_to_str(const xmpp_ctx_t *ctx, ASN1_TIME *t)
{
    char buf[128];
    int res = _convert_ASN1TIME(t, buf, sizeof(buf));
    if (res) {
        return strophe_strdup(ctx, buf);
    }
    return NULL;
}

static char *
_get_fingerprint(const xmpp_ctx_t *ctx, X509 *err_cert, xmpp_cert_element_t el)
{
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int len;
    const EVP_MD *digest;
    switch (el) {
    case XMPP_CERT_FINGERPRINT_SHA1:
        digest = EVP_sha1();
        break;
    case XMPP_CERT_FINGERPRINT_SHA256:
        digest = EVP_sha256();
        break;
    default:
        return NULL;
    }
    if (X509_digest(err_cert, digest, buf, &len) != 0) {
        char fingerprint[4 * EVP_MAX_MD_SIZE];
        hex_encode(fingerprint, buf, len);
        return strophe_strdup(ctx, fingerprint);
    }
    return NULL;
}

static char *
_get_alg(const xmpp_ctx_t *ctx, X509 *err_cert, xmpp_cert_element_t el)
{
    int alg_nid = NID_undef;

    switch (el) {
    case XMPP_CERT_KEYALG: {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        alg_nid = OBJ_obj2nid(err_cert->cert_info->key->algor->algorithm);
#else
        X509_PUBKEY *pubkey = X509_get_X509_PUBKEY(err_cert);
        ASN1_OBJECT *ppkalg = NULL;
        if (X509_PUBKEY_get0_param(&ppkalg, NULL, NULL, NULL, pubkey)) {
            alg_nid = OBJ_obj2nid(ppkalg);
        }
#endif
    } break;
    case XMPP_CERT_SIGALG: {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        alg_nid = OBJ_obj2nid(err_cert->sig_alg->algorithm);
#else
        const X509_ALGOR *palg;
        X509_get0_signature(NULL, &palg, err_cert);
        alg_nid = OBJ_obj2nid(palg->algorithm);
#endif
    } break;
    default:
        break;
    }
    if (alg_nid != NID_undef) {
        const char *alg = OBJ_nid2ln(alg_nid);
        if (alg) {
            return strophe_strdup(ctx, alg);
        }
    }
    return NULL;
}

static xmpp_tlscert_t *_x509_to_tlscert(xmpp_ctx_t *ctx, X509 *cert)
{
    char *subject, *issuer, buf[32];
    xmpp_tlscert_t *tlscert = tlscert_new(ctx);
    if (!tlscert)
        return NULL;

    BIO *b = BIO_new(BIO_s_mem());
    if (!b)
        goto error_out;
    PEM_write_bio_X509(b, cert);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b, &bptr);
    tlscert->pem = strophe_alloc(ctx, bptr->length + 1);
    if (!tlscert->pem)
        goto error_out;
    memcpy(tlscert->pem, bptr->data, bptr->length);
    tlscert->pem[bptr->length] = '\0';
    BIO_free(b);

    subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    if (!subject)
        goto error_out;
    tlscert->elements[XMPP_CERT_SUBJECT] = strophe_strdup(ctx, subject);
    OPENSSL_free(subject);
    issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    if (!issuer)
        goto error_out;
    tlscert->elements[XMPP_CERT_ISSUER] = strophe_strdup(ctx, issuer);
    OPENSSL_free(issuer);

    tlscert->elements[XMPP_CERT_NOTBEFORE] =
        _asn1_time_to_str(ctx, X509_get_notBefore(cert));
    tlscert->elements[XMPP_CERT_NOTAFTER] =
        _asn1_time_to_str(ctx, X509_get_notAfter(cert));

    tlscert->elements[XMPP_CERT_FINGERPRINT_SHA1] =
        _get_fingerprint(ctx, cert, XMPP_CERT_FINGERPRINT_SHA1);
    tlscert->elements[XMPP_CERT_FINGERPRINT_SHA256] =
        _get_fingerprint(ctx, cert, XMPP_CERT_FINGERPRINT_SHA256);

    strophe_snprintf(buf, sizeof(buf), "%ld", X509_get_version(cert) + 1);
    tlscert->elements[XMPP_CERT_VERSION] = strophe_strdup(ctx, buf);

    tlscert->elements[XMPP_CERT_KEYALG] = _get_alg(ctx, cert, XMPP_CERT_KEYALG);
    tlscert->elements[XMPP_CERT_SIGALG] = _get_alg(ctx, cert, XMPP_CERT_SIGALG);

    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (bn) {
        char *serialnumber = BN_bn2hex(bn);
        if (serialnumber) {
            tlscert->elements[XMPP_CERT_SERIALNUMBER] =
                strophe_strdup(ctx, serialnumber);
            OPENSSL_free(serialnumber);
        }
        BN_free(bn);
    }

    GENERAL_NAMES *names = _tls_cert_get_names(cert);
    if (names) {
        int j, num_names = sk_GENERAL_NAME_num(names);
        size_t n = 0;
        for (j = 0; j < num_names; ++j) {
            char *res;
            GENERAL_NAME *name = sk_GENERAL_NAME_value(names, j);
            if (_tls_dnsname_to_string(name, &res))
                continue;
            if (tlscert_add_dnsname(tlscert, res))
                strophe_debug(ctx, "tls", "Can't store dnsName(%zu): %s", n,
                              res);
            n++;
            OPENSSL_free(res);
        }
        GENERAL_NAMES_free(names);
    }

    return tlscert;
error_out:
    xmpp_tlscert_free(tlscert);
    return NULL;
}

static int _tls_verify(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    if (preverify_ok == 1)
        return 1;

    SSL *ssl = X509_STORE_CTX_get_ex_data(x509_ctx,
                                          SSL_get_ex_data_X509_STORE_CTX_idx());
    xmpp_conn_t *conn = SSL_get_app_data(ssl);

    if (!conn->certfail_handler) {
        strophe_error(conn->ctx, "tls",
                      "No certfail handler set, canceling connection attempt");
        return 0;
    }

    X509 *err_cert = X509_STORE_CTX_get_current_cert(x509_ctx);

    xmpp_tlscert_t *tlscert = _x509_to_tlscert(conn->ctx, err_cert);

    if (!tlscert)
        return 0;

    strophe_debug(conn->ctx, "tls", "preverify_ok:%d\nSubject: %s\nIssuer: %s",
                  preverify_ok, tlscert->elements[XMPP_CERT_SUBJECT],
                  tlscert->elements[XMPP_CERT_ISSUER]);

    int ret = conn->certfail_handler(
        tlscert,
        X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx)));

    xmpp_tlscert_free(tlscert);

    return ret;
}

static int _tls_password_callback(char *buf, int size, int rwflag, void *u)
{
    UNUSED(rwflag);
    return tls_caching_password_callback(buf, size, u);
}

tls_t *tls_new(xmpp_conn_t *conn)
{
    tls_t *tls = strophe_alloc(conn->ctx, sizeof(*tls));

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

        if (conn->password_callback) {
            SSL_CTX_set_default_passwd_cb(tls->ssl_ctx, _tls_password_callback);
            SSL_CTX_set_default_passwd_cb_userdata(tls->ssl_ctx, conn);
        }

        if (conn->tls_client_cert && conn->tls_client_key) {
            unsigned int retries = 0;
            tls->client_cert = _tls_cert_read(conn);
            if (!tls->client_cert) {
                strophe_error(tls->ctx, "tls",
                              "could not read client certificate");
                goto err_free_ctx;
            }

            SSL_CTX_use_certificate_file(tls->ssl_ctx, conn->tls_client_cert,
                                         SSL_FILETYPE_PEM);
            while (retries++ < conn->password_retries) {
                if (SSL_CTX_use_PrivateKey_file(
                        tls->ssl_ctx, conn->tls_client_key, SSL_FILETYPE_PEM)) {
                    break;
                }
                tls_clear_password_cache(conn);
                unsigned long err = ERR_peek_error();
                if ((ERR_GET_LIB(err) == ERR_LIB_EVP &&
                     ERR_GET_REASON(err) == EVP_R_BAD_DECRYPT) ||
                    (ERR_GET_LIB(err) == ERR_LIB_PEM &&
                     ERR_GET_REASON(err) == PEM_R_BAD_DECRYPT)) {
                    strophe_debug(tls->ctx, "tls", "wrong password?");
                    continue;
                }
                strophe_error(tls->ctx, "tls",
                              "could not use private key %d %d",
                              ERR_GET_LIB(err), ERR_GET_REASON(err));
                goto err_free_ctx;
            }
        } else if (conn->tls_client_cert) {
            EVP_PKEY *pkey = NULL;
            STACK_OF(X509) *ca = NULL;
            X509 *cert = _tls_cert_read_p12(conn, &pkey, &ca);
            if (!cert) {
                goto err_free_ctx;
            }

            SSL_CTX_use_cert_and_key(tls->ssl_ctx, cert, pkey, ca, 1);

            if (pkey)
                EVP_PKEY_free(pkey);
            if (ca)
                sk_X509_pop_free(ca, X509_free);
            tls->client_cert = cert;
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
            strophe_error(tls->ctx, "tls",
                          "SSL_CTX_set_default_verify_paths() failed");
            goto err_free_cert;
        }

        if (conn->tls_cafile || conn->tls_capath) {
            if (SSL_CTX_load_verify_locations(tls->ssl_ctx, conn->tls_cafile,
                                              conn->tls_capath) == 0) {
                strophe_error(tls->ctx, "tls",
                              "SSL_CTX_load_verify_locations() failed");
                goto err_free_cert;
            }
        }

        tls->ssl = SSL_new(tls->ssl_ctx);
        if (tls->ssl == NULL)
            goto err_free_cert;

#if OPENSSL_VERSION_NUMBER >= 0x0908060L && !defined(OPENSSL_NO_TLSEXT)
        /* Enable SNI. */
        SSL_set_tlsext_host_name(tls->ssl, conn->domain);
#endif

        /* Trust server's certificate when user sets the flag explicitly.
         * Otherwise call the verification callback */
        if (conn->tls_trust)
            SSL_set_verify(tls->ssl, SSL_VERIFY_NONE, NULL);
        else
            SSL_set_verify(tls->ssl, SSL_VERIFY_PEER, _tls_verify);
        SSL_set_app_data(tls->ssl, conn);
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
    strophe_free(conn->ctx, tls);
    _tls_log_error(conn->ctx);
    return NULL;
}

void tls_free(tls_t *tls)
{
    SSL_free(tls->ssl);
    X509_free(tls->client_cert);
    SSL_CTX_free(tls->ssl_ctx);
    strophe_free(tls->ctx, tls);
}

xmpp_tlscert_t *tls_peer_cert(xmpp_conn_t *conn)
{
    if (conn && conn->tls && conn->tls->ssl) {
        X509 *cert = SSL_get_peer_certificate(conn->tls->ssl);
        if (cert) {
            xmpp_tlscert_t *tlscert = _x509_to_tlscert(conn->ctx, cert);
            X509_free(cert);
            return tlscert;
        }
    }
    return NULL;
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
        strophe_debug(tls->ctx, "tls", "Certificate verification passed");
    } else {
        strophe_debug(tls->ctx, "tls",
                      "Certificate verification FAILED, result=%s(%ld)",
                      TLS_ERROR_STR((int)x509_res, cert_errors), x509_res);
        if (ret > 0)
            strophe_debug(tls->ctx, "tls", "User decided to connect anyways");
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
        strophe_debug(tls->ctx, "tls", "error=%s(%d) errno=%d lasterror=%d",
                      TLS_ERROR_STR(error, tls_errors), error, errno,
                      tls->lasterror);
        _tls_log_error(tls->ctx);
    } else if (tls->lasterror && tls->lasterror != error) {
        strophe_debug_verbose(1, tls->ctx, "tls", "overwrite lasterror=%d",
                              tls->lasterror);
    }
    tls->lasterror = error;
}

static void _tls_log_error(xmpp_ctx_t *ctx)
{
    unsigned long e;

    do {
        e = ERR_get_error();
        if (e != 0) {
            strophe_debug(
                ctx, "tls", "error:%08X:%s:%s:%s", e, ERR_lib_error_string(e),
                STROPHE_ERR_func_error_string(e), ERR_reason_error_string(e));
        }
    } while (e != 0);
}

static void _tls_dump_cert_info(tls_t *tls)
{
    X509 *cert;
    char *name;

    cert = SSL_get_peer_certificate(tls->ssl);
    if (cert == NULL)
        strophe_debug(tls->ctx, "tls", "Certificate was not presented by peer");
    else {
        name = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
        if (name != NULL) {
            strophe_debug(tls->ctx, "tls", "Subject=%s", name);
            OPENSSL_free(name);
        }
        name = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
        if (name != NULL) {
            strophe_debug(tls->ctx, "tls", "Issuer=%s", name);
            OPENSSL_free(name);
        }
        X509_free(cert);
    }
}

static X509 *_tls_cert_read_x509(xmpp_conn_t *conn)
{
    if (conn->tls && conn->tls->client_cert)
        return conn->tls->client_cert;
    BIO *f = BIO_new_file(conn->tls_client_cert, "r");
    if (!f) {
        strophe_debug(conn->ctx, "tls", "f == NULL");
        return NULL;
    }
    X509 *c = PEM_read_bio_X509(f, NULL, NULL, NULL);
    BIO_free(f);
    if (!c) {
        _tls_log_error(conn->ctx);
    }
    return c;
}

static int _tls_parse_p12(PKCS12 *p12,
                          const char *pass,
                          EVP_PKEY **pkey,
                          X509 **cert,
                          STACK_OF(X509) * *ca)
{
    /* For some reason `PKCS12_parse()` fails without a `EVP_PKEY`
     * so if the user doesn't want it, use a local one and free it
     * again directly after parsing.
     */
    EVP_PKEY *pkey_;
    if (!pkey)
        pkey = &pkey_;
    int parse_ok = PKCS12_parse(p12, pass, pkey, cert, ca);
    if (pkey == &pkey_ && pkey_)
        EVP_PKEY_free(pkey_);
    return parse_ok;
}

static X509 *
_tls_cert_read_p12(xmpp_conn_t *conn, EVP_PKEY **pkey, STACK_OF(X509) * *ca)
{
    if (conn->tls && conn->tls->client_cert && !pkey && !ca)
        return conn->tls->client_cert;
    X509 *cert = NULL;
    PKCS12 *p12 = NULL;
    BIO *f = BIO_new_file(conn->tls_client_cert, "rb");
    if (!f) {
        strophe_debug(conn->ctx, "tls", "f == NULL");
        goto error_out;
    }
    p12 = d2i_PKCS12_bio(f, NULL);
    BIO_free(f);
    if (!p12) {
        strophe_debug(conn->ctx, "tls", "Could not read p12 file");
        goto error_out;
    }

    /* First try to open file w/o a pass */
    if (_tls_parse_p12(p12, NULL, pkey, &cert, ca)) {
        goto success;
    }
    cert = NULL;

    unsigned int retries = 0;

    pem_password_cb *cb = PEM_def_callback;
    void *userdata = NULL;
    if (conn->password_callback) {
        cb = _tls_password_callback;
        userdata = conn;
    }

    while (retries++ < conn->password_retries) {
        char pass[PEM_BUFSIZE + 1];
        int passlen = cb(pass, PEM_BUFSIZE, 0, userdata);
        if (passlen < 0 || passlen > PEM_BUFSIZE)
            goto error_out;
        int parse_ok = _tls_parse_p12(p12, pass, pkey, &cert, ca);
        if (parse_ok) {
            goto success;
        }
        cert = NULL;
        tls_clear_password_cache(conn);
        int err = ERR_peek_last_error();
        if (ERR_GET_LIB(err) == ERR_LIB_PKCS12 &&
            ERR_GET_REASON(err) == PKCS12_R_MAC_VERIFY_FAILURE) {
            strophe_debug(conn->ctx, "tls",
                          "Entered password is most likely wrong!");
            continue;
        }
        strophe_debug(conn->ctx, "tls", "Could not parse PKCS#12");
        goto error_out;
    }
error_out:
    _tls_log_error(conn->ctx);
success:
    if (p12)
        PKCS12_free(p12);
    return cert;
}

static X509 *_tls_cert_read(xmpp_conn_t *conn)
{
    if (conn->tls && conn->tls->client_cert)
        return conn->tls->client_cert;
    if (conn->tls_client_cert && !conn->tls_client_key) {
        return _tls_cert_read_p12(conn, NULL, NULL);
    }
    return _tls_cert_read_x509(conn);
}

static int _tls_xaddr_nid(void)
{
    static int xaddr_nid = NID_undef;
    if (xaddr_nid == NID_undef) {
        xaddr_nid = OBJ_sn2nid("id-on-xmppAddr");
    }
    if (xaddr_nid == NID_undef) {
        xaddr_nid = OBJ_create("1.3.6.1.5.5.7.8.5", "id-on-xmppAddr",
                               "XmppAddr Identifier");
    }
    return xaddr_nid;
}

static GENERAL_NAMES *_tls_conn_get_names(xmpp_conn_t *conn)
{
    X509 *client_cert;
    GENERAL_NAMES *names = NULL;
    client_cert = _tls_cert_read(conn);
    if (!client_cert)
        return NULL;
    names = _tls_cert_get_names(client_cert);
    if (!conn->tls || !conn->tls->client_cert)
        X509_free(client_cert);
    return names;
}

static GENERAL_NAMES *_tls_cert_get_names(X509 *client_cert)
{
    int san = X509_get_ext_by_NID(client_cert, NID_subject_alt_name, 0);
    X509_EXTENSION *san_ext = X509_get_ext(client_cert, san);
    if (!san_ext)
        return NULL;
    ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(san_ext);
    if (!data)
        return NULL;
    const unsigned char *d = ASN1_STRING_get0_data(data);
    if (!d)
        return NULL;
    return d2i_GENERAL_NAMES(NULL, &d, ASN1_STRING_length(data));
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
static int _tls_xmppaddr_to_string(GENERAL_NAME *name, char **res)
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

static int _tls_dnsname_to_string(GENERAL_NAME *name, char **res)
{
    ASN1_STRING *str;
    if (!name || name->type != GEN_DNS)
        return 1;
    str = GENERAL_NAME_get0_value(name, NULL);
    if (str == NULL)
        return 1;
    if (!res)
        return 0;
    if (ASN1_STRING_to_UTF8((unsigned char **)res, str) < 0)
        return 1;
    return 0;
}
