/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* tls.c
** strophe XMPP client library -- generic TLS functions
**
** Copyright (C) 2021 Steffen Jaeckel <jaeckel-floss@eyet-services.de>
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT or GPLv3 licenses.
*/

/** @file
 *  Generic TLS functionality.
 */

/** @defgroup TLS SSL/TLS specific functionality
 *  These functions provide SSL/TLS specific functionality.
 */

#include <errno.h>
#include <stdarg.h>
#include <string.h>

#if !defined(_WIN32)
#include <unistd.h>
#endif

#include "strophe.h"

#include "common.h"
#ifdef _MSC_VER
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

const struct conn_interface tls_intf = {
    tls_read,
    tls_write,
    tls_clear_pending_write,
    tls_pending,
    tls_error,
    tls_is_recoverable,
    /* init conn */
    NULL,
};

struct _dnsname_t {
    char **data;
    size_t cur, max;
};

const size_t tlscert_dnsnames_increment = 4;

/** Get the Strophe context which is assigned to this certificate.
 *
 *  @param cert a Strophe TLS certificate object
 *
 *  @return the Strophe context object where this certificate originates from
 *
 *  @ingroup TLS
 */
xmpp_ctx_t *xmpp_tlscert_get_ctx(const xmpp_tlscert_t *cert)
{
    return cert->ctx;
}

/** Get the Strophe connection which is assigned to this certificate.
 *
 *  @param cert a Strophe TLS certificate object
 *
 *  @return the Strophe connection object where this certificate originates from
 *
 *  @ingroup TLS
 */
xmpp_conn_t *xmpp_tlscert_get_conn(const xmpp_tlscert_t *cert)
{
    return cert->conn;
}

/** Get the userdata of a Strophe connection which is assigned to this
 *  certificate.
 *
 *  @param cert a Strophe TLS certificate object
 *
 *  @return the userdata of a Strophe connection object where this certificate
 *  originates from
 *
 *  @ingroup TLS
 */
void *xmpp_tlscert_get_userdata(const xmpp_tlscert_t *cert)
{
    if (cert->conn == NULL)
        return NULL;
    return cert->conn->userdata;
}

/** Get the complete PEM of this certificate.
 *
 *  @param cert a Strophe TLS certificate object
 *
 *  @return a string containing the PEM of this certificate
 *
 *  @ingroup TLS
 */
const char *xmpp_tlscert_get_pem(const xmpp_tlscert_t *cert)
{
    return cert->pem;
}

/** Get the dnsName entries out of the SubjectAlternativeNames.
 *
 *  Note: Max. `MAX_NUM_DNSNAMES` are supported.
 *
 *  @param cert a Strophe TLS certificate object
 *  @param n which dnsName entry
 *
 *  @return a string with the n'th dnsName
 *
 *  @ingroup TLS
 */
const char *xmpp_tlscert_get_dnsname(const xmpp_tlscert_t *cert, size_t n)
{
    if (n >= cert->dnsnames->cur)
        return NULL;
    return cert->dnsnames->data[n];
}

/** Get various parts of the certificate as String.
 *
 *  c.f. \ref xmpp_cert_element_t for details.
 *
 *  @param cert a Strophe TLS certificate object
 *  @param elmnt which part of the certificate
 *
 *  @return a string with the part of the certificate
 *
 *  @ingroup TLS
 */
const char *xmpp_tlscert_get_string(const xmpp_tlscert_t *cert,
                                    xmpp_cert_element_t elmnt)
{
    if (elmnt < 0 || elmnt >= XMPP_CERT_ELEMENT_MAX)
        return NULL;
    return cert->elements[elmnt];
}

/** Get a descriptive string for each xmpp_cert_element_t.
 *
 *  c.f. \ref xmpp_cert_element_t for details.
 *
 *  @param elmnt which element
 *
 *  @return a string with the description
 *
 *  @ingroup TLS
 */
const char *xmpp_tlscert_get_description(xmpp_cert_element_t elmnt)
{
    static const char *descriptions[] = {
        "X.509 Version",
        "SerialNumber",
        "Subject",
        "Issuer",
        "Issued On",
        "Expires On",
        "Public Key Algorithm",
        "Certificate Signature Algorithm",
        "Fingerprint SHA-1",
        "Fingerprint SHA-256",
    };
    if (elmnt < 0 || elmnt >= XMPP_CERT_ELEMENT_MAX)
        return NULL;
    return descriptions[elmnt];
}

/** Allocate and initialize a Strophe TLS certificate object.
 *
 *  @param ctx a Strophe context object
 *
 *  @return a certificate object or NULL
 */
xmpp_tlscert_t *tlscert_new(xmpp_ctx_t *ctx)
{
    xmpp_tlscert_t *tlscert = strophe_alloc(ctx, sizeof(*tlscert));
    if (!tlscert)
        return NULL;
    memset(tlscert, 0, sizeof(*tlscert));

    tlscert->dnsnames = strophe_alloc(ctx, sizeof(*tlscert->dnsnames));
    if (!tlscert->dnsnames) {
        strophe_free(ctx, tlscert);
        return NULL;
    }
    memset(tlscert->dnsnames, 0, sizeof(*tlscert->dnsnames));

    tlscert->ctx = ctx;

    return tlscert;
}

/** Free a certificate object.
 *
 *  @param cert a Strophe TLS certificate object
 *
 *  @ingroup TLS
 */
void xmpp_tlscert_free(xmpp_tlscert_t *cert)
{
    size_t n;
    for (n = 0; n < ARRAY_SIZE(cert->elements); ++n) {
        if (cert->elements[n])
            strophe_free(cert->ctx, cert->elements[n]);
    }
    if (cert->dnsnames->data) {
        for (n = 0; n < cert->dnsnames->cur; ++n) {
            if (cert->dnsnames->data[n])
                strophe_free(cert->ctx, cert->dnsnames->data[n]);
        }
    }
    strophe_free(cert->ctx, cert->dnsnames->data);
    strophe_free(cert->ctx, cert->dnsnames);
    if (cert->pem)
        strophe_free(cert->ctx, cert->pem);
    strophe_free(cert->ctx, cert);
}

/** Add a dnsName to the Strophe TLS certificate object.
 *
 *  @param cert a Strophe TLS certificate object
 *  @param dnsname dnsName that shall be stored
 *
 *  @return classic Unix style - 0=success, 1=error
 */
int tlscert_add_dnsname(xmpp_tlscert_t *cert, const char *dnsname)
{
    if ((cert->dnsnames->cur + 1) >= cert->dnsnames->max) {
        char **dnsnames =
            strophe_realloc(cert->ctx, cert->dnsnames->data,
                            (cert->dnsnames->max + tlscert_dnsnames_increment) *
                                sizeof(char **));
        if (!dnsnames)
            return 1;
        cert->dnsnames->data = dnsnames;
        cert->dnsnames->max += tlscert_dnsnames_increment;
    }
    cert->dnsnames->data[cert->dnsnames->cur++] =
        strophe_strdup(cert->ctx, dnsname);
    return 0;
}

int tls_caching_password_callback(char *pw, size_t pw_max, xmpp_conn_t *conn)
{
    int ret;
    unsigned char hash[XMPP_SHA1_DIGEST_SIZE];

    const char *fname = conn->tls_client_cert;
    size_t fname_len = strlen(fname);
    xmpp_sha1_digest((void *)fname, fname_len, hash);
    if (fname_len && fname_len == conn->password_cache.fnamelen &&
        memcmp(hash, conn->password_cache.fname_hash, sizeof(hash)) == 0) {
        if (conn->password_cache.passlen) {
            memcpy(pw, conn->password_cache.pass,
                   conn->password_cache.passlen + 1);
            return conn->password_cache.passlen;
        }
    }
    size_t max_len = pw_max == 256 ? pw_max : sizeof(conn->password_cache.pass);
    ret = conn->password_callback(conn->password_cache.pass, max_len, conn,
                                  conn->password_callback_userdata);

    if (ret < 0 || ret >= (ssize_t)max_len) {
        memset(conn->password_cache.pass, 0, sizeof(conn->password_cache.pass));
        return -1;
    }
    conn->password_cache.pass[ret] = '\0';
    memcpy(pw, conn->password_cache.pass, ret + 1);
    conn->password_cache.passlen = ret;
    conn->password_cache.fnamelen = fname_len;
    memcpy(conn->password_cache.fname_hash, hash, sizeof(hash));
    return conn->password_cache.passlen;
}

void tls_clear_password_cache(xmpp_conn_t *conn)
{
    memset(&conn->password_cache, 0, sizeof(conn->password_cache));
}
