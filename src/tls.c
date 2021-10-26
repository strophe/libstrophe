/* tls.c
** strophe XMPP client library -- generic TLS functions
**
** Copyright (C) 2021 Steffen Jaeckel <jaeckel-floss@eyet-services.de>
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
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

#include "strophe.h"

#include "common.h"

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
    if (elmnt >= XMPP_CERT_ELEMENT_MAX)
        return NULL;
    return cert->elements[elmnt];
}

/** Get a descriptive string for each xmpp_cert_element_t.
 *
 *  c.f. \ref xmpp_cert_element_t for details.
 *
 *  @param cert a Strophe TLS certificate object
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
    if (elmnt >= XMPP_CERT_ELEMENT_MAX)
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
    xmpp_tlscert_t *tlscert = xmpp_alloc(ctx, sizeof(*tlscert));
    if (!tlscert)
        return NULL;
    memset(tlscert, 0, sizeof(*tlscert));

    tlscert->dnsnames = xmpp_alloc(ctx, sizeof(*tlscert->dnsnames));
    if (!tlscert->dnsnames) {
        xmpp_free(ctx, tlscert);
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
            xmpp_free(cert->ctx, cert->elements[n]);
    }
    if (cert->dnsnames->data) {
        for (n = 0; n < cert->dnsnames->cur; ++n) {
            if (cert->dnsnames->data[n])
                xmpp_free(cert->ctx, cert->dnsnames->data[n]);
        }
    }
    xmpp_free(cert->ctx, cert->dnsnames->data);
    xmpp_free(cert->ctx, cert->dnsnames);
    if (cert->pem)
        xmpp_free(cert->ctx, cert->pem);
    xmpp_free(cert->ctx, cert);
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
            xmpp_realloc(cert->ctx, cert->dnsnames->data,
                         (cert->dnsnames->max + tlscert_dnsnames_increment) *
                             sizeof(char **));
        if (!dnsnames)
            return 1;
        cert->dnsnames->data = dnsnames;
        cert->dnsnames->max += tlscert_dnsnames_increment;
    }
    cert->dnsnames->data[cert->dnsnames->cur++] =
        xmpp_strdup(cert->ctx, dnsname);
    return 0;
}
