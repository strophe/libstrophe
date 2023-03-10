/* jid.c
** strophe XMPP client library -- helper functions for parsing JIDs
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  JID creation and parsing.
 */

#include <string.h>

#include "strophe.h"
#include "common.h"

/** Create a JID string from component parts node, domain, and resource.
 *
 *  @param ctx the Strophe context object
 *  @param node a string representing the node
 *  @param domain a string representing the domain.  Required.
 *  @param resource a string representing the resource
 *
 *  @return an allocated string with the full JID or NULL if no domain
 *      is specified
 */
char *xmpp_jid_new(xmpp_ctx_t *ctx,
                   const char *node,
                   const char *domain,
                   const char *resource)
{
    char *result;
    size_t len, nlen, dlen, rlen;

    /* jid must at least have a domain */
    if (domain == NULL) {
        strophe_error(ctx, "jid", "domainpart missing.");
        return NULL;
    }

    /* accumulate lengths */
    dlen = strlen(domain);
    nlen = (node) ? strlen(node) + 1 : 0;
    rlen = (resource) ? strlen(resource) + 1 : 0;
    len = nlen + dlen + rlen;

    if (dlen > 1023) {
        strophe_error(ctx, "jid", "domainpart too long.");
        return NULL;
    }
    if (nlen > 1024) {
        strophe_error(ctx, "jid", "localpart too long.");
        return NULL;
    }
    if (rlen > 1024) {
        strophe_error(ctx, "jid", "resourcepart too long.");
        return NULL;
    }

    if (node) {
        if (strcspn(node, "\"&'/:<>@") != nlen - 1) {
            strophe_error(ctx, "jid", "localpart contained invalid character.");
            return NULL;
        }
    }

    /* concat components */
    result = strophe_alloc(ctx, len + 1);
    if (result != NULL) {
        if (node != NULL) {
            memcpy(result, node, nlen - 1);
            result[nlen - 1] = '@';
        }
        memcpy(result + nlen, domain, dlen);
        if (resource != NULL) {
            result[nlen + dlen] = '/';
            memcpy(result + nlen + dlen + 1, resource, rlen - 1);
        }
        result[len] = '\0';
    }

    return result;
}

/** Create a bare JID from a JID.
 *
 *  @param ctx the Strophe context object
 *  @param jid the JID
 *
 *  @return an allocated string with the bare JID or NULL on an error
 */
char *xmpp_jid_bare(xmpp_ctx_t *ctx, const char *jid)
{
    char *result;
    size_t len;

    len = strcspn(jid, "/");
    result = strophe_alloc(ctx, len + 1);
    if (result != NULL) {
        memcpy(result, jid, len);
        result[len] = '\0';
    }

    return result;
}

/** Create a node string from a JID.
 *
 *  @param ctx a Strophe context object
 *  @param jid the JID
 *
 *  @return an allocated string with the node or NULL if no node is found
 *      or an error occurs
 */
char *xmpp_jid_node(xmpp_ctx_t *ctx, const char *jid)
{
    char *dup_jid = strophe_strdup(ctx, jid);
    char *result = NULL;
    const char *c;

    /* Apply the same parsing rules from rfc7622 Section 3.2
     * 1. Strip resource
     * 2. take part before the '@'
     */

    char *resource = strchr(dup_jid, '/');
    if (resource != NULL) {
        *resource = '\0';
    }

    c = strchr(dup_jid, '@');
    if (c != NULL) {
        result = strophe_alloc(ctx, (c - dup_jid) + 1);
        if (result != NULL) {
            memcpy(result, dup_jid, (c - dup_jid));
            result[c - dup_jid] = '\0';
        }
    }
    strophe_free(ctx, dup_jid);

    return result;
}

/** Create a domain string from a JID.
 *
 *  @param ctx the Strophe context object
 *  @param jid the JID
 *
 *  @return an allocated string with the domain or NULL on an error
 */
char *xmpp_jid_domain(xmpp_ctx_t *ctx, const char *jid)
{
    char *dup_jid = strophe_strdup(ctx, jid);

    /* rfc7622 Section 3.2
     * 1.  Remove any portion from the first '/' character to the end of the
     *     string (if there is a '/' character present).
     */

    char *resource = strchr(dup_jid, '/');
    if (resource != NULL) {
        *resource = '\0';
    }

    /* 2.  Remove any portion from the beginning of the string to the first
     *     '@' character (if there is an '@' character present).
     */
    char *at_sign = strchr(dup_jid, '@');
    char *result = NULL;
    if (at_sign != NULL) {
        result = strophe_strdup(ctx, (at_sign + 1));
    } else {
        result = strophe_strdup(ctx, dup_jid);
    }
    strophe_free(ctx, dup_jid);

    return result;
}

/** Create a resource string from a JID.
 *
 *  @param ctx a Strophe context object
 *  @param jid the JID
 *
 *  @return an allocated string with the resource or NULL if no resource
 *      is found or an error occurs
 */
char *xmpp_jid_resource(xmpp_ctx_t *ctx, const char *jid)
{
    const char *c;

    c = strchr(jid, '/');
    return c != NULL ? strophe_strdup(ctx, c + 1) : NULL;
}
