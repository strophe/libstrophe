/* jid.c
** libstrophe XMPP client library -- helper functions for parsing JIDs
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

#include <string.h>

#include "strophe.h"
#include "common.h"

/** join jid component parts to form a new jid string */
char *xmpp_jid_new(xmpp_ctx_t *ctx, const char *node,
				    const char *domain,
				    const char *resource)
{
    char *result;
    int len,nlen,dlen,rlen;

    /* jid must at least have a domain */
    if (domain == NULL) return NULL;

    /* accumulate lengths */
    dlen = strlen(domain);
    nlen = (node) ? strlen(node) + 1 : 0;
    rlen = (resource) ? strlen(resource) + 1 : 0;
    len = nlen + dlen + rlen;

    /* concat components */
    result = xmpp_alloc(ctx, len + 1);
    if (result != NULL) {
	if (node != NULL) {
	    memcpy(result, node, nlen - 1);
	    result[nlen-1] = '@';
	}
        memcpy(result + nlen, domain, dlen);
	if (resource != NULL) {
	    result[nlen+dlen] = '/';
	    memcpy(result+nlen+dlen+1, resource, rlen - 1);
	}
	result[nlen+dlen+rlen] = '\0';
    }

    return result;
}

/** return a bare jid */
char *xmpp_jid_bare(xmpp_ctx_t *ctx, const char *jid)
{
    char *result;
    const char *c;

    c = strchr(jid, '/');
    if (c == NULL) return xmpp_strdup(ctx, jid);

    result = xmpp_alloc(ctx, c-jid+1);
    if (result != NULL) {
	memcpy(result, jid, c-jid);
	result[c-jid] = '\0';
    }

    return result;
}

/** return the node portion of a jid */
char *xmpp_jid_node(xmpp_ctx_t *ctx, const char *jid)
{
    char *result = NULL;
    const char *c;

    c = strchr(jid, '@');
    if (c != NULL) {
	result = xmpp_alloc(ctx, (c-jid) + 1);
	if (result != NULL) {
	    memcpy(result, jid, (c-jid));
	    result[c-jid] = '\0';
	}
    }

    return result;
}

/** return the domain portion of a jid */
char *xmpp_jid_domain(xmpp_ctx_t *ctx, const char *jid)
{
    char *result = NULL;
    const char *c,*s;

    c = strchr(jid, '@');
    if (c == NULL) {
	/* no node, assume domain */
	c = jid;
    } else {
	/* advance past the separator */
	c++;
    }
    s = strchr(c, '/');
    if (s == NULL) {
	/* no resource */
	s = c + strlen(c);
    }
    result = xmpp_alloc(ctx, (s-c) + 1);
    if (result != NULL) {
	memcpy(result, c, (s-c));
	result[s-c] = '\0';
    }

    return result;
}

/** return the node portion of a jid */
char *xmpp_jid_resource(xmpp_ctx_t *ctx, const char *jid)
{
    char *result = NULL;
    const char *c;
    int len;

    c = strchr(jid, '/');
    if (c != NULL)  {
	c++;
	len = strlen(c);
	result = xmpp_alloc(ctx, len + 1);
	if (result != NULL) {
	    memcpy(result, c, len);
	    result[len] = '\0';
	}
    }

    return result;
}
