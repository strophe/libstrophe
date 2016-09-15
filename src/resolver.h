/* resolver.h
 * strophe XMPP client library -- DNS resolver
 *
 * Copyright (C) 2015 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/** @file
 *  DNS resolver.
 */

#ifndef __LIBSTROPHE_RESOLVER_H__
#define __LIBSTROPHE_RESOLVER_H__

#include "ostypes.h"
#include "common.h"

typedef enum {
    XMPP_DOMAIN_NOT_FOUND,
    XMPP_DOMAIN_FOUND,
    XMPP_DOMAIN_ALTDOMAIN
} xmpp_domain_state_t;

typedef struct resolver_srv_rr_struc {
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    char target[MAX_DOMAIN_LEN];
    struct resolver_srv_rr_struc *next;
} resolver_srv_rr_t;

/** Perform lookup for RFC1035 message format.
 *  This function allocates all elements.
 *
 *  @param ctx a Strophe context object
 *  @param buf message in RFC1035 format
 *  @param len length of the message
 *  @param srv_rr_list is the result
 *
 *  @return XMPP_DOMAIN_FOUND on success or XMPP_DOMAIN_NOT_FOUND on fail
 */
int resolver_srv_lookup_buf(xmpp_ctx_t *ctx, const unsigned char *buf,
                            size_t len, resolver_srv_rr_t **srv_rr_list);
/** Resolve SRV record.
 *
 *  @param ctx a Strophe context object
 *  @param service service of the SRV record
 *  @param proto protocol of the SRV record
 *  @param domain resolving domain
 *  @param srv_rr_list is the result
 *
 *  @return XMPP_DOMAIN_FOUND on success or XMPP_DOMAIN_NOT_FOUND on fail
 */
int resolver_srv_lookup(xmpp_ctx_t *ctx, const char *service, const char *proto,
                        const char *domain, resolver_srv_rr_t **srv_rr_list);

/** Release a list returned by resolver_srv_lookup() or
 *  resolver_srv_lookup_buf().
 *
 *  @param ctx a Strophe context object
 *  @param srv_rr_list a list allocated by lookup functions
 */
void resolver_srv_free(xmpp_ctx_t *ctx, resolver_srv_rr_t *srv_rr_list);

#endif /* __LIBSTROPHE_RESOLVER_H__ */
