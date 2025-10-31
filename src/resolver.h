/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* resolver.h
 * strophe XMPP client library -- DNS resolver
 *
 * Copyright (C) 2015 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT or GPLv3 licenses.
 */

/** @file
 *  DNS resolver.
 */

#ifndef __LIBSTROPHE_RESOLVER_H__
#define __LIBSTROPHE_RESOLVER_H__

#include "ostypes.h"
#include "common.h"

#ifdef HAVE_CARES
#include <ares.h>

extern ares_channel ares_chan;
#define resolver_freeaddrinfo ares_freeaddrinfo
typedef struct ares_addrinfo resolver_addrinfo;
typedef struct ares_addrinfo_node resolver_addrinfo_node;
typedef struct ares_addrinfo_hints resolver_addrinfo_hints;
typedef ares_addrinfo_callback resolver_addrinfo_callback;
#define RESOLVER_SUCCESS ARES_SUCCESS
#define RESOLVER_ADDRINFO_HEAD(x) ((x)->nodes)
#else
#define resolver_freeaddrinfo freeaddrinfo
typedef struct addrinfo resolver_addrinfo_hints;
typedef struct addrinfo resolver_addrinfo;
typedef struct addrinfo resolver_addrinfo_node;
typedef void (*resolver_addrinfo_callback)(void *arg,
                                           int status,
                                           int timeouts,
                                           resolver_addrinfo *result);
#define RESOLVER_SUCCESS 0
#define RESOLVER_ADDRINFO_HEAD(x) x
typedef struct addrinfo resolver_addrinfo;
#endif

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

void resolver_initialize(void);
void resolver_shutdown(void);

resolver_srv_rr_t *resolver_srv_rr_new(xmpp_ctx_t *ctx,
                                       const char *host,
                                       unsigned short port,
                                       unsigned short prio,
                                       unsigned short weight);

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
int resolver_srv_lookup_buf(xmpp_ctx_t *ctx,
                            const unsigned char *buf,
                            size_t len,
                            resolver_srv_rr_t **srv_rr_list);
/** Resolve SRV record.
 *
 *  @param ctx a Strophe context object
 *  @param service service of the SRV record
 *  @param proto protocol of the SRV record
 *  @param domain resolving domain
 *  @param srv_rr_list is the result
 *  @param callback is called when the resolve is complete
 *  @param xsock gets passed to the callback
 */
void resolver_srv_lookup(xmpp_ctx_t *ctx,
                         const char *service,
                         const char *proto,
                         const char *domain,
                         resolver_srv_rr_t **srv_rr_list,
                         void (*callback)(xmpp_sock_t *xsock,
                                          const char *domain),
                         xmpp_sock_t *xsock);

/** Release a list returned by resolver_srv_lookup() or
 *  resolver_srv_lookup_buf().
 *
 *  @param ctx a Strophe context object
 *  @param srv_rr_list a list allocated by lookup functions
 */
void resolver_srv_free(xmpp_ctx_t *ctx, resolver_srv_rr_t *srv_rr_list);

/** Resolve a DNS name, just like getaddrinfo
 *  Async safe when using c-ares
 *
 *  @param name a DNS name to resolve
 *  @param service a DNS service
 *  @param hints options for the resolver
 *  @param callback is called when the resolve is complete
 *  @param arg is passed to callback
 */
void resolver_getaddrinfo(const char *name,
                          const char *service,
                          const resolver_addrinfo_hints *hints,
                          resolver_addrinfo_callback callback,
                          void *arg);

#endif /* __LIBSTROPHE_RESOLVER_H__ */
