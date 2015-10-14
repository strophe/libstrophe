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

/** Perform lookup for RFC1035 message format. */
int resolver_srv_lookup_buf(const unsigned char *buf, size_t len,
                            char *target, size_t target_len,
                            unsigned short *port);

/** Resolve SRV record.
 *
 *  @param service service of the SRV record
 *  @param proto protocol of the SRV record
 *  @param domain resolving domain
 *  @param target pre-allocated string where result is stored
 *  @param target_len maximum size of the target
 *  @param port pointer where resulting port is stored
 *
 *  @return 1 on success or 0 on fail
 */
int resolver_srv_lookup(const char *service, const char *proto,
                        const char *domain, char *target,
                        size_t target_len, unsigned short *port);

#endif /* __LIBSTROPHE_RESOLVER_H__ */
