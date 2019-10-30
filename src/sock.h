/* sock.h
** strophe XMPP client library -- socket abstraction header
**
** Copyright (C) 2005-2009 Collecta, Inc. 
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  Socket abstraction API.
 */

#ifndef __LIBSTROPHE_SOCK_H__
#define __LIBSTROPHE_SOCK_H__

#include <stdio.h>

#ifndef _WIN32
typedef int sock_t;
#else
#include <winsock2.h>
typedef SOCKET sock_t;
#endif

typedef struct _xmpp_sock_t xmpp_sock_t;

void sock_initialize(void);
void sock_shutdown(void);

int sock_error(void);

xmpp_sock_t *sock_new(xmpp_ctx_t *ctx, const char *host, unsigned short port);
void sock_free(xmpp_sock_t *xsock);
sock_t sock_connect(xmpp_sock_t *xsock);
int sock_close(const sock_t sock);

int sock_set_blocking(const sock_t sock);
int sock_set_nonblocking(const sock_t sock);
int sock_read(const sock_t sock, void * const buff, const size_t len);
int sock_write(const sock_t sock, const void * const buff, const size_t len);
int sock_is_recoverable(const int error);
/* checks for an error after connect, return 0 if connect successful */
int sock_connect_error(const sock_t sock);
int sock_set_keepalive(const sock_t sock, int timeout, int interval);

#endif /* __LIBSTROPHE_SOCK_H__ */
