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
#define INVALID_SOCKET (-1)
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <mstcpip.h> /* tcp_keepalive */
typedef SOCKET sock_t;
#endif

typedef struct _xmpp_sock_t xmpp_sock_t;

void sock_initialize(void);
void sock_shutdown(void);

int sock_error(void);

xmpp_sock_t *sock_new(xmpp_conn_t *conn,
                      const char *domain,
                      const char *host,
                      unsigned short port);
void sock_free(xmpp_sock_t *xsock);
sock_t sock_connect(xmpp_sock_t *xsock);
int sock_close(sock_t sock);

int sock_set_blocking(sock_t sock);
int sock_set_nonblocking(sock_t sock);
int sock_read(sock_t sock, void *buff, size_t len);
int sock_write(sock_t sock, const void *buff, size_t len);
int sock_is_recoverable(int error);
/* checks for an error after connect, return 0 if connect successful */
int sock_connect_error(sock_t sock);
int sock_set_keepalive(sock_t sock,
                       int timeout,
                       int interval,
                       int count,
                       unsigned int user_timeout);

#endif /* __LIBSTROPHE_SOCK_H__ */
