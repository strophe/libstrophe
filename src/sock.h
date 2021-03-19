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

void sock_initialize(void);
void sock_shutdown(void);

int sock_error(void);

sock_t sock_connect(const char *host, unsigned short port);
int sock_close(sock_t sock);

int sock_set_blocking(sock_t sock);
int sock_set_nonblocking(sock_t sock);
int sock_read(sock_t sock, void *buff, size_t len);
int sock_write(sock_t sock, const void *buff, size_t len);
int sock_is_recoverable(int error);
/* checks for an error after connect, return 0 if connect successful */
int sock_connect_error(sock_t sock);
int sock_set_keepalive(sock_t sock, int timeout, int interval);

#endif /* __LIBSTROPHE_SOCK_H__ */
