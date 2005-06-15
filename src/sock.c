/* sock.c
** libstrophe XMPP client library -- socket abstraction implementation
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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define snprintf _snprintf
#else
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#endif

#include "sock.h"

void sock_initialize(void)
{
#ifdef _WIN32
    WSADATA wsad;
    WSAStartup(0x0101, &wsad);
#endif
}

void sock_shutdown(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

int sock_error(void)
{
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

static int _in_progress(int error)
{
#ifdef _WIN32
    return (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS);
#else
    return (errno == EINPROGRESS);
#endif
}

sock_t sock_connect(const char * const host, const unsigned int port)
{
    sock_t sock;
    char service[6];
    struct addrinfo *res, *ainfo, hints;
    int err;
    
    sock = -1;

    snprintf(service, 6, "%u", port);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_socktype = SOCK_STREAM;

    if ((err = getaddrinfo(host, service, &hints, &res)) != 0)
	return -1;

    ainfo = res;
    while (ainfo) {
	if ((sock = socket(ainfo->ai_family, ainfo->ai_socktype, 
		   ainfo->ai_protocol)) >= 0) {
	    sock_set_nonblocking(sock);

	    err = connect(sock, ainfo->ai_addr, ainfo->ai_addrlen);

	    if ((err == 0) || (err < 0 && _in_progress(sock_error())))
		break;
	}

	ainfo = ainfo->ai_next;
    }

    if (res) freeaddrinfo(res);

    return sock;
}

int sock_close(const sock_t sock)
{
#ifdef _WIN32
    return closesocket(sock);
#else
    return close(sock);
#endif
}

int sock_set_blocking(const sock_t sock)
{
#ifdef _WIN32
    u_long block = 0;
    return ioctlsocket(sock, FIONBIO, &block);
#else
    return fcntl(sock, F_SETFL, 0);
#endif
}

int sock_set_nonblocking(const sock_t sock)
{
#ifdef _WIN32
    u_long nonblock = 1;
    return ioctlsocket(sock, FIONBIO, &nonblock);
#else
    return fcntl(sock, F_SETFL, O_NONBLOCK);
#endif
}

int sock_read(const sock_t sock, void * const buff, const size_t len)
{
    return recv(sock, buff, len, 0);
}

int sock_write(const sock_t sock, const void * const buff, const size_t len)
{
    return send(sock, buff, len, 0);
}

int sock_is_recoverable(const int error)
{
#ifdef _WIN32
    return (error == WSAEINTR || error == WSAEWOULDBLOCK || 
	    error == WSAEINPROGRESS);
#else
    return (error == EAGAIN || error == EINTR);
#endif
}

int sock_connect_error(const sock_t sock)
{
    socklen_t len;
    int error, ret;

    len = sizeof(int);
    
    ret = getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
    if (ret < 0) return ret;
    return error;
}
