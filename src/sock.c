/* sock.c
** strophe XMPP client library -- socket abstraction implementation
**
** Copyright (C) 2005-2009 Collecta, Inc. 
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
** This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  Socket abstraction.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Iphlpapi.h>
#include <Mstcpip.h>    /* tcp_keepalive */
#else
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#endif

#include "sock.h"
#include "snprintf.h"

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
    return (error == EINPROGRESS);
#endif
}

sock_t sock_connect(const char * const host, const unsigned short port)
{
    sock_t sock;
    char service[6];
    struct addrinfo *res, *ainfo, hints;
    int err;

    xmpp_snprintf(service, 6, "%u", port);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
#ifdef AI_ADDRCONFIG
    hints.ai_flags = AI_ADDRCONFIG;
#endif /* AI_ADDRCONFIG */
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_socktype = SOCK_STREAM;

    err = getaddrinfo(host, service, &hints, &res);
    if (err != 0)
        return -1;

    for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
        sock = socket(ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol);
        if (sock < 0)
            continue;

        err = sock_set_nonblocking(sock);
        if (err == 0) {
            err = connect(sock, ainfo->ai_addr, ainfo->ai_addrlen);
            if (err == 0 || _in_progress(sock_error()))
                break;
        }
        sock_close(sock);
    }
    freeaddrinfo(res);
    sock = ainfo == NULL ? -1 : sock;

    return sock;
}

int sock_set_keepalive(const sock_t sock, int timeout, int interval)
{
    int ret;
    int optval = (timeout && interval) ? 1 : 0;

    /* This function doesn't change maximum number of keepalive probes */

#ifdef _WIN32
    struct tcp_keepalive ka;
    DWORD dw = 0;

    ka.onoff = optval;
    ka.keepalivetime = timeout * 1000;
    ka.keepaliveinterval = interval * 1000;
    ret = WSAIoctl(sock, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &dw, NULL, NULL);
#else
    ret = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
    if (ret < 0)
        return ret;

    if (optval) {
#ifdef TCP_KEEPIDLE
        ret = setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &timeout, sizeof(timeout));
#elif defined(TCP_KEEPALIVE)
        /* QNX receives `struct timeval' as argument, but it seems OSX does int */
        ret = setsockopt(sock, IPPROTO_TCP, TCP_KEEPALIVE, &timeout, sizeof(timeout));
#endif /* TCP_KEEPIDLE */
        if (ret < 0)
            return ret;
#ifdef TCP_KEEPINTVL
        ret = setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
        if (ret < 0)
            return ret;
#endif /* TCP_KEEPINTVL */
    }
#endif /* _WIN32 */

    return ret;
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
    int rc;

    rc = fcntl(sock, F_GETFL, NULL);
    if (rc >= 0) {
        rc = fcntl(sock, F_SETFL, rc & (~O_NONBLOCK));
    }
    return rc;
#endif
}

int sock_set_nonblocking(const sock_t sock)
{
#ifdef _WIN32
    u_long nonblock = 1;
    return ioctlsocket(sock, FIONBIO, &nonblock);
#else
    int rc;

    rc = fcntl(sock, F_GETFL, NULL);
    if (rc >= 0) {
        rc = fcntl(sock, F_SETFL, rc | O_NONBLOCK);
    }
    return rc;
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
    struct sockaddr sa;
    socklen_t len;
    char temp;

    memset(&sa, 0, sizeof(sa));
    sa.sa_family = AF_UNSPEC;
    len = sizeof(sa);

    /* we don't actually care about the peer name, we're just checking if
     * we're connected or not */
    if (getpeername(sock, &sa, &len) == 0)
    {
        return 0;
    }

    /* it's possible that the error wasn't ENOTCONN, so if it wasn't,
     * return that */
#ifdef _WIN32
    if (sock_error() != WSAENOTCONN) return sock_error();
#else
    if (sock_error() != ENOTCONN) return sock_error();
#endif

    /* load the correct error into errno through error slippage */
    recv(sock, &temp, 1, 0);

    return sock_error();
}
