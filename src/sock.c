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
#include <iphlpapi.h>
#include <mstcpip.h> /* tcp_keepalive */
#else
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#endif

#include "common.h"
#include "resolver.h"

struct _xmpp_sock_t {
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    struct addrinfo *ainfo_list;
    struct addrinfo *ainfo_cur;
    resolver_srv_rr_t *srv_rr_list;
    resolver_srv_rr_t *srv_rr_cur;
    const char *host;
    unsigned short port;
};

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

static void sock_getaddrinfo(xmpp_sock_t *xsock)
{
    char service[6];
    struct addrinfo hints;
    int rc;

    if (xsock->ainfo_list) {
        freeaddrinfo(xsock->ainfo_list);
        xsock->ainfo_list = NULL;
    }

    if (xsock->srv_rr_cur) {
        /* Cache host and port for debug logs. */
        xsock->host = xsock->srv_rr_cur->target;
        xsock->port = xsock->srv_rr_cur->port;

        strophe_snprintf(service, 6, "%u", xsock->srv_rr_cur->port);
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;
#ifdef AI_ADDRCONFIG
        hints.ai_flags = AI_ADDRCONFIG;
#endif /* AI_ADDRCONFIG */
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_socktype = SOCK_STREAM;

        rc = getaddrinfo(xsock->srv_rr_cur->target, service, &hints,
                         &xsock->ainfo_list);
        if (rc != 0) {
            strophe_debug(xsock->ctx, "sock", "getaddrinfo() failed with %d",
                          rc);
            xsock->ainfo_list = NULL;
        }
    }

    xsock->ainfo_cur = xsock->ainfo_list;
}

xmpp_sock_t *sock_new(xmpp_conn_t *conn,
                      const char *domain,
                      const char *host,
                      unsigned short port)
{
    xmpp_ctx_t *ctx = conn->ctx;
    xmpp_sock_t *xsock;
    int found = XMPP_DOMAIN_NOT_FOUND;

    xsock = strophe_alloc(ctx, sizeof(*xsock));
    if (!xsock) {
        return NULL;
    }

    xsock->ctx = ctx;
    xsock->conn = conn;
    xsock->host = NULL;
    xsock->port = 0;

    if (!host) {
        found = resolver_srv_lookup(ctx, "xmpp-client", "tcp", domain,
                                    &xsock->srv_rr_list);
        if (XMPP_DOMAIN_NOT_FOUND == found)
            strophe_debug(ctx, "sock",
                          "SRV lookup failed, connecting via domain.");
    }
    if (XMPP_DOMAIN_NOT_FOUND == found) {
        /* Resolution failed or the host is provided explicitly. */
        xsock->srv_rr_list =
            resolver_srv_rr_new(ctx, host ? host : domain, port, 0, 0);
    }
    xsock->srv_rr_cur = xsock->srv_rr_list;

    xsock->ainfo_list = NULL;
    sock_getaddrinfo(xsock);
    if (xsock->srv_rr_cur)
        xsock->srv_rr_cur = xsock->srv_rr_cur->next;

    return xsock;
}

void sock_free(xmpp_sock_t *xsock)
{
    if (!xsock)
        return;

    if (xsock->ainfo_list)
        freeaddrinfo(xsock->ainfo_list);
    if (xsock->srv_rr_list)
        resolver_srv_free(xsock->ctx, xsock->srv_rr_list);
    strophe_free(xsock->ctx, xsock);
}

static const char *_sockaddr2str(struct sockaddr *sa, char *buf, size_t buflen)
{
    buf[0] = '\0';

    switch (sa->sa_family) {
    case AF_INET:
        inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, buf, buflen);
        break;
    case AF_INET6:
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, buf,
                  buflen);
        break;
    default:
        strophe_snprintf(buf, buflen, "<Unknown>");
    }
    return buf;
}

sock_t sock_connect(xmpp_sock_t *xsock)
{
    struct addrinfo *ainfo;
    sock_t sock;
    int rc = 0;
    char buf[64];

    do {
        if (!xsock->ainfo_cur) {
            sock_getaddrinfo(xsock);
            if (xsock->srv_rr_cur)
                xsock->srv_rr_cur = xsock->srv_rr_cur->next;
        }
        if (!xsock->ainfo_cur) {
            /* We tried all available addresses. */
            return INVALID_SOCKET;
        }

        ainfo = xsock->ainfo_cur;
        strophe_debug(xsock->ctx, "sock", "Connecting to %s:%u via %s",
                      xsock->host, xsock->port,
                      _sockaddr2str(ainfo->ai_addr, buf, sizeof(buf)));

        sock = socket(ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol);
        if (sock != INVALID_SOCKET) {
            if (xsock->conn->sockopt_cb) {
                /* Don't allow user to overwrite sockfd value. */
                sock_t sock_copy = sock;
                rc = xsock->conn->sockopt_cb(xsock->conn, &sock_copy);
                if (rc != 0) {
                    strophe_debug(xsock->ctx, "sock",
                                  "User's setsockopt callback"
                                  "failed with %d (errno=%d)",
                                  rc, errno);
                }
            }
            if (rc == 0)
                rc = sock_set_nonblocking(sock);
            if (rc == 0)
                rc = connect(sock, ainfo->ai_addr, ainfo->ai_addrlen);
            /* Assume only connect() can cause "in progress" error. */
            if (rc != 0 && !_in_progress(sock_error())) {
                sock_close(sock);
                sock = INVALID_SOCKET;
            }
        }
        strophe_debug(xsock->ctx, "sock", "sock_connect() result %d", sock);

        xsock->ainfo_cur = xsock->ainfo_cur->ai_next;
    } while (sock == INVALID_SOCKET);

    return sock;
}

int sock_set_keepalive(sock_t sock,
                       int timeout,
                       int interval,
                       int count,
                       unsigned int user_timeout)
{
    int ret;
    int optval = (timeout && interval) ? 1 : 0;

    UNUSED(count);
    UNUSED(user_timeout);

#ifdef _WIN32
    struct tcp_keepalive ka;
    DWORD dw = 0;

    ka.onoff = optval;
    ka.keepalivetime = timeout * 1000;
    ka.keepaliveinterval = interval * 1000;
    ret = WSAIoctl(sock, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &dw,
                   NULL, NULL);
#else
    ret = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
    if (ret < 0)
        return ret;

    if (optval) {
#ifdef TCP_KEEPIDLE
        ret = setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &timeout,
                         sizeof(timeout));
#elif defined(TCP_KEEPALIVE)
        /* QNX receives `struct timeval' as argument, but it seems OSX does int
         */
        ret = setsockopt(sock, IPPROTO_TCP, TCP_KEEPALIVE, &timeout,
                         sizeof(timeout));
#endif /* TCP_KEEPIDLE */
        if (ret < 0)
            return ret;
#ifdef TCP_KEEPINTVL
        ret = setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval,
                         sizeof(interval));
        if (ret < 0)
            return ret;
#endif /* TCP_KEEPINTVL */
    }

    if (count) {
#ifdef TCP_KEEPCNT
        ret = setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
        if (ret < 0)
            return ret;
#endif /* TCP_KEEPCNT */
    }

    if (user_timeout) {
#ifdef TCP_USER_TIMEOUT
        ret = setsockopt(sock, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout,
                         sizeof(user_timeout));
        if (ret < 0)
            return ret;
#elif defined(TCP_RXT_CONNDROPTIME)
        int rxt = user_timeout / 1000;
        ret = setsockopt(sock, IPPROTO_TCP, TCP_RXT_CONNDROPTIME, &rxt,
                         sizeof(rxt));
        if (ret < 0)
            return ret;
#endif /* TCP_USER_TIMEOUT */
    }

#endif /* _WIN32 */

    return ret;
}

/** Example sockopt callback function
 *  An example function that can be used to set reasonable default keepalive
 *  options on sockets when registered for a connection with
 *  xmpp_conn_set_sockopt_callback()
 *
 *  @param conn a Strophe connection object
 *  @param socket pointer to a socket descriptor
 *
 *  @see xmpp_sockopt_callback for details on the `socket` parameter
 *  @ingroup Connections
 */
int xmpp_sockopt_cb_keepalive(xmpp_conn_t *conn, void *socket)
{
    sock_t sock = *((sock_t *)socket);

    return sock_set_keepalive(
        sock, conn->ka_timeout, conn->ka_interval, conn->ka_count,
        conn->ka_count
            ? (conn->ka_timeout + conn->ka_interval * conn->ka_count) * 1000
            : 0);
}

int sock_close(sock_t sock)
{
#ifdef _WIN32
    return closesocket(sock);
#else
    return close(sock);
#endif
}

static int _sock_set_blocking_mode(sock_t sock, int blocking)
{
#ifdef _WIN32
    u_long nonblock = blocking ? 0 : 1;
    return ioctlsocket(sock, FIONBIO, &nonblock);
#else
    int rc;

    rc = fcntl(sock, F_GETFL, NULL);
    if (rc >= 0) {
        rc = blocking ? rc & (~O_NONBLOCK) : rc | O_NONBLOCK;
        rc = fcntl(sock, F_SETFL, rc);
    }
    return rc;
#endif
}

int sock_set_blocking(sock_t sock)
{
    return _sock_set_blocking_mode(sock, 1);
}

int sock_set_nonblocking(sock_t sock)
{
    return _sock_set_blocking_mode(sock, 0);
}

int sock_read(sock_t sock, void *buff, size_t len)
{
    return recv(sock, buff, len, 0);
}

int sock_write(sock_t sock, const void *buff, size_t len)
{
    return send(sock, buff, len, 0);
}

int sock_is_recoverable(int error)
{
#ifdef _WIN32
    return (error == WSAEINTR || error == WSAEWOULDBLOCK ||
            error == WSAEINPROGRESS);
#else
    return (error == EAGAIN || error == EINTR);
#endif
}

int sock_connect_error(sock_t sock)
{
    struct sockaddr_storage ss;
    struct sockaddr *sa = (struct sockaddr *)&ss;
    socklen_t len;
    char temp;

    memset(&ss, 0, sizeof(ss));
    len = sizeof(ss);
    sa->sa_family = AF_UNSPEC;

    /* we don't actually care about the peer name, we're just checking if
     * we're connected or not */
    if (getpeername(sock, sa, &len) == 0) {
        return 0;
    }

    /* it's possible that the error wasn't ENOTCONN, so if it wasn't,
     * return that */
#ifdef _WIN32
    if (sock_error() != WSAENOTCONN)
        return sock_error();
#else
    if (sock_error() != ENOTCONN)
        return sock_error();
#endif

    /* load the correct error into errno through error slippage */
    recv(sock, &temp, 1, 0);

    return sock_error();
}
