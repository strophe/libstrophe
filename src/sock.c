/* SPDX-License-Identifier: MIT OR GPL-3.0-only */
/* sock.c
** strophe XMPP client library -- socket abstraction implementation
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
** This program is dual licensed under the MIT or GPLv3 licenses.
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

const struct conn_interface sock_intf = {
    sock_read,
    sock_write,
    /* no flush */
    conn_int_nop,
    /* no pending */
    conn_int_nop,
    sock_error,
    sock_is_recoverable,
    NULL,
};

struct _xmpp_sock_t {
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    resolver_addrinfo *ainfo_list;
    resolver_addrinfo_node *ainfo_cur;
    resolver_srv_rr_t *srv_rr_list;
    resolver_srv_rr_t *srv_rr_cur;
    const char *host;
    unsigned short port;
    void (*getaddrinfo_cb)(xmpp_sock_t *xsock);
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

int sock_error(struct conn_interface *intf)
{
    UNUSED(intf);
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

void sock_getaddrinfo_cb(void *arg,
                         int status,
                         int timeouts,
                         resolver_addrinfo *result)
{
    xmpp_sock_t *xsock = arg;
    (void)status;
    (void)timeouts;

    if (status == RESOLVER_SUCCESS) {
        xsock->ainfo_list = result;
    } else {
        strophe_debug(xsock->ctx, "sock",
                      "resolver_getaddrinfo() failed with %d (%d)", status,
                      timeouts);
        xsock->ainfo_list = NULL;
    }

    xsock->ainfo_cur = RESOLVER_ADDRINFO_HEAD(xsock->ainfo_list);
    if (xsock->srv_rr_cur)
        xsock->srv_rr_cur = xsock->srv_rr_cur->next;

    if (xsock->getaddrinfo_cb) {
        void (*callback)(xmpp_sock_t *sock) = xsock->getaddrinfo_cb;
        xsock->getaddrinfo_cb = NULL;
        callback(xsock);
    }
}

static void sock_getaddrinfo(xmpp_sock_t *xsock,
                             void (*callback)(xmpp_sock_t *xsock))
{
    char service[6];
    resolver_addrinfo_hints hints;

    if (xsock->ainfo_list) {
        resolver_freeaddrinfo(xsock->ainfo_list);
        xsock->ainfo_list = NULL;
    }

    if (xsock->srv_rr_cur) {
        /* Cache host and port for debug logs. */
        xsock->host = xsock->srv_rr_cur->target;
        xsock->port = xsock->srv_rr_cur->port;

        strophe_snprintf(service, 6, "%u", xsock->srv_rr_cur->port);
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
#ifdef AI_ADDRCONFIG
        hints.ai_flags = AI_ADDRCONFIG;
#endif /* AI_ADDRCONFIG */
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_socktype = SOCK_STREAM;

        xsock->getaddrinfo_cb = callback;
        resolver_getaddrinfo(xsock->srv_rr_cur->target, service, &hints,
                             &sock_getaddrinfo_cb, xsock);
    } else {
        callback(xsock);
    }
}

static void sock_new_after_dns(xmpp_sock_t *xsock, const char *domain)
{
    if (!xsock->srv_rr_list) {
        strophe_debug(xsock->ctx, "sock",
                      "SRV lookup failed, connecting via domain.");
        xsock->srv_rr_list =
            resolver_srv_rr_new(xsock->ctx, domain, xsock->port, 0, 0);
    }
    xsock->srv_rr_cur = xsock->srv_rr_list;

    sock_getaddrinfo(xsock, &sock_connect);
}

int sock_new(xmpp_conn_t *conn,
             const char *domain,
             const char *host,
             unsigned short port)
{
    xmpp_ctx_t *ctx = conn->ctx;
    xmpp_sock_t *xsock;

    xsock = strophe_alloc(ctx, sizeof(*xsock));
    if (!xsock) {
        conn->xsock = NULL;
        return XMPP_EMEM;
    }

    xsock->ctx = ctx;
    xsock->conn = conn;
    xsock->host = NULL;
    xsock->port = port;
    xsock->ainfo_list = NULL;
    conn->xsock = xsock;

    if (host) {
        xsock->srv_rr_list = resolver_srv_rr_new(ctx, host, port, 0, 0);
    } else {
        resolver_srv_lookup(ctx, "xmpp-client", "tcp", domain,
                            &xsock->srv_rr_list, &sock_new_after_dns, xsock);
    }

    return 0;
}

void sock_free(xmpp_sock_t *xsock)
{
    if (!xsock)
        return;

    if (xsock->ainfo_list)
        resolver_freeaddrinfo(xsock->ainfo_list);
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

void sock_connect(xmpp_sock_t *xsock)
{
    xmpp_conn_t *conn = xsock->conn;
    resolver_addrinfo_node *ainfo;
    int rc;
    char buf[64];
    sock_t sock = INVALID_SOCKET;

    conn->sock = INVALID_SOCKET;
    do {
        if (!xsock->ainfo_cur && !xsock->srv_rr_cur) {
            /* We tried all available addresses. */
            conn->error = XMPP_EINT;
            conn_disconnect(conn);
            return;
        }

        if (!xsock->ainfo_cur) {
            sock_getaddrinfo(xsock, &sock_connect);
            return;
        }

        ainfo = xsock->ainfo_cur;
        strophe_debug(xsock->ctx, "sock", "Connecting to %s:%u via %s",
                      xsock->host, xsock->port,
                      _sockaddr2str(ainfo->ai_addr, buf, sizeof(buf)));

        sock = socket(ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol);
        if (sock != INVALID_SOCKET) {
            rc = 0;
            if (xsock->conn->sockopt_cb) {
                /* Don't allow user to overwrite sockfd value. */
                sock_t sock_copy = sock;
                rc = xsock->conn->sockopt_cb(xsock->conn, &sock_copy);
                if (rc != 0) {
                    strophe_debug(xsock->ctx, "sock",
                                  "User's setsockopt callback"
                                  " failed with %d (errno=%d)",
                                  rc, errno);
                }
            }
            if (rc == 0)
                rc = sock_set_nonblocking(sock);
            if (rc == 0)
                rc = connect(sock, ainfo->ai_addr, ainfo->ai_addrlen);
            /* Assume only connect() can cause "in progress" error. */
            if (rc != 0 && !_in_progress(sock_error(NULL))) {
                sock_close(sock);
                sock = INVALID_SOCKET;
            }
        }
        strophe_debug(xsock->ctx, "sock", "sock_connect() result %d", sock);

        xsock->ainfo_cur = xsock->ainfo_cur->ai_next;
    } while (sock == INVALID_SOCKET);

    conn->sock = sock;
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

int sock_read(struct conn_interface *intf, void *buff, size_t len)
{
    return recv(intf->conn->sock, buff, len, 0);
}

int sock_write(struct conn_interface *intf, const void *buff, size_t len)
{
    return send(intf->conn->sock, buff, len, 0);
}

int sock_is_recoverable(struct conn_interface *intf, int error)
{
    UNUSED(intf);
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
    if (sock_error(NULL) != WSAENOTCONN)
        return sock_error(NULL);
#else
    if (sock_error(NULL) != ENOTCONN)
        return sock_error(NULL);
#endif

    /* load the correct error into errno through error slippage */
    recv(sock, &temp, 1, 0);

    return sock_error(NULL);
}
